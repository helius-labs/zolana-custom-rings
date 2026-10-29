use custom_ring_interface::{
    key_catalog::RingCircuit,
    storage::{Revision, StorageRegistry},
    storage_instruction::{StorageWriteData, UpdateMode},
    verifying_key, CustomRingProof, QueueEntry, RegisterKeyStatement, RingMode, RingPolicy,
    RingProof, APPLY_BATCH, AUDIT_CIPHERTEXT_LEN, ROOT_HISTORY,
};
use solana_address::Address;
use spr_indexer_api::Hash;
use spr_keypair::X25519Pubkey;
use thiserror::Error;
use zolana_ring_client::{
    rpc::{EscrowRegistration, RecordUpdateEntry, RecordUpdateId, SubmitRecordUpdateRequest},
    storage_apply_proof_inputs, MemberOpeningRead,
};
use zolana_ring_indexer::rpc::GetStorageApplyProofInputsResponse;
use zolana_ring_member_registry::{ApplyProofInputs, RecordWriteProofInput};
use zolana_ring_policy::{ListId, ListSet, Member, MintPolicy};

use crate::{error::RingRpcError, upstream::RingConfiguration};

/// Slots a graced update waits for more writes before it goes out short.
pub const BATCH_WINDOW_SLOTS: u64 = 40;
/// Failed or expired batches an update rides in before it turns refused.
pub const MAX_BATCH_ATTEMPTS: u64 = 3;
const REVOKING_SETS: u64 = ListSet::of(&[ListId::Block, ListId::Frozen]).record_bits();
// A graced reader revocation stops reads at once, grants open under the newest mirrored root.
const REVOKING_CLEARS: u64 = ListSet::of(&[ListId::Allow, ListId::Approval]).record_bits();

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[repr(i32)]
pub enum RecordUpdateRefusal {
    #[error("record writes are not served")]
    Disabled = -32140,
    #[error("record update carries no entry or more than {APPLY_BATCH}")]
    EntryCount = -32141,
    #[error("record update entry is invalid")]
    InvalidEntry = -32142,
    #[error("record update signature does not verify")]
    Signature = -32143,
    #[error("record update is past its valid until slot")]
    Expired = -32144,
    #[error("ring has no config")]
    UnknownRing = -32145,
    #[error("registry is not the ring records under the writer authority")]
    RegistryNotServed = -32146,
    #[error("signer may not write the entry")]
    Unauthorized = -32147,
    #[error("escrow registration proof does not verify")]
    EscrowProof = -32148,
    #[error("record update is unknown")]
    UnknownUpdate = -32149,
    #[error("record update names another cluster")]
    WrongCluster = -32190,
    #[error("anonymous ring takes no escrow key")]
    EscrowOnAnonymousRing = -32191,
    #[error("member already holds or awaits an escrow key")]
    EscrowRegistered = -32192,
    #[error("record update batch failed on every attempt")]
    BatchFailed = -32193,
}

pub(crate) struct UpdateContext<'a> {
    pub genesis_hash: &'a [u8; 32],
    pub config: &'a RingConfiguration,
    pub policy: &'a RingPolicy,
    pub registry: &'a StorageRegistry,
    pub writer: Address,
    pub slot: u64,
}

#[must_use]
pub(crate) struct RecordUpdateCheck<'a> {
    pub request: &'a SubmitRecordUpdateRequest,
    pub context: UpdateContext<'a>,
}

#[must_use]
pub(crate) struct CheckedUpdate {
    pub id: RecordUpdateId,
    pub writes: Vec<StorageWriteData>,
    pub urgent: bool,
}

pub(crate) struct QueuedUpdate {
    pub id: [u8; 32],
    pub ring: Address,
    pub writes: Vec<StorageWriteData>,
    pub urgent: bool,
    pub queued_slot: u64,
    pub valid_until_slot: u64,
}

/// `queue` holds no update past its valid until slot.
#[must_use]
pub(crate) struct BatchPlan<'a> {
    pub queue: &'a [QueuedUpdate],
    pub slot: u64,
}

/// Every update urgent or every update graced, in submit order.
#[must_use]
pub(crate) struct PlannedBatch<'a> {
    pub updates: Vec<&'a QueuedUpdate>,
}

/// `records[i]` opens `registering[i]` under the newest mirrored root.
#[must_use]
pub(crate) struct EscrowUniqueness<'a> {
    pub registering: &'a [[u8; 32]],
    pub records: &'a [MemberOpeningRead],
    /// Queued and submitted writes of the registry.
    pub pending: &'a [StorageWriteData],
}

#[must_use]
pub(crate) struct ApplyInputsCheck<'a> {
    pub response: &'a GetStorageApplyProofInputsResponse,
    pub registry: &'a StorageRegistry,
    pub entries: &'a [QueueEntry],
}

pub(crate) struct CheckedInputs {
    pub revision: Revision,
    pub inputs: ApplyProofInputs,
}

#[must_use]
pub(crate) struct ModeDecision<'a> {
    pub inputs: &'a ApplyProofInputs,
    pub registry: &'a StorageRegistry,
    pub slot: u64,
}

/// The config authority also writes its own wallet records.
#[derive(Clone, Copy)]
enum RecordSigner {
    Wallet(Member),
    ConfigAuthority(Member),
}

/// The statement `RegisterKey` verifies, the escrow key sealed to the ring auditor.
struct EscrowProof<'a> {
    registration: &'a EscrowRegistration,
    auditor: &'a X25519Pubkey,
}

impl RecordUpdateRefusal {
    pub const fn code(self) -> i32 {
        self as i32
    }
}

impl RecordUpdateCheck<'_> {
    pub fn check(self) -> Result<CheckedUpdate, RecordUpdateRefusal> {
        let Self { request, context } = self;
        let entries = &request.update.entries;
        if !(1..=APPLY_BATCH).contains(&entries.len()) {
            return Err(RecordUpdateRefusal::EntryCount);
        }
        if request.update.genesis_hash.0 != *context.genesis_hash {
            return Err(RecordUpdateRefusal::WrongCluster);
        }
        // 1. The signature binds the cluster, the ring, the registry and the ordered entries.
        let hash = request
            .statement()
            .and_then(|statement| Ok(statement.hash()?))
            .map_err(invalid_entry)?;
        let signer = request.signer.0;
        if !request.signature.0.verify(signer.as_ref(), &hash) {
            return Err(RecordUpdateRefusal::Signature);
        }
        if context.slot > request.update.valid_until_slot {
            return Err(RecordUpdateRefusal::Expired);
        }
        // 2. The registry is the ring records and the writer holds its authority.
        if context.policy.records != request.registry.0
            || context.registry.authority != context.writer
        {
            return Err(RecordUpdateRefusal::RegistryNotServed);
        }
        // 3. Every entry is the signer's to write and every escrow key is sealed to the ring auditor.
        let record_signer = RecordSigner::new(signer, context.config.authority)?;
        for entry in entries {
            if !record_signer.may_write(entry) {
                return Err(RecordUpdateRefusal::Unauthorized);
            }
            if let RecordUpdateEntry::Escrow(registration) = entry {
                if context.config.mode == RingMode::Anonymous {
                    return Err(RecordUpdateRefusal::EscrowOnAnonymousRing);
                }
                EscrowProof {
                    registration,
                    auditor: &context.config.auditor_pubkey,
                }
                .verify()?;
            }
        }
        let writes = entries
            .iter()
            .map(|entry| entry.write(&signer))
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid_entry)?;
        let urgent = writes
            .iter()
            .map(StorageWriteData::entry)
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid_entry)?
            .iter()
            .any(urgent);
        Ok(CheckedUpdate {
            id: RecordUpdateId(Hash(hash)),
            writes,
            urgent,
        })
    }
}

impl<'a> BatchPlan<'a> {
    /// Urgent updates go at once ahead of graced ones on other records, graced ones once full, aged or blocking an urgent one.
    pub fn decide(self) -> Result<Option<PlannedBatch<'a>>, RecordUpdateRefusal> {
        let urgent = self.urgent()?;
        if !urgent.is_empty() {
            return Ok(Some(PlannedBatch { updates: urgent }));
        }
        let graced = within_batch(self.queue.iter().take_while(|update| !update.urgent));
        let carried: usize = graced.iter().map(|update| update.writes.len()).sum();
        let full = carried == APPLY_BATCH
            || self
                .queue
                .get(graced.len())
                .is_some_and(|next| !next.urgent);
        let blocking = self.queue.iter().any(|update| update.urgent);
        let aged = self.queue.first().is_some_and(|oldest| {
            self.slot >= oldest.queued_slot.saturating_add(BATCH_WINDOW_SLOTS)
        });
        Ok((!graced.is_empty() && (full || blocking || aged))
            .then_some(PlannedBatch { updates: graced }))
    }

    /// Stops at an urgent update sharing a record with an earlier graced one, each record keeps its write order.
    fn urgent(&self) -> Result<Vec<&'a QueuedUpdate>, RecordUpdateRefusal> {
        let mut graced_members = Vec::new();
        let mut urgent = Vec::new();
        for update in self.queue {
            let members = update
                .writes
                .iter()
                .map(StorageWriteData::member)
                .collect::<Result<Vec<_>, _>>()
                .map_err(invalid_entry)?;
            if !update.urgent {
                graced_members.extend(members);
            } else if members.iter().any(|member| graced_members.contains(member)) {
                break;
            } else {
                urgent.push(update);
            }
        }
        Ok(within_batch(urgent))
    }
}

impl EscrowUniqueness<'_> {
    pub fn check(self) -> Result<(), RecordUpdateRefusal> {
        let recorded = self.records.iter().any(|read| {
            read.record()
                .is_some_and(|record| record.escrow_key != [0; 32])
        });
        let mut seen = escrowed_members(self.pending)?;
        for member in self.registering {
            if recorded || seen.contains(member) {
                return Err(RecordUpdateRefusal::EscrowRegistered);
            }
            seen.push(*member);
        }
        Ok(())
    }
}

impl ApplyInputsCheck<'_> {
    /// Inputs off the registry's current root or off the batch are a stale projection.
    pub fn check(self) -> Result<CheckedInputs, RingRpcError> {
        let current = &self.registry.roots[0];
        let inputs =
            storage_apply_proof_inputs(self.response).map_err(|_| RingRpcError::StaleRecords)?;
        let matches = self.response.revision == current.revision.value()
            && inputs.old_root == current.hash
            && inputs.old_next_index == u64::from(self.registry.next_index())
            && inputs
                .writes
                .iter()
                .map(|write| &write.entry)
                .eq(self.entries.iter());
        if !matches {
            return Err(RingRpcError::StaleRecords);
        }
        Ok(CheckedInputs {
            revision: current.revision,
            inputs,
        })
    }
}

impl ModeDecision<'_> {
    /// `None` waits for the oldest retired root to expire.
    pub fn decide(self) -> Option<UpdateMode> {
        if self.inputs.writes.iter().any(revokes) {
            return Some(UpdateMode::Immediate);
        }
        // A graced update over an unexpired oldest root fails on chain.
        let history_full = self.slot < self.registry.roots[ROOT_HISTORY - 1].expires_at();
        (!history_full).then_some(UpdateMode::Graced)
    }
}

impl RecordSigner {
    fn new(signer: Address, config_authority: Address) -> Result<Self, RecordUpdateRefusal> {
        let wallet = Member::owner_tag(signer.as_array()).map_err(invalid_entry)?;
        Ok(if signer == config_authority {
            Self::ConfigAuthority(wallet)
        } else {
            Self::Wallet(wallet)
        })
    }

    /// A wallet writes its member lists, its escrow and its grants, the authority every authority list and mint setting.
    fn may_write(self, entry: &RecordUpdateEntry) -> bool {
        let (Self::Wallet(wallet) | Self::ConfigAuthority(wallet)) = self;
        let own = |member: &Hash| member.0 == *wallet.as_bytes();
        let wallet_write = match entry {
            RecordUpdateEntry::Write(write) => {
                own(&write.member)
                    && write.mint_policy.is_none()
                    && lists_within(write.mask, ListSet::MEMBER_WRITES)
            }
            RecordUpdateEntry::Escrow(registration) => own(&registration.member),
            RecordUpdateEntry::WalletGrant(grant) => own(&grant.wallet),
        };
        let authority_write = matches!(self, Self::ConfigAuthority(_))
            && matches!(entry, RecordUpdateEntry::Write(write)
                if lists_within(write.mask, ListSet::AUTHORITY_WRITES));
        wallet_write || authority_write
    }
}

impl EscrowProof<'_> {
    fn verify(self) -> Result<(), RecordUpdateRefusal> {
        let registration = self.registration;
        let eph_pk = <[u8; 33]>::try_from(registration.eph_pk.0.as_slice())
            .map_err(invalid_entry)
            .and_then(|bytes| X25519Pubkey::from_bytes(bytes).map_err(invalid_entry))?;
        let ciphertext =
            <&[u8; AUDIT_CIPHERTEXT_LEN]>::try_from(registration.ciphertext.0.as_slice())
                .map_err(invalid_entry)?;
        let proof: CustomRingProof =
            bytemuck::try_pod_read_unaligned(&registration.proof.0).map_err(invalid_entry)?;
        let statement = RegisterKeyStatement {
            member: &registration.member.0,
            nullifier_pk: &registration.nullifier_pk.0,
            auditor_pubkey: self.auditor.as_bytes(),
            eph_u: &eph_pk.u(),
            ciphertext,
        }
        .hash()
        .map_err(invalid_entry)?;
        RingProof {
            proof: &proof,
            statement,
            key: verifying_key(RingCircuit::RegisterKey).ok_or(RecordUpdateRefusal::EscrowProof)?,
        }
        .verify()
        .map_err(|_| RecordUpdateRefusal::EscrowProof)
    }
}

pub(crate) fn escrowed_members(
    writes: &[StorageWriteData],
) -> Result<Vec<[u8; 32]>, RecordUpdateRefusal> {
    writes
        .iter()
        .filter_map(|write| match write {
            StorageWriteData::Escrow(escrow) => Some(escrow.member().map_err(invalid_entry)),
            StorageWriteData::Record(_) => None,
        })
        .collect()
}

/// The longest prefix one `Update` carries without splitting an update.
fn within_batch<'a>(updates: impl IntoIterator<Item = &'a QueuedUpdate>) -> Vec<&'a QueuedUpdate> {
    let mut writes = 0;
    updates
        .into_iter()
        .take_while(|update| {
            writes += update.writes.len();
            writes <= APPLY_BATCH
        })
        .collect()
}

fn lists_within(mask: u64, lists: ListSet) -> bool {
    mask & !lists.record_bits() == 0
}

/// Revokes by its lists, or writes a mint whose old settings the flush reads first.
fn urgent(entry: &QueueEntry) -> bool {
    revokes_lists(entry) || entry.mint_policy.is_some()
}

fn revokes(write: &RecordWriteProofInput) -> bool {
    revokes_lists(&write.entry)
        || write
            .entry
            .mint_policy
            .is_some_and(|new| restricts(write.old_mint_policy, new))
}

fn revokes_lists(entry: &QueueEntry) -> bool {
    entry.value & REVOKING_SETS != 0 || entry.mask & !entry.value & REVOKING_CLEARS != 0
}

/// Zero turns a cap or co-sign bound off, so a bound set from zero restricts.
fn restricts(old: MintPolicy, new: MintPolicy) -> bool {
    let bound = |old: u64, new: u64| new != 0 && (old == 0 || new < old);
    new.threshold < old.threshold
        || new.withdrawal_threshold < old.withdrawal_threshold
        || bound(old.cap, new.cap)
        || bound(old.cosign_above, new.cosign_above)
}

fn invalid_entry<E>(_: E) -> RecordUpdateRefusal {
    RecordUpdateRefusal::InvalidEntry
}
