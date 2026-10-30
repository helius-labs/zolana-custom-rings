use custom_ring_interface::{
    key_catalog::RingCircuit,
    storage::{Revision, StorageRegistry},
    storage_instruction::{StorageWriteData, UpdateMode},
    verifying_key, CustomRingProof, ListRegistry, QueueEntry, RegisterKeyStatement, RingMode,
    RingPolicy, RingProof, APPLY_BATCH, AUDIT_CIPHERTEXT_LEN, ROOT_HISTORY,
};
use solana_address::Address;
use spr_indexer_api::Hash;
use spr_keypair::X25519Pubkey;
use thiserror::Error;
use zolana_ring_client::{
    rpc::{
        EscrowRegistration, RecordUpdateEntry, RecordUpdateId, SubmitRecordUpdateRequest,
        ENROLMENT_LISTS,
    },
    storage_apply_proof_inputs, MemberOpeningRead,
};
use zolana_ring_indexer::rpc::{GetStorageApplyProofInputsResponse, RingListWriteView};
use zolana_ring_member_registry::{ApplyProofInputs, RecordWriteProofInput};
use zolana_ring_policy::{AssetLimits, ListId, ListSet, Member, MintPolicy};

use crate::{config::ReaderGrantStore, error::RingRpcError, upstream::RingConfiguration};

/// Slots a graced update waits for more writes before it goes out short.
pub const BATCH_WINDOW_SLOTS: u64 = 40;
/// Failed or expired batches an update rides in before it turns refused.
pub const MAX_BATCH_ATTEMPTS: u64 = 3;
/// One day of 250 ms slots.
pub const MAX_ENROLMENT_WINDOW_SLOTS: u64 = 4 * 60 * 60 * 24;
/// Thirty days of 250 ms slots.
pub const MAX_LIMIT_WINDOW_SLOTS: u64 = 4 * 60 * 60 * 24 * 30;
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
    #[error("ring has no policy account")]
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
    #[error("service keeps reader grants in its database")]
    ReaderGrantsInDatabase = -32230,
    #[error("only a wallet may await allow, reader or approval from the ring's own records")]
    EnrolmentLists = -32240,
    #[error("signer is not the ring policy authority")]
    NotPolicyAuthority = -32241,
    #[error("approved enrolments and the update exceed one batch")]
    EnrolmentBatch = -32242,
    #[error("policy authority refused the enrolment")]
    EnrolmentRefused = -32243,
    #[error("no enrolment of the ring awaits the authority under the id")]
    UnknownEnrolment = -32244,
    #[error("enrolment valid until slot is past the enrolment window")]
    EnrolmentWindow = -32245,
    // -32246 retired.
    #[error("records registry creation did not land")]
    RecordsNotCreated = -32260,
    #[error("signer no longer holds the ring policy role")]
    AuthorityLapsed = -32275,
    #[error("mint limits are unpaired or exceed the window bound")]
    InvalidLimits = -32276,
    #[error("mint limits name an asset without a record")]
    LimitsWithoutRecord = -32277,
}

pub(crate) struct UpdateContext<'a> {
    pub genesis_hash: &'a [u8; 32],
    pub config: &'a RingConfiguration,
    pub policy: &'a RingPolicy,
    pub registry: &'a StorageRegistry,
    pub writer: Address,
    pub slot: u64,
    pub reader_grants: ReaderGrantStore,
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
    pub signer: UpdateSigner,
    /// `Some` holds the update until the policy authority sets these lists on the signer's record.
    pub awaited: Option<AwaitedLists>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AwaitedLists {
    pub lists: ListSet,
    /// The owner identity of the signer.
    pub member: [u8; 32],
}

pub(crate) struct AwaitingEnrolment {
    pub id: [u8; 32],
    pub wallet: Address,
    pub member: [u8; 32],
    pub lists: ListSet,
    pub writes: usize,
    pub valid_until_slot: u64,
}

#[must_use]
pub(crate) struct EnrolmentApproval<'a> {
    pub update: &'a CheckedUpdate,
    /// The awaiting enrolments of the members the update writes, oldest first.
    pub awaiting: &'a [AwaitingEnrolment],
}

pub(crate) struct QueuedUpdate {
    pub id: [u8; 32],
    pub ring: Address,
    pub writes: Vec<StorageWriteData>,
    pub signer: UpdateSigner,
    pub queued_slot: u64,
    pub valid_until_slot: u64,
}

/// The policy role whenever an entry is not the signer's own wallet write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UpdateSigner {
    Wallet(Address),
    PolicyAuthority(Address),
}

#[must_use]
pub(crate) struct QueuedCheck<'a> {
    pub update: &'a QueuedUpdate,
    pub slot: u64,
    pub policy_authority: Option<Address>,
}

/// `queue` holds no update past its valid until slot.
#[must_use]
pub(crate) struct BatchPlan<'a> {
    pub queue: &'a [QueuedUpdate],
    pub slot: u64,
}

/// All authority updates or all wallet updates, in submit order.
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
        // 1. The signature binds the cluster, the ring, the registry, the ordered entries and the awaited lists.
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
        let update_signer = UpdateSigner::of(request)?;
        if !update_signer.holds_role(Some(context.config.roles.policy)) {
            return Err(RecordUpdateRefusal::Unauthorized);
        }
        for entry in entries {
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
        // 4. A wallet awaits only enrolment lists the policy reads from its own records.
        let awaited = match request.update.awaited_lists {
            0 => None,
            bits if signer != context.config.roles.policy => Some(AwaitedLists {
                lists: awaited_lists(bits, context.policy)?,
                member: *Member::owner_tag(signer.as_array())
                    .map_err(invalid_entry)?
                    .as_bytes(),
            }),
            _ => return Err(RecordUpdateRefusal::EnrolmentLists),
        };
        if awaited.is_some()
            && request.update.valid_until_slot
                > context.slot.saturating_add(MAX_ENROLMENT_WINDOW_SLOTS)
        {
            return Err(RecordUpdateRefusal::EnrolmentWindow);
        }
        let writes = entries
            .iter()
            .map(|entry| entry.write(&signer))
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid_entry)?;
        let queued = writes
            .iter()
            .map(StorageWriteData::entry)
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid_entry)?;
        // 5. No entry writes and no enrolment awaits a tree reader list the service never reads.
        if context.reader_grants == ReaderGrantStore::Database
            && (awaited.is_some_and(|awaited| awaited.lists.contains(ListId::Reader))
                || queued
                    .iter()
                    .any(|entry| entry.mask & ListId::Reader.record_bit() != 0))
        {
            return Err(RecordUpdateRefusal::ReaderGrantsInDatabase);
        }
        Ok(CheckedUpdate {
            id: RecordUpdateId(Hash(hash)),
            writes,
            signer: update_signer,
            awaited,
        })
    }
}

impl CheckedUpdate {
    /// Each member once, in write order.
    pub fn written_members(&self) -> Result<Vec<[u8; 32]>, RecordUpdateRefusal> {
        let mut members = Vec::new();
        for write in &self.writes {
            let member = write.entry().map_err(invalid_entry)?.member;
            if !members.contains(&member) {
                members.push(member);
            }
        }
        Ok(members)
    }

    pub fn limited_assets(&self) -> Result<Vec<[u8; 32]>, RecordUpdateRefusal> {
        let mut assets = Vec::new();
        for write in &self.writes {
            let entry = write.entry().map_err(invalid_entry)?;
            if entry
                .mint_policy
                .is_some_and(|policy| policy.limits != AssetLimits::EMPTY)
            {
                assets.push(entry.member);
            }
        }
        Ok(assets)
    }
}

impl UpdateSigner {
    /// `Unauthorized` for an entry that is neither the signer's wallet write nor an authority write.
    pub fn of(request: &SubmitRecordUpdateRequest) -> Result<Self, RecordUpdateRefusal> {
        let signer = request.signer.0;
        let wallet = Member::owner_tag(signer.as_array()).map_err(invalid_entry)?;
        request
            .update
            .entries
            .iter()
            .try_fold(Self::Wallet(signer), |role, entry| {
                if wallet_write(entry, &wallet) {
                    Ok(role)
                } else if authority_write(entry) {
                    Ok(Self::PolicyAuthority(signer))
                } else {
                    Err(RecordUpdateRefusal::Unauthorized)
                }
            })
    }

    pub const fn address(self) -> Address {
        let (Self::Wallet(signer) | Self::PolicyAuthority(signer)) = self;
        signer
    }

    pub const fn is_authority(self) -> bool {
        matches!(self, Self::PolicyAuthority(_))
    }

    /// A wallet write outlives a policy rotation, an authority write lapses with the role.
    pub fn holds_role(self, policy_authority: Option<Address>) -> bool {
        match self {
            Self::Wallet(_) => true,
            Self::PolicyAuthority(signer) => policy_authority == Some(signer),
        }
    }
}

impl QueuedCheck<'_> {
    /// No update goes out past its valid until slot or after its signer lost the role it signed as.
    pub fn check(self) -> Result<(), RecordUpdateRefusal> {
        if self.slot > self.update.valid_until_slot {
            return Err(RecordUpdateRefusal::Expired);
        }
        if !self.update.signer.holds_role(self.policy_authority) {
            return Err(RecordUpdateRefusal::AuthorityLapsed);
        }
        Ok(())
    }
}

impl<'a> BatchPlan<'a> {
    /// Authority updates go at the next pass ahead of wallet ones on other records, wallet ones once full, aged or blocking an authority one.
    pub fn decide(self) -> Result<Option<PlannedBatch<'a>>, RecordUpdateRefusal> {
        let authority = self.authority()?;
        if !authority.is_empty() {
            return Ok(Some(PlannedBatch { updates: authority }));
        }
        let wallet = within_batch(
            self.queue
                .iter()
                .take_while(|update| !update.signer.is_authority()),
        );
        let carried: usize = wallet.iter().map(|update| update.writes.len()).sum();
        let full = carried == APPLY_BATCH
            || self
                .queue
                .get(wallet.len())
                .is_some_and(|next| !next.signer.is_authority());
        let blocking = self.queue.iter().any(|update| update.signer.is_authority());
        let aged = self.queue.first().is_some_and(|oldest| {
            self.slot >= oldest.queued_slot.saturating_add(BATCH_WINDOW_SLOTS)
        });
        Ok((!wallet.is_empty() && (full || blocking || aged))
            .then_some(PlannedBatch { updates: wallet }))
    }

    /// Stops at an authority update sharing a record with an earlier wallet one, each record keeps its write order.
    fn authority(&self) -> Result<Vec<&'a QueuedUpdate>, RecordUpdateRefusal> {
        let mut wallet_members = Vec::new();
        let mut authority = Vec::new();
        for update in self.queue {
            let members = update
                .writes
                .iter()
                .map(StorageWriteData::member)
                .collect::<Result<Vec<_>, _>>()
                .map_err(invalid_entry)?;
            if !update.signer.is_authority() {
                wallet_members.extend(members);
            } else if members.iter().any(|member| wallet_members.contains(member)) {
                break;
            } else {
                authority.push(update);
            }
        }
        Ok(within_batch(authority))
    }
}

impl EnrolmentApproval<'_> {
    /// The enrolments whose every awaited list the update sets on their member.
    pub fn decide(self) -> Result<Vec<[u8; 32]>, RecordUpdateRefusal> {
        if self.update.awaited.is_some() {
            return Ok(Vec::new());
        }
        let entries = self
            .update
            .writes
            .iter()
            .map(StorageWriteData::entry)
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid_entry)?;
        let approved: Vec<&AwaitingEnrolment> = self
            .awaiting
            .iter()
            .filter(|enrolment| {
                let granted = entries
                    .iter()
                    .filter(|entry| entry.member == enrolment.member)
                    .fold(0, |bits, entry| bits | (entry.mask & entry.value));
                enrolment.lists.record_bits() & !granted == 0
            })
            .collect();
        // The update and its enrolments land in one `Update` or not at all.
        let writes = approved
            .iter()
            .fold(self.update.writes.len(), |writes, enrolment| {
                writes + enrolment.writes
            });
        if !approved.is_empty() && writes > APPLY_BATCH {
            return Err(RecordUpdateRefusal::EnrolmentBatch);
        }
        Ok(approved.iter().map(|enrolment| enrolment.id).collect())
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

/// Each cap pairs with its window, and no window exceeds `MAX_LIMIT_WINDOW_SLOTS`.
pub(crate) fn limits_within_bounds(entry: &RecordUpdateEntry) -> bool {
    let RecordUpdateEntry::Write(RingListWriteView {
        mint_policy: Some(policy),
        ..
    }) = entry
    else {
        return true;
    };
    let limits = policy.limits;
    limits.check().is_ok()
        && [
            limits.sender_window_slots,
            limits.volume_window_slots,
            limits.deposit_window_slots,
            limits.withdrawal_window_slots,
        ]
        .into_iter()
        .all(|window_slots| window_slots <= MAX_LIMIT_WINDOW_SLOTS)
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

fn awaited_lists(bits: u64, policy: &RingPolicy) -> Result<ListSet, RecordUpdateRefusal> {
    ListSet::from_record_bits(bits)
        .filter(|lists| {
            lists.is_subset(ENROLMENT_LISTS)
                && lists
                    .iter()
                    .all(|list| policy.registry_for(list) == Some(ListRegistry::Own))
        })
        .ok_or(RecordUpdateRefusal::EnrolmentLists)
}

fn lists_within(mask: u64, lists: ListSet) -> bool {
    mask & !lists.record_bits() == 0
}

/// A wallet writes its member lists, its escrow and its grants.
fn wallet_write(entry: &RecordUpdateEntry, wallet: &Member) -> bool {
    let own = |member: &Hash| member.0 == *wallet.as_bytes();
    match entry {
        RecordUpdateEntry::Write(write) => {
            own(&write.member)
                && write.mint_policy.is_none()
                && lists_within(write.mask, ListSet::MEMBER_WRITES)
        }
        RecordUpdateEntry::Escrow(registration) => own(&registration.member),
        RecordUpdateEntry::WalletGrant(grant) => own(&grant.wallet),
    }
}

/// The policy authority writes every authority list and mint setting.
fn authority_write(entry: &RecordUpdateEntry) -> bool {
    matches!(entry, RecordUpdateEntry::Write(write)
        if lists_within(write.mask, ListSet::AUTHORITY_WRITES))
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
