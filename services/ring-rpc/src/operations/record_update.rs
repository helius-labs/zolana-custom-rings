//! Checks a signed record update and plans its batches. Every update takes one lifecycle, pending list approval when it awaits lists, then queued, submitted, and applied or refused.
//! Pending list approval is the wait for the policy authority to approve off chain, a KYC check for one, and is not an enrollment. The writer holds the wallet's writes until the authority's own update sets every awaited list, then sends both in one `Update`.
//! It reserves no approval and binds the authority to nothing, an update past its valid until slot turns refused.
//! Read `update_queue` after for the stored states and `record_writer` for the passes that move them.

use std::collections::BTreeMap;

use custom_ring_interface::{
    storage::{Revision, StorageRegistry},
    ListRegistry, RecordWrite, RecordWriteData, RingPolicy, APPLY_BATCH,
};
use solana_address::Address;
use spr_indexer_api::Hash;
use thiserror::Error;
use zolana_ring_client::{
    owner_record_key,
    rpc::{RecordUpdateEntry, RecordUpdateId, SubmitRecordUpdateRequest, AWAITABLE_LISTS},
    storage_apply_proof_inputs,
};
use zolana_ring_indexer::rpc::{GetStorageApplyProofInputsResponse, RingListWriteView};
use zolana_ring_member_registry::ApplyProofInputs;
use zolana_ring_policy::{AssetLimits, ListId, ListSet, Member};

use crate::{config::ReaderGrantStore, error::RingRpcError, upstream::RingConfiguration};

pub use zolana_ring_client::rpc::BATCH_WINDOW_SLOTS;
/// Failed or expired batches an update rides in before it turns refused.
pub const MAX_BATCH_ATTEMPTS: u64 = 3;
/// One day of 250 ms slots, the longest an update waits pending list approval.
pub const MAX_LIST_APPROVAL_WINDOW_SLOTS: u64 = 4 * 60 * 60 * 24;
/// Thirty days of 250 ms slots.
pub const MAX_LIMIT_WINDOW_SLOTS: u64 = 4 * 60 * 60 * 24 * 30;

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
    #[error("record update is unknown")]
    UnknownUpdate = -32149,
    #[error("record update names another cluster")]
    WrongCluster = -32190,
    #[error("record update batch failed on every attempt")]
    BatchFailed = -32193,
    #[error("service keeps reader grants in its database")]
    ReaderGrantsInDatabase = -32230,
    #[error("only a wallet may await allow, reader or approval from the ring's own records")]
    InvalidAwaitedLists = -32240,
    #[error("signer is not the ring policy authority")]
    NotPolicyAuthority = -32241,
    #[error("approved updates and the approval exceed one batch")]
    ListApprovalBatch = -32242,
    #[error("policy authority refused the list approval")]
    ListApprovalRefused = -32243,
    #[error("no update of the ring is pending list approval under the id")]
    UnknownListApproval = -32244,
    #[error("valid until slot is past the list approval window")]
    ListApprovalWindow = -32245,
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
    pub writes: Vec<RecordWriteData>,
    /// The leaf write of each entry.
    pub entries: Vec<RecordWrite>,
    pub signer: UpdateSigner,
    /// `Some` puts the update pending list approval.
    pub awaited: Option<AwaitedLists>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AwaitedLists {
    pub lists: ListSet,
    /// The owner identity of the signer.
    pub member: [u8; 32],
}

/// A stored update pending list approval.
pub(crate) struct PendingApproval {
    pub id: [u8; 32],
    pub wallet: Address,
    pub member: [u8; 32],
    pub lists: ListSet,
    pub writes: usize,
    pub valid_until_slot: u64,
}

pub(crate) struct ApprovalGrant {
    pub member: [u8; 32],
    pub lists: ListSet,
}

#[must_use]
pub(crate) struct ListApproval<'a> {
    pub update: &'a CheckedUpdate,
    /// The updates pending list approval of the members the update writes, oldest first.
    pub pending: &'a [PendingApproval],
}

pub(crate) struct QueuedUpdate {
    pub id: [u8; 32],
    pub ring: Address,
    pub registry: Address,
    pub joined: Vec<[u8; 32]>,
    pub writes: Vec<RecordWriteData>,
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
    /// `None` while the ring account is unread.
    pub policy_authority: Option<Address>,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueuedState {
    Live,
    Deferred,
}

/// An authority update with whether an earlier queued wallet update writes one of its records.
pub(crate) struct AuthorityHead {
    pub update: QueuedUpdate,
    pub blocked: bool,
}

/// The oldest queued updates of either role in submit order, one past a full batch.
#[must_use]
pub(crate) struct WalletBatch {
    pub oldest: Vec<QueuedUpdate>,
    /// An authority update waits behind the wallet updates.
    pub blocking: bool,
    pub slot: u64,
}

#[must_use]
pub(crate) struct ApplyInputsCheck<'a> {
    pub response: &'a GetStorageApplyProofInputsResponse,
    pub registry: &'a StorageRegistry,
    pub entries: &'a [RecordWrite],
}

pub(crate) struct CheckedInputs {
    pub revision: Revision,
    pub inputs: ApplyProofInputs,
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
        // 3. Every entry is the signer's to write.
        let update_signer = UpdateSigner::of(request)?;
        if !update_signer.holds_role(context.config.roles.policy) {
            return Err(RecordUpdateRefusal::Unauthorized);
        }
        // 4. A wallet awaits only grant lists the policy reads from its own records, a list a curator registry holds never lands in the writer's batch.
        let awaited = match request.update.awaited_lists {
            0 => None,
            bits if signer != context.config.roles.policy => Some(AwaitedLists {
                lists: awaited_lists(bits, context.policy)?,
                member: *owner_record_key(signer.as_array())
                    .map_err(invalid_entry)?
                    .as_bytes(),
            }),
            _ => return Err(RecordUpdateRefusal::InvalidAwaitedLists),
        };
        if awaited.is_some()
            && request.update.valid_until_slot
                > context.slot.saturating_add(MAX_LIST_APPROVAL_WINDOW_SLOTS)
        {
            return Err(RecordUpdateRefusal::ListApprovalWindow);
        }
        let writes = entries
            .iter()
            .map(RecordUpdateEntry::write)
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid_entry)?;
        let queued = entries
            .iter()
            .map(RecordUpdateEntry::entry)
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid_entry)?;
        // 5. No entry writes and no update awaits a tree reader list the service never reads.
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
            entries: queued,
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
            if !members.contains(&write.member) {
                members.push(write.member);
            }
        }
        Ok(members)
    }

    pub fn approval_grants(&self) -> Result<Vec<ApprovalGrant>, RecordUpdateRefusal> {
        if self.awaited.is_some() {
            return Ok(Vec::new());
        }
        let mut grants = BTreeMap::new();
        for entry in &self.entries {
            let lists =
                ListSet::from_record_bits(entry.mask & entry.value & AWAITABLE_LISTS.record_bits())
                    .ok_or(RecordUpdateRefusal::InvalidAwaitedLists)?;
            if !lists.is_empty() {
                let granted = grants.entry(entry.member).or_insert(ListSet::EMPTY);
                *granted = granted.union(lists);
            }
        }
        Ok(grants
            .into_iter()
            .map(|(member, lists)| ApprovalGrant { member, lists })
            .collect())
    }

    pub fn limited_assets(&self) -> Result<Vec<[u8; 32]>, RecordUpdateRefusal> {
        Ok(self
            .entries
            .iter()
            .filter(|entry| {
                entry
                    .mint_policy
                    .is_some_and(|policy| policy.limits != AssetLimits::EMPTY)
            })
            .map(|entry| entry.member)
            .collect())
    }
}

impl UpdateSigner {
    /// `Unauthorized` for an entry that is neither the signer's wallet write nor an authority write.
    pub fn of(request: &SubmitRecordUpdateRequest) -> Result<Self, RecordUpdateRefusal> {
        let signer = request.signer.0;
        let wallet = WalletKeys {
            identity: Member::owner_tag(signer.as_array()).map_err(invalid_entry)?,
            record: owner_record_key(signer.as_array()).map_err(invalid_entry)?,
        };
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
    pub fn holds_role(self, policy_authority: Address) -> bool {
        match self {
            Self::Wallet(_) => true,
            Self::PolicyAuthority(signer) => policy_authority == signer,
        }
    }
}

impl QueuedCheck<'_> {
    /// No update goes out past its valid until slot or after its signer lost the role it signed as.
    pub fn check(self) -> Result<QueuedState, RecordUpdateRefusal> {
        if self.slot > self.update.valid_until_slot {
            return Err(RecordUpdateRefusal::Expired);
        }
        let Some(policy_authority) = self.policy_authority else {
            return Ok(QueuedState::Deferred);
        };
        if !self.update.signer.holds_role(policy_authority) {
            return Err(RecordUpdateRefusal::AuthorityLapsed);
        }
        Ok(QueuedState::Live)
    }
}

/// Authority updates go at the next pass ahead of wallet ones on other records, up to the first
/// that shares a record with an earlier wallet update, so each record keeps its write order.
pub(crate) fn authority_batch(heads: Vec<AuthorityHead>) -> Vec<QueuedUpdate> {
    within_batch(
        heads
            .into_iter()
            .take_while(|head| !head.blocked)
            .map(|head| head.update),
    )
}

impl WalletBatch {
    /// Wallet updates go once full, aged or blocking an authority one.
    pub fn decide(self) -> Option<Vec<QueuedUpdate>> {
        let Self {
            oldest,
            blocking,
            slot,
        } = self;
        let aged = oldest
            .first()
            .is_some_and(|oldest| slot >= oldest.queued_slot.saturating_add(BATCH_WINDOW_SLOTS));
        let wallet_heads = oldest
            .iter()
            .take_while(|update| !update.signer.is_authority())
            .count();
        let batch = within_batch(oldest.into_iter().take(wallet_heads));
        let carried: usize = batch.iter().map(|update| update.writes.len()).sum();
        // A wallet update left out of the batch fills it, the read holds one past a full batch.
        let full = carried == APPLY_BATCH || batch.len() < wallet_heads;
        (!batch.is_empty() && (full || blocking || aged)).then_some(batch)
    }
}

impl ListApproval<'_> {
    /// The pending updates whose every awaited list the update sets on their member, the writer
    /// checks no outside process behind the approval.
    pub fn decide(self) -> Result<Vec<[u8; 32]>, RecordUpdateRefusal> {
        if self.update.awaited.is_some() {
            return Ok(Vec::new());
        }
        let grants = self.update.approval_grants()?;
        let approved: Vec<&PendingApproval> = self
            .pending
            .iter()
            .filter(|pending| {
                grants.iter().any(|grant| {
                    grant.member == pending.member && pending.lists.is_subset(grant.lists)
                })
            })
            .collect();
        // The approval and the updates it approves land in one `Update` or not at all.
        let writes = approved
            .iter()
            .fold(self.update.writes.len(), |writes, pending| {
                writes + pending.writes
            });
        if !approved.is_empty() && writes > APPLY_BATCH {
            return Err(RecordUpdateRefusal::ListApprovalBatch);
        }
        Ok(approved.iter().map(|pending| pending.id).collect())
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
fn within_batch(updates: impl IntoIterator<Item = QueuedUpdate>) -> Vec<QueuedUpdate> {
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
            lists.is_subset(AWAITABLE_LISTS)
                && lists.iter().all(|list| {
                    // No rule reads Reader, a grant always reads the ring's own records.
                    list == ListId::Reader || policy.registry_for(list) == Some(ListRegistry::Own)
                })
        })
        .ok_or(RecordUpdateRefusal::InvalidAwaitedLists)
}

fn lists_within(mask: u64, lists: ListSet) -> bool {
    mask & !lists.record_bits() == 0
}

struct WalletKeys {
    identity: Member,
    record: Member,
}

/// A wallet writes the lists of its public record and its grants.
fn wallet_write(entry: &RecordUpdateEntry, wallet: &WalletKeys) -> bool {
    match entry {
        RecordUpdateEntry::Write(write) => {
            write.member.0 == *wallet.record.as_bytes()
                && write.mint_policy.is_none()
                && lists_within(write.mask, ListSet::MEMBER_WRITES)
        }
        RecordUpdateEntry::WalletGrant(grant) => grant.wallet.0 == *wallet.identity.as_bytes(),
    }
}

/// The policy authority writes every authority list and mint setting.
fn authority_write(entry: &RecordUpdateEntry) -> bool {
    match entry {
        RecordUpdateEntry::Write(write) => lists_within(write.mask, ListSet::AUTHORITY_WRITES),
        RecordUpdateEntry::WalletGrant(_) => false,
    }
}

fn invalid_entry<E>(_: E) -> RecordUpdateRefusal {
    RecordUpdateRefusal::InvalidEntry
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn an_update_awaiting_reader_needs_no_reader_rule() {
        let policy = bytemuck::Zeroable::zeroed();
        assert_eq!(
            awaited_lists(ListId::Reader.record_bit(), &policy),
            Ok(ListSet::single(ListId::Reader))
        );
        assert_eq!(
            awaited_lists(ListId::Allow.record_bit(), &policy),
            Err(RecordUpdateRefusal::InvalidAwaitedLists),
            "a list no rule reads from the ring's own records stays refused"
        );
    }
}
