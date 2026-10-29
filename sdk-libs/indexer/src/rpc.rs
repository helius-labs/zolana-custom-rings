use serde::{Deserialize, Serialize};
use spr_indexer_api::{Base64String, Context, Hash, RpcMethod, SerializablePubkey};
use thiserror::Error;

/// Pages and opening batches include one authentication path per record.
pub const MAX_RING_MEMBER_PAGE_LIMIT: u64 = 100;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(i32)]
pub enum RingRpcError {
    #[error("the ring member registry indexer is catching up or recovering")]
    RegistryOutOfSync = -32070,
    #[error("the ring member registry root has changed")]
    RegistryRootChanged = -32071,
    #[error("the ring member registry page has an index gap or inconsistent leaf")]
    RegistryPageGap = -32075,
    #[error("the ring record queue moved under the request")]
    RecordQueueChanged = -32076,
}

impl RingRpcError {
    pub const ALL: [Self; 4] = [
        Self::RegistryOutOfSync,
        Self::RegistryRootChanged,
        Self::RegistryPageGap,
        Self::RecordQueueChanged,
    ];

    pub fn code(self) -> i32 {
        self as i32
    }

    pub fn from_code(code: i64) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|error| i64::from(error.code()) == code)
    }
}

pub mod method {
    use super::*;

    pub struct GetRingMemberRecord;
    pub struct GetRingMemberRecords;
    pub struct GetRingMemberOpenings;
    pub struct GetRingRecordPool;
    pub struct GetRingMemberRegistryRoot;
    pub struct GetRingRecordQueue;
    pub struct GetRingApplyProofInputs;
    pub struct GetStorageMemberOpenings;
    pub struct GetStorageRecordPool;
    pub struct GetStorageApplyProofInputs;

    impl RpcMethod for GetRingMemberRecord {
        const NAME: &'static str = "getRingMemberRecord";
        type Request = GetRingMemberRecordRequest;
        type Response = GetRingMemberRecordResponse;
    }

    impl RpcMethod for GetRingMemberRecords {
        const NAME: &'static str = "getRingMemberRecords";
        type Request = GetRingMemberRecordsRequest;
        type Response = GetRingMemberRecordsResponse;
    }

    impl RpcMethod for GetRingMemberOpenings {
        const NAME: &'static str = "getRingMemberOpenings";
        type Request = GetRingMemberOpeningsRequest;
        type Response = GetRingMemberOpeningsResponse;
    }

    impl RpcMethod for GetRingRecordPool {
        const NAME: &'static str = "getRingRecordPool";
        type Request = GetRingRecordPoolRequest;
        type Response = GetRingRecordPoolResponse;
    }

    impl RpcMethod for GetRingMemberRegistryRoot {
        const NAME: &'static str = "getRingMemberRegistryRoot";
        type Request = GetRingMemberRegistryRootRequest;
        type Response = GetRingMemberRegistryRootResponse;
    }

    impl RpcMethod for GetRingRecordQueue {
        const NAME: &'static str = "getRingRecordQueue";
        type Request = GetRingRecordQueueRequest;
        type Response = GetRingRecordQueueResponse;
    }

    impl RpcMethod for GetRingApplyProofInputs {
        const NAME: &'static str = "getRingApplyProofInputs";
        type Request = GetRingApplyProofInputsRequest;
        type Response = GetRingApplyProofInputsResponse;
    }

    impl RpcMethod for GetStorageMemberOpenings {
        const NAME: &'static str = "getStorageMemberOpenings";
        type Request = GetStorageMemberOpeningsRequest;
        type Response = GetStorageMemberOpeningsResponse;
    }

    impl RpcMethod for GetStorageRecordPool {
        const NAME: &'static str = "getStorageRecordPool";
        type Request = GetStorageRecordPoolRequest;
        type Response = GetStorageRecordPoolResponse;
    }

    impl RpcMethod for GetStorageApplyProofInputs {
        const NAME: &'static str = "getStorageApplyProofInputs";
        type Request = GetStorageApplyProofInputsRequest;
        type Response = GetStorageApplyProofInputsResponse;
    }
}

/// A record read at the exact root and append cursor the caller saw on chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingMemberRecordRequest {
    pub ring_program_id: SerializablePubkey,
    pub member: Hash,
    /// Any root the on-chain history still holds.
    pub expected_root: Hash,
    pub expected_next_index: u64,
}

/// Up to [`MAX_RING_MEMBER_PAGE_LIMIT`] members under one root the on-chain history holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingMemberOpeningsRequest {
    pub ring_program_id: SerializablePubkey,
    pub members: Vec<Hash>,
    pub expected_root: Hash,
}

/// Each member's record or low record under one root, a shared record opened once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingRecordPoolRequest {
    pub ring_program_id: SerializablePubkey,
    pub members: Vec<Hash>,
    pub expected_root: Hash,
    /// At least `members.len()` and at most [`MAX_RING_MEMBER_PAGE_LIMIT`].
    pub openings: u64,
}

/// Page real member leaves at one current, on-chain-checked registry root.
/// Leaf 0 is the sentinel. Start at 1 and pass `next_leaf_index` to continue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingMemberRecordsRequest {
    pub ring_program_id: SerializablePubkey,
    pub expected_root: Hash,
    pub expected_next_index: u64,
    pub start_index: u64,
    /// Between 1 and [`MAX_RING_MEMBER_PAGE_LIMIT`].
    pub limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingMemberRegistryRootRequest {
    pub ring_program_id: SerializablePubkey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingRecordQueueRequest {
    pub ring_program_id: SerializablePubkey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingApplyProofInputsRequest {
    pub ring_program_id: SerializablePubkey,
    /// Applied after every pending write.
    #[serde(default)]
    pub authority_writes: Vec<RingListWriteView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingListWriteView {
    pub mint_policy: Option<zolana_ring_policy::MintPolicy>,
    pub member: Hash,
    pub mask: u64,
    /// Lies inside `mask`.
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingRegistryRootView {
    pub root: Hash,
    /// The on-chain history slot of `root`.
    pub root_index: u8,
    /// The queue position applied at the root, checked against the registry floor.
    pub applied: u64,
    pub next_index: u64,
}

/// A member's record, with the sealed nullifier key once the member registered one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingMemberRecordView {
    pub member: Hash,
    pub next: Hash,
    /// Bit `i` marks list id `i + 1`.
    pub lists: u64,
    pub escrow_key: Hash,
    /// The RegisterKey signer whose owner tag hashes to `member`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_pubkey: Option<SerializablePubkey>,
    /// `escrow_key` is `Poseidon(nullifier_pk, hash_bytes(ciphertext))`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier_pk: Option<Hash>,
    /// Tagged X25519 ephemeral key of the sealed nullifier secret, 33 bytes.
    #[serde(default)]
    pub eph_pk: Option<Base64String>,
    /// AES-256-CTR ciphertext of the nullifier secret, 32 bytes.
    #[serde(default)]
    pub ciphertext: Option<Base64String>,
    pub mint_policy: zolana_ring_policy::MintPolicy,
}

/// A leaf index and the three siblings of every level in ascending child order, leaf level first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingRecordPathView {
    pub index: u64,
    pub siblings: Vec<[Hash; 3]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingMemberOpening {
    pub present: bool,
    /// Absent members open the low record, `record.member < member < record.next`.
    pub record: RingMemberRecordView,
    pub path: RingRecordPathView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingMemberRecordResponse {
    pub context: Context,
    pub root: RingRegistryRootView,
    pub opening: RingMemberOpening,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingMemberOpeningsResponse {
    pub context: Context,
    pub root: RingRegistryRootView,
    /// In request order.
    pub openings: Vec<RingMemberOpening>,
}

/// Each path stops below the canopy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingRecordPoolResponse {
    pub context: Context,
    pub root: RingRegistryRootView,
    /// Distinct leaves in first use order.
    pub records: Vec<RingIndexedMemberRecordView>,
    /// The narrowest tree level at least `openings` nodes wide.
    pub canopy: Vec<Hash>,
    /// The `records` index opening each requested member, in request order.
    pub subjects: Vec<u32>,
}

/// One contiguous member leaf and its authentication path at `root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingIndexedMemberRecordView {
    pub record: RingMemberRecordView,
    pub path: RingRecordPathView,
}

/// A complete leaf-index range. An indexer gap fails the call instead of
/// shortening the page. A changed root also fails, so pages cannot mix states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingMemberRecordsResponse {
    pub context: Context,
    pub root: RingRegistryRootView,
    pub records: Vec<RingIndexedMemberRecordView>,
    pub next_leaf_index: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingRootEntryView {
    pub root: Hash,
    pub applied: u64,
    pub slot: u64,
}

/// The projected registry at its tip, `append_path` opens the empty leaf at `next_index`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingMemberRegistryRootResponse {
    pub context: Context,
    /// Entry `i` sits at history slot `i`, `null` for a slot never written.
    pub history: Vec<Option<RingRootEntryView>>,
    /// The history slot of the newest root.
    pub history_cursor: u8,
    pub next_index: u64,
    /// The applied position every own-ring root must reach.
    pub floor: u64,
    pub prior_floor: u64,
    /// The slot of the last floor raise.
    pub floor_slot: u64,
    /// `null` once the registry is full.
    pub append_path: Option<RingRecordPathView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingQueueEntryView {
    pub position: u64,
    pub member: Hash,
    pub mask: u64,
    pub value: u64,
    /// Zero except on a RegisterKey write.
    pub escrow_key: Hash,
    pub slot: u64,
    pub mint_policy: Option<zolana_ring_policy::MintPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingRecordQueueResponse {
    pub context: Context,
    /// Position of the oldest pending write.
    pub head: u64,
    /// Position the next write takes.
    pub tail: u64,
    /// The queue chain through position `head - 1`, zero at head 0.
    pub chain_head: Hash,
    /// Positions `head..tail`.
    pub entries: Vec<RingQueueEntryView>,
}

/// Paths are under the root the preceding writes reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingRecordWriteView {
    pub member: Hash,
    pub mask: u64,
    pub value: u64,
    pub escrow_key: Hash,
    pub exists: bool,
    pub old_next: Hash,
    pub old_lists: u64,
    pub old_escrow: Hash,
    pub old_mint_policy: zolana_ring_policy::MintPolicy,
    /// The member's leaf, for an absent member the append leaf after its low record relinks.
    pub slot: RingRecordPathView,
    /// An absent member's low record, empty for a present member.
    pub low: RingMemberRecordView,
    pub low_path: RingRecordPathView,
    pub mint_policy: Option<zolana_ring_policy::MintPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingApplyProofInputsResponse {
    pub context: Context,
    pub old_root: Hash,
    pub new_root: Hash,
    pub old_next_index: u64,
    pub new_next_index: u64,
    pub chain_start: Hash,
    pub chain_end: Hash,
    /// In queue order.
    pub writes: Vec<RingRecordWriteView>,
}

/// Up to [`MAX_RING_MEMBER_PAGE_LIMIT`] members under one root the registry history holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetStorageMemberOpeningsRequest {
    /// A `StorageRegistry` account.
    pub registry: SerializablePubkey,
    pub members: Vec<Hash>,
    pub expected_root: Hash,
}

/// Each member's record or low record under one root, a shared record opened once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetStorageRecordPoolRequest {
    pub registry: SerializablePubkey,
    pub members: Vec<Hash>,
    pub expected_root: Hash,
    /// At least `members.len()` and at most [`MAX_RING_MEMBER_PAGE_LIMIT`].
    pub openings: u64,
}

/// The writes one `Update` carries, applied in order from the current root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetStorageApplyProofInputsRequest {
    pub registry: SerializablePubkey,
    pub writes: Vec<StorageWriteView>,
}

/// `StorageWriteData` on the wire, `escrow_key` zero except on an escrow write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StorageWriteView {
    pub member: Hash,
    pub mask: u64,
    /// Lies inside `mask`.
    pub value: u64,
    pub escrow_key: Hash,
    pub mint_policy: Option<zolana_ring_policy::MintPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StorageRootView {
    pub root: Hash,
    pub revision: u64,
    pub next_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetStorageMemberOpeningsResponse {
    pub context: Context,
    pub root: StorageRootView,
    /// In request order.
    pub openings: Vec<RingMemberOpening>,
}

/// Each path stops below the canopy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetStorageRecordPoolResponse {
    pub context: Context,
    pub root: StorageRootView,
    /// Distinct leaves in first use order.
    pub records: Vec<RingIndexedMemberRecordView>,
    /// The narrowest tree level at least `openings` nodes wide.
    pub canopy: Vec<Hash>,
    /// The `records` index opening each requested member, in request order.
    pub subjects: Vec<u32>,
}

/// `chain_start` binds the registry and `revision`, the revision `Update` names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetStorageApplyProofInputsResponse {
    pub context: Context,
    pub revision: u64,
    pub old_root: Hash,
    pub new_root: Hash,
    pub old_next_index: u64,
    pub new_next_index: u64,
    pub chain_start: Hash,
    pub chain_end: Hash,
    /// In request order.
    pub writes: Vec<RingRecordWriteView>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(
            RingRpcError::ALL.map(RingRpcError::code),
            [-32070, -32071, -32075, -32076]
        );
        for error in RingRpcError::ALL {
            assert_eq!(
                RingRpcError::from_code(i64::from(error.code())),
                Some(error)
            );
        }
        assert_eq!(RingRpcError::from_code(-32072), None);
        assert_eq!(RingRpcError::from_code(-32603), None);
    }
}
