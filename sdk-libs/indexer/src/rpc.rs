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
    // -32076 retired.
}

impl RingRpcError {
    pub const ALL: [Self; 3] = [
        Self::RegistryOutOfSync,
        Self::RegistryRootChanged,
        Self::RegistryPageGap,
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

    pub struct GetStorageMemberOpenings;
    pub struct GetStorageMemberRecords;
    pub struct GetStorageRecordPool;
    pub struct GetStorageApplyProofInputs;

    impl RpcMethod for GetStorageMemberOpenings {
        const NAME: &'static str = "getStorageMemberOpenings";
        type Request = GetStorageMemberOpeningsRequest;
        type Response = GetStorageMemberOpeningsResponse;
    }

    impl RpcMethod for GetStorageMemberRecords {
        const NAME: &'static str = "getStorageMemberRecords";
        type Request = GetStorageMemberRecordsRequest;
        type Response = GetStorageMemberRecordsResponse;
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

/// Leaves from `start_index` under one root the registry history holds, leaf 0 the sentinel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetStorageMemberRecordsRequest {
    pub registry: SerializablePubkey,
    pub expected_root: Hash,
    pub start_index: u64,
    /// Between 1 and [`MAX_RING_MEMBER_PAGE_LIMIT`].
    pub limit: u64,
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

/// A member's record, with the sealed nullifier key once the member registered one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingMemberRecordView {
    pub member: Hash,
    pub next: Hash,
    /// Bit `i` marks list id `i + 1`.
    pub lists: u64,
    pub escrow_key: Hash,
    /// The escrow write's owner, its owner tag hashes to `member`.
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

/// One contiguous member leaf and its authentication path at `root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingIndexedMemberRecordView {
    pub record: RingMemberRecordView,
    pub path: RingRecordPathView,
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

/// The leaf write of a `StorageWriteData`, `escrow_key` zero except on an escrow write.
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

impl From<&custom_ring_interface::QueueEntry> for StorageWriteView {
    fn from(entry: &custom_ring_interface::QueueEntry) -> Self {
        Self {
            member: Hash(entry.member),
            mask: entry.mask,
            value: entry.value,
            escrow_key: Hash(entry.escrow_key),
            mint_policy: entry.mint_policy,
        }
    }
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

/// A complete leaf range, an indexer gap fails the call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetStorageMemberRecordsResponse {
    pub context: Context,
    pub root: StorageRootView,
    pub records: Vec<RingIndexedMemberRecordView>,
    pub next_leaf_index: Option<u64>,
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
            [-32070, -32071, -32075]
        );
        for error in RingRpcError::ALL {
            assert_eq!(
                RingRpcError::from_code(i64::from(error.code())),
                Some(error)
            );
        }
        assert_eq!(RingRpcError::from_code(-32072), None);
        assert_eq!(RingRpcError::from_code(-32076), None);
        assert_eq!(RingRpcError::from_code(-32603), None);
    }
}
