//! Member record views as record tree types, every opening checked against its root.

use custom_ring_interface::{storage::StorageRegistry, RecordWrite, QUAD_ARITY};
use solana_address::Address;
use spr_indexer_api::Hash;
use zolana_ring_indexer::rpc::{
    GetStorageApplyProofInputsResponse, GetStorageMemberOpeningsRequest,
    GetStorageMemberOpeningsResponse, GetStorageMemberRecordsResponse,
    GetStorageRecordPoolResponse, RingMemberOpening, RingMemberRecordView, RingRecordPathView,
    RingRecordWriteView, MAX_RING_MEMBER_PAGE_LIMIT,
};
use zolana_ring_member_registry::{
    ApplyProofInputs, Canopy, MemberRecord, OpeningCheck, PoolSubject, QuadPath, QuadPathOf,
    RecordOpening, RecordPool, RecordWriteProofInput, SharedPath, SharedProof,
};
use zolana_ring_policy::{ListId, Member, MemberError};

use crate::AuditError;

/// `Poseidon(CRPL, owner identity, 0)`, the one record every writer and reader of the owner's lists
/// names.
pub fn owner_record_key(owner: &[u8; 32]) -> Result<Member, MemberError> {
    Member::public(&Member::owner_tag(owner)?)
}

/// A member's record, or the low record bracketing its absence, read under one root.
#[derive(Clone, PartialEq, Eq)]
pub struct MemberOpeningRead {
    pub opening: RecordOpening,
}

/// A registry's newest root, every record page is read under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageTip {
    pub registry: Address,
    pub root: [u8; 32],
    pub revision: u64,
}

/// Every record of a pool read under one root, each subject's own or the low record bracketing it.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordPoolRead {
    pool: RecordPool,
}

/// One pool read of distinct `members` under `root`, its canopy sized for `openings` paths.
#[must_use]
pub struct RecordPoolCheck<'a> {
    pub response: &'a GetStorageRecordPoolResponse,
    pub root: &'a [u8; 32],
    pub members: &'a [[u8; 32]],
    pub openings: usize,
}

impl RecordPoolCheck<'_> {
    pub fn verify(self) -> Result<RecordPoolRead, AuditError> {
        let response = self.response;
        let invalid = |_| AuditError::InvalidMemberRegistry;
        let canopy = Canopy::covering(self.openings).map_err(invalid)?;
        if response.root.root.0 != *self.root
            || response.canopy.len() != canopy.width()
            || response.subjects.len() != self.members.len()
        {
            return Err(AuditError::InvalidMemberRegistry);
        }
        let pool = RecordPool {
            records: response
                .records
                .iter()
                .map(|row| member_record(&row.record))
                .collect(),
            proof: SharedProof {
                canopy: response.canopy.iter().map(|node| node.0).collect(),
                paths: response
                    .records
                    .iter()
                    .map(|row| SharedPath {
                        index: row.path.index,
                        siblings: row
                            .path
                            .siblings
                            .iter()
                            .map(|level| level.clone().map(|sibling| sibling.0))
                            .collect(),
                    })
                    .collect(),
            },
            subjects: self
                .members
                .iter()
                .zip(&response.subjects)
                .map(|(member, record_index)| PoolSubject {
                    member: *member,
                    record_index: *record_index,
                })
                .collect(),
        };
        pool.verify(self.root).map_err(invalid)?;
        Ok(RecordPoolRead { pool })
    }
}

impl RecordPoolRead {
    pub fn pool(&self) -> &RecordPool {
        &self.pool
    }

    /// The member's record, `None` for an absent member or one outside the pool.
    pub fn record(&self, member: &[u8; 32]) -> Option<&MemberRecord> {
        self.position(member)
            .and_then(|index| self.pool.records.get(index))
            .filter(|record| record.member == *member)
    }

    fn position(&self, member: &[u8; 32]) -> Option<usize> {
        self.pool
            .subjects
            .iter()
            .find(|subject| subject.member == *member)
            .map(|subject| subject.record_index as usize)
    }
}

impl StorageTip {
    /// The newest root `account` holds, the one a reader proves against.
    pub fn newest(registry: Address, account: &StorageRegistry) -> Self {
        let newest = account.newest();
        Self {
            registry,
            root: newest.hash,
            revision: newest.revision.value(),
        }
    }

    pub fn openings_request(&self, members: &[[u8; 32]]) -> GetStorageMemberOpeningsRequest {
        GetStorageMemberOpeningsRequest {
            registry: self.registry.into(),
            members: members.iter().copied().map(Hash).collect(),
            expected_root: Hash(self.root),
        }
    }

    /// `members[i]` opened under the tip root, else the indexer response is invalid.
    pub fn verify_openings(
        &self,
        response: &GetStorageMemberOpeningsResponse,
        members: &[[u8; 32]],
    ) -> Result<Vec<MemberOpeningRead>, AuditError> {
        if response.openings.len() != members.len() {
            return Err(AuditError::InvalidMemberRegistry);
        }
        response
            .openings
            .iter()
            .zip(members)
            .map(|(view, member)| MemberOpeningRead::verify(view, &self.root, member))
            .collect()
    }

    /// `None` after the last page, refused unless the page holds every record from `start_index`.
    pub fn next_page(
        &self,
        page: &GetStorageMemberRecordsResponse,
        start_index: u64,
    ) -> Result<Option<u64>, AuditError> {
        let next_index = page.root.next_index;
        let end_index = start_index
            .saturating_add(MAX_RING_MEMBER_PAGE_LIMIT)
            .min(next_index);
        let complete = page.root.root.0 == self.root
            && page.root.revision == self.revision
            && start_index <= end_index
            && page.records.len() as u64 == end_index - start_index
            && page
                .records
                .iter()
                .zip(start_index..)
                .all(|(row, index)| row.path.index == index)
            && page.next_leaf_index == (end_index < next_index).then_some(end_index);
        complete
            .then_some(page.next_leaf_index)
            .ok_or(AuditError::InvalidMemberRegistry)
    }
}

impl MemberOpeningRead {
    /// `member`'s opening under `root`, refused unless the path reaches the root.
    pub fn verify(
        view: &RingMemberOpening,
        root: &[u8; 32],
        member: &[u8; 32],
    ) -> Result<Self, AuditError> {
        let record = member_record(&view.record);
        let path = quad_path(&view.path)?;
        let opening = match view.present {
            true => RecordOpening::Present { record, path },
            false => RecordOpening::Absent { low: record, path },
        };
        OpeningCheck {
            opening: &opening,
            root,
            member,
        }
        .verify()
        .map_err(|_| AuditError::InvalidMemberRegistry)?;
        Ok(Self { opening })
    }

    /// The member's record, `None` for an absent member.
    pub fn record(&self) -> Option<&MemberRecord> {
        match &self.opening {
            RecordOpening::Present { record, .. } => Some(record),
            RecordOpening::Absent { .. } => None,
        }
    }

    pub fn listed(&self, list: ListId) -> bool {
        self.record()
            .is_some_and(|record| record.lists & list.record_bit() != 0)
    }
}

/// Leaf level first.
pub fn path_of<const H: usize>(view: &RingRecordPathView) -> Result<QuadPathOf<H>, AuditError> {
    let levels: [[_; QUAD_ARITY - 1]; H] = view
        .siblings
        .iter()
        .map(|level| level.clone().map(|sibling| sibling.0))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| AuditError::InvalidMemberRegistry)?;
    Ok(QuadPathOf {
        index: view.index,
        siblings: levels,
    })
}

pub fn quad_path(view: &RingRecordPathView) -> Result<QuadPath, AuditError> {
    path_of(view)
}

pub fn member_record(view: &RingMemberRecordView) -> MemberRecord {
    MemberRecord {
        member: view.member.0,
        next: view.next.0,
        lists: view.lists,
        mint_policy: view.mint_policy,
    }
}

/// The proof inputs of one storage `Update`, in request order.
pub fn storage_apply_proof_inputs(
    response: &GetStorageApplyProofInputsResponse,
) -> Result<ApplyProofInputs, AuditError> {
    Ok(ApplyProofInputs {
        old_root: response.old_root.0,
        new_root: response.new_root.0,
        old_next_index: response.old_next_index,
        new_next_index: response.new_next_index,
        chain_start: response.chain_start.0,
        chain_end: response.chain_end.0,
        writes: record_writes(&response.writes)?,
    })
}

fn record_writes(views: &[RingRecordWriteView]) -> Result<Vec<RecordWriteProofInput>, AuditError> {
    views.iter().map(record_write).collect()
}

fn record_write(view: &RingRecordWriteView) -> Result<RecordWriteProofInput, AuditError> {
    Ok(RecordWriteProofInput {
        entry: RecordWrite {
            member: view.member.0,
            mask: view.mask,
            value: view.value,
            mint_policy: view.mint_policy,
        },
        exists: view.exists,
        old_next: view.old_next.0,
        old_lists: view.old_lists,
        old_mint_policy: view.old_mint_policy,
        slot: quad_path(&view.slot)?,
        low: member_record(&view.low),
        low_path: quad_path(&view.low_path)?,
    })
}
