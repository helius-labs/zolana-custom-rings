//! The tracking tree's leaf, one indexed tree per ring holding every enrolled key.
//!
//! Read after `program-libs/member-registry/src/tree.rs`, `program-libs/interface/src/accounts/tracking.rs`.
//! Read before `prover/circuits/registry/tracking.go`, `prover/circuits/registry/apply_enrollments.go`.
//!
//! Invariants, `ApplyEnrollmentsCircuit` holds each.
//! 1. Every write inserts an absent owner, only a row's successor link moves after insert.
//! 2. An insert takes the next empty leaf, so a full tree refuses a new owner.

use custom_ring_interface::{
    domain,
    tracking::{TrackingEntry, TRACKING_QUAD_HEIGHT},
    ApplyEnrollmentsStatement, FIELD_MAX,
};
use spr_hasher::{Hasher, HasherError, Poseidon};

use crate::{
    memory::MemoryTree,
    record::check_member,
    record_pool::RecordPoolOf,
    tree::{ApplyProofInputs, IndexedLeaf, RecordOpening, WritableLeaf, WriteStep},
    RecordTreeError, TrackingPath,
};

/// One enrolled owner, a zero `nullifier_pk` marks the sentinel and an unwritten leaf.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrackingRecord {
    pub member: [u8; 32],
    pub next: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub ct_hash: [u8; 32],
    pub list_tag: [u8; 32],
}

pub type TrackingTree = MemoryTree<TrackingRecord, TRACKING_QUAD_HEIGHT>;
pub type TrackingOpening = RecordOpening<TrackingRecord, TRACKING_QUAD_HEIGHT>;
pub type TrackingPool = RecordPoolOf<TrackingRecord>;

/// One entry's proof input, mirror `EnrollmentWrite` of
/// `prover/circuits/registry/apply_enrollments.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackingWriteProofInput {
    pub entry: TrackingEntry,
    /// The `next_index` leaf after the relink.
    pub slot: TrackingPath,
    /// The low record and its path before the relink.
    pub low: TrackingRecord,
    pub low_path: TrackingPath,
}

impl TrackingRecord {
    /// Leaf 0, every member sorts strictly between it and `FIELD_MAX`.
    pub const SENTINEL: Self = Self {
        member: [0; 32],
        next: FIELD_MAX,
        nullifier_pk: [0; 32],
        ct_hash: [0; 32],
        list_tag: [0; 32],
    };

    /// `Poseidon(CRTK, member, next, nullifier_pk, ct_hash, list_tag)`, mirror
    /// `prover/circuits/registry/tracking.go`.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &domain::field(domain::TRACKING_LEAF),
            &self.member,
            &self.next,
            &self.nullifier_pk,
            &self.ct_hash,
            &self.list_tag,
        ])
    }

    pub fn brackets(&self, member: &[u8; 32]) -> bool {
        self.member < *member && *member < self.next
    }
}

impl IndexedLeaf for TrackingRecord {
    const SENTINEL: Self = Self::SENTINEL;
    const HEIGHT: usize = TRACKING_QUAD_HEIGHT;

    fn member(&self) -> &[u8; 32] {
        &self.member
    }

    fn next(&self) -> &[u8; 32] {
        &self.next
    }

    fn relinked(self, next: [u8; 32]) -> Self {
        Self { next, ..self }
    }

    fn leaf_hash(&self) -> Result<[u8; 32], HasherError> {
        self.hash()
    }

    fn is_blank(&self) -> bool {
        self.nullifier_pk == [0; 32]
    }

    fn blank(member: [u8; 32], next: [u8; 32]) -> Self {
        Self {
            member,
            next,
            ..Self::default()
        }
    }
}

impl WritableLeaf<TRACKING_QUAD_HEIGHT> for TrackingRecord {
    type Entry = TrackingEntry;
    type WriteProof = TrackingWriteProofInput;

    fn entry_member(entry: &TrackingEntry) -> &[u8; 32] {
        &entry.member
    }

    fn check_entry(entry: &TrackingEntry) -> Result<(), RecordTreeError> {
        check_member(&entry.member)?;
        if entry.nullifier_pk == [0; 32] {
            return Err(RecordTreeError::TrackingKeyChanged);
        }
        Ok(())
    }

    fn chained(previous: &[u8; 32], entry: &TrackingEntry) -> Result<[u8; 32], HasherError> {
        entry.chained(previous)
    }

    /// A present owner refuses, the apply circuit only inserts.
    fn after(self, entry: &TrackingEntry) -> Result<Self, RecordTreeError> {
        if !self.is_blank() {
            return Err(RecordTreeError::TrackingOwnerPresent);
        }
        Ok(Self {
            nullifier_pk: entry.nullifier_pk,
            ct_hash: entry.ct_hash,
            list_tag: entry.list_tag,
            ..self
        })
    }

    /// `after` refused a present owner before the tree built a `Present` step, the slot alone stands.
    fn write_proof(
        entry: TrackingEntry,
        step: WriteStep<Self, TRACKING_QUAD_HEIGHT>,
    ) -> TrackingWriteProofInput {
        match step {
            WriteStep::Present { slot, .. } => TrackingWriteProofInput {
                entry,
                slot,
                low: Self::default(),
                low_path: TrackingPath::default(),
            },
            WriteStep::Absent {
                low,
                low_path,
                slot,
            } => TrackingWriteProofInput {
                entry,
                slot,
                low,
                low_path,
            },
        }
    }
}

impl ApplyProofInputs<TrackingWriteProofInput> {
    pub fn statement(&self) -> ApplyEnrollmentsStatement {
        ApplyEnrollmentsStatement {
            old_root: self.old_root,
            new_root: self.new_root,
            old_next_index: self.old_next_index,
            new_next_index: self.new_next_index,
            chain_start: self.chain_start,
            chain_end: self.chain_end,
            count: self.writes.len() as u64,
        }
    }
}
