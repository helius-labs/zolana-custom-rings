//! The 4-ary indexed trees of a ring, one apply and one opening over any [`RecordStore`].
//!
//! The Storage program holds roots alone, and no program links the crate. The SDK, the indexer and Ring
//! RPC replay a tree from the published writes, then hand a prover its openings and apply inputs. A
//! policy rule needs a proof of absence as well as of presence, a blocked owner must not pass by leaving
//! its record out, so each leaf links to the next member in sort order.
//!
//! Read after `docs/design/records-and-roots.md`, `program-libs/interface/src/accounts/member_registry.rs`.
//! Read before `program-libs/member-registry/src/path.rs`, `program-libs/member-registry/src/tree.rs`,
//! `program-libs/member-registry/src/record.rs`, `program-libs/member-registry/src/tracking.rs`,
//! `program-libs/member-registry/src/record_pool.rs`.
//!
//! Invariants.
//! 1. Leaf 0 is the sentinel `(0, q - 1)`, a registry's first root folds it, and strict bracketing keeps every member in `[1, q - 2]`, so exactly one leaf brackets an absent member.
//! 2. An insert relinks the low leaf to the member and takes the next empty leaf with the low leaf's old link, so the links stay one list sorted by member while the leaves stay in insert order.
//! 3. A member keeps its leaf for good, and a full tree takes no new member.
//! 4. An empty leaf is zero, and `ZERO_SUBTREES` roots an empty subtree of each height.

mod memory;
mod path;
mod record;
mod record_pool;
mod tracking;
mod tree;

use spr_hasher::HasherError;
use thiserror::Error;

pub use memory::{MemberRegistryTree, MemoryTree};
pub use path::{quad_node, NodePosition, QuadPath, QuadPathOf, TrackingPath, ZERO_SUBTREES};
pub use record::{
    MemberRecord, RecordStatementContext, RecordStatementError, RecordTracking,
    RecordWriteProofInput,
};
pub use record_pool::{Canopy, PoolSubject, RecordPool, RecordPoolOf, SharedPath, SharedProof};
pub use tracking::{
    TrackingOpening, TrackingPool, TrackingRecord, TrackingTree, TrackingWriteProofInput,
};
pub use tree::{
    AppliedTree, ApplyProofInputs, IndexedLeaf, IndexedRecord, OpeningCheck, RecordOpening,
    RecordStore, RecordTree, WritableLeaf, WriteStep,
};

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RecordTreeError {
    #[error("record tree hashing failed")]
    Hashing,
    #[error("member lies outside the record range")]
    MemberOutOfRange,
    #[error("a list value leaves its mask")]
    ValueOutsideMask,
    #[error("the record tree is full")]
    Full,
    #[error("leaf index lies outside the tree")]
    IndexOutOfRange,
    #[error("the store holds no node at level {level} position {position}")]
    NodeMissing { level: usize, position: u64 },
    #[error("the store holds no record at index {0}")]
    RecordMissing(u64),
    #[error("the record at index {0} belongs to another member")]
    ForeignRecord(u64),
    #[error("the low record does not bracket the member")]
    NotBracketed,
    #[error("the path does not reach the root")]
    RootMismatch,
    #[error("the first record is not the sentinel")]
    MissingSentinel,
    #[error("a member holds two records")]
    DuplicateMember,
    #[error("the record pool exceeds its capacity")]
    PoolCapacity,
    #[error("the record pool proof has the wrong shape")]
    PoolShape,
    #[error("a tracking entry names a zero key")]
    TrackingKeyChanged,
    #[error("a tracking entry names an owner the tree already holds")]
    TrackingOwnerPresent,
}

impl From<HasherError> for RecordTreeError {
    fn from(_: HasherError) -> Self {
        Self::Hashing
    }
}
