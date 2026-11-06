//! One indexed tree, generic over its leaf, and the writes an apply proof replays.
//!
//! The tree is off chain. Each write here runs in the order the apply circuit proves its steps, so the
//! proof input it returns opens the running root the circuit folds. A leaf type supplies its hash, the
//! fields a write moves and the entry the program chains.
//!
//! Read after `program-libs/member-registry/src/lib.rs`, `program-libs/member-registry/src/path.rs`.
//! Read before `program-libs/member-registry/src/memory.rs`, `program-libs/member-registry/src/record.rs`,
//! `prover/circuits/registry/apply_records.go`, `prover/circuits/registry/apply_enrollments.go`.

use core::marker::PhantomData;

use custom_ring_interface::{QUAD_ARITY, QUAD_HEIGHT};
use spr_hasher::HasherError;

use crate::{
    path::{capacity, children, quad_node, NodePosition, QuadPathOf, ZERO_SUBTREES},
    record::check_member,
    record_pool::{Canopy, PoolSubject, RecordPoolOf, SharedPath, SharedProof},
    MemberRecord, RecordTreeError,
};

/// A sorted linked leaf, a member's absence opens the low leaf bracketing it.
pub trait IndexedLeaf: Copy {
    const SENTINEL: Self;
    /// Levels of the leaf's tree.
    const HEIGHT: usize;

    fn member(&self) -> &[u8; 32];

    fn next(&self) -> &[u8; 32];

    #[must_use]
    fn relinked(self, next: [u8; 32]) -> Self;

    fn leaf_hash(&self) -> Result<[u8; 32], HasherError>;

    /// Holds nothing but its member and link.
    fn is_blank(&self) -> bool;

    fn blank(member: [u8; 32], next: [u8; 32]) -> Self;

    fn brackets(&self, member: &[u8; 32]) -> bool {
        self.member() < member && member < self.next()
    }
}

/// A leaf an apply proof moves, `H` is the height of its tree.
pub trait WritableLeaf<const H: usize>: IndexedLeaf {
    type Entry: Copy;
    type WriteProof;

    fn entry_member(entry: &Self::Entry) -> &[u8; 32];

    /// Refuses an entry the program never chains, ahead of any write.
    fn check_entry(entry: &Self::Entry) -> Result<(), RecordTreeError>;

    fn chained(previous: &[u8; 32], entry: &Self::Entry) -> Result<[u8; 32], HasherError>;

    fn after(self, entry: &Self::Entry) -> Result<Self, RecordTreeError>;

    fn write_proof(entry: Self::Entry, step: WriteStep<Self, H>) -> Self::WriteProof;
}

/// What one write opened, in the order the apply circuit proves its steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteStep<L, const H: usize> {
    Present {
        old: L,
        slot: QuadPathOf<H>,
    },
    Absent {
        low: L,
        low_path: QuadPathOf<H>,
        /// The `next_index` leaf after the relink, the low leaf for a no-op on a full tree.
        slot: QuadPathOf<H>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedRecord<L = MemberRecord> {
    pub index: u64,
    pub record: L,
}

/// One tree's nodes and records, the tree reads no node of an empty subtree from it.
pub trait RecordStore<L: IndexedLeaf = MemberRecord, const H: usize = QUAD_HEIGHT> {
    type Error: From<RecordTreeError>;

    /// The leaf the next insert takes.
    fn next_index(&self) -> Result<u64, Self::Error>;

    /// A node the store does not hold is an error, never a zero.
    fn node(&self, at: NodePosition) -> Result<[u8; 32], Self::Error>;

    fn set_node(&mut self, at: NodePosition, node: [u8; 32]) -> Result<(), Self::Error>;

    fn record(&self, member: &[u8; 32]) -> Result<Option<IndexedRecord<L>>, Self::Error>;

    /// The record of the greatest member below `member`.
    fn low_record(&self, member: &[u8; 32]) -> Result<IndexedRecord<L>, Self::Error>;

    /// Replaces the record at `index`, or appends it when `index` is `next_index`.
    fn set_record(&mut self, index: u64, record: L) -> Result<(), Self::Error>;
}

/// A member under one root, its record or the low record bracketing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordOpening<L = MemberRecord, const H: usize = QUAD_HEIGHT> {
    Present { record: L, path: QuadPathOf<H> },
    Absent { low: L, path: QuadPathOf<H> },
}

#[must_use]
pub struct OpeningCheck<'a, L = MemberRecord, const H: usize = QUAD_HEIGHT> {
    pub opening: &'a RecordOpening<L, H>,
    pub root: &'a [u8; 32],
    pub member: &'a [u8; 32],
}

impl<L: IndexedLeaf, const H: usize> OpeningCheck<'_, L, H> {
    /// The member's record under `root`, `None` for an absent member.
    pub fn verify(self) -> Result<Option<L>, RecordTreeError> {
        let member = self.member;
        check_member(member)?;
        let (leaf, path, present) = match self.opening {
            RecordOpening::Present { record, path } if record.member() == member => {
                (record, path, Some(*record))
            }
            RecordOpening::Absent { low, path } if low.brackets(member) => (low, path, None),
            RecordOpening::Present { .. } | RecordOpening::Absent { .. } => {
                return Err(RecordTreeError::NotBracketed)
            }
        };
        if path.root(leaf.leaf_hash()?)? != *self.root {
            return Err(RecordTreeError::RootMismatch);
        }
        Ok(present)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyProofInputs<W = crate::RecordWriteProofInput> {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub old_next_index: u64,
    pub new_next_index: u64,
    pub chain_start: [u8; 32],
    pub chain_end: [u8; 32],
    /// Chain order.
    pub writes: Vec<W>,
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedTree<T, W = crate::RecordWriteProofInput> {
    pub tree: T,
    pub proof: ApplyProofInputs<W>,
}

pub trait RecordTree<L: IndexedLeaf = MemberRecord, const H: usize = QUAD_HEIGHT>:
    RecordStore<L, H>
{
    fn root(&self) -> Result<[u8; 32], Self::Error> {
        Filled::of(self)?.node(NodePosition::root(H))
    }

    fn path(&self, index: u64) -> Result<QuadPathOf<H>, Self::Error> {
        Filled::of(self)?.path(index)
    }

    fn opening(&self, member: &[u8; 32]) -> Result<RecordOpening<L, H>, Self::Error> {
        check_member(member)?;
        Ok(match self.record(member)? {
            Some(IndexedRecord { index, record }) => RecordOpening::Present {
                record,
                path: self.path(index)?,
            },
            None => {
                let IndexedRecord { index, record } = self.low_record(member)?;
                if !record.brackets(member) {
                    return Err(RecordTreeError::NotBracketed.into());
                }
                RecordOpening::Absent {
                    low: record,
                    path: self.path(index)?,
                }
            }
        })
    }

    /// Each member's record or low record once.
    fn record_pool(
        &self,
        members: &[[u8; 32]],
        canopy: Canopy,
    ) -> Result<RecordPoolOf<L>, Self::Error> {
        if members.len() > canopy.width() {
            return Err(RecordTreeError::PoolCapacity.into());
        }
        if canopy.height() != H {
            return Err(RecordTreeError::PoolShape.into());
        }
        let mut records: Vec<L> = Vec::new();
        let mut paths: Vec<SharedPath> = Vec::new();
        let mut subjects = Vec::with_capacity(members.len());
        for member in members {
            let (RecordOpening::Present { record, path }
            | RecordOpening::Absent { low: record, path }) = self.opening(member)?;
            let record_index = match paths.iter().position(|known| known.index == path.index) {
                Some(index) => index,
                None => {
                    records.push(record);
                    paths.push(SharedPath {
                        index: path.index,
                        siblings: path.siblings[..canopy.path_levels()].to_vec(),
                    });
                    records.len() - 1
                }
            };
            subjects.push(PoolSubject {
                member: *member,
                record_index: u32::try_from(record_index)
                    .map_err(|_| RecordTreeError::PoolCapacity)?,
            });
        }
        let filled = Filled::of(self)?;
        Ok(RecordPoolOf {
            records,
            proof: SharedProof {
                canopy: canopy
                    .positions()
                    .map(|at| filled.node(at))
                    .collect::<Result<_, _>>()?,
                paths,
            },
            subjects,
        })
    }

    /// Consumes owned staging storage and returns it only after the complete batch succeeds.
    /// An error drops the staging store, including any partial writes.
    /// Store implementations must isolate writes from accepted state until success.
    /// Persistent storage requires a separate transaction for atomic publication.
    fn apply(
        mut self,
        chain_start: [u8; 32],
        entries: &[L::Entry],
    ) -> Result<AppliedTree<Self, L::WriteProof>, Self::Error>
    where
        Self: Sized,
        L: WritableLeaf<H>,
    {
        let next_index = self.next_index()?;
        let proof = Growing {
            store: &mut self,
            next_index,
            leaf: PhantomData,
        }
        .apply_batch(chain_start, entries)?;
        Ok(AppliedTree { tree: self, proof })
    }
}

impl<L: IndexedLeaf, const H: usize, S: RecordStore<L, H> + ?Sized> RecordTree<L, H> for S {}

/// The store with every leaf from `next_index` on empty.
struct Filled<'s, S: ?Sized, L, const H: usize> {
    store: &'s S,
    next_index: u64,
    leaf: PhantomData<L>,
}

impl<'s, L: IndexedLeaf, const H: usize, S: RecordStore<L, H> + ?Sized> Filled<'s, S, L, H> {
    fn of(store: &'s S) -> Result<Self, S::Error> {
        Ok(Self {
            next_index: store.next_index()?,
            store,
            leaf: PhantomData,
        })
    }

    fn node(&self, at: NodePosition) -> Result<[u8; 32], S::Error> {
        if at.is_empty(self.next_index) {
            return Ok(ZERO_SUBTREES[at.level]);
        }
        self.store.node(at)
    }

    fn path(&self, index: u64) -> Result<QuadPathOf<H>, S::Error> {
        let mut siblings = [[[0u8; 32]; QUAD_ARITY - 1]; H];
        for (level, positions) in QuadPathOf::<H>::sibling_positions(index)?
            .iter()
            .enumerate()
        {
            for (sibling, at) in siblings[level].iter_mut().zip(positions) {
                *sibling = self.node(*at)?;
            }
        }
        Ok(QuadPathOf { index, siblings })
    }
}

/// The store an application writes, `next_index` advancing at each insert.
struct Growing<'s, S: ?Sized, L, const H: usize> {
    store: &'s mut S,
    next_index: u64,
    leaf: PhantomData<L>,
}

impl<L: IndexedLeaf, const H: usize, S: RecordStore<L, H> + ?Sized> Growing<'_, S, L, H> {
    fn filled(&self) -> Filled<'_, S, L, H> {
        Filled {
            store: self.store,
            next_index: self.next_index,
            leaf: PhantomData,
        }
    }

    /// Writes the record and every node from its leaf to the root.
    fn write(&mut self, index: u64, record: L) -> Result<(), S::Error> {
        let path = self.filled().path(index)?;
        self.store.set_record(index, record)?;
        let mut node = record.leaf_hash().map_err(RecordTreeError::from)?;
        for (level, siblings) in path.siblings.iter().enumerate() {
            let at = NodePosition::on_path(index, level);
            self.store.set_node(at, node)?;
            node =
                quad_node(&children(node, at.digit(), siblings)).map_err(RecordTreeError::from)?;
        }
        self.store.set_node(NodePosition::root(H), node)
    }
}

impl<L: WritableLeaf<H>, const H: usize, S: RecordStore<L, H> + ?Sized> Growing<'_, S, L, H> {
    fn apply_batch(
        &mut self,
        chain_start: [u8; 32],
        entries: &[L::Entry],
    ) -> Result<ApplyProofInputs<L::WriteProof>, S::Error> {
        // 1. Every entry must pass its independent checks before the first write.
        // Record state and storage failures can still reject a later step.
        entries.iter().try_for_each(L::check_entry)?;
        // 2. The original root and next index anchor the proof before any staged mutation.
        let old_root = self.filled().node(NodePosition::root(H))?;
        let old_next_index = self.next_index;
        // 3. Proof steps and the entry chain follow the same batch order.
        // Each opening uses the running root, and the chain includes entries that leave the root unchanged.
        let mut chain_end = chain_start;
        let mut writes = Vec::with_capacity(entries.len());
        for entry in entries {
            writes.push(self.apply(entry)?);
            chain_end = L::chained(&chain_end, entry).map_err(RecordTreeError::from)?;
        }
        // 4. The final root completes the proof before `RecordTree::apply` can return the owned store.
        // Any error propagates to that consuming boundary and discards the staged state.
        Ok(ApplyProofInputs {
            old_root,
            new_root: self.filled().node(NodePosition::root(H))?,
            old_next_index,
            new_next_index: self.next_index,
            chain_start,
            chain_end,
            writes,
        })
    }

    /// One write in the order the apply circuit proves its steps.
    fn apply(&mut self, entry: &L::Entry) -> Result<L::WriteProof, S::Error> {
        let member = L::entry_member(entry);
        // 1. A present member's write replaces its own leaf.
        if let Some(IndexedRecord { index, record }) = self.store.record(member)? {
            let slot = self.filled().path(index)?;
            self.write(index, record.after(entry)?)?;
            return Ok(L::write_proof(
                *entry,
                WriteStep::Present { old: record, slot },
            ));
        }
        // 2. An absent member lies strictly inside its low record's link under the running root.
        let IndexedRecord {
            index: low_index,
            record: low,
        } = self.store.low_record(member)?;
        if !low.brackets(member) {
            return Err(RecordTreeError::NotBracketed.into());
        }
        let low_path = self.filled().path(low_index)?;
        let inserted = L::blank(*member, *low.next()).after(entry)?;
        let full = self.next_index >= capacity(H);
        // An empty record is never inserted, the write proves the absence and keeps the root.
        if inserted.is_blank() {
            // The circuit range-checks a no-op's slot and nothing else.
            let slot = if full {
                low_path
            } else {
                self.filled().path(self.next_index)?
            };
            return Ok(L::write_proof(
                *entry,
                WriteStep::Absent {
                    low,
                    low_path,
                    slot,
                },
            ));
        }
        if full {
            return Err(RecordTreeError::Full.into());
        }
        // 3. An insert relinks the low record first, the new leaf's path then reads the relinked root the circuit folds.
        self.write(low_index, low.relinked(*member))?;
        let slot = self.filled().path(self.next_index)?;
        self.write(self.next_index, inserted)?;
        self.next_index += 1;
        Ok(L::write_proof(
            *entry,
            WriteStep::Absent {
                low,
                low_path,
                slot,
            },
        ))
    }
}
