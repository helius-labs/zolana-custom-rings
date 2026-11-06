use std::collections::{BTreeMap, BTreeSet};

use custom_ring_interface::QUAD_HEIGHT;
use thiserror::Error;
use zolana_ring_member_registry::MemoryTree;
pub use zolana_ring_member_registry::{
    ApplyProofInputs, Canopy, IndexedLeaf, IndexedRecord, MemberRecord, NodePosition, OpeningCheck,
    PoolSubject, QuadPath, QuadPathOf, RecordOpening, RecordPool, RecordPoolOf, RecordStore,
    RecordTree, RecordTreeError, RecordWriteProofInput, SharedPath, SharedProof, TrackingOpening,
    TrackingPath, TrackingPool, TrackingRecord, TrackingWriteProofInput, WritableLeaf,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberRead<L = MemberRecord> {
    Present(IndexedRecord<L>),
    Absent {
        member: [u8; 32],
        low: IndexedRecord<L>,
    },
}

/// `nodes` holds every node `node_keys` names whose subtree holds a record.
pub struct ReadRows<L = MemberRecord> {
    pub next_index: u64,
    pub reads: Vec<MemberRead<L>>,
    pub nodes: BTreeMap<NodePosition, [u8; 32]>,
}

impl<L: IndexedLeaf> ReadRows<L> {
    pub fn into_tree<const H: usize>(self) -> LoadedTree<L, H> {
        let mut records = BTreeMap::new();
        let mut absent = BTreeSet::new();
        for read in self.reads {
            let record = match read {
                MemberRead::Present(record) => record,
                MemberRead::Absent { member, low } => {
                    absent.insert(member);
                    low
                }
            };
            records.insert(*record.record.member(), record);
        }
        LoadedTree {
            next_index: self.next_index,
            nodes: self.nodes,
            records,
            absent,
            written: WrittenRows::default(),
        }
    }
}

pub struct WrittenRows<L = MemberRecord> {
    pub records: BTreeMap<[u8; 32], IndexedRecord<L>>,
    pub nodes: BTreeMap<NodePosition, [u8; 32]>,
}

impl<L> Default for WrittenRows<L> {
    fn default() -> Self {
        Self {
            records: BTreeMap::new(),
            nodes: BTreeMap::new(),
        }
    }
}

impl<L: IndexedLeaf> WrittenRows<L> {
    /// The rows of a tree holding only the sentinel, `H` its height.
    pub fn fresh<const H: usize>() -> Result<Self, RecordTreeError> {
        let tree = MemoryTree::<L, H>::new()?;
        let next_index = RecordStore::<L, H>::next_index(&tree)?;
        let mut nodes = BTreeMap::new();
        for level in 0..=H {
            let populated = (0..)
                .map(|position| NodePosition { level, position })
                .take_while(|at| !at.is_empty(next_index));
            for at in populated {
                nodes.insert(at, RecordStore::<L, H>::node(&tree, at)?);
            }
        }
        let records = (0..)
            .zip(tree.records())
            .map(|(index, record)| {
                let record = *record;
                (*record.member(), IndexedRecord { index, record })
            })
            .collect();
        Ok(Self { records, nodes })
    }
}

pub struct Application<W, L> {
    pub inputs: ApplyProofInputs<W>,
    pub rows: WrittenRows<L>,
}

#[derive(Debug, Error)]
pub enum LoadedTreeError {
    #[error(transparent)]
    Tree(#[from] RecordTreeError),
    #[error("storage did not load the record of a member the tree reads")]
    RecordNotLoaded,
}

pub struct LoadedTree<L = MemberRecord, const H: usize = QUAD_HEIGHT> {
    next_index: u64,
    nodes: BTreeMap<NodePosition, [u8; 32]>,
    records: BTreeMap<[u8; 32], IndexedRecord<L>>,
    /// Members storage read as absent, their low records are loaded.
    absent: BTreeSet<[u8; 32]>,
    written: WrittenRows<L>,
}

impl<L: WritableLeaf<H>, const H: usize> LoadedTree<L, H> {
    /// A failed batch drops the staged tree and leaves the caller's savepoint nothing to roll back.
    pub fn apply_batch(
        self,
        chain_start: [u8; 32],
        entries: &[L::Entry],
    ) -> Result<Application<L::WriteProof, L>, LoadedTreeError> {
        let applied = RecordTree::<L, H>::apply(self, chain_start, entries)?;
        Ok(Application {
            inputs: applied.proof,
            rows: applied.tree.written,
        })
    }
}

impl<L: IndexedLeaf, const H: usize> RecordStore<L, H> for LoadedTree<L, H> {
    type Error = LoadedTreeError;

    fn next_index(&self) -> Result<u64, LoadedTreeError> {
        Ok(self.next_index)
    }

    fn node(&self, at: NodePosition) -> Result<[u8; 32], LoadedTreeError> {
        let missing = RecordTreeError::NodeMissing {
            level: at.level,
            position: at.position,
        };
        Ok(*self.nodes.get(&at).ok_or(missing)?)
    }

    fn set_node(&mut self, at: NodePosition, node: [u8; 32]) -> Result<(), LoadedTreeError> {
        self.nodes.insert(at, node);
        self.written.nodes.insert(at, node);
        Ok(())
    }

    fn record(&self, member: &[u8; 32]) -> Result<Option<IndexedRecord<L>>, LoadedTreeError> {
        match self.records.get(member) {
            Some(record) => Ok(Some(*record)),
            None if self.absent.contains(member) => Ok(None),
            None => Err(LoadedTreeError::RecordNotLoaded),
        }
    }

    /// The loaded low record, or a record the batch inserted closer below `member`.
    fn low_record(&self, member: &[u8; 32]) -> Result<IndexedRecord<L>, LoadedTreeError> {
        if !self.absent.contains(member) {
            return Err(LoadedTreeError::RecordNotLoaded);
        }
        let (_, low) = self
            .records
            .range(..*member)
            .next_back()
            .ok_or(RecordTreeError::NotBracketed)?;
        Ok(*low)
    }

    fn set_record(&mut self, index: u64, record: L) -> Result<(), LoadedTreeError> {
        if index == self.next_index {
            self.next_index += 1;
        }
        let written = IndexedRecord { index, record };
        self.records.insert(*record.member(), written);
        self.written.records.insert(*record.member(), written);
        Ok(())
    }
}

/// The root and every node the openings of `leaves` read.
pub fn node_keys<const H: usize>(
    leaves: impl IntoIterator<Item = u64>,
) -> Result<BTreeSet<NodePosition>, RecordTreeError> {
    let mut keys = BTreeSet::from([NodePosition::root(H)]);
    for leaf in leaves {
        keys.extend(
            QuadPathOf::<H>::sibling_positions(leaf)?
                .into_iter()
                .flatten(),
        );
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::RecordWrite;

    use super::*;

    /// The sentinel tree with `member` read as absent, its low record the sentinel.
    fn loaded(member: [u8; 32]) -> LoadedTree {
        let fresh = WrittenRows::<MemberRecord>::fresh::<QUAD_HEIGHT>().unwrap();
        let low = *fresh.records.values().next().unwrap();
        ReadRows {
            next_index: 1,
            reads: vec![MemberRead::Absent { member, low }],
            nodes: fresh.nodes,
        }
        .into_tree()
    }

    fn write(byte: u8) -> RecordWrite {
        RecordWrite {
            member: [byte; 32],
            mask: 1,
            value: 1,
            mint_policy: None,
        }
    }

    #[test]
    fn a_batch_returns_its_proof_and_staged_rows() {
        let applied = loaded([1; 32]).apply_batch([0; 32], &[write(1)]).unwrap();
        assert_eq!(applied.inputs.writes.len(), 1);
        assert_eq!(applied.inputs.new_next_index, 2);
        assert!(applied.rows.records.contains_key(&[1; 32]));
    }

    /// A later entry fails after the first relinked its low record, the consumed tree leaves no rows to save.
    #[test]
    fn a_batch_failing_on_a_later_entry_returns_no_rows() {
        assert!(matches!(
            loaded([1; 32]).apply_batch([0; 32], &[write(1), write(2)]),
            Err(LoadedTreeError::RecordNotLoaded)
        ));
    }
}
