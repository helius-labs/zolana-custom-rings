use std::{cell::RefCell, rc::Rc};

use custom_ring_interface::RecordWrite;
use spr_hasher::primitives::right_align;
use zolana_ring_member_registry::{
    AppliedTree, IndexedRecord, MemberRecord, MemberRegistryTree, NodePosition, RecordStore,
    RecordTree, RecordTreeError,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum StoreError {
    #[error(transparent)]
    Tree(#[from] RecordTreeError),
    #[error("insert refused")]
    InsertRefused,
}

#[derive(Default)]
struct Observed {
    dropped: bool,
    root_at_failure: Option<[u8; 32]>,
    next_index_at_failure: Option<u64>,
    low_at_failure: Option<MemberRecord>,
}

struct StagedStore {
    tree: MemberRegistryTree,
    rejected_member: [u8; 32],
    observed: Rc<RefCell<Observed>>,
}

struct RefusedBatch<'a> {
    entries: &'a [RecordWrite],
    predecessor: [u8; 32],
    next_index: u64,
}

impl Drop for StagedStore {
    fn drop(&mut self) {
        self.observed.borrow_mut().dropped = true;
    }
}

impl RecordStore for StagedStore {
    type Error = StoreError;

    fn next_index(&self) -> Result<u64, Self::Error> {
        self.tree.next_index().map_err(Into::into)
    }

    fn node(&self, at: NodePosition) -> Result<[u8; 32], Self::Error> {
        self.tree.node(at).map_err(Into::into)
    }

    fn set_node(&mut self, at: NodePosition, node: [u8; 32]) -> Result<(), Self::Error> {
        self.tree.set_node(at, node).map_err(Into::into)
    }

    fn record(&self, member: &[u8; 32]) -> Result<Option<IndexedRecord>, Self::Error> {
        self.tree.record(member).map_err(Into::into)
    }

    fn low_record(&self, member: &[u8; 32]) -> Result<IndexedRecord, Self::Error> {
        self.tree.low_record(member).map_err(Into::into)
    }

    fn set_record(&mut self, index: u64, record: MemberRecord) -> Result<(), Self::Error> {
        if record.member == self.rejected_member {
            let mut observed = self.observed.borrow_mut();
            observed.root_at_failure = Some(self.tree.root()?);
            observed.next_index_at_failure = Some(self.tree.next_index()?);
            observed.low_at_failure = Some(self.tree.low_record(&record.member)?.record);
            return Err(StoreError::InsertRefused);
        }
        self.tree.set_record(index, record).map_err(Into::into)
    }
}

impl RefusedBatch<'_> {
    fn check(self) {
        let committed = MemberRegistryTree::new().unwrap();
        let original = committed.clone();
        let rejected_member = self.entries.last().unwrap().member;
        let observed = Rc::new(RefCell::new(Observed::default()));
        let staged = StagedStore {
            tree: committed.clone(),
            rejected_member,
            observed: Rc::clone(&observed),
        };

        let result = staged.apply([0; 32], self.entries);

        assert!(matches!(result, Err(StoreError::InsertRefused)));
        assert_eq!(committed, original);
        let observed = observed.borrow();
        assert!(observed.dropped);
        assert_ne!(observed.root_at_failure, Some(committed.root().unwrap()));
        assert_eq!(observed.next_index_at_failure, Some(self.next_index));
        let predecessor = observed.low_at_failure.unwrap();
        assert_eq!(predecessor.member, self.predecessor);
        assert_eq!(predecessor.next, rejected_member);
        for entry in self.entries {
            assert_eq!(committed.record(&entry.member).unwrap(), None);
        }
    }
}

fn write(member: u8) -> RecordWrite {
    RecordWrite {
        mint_policy: Default::default(),
        member: right_align(&[member]),
        mask: 1,
        value: 1,
    }
}

#[test]
fn failure_after_predecessor_relink_drops_the_staged_tree() {
    RefusedBatch {
        entries: &[write(9)],
        predecessor: [0; 32],
        next_index: 1,
    }
    .check();
}

#[test]
fn failure_in_a_later_entry_publishes_no_partial_batch() {
    RefusedBatch {
        entries: &[write(4), write(9)],
        predecessor: write(4).member,
        next_index: 2,
    }
    .check();
}

#[test]
fn successful_batch_returns_its_tree_with_the_matching_proof() {
    let committed = MemberRegistryTree::new().unwrap();
    let original_root = committed.root().unwrap();
    let entries = [write(4), write(9)];
    let AppliedTree { tree, proof } = committed.apply([0; 32], &entries).unwrap();

    assert_eq!(proof.old_root, original_root);
    assert_eq!(proof.new_root, tree.root().unwrap());
    assert_eq!(proof.new_next_index, tree.next_index().unwrap());
    assert_eq!(proof.writes.len(), entries.len());
    for entry in entries {
        assert_eq!(tree.record(&entry.member).unwrap().unwrap().record.lists, 1);
    }
}
