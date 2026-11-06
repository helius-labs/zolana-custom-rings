use custom_ring_interface::{
    tracking::{TrackingEntry, TRACKING_CAPACITY, TRACKING_QUAD_HEIGHT},
    FIELD_MAX,
};
use spr_hasher::primitives::right_align;
use zolana_ring_member_registry::{
    AppliedTree, ApplyProofInputs, Canopy, IndexedRecord, NodePosition, OpeningCheck,
    RecordOpening, RecordStore, RecordTree, RecordTreeError, TrackingPath, TrackingRecord,
    TrackingTree, TrackingWriteProofInput,
};

fn member(byte: u8) -> [u8; 32] {
    right_align(&[byte])
}

fn entry(byte: u8) -> TrackingEntry {
    TrackingEntry {
        member: member(byte),
        nullifier_pk: member(byte ^ 0x40),
        ct_hash: member(byte ^ 0x50),
        list_tag: member(byte ^ 0x70),
    }
}

/// Keeps the tree on a refusal, as an indexer keeps its accepted state.
fn apply(
    tree: &mut TrackingTree,
    chain_start: [u8; 32],
    entries: &[TrackingEntry],
) -> Result<ApplyProofInputs<TrackingWriteProofInput>, RecordTreeError> {
    let AppliedTree { tree: next, proof } = tree.clone().apply(chain_start, entries)?;
    *tree = next;
    Ok(proof)
}

fn record(tree: &TrackingTree, byte: u8) -> Option<TrackingRecord> {
    tree.record(&member(byte))
        .unwrap()
        .map(|indexed| indexed.record)
}

#[test]
fn an_insert_relinks_the_low_record_and_holds_the_entry() {
    let mut tree = TrackingTree::new().unwrap();
    let first = apply(&mut tree, [1; 32], &[entry(9)]).unwrap();
    assert_eq!(first.chain_end, entry(9).chained(&[1; 32]).unwrap());
    let relinked = tree.root().unwrap();
    let inputs = apply(&mut tree, first.chain_end, &[entry(4)]).unwrap();
    let insert = inputs.writes[0];
    assert_eq!(insert.slot.index, 2);
    assert_eq!(insert.low.next, member(9));
    assert_eq!(
        insert.low_path.root(insert.low.hash().unwrap()),
        Ok(relinked)
    );
    assert_eq!(
        record(&tree, 4),
        Some(TrackingRecord {
            member: member(4),
            next: member(9),
            nullifier_pk: entry(4).nullifier_pk,
            ct_hash: entry(4).ct_hash,
            list_tag: entry(4).list_tag,
        })
    );
    assert_eq!(tree.records()[0].next, member(4));
    let statement = inputs.statement();
    assert_eq!((statement.old_next_index, statement.new_next_index), (2, 3));
    assert_eq!(statement.new_root, tree.root().unwrap());
    assert_eq!(statement.count, 1);
}

#[test]
fn a_present_owner_refuses_a_second_write_and_keeps_the_root() {
    let mut tree = TrackingTree::new().unwrap();
    apply(&mut tree, [0; 32], &[entry(5)]).unwrap();
    let root = tree.root().unwrap();
    assert_eq!(
        apply(&mut tree, [0; 32], &[entry(5)]),
        Err(RecordTreeError::TrackingOwnerPresent)
    );
    assert_eq!(
        apply(&mut tree, [0; 32], &[entry(6), entry(6)]),
        Err(RecordTreeError::TrackingOwnerPresent)
    );
    assert_eq!(tree.root().unwrap(), root);
}

#[test]
fn the_tree_refuses_entries_the_program_never_chains() {
    let mut tree = TrackingTree::new().unwrap();
    let before = tree.clone();
    for (outside, refusal) in [
        (
            TrackingEntry {
                nullifier_pk: [0; 32],
                ..entry(5)
            },
            RecordTreeError::TrackingKeyChanged,
        ),
        (
            TrackingEntry {
                member: FIELD_MAX,
                ..entry(5)
            },
            RecordTreeError::MemberOutOfRange,
        ),
    ] {
        assert_eq!(apply(&mut tree, [0; 32], &[outside]), Err(refusal));
    }
    assert_eq!(tree, before);
}

#[test]
fn the_tree_opens_leaf_two_to_the_thirty_two_minus_one_and_refuses_the_next() {
    assert_eq!(TRACKING_CAPACITY, 1 << 32);
    assert!(TrackingPath::sibling_positions(TRACKING_CAPACITY - 1).is_ok());
    assert_eq!(
        TrackingPath::sibling_positions(TRACKING_CAPACITY),
        Err(RecordTreeError::IndexOutOfRange)
    );
}

#[test]
fn openings_prove_presence_and_absence_under_the_root() {
    let mut tree = TrackingTree::new().unwrap();
    apply(&mut tree, [0; 32], &[entry(4), entry(9)]).unwrap();
    let root = tree.root().unwrap();
    let [four, seven] = [4, 7].map(member);
    let present = tree.opening(&four).unwrap();
    let verify = |opening, member| {
        OpeningCheck {
            opening,
            root: &root,
            member,
        }
        .verify()
    };
    assert_eq!(verify(&present, &four), Ok(record(&tree, 4)));
    let absent = tree.opening(&seven).unwrap();
    assert!(matches!(absent, RecordOpening::Absent { low, .. } if low.member == four));
    assert_eq!(verify(&absent, &seven), Ok(None));
    assert_eq!(verify(&absent, &four), Err(RecordTreeError::NotBracketed));
    assert_eq!(
        OpeningCheck {
            opening: &present,
            root: &[3; 32],
            member: &four,
        }
        .verify(),
        Err(RecordTreeError::RootMismatch)
    );
}

#[test]
fn a_record_pool_opens_the_taller_tree_and_refuses_the_policy_canopy() {
    let mut tree = TrackingTree::new().unwrap();
    apply(&mut tree, [0; 32], &[entry(4), entry(9)]).unwrap();
    let root = tree.root().unwrap();
    let members = [9, 6, 4, 9].map(member);
    let pool = tree
        .record_pool(&members, Canopy::covering_tracking(4).unwrap())
        .unwrap();
    assert_eq!(pool.records.len(), 2);
    assert_eq!(pool.verify(&root), Ok(()));
    assert_eq!(pool.clone().padded(4).unwrap().verify(&root), Ok(()));
    let mut forged = pool;
    forged.records[1].ct_hash = member(9);
    assert_eq!(forged.verify(&root), Err(RecordTreeError::RootMismatch));
    assert_eq!(
        tree.record_pool(&members, Canopy::covering(4).unwrap()),
        Err(RecordTreeError::PoolShape)
    );
}

#[test]
fn a_full_tree_refuses_an_insert() {
    assert!(matches!(
        FullStore::with_present(member(10)).apply([0; 32], &[entry(7)]),
        Err(RecordTreeError::Full)
    ));
}

/// `TRACKING_CAPACITY` leaves written, only what these writes read is stored.
struct FullStore {
    records: Vec<IndexedRecord<TrackingRecord>>,
}

impl FullStore {
    fn with_present(present: [u8; 32]) -> Self {
        let sentinel = TrackingRecord {
            next: present,
            ..TrackingRecord::SENTINEL
        };
        let enrolled = entry(10);
        let written = TrackingRecord {
            member: present,
            next: FIELD_MAX,
            nullifier_pk: enrolled.nullifier_pk,
            ct_hash: enrolled.ct_hash,
            list_tag: enrolled.list_tag,
        };
        Self {
            records: vec![
                IndexedRecord {
                    index: 0,
                    record: sentinel,
                },
                IndexedRecord {
                    index: 5,
                    record: written,
                },
            ],
        }
    }
}

impl RecordStore<TrackingRecord, TRACKING_QUAD_HEIGHT> for FullStore {
    type Error = RecordTreeError;

    fn next_index(&self) -> Result<u64, RecordTreeError> {
        Ok(TRACKING_CAPACITY)
    }

    fn node(&self, _at: NodePosition) -> Result<[u8; 32], RecordTreeError> {
        Ok([1; 32])
    }

    fn set_node(&mut self, _at: NodePosition, _node: [u8; 32]) -> Result<(), RecordTreeError> {
        Ok(())
    }

    fn record(
        &self,
        member: &[u8; 32],
    ) -> Result<Option<IndexedRecord<TrackingRecord>>, RecordTreeError> {
        Ok(self
            .records
            .iter()
            .find(|indexed| indexed.record.member == *member)
            .copied())
    }

    fn low_record(
        &self,
        member: &[u8; 32],
    ) -> Result<IndexedRecord<TrackingRecord>, RecordTreeError> {
        self.records
            .iter()
            .rfind(|indexed| indexed.record.member < *member)
            .copied()
            .ok_or(RecordTreeError::NotBracketed)
    }

    fn set_record(&mut self, _index: u64, _record: TrackingRecord) -> Result<(), RecordTreeError> {
        Ok(())
    }
}
