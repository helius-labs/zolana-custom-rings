use std::collections::{BTreeMap, HashMap};

use bytemuck::Zeroable;
use custom_ring_interface::{
    key_catalog::{ApplyMode, RingCircuit},
    mint_policy_write,
    storage::{RegistryId, RootUpdate, StorageError, StorageRegistry},
    storage_instruction::{AssetWrite, InitializeIxData, StorageUpdateIxData},
    ApplyRecordsIxData, PrivateWrites, RecordWrite, RecordWriteData, WriteRecordsIxData, FIELD_MAX,
    MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_EMPTY_ROOT,
};
use solana_address::Address;
use spr_hasher::primitives::right_align;
use zolana_ring_member_registry::{
    quad_node, AppliedTree, Canopy, IndexedRecord, MemberRecord, MemberRegistryTree, NodePosition,
    OpeningCheck, QuadPath, RecordOpening, RecordStatementContext, RecordStatementError,
    RecordStore, RecordTracking, RecordTree, RecordTreeError, ZERO_SUBTREES,
};
use zolana_ring_policy::{ListId, ListSet, Member, MintPolicy};

fn member(byte: u8) -> [u8; 32] {
    right_align(&[byte])
}

fn write(byte: u8, mask: u64, value: u64) -> RecordWrite {
    RecordWrite {
        mint_policy: Default::default(),
        member: member(byte),
        mask,
        value,
    }
}

fn record(tree: &MemberRegistryTree, byte: u8) -> Option<MemberRecord> {
    tree.record(&member(byte))
        .unwrap()
        .map(|indexed| indexed.record)
}

const ALLOW: u64 = 1 << 0;
const BLOCK: u64 = 1 << 1;

#[test]
fn a_fresh_tree_is_the_registry_genesis_root() {
    for level in 0..ZERO_SUBTREES.len() - 1 {
        let zero = ZERO_SUBTREES[level];
        assert_eq!(quad_node(&[zero; 4]).unwrap(), ZERO_SUBTREES[level + 1]);
    }
    let tree = MemberRegistryTree::new().unwrap();
    assert_eq!(tree.root().unwrap(), MEMBER_REGISTRY_EMPTY_ROOT);
    assert_eq!(tree.next_index().unwrap(), 1);
}

#[test]
fn an_insert_relinks_the_low_record_and_fills_the_next_index() {
    let tree = MemberRegistryTree::new().unwrap();
    let AppliedTree { tree, proof: first } =
        tree.apply([0; 32], &[write(9, ALLOW, ALLOW)]).unwrap();
    let relinked = tree.root().unwrap();
    let AppliedTree {
        tree,
        proof: inputs,
    } = tree
        .apply(first.chain_end, &[write(4, BLOCK, BLOCK)])
        .unwrap();
    let insert = inputs.writes[0];
    assert!(!insert.exists);
    assert_eq!(insert.slot.index, 2);
    assert_eq!(insert.low.member, [0; 32]);
    assert_eq!(insert.low.next, member(9));
    assert_eq!(insert.old_next, member(9));
    assert_eq!(
        insert.low_path.root(insert.low.hash().unwrap()),
        Ok(relinked)
    );
    assert_eq!(record(&tree, 4).map(|record| record.next), Some(member(9)));
    assert_eq!(
        tree.records()[0].next,
        member(4),
        "the sentinel now links to the lower member"
    );
    assert_eq!((inputs.old_next_index, inputs.new_next_index), (2, 3));
    assert_eq!(inputs.new_root, tree.root().unwrap());
}

#[test]
fn an_update_keeps_the_list_bits_outside_its_mask() {
    let tree = MemberRegistryTree::new().unwrap();
    let tree = tree
        .apply([0; 32], &[write(5, ALLOW | BLOCK, ALLOW | BLOCK)])
        .unwrap()
        .tree;
    let AppliedTree {
        tree,
        proof: inputs,
    } = tree.apply([0; 32], &[write(5, BLOCK, 0)]).unwrap();
    let update = inputs.writes[0];
    assert!(update.exists);
    assert_eq!((update.old_lists, update.slot.index), (ALLOW | BLOCK, 1));
    assert_eq!(update.low, MemberRecord::default());
    assert_eq!(record(&tree, 5).map(|record| record.lists), Some(ALLOW));
    assert_eq!(inputs.new_next_index, inputs.old_next_index);
}

#[test]
fn an_absent_member_whose_write_leaves_no_list_stays_absent() {
    let tree = MemberRegistryTree::new().unwrap();
    let before = tree.root().unwrap();
    let AppliedTree {
        tree,
        proof: inputs,
    } = tree.apply([0; 32], &[write(7, ALLOW, 0)]).unwrap();
    let noop = inputs.writes[0];
    assert!(!noop.exists);
    assert_eq!(noop.low, MemberRecord::SENTINEL);
    assert_eq!(noop.low_path.root(noop.low.hash().unwrap()), Ok(before));
    assert_eq!((inputs.new_root, inputs.new_next_index), (before, 1));
    assert_eq!(record(&tree, 7), None);
}

#[test]
fn the_tree_refuses_writes_the_program_never_chains() {
    let tree = MemberRegistryTree::new().unwrap();
    let before = tree.clone();
    assert_eq!(
        tree.clone()
            .apply([0; 32], &[write(6, ALLOW, ALLOW | BLOCK)]),
        Err(RecordTreeError::ValueOutsideMask)
    );
    let mut zero = write(6, ALLOW, ALLOW);
    zero.member = [0; 32];
    assert_eq!(
        tree.clone().apply([0; 32], &[zero]),
        Err(RecordTreeError::MemberOutOfRange)
    );
    let mut max = zero;
    max.member = FIELD_MAX;
    assert_eq!(
        tree.clone().apply([0; 32], &[max]),
        Err(RecordTreeError::MemberOutOfRange)
    );
    assert_eq!(tree, before);
    assert_eq!(
        QuadPath::sibling_positions(MEMBER_REGISTRY_CAPACITY),
        Err(RecordTreeError::IndexOutOfRange)
    );
}

#[test]
fn openings_resolve_present_and_absent_members_under_their_root() {
    let tree = MemberRegistryTree::new().unwrap();
    let tree = tree
        .apply([0; 32], &[write(4, ALLOW, ALLOW), write(9, BLOCK, BLOCK)])
        .unwrap()
        .tree;
    let root = tree.root().unwrap();
    let [four, five, seven, nine, ten] = [4, 5, 7, 9, 10].map(member);
    let present = tree.opening(&four).unwrap();
    let check = |opening, member| OpeningCheck {
        opening,
        root: &root,
        member,
    };
    assert_eq!(check(&present, &four).verify(), Ok(record(&tree, 4)));
    let absent = tree.opening(&seven).unwrap();
    assert!(matches!(absent, RecordOpening::Absent { low, .. } if low.member == four));
    assert_eq!(check(&absent, &seven).verify(), Ok(None));
    for outside in [&four, &nine, &ten] {
        assert_eq!(
            check(&absent, outside).verify(),
            Err(RecordTreeError::NotBracketed)
        );
    }
    assert_eq!(
        check(&present, &five).verify(),
        Err(RecordTreeError::NotBracketed)
    );
    let stale = OpeningCheck {
        opening: &present,
        root: &MEMBER_REGISTRY_EMPTY_ROOT,
        member: &four,
    };
    assert_eq!(stale.verify(), Err(RecordTreeError::RootMismatch));
}

#[test]
fn a_record_pool_opens_each_record_once_and_refuses_a_forged_subject() {
    let tree = MemberRegistryTree::new().unwrap();
    let tree = tree
        .apply([0; 32], &[write(4, ALLOW, ALLOW), write(9, BLOCK, BLOCK)])
        .unwrap()
        .tree;
    let root = tree.root().unwrap();
    let members = [9, 6, 4, 9].map(member);
    let pool = tree
        .record_pool(&members, Canopy::covering(4).unwrap())
        .unwrap();
    assert_eq!(pool.records.len(), 2);
    assert_eq!(
        pool.subjects
            .iter()
            .map(|subject| subject.record_index)
            .collect::<Vec<_>>(),
        [0, 1, 1, 0]
    );
    assert_eq!(pool.verify(&root), Ok(()));
    let padded = pool.clone().padded(4).unwrap();
    assert_eq!(padded.verify(&root), Ok(()));
    assert_eq!(pool.clone().padded(5), Err(RecordTreeError::PoolShape));

    let mut skipped = pool.clone();
    skipped.subjects[1].record_index = 0;
    assert_eq!(skipped.verify(&root), Err(RecordTreeError::NotBracketed));
    let mut forged = pool.clone();
    forged.records[1].lists = 0;
    assert_eq!(forged.verify(&root), Err(RecordTreeError::RootMismatch));
    let mut canopy = pool;
    canopy.proof.canopy[3] = member(1);
    assert_eq!(canopy.verify(&root), Err(RecordTreeError::RootMismatch));
}

#[test]
fn records_rebuild_the_tree_they_came_from() {
    let tree = MemberRegistryTree::new().unwrap();
    let entries: Vec<RecordWrite> = (1..=40).map(|byte| write(byte * 5, ALLOW, ALLOW)).collect();
    let tree = tree.apply([0; 32], &entries).unwrap().tree;
    let rebuilt = MemberRegistryTree::from_records(tree.records().to_vec()).unwrap();
    assert_eq!(rebuilt, tree);
    let mut duplicated = tree.records().to_vec();
    duplicated.push(duplicated[1]);
    assert_eq!(
        MemberRegistryTree::from_records(duplicated),
        Err(RecordTreeError::DuplicateMember)
    );
    assert_eq!(
        MemberRegistryTree::from_records(tree.records()[1..].to_vec()),
        Err(RecordTreeError::MissingSentinel)
    );
}

#[derive(Default)]
struct PreloadedStore {
    next_index: u64,
    nodes: HashMap<NodePosition, [u8; 32]>,
    records: BTreeMap<[u8; 32], IndexedRecord>,
}

impl PreloadedStore {
    fn for_batch(tree: &MemberRegistryTree, entries: &[RecordWrite]) -> Self {
        let next_index = tree.next_index().unwrap();
        let mut store = Self {
            next_index,
            ..Self::default()
        };
        store.nodes.insert(NodePosition::ROOT, tree.root().unwrap());
        let mut indexes: Vec<u64> = (next_index..next_index + entries.len() as u64).collect();
        for entry in entries {
            let indexed = match tree.record(&entry.member).unwrap() {
                Some(indexed) => indexed,
                None => tree.low_record(&entry.member).unwrap(),
            };
            store.records.insert(indexed.record.member, indexed);
            indexes.push(indexed.index);
        }
        for index in indexes {
            for at in QuadPath::sibling_positions(index)
                .unwrap()
                .into_iter()
                .flatten()
            {
                if !at.is_empty(next_index) {
                    store.nodes.insert(at, tree.node(at).unwrap());
                }
            }
        }
        store
    }
}

impl RecordStore for PreloadedStore {
    type Error = RecordTreeError;

    fn next_index(&self) -> Result<u64, RecordTreeError> {
        Ok(self.next_index)
    }

    fn node(&self, at: NodePosition) -> Result<[u8; 32], RecordTreeError> {
        self.nodes
            .get(&at)
            .copied()
            .ok_or(RecordTreeError::NodeMissing {
                level: at.level,
                position: at.position,
            })
    }

    fn set_node(&mut self, at: NodePosition, node: [u8; 32]) -> Result<(), RecordTreeError> {
        self.nodes.insert(at, node);
        Ok(())
    }

    fn record(&self, member: &[u8; 32]) -> Result<Option<IndexedRecord>, RecordTreeError> {
        Ok(self.records.get(member).copied())
    }

    fn low_record(&self, member: &[u8; 32]) -> Result<IndexedRecord, RecordTreeError> {
        self.records
            .range(..*member)
            .next_back()
            .map(|(_, indexed)| *indexed)
            .ok_or(RecordTreeError::NotBracketed)
    }

    fn set_record(&mut self, index: u64, record: MemberRecord) -> Result<(), RecordTreeError> {
        self.next_index = self.next_index.max(index + 1);
        self.records
            .insert(record.member, IndexedRecord { index, record });
        Ok(())
    }
}

#[test]
fn a_store_preloaded_by_sibling_positions_applies_like_the_full_tree() {
    let tree = MemberRegistryTree::new().unwrap();
    let seeded: Vec<RecordWrite> = (1..=30).map(|byte| write(byte * 7, ALLOW, ALLOW)).collect();
    let tree = tree.apply([0; 32], &seeded).unwrap().tree;
    let batch = [
        write(50, BLOCK, BLOCK),
        write(51, ALLOW, ALLOW),
        write(7, ALLOW, 0),
        write(52, BLOCK, BLOCK),
        write(53, ALLOW, 0),
    ];
    let store = PreloadedStore::for_batch(&tree, &batch);
    let expected = tree.clone().apply([5; 32], &batch).unwrap().proof;
    assert_eq!(store.apply([5; 32], &batch).unwrap().proof, expected);

    let mut short = PreloadedStore::for_batch(&tree, &batch);
    let low = tree.low_record(&batch[0].member).unwrap().index;
    let needed = QuadPath::sibling_positions(low).unwrap()[0][0];
    assert!(short.nodes.remove(&needed).is_some());
    assert!(matches!(
        short.apply([5; 32], &batch),
        Err(RecordTreeError::NodeMissing { .. })
    ));
}

#[test]
fn a_full_tree_applies_updates_and_no_ops_but_no_insert() {
    let sentinel = IndexedRecord {
        index: 0,
        record: MemberRecord {
            next: member(10),
            ..MemberRecord::SENTINEL
        },
    };
    let present = IndexedRecord {
        index: 5,
        record: MemberRecord {
            mint_policy: Default::default(),
            member: member(10),
            next: FIELD_MAX,
            lists: ALLOW,
        },
    };
    let mut full = PreloadedStore {
        next_index: MEMBER_REGISTRY_CAPACITY,
        ..PreloadedStore::default()
    };
    full.nodes.insert(NodePosition::ROOT, [2; 32]);
    for indexed in [sentinel, present] {
        full.records.insert(indexed.record.member, indexed);
        let positions = QuadPath::sibling_positions(indexed.index).unwrap();
        full.nodes
            .extend(positions.into_iter().flatten().map(|at| (at, [1; 32])));
    }
    let frozen = ListId::Frozen.record_bit();
    let AppliedTree {
        tree: full,
        proof: inputs,
    } = full
        .apply([0; 32], &[write(10, BLOCK, BLOCK), write(7, frozen, 0)])
        .unwrap();
    assert!(inputs.writes[0].exists);
    let noop = inputs.writes[1];
    assert!(!noop.exists);
    assert_eq!(noop.slot, noop.low_path);
    assert_eq!(inputs.new_next_index, MEMBER_REGISTRY_CAPACITY);
    assert_eq!(
        full.apply([0; 32], &[write(7, frozen, frozen)])
            .map(|applied| applied.proof),
        Err(RecordTreeError::Full)
    );
}

#[test]
fn mint_settings_survive_relinks_and_list_writes_and_clear_explicitly() {
    use zolana_ring_policy::MintPolicy;
    let tree = MemberRegistryTree::new().unwrap();
    let policy = MintPolicy {
        threshold: 10,
        cap: 20,
        cosign_above: 15,
        withdrawal_threshold: u64::MAX,
        limits: zolana_ring_policy::AssetLimits {
            sender_cap: 30,
            sender_window_slots: 40,
            ..Default::default()
        },
    };
    let tree = tree
        .apply(
            [0; 32],
            &[RecordWrite {
                mint_policy: Some(policy),
                ..write(5, 0, 0)
            }],
        )
        .unwrap()
        .tree;
    let tree = tree
        .apply([0; 32], &[write(7, ALLOW, ALLOW), write(5, BLOCK, BLOCK)])
        .unwrap()
        .tree;
    let before = record(&tree, 5).unwrap();
    assert_eq!(before.mint_policy, policy);
    assert_eq!(before.next, member(7));
    let tree = tree
        .apply(
            [0; 32],
            &[RecordWrite {
                mint_policy: Some(MintPolicy::EMPTY),
                ..write(5, 0, 0)
            }],
        )
        .unwrap()
        .tree;
    assert_eq!(
        record(&tree, 5).unwrap(),
        MemberRecord {
            mint_policy: MintPolicy::EMPTY,
            ..before
        }
    );
}

fn registry() -> StorageRegistry {
    StorageRegistry::new(
        Address::new_from_array([0x52; 32]),
        &InitializeIxData {
            registry_id: RegistryId::default(),
            grace_slots: [0; 8],
            ring_id: [0; 32],
            tracking_registry: Address::default(),
        },
    )
}

#[test]
fn public_statements_select_the_public_key_and_bind_no_tracking_root() {
    let proof = MemberRegistryTree::new()
        .unwrap()
        .apply(
            [0; 32],
            &[
                write(4, ALLOW, ALLOW),
                write(5, BLOCK, BLOCK),
                write(6, ALLOW, 0),
            ],
        )
        .unwrap()
        .proof;
    let mut state = registry();
    state.tracking_registry = Address::new_from_array(member(9));
    let statement = proof
        .statement(RecordStatementContext {
            registry: &state,
            asset_writes: &[],
            tracking: RecordTracking::Public,
        })
        .unwrap();
    assert_eq!(statement.count, 3);
    assert_eq!(statement.private, None);
    assert_eq!(
        statement.circuit(),
        RingCircuit::ApplyRecords {
            writes: 4,
            mode: ApplyMode::Public
        }
    );
    assert!(statement.restrictive);
    assert_eq!(statement.elements().len(), 9);
}

#[test]
fn only_a_tightening_write_retires_the_served_root() {
    let mint = |policy: MintPolicy| RecordWrite {
        mint_policy: Some(policy),
        ..write(9, 0, 0)
    };
    let capped = |cap| MintPolicy {
        threshold: 5,
        cap,
        ..MintPolicy::EMPTY
    };
    let mut tree = MemberRegistryTree::new().unwrap();
    let mut state = StorageRegistry::new(
        Address::new_from_array([0x52; 32]),
        &InitializeIxData {
            registry_id: RegistryId::default(),
            grace_slots: 10u64.to_le_bytes(),
            ring_id: [0; 32],
            tracking_registry: Address::default(),
        },
    );
    for (entry, served) in [
        (write(4, ALLOW, ALLOW), true),
        (write(4, ALLOW, ALLOW), true),
        (write(4, BLOCK, BLOCK), false),
        (write(4, BLOCK, 0), true),
        (mint(capped(0)), true),
        (mint(capped(100)), false),
        (mint(capped(200)), true),
        (mint(capped(0)), true),
    ] {
        let AppliedTree { tree: next, proof } = tree.apply([0; 32], &[entry]).unwrap();
        let statement = proof
            .statement(RecordStatementContext {
                registry: &state,
                asset_writes: &[],
                tracking: RecordTracking::Public,
            })
            .unwrap();
        let apply = ApplyRecordsIxData {
            new_root: statement.new_root,
            new_next_index: statement.new_next_index.to_le_bytes(),
            restrictive: u8::from(statement.restrictive),
            ..ApplyRecordsIxData::zeroed()
        };
        let revision = state.newest().revision;
        let data = StorageUpdateIxData {
            revision,
            writes: vec![RecordWriteData {
                member: entry.member,
                lists: WriteRecordsIxData {
                    mask: entry.mask.to_le_bytes(),
                    value: entry.value.to_le_bytes(),
                },
                mint_policy: mint_policy_write(entry.mint_policy),
            }],
            asset_writes: Vec::new(),
            tracking_revision: None,
            apply: &apply,
        };
        state
            .update(RootUpdate {
                slot: 1,
                data: &data,
            })
            .unwrap();
        assert_eq!(state.root(revision, 1).is_ok(), served, "{entry:?}");
        tree = next;
    }
}

#[test]
fn private_owner_writes_cannot_use_public_statement_context() {
    for private in ListSet::PRIVATE_LISTS.iter() {
        for value in [0, private.record_bit()] {
            let proof = MemberRegistryTree::new()
                .unwrap()
                .apply([0; 32], &[write(4, private.record_bit(), value)])
                .unwrap()
                .proof;
            let state = registry();
            assert!(matches!(
                proof.statement(RecordStatementContext {
                    registry: &state,
                    asset_writes: &[],
                    tracking: RecordTracking::Public,
                }),
                Err(RecordStatementError::Storage(
                    StorageError::InvalidTrackingRegistry
                ))
            ));
        }
    }
}

#[test]
fn private_owner_writes_bind_the_tracking_root_on_a_pinned_registry_only() {
    let private = ListId::PrivateBlock.record_bit();
    let proof = MemberRegistryTree::new()
        .unwrap()
        .apply(
            [0; 32],
            &[write(4, private, private), write(5, ALLOW, ALLOW)],
        )
        .unwrap()
        .proof;
    let tracking = RecordTracking::Private {
        tracking_root: member(7),
    };
    let unpinned = registry();
    assert!(matches!(
        proof.statement(RecordStatementContext {
            registry: &unpinned,
            asset_writes: &[],
            tracking,
        }),
        Err(RecordStatementError::Storage(
            StorageError::PrivateWriteWithoutTracking
        ))
    ));
    let mut pinned = registry();
    pinned.tracking_registry = Address::new_from_array(member(9));
    let statement = proof
        .statement(RecordStatementContext {
            registry: &pinned,
            asset_writes: &[],
            tracking,
        })
        .unwrap();
    assert_eq!(
        statement.private,
        Some(PrivateWrites {
            private_writes: 0b01,
            tracking_root: member(7),
        })
    );
    assert_eq!(statement.mode(), ApplyMode::Private);
    assert_eq!(statement.elements().len(), 11);
}

#[test]
fn private_asset_exemption_requires_the_exact_mint_preimage() {
    let mint = Address::new_from_array([0x31; 32]);
    let private = ListId::PrivateBlock.record_bit();
    let entry = RecordWrite {
        member: *Member::asset(&mint).unwrap().as_bytes(),
        ..write(4, private, private)
    };
    let proof = MemberRegistryTree::new()
        .unwrap()
        .apply([0; 32], &[entry])
        .unwrap()
        .proof;
    let state = registry();
    let statement = proof
        .statement(RecordStatementContext {
            registry: &state,
            asset_writes: &[AssetWrite {
                write_index: 0,
                mint,
            }],
            tracking: RecordTracking::Public,
        })
        .unwrap();
    assert_eq!(statement.mode(), ApplyMode::Public);
    for claimed_mint in [
        Address::new_from_array([0x32; 32]),
        Address::new_from_array([0x33; 32]),
    ] {
        assert!(matches!(
            proof.statement(RecordStatementContext {
                registry: &state,
                asset_writes: &[AssetWrite {
                    write_index: 0,
                    mint: claimed_mint
                }],
                tracking: RecordTracking::Public,
            }),
            Err(RecordStatementError::Storage(
                StorageError::InvalidAssetWrite
            ))
        ));
    }
}

#[test]
fn statements_refuse_a_different_registry_root_or_allocation_cursor() {
    let proof = MemberRegistryTree::new()
        .unwrap()
        .apply([0; 32], &[write(4, ALLOW, ALLOW)])
        .unwrap()
        .proof;
    let mut wrong_root = registry();
    wrong_root.roots[0].hash = proof.new_root;
    let mut wrong_index = registry();
    wrong_index.next_index = 2u32.to_le_bytes();
    for state in [wrong_root, wrong_index] {
        assert!(matches!(
            proof.statement(RecordStatementContext {
                registry: &state,
                asset_writes: &[],
                tracking: RecordTracking::Public,
            }),
            Err(RecordStatementError::RegistryStateMismatch)
        ));
    }
}
