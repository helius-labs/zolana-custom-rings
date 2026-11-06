//! A storage update whose record rows fail to save part way leaves the stored tree, roots and
//! tracking floor as they were.

use custom_ring_interface::{
    mint_policy_write,
    storage::{chain_start, RegistryId, Revision, StorageRegistry},
    storage_instruction::{tag, InitializeIxData, StorageUpdateIxData},
    ApplyRecordsIxData, RecordWriteData, WriteRecordsIxData, FIELD_MAX, STORAGE_PROGRAM_ID,
};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement, TransactionTrait};
use sea_orm_migration::MigratorTrait;
use solana_address::Address;
use solana_signature::Signature;
use spr_indexer_api::Hash;
use zolana_ring_indexer::tree::{IndexedRecord, MemberRecord};
use zolana_ring_member_registry::{MemberRegistryTree, RecordTree};
use zolana_ring_policy::{ListId, ListSet};

use crate::{
    block::{BlockInfo, BlockMetadata, Instruction, InstructionGroup, TransactionInfo},
    indexer::RegistryCall,
    migration::Migrator,
    storage::{RingCursor, StorageState, StorageStore},
    storage_registry::StorageCall,
    tests::{database, field, indexer},
};

const REGISTRY: [u8; 32] = [11; 32];
const AUTHORITY: Address = Address::new_from_array([3; 32]);
const TRACKING: Address = Address::new_from_array([12; 32]);
const FLOOR: u64 = 4;

/// A registry pinned to a tracking registry, its floor already raised to `FLOOR`.
async fn private_registry(db: &DatabaseConnection) -> StorageState {
    let mut account = StorageRegistry::new(
        AUTHORITY,
        &InitializeIxData {
            registry_id: RegistryId::default(),
            grace_slots: [0; 8],
            ring_id: field(9),
            tracking_registry: TRACKING,
        },
    );
    account.tracking_floor = Revision::from(FLOOR);
    let state = StorageState {
        registry: REGISTRY,
        account: Box::new(account),
        fault: None,
    };
    let tx = db.begin().await.unwrap();
    <StorageCall as RegistryCall<StorageRegistry>>::create(
        &StorageStore::new(&tx, REGISTRY),
        &state,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    state
}

/// A PrivateAllow write of each member at revision 0, its tracking revision above `FLOOR`.
fn private_update(members: &[u8]) -> BlockInfo {
    let mask = ListSet::single(ListId::PrivateAllow).record_bits();
    let writes: Vec<RecordWriteData> = members
        .iter()
        .map(|member| RecordWriteData {
            member: field(*member),
            lists: WriteRecordsIxData {
                mask: mask.to_le_bytes(),
                value: mask.to_le_bytes(),
            },
            mint_policy: mint_policy_write(None),
        })
        .collect();
    let entries: Vec<_> = writes
        .iter()
        .map(|write| write.storage_entry().unwrap())
        .collect();
    let registry = Address::new_from_array(REGISTRY);
    let proof = MemberRegistryTree::new()
        .unwrap()
        .apply(
            chain_start(&registry, Revision::default()).unwrap(),
            &entries,
        )
        .unwrap()
        .proof;
    let apply = ApplyRecordsIxData {
        proof: bytemuck::Zeroable::zeroed(),
        new_root: proof.new_root,
        new_next_index: u32::try_from(proof.new_next_index).unwrap().to_le_bytes(),
        restrictive: 0,
    };
    let data = StorageUpdateIxData {
        revision: Revision::default(),
        writes,
        asset_writes: Vec::new(),
        tracking_revision: Some(Revision::from(FLOOR + 5)),
        apply: &apply,
    };
    let instruction = Instruction {
        program_id: STORAGE_PROGRAM_ID,
        data: [&[tag::UPDATE][..], &data.encode().unwrap()].concat(),
        accounts: vec![AUTHORITY, registry, TRACKING],
        stack_height: Some(1),
    };
    BlockInfo {
        metadata: BlockMetadata {
            slot: 3,
            blockhash: Hash(field(3)),
            ..Default::default()
        },
        transactions: vec![TransactionInfo {
            instruction_groups: vec![InstructionGroup {
                outer_instruction: instruction,
                inner_instructions: Vec::new(),
            }],
            signature: Signature::from([1; 64]),
            error: None,
        }],
    }
}

/// The registry's records and state, with the row counts of the node and root tables.
#[derive(Debug, PartialEq, Eq)]
struct Stored {
    records: Vec<IndexedRecord<MemberRecord>>,
    nodes: i64,
    roots: i64,
    state: Option<StorageState>,
}

async fn stored(db: &DatabaseConnection) -> Stored {
    let store = StorageStore::new(db, REGISTRY);
    let count = |table: &str| {
        Statement::from_string(
            db.get_database_backend(),
            format!("SELECT COUNT(*) AS n FROM {table}"),
        )
    };
    let rows = |statement| async {
        db.query_one(statement)
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "n")
            .unwrap()
    };
    Stored {
        records: store
            .tree()
            .records_by_index(0..8, u64::MAX >> 1)
            .await
            .unwrap(),
        nodes: rows(count("ring_record_nodes")).await,
        roots: rows(count("storage_roots")).await,
        state: store.state().await.unwrap(),
    }
}

/// `blocked` already holds a row at revision 1, so the update's insert at that index fails after
/// its earlier rows saved.
async fn refused_rows_leave_the_tree_and_floor(
    db: &DatabaseConnection,
    members: &[u8],
    blocked: u64,
) {
    let state = private_registry(db).await;
    StorageStore::new(db, REGISTRY)
        .tree()
        .save_records(
            &[IndexedRecord {
                index: blocked,
                record: MemberRecord {
                    member: field(200),
                    next: FIELD_MAX,
                    ..MemberRecord::default()
                },
            }],
            1,
        )
        .await
        .unwrap();
    let before = stored(db).await;
    let tx = db.begin().await.unwrap();
    let mut cursor = RingCursor::new(0);
    assert!(indexer(db, None)
        .apply_block(&tx, &private_update(members), &mut cursor)
        .await
        .is_err());
    tx.commit().await.unwrap();
    let after = stored(db).await;
    assert_eq!(after, before);
    assert_eq!(
        after.state.unwrap().account.tracking_floor,
        Revision::from(FLOOR)
    );
    assert_eq!(state.account.tracking_floor, Revision::from(FLOOR));
}

#[tokio::test]
async fn the_update_with_no_blocked_leaf_applies_and_raises_the_floor() {
    let db = database().await;
    private_registry(&db).await;
    let tx = db.begin().await.unwrap();
    let mut cursor = RingCursor::new(0);
    indexer(&db, None)
        .apply_block(&tx, &private_update(&[4, 9]), &mut cursor)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let after = stored(&db).await;
    assert_eq!(
        after.state.unwrap().account.tracking_floor,
        Revision::from(FLOOR + 5)
    );
    assert_eq!(after.records.len(), 3);
}

#[tokio::test]
async fn a_failed_insert_after_the_predecessor_relink_keeps_the_tree_and_floor() {
    refused_rows_leave_the_tree_and_floor(&database().await, &[9], 1).await;
}

#[tokio::test]
async fn a_failed_later_entry_keeps_the_earlier_entries_out_of_the_tree() {
    refused_rows_leave_the_tree_and_floor(&database().await, &[4, 9], 2).await;
}

/// A fresh database per test, the recipe runs the crate's ignored tests in parallel.
pub(crate) async fn postgres(name: &str) -> DatabaseConnection {
    let url = std::env::var("RING_INDEXER_TEST_POSTGRES_URL").unwrap();
    let server = Database::connect(&url).await.unwrap();
    for sql in [
        format!("DROP DATABASE IF EXISTS {name}"),
        format!("CREATE DATABASE {name}"),
    ] {
        server.execute_unprepared(&sql).await.unwrap();
    }
    let (base, _) = url.rsplit_once('/').unwrap();
    let db = Database::connect(format!("{base}/{name}")).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    db
}

#[tokio::test]
#[ignore = "needs RING_INDEXER_TEST_POSTGRES_URL"]
async fn postgres_a_failed_insert_after_the_predecessor_relink_keeps_the_tree_and_floor() {
    refused_rows_leave_the_tree_and_floor(&postgres("savepoint_relink").await, &[9], 1).await;
}

#[tokio::test]
#[ignore = "needs RING_INDEXER_TEST_POSTGRES_URL"]
async fn postgres_a_failed_later_entry_keeps_the_earlier_entries_out_of_the_tree() {
    refused_rows_leave_the_tree_and_floor(&postgres("savepoint_later_entry").await, &[4, 9], 2)
        .await;
}
