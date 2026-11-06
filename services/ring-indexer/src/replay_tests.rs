use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use bytemuck::Zeroable;
use custom_ring_interface::{
    mint_policy_write,
    storage::{chain_start, RegistryId, Revision, StorageRegistry},
    storage_instruction::{tag, InitializeIxData, InitializeTrackingIxData, StorageUpdateIxData},
    tracking::TrackingRegistry,
    ApplyRecordsIxData, RecordWriteData, WriteRecordsIxData, STORAGE_PROGRAM_ID,
};
use jsonrpsee::{server::ServerHandle, types::ErrorObjectOwned};
use sea_orm::DatabaseConnection;
use serde_json::{json, Value};
use solana_address::Address;
use spr_indexer_api::Hash;
use zolana_ring_indexer::{
    rpc::{
        GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse, RingMemberOpening,
        RingMemberRecordView, RingRecordPathView, StorageRootView,
    },
    tree::{MemberRecord, OpeningCheck, QuadPath, RecordOpening, RecordTree},
};
use zolana_ring_member_registry::{ApplyProofInputs, MemberRegistryTree, RecordWriteProofInput};
use zolana_ring_policy::{ListId, ListSet, Member};

use crate::{
    api,
    indexer::{Indexer, Progress, Readiness, StartSlot},
    rpc::SolanaRpc,
    storage::{StorageState, StorageStore},
    tests::{database, field},
};

#[path = "tracking_replay_tests.rs"]
mod tracking_replay;

/// Mutable confirmed RPC history, including failures between replay commits.
#[derive(Default)]
struct Chain {
    blocks: BTreeMap<u64, Value>,
    accounts: HashMap<String, Value>,
    failed_block: Option<u64>,
    /// Account reads answer from a bank that many slots behind the newest block.
    accounts_lag: u64,
    /// Every `getBlock` and `getMultipleAccounts` answered.
    upstream_calls: u64,
}

impl Chain {
    fn accounts_slot(&self) -> u64 {
        let newest = self.blocks.last_key_value().map_or(0, |(slot, _)| *slot);
        newest.saturating_sub(self.accounts_lag)
    }
}

async fn rpc(chain: Arc<Mutex<Chain>>) -> (Arc<SolanaRpc>, ServerHandle) {
    let server = jsonrpsee::server::ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let mut module = jsonrpsee::RpcModule::new(chain);
    module
        .register_method("getSlot", |_, chain, _| {
            *chain.lock().unwrap().blocks.last_key_value().unwrap().0
        })
        .unwrap();
    module
        .register_method("getBlocks", |params, chain, _| {
            let (start, end, _): (u64, u64, Value) = params.parse()?;
            Ok::<_, ErrorObjectOwned>(
                chain
                    .lock()
                    .unwrap()
                    .blocks
                    .range(start..=end)
                    .map(|(slot, _)| *slot)
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap();
    module
        .register_method("getBlock", |params, chain, _| {
            let (slot, options): (u64, Value) = params.parse()?;
            let mut chain = chain.lock().unwrap();
            chain.upstream_calls += 1;
            if chain.failed_block == Some(slot) && options["transactionDetails"] == "full" {
                return Err(ErrorObjectOwned::owned(
                    -32000,
                    "temporary archive failure",
                    None::<()>,
                ));
            }
            chain
                .blocks
                .get(&slot)
                .cloned()
                .ok_or_else(|| ErrorObjectOwned::owned(-32007, "skipped", None::<()>))
        })
        .unwrap();
    module
        .register_method("getMultipleAccounts", |params, chain, _| {
            let (addresses, config): (Vec<String>, Value) = params.parse()?;
            let mut chain = chain.lock().unwrap();
            chain.upstream_calls += 1;
            let slot = chain.accounts_slot();
            if config["minContextSlot"].as_u64() > Some(slot) {
                return Err(ErrorObjectOwned::owned(
                    -32016,
                    "Minimum context slot has not been reached",
                    None::<()>,
                ));
            }
            let accounts = addresses
                .iter()
                .map(|address| chain.accounts.get(address))
                .collect::<Vec<_>>();
            Ok(json!({ "context": { "slot": slot }, "value": accounts }))
        })
        .unwrap();
    (
        Arc::new(SolanaRpc::new(format!("http://{address}"))),
        server.start(module),
    )
}

fn account(owner: Address, data: &[u8]) -> Value {
    json!({"lamports": 1, "owner": owner.to_string(), "data": [STANDARD.encode(data), "base64"], "executable": false, "rentEpoch": 0})
}

fn block(slot: u64, transactions: Vec<Value>) -> Value {
    json!({"blockhash": Hash(field(slot as u8)).to_string(),
        "previousBlockhash": Hash(field(slot.saturating_sub(1) as u8)).to_string(),
        "parentSlot": slot.saturating_sub(1), "blockTime": slot, "blockHeight": slot, "transactions": transactions})
}

/// Archived transactions must pass the production RPC decoder.
fn transaction(program: Address, accounts: &[Address], data: &[u8]) -> Value {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&[1; 64]);
    bytes.extend_from_slice(&[1, 0, 1, (accounts.len() + 1) as u8]);
    for key in accounts.iter().chain(std::iter::once(&program)) {
        bytes.extend_from_slice(key.as_ref());
    }
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&[1, accounts.len() as u8, accounts.len() as u8]);
    bytes.extend(0..accounts.len() as u8);
    let mut length = data.len();
    loop {
        let byte = (length & 127) as u8;
        length >>= 7;
        bytes.push(byte | if length == 0 { 0 } else { 128 });
        if length == 0 {
            break;
        }
    }
    bytes.extend_from_slice(data);
    json!({"transaction": [STANDARD.encode(bytes), "base64"], "version": "legacy", "meta": {
        "err": null, "status": {"Ok": null}, "fee": 0,
        "preBalances": vec![1; accounts.len()+1], "postBalances": vec![1; accounts.len()+1],
        "innerInstructions": [], "logMessages": [], "loadedAddresses": {"readonly": [], "writable": []}
    }})
}

fn apply_data(inputs: &ApplyProofInputs) -> ApplyRecordsIxData {
    ApplyRecordsIxData {
        proof: Zeroable::zeroed(),
        new_root: inputs.new_root,
        new_next_index: u32::try_from(inputs.new_next_index).unwrap().to_le_bytes(),
        restrictive: u8::from(inputs.writes.iter().any(RecordWriteProofInput::restricts)),
    }
}

fn wire_record(record: &RingMemberRecordView) -> MemberRecord {
    MemberRecord {
        mint_policy: record.mint_policy,
        member: record.member.0,
        next: record.next.0,
        lists: record.lists,
    }
}

fn wire_path(path: &RingRecordPathView) -> QuadPath {
    QuadPath {
        index: path.index,
        siblings: core::array::from_fn(|level| {
            path.siblings[level].clone().map(|sibling| sibling.0)
        }),
    }
}

fn record_opening(opening: &RingMemberOpening) -> RecordOpening {
    let (record, path) = (wire_record(&opening.record), wire_path(&opening.path));
    if opening.present {
        RecordOpening::Present { record, path }
    } else {
        RecordOpening::Absent { low: record, path }
    }
}

fn replay_indexer(db: Arc<DatabaseConnection>, rpc: Arc<SolanaRpc>) -> Indexer {
    Indexer {
        db,
        rpc,
        start: Some(StartSlot::Slot(0)),
        block_fetches: 4,
        readiness: Readiness::default(),
    }
}

fn update_instruction(accounts: [Address; 2], data: &StorageUpdateIxData) -> Value {
    let wire = [&[tag::UPDATE][..], &data.encode().unwrap()].concat();
    transaction(STORAGE_PROGRAM_ID, &accounts, &wire)
}

fn initialize_transaction(
    creator: Address,
    registry_id: [u8; 32],
    ring_id: [u8; 32],
) -> (Address, Value) {
    let registry_id = RegistryId(registry_id);
    let (registry, _) = StorageRegistry::find_address(&creator, &registry_id);
    let data = InitializeIxData {
        registry_id,
        grace_slots: 100u64.to_le_bytes(),
        ring_id,
        tracking_registry: Address::default(),
    };
    let wire = [&[tag::INITIALIZE][..], bytemuck::bytes_of(&data)].concat();
    let accounts = [
        Address::new_from_array([1; 32]),
        creator,
        registry,
        Address::new_from_array([0; 32]),
    ];
    (registry, transaction(STORAGE_PROGRAM_ID, &accounts, &wire))
}

/// One registry the indexer projected through `Initialize` and one graced `Update`.
struct StorageReplay {
    indexer: Indexer,
    handle: ServerHandle,
    registry: Address,
    root: [u8; 32],
    next_index: u64,
}

impl StorageReplay {
    async fn updated(writes: Vec<RecordWriteData>) -> Self {
        let creator = Address::new_from_array([41; 32]);
        let (registry, initialize) = initialize_transaction(creator, [42; 32], [0; 32]);
        let chain_start = chain_start(&registry, Revision::default()).unwrap();
        let entries: Vec<_> = writes
            .iter()
            .map(|write| write.storage_entry().unwrap())
            .collect();
        let inputs = MemberRegistryTree::new()
            .unwrap()
            .apply(chain_start, &entries)
            .unwrap()
            .proof;
        let update = update_instruction(
            [creator, registry],
            &StorageUpdateIxData {
                revision: Revision::default(),
                writes,
                asset_writes: vec![],
                tracking_revision: None,
                apply: &apply_data(&inputs),
            },
        );
        let chain = Arc::new(Mutex::new(Chain {
            blocks: BTreeMap::from([(1, block(1, vec![initialize])), (2, block(2, vec![update]))]),
            ..Default::default()
        }));
        let (rpc, handle) = rpc(chain.clone()).await;
        let indexer = replay_indexer(Arc::new(database().await), rpc);
        while indexer.synchronize().await.unwrap() == Progress::Behind {}
        // The chain takes the projected account, as an honest program writes it.
        let projected = StorageStore::new(indexer.db.as_ref(), registry.to_bytes())
            .state()
            .await
            .unwrap()
            .unwrap();
        let image = account(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&*projected.account));
        chain
            .lock()
            .unwrap()
            .accounts
            .insert(registry.to_string(), image);
        Self {
            indexer,
            handle,
            registry,
            root: inputs.new_root,
            next_index: inputs.new_next_index,
        }
    }

    async fn openings(&self, members: &[[u8; 32]]) -> GetStorageMemberOpeningsResponse {
        api::storage_member_openings(
            self.indexer.db.as_ref(),
            self.indexer.rpc.as_ref(),
            GetStorageMemberOpeningsRequest {
                registry: self.registry.into(),
                members: members.iter().copied().map(Hash).collect(),
                expected_root: Hash(self.root),
            },
        )
        .await
        .unwrap()
    }

    async fn stop(self) {
        self.handle.stop().unwrap();
        self.handle.stopped().await;
    }
}

#[tokio::test]
async fn a_storage_update_serves_openings_under_its_new_root() {
    let member = *Member::owner_tag(&[43; 32]).unwrap().as_bytes();
    let write = RecordWriteData {
        member,
        lists: WriteRecordsIxData {
            mask: 1u64.to_le_bytes(),
            value: 1u64.to_le_bytes(),
        },
        ..Zeroable::zeroed()
    };
    let replay = StorageReplay::updated(vec![write]).await;
    let response = replay.openings(&[member]).await;
    let served = StorageRootView {
        root: Hash(replay.root),
        revision: 1,
        next_index: replay.next_index,
    };
    assert_eq!(response.root, served);
    let [opening] = response.openings.as_slice() else {
        panic!("one member opens once");
    };
    let opened = OpeningCheck {
        opening: &record_opening(opening),
        root: &replay.root,
        member: &member,
    }
    .verify()
    .unwrap();
    assert_eq!(opened.map(|record| record.lists), Some(1));
    replay.stop().await;
}

struct PolicySource {
    source: Address,
    initialized: Vec<Value>,
    tree: MemberRegistryTree,
}

const READER_MASK: u64 = ListSet::single(ListId::Reader).record_bits();
const BLOCK_MASK: u64 = ListSet::single(ListId::Block).record_bits();
const PRIVATE_MASK: u64 = ListSet::PRIVATE_LISTS.record_bits();
const PRIVATE_ALLOW_MASK: u64 = ListSet::single(ListId::PrivateAllow).record_bits();

impl PolicySource {
    const CREATOR: Address = Address::new_from_array([41; 32]);

    fn new(tracking: Address) -> Self {
        let registry_id = RegistryId([42; 32]);
        let (source, _) = StorageRegistry::find_address(&Self::CREATOR, &registry_id);
        let data = InitializeIxData {
            registry_id,
            grace_slots: 100u64.to_le_bytes(),
            ring_id: field(9),
            tracking_registry: tracking,
        };
        let wire = [&[tag::INITIALIZE][..], bytemuck::bytes_of(&data)].concat();
        let accounts = [Self::CREATOR, Self::CREATOR, source];
        Self {
            source,
            initialized: vec![transaction(STORAGE_PROGRAM_ID, &accounts, &wire)],
            tree: MemberRegistryTree::new().unwrap(),
        }
    }

    /// The root an honest proof reaches, a private write names `tracking` as its tracking revision.
    fn update(
        &mut self,
        revision: u64,
        mask: u64,
        tracking: u64,
        accounts: &[Address],
    ) -> ([u8; 32], Value) {
        let revision = Revision::from(revision);
        let write = RecordWriteData {
            member: field(4),
            lists: WriteRecordsIxData {
                mask: mask.to_le_bytes(),
                value: mask.to_le_bytes(),
            },
            mint_policy: mint_policy_write(None),
        };
        let applied = self
            .tree
            .clone()
            .apply(
                chain_start(&self.source, revision).unwrap(),
                &[write.storage_entry().unwrap()],
            )
            .unwrap();
        self.tree = applied.tree;
        let inputs = applied.proof;
        // A private list write names its tracking revision, the indexer verifies no proof.
        let tracking_revision = (mask & PRIVATE_MASK != 0).then(|| Revision::from(tracking));
        let data = StorageUpdateIxData {
            revision,
            writes: vec![write],
            asset_writes: vec![],
            tracking_revision,
            apply: &apply_data(&inputs),
        };
        let wire = [&[tag::UPDATE][..], &data.encode().unwrap()].concat();
        (
            inputs.new_root,
            transaction(STORAGE_PROGRAM_ID, accounts, &wire),
        )
    }
}

async fn replayed(blocks: Vec<Vec<Value>>) -> (Indexer, ServerHandle) {
    let blocks = (1..)
        .zip(blocks)
        .map(|(slot, transactions)| (slot, block(slot, transactions)))
        .collect();
    let chain = Arc::new(Mutex::new(Chain {
        blocks,
        ..Default::default()
    }));
    let (rpc, handle) = rpc(chain).await;
    let indexer = replay_indexer(Arc::new(database().await), rpc);
    while indexer.synchronize().await.unwrap() == Progress::Behind {}
    (indexer, handle)
}

#[tokio::test]
async fn a_write_a_rule_can_read_stops_every_older_root_in_the_same_slot() {
    let mut source = PolicySource::new(Address::default());
    let accounts = [PolicySource::CREATOR, source.source];
    let (graced_root, graced) = source.update(0, READER_MASK, 0, &accounts);
    let (policy_root, policy) = source.update(1, BLOCK_MASK, 0, &accounts);
    let initialized = std::mem::take(&mut source.initialized);
    let (indexer, handle) = replayed(vec![initialized, vec![graced], vec![policy]]).await;
    let state = StorageStore::new(indexer.db.as_ref(), source.source.to_bytes())
        .state()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.fault, None);
    assert_eq!(state.account.newest().hash, policy_root);
    assert!(state.account.roots[1..]
        .iter()
        .all(|root| root.hash == [0; 32]));
    let refused = api::storage_member_openings(
        indexer.db.as_ref(),
        indexer.rpc.as_ref(),
        GetStorageMemberOpeningsRequest {
            registry: source.source.into(),
            members: vec![Hash(field(4))],
            expected_root: Hash(graced_root),
        },
    )
    .await;
    assert_eq!(refused, Err(crate::error::RingApiError::RootChanged));
    handle.stop().unwrap();
    handle.stopped().await;
}

async fn projected(indexer: &Indexer, registry: Address) -> StorageState {
    StorageStore::new(indexer.db.as_ref(), registry.to_bytes())
        .state()
        .await
        .unwrap()
        .unwrap()
}

fn tracking_initialized() -> (Address, Value) {
    let ring_id = field(9);
    let creator = PolicySource::CREATOR;
    let (tracking, _) = TrackingRegistry::find_address(&creator, &ring_id);
    let data = InitializeTrackingIxData {
        ring_id,
        auditor_pubkey: [9; 33],
    };
    let wire = [&[tag::INITIALIZE_TRACKING][..], bytemuck::bytes_of(&data)].concat();
    let sent = transaction(STORAGE_PROGRAM_ID, &[creator, creator, tracking], &wire);
    (tracking, sent)
}

/// A pinned policy source with its tracking registry created in the first block.
fn pinned() -> (PolicySource, Address, Vec<Address>) {
    let (tracking, created) = tracking_initialized();
    let mut source = PolicySource::new(tracking);
    source.initialized.insert(0, created);
    let accounts = vec![PolicySource::CREATOR, source.source, tracking];
    (source, tracking, accounts)
}

#[tokio::test]
async fn a_private_write_raises_the_tracking_floor_and_a_lower_or_public_write_keeps_it() {
    let (mut source, _, accounts) = pinned();
    let (_, raised) = source.update(0, PRIVATE_ALLOW_MASK, 7, &accounts);
    let (_, lower) = source.update(1, PRIVATE_ALLOW_MASK, 3, &accounts);
    let (root, public) = source.update(2, READER_MASK, 0, &accounts[..2]);
    let initialized = std::mem::take(&mut source.initialized);
    let blocks = vec![initialized, vec![raised], vec![lower], vec![public]];
    let (indexer, handle) = replayed(blocks).await;
    let state = projected(&indexer, source.source).await;
    assert_eq!(state.fault, None);
    assert_eq!(state.account.newest().hash, root);
    assert_eq!(state.account.tracking_floor, Revision::from(7));
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn a_failed_private_write_leaves_the_root_and_the_floor() {
    let (mut source, _, accounts) = pinned();
    let (root, raised) = source.update(0, PRIVATE_ALLOW_MASK, 4, &accounts);
    let (_, mut failed) = source.update(1, PRIVATE_ALLOW_MASK, 9, &accounts);
    failed["meta"]["err"] = json!({"InstructionError": [0, {"Custom": 1}]});
    failed["meta"]["status"] = json!({"Err": {"InstructionError": [0, {"Custom": 1}]}});
    let initialized = std::mem::take(&mut source.initialized);
    let (indexer, handle) = replayed(vec![initialized, vec![raised], vec![failed]]).await;
    let state = projected(&indexer, source.source).await;
    assert_eq!(state.fault, None);
    assert_eq!(state.account.newest().hash, root);
    assert_eq!(state.account.tracking_floor, Revision::from(4));
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn a_private_write_naming_another_tracking_registry_stops_the_projection() {
    let (mut source, _, mut accounts) = pinned();
    accounts[2] = Address::new_from_array([60; 32]);
    let (_, named) = source.update(0, PRIVATE_ALLOW_MASK, 1, &accounts);
    let initialized = std::mem::take(&mut source.initialized);
    let (indexer, handle) = replayed(vec![initialized, vec![named]]).await;
    let fault = projected(&indexer, source.source).await.fault.unwrap();
    assert!(fault.contains("another tracking registry"), "{fault}");
    handle.stop().unwrap();
    handle.stopped().await;
}
