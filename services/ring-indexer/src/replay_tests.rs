use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{chain_start, RegistryId, Revision},
    storage_instruction::{StorageUpdateIxData, StorageWriteData, UpdateMode},
    ApplyRecordsIxData, RecordWriteData, WriteRecordsIxData, STORAGE_PROGRAM_ID,
};
use custom_ring_sdk::{InitializeStorage, UpdateStorage};
use jsonrpsee::{server::ServerHandle, types::ErrorObjectOwned};
use sea_orm::DatabaseConnection;
use serde_json::{json, Value};
use solana_address::Address;
use solana_transaction::Instruction;
use spr_indexer_api::Hash;
use spr_keypair::{NullifierKey, X25519Keypair};
use zolana_ring_client::{
    rpc::{EscrowRegistration, RecordUpdateEntry},
    MemberOpeningRead, NullifierKeyEnvelope,
};
use zolana_ring_indexer::{
    rpc::{
        GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse,
        GetStorageMemberRecordsRequest, RingMemberOpening, RingMemberRecordView,
        RingRecordPathView, StorageRootView,
    },
    tree::{MemberRecord, OpeningCheck, QuadPath, RecordOpening, RecordTree},
};
use zolana_ring_member_registry::MemberRegistryTree;
use zolana_ring_policy::Member;

use crate::{
    api,
    indexer::{Indexer, Progress, Readiness, StartSlot},
    rpc::SolanaRpc,
    storage::StorageStore,
    tests::{database, field},
};

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

fn apply_data(new_root: [u8; 32], new_next_index: u64) -> ApplyRecordsIxData {
    ApplyRecordsIxData {
        proof: Zeroable::zeroed(),
        new_root,
        new_next_index: u32::try_from(new_next_index).unwrap().to_le_bytes(),
    }
}

fn wire_record(record: &RingMemberRecordView) -> MemberRecord {
    MemberRecord {
        mint_policy: record.mint_policy,
        member: record.member.0,
        next: record.next.0,
        lists: record.lists,
        escrow_key: record.escrow_key.0,
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

fn sent(instruction: &Instruction) -> Value {
    let accounts = instruction
        .accounts
        .iter()
        .map(|meta| meta.pubkey)
        .collect::<Vec<_>>();
    transaction(instruction.program_id, &accounts, &instruction.data)
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
    async fn updated(writes: Vec<StorageWriteData>) -> Self {
        let creator = Address::new_from_array([41; 32]);
        let initialize = InitializeStorage {
            payer: Address::new_from_array([1; 32]),
            creator,
            registry_id: RegistryId([42; 32]),
            grace_slots: 100,
        };
        let registry = initialize.registry();
        let chain_start = chain_start(&registry, Revision::default()).unwrap();
        let entries: Vec<_> = writes.iter().map(|write| write.entry().unwrap()).collect();
        let inputs = MemberRegistryTree::new()
            .unwrap()
            .apply(chain_start, &entries)
            .unwrap();
        let update = UpdateStorage {
            authority: creator,
            registry,
            mode: UpdateMode::Graced,
            data: StorageUpdateIxData {
                revision: Revision::default(),
                writes,
                apply: &apply_data(inputs.new_root, inputs.new_next_index),
            },
        }
        .instruction()
        .unwrap();
        let chain = Arc::new(Mutex::new(Chain {
            blocks: BTreeMap::from([
                (1, block(1, vec![sent(&initialize.instruction())])),
                (2, block(2, vec![sent(&update)])),
            ]),
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
    let write = StorageWriteData::Record(RecordWriteData {
        member,
        lists: WriteRecordsIxData {
            mask: 1u64.to_le_bytes(),
            value: 1u64.to_le_bytes(),
        },
        ..Zeroable::zeroed()
    });
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

#[tokio::test]
async fn a_storage_escrow_write_serves_an_envelope_the_auditor_opens() {
    let auditor = X25519Keypair::new();
    let owner = Address::new_from_array([43; 32]);
    let member = *Member::owner_tag(owner.as_array()).unwrap().as_bytes();
    let envelope =
        NullifierKeyEnvelope::new(&NullifierKey::from_secret([7; 31]), &auditor.pubkey()).unwrap();
    let registration = EscrowRegistration {
        member: Hash(member),
        nullifier_pk: Hash(envelope.nullifier_pk),
        eph_pk: envelope.sealed.eph_pk.as_bytes().to_vec().into(),
        ciphertext: envelope.sealed.ciphertext.to_vec().into(),
        proof: Vec::new().into(),
    };
    let write = RecordUpdateEntry::Escrow(registration)
        .write(&owner)
        .unwrap();
    let replay = StorageReplay::updated(vec![write]).await;
    let page = api::storage_member_records(
        replay.indexer.db.as_ref(),
        replay.indexer.rpc.as_ref(),
        GetStorageMemberRecordsRequest {
            registry: replay.registry.into(),
            expected_root: Hash(replay.root),
            start_index: 1,
            limit: 16,
        },
    )
    .await
    .unwrap();
    let [row] = page.records.as_slice() else {
        panic!("one record past the sentinel, {:?}", page.records);
    };
    let [opening] = replay
        .openings(&[member])
        .await
        .openings
        .try_into()
        .unwrap();
    assert_eq!(opening.record, row.record);
    let read = MemberOpeningRead::verify(&opening, &replay.root, &member).unwrap();
    assert_eq!(read.owner_pubkey, Some(owner));
    let escrowed = read.escrowed(&envelope.nullifier_pk).unwrap().unwrap();
    let opened = escrowed.sealed.open(&auditor).unwrap();
    assert_eq!(opened.pubkey().unwrap(), envelope.nullifier_pk);
    replay.stop().await;
}
