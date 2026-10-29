//! Record updates refuse a forged escrow proof and send a block entry as an immediate update.

use std::sync::atomic::AtomicU64;

use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::StorageRegistry,
    storage_instruction::{tag, StorageUpdateIxData},
    ApplyRecordsIxData, RingPolicy, QUAD_HEIGHT, RING_POLICY, STORAGE_PROGRAM_ID,
};
use custom_ring_sdk::CustomRing;
use jsonrpsee::MethodsError;
use solana_account::Account;
use solana_transaction::versioned::VersionedTransaction;
use spr_client::Proof;
use zolana_ring_client::rpc::{
    EscrowRegistration, RecordUpdate, RecordUpdateEntry, SubmitRecordUpdateRequest,
    SubmitRecordUpdateResponse, SUBMIT_RECORD_UPDATE,
};
use zolana_ring_indexer::rpc::{
    GetStorageApplyProofInputsRequest, GetStorageApplyProofInputsResponse, RingListWriteView,
    RingRecordWriteView,
};
use zolana_ring_member_registry::ApplyProofInputs;
use zolana_ring_policy::{ListId, MintPolicy};
use zolana_ring_rpc::{
    LatestBlockhash, RecordUpdateRefusal, RecordWriter, StorageChain, Store, TransactionOutcome,
    BATCH_WINDOW_SLOTS,
};

use super::*;

const REGISTRY: Address = Address::new_from_array([0x52; 32]);
const NOW: u64 = 100;
const NEW_ROOT: [u8; 32] = [0x77; 32];

/// The fixture escrow proof binds the owner identity of the wallet.
fn wallet() -> Keypair {
    Keypair::new_from_array([47; 32])
}

struct StubChain {
    slot: AtomicU64,
    config: RingConfiguration,
    accounts: Mutex<HashMap<Address, Account>>,
    sent: Mutex<Vec<VersionedTransaction>>,
}

#[async_trait::async_trait]
impl StorageChain for StubChain {
    async fn slot(&self) -> Result<u64, RingRpcError> {
        Ok(self.slot.load(Ordering::Relaxed))
    }

    async fn block_height(&self) -> Result<u64, RingRpcError> {
        Ok(NOW)
    }

    async fn account(&self, address: Address) -> Result<Option<Account>, RingRpcError> {
        Ok(self.accounts.lock().unwrap().get(&address).cloned())
    }

    async fn ring_config(&self, ring: Address) -> Result<Option<RingConfiguration>, RingRpcError> {
        Ok((ring == RING).then_some(self.config))
    }

    async fn apply_inputs(
        &self,
        request: GetStorageApplyProofInputsRequest,
    ) -> Result<GetStorageApplyProofInputsResponse, RingRpcError> {
        let registry = StorageRegistry::new(Address::default(), 0);
        let empty = || Hash([0; 32]);
        let path = || RingRecordPathView {
            index: 0,
            siblings: vec![[empty(), empty(), empty()]; QUAD_HEIGHT],
        };
        Ok(GetStorageApplyProofInputsResponse {
            context: spr_indexer_api::Context {
                block_time: 0,
                slot: NOW,
            },
            revision: 0,
            old_root: Hash(registry.roots[0].hash),
            new_root: Hash(NEW_ROOT),
            old_next_index: 1,
            new_next_index: 1 + request.writes.len() as u64,
            chain_start: empty(),
            chain_end: empty(),
            writes: request
                .writes
                .into_iter()
                .map(|write| RingRecordWriteView {
                    member: write.member,
                    mask: write.mask,
                    value: write.value,
                    escrow_key: write.escrow_key,
                    exists: false,
                    old_next: empty(),
                    old_lists: 0,
                    old_escrow: empty(),
                    old_mint_policy: MintPolicy::EMPTY,
                    slot: path(),
                    low: RingMemberRecordView {
                        member: empty(),
                        next: empty(),
                        lists: 0,
                        escrow_key: empty(),
                        owner_pubkey: None,
                        nullifier_pk: None,
                        eph_pk: None,
                        ciphertext: None,
                        mint_policy: MintPolicy::EMPTY,
                    },
                    low_path: path(),
                    mint_policy: write.mint_policy,
                })
                .collect(),
        })
    }

    async fn prove_apply(
        &self,
        inputs: &ApplyProofInputs,
    ) -> Result<ApplyRecordsIxData, RingRpcError> {
        Ok(ApplyRecordsIxData {
            new_root: inputs.new_root,
            ..ApplyRecordsIxData::zeroed()
        })
    }

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError> {
        Ok(LatestBlockhash {
            blockhash: solana_hash::Hash::new_from_array([1; 32]),
            last_valid_block_height: NOW + 150,
        })
    }

    async fn send(&self, transaction: &VersionedTransaction) -> Result<Signature, RingRpcError> {
        self.sent.lock().unwrap().push(transaction.clone());
        Ok(transaction.signatures[0])
    }

    async fn outcome(&self, _signature: Signature) -> Result<TransactionOutcome, RingRpcError> {
        Ok(TransactionOutcome::Unknown)
    }
}

struct Records {
    chain: Arc<StubChain>,
    module: jsonrpsee::RpcModule<Arc<Hub<StaticSource>>>,
    writer: Arc<RecordWriter>,
}

impl Records {
    /// A ring whose records registry the writer's authority holds, its auditor the fixture's.
    async fn new() -> Self {
        let fixture = Fixture::new();
        let escrow = escrow_fixture();
        let chain = Arc::new(StubChain {
            slot: AtomicU64::new(NOW),
            config: RingConfiguration {
                auditor_pubkey: X25519Pubkey::from_bytes(
                    hex_bytes(&escrow["auditorPk"])
                        .try_into()
                        .expect("auditor key"),
                )
                .expect("auditor key"),
                authority: authority().pubkey(),
                mode: RingMode::Confidential,
            },
            accounts: Mutex::default(),
            sent: Mutex::default(),
        });
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let hub = Hub::builder(fixture.source(), GENESIS)
            .with_origins(origins())
            .with_record_writer(store, chain.clone())
            .local(RING, fixture.auditor.clone())
            .expect("hub");
        let writer = hub.record_writer().expect("writer").clone();
        let mut policy = RingPolicy::zeroed();
        policy.discriminator = RING_POLICY;
        policy.records = REGISTRY;
        let registry = StorageRegistry::new(writer.authority(), 0);
        chain.accounts.lock().unwrap().extend([
            (
                CustomRing::new(RING).policy_pda(),
                owned(RING, bytemuck::bytes_of(&policy)),
            ),
            (
                REGISTRY,
                owned(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&registry)),
            ),
        ]);
        Self {
            chain,
            module: rpc_module(Arc::new(hub)).expect("module"),
            writer,
        }
    }

    async fn submit(
        &self,
        request: SubmitRecordUpdateRequest,
    ) -> Result<SubmitRecordUpdateResponse, MethodsError> {
        self.module
            .call(SUBMIT_RECORD_UPDATE, as_object(request))
            .await
    }

    /// The one transaction the flush sent.
    async fn flushed(&self) -> Flushed {
        self.writer.flush().await.expect("flush");
        let sent = self.chain.sent.lock().unwrap();
        let [transaction] = sent.as_slice() else {
            panic!("expected one transaction, sent {}", sent.len());
        };
        let message = &transaction.message;
        let data: Vec<Vec<u8>> = message
            .instructions()
            .iter()
            .map(|instruction| instruction.data.clone())
            .collect();
        let (mode, update) = data[0].split_first().expect("update tag");
        let members = StorageUpdateIxData::parse(update)
            .expect("update data")
            .writes
            .iter()
            .map(|write| write.member)
            .collect();
        Flushed {
            mode: *mode,
            members,
            data,
        }
    }
}

struct Flushed {
    mode: u8,
    /// The members the `Update` writes, in order.
    members: Vec<[u8; 32]>,
    data: Vec<Vec<u8>>,
}

fn owned(owner: Address, data: &[u8]) -> Account {
    Account {
        lamports: 1,
        data: data.to_vec(),
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

fn escrow_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../escrow_proof.json")).expect("escrow fixture")
}

fn hex_bytes(value: &serde_json::Value) -> Vec<u8> {
    let text = value.as_str().expect("hex string");
    hex::decode(text.strip_prefix("0x").unwrap_or(text)).expect("hex")
}

fn escrow_registration() -> EscrowRegistration {
    let fixture = escrow_fixture();
    let proof = Proof::from_gnark_json(&fixture["proof"].to_string()).expect("proof");
    let compressed = spr_client::ProofCompressed::try_from(proof).expect("compressed proof");
    let commitment = compressed.commitment.expect("commitment");
    let proof_bytes = [
        &compressed.a[..],
        &compressed.compressed_b().expect("proof b")[..],
        &compressed.c[..],
        &commitment.commitment[..],
        &commitment.commitment_pok[..],
    ]
    .concat();
    let hash = |key: &str| Hash(hex_bytes(&fixture[key]).try_into().expect("32 bytes"));
    EscrowRegistration {
        member: hash("member"),
        nullifier_pk: hash("nullifierPk"),
        eph_pk: hex_bytes(&fixture["ephPk"]).into(),
        ciphertext: hex_bytes(&fixture["ciphertext"]).into(),
        proof: proof_bytes.into(),
    }
}

fn signed(signer: &Keypair, entries: Vec<RecordUpdateEntry>) -> SubmitRecordUpdateRequest {
    let mut request = SubmitRecordUpdateRequest {
        registry: REGISTRY.into(),
        update: RecordUpdate {
            ring: RING.into(),
            entries,
            valid_until_slot: NOW + 1_000,
        },
        signer: signer.pubkey().into(),
        signature: Signature::default().into(),
    };
    let hash = request
        .statement()
        .expect("statement")
        .hash()
        .expect("statement hash");
    request.signature = signer.sign_message(&hash).into();
    request
}

fn refusal(result: Result<SubmitRecordUpdateResponse, MethodsError>) -> i32 {
    match result {
        Err(MethodsError::JsonRpc(error)) => error.code(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_wallet_escrow_registration_is_batched_only_after_its_proof_checks() {
    let records = Records::new().await;
    let registration = escrow_registration();
    let mut forged = registration.clone();
    // A valid curve point that is not the commitment's proof of knowledge.
    forged.proof.0.copy_within(128..160, 160);
    assert_eq!(
        refusal(
            records
                .submit(signed(&wallet(), vec![RecordUpdateEntry::Escrow(forged)]))
                .await
        ),
        RecordUpdateRefusal::EscrowProof.code()
    );
    records
        .submit(signed(
            &wallet(),
            vec![RecordUpdateEntry::Escrow(registration.clone())],
        ))
        .await
        .expect("queued");
    records
        .chain
        .slot
        .store(NOW + BATCH_WINDOW_SLOTS, Ordering::Relaxed);
    let flushed = records.flushed().await;
    assert_eq!(flushed.mode, tag::UPDATE);
    assert_eq!(flushed.members, [registration.member.0]);
}

#[tokio::test]
async fn a_block_entry_goes_out_as_an_immediate_update() {
    let records = Records::new().await;
    let blocked = ListId::Block.record_bit();
    let member = Hash([0x0c; 32]);
    records
        .submit(signed(
            &authority(),
            vec![RecordUpdateEntry::Write(RingListWriteView {
                mint_policy: None,
                member: member.clone(),
                mask: blocked,
                value: blocked,
            })],
        ))
        .await
        .expect("queued");
    let flushed = records.flushed().await;
    assert_eq!(flushed.mode, tag::UPDATE_IMMEDIATE);
    assert_eq!(flushed.members, [member.0]);
    assert_eq!(flushed.data[1], [custom_ring_interface::tag::SYNC_ROOTS]);
}
