//! Record updates refuse a forged escrow proof, a second escrow key, an enrolment past its window or awaiting the reader list in database mode, send only a block entry as an immediate update, hold an enrolment for its allow entry, and page the enrolments that await the config authority.

use std::sync::atomic::AtomicU64;

use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::StorageRegistry,
    storage_instruction::{tag, StorageUpdateIxData, StorageWriteData},
    ApplyRecordsIxData, RingPolicy, SourceSlot, QUAD_HEIGHT, RING_POLICY, STORAGE_PROGRAM_ID,
};
use custom_ring_sdk::CustomRing;
use jsonrpsee::MethodsError;
use solana_account::Account;
use solana_transaction::versioned::VersionedTransaction;
use spr_client::Proof;
use zolana_ring_client::rpc::{
    EscrowRegistration, GetPendingEnrolmentsRequest, GetPendingEnrolmentsResponse,
    GetRecordUpdateStatusRequest, ReadTarget, ReaderAccess, RecordUpdate, RecordUpdateEntry,
    RecordUpdateStatus, SubmitRecordUpdateRequest, SubmitRecordUpdateResponse, WalletGrant,
    GET_PENDING_ENROLMENTS, PENDING_ENROLMENTS_PAGE_LIMIT, SUBMIT_RECORD_UPDATE,
};
use zolana_ring_indexer::rpc::{
    GetStorageApplyProofInputsRequest, GetStorageApplyProofInputsResponse,
    GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse, RingListWriteView,
    RingRecordWriteView,
};
use zolana_ring_member_registry::ApplyProofInputs;
use zolana_ring_policy::{ListId, Member, MintPolicy};
use zolana_ring_rpc::{
    LatestBlockhash, ReaderGrantStore, RecordUpdateRefusal, RecordWriter, StorageChain, Store,
    Subscriber, TransactionOutcome, BATCH_WINDOW_SLOTS, MAX_ENROLMENT_WINDOW_SLOTS,
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
    outcome: Mutex<TransactionOutcome>,
    records: super::Records,
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

    async fn member_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingRpcError> {
        let root = self.records.root();
        assert_eq!(request.expected_root, root.root);
        Ok(GetStorageMemberOpeningsResponse {
            context: spr_indexer_api::Context {
                block_time: 0,
                slot: NOW,
            },
            root,
            openings: request
                .members
                .iter()
                .map(|member| self.records.opening(&member.0))
                .collect(),
        })
    }

    async fn subscribers(&self, _registry: Address) -> Result<Vec<Subscriber>, RingRpcError> {
        Ok(Vec::new())
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
        Ok(*self.outcome.lock().unwrap())
    }
}

struct Records {
    chain: Arc<StubChain>,
    hub: Arc<Hub<StaticSource>>,
    module: jsonrpsee::RpcModule<Arc<Hub<StaticSource>>>,
    writer: Arc<RecordWriter>,
}

struct RecordsSetup<'a> {
    fixture: &'a Fixture,
    source: StaticSource,
    reader_grants: ReaderGrantStore,
}

impl Records {
    async fn new() -> Self {
        Self::with_reader_grants(ReaderGrantStore::Tree).await
    }

    async fn with_reader_grants(reader_grants: ReaderGrantStore) -> Self {
        let fixture = Fixture::new();
        RecordsSetup {
            fixture: &fixture,
            source: fixture.source(),
            reader_grants,
        }
        .serve()
        .await
    }
}

impl RecordsSetup<'_> {
    /// A ring whose records registry the writer's authority holds, its escrow auditor the fixture's.
    async fn serve(self) -> Records {
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
                delegate: None,
            },
            accounts: Mutex::default(),
            sent: Mutex::default(),
            outcome: Mutex::new(TransactionOutcome::Unknown),
            records: super::Records::listing(&[]),
        });
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let hub = Hub::builder(self.source, identity(GENESIS))
            .with_origins(origins())
            .with_store(store)
            .with_storage_chain(chain.clone(), storage_authority())
            .with_reader_grants(self.reader_grants)
            .with_grant_rows_key(grant_rows_key())
            .local(RING, self.fixture.auditor.clone())
            .expect("hub");
        let writer = hub.record_writer().expect("writer").clone();
        let registry = StorageRegistry::new(writer.authority(), 0);
        let mut policy = RingPolicy::zeroed();
        policy.discriminator = RING_POLICY;
        policy.records = REGISTRY;
        policy.own_roots.registry = REGISTRY;
        policy.own_roots.roots = registry.roots;
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
        let hub = Arc::new(hub);
        Records {
            chain,
            module: rpc_module(hub.clone()).expect("module"),
            hub,
            writer,
        }
    }
}

impl Records {
    async fn submit(
        &self,
        request: SubmitRecordUpdateRequest,
    ) -> Result<SubmitRecordUpdateResponse, MethodsError> {
        self.module
            .call(SUBMIT_RECORD_UPDATE, as_object(request))
            .await
    }

    /// The member's record holds an escrow key under the root the policy mirrors.
    fn escrowed(&self, member: [u8; 32]) {
        let entry = QueueEntry {
            member,
            mask: 0,
            value: 0,
            escrow_key: [0x0e; 32],
            mint_policy: None,
        };
        self.chain.records.apply(entry);
        let mut accounts = self.chain.accounts.lock().unwrap();
        let account = accounts
            .get_mut(&CustomRing::new(RING).policy_pda())
            .expect("policy");
        let policy: &mut RingPolicy = bytemuck::from_bytes_mut(&mut account.data);
        policy.own_roots.roots[0].hash = self.chain.records.root().root.0;
    }

    /// The ring's own records serve `list_id` to its policy.
    fn serves_own(&self, list_id: ListId) {
        let mut accounts = self.chain.accounts.lock().unwrap();
        let account = accounts
            .get_mut(&CustomRing::new(RING).policy_pda())
            .expect("policy");
        let policy: &mut RingPolicy = bytemuck::from_bytes_mut(&mut account.data);
        policy.sources[list_id.slot()] = SourceSlot {
            list_id: list_id as u8,
            registry: Address::default(),
        };
    }

    async fn status(&self, update: &SubmitRecordUpdateResponse) -> RecordUpdateStatus {
        self.writer
            .status(GetRecordUpdateStatusRequest {
                update_id: update.update_id.clone(),
            })
            .await
            .expect("status")
    }

    /// The one transaction the flush sent.
    async fn flushed(&self) -> Flushed {
        self.writer.flush().await.expect("flush");
        let sent = std::mem::take(&mut *self.chain.sent.lock().unwrap());
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
        let writes = StorageUpdateIxData::parse(update)
            .expect("update data")
            .writes;
        Flushed {
            mode: *mode,
            members: writes
                .iter()
                .map(|write| write.entry().expect("leaf write").member)
                .collect(),
            writes,
            data,
        }
    }
}

struct Flushed {
    mode: u8,
    /// The members the `Update` writes, in order.
    members: Vec<[u8; 32]>,
    writes: Vec<StorageWriteData>,
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
    signed_until(signer, entries, NOW + 1_000)
}

fn signed_until(
    signer: &Keypair,
    entries: Vec<RecordUpdateEntry>,
    valid_until_slot: u64,
) -> SubmitRecordUpdateRequest {
    signed_update(
        signer,
        RecordUpdate {
            genesis_hash: Hash(GENESIS),
            ring: RING.into(),
            entries,
            valid_until_slot,
            awaited_lists: 0,
        },
    )
}

fn signed_update(signer: &Keypair, update: RecordUpdate) -> SubmitRecordUpdateRequest {
    let mut request = SubmitRecordUpdateRequest {
        registry: REGISTRY.into(),
        update,
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
async fn a_second_escrow_key_for_one_member_is_refused() {
    let records = Records::new().await;
    let escrow = || vec![RecordUpdateEntry::Escrow(escrow_registration())];
    records
        .submit(signed(&wallet(), escrow()))
        .await
        .expect("queued");
    // Another slot bound names another update for the same member.
    assert_eq!(
        refusal(
            records
                .submit(signed_until(&wallet(), escrow(), NOW + 1_001))
                .await
        ),
        RecordUpdateRefusal::EscrowRegistered.code()
    );

    let records = Records::new().await;
    records.escrowed(escrow_registration().member.0);
    assert_eq!(
        refusal(records.submit(signed(&wallet(), escrow())).await),
        RecordUpdateRefusal::EscrowRegistered.code()
    );
}

#[tokio::test]
async fn a_wallet_reader_revocation_goes_out_graced_and_a_block_entry_immediate_alone() {
    let records = Records::new().await;
    let blocked = ListId::Block.record_bit();
    let member = Hash([0x0c; 32]);
    let wallet = wallet();
    let wallet_member = Member::owner_tag(wallet.pubkey().as_array()).expect("wallet member");
    let reader = Member::owner_tag(&[0x0d; 32]).expect("reader member");
    records
        .submit(signed(
            &wallet,
            vec![RecordUpdateEntry::WalletGrant(WalletGrant {
                wallet: Hash(*wallet_member.as_bytes()),
                reader: Hash(*reader.as_bytes()),
                access: ReaderAccess::Revoked,
            })],
        ))
        .await
        .expect("queued");
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

    *records.chain.outcome.lock().unwrap() = TransactionOutcome::Succeeded;
    records.writer.flush().await.expect("settle");
    records
        .chain
        .slot
        .store(NOW + BATCH_WINDOW_SLOTS, Ordering::Relaxed);
    let flushed = records.flushed().await;
    assert_eq!(flushed.mode, tag::UPDATE);
    assert_eq!(
        flushed.members,
        [*Member::wallet_grant(&wallet_member, &reader)
            .expect("grant member")
            .as_bytes()]
    );
}

#[tokio::test]
async fn an_escrow_written_through_the_writer_opens_the_wallets_outputs() {
    let fixture = Fixture::new();
    let registration = escrow_registration();
    let owner = UtxoFields {
        owner_key: wallet().pubkey().to_bytes(),
        nullifier_pk: registration.nullifier_pk.0,
        ..sol(0xc0, 30)
    };
    let source = escrowed_source(&fixture, &[owner], &[]);
    let own_records = source.records.clone();
    let records = RecordsSetup {
        fixture: &fixture,
        source,
        reader_grants: ReaderGrantStore::Tree,
    }
    .serve()
    .await;
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
    let [StorageWriteData::Escrow(published)] = flushed.writes.as_slice() else {
        panic!("one escrow write, {:?}", flushed.writes);
    };
    assert_eq!(published.owner, wallet().pubkey());
    assert_eq!(published.nullifier_pk, registration.nullifier_pk.0);
    assert_eq!(
        tagged_x25519(&published.eph_u).as_slice(),
        registration.eph_pk.0
    );
    assert_eq!(published.ciphertext.as_slice(), registration.ciphertext.0);

    own_records.escrow(&[*published]);
    let service = records.hub.service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert!(escrow_errors(&read_at(&service, None).await).is_empty());
}

#[tokio::test]
async fn a_wallet_enrolment_awaits_the_config_authority_then_lands_with_its_allow_entry() {
    let records = Records::new().await;
    records.serves_own(ListId::Allow);
    let registration = escrow_registration();
    let member = registration.member.clone();
    let allowed = ListId::Allow.record_bit();
    let enrolment = records
        .submit(signed_update(
            &wallet(),
            RecordUpdate {
                genesis_hash: Hash(GENESIS),
                ring: RING.into(),
                entries: vec![RecordUpdateEntry::Escrow(registration)],
                valid_until_slot: NOW + 1_000,
                awaited_lists: allowed,
            },
        ))
        .await
        .expect("awaiting");
    records
        .chain
        .slot
        .store(NOW + BATCH_WINDOW_SLOTS, Ordering::Relaxed);
    records.writer.flush().await.expect("flush");
    assert!(records.chain.sent.lock().unwrap().is_empty());
    assert_eq!(
        records.status(&enrolment).await,
        RecordUpdateStatus::AwaitingAuthority
    );

    let target = ReadTarget {
        cluster: GENESIS,
        service: records.hub.service_pubkey(),
        ring: RING,
    };
    let pending: GetPendingEnrolmentsResponse = records
        .module
        .call(
            GET_PENDING_ENROLMENTS,
            as_object(
                GetPendingEnrolmentsRequest::read(target, authority().pubkey())
                    .sign(&authority())
                    .expect("signed list"),
            ),
        )
        .await
        .expect("pending");
    let [listed] = pending.enrolments.as_slice() else {
        panic!("one pending enrolment, {pending:?}");
    };
    assert_eq!(listed.update_id, enrolment.update_id);
    assert_eq!(listed.member, member);

    records
        .submit(signed(
            &authority(),
            vec![RecordUpdateEntry::Write(RingListWriteView {
                mint_policy: None,
                member: member.clone(),
                mask: allowed,
                value: allowed,
            })],
        ))
        .await
        .expect("approval");
    records
        .chain
        .slot
        .store(NOW + 2 * BATCH_WINDOW_SLOTS, Ordering::Relaxed);
    let flushed = records.flushed().await;
    assert_eq!(flushed.mode, tag::UPDATE);
    assert!(matches!(
        flushed.writes.as_slice(),
        [StorageWriteData::Escrow(_), StorageWriteData::Record(_)]
    ));
    assert_eq!(flushed.members, [member.0, member.0]);

    *records.chain.outcome.lock().unwrap() = TransactionOutcome::Succeeded;
    records.writer.flush().await.expect("settle");
    assert!(matches!(
        records.status(&enrolment).await,
        RecordUpdateStatus::Applied { .. }
    ));
}

/// An enrolment that sets ring-viewing on the wallet's own record.
fn viewing_enrolment(wallet: &Keypair, awaited: ListId) -> SubmitRecordUpdateRequest {
    let member = Member::owner_tag(wallet.pubkey().as_array()).expect("member");
    let viewing = ListId::RingViewing.record_bit();
    signed_update(
        wallet,
        RecordUpdate {
            genesis_hash: Hash(GENESIS),
            ring: RING.into(),
            entries: vec![RecordUpdateEntry::Write(RingListWriteView {
                mint_policy: None,
                member: Hash(*member.as_bytes()),
                mask: viewing,
                value: viewing,
            })],
            valid_until_slot: NOW + 1_000,
            awaited_lists: awaited.record_bit(),
        },
    )
}

#[tokio::test]
async fn an_enrolment_past_its_window_is_refused() {
    let records = Records::new().await;
    records.serves_own(ListId::Allow);
    let wallet = Keypair::new();
    let enrolment = viewing_enrolment(&wallet, ListId::Allow);
    let late = signed_update(
        &wallet,
        RecordUpdate {
            valid_until_slot: NOW + MAX_ENROLMENT_WINDOW_SLOTS + 1,
            ..enrolment.update
        },
    );

    assert_eq!(
        refusal(records.submit(late).await),
        RecordUpdateRefusal::EnrolmentWindow.code()
    );
}

#[tokio::test]
async fn pending_enrolments_page_oldest_first_after_a_cursor() {
    let records = Records::new().await;
    records.serves_own(ListId::Allow);
    let mut submitted = Vec::new();
    for _ in 0..=PENDING_ENROLMENTS_PAGE_LIMIT {
        let enrolment = viewing_enrolment(&Keypair::new(), ListId::Allow);
        submitted.push(records.submit(enrolment).await.expect("awaiting").update_id);
    }
    let target = ReadTarget {
        cluster: GENESIS,
        service: records.hub.service_pubkey(),
        ring: RING,
    };
    let list = |page: GetPendingEnrolmentsRequest| {
        records
            .module
            .call::<_, GetPendingEnrolmentsResponse>(GET_PENDING_ENROLMENTS, as_object(page))
    };
    let read = || GetPendingEnrolmentsRequest::read(target, authority().pubkey());

    let first = list(read().sign(&authority()).expect("signed list"))
        .await
        .expect("first page");
    let listed: Vec<_> = first
        .enrolments
        .iter()
        .map(|row| row.update_id.clone())
        .collect();
    assert_eq!(listed, submitted[..PENDING_ENROLMENTS_PAGE_LIMIT]);
    let cursor = first.next_cursor.expect("a second page");
    assert_eq!(cursor, submitted[PENDING_ENROLMENTS_PAGE_LIMIT - 1]);

    let last = list(
        read()
            .with_cursor(cursor)
            .sign(&authority())
            .expect("signed list"),
    )
    .await
    .expect("last page");
    let [only] = last.enrolments.as_slice() else {
        panic!("one enrolment past the cursor, {last:?}");
    };
    assert_eq!(only.update_id, submitted[PENDING_ENROLMENTS_PAGE_LIMIT]);
    assert_eq!(last.next_cursor, None);
}

#[tokio::test]
async fn database_mode_refuses_an_enrolment_awaiting_a_tree_reader_list() {
    let records = Records::with_reader_grants(ReaderGrantStore::Database).await;
    records.serves_own(ListId::Reader);

    let awaiting = records
        .submit(viewing_enrolment(&wallet(), ListId::Reader))
        .await;

    assert_eq!(
        refusal(awaiting),
        RecordUpdateRefusal::ReaderGrantsInDatabase.code()
    );
}
