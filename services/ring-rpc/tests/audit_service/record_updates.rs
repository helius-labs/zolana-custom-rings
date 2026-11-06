use std::{collections::VecDeque, sync::atomic::AtomicU64};

use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{Revision, StorageRegistry},
    storage_instruction::{tag, StorageUpdateIxData},
    ApplyRecordsIxData, RingPolicy, SourceSlot, GRACE_SLOTS, QUAD_HEIGHT, RING_POLICY,
    ROOT_HISTORY, STORAGE_PROGRAM_ID,
};
use custom_ring_sdk::{CustomRing, PrivateStorageWrite, ProvenPrivateWrite};
use jsonrpsee::MethodsError;
use solana_account::Account;
use solana_transaction::versioned::VersionedTransaction;
use zolana_ring_client::owner_record_key;
use zolana_ring_client::rpc::{
    GetPendingListApprovalsRequest, GetPendingListApprovalsResponse, GetRecordUpdateStatusRequest,
    ListApprovalScope, ReadTarget, ReaderAccess, RecordUpdate, RecordUpdateEntry,
    RecordUpdateStatus, RefuseListApprovalRequest, SubmitRecordUpdateRequest,
    SubmitRecordUpdateResponse, WalletGrant, GET_PENDING_LIST_APPROVALS,
    PENDING_LIST_APPROVALS_PAGE_LIMIT, RECORD_UPDATE_SLOTS, REFUSE_LIST_APPROVAL,
    SUBMIT_RECORD_UPDATE,
};
use zolana_ring_indexer::rpc::{
    GetStorageApplyProofInputsRequest, GetStorageApplyProofInputsResponse,
    GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse, RingListWriteView,
    RingRecordWriteView,
};
use zolana_ring_indexer::tracking::{GetPendingEnrollmentsRequest, GetPendingEnrollmentsResponse};
use zolana_ring_member_registry::ApplyProofInputs;
use zolana_ring_policy::{AssetLimits, ListId, Member, MintPolicy, Rule, RuleTable, Subject};
use zolana_ring_rpc::{
    ChainOutcome, ChainSubmit, LatestBlockhash, PrivateWrites, ProvedEnrollments, ReaderGrantStore,
    RecordUpdateRefusal, RecordWriter, SaltedOwner, StorageChain, Store, BATCH_WINDOW_SLOTS,
    MAX_LIMIT_WINDOW_SLOTS, MAX_LIST_APPROVAL_WINDOW_SLOTS,
};

use super::*;

const REGISTRY: Address = Address::new_from_array([0x52; 32]);
const NOW: u64 = 100;
const NEW_ROOT: [u8; 32] = [0x77; 32];
const BLOCKHASH_HEIGHTS: u64 = 150;

fn initialize_records() -> custom_ring_interface::storage_instruction::InitializeIxData {
    custom_ring_interface::storage_instruction::InitializeIxData {
        registry_id: custom_ring_interface::storage::RegistryId([0; 32]),
        grace_slots: [0; 8],
        ring_id: [1; 32],
        tracking_registry: Address::new_from_array([0x53; 32]),
    }
}

fn wallet() -> Keypair {
    Keypair::new_from_array([47; 32])
}

enum ProofChange {
    Slot(u64),
    PolicyAuthority(Address),
}

struct StubChain {
    slot: AtomicU64,
    height: AtomicU64,
    config: Mutex<RingConfiguration>,
    accounts: Mutex<HashMap<Address, Account>>,
    sent: Mutex<Vec<VersionedTransaction>>,
    outcome: Mutex<Option<ChainOutcome>>,
    /// Answered ahead of `outcome`, one lookup each.
    lookups: Mutex<VecDeque<Option<ChainOutcome>>>,
    records: super::Records,
    proof_change: Mutex<Option<ProofChange>>,
}

impl StubChain {
    fn rotate_policy_authority(&self, authority: Address) {
        self.config.lock().unwrap().roles.policy = authority;
        let mut accounts = self.accounts.lock().unwrap();
        let account = accounts
            .get_mut(&CustomRing::new(RING).policy_pda())
            .expect("policy");
        let policy: &mut RingPolicy = bytemuck::from_bytes_mut(&mut account.data);
        policy.roles.policy = authority;
    }
}

#[async_trait::async_trait]
impl ChainSubmit for StubChain {
    async fn simulate(
        &self,
        _message: &solana_message::VersionedMessage,
    ) -> Result<zolana_ring_rpc::Simulation, RingRpcError> {
        Ok(zolana_ring_rpc::Simulation::Passed)
    }

    async fn account_data(
        &self,
        _address: solana_address::Address,
    ) -> Result<Option<Vec<u8>>, RingRpcError> {
        Ok(None)
    }

    async fn rent_exempt_lamports(&self, _data_len: usize) -> Result<u64, RingRpcError> {
        Ok(0)
    }

    async fn slot(&self) -> Result<u64, RingRpcError> {
        Ok(self.slot.load(Ordering::Relaxed))
    }

    async fn block_height(&self) -> Result<u64, RingRpcError> {
        Ok(self.height.load(Ordering::Relaxed))
    }

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError> {
        let height = self.height.load(Ordering::Relaxed);
        Ok(LatestBlockhash {
            blockhash: solana_hash::Hash::new_from_array([height as u8; 32]),
            last_valid_block_height: height + BLOCKHASH_HEIGHTS,
        })
    }

    async fn send(&self, transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
        self.sent.lock().unwrap().push(transaction.clone());
        Ok(())
    }

    async fn outcome(&self, _signature: Signature) -> Result<Option<ChainOutcome>, RingRpcError> {
        let scripted = self.lookups.lock().unwrap().pop_front();
        Ok(scripted.unwrap_or_else(|| self.outcome.lock().unwrap().clone()))
    }
}

#[async_trait::async_trait]
impl StorageChain for StubChain {
    async fn account(&self, address: Address) -> Result<Option<Account>, RingRpcError> {
        Ok(self.accounts.lock().unwrap().get(&address).cloned())
    }

    /// Read from the ring account, `None` while it is unread.
    async fn ring_config(&self, ring: Address) -> Result<Option<RingConfiguration>, RingRpcError> {
        let read = self
            .accounts
            .lock()
            .unwrap()
            .contains_key(&CustomRing::new(RING).policy_pda());
        Ok((ring == RING && read).then_some(*self.config.lock().unwrap()))
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

    async fn apply_inputs(
        &self,
        request: GetStorageApplyProofInputsRequest,
    ) -> Result<GetStorageApplyProofInputsResponse, RingRpcError> {
        let registry = StorageRegistry::new(Address::default(), &initialize_records());
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
                    exists: false,
                    old_next: empty(),
                    old_lists: 0,
                    old_mint_policy: MintPolicy::EMPTY,
                    slot: path(),
                    low: RingMemberRecordView {
                        member: empty(),
                        next: empty(),
                        lists: 0,
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
        _registry: &StorageRegistry,
    ) -> Result<ApplyRecordsIxData, RingRpcError> {
        match self.proof_change.lock().unwrap().take() {
            Some(ProofChange::Slot(slot)) => self.slot.store(slot, Ordering::Relaxed),
            Some(ProofChange::PolicyAuthority(authority)) => {
                self.rotate_policy_authority(authority);
            }
            None => {}
        }
        Ok(ApplyRecordsIxData {
            new_root: inputs.new_root,
            ..ApplyRecordsIxData::zeroed()
        })
    }

    async fn pending_enrollments(
        &self,
        _request: GetPendingEnrollmentsRequest,
    ) -> Result<GetPendingEnrollmentsResponse, RingRpcError> {
        unreachable!("the record writer applies no enrollment")
    }

    async fn prove_enrollments(
        &self,
        _registry: Address,
        _owners: &[Address],
    ) -> Result<ProvedEnrollments, RingRpcError> {
        unreachable!("the record writer applies no enrollment")
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
    /// A ring whose records registry the writer's authority holds.
    async fn serve(self) -> Records {
        let chain = Arc::new(StubChain {
            slot: AtomicU64::new(NOW),
            height: AtomicU64::new(NOW),
            config: Mutex::new(RingConfiguration {
                auditor_pubkey: X25519Keypair::new().pubkey(),
                roles: custom_ring_interface::RingRoles {
                    policy: authority().pubkey(),
                    ..bytemuck::Zeroable::zeroed()
                },
                mode: RingMode::Confidential,
                delegate: None,
            }),
            accounts: Mutex::default(),
            sent: Mutex::default(),
            outcome: Mutex::new(None),
            lookups: Mutex::default(),
            records: super::Records::listing(&[]),
            proof_change: Mutex::default(),
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
        let registry = StorageRegistry::new(writer.authority(), &initialize_records());
        let mut policy = RingPolicy::zeroed();
        policy.discriminator = RING_POLICY;
        policy.records = REGISTRY;
        policy.roles.policy = authority().pubkey();
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

    /// The entry lands under the registry's newest root.
    fn recorded(&self, entry: RecordWrite) {
        self.chain.records.apply(entry);
        let mut accounts = self.chain.accounts.lock().unwrap();
        let account = accounts.get_mut(&REGISTRY).expect("registry");
        let registry: &mut StorageRegistry = bytemuck::from_bytes_mut(&mut account.data);
        registry.roots[0].hash = self.chain.records.root().root.0;
    }

    /// The ring's own records serve `list_id` to its policy.
    fn serves_own(&self, list_id: ListId) {
        self.policy(|policy| {
            policy.sources[list_id.slot()] = SourceSlot {
                list_id: list_id as u8,
                registry: Address::default(),
            }
        });
    }

    /// The policy reads `table`, each list from the ring's own records.
    fn reads(&self, table: RuleTable) {
        for list_id in table.referenced().iter() {
            self.serves_own(list_id);
        }
        self.policy(|policy| policy.rules = table.encode());
    }

    /// The ring account and its decoded config name `key` the policy authority.
    fn rotate_policy_authority(&self, key: Address) {
        self.chain.rotate_policy_authority(key);
    }

    fn policy(&self, write: impl FnOnce(&mut RingPolicy)) {
        let mut accounts = self.chain.accounts.lock().unwrap();
        let account = accounts
            .get_mut(&CustomRing::new(RING).policy_pda())
            .expect("policy");
        write(bytemuck::from_bytes_mut(&mut account.data));
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
            accounts: message.static_account_keys().to_vec(),
            signature: transaction.signatures[0],
            mode: *mode,
            members: writes.iter().map(|write| write.member).collect(),
            writes,
            data,
        }
    }
}

struct Flushed {
    accounts: Vec<Address>,
    signature: Signature,
    mode: u8,
    /// The members the `Update` writes, in order.
    members: Vec<[u8; 32]>,
    writes: Vec<custom_ring_interface::RecordWriteData>,
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

/// An update pending list approval that sets ring-viewing on the wallet's own record.
fn viewing_update_pending_approval(wallet: &Keypair, awaited: ListId) -> SubmitRecordUpdateRequest {
    let member = owner_record_key(wallet.pubkey().as_array()).expect("member");
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
async fn an_update_pending_approval_past_its_window_is_refused() {
    let records = Records::new().await;
    records.serves_own(ListId::Allow);
    let wallet = Keypair::new();
    let pending = viewing_update_pending_approval(&wallet, ListId::Allow);
    let late = signed_update(
        &wallet,
        RecordUpdate {
            valid_until_slot: NOW + MAX_LIST_APPROVAL_WINDOW_SLOTS + 1,
            ..pending.update
        },
    );

    assert_eq!(
        refusal(records.submit(late).await),
        RecordUpdateRefusal::ListApprovalWindow.code()
    );
}

#[tokio::test]
async fn pending_list_approvals_page_oldest_first_after_a_cursor() {
    let records = Records::new().await;
    records.serves_own(ListId::Allow);
    let mut submitted = Vec::new();
    for _ in 0..=PENDING_LIST_APPROVALS_PAGE_LIMIT {
        let pending = viewing_update_pending_approval(&Keypair::new(), ListId::Allow);
        submitted.push(records.submit(pending).await.expect("awaiting").update_id);
    }
    let target = ReadTarget {
        cluster: GENESIS,
        service: records.hub.service_pubkey(),
        ring: RING,
    };
    let list = |page: GetPendingListApprovalsRequest| {
        records
            .module
            .call::<_, GetPendingListApprovalsResponse>(GET_PENDING_LIST_APPROVALS, as_object(page))
    };
    let read = || {
        GetPendingListApprovalsRequest::read(ListApprovalScope {
            target,
            authority: authority().pubkey(),
            registry: REGISTRY,
        })
    };

    let first = list(read().sign(&authority()).expect("signed list"))
        .await
        .expect("first page");
    let listed: Vec<_> = first
        .pending
        .iter()
        .map(|row| row.update_id.clone())
        .collect();
    assert_eq!(listed, submitted[..PENDING_LIST_APPROVALS_PAGE_LIMIT]);
    let cursor = first.next_cursor.expect("a second page");
    assert_eq!(cursor, submitted[PENDING_LIST_APPROVALS_PAGE_LIMIT - 1]);

    let last = list(
        read()
            .with_cursor(cursor)
            .sign(&authority())
            .expect("signed list"),
    )
    .await
    .expect("last page");
    let [only] = last.pending.as_slice() else {
        panic!("one update past the cursor, {last:?}");
    };
    assert_eq!(only.update_id, submitted[PENDING_LIST_APPROVALS_PAGE_LIMIT]);
    assert_eq!(last.next_cursor, None);
}

#[tokio::test]
async fn rebinding_records_keeps_pending_wallet_grants_in_the_signed_registry() {
    let records = Records::new().await;
    records.serves_own(ListId::Allow);
    let wallet = wallet();
    let owner = Member::owner_tag(wallet.pubkey().as_array()).expect("owner");
    let reader = Member::owner_tag(&[71; 32]).expect("reader");
    let request = RecordUpdate {
        genesis_hash: Hash(GENESIS),
        ring: RING.into(),
        entries: vec![RecordUpdateEntry::WalletGrant(WalletGrant {
            wallet: Hash(*owner.as_bytes()),
            reader: Hash(*reader.as_bytes()),
            access: ReaderAccess::Granted,
        })],
        valid_until_slot: NOW + 1_000,
        awaited_lists: ListId::Allow.record_bit(),
    }
    .sign(REGISTRY, &wallet)
    .expect("signed grant");
    let pending = records.submit(request).await.expect("pending grant");
    let replacement = Address::new_from_array([0x54; 32]);
    {
        let mut accounts = records.chain.accounts.lock().unwrap();
        let registry = accounts.get(&REGISTRY).expect("registry").clone();
        accounts.insert(replacement, registry);
    }
    records.policy(|policy| policy.records = replacement);
    let scope = |registry| ListApprovalScope {
        target: ReadTarget {
            cluster: GENESIS,
            service: records.hub.service_pubkey(),
            ring: RING,
        },
        authority: authority().pubkey(),
        registry,
    };
    let list = |request: GetPendingListApprovalsRequest| {
        records.module.call::<_, GetPendingListApprovalsResponse>(
            GET_PENDING_LIST_APPROVALS,
            as_object(request),
        )
    };
    let signed = GetPendingListApprovalsRequest::read(scope(REGISTRY))
        .sign(&authority())
        .expect("signed list");
    let mut altered = signed.clone();
    altered.registry = replacement.into();
    assert!(list(altered).await.is_err());
    let old_page = list(signed).await.expect("old registry");
    assert_eq!(old_page.pending.len(), 1);
    assert_eq!(old_page.pending[0].update_id, pending.update_id);
    let new_page = list(
        GetPendingListApprovalsRequest::read(scope(replacement))
            .sign(&authority())
            .expect("signed list"),
    )
    .await
    .expect("new registry");
    assert!(new_page.pending.is_empty());
    assert!(list(
        GetPendingListApprovalsRequest::read(scope(replacement))
            .with_cursor(pending.update_id.clone())
            .sign(&authority())
            .expect("signed cursor")
    )
    .await
    .is_err());
    let approval = RecordUpdate {
        genesis_hash: Hash(GENESIS),
        ring: RING.into(),
        entries: vec![list_write(*owner.as_bytes(), ListId::Allow)],
        valid_until_slot: NOW + 1_000,
        awaited_lists: 0,
    }
    .sign(replacement, &authority())
    .expect("signed approval");
    records.submit(approval).await.expect("approval");
    let applied = records.flushed().await;
    assert!(applied.accounts.contains(&replacement));
    assert_eq!(applied.writes.len(), 1);
    assert_eq!(applied.members, [*owner.as_bytes()]);
    assert_eq!(
        records.status(&pending).await,
        RecordUpdateStatus::PendingListApproval
    );
    let refuse = |registry| {
        RefuseListApprovalRequest::refusal(scope(registry), pending.update_id.clone())
            .sign(&authority())
            .expect("signed refusal")
    };
    assert!(records
        .module
        .call::<_, RecordUpdateStatus>(REFUSE_LIST_APPROVAL, as_object(refuse(replacement)))
        .await
        .is_err());
    records
        .module
        .call::<_, RecordUpdateStatus>(REFUSE_LIST_APPROVAL, as_object(refuse(REGISTRY)))
        .await
        .expect("old registry refusal");
    assert!(matches!(
        records.status(&pending).await,
        RecordUpdateStatus::Refused { .. }
    ));
}

#[tokio::test]
async fn database_mode_refuses_an_update_awaiting_a_tree_reader_list() {
    let records = Records::with_reader_grants(ReaderGrantStore::Database).await;
    records.serves_own(ListId::Reader);

    let awaiting = records
        .submit(viewing_update_pending_approval(&wallet(), ListId::Reader))
        .await;

    assert_eq!(
        refusal(awaiting),
        RecordUpdateRefusal::ReaderGrantsInDatabase.code()
    );
}

fn list_write(member: [u8; 32], list: ListId) -> RecordUpdateEntry {
    let bit = list.record_bit();
    RecordUpdateEntry::Write(RingListWriteView {
        mint_policy: None,
        member: Hash(member),
        mask: bit,
        value: bit,
    })
}

#[tokio::test]
async fn an_authority_grant_goes_out_without_waiting_for_the_wallet_batch_window() {
    let records = Records::new().await;
    let member = [0x0c; 32];
    records
        .submit(signed(
            &authority(),
            vec![list_write(member, ListId::Allow)],
        ))
        .await
        .expect("queued");

    let flushed = records.flushed().await;

    assert_eq!(flushed.mode, tag::UPDATE);
    assert_eq!(flushed.members, [member]);
}

#[tokio::test]
async fn an_authority_update_waits_behind_an_earlier_wallet_update_on_the_same_record() {
    let records = Records::new().await;
    let wallet = wallet();
    let member = *owner_record_key(wallet.pubkey().as_array())
        .expect("member")
        .as_bytes();
    let earlier = records
        .submit(signed(
            &wallet,
            vec![list_write(member, ListId::RingViewing)],
        ))
        .await
        .expect("queued");
    let later = records
        .submit(signed(
            &authority(),
            vec![list_write(member, ListId::Allow)],
        ))
        .await
        .expect("queued");

    // The authority update blocks on the wallet one, so the wallet batch goes out first and alone.
    let flushed = records.flushed().await;
    assert_eq!(flushed.members, [member]);
    assert_eq!(
        u64::from_le_bytes(flushed.writes[0].lists.mask),
        ListId::RingViewing.record_bit()
    );
    assert!(matches!(
        records.status(&earlier).await,
        RecordUpdateStatus::Submitted { .. }
    ));
    assert_eq!(records.status(&later).await, RecordUpdateStatus::Queued);

    *records.chain.outcome.lock().unwrap() = Some(ChainOutcome::Confirmed { slot: NOW });
    records.writer.flush().await.expect("settle");
    let flushed = records.flushed().await;
    assert_eq!(flushed.members, [member]);
    assert_eq!(
        u64::from_le_bytes(flushed.writes[0].lists.mask),
        ListId::Allow.record_bit()
    );
}

#[tokio::test]
async fn an_authority_write_queued_before_a_policy_rotation_is_refused_and_a_wallet_write_applies()
{
    let records = Records::new().await;
    records.serves_own(ListId::Allow);
    let applicant = Keypair::new();
    let applicant_member = *owner_record_key(applicant.pubkey().as_array())
        .expect("member")
        .as_bytes();
    let pending = records
        .submit(viewing_update_pending_approval(&applicant, ListId::Allow))
        .await
        .expect("awaiting");
    let approval = records
        .submit(signed(
            &authority(),
            vec![list_write(applicant_member, ListId::Allow)],
        ))
        .await
        .expect("queued");
    let wallet = Keypair::new();
    let member = *owner_record_key(wallet.pubkey().as_array())
        .expect("member")
        .as_bytes();
    records
        .submit(signed(
            &wallet,
            vec![list_write(member, ListId::RingViewing)],
        ))
        .await
        .expect("queued");

    records.rotate_policy_authority(Keypair::new().pubkey());
    records
        .chain
        .slot
        .store(NOW + BATCH_WINDOW_SLOTS, Ordering::Relaxed);
    let flushed = records.flushed().await;

    assert_eq!(flushed.members, [member]);
    assert_eq!(
        records.status(&approval).await,
        RecordUpdateStatus::Refused {
            reason: RecordUpdateRefusal::AuthorityLapsed.to_string()
        }
    );
    // The approval lapsed, the update it joined waits for the new policy authority.
    assert_eq!(
        records.status(&pending).await,
        RecordUpdateStatus::PendingListApproval
    );
}

#[tokio::test]
async fn a_member_that_expires_during_proving_refuses_the_batch_and_preserves_other_updates() {
    let records = Records::new().await;
    let live_member = [0x0c; 32];
    let live = records
        .submit(signed(
            &authority(),
            vec![list_write(live_member, ListId::Allow)],
        ))
        .await
        .expect("queued");
    let expired = records
        .submit(signed_until(
            &authority(),
            vec![list_write([0x0d; 32], ListId::Allow)],
            NOW + 1,
        ))
        .await
        .expect("queued");
    *records.chain.proof_change.lock().unwrap() = Some(ProofChange::Slot(NOW + 2));

    records.writer.flush().await.expect("flush");

    assert!(records.chain.sent.lock().unwrap().is_empty());
    assert_eq!(records.status(&live).await, RecordUpdateStatus::Queued);
    assert_eq!(
        records.status(&expired).await,
        RecordUpdateStatus::Refused {
            reason: RecordUpdateRefusal::Expired.to_string()
        }
    );
    assert_eq!(records.flushed().await.members, [live_member]);
}

#[tokio::test]
async fn a_policy_rotation_during_proving_refuses_the_approval_and_preserves_wallet_updates() {
    let records = Records::new().await;
    records.serves_own(ListId::Allow);
    let applicant = Keypair::new();
    let applicant_member = *owner_record_key(applicant.pubkey().as_array())
        .expect("member")
        .as_bytes();
    let pending = records
        .submit(viewing_update_pending_approval(&applicant, ListId::Allow))
        .await
        .expect("awaiting");
    let approval = records
        .submit(signed(
            &authority(),
            vec![list_write(applicant_member, ListId::Allow)],
        ))
        .await
        .expect("queued");
    let wallet = Keypair::new();
    let wallet_member = *owner_record_key(wallet.pubkey().as_array())
        .expect("member")
        .as_bytes();
    let live = records
        .submit(signed(
            &wallet,
            vec![list_write(wallet_member, ListId::RingViewing)],
        ))
        .await
        .expect("queued");
    *records.chain.proof_change.lock().unwrap() =
        Some(ProofChange::PolicyAuthority(Keypair::new().pubkey()));

    records.writer.flush().await.expect("flush");

    assert!(records.chain.sent.lock().unwrap().is_empty());
    assert_eq!(
        records.status(&approval).await,
        RecordUpdateStatus::Refused {
            reason: RecordUpdateRefusal::AuthorityLapsed.to_string()
        }
    );
    assert_eq!(
        records.status(&pending).await,
        RecordUpdateStatus::PendingListApproval
    );
    assert_eq!(records.status(&live).await, RecordUpdateStatus::Queued);
    records
        .chain
        .slot
        .store(NOW + BATCH_WINDOW_SLOTS, Ordering::Relaxed);
    assert_eq!(records.flushed().await.members, [wallet_member]);
}

#[tokio::test]
async fn an_invalid_mint_limits_update_is_refused_at_admission() {
    let records = Records::new().await;
    let asset = *Member::asset(&Address::new_from_array([0x3a; 32]))
        .expect("asset member")
        .as_bytes();
    let limits_update = |limits| RecordUpdate {
        genesis_hash: Hash(GENESIS),
        ring: RING.into(),
        entries: vec![RecordUpdateEntry::Write(RingListWriteView {
            mint_policy: Some(MintPolicy {
                limits,
                ..MintPolicy::EMPTY
            }),
            member: Hash(asset),
            mask: 0,
            value: 0,
        })],
        valid_until_slot: NOW + 1_000,
        awaited_lists: 0,
    };
    let sender_window = |sender_window_slots| AssetLimits {
        sender_cap: 10,
        sender_window_slots,
        ..AssetLimits::EMPTY
    };
    // Refused ahead of the signature check, an unpaired cap hashes to no statement.
    for limits in [
        AssetLimits {
            sender_cap: 10,
            ..AssetLimits::EMPTY
        },
        AssetLimits {
            volume_window_slots: 10,
            ..AssetLimits::EMPTY
        },
        sender_window(MAX_LIMIT_WINDOW_SLOTS + 1),
    ] {
        let unsigned = SubmitRecordUpdateRequest {
            registry: REGISTRY.into(),
            update: limits_update(limits),
            signer: authority().pubkey().into(),
            signature: Signature::default().into(),
        };
        assert_eq!(
            refusal(records.submit(unsigned).await),
            RecordUpdateRefusal::InvalidLimits.code(),
            "{limits:?}"
        );
    }
    let longest = || {
        signed_update(
            &authority(),
            limits_update(sender_window(MAX_LIMIT_WINDOW_SLOTS)),
        )
    };
    assert_eq!(
        refusal(records.submit(longest()).await),
        RecordUpdateRefusal::LimitsWithoutRecord.code()
    );

    records.recorded(RecordWrite {
        member: asset,
        mint_policy: Some(MintPolicy {
            threshold: 5,
            ..MintPolicy::EMPTY
        }),
        ..RecordWrite::default()
    });
    records.submit(longest()).await.expect("queued");
}

#[tokio::test]
async fn a_batch_that_lands_after_its_status_lookup_applies_once_past_expiry() {
    let records = Records::new().await;
    let update = records
        .submit(signed(
            &authority(),
            vec![list_write([0x0c; 32], ListId::Allow)],
        ))
        .await
        .expect("queued");
    records.flushed().await;

    // The batch lands between the status lookup and the height read.
    records
        .chain
        .height
        .store(NOW + BLOCKHASH_HEIGHTS + 1, Ordering::Relaxed);
    records.chain.lookups.lock().unwrap().push_back(None);
    *records.chain.outcome.lock().unwrap() = Some(ChainOutcome::Confirmed { slot: NOW });
    records.writer.flush().await.expect("settle");
    records.writer.flush().await.expect("next flush");

    assert!(records.chain.sent.lock().unwrap().is_empty());
    assert!(matches!(
        records.status(&update).await,
        RecordUpdateStatus::Applied { .. }
    ));
}

#[tokio::test]
async fn an_expired_batch_is_requeued_and_resent_once() {
    let records = Records::new().await;
    let update = records
        .submit(signed(
            &authority(),
            vec![list_write([0x0c; 32], ListId::Allow)],
        ))
        .await
        .expect("queued");
    let first = records.flushed().await;

    records
        .chain
        .height
        .store(NOW + BLOCKHASH_HEIGHTS + 1, Ordering::Relaxed);
    records.writer.flush().await.expect("requeue");
    let resent = records.flushed().await;
    records.writer.flush().await.expect("pending resend");

    assert_eq!(resent.members, first.members);
    assert!(records.chain.sent.lock().unwrap().is_empty());
    let RecordUpdateStatus::Submitted { signature } = records.status(&update).await else {
        panic!("the resent batch is pending");
    };
    assert_eq!(signature.0, resent.signature);
    assert_ne!(resent.signature, first.signature);
}

#[tokio::test]
async fn an_unread_ring_account_holds_its_updates_until_a_later_pass() {
    let records = Records::new().await;
    let member = [0x0c; 32];
    let queued = records
        .submit(signed(
            &authority(),
            vec![list_write(member, ListId::Allow)],
        ))
        .await
        .expect("queued");
    let policy_pda = CustomRing::new(RING).policy_pda();
    let policy = records
        .chain
        .accounts
        .lock()
        .unwrap()
        .remove(&policy_pda)
        .expect("policy");

    records.writer.flush().await.expect("flush");

    assert!(records.chain.sent.lock().unwrap().is_empty());
    assert_eq!(records.status(&queued).await, RecordUpdateStatus::Queued);
    records
        .chain
        .accounts
        .lock()
        .unwrap()
        .insert(policy_pda, policy);
    assert_eq!(records.flushed().await.members, [member]);
}

#[tokio::test]
async fn an_unexpired_full_history_holds_no_graced_batch_past_its_window() {
    let records = Records::new().await;
    let wallet = wallet();
    let member = *owner_record_key(wallet.pubkey().as_array())
        .expect("member")
        .as_bytes();
    records
        .submit(signed_until(
            &wallet,
            vec![list_write(member, ListId::RingViewing)],
            NOW + RECORD_UPDATE_SLOTS,
        ))
        .await
        .expect("queued");
    let sendable = NOW + BATCH_WINDOW_SLOTS;
    {
        let mut accounts = records.chain.accounts.lock().unwrap();
        let account = accounts.get_mut(&REGISTRY).expect("registry");
        let registry: &mut StorageRegistry = bytemuck::from_bytes_mut(&mut account.data);
        registry.roots[ROOT_HISTORY - 1].expires_at = (sendable + GRACE_SLOTS).to_le_bytes();
    }
    records.chain.slot.store(sendable - 1, Ordering::Relaxed);
    records.writer.flush().await.expect("flush");
    assert!(records.chain.sent.lock().unwrap().is_empty());

    records.chain.slot.store(sendable, Ordering::Relaxed);

    let flushed = records.flushed().await;
    assert_eq!(flushed.mode, tag::UPDATE);
    assert_eq!(flushed.members, [member]);
}

#[tokio::test]
async fn a_wallet_reader_revocation_goes_out_graced_and_a_block_entry_immediate_alone() {
    let records = Records::new().await;
    records.reads(
        RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::Block))
            .build(),
    );
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
    assert_eq!(flushed.mode, tag::UPDATE);
    assert_eq!(flushed.members, [member.0]);
    assert_eq!(flushed.data.len(), 1);

    *records.chain.outcome.lock().unwrap() = Some(ChainOutcome::Confirmed { slot: NOW });
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
async fn a_wallet_update_pending_list_approval_lands_with_its_allow_entry() {
    let records = Records::new().await;
    records.serves_own(ListId::Allow);
    let wallet = wallet();
    let member = Hash(
        *owner_record_key(wallet.pubkey().as_array())
            .expect("member")
            .as_bytes(),
    );
    let allowed = ListId::Allow.record_bit();
    let pending_update = records
        .submit(viewing_update_pending_approval(&wallet, ListId::Allow))
        .await
        .expect("awaiting");
    records
        .chain
        .slot
        .store(NOW + BATCH_WINDOW_SLOTS, Ordering::Relaxed);
    records.writer.flush().await.expect("flush");
    assert!(records.chain.sent.lock().unwrap().is_empty());
    assert_eq!(
        records.status(&pending_update).await,
        RecordUpdateStatus::PendingListApproval
    );

    let target = ReadTarget {
        cluster: GENESIS,
        service: records.hub.service_pubkey(),
        ring: RING,
    };
    let pending: GetPendingListApprovalsResponse = records
        .module
        .call(
            GET_PENDING_LIST_APPROVALS,
            as_object(
                GetPendingListApprovalsRequest::read(ListApprovalScope {
                    target,
                    authority: authority().pubkey(),
                    registry: REGISTRY,
                })
                .sign(&authority())
                .expect("signed list"),
            ),
        )
        .await
        .expect("pending");
    let [listed] = pending.pending.as_slice() else {
        panic!("one pending update, {pending:?}");
    };
    assert_eq!(listed.update_id, pending_update.update_id);
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
    assert_eq!(flushed.writes.len(), 2);
    assert_eq!(flushed.members, [member.0, member.0]);

    *records.chain.outcome.lock().unwrap() = Some(ChainOutcome::Confirmed { slot: NOW });
    records.writer.flush().await.expect("settle");
    assert!(matches!(
        records.status(&pending_update).await,
        RecordUpdateStatus::Applied { .. }
    ));
}

/// The owner behind `SALTED_KEY`, proven under the tracking root at `TRACKING_REVISION`.
#[derive(Default)]
struct HeldOwner {
    proved: Mutex<Vec<(u8, Address, [u8; 32])>>,
}

const SALTED_KEY: [u8; 32] = [0x0d; 32];
const LIST_SALT: [u8; 32] = [0x2a; 32];
const TRACKING_REVISION: u64 = 40;

fn salted_owner() -> Address {
    Address::new_from_array([0x0e; 32])
}

#[async_trait::async_trait]
impl PrivateWrites for HeldOwner {
    async fn salted_owner(
        &self,
        ring: Address,
        written_key: [u8; 32],
    ) -> Result<Option<SaltedOwner>, RingRpcError> {
        Ok(
            (ring == RING && written_key == SALTED_KEY).then_some(SaltedOwner {
                owner: salted_owner(),
                list_salt: LIST_SALT,
            }),
        )
    }

    async fn prove(
        &self,
        write: PrivateStorageWrite<'_>,
    ) -> Result<ProvenPrivateWrite, custom_ring_sdk::RingError> {
        self.proved.lock().unwrap().extend(
            write
                .owners
                .iter()
                .map(|owner| (owner.write_index, owner.owner, owner.list_salt)),
        );
        Ok(ProvenPrivateWrite {
            apply: ApplyRecordsIxData {
                new_root: write.inputs.new_root,
                ..ApplyRecordsIxData::zeroed()
            },
            tracking_revision: Revision::from(TRACKING_REVISION),
        })
    }
}

impl Records {
    fn serve_salted_owner(&self) -> Arc<HeldOwner> {
        let held = Arc::new(HeldOwner::default());
        assert!(self.writer.serve_private_writes(held.clone()).is_ok());
        held
    }

    async fn submit_salted_write(&self) -> SubmitRecordUpdateResponse {
        self.submit(signed(
            &authority(),
            vec![list_write(SALTED_KEY, ListId::PrivateAllow)],
        ))
        .await
        .expect("queued")
    }
}

#[tokio::test]
async fn a_salted_owner_write_sends_its_tracking_revision_and_the_pinned_registry() {
    let records = Records::new().await;
    let held = records.serve_salted_owner();
    records.submit_salted_write().await;

    let flushed = records.flushed().await;

    let sent = StorageUpdateIxData::parse(&flushed.data[0][1..]).expect("update data");
    assert_eq!(
        sent.tracking_revision,
        Some(Revision::from(TRACKING_REVISION))
    );
    assert_eq!(flushed.members, [SALTED_KEY]);
    assert_eq!(
        *held.proved.lock().unwrap(),
        [(0, salted_owner(), LIST_SALT)]
    );
    let pinned = StorageRegistry::new(Address::default(), &initialize_records()).tracking_registry;
    assert_eq!(flushed.accounts.last(), Some(&pinned));
}

#[tokio::test]
async fn a_salted_owner_write_without_a_private_write_source_sends_nothing() {
    let records = Records::new().await;
    records.submit_salted_write().await;

    records.writer.flush().await.expect("flush");

    assert!(records.chain.sent.lock().unwrap().is_empty());
}
