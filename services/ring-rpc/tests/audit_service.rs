#[path = "../../../sdk-libs/client/tests/common/deposit.rs"]
mod deposit_fixture;
#[path = "../../../sdk-libs/client/tests/common/origin.rs"]
mod origin_fixture;

#[path = "audit_service/audit_pages.rs"]
mod audit_pages;
#[path = "audit_service/authorization.rs"]
mod authorization;
#[path = "audit_service/backfill.rs"]
mod backfill;
#[path = "audit_service/cosign_relay.rs"]
mod cosign_relay;
#[path = "audit_service/deposits.rs"]
mod deposits;
#[path = "audit_service/reader_grants.rs"]
mod reader_grants;
#[path = "audit_service/record_updates.rs"]
mod record_updates;
#[path = "common/relay.rs"]
mod relay_fixture;
#[path = "../../../sdk-libs/client/tests/common/transfer.rs"]
pub mod transfer;

use custom_ring_interface::{
    encode_ring_confidential_delivered_output,
    storage_instruction::{EscrowWriteData, StorageWriteData},
    tagged_x25519, QueueEntry, RingMode, DELIVERED_AUDIT_CAPACITIES,
};
use spr_keypair::{X25519Keypair, X25519Pubkey};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, LazyLock, Mutex,
    },
    time::Duration,
};
use zolana_ring_member_registry::{MemberRecord, MemberRegistryTree, RecordOpening, RecordTree};
use zolana_ring_policy::{ListId, Member, MintPolicy};

use p256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::Digest;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{ClientError, Context, GetShieldedTransactionsByTagsResponse};
use spr_indexer_api::{Base64String, Hash, Limit};
use spr_keypair::ViewingKey;
use spr_transaction::{Mint, ShieldedTransaction, SOL_MINT};
use zolana_ring_client::{
    auditor_view_tag, ring_event_origin_in,
    rpc::{
        unix_now, AuditorKeyStatement, CreateAuditorKeyRequest, CreateAuditorKeyResponse,
        DecryptedInputRing, DecryptedOutputKind, DecryptedPayloadError, DecryptedSender,
        DecryptedTransaction, DecryptedWithdrawal, DepositRecord, GetAuditedMergesResponse,
        GetAuditedUtxosRequest, GetAuditedUtxosResponse, GetDecryptedTransactionsRequest,
        GetDecryptedTransactionsResponse, HealthResponse, KeyMode, PagedRead, ReadAttestation,
        ReadAuth, ReadBuildError, ReadSignature, ReadSigner, ReadTarget, ReaderGrantAction,
        ReaderGrantAttestation, ReaderGrantRequest, RegistryRoot, RegistryStatus, RingActivation,
        RingChainStatus, RingDepositsRequest, RingDepositsResponse, RingState, RingStatusRequest,
        RingStatusResponse, SkippedReason, WebAuthnAssertion, AUDITED_UTXOS_LIMIT,
        CREATE_AUDITOR_KEY, GET_AUDITED_MERGES, GET_AUDITED_UTXOS, GET_DECRYPTED_TRANSACTIONS,
        HEALTH, RING_DEPOSITS, RING_STATUS, SET_READER_GRANT,
    },
    seal_deposits, AnonymousInputs, AuditDisclosure, AuditError, ConfirmedDeposit, DepositOpening,
    MergeAuditPage, MergeAuditResult, OutputPayloadErrorKind, ReaderKey, RingOrigin,
    RingWithdrawal,
};
use zolana_ring_client::{P256ReaderKey, RingIndexerError, StorageTip};
use zolana_ring_indexer::rpc::{
    GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse,
    GetStorageMemberRecordsRequest, GetStorageMemberRecordsResponse, RingIndexedMemberRecordView,
    RingMemberOpening, RingMemberRecordView, RingRecordPathView, StorageRootView,
};
use zolana_ring_rpc::{
    rpc_module, AuditRead, AuditService, Clock, DepositHistory, DepositPage, Hub,
    MergeAuditRequest, OriginPolicy, Origins, Page, ReadCheck, RingConfiguration, RingHistoryPage,
    RingRpcError, RootSecret, Store, TransactionPage, TransactionSource, Unauthorized, AUTH_SKEW,
};
use zolana_ring_transaction::{RingAssets, RingDeliveredBody};

use transfer::{
    field, input_opening, x25519_u, Frame, Output, Placement, Publish, Rail, Transfer, UtxoFields,
};

/// Raw id of the tree these fixtures publish into. A slot names the id, not the
/// account; the account is `pda::tree(TREE_ID)` wherever one is needed.
const TREE_ID: u16 = 4;
const RING: Address = Address::new_from_array([5; 32]);
const GENESIS: [u8; 32] = [9; 32];
const FIXTURE_AUDITOR: [u8; 32] = [0x41; 32];
/// Ring history reads past it fail, a cycling page set ends there.
const HISTORY_READ_CAP: usize = 1_000;
const OTHER_RING: Address = Address::new_from_array([6; 32]);
const SENDER: Address = Address::new_from_array([7; 32]);
const RECIPIENT: Address = Address::new_from_array([8; 32]);
const WITHDRAWN: u64 = 250;
const TOKEN_ACCOUNT: Address = Address::new_from_array([9; 32]);
const MINT: Address = Address::new_from_array([10; 32]);
const SPL_WITHDRAWN: u64 = 75;
const ORIGIN: &str = "http://localhost:3000";
/// Every fixture ring's own `StorageRegistry`.
const RECORDS: Address = Address::new_from_array([11; 32]);
const USER_PRESENT_AND_VERIFIED: u8 = 0x05;

fn authority() -> Keypair {
    Keypair::new_from_array([42; 32])
}

fn delegate() -> Keypair {
    Keypair::new_from_array([45; 32])
}

fn deployer() -> Keypair {
    Keypair::new_from_array([44; 32])
}

fn stranger() -> Keypair {
    Keypair::new_from_array([43; 32])
}

struct Passkey {
    key: p256::ecdsa::SigningKey,
    origin: &'static str,
    relying_party: &'static str,
    flags: u8,
    cross_origin: bool,
    padded_challenge: bool,
    top_origin: Option<&'static str>,
}

impl Passkey {
    fn new(byte: u8) -> Self {
        Self {
            key: p256::ecdsa::SigningKey::from_bytes(&[byte; 32].into()).expect("scalar"),
            origin: ORIGIN,
            relying_party: "localhost",
            flags: USER_PRESENT_AND_VERIFIED,
            cross_origin: false,
            padded_challenge: false,
            top_origin: None,
        }
    }

    fn origin(mut self, origin: &'static str) -> Self {
        self.origin = origin;
        self
    }

    fn relying_party(mut self, relying_party: &'static str) -> Self {
        self.relying_party = relying_party;
        self
    }

    fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    fn cross_origin(mut self) -> Self {
        self.cross_origin = true;
        self
    }

    fn padded_challenge(mut self) -> Self {
        self.padded_challenge = true;
        self
    }

    fn top_origin(mut self, origin: &'static str) -> Self {
        self.top_origin = Some(origin);
        self
    }

    fn pubkey(&self) -> P256ReaderKey {
        let sec1 = self.key.verifying_key().to_encoded_point(true);
        P256ReaderKey::from_bytes(sec1.as_bytes().try_into().expect("compressed key")).expect("key")
    }
}

impl ReadSigner for Passkey {
    fn reader(&self) -> Result<ReaderKey, zolana_ring_client::ReaderKeyError> {
        ReaderKey::p256(self.pubkey())
    }

    fn sign(&self, attestation: &[u8]) -> Result<ReadSignature, ReadBuildError> {
        let mut challenge = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            sha2::Sha256::digest(attestation),
        );
        if self.padded_challenge {
            challenge.push('=');
        }
        let top_origin = self
            .top_origin
            .map(|origin| format!(r#", "topOrigin":"{origin}""#))
            .unwrap_or_default();
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{}","crossOrigin":{}{top_origin}}}"#,
            self.origin, self.cross_origin
        );
        let mut authenticator_data = sha2::Sha256::digest(self.relying_party).to_vec();
        authenticator_data.push(self.flags);
        authenticator_data.extend_from_slice(&[0, 0, 0, 1]);
        let mut signed = sha2::Sha256::new();
        signed.update(&authenticator_data);
        signed.update(sha2::Sha256::digest(client_data.as_bytes()));
        let signature: p256::ecdsa::Signature = self
            .key
            .sign_prehash(&signed.finalize())
            .expect("signature");
        Ok(ReadSignature::WebAuthn {
            signature_der: signature.to_der().as_bytes().to_vec(),
            assertion: WebAuthnAssertion {
                authenticator_data: authenticator_data.into(),
                client_data_json: client_data.into_bytes().into(),
            },
        })
    }
}

fn origins() -> Origins {
    OriginPolicy::new(vec![ORIGIN.to_owned()])
        .with_relying_party_id("localhost".to_owned())
        .build()
        .expect("origins")
}

/// Fixture hubs share one auditor key and so one service key.
static FIXTURE_SERVICE: LazyLock<Address> = LazyLock::new(|| {
    let fixture = Fixture::new();
    fixture.hub(fixture.source()).service_pubkey()
});

fn target(ring: Address) -> ReadTarget {
    ReadTarget {
        cluster: GENESIS,
        service: *FIXTURE_SERVICE,
        ring,
    }
}

fn served(hub: &Hub<StaticSource>, ring: Address) -> ReadTarget {
    ReadTarget {
        cluster: GENESIS,
        service: hub.service_pubkey(),
        ring,
    }
}

fn signed_request<S: ReadSigner + ?Sized>(
    signer: &S,
    target: ReadTarget,
    timestamp: u64,
) -> GetDecryptedTransactionsRequest {
    GetDecryptedTransactionsRequest::read(target)
        .at(timestamp)
        .sign(signer)
        .expect("signed request")
}

fn auth<S: ReadSigner + ?Sized>(signer: &S) -> ReadAuth {
    signed_request(signer, target(RING), unix_now().expect("clock")).auth
}

fn decide_now(auth: &ReadAuth, origins: &Origins) -> Result<ReaderKey, Unauthorized> {
    let attestation = ReadAttestation {
        read: PagedRead::DecryptedTransactions,
        target: target(RING),
        cursor: None,
        limit: None,
        wallet: None,
    };
    ReadCheck {
        auth,
        attestation: &attestation,
        now: unix_now().expect("clock"),
        origins,
    }
    .decide()
    .map(|claim| claim.reader)
}

#[test]
fn signatures_bind_the_reader_and_request() {
    let wallet = delegate();
    assert_eq!(
        decide_now(&auth(&wallet), &origins()).expect("wallet claim"),
        ReaderKey::ed25519(wallet.pubkey()).expect("reader")
    );
    let passkey = Passkey::new(46);
    assert_eq!(
        decide_now(&auth(&passkey), &origins()).expect("passkey claim"),
        ReaderKey::p256(passkey.pubkey()).expect("reader")
    );

    let mut changed = auth(&wallet);
    changed.timestamp += 1;
    assert_eq!(
        decide_now(&changed, &origins()),
        Err(Unauthorized::BadSignature)
    );
    assert_eq!(
        decide_now(
            &signed_request(&wallet, target(OTHER_RING), unix_now().expect("clock")).auth,
            &origins()
        ),
        Err(Unauthorized::BadSignature)
    );
}

#[test]
fn passkeys_require_canonical_same_origin_assertions() {
    for (passkey, expected) in [
        (
            Passkey::new(46).origin("https://evil.example"),
            Unauthorized::OriginNotAllowed,
        ),
        (
            Passkey::new(46).relying_party("evil.example"),
            Unauthorized::RelyingPartyMismatch,
        ),
        (
            Passkey::new(46).flags(0x01),
            Unauthorized::UserVerificationMissing,
        ),
        (
            Passkey::new(46).flags(0x04),
            Unauthorized::UserVerificationMissing,
        ),
        (
            Passkey::new(46).cross_origin(),
            Unauthorized::CrossOriginAssertion,
        ),
        (
            Passkey::new(46).top_origin("https://top.example"),
            Unauthorized::CrossOriginAssertion,
        ),
        (
            Passkey::new(46).padded_challenge(),
            Unauthorized::ChallengeMismatch,
        ),
    ] {
        assert_eq!(decide_now(&auth(&passkey), &origins()), Err(expected));
    }
}

type Frames = Arc<Mutex<HashMap<Signature, Vec<u8>>>>;

#[derive(Clone)]
struct StaticSource {
    transactions: Vec<ShieldedTransaction>,
    origins: HashMap<(Signature, u16), bool>,
    frames: Frames,
    /// Confirmed deposits and merges do not carry transfer auditor messages.
    confirmed_events: HashMap<(Signature, u16), zolana_ring_client::ConfirmedEvent>,
    /// The capsule bindings of each audited deposit.
    deposits: HashMap<Signature, Vec<ConfirmedDeposit>>,
    next_cursor: Option<Vec<u8>>,
    scanned_through: Option<Vec<u8>>,
    /// Per ring, so a read can never be authorized against another ring's
    /// config.
    configs: HashMap<Address, RingConfiguration>,
    /// Per ring, the default where SPP and the registry hold nothing.
    chain: HashMap<Address, RingChainStatus>,
    /// Per auditor view tag, empty when every read shares `transactions`.
    by_tag: HashMap<[u8; 32], Vec<ShieldedTransaction>>,
    /// The ring's own storage tree, rewritten while a hub serves it.
    records: Records,
    /// Per program, absent when immutable or not deployed.
    upgrade_authorities: HashMap<Address, Address>,
    healthy: bool,
    assets: Option<RingAssets>,
    asset_reads: Arc<AtomicUsize>,
    asset_delay: Option<Duration>,
    /// Ring history, newest first.
    history: Vec<Examined>,
    examined_limit: Arc<AtomicUsize>,
    /// Per request cursor, empty when every read shares one page.
    pages: HashMap<Option<Vec<u8>>, Paged>,
    record_reads: Arc<AtomicUsize>,
    history_reads: Arc<AtomicUsize>,
}

/// The indexer page one cursor reads.
#[derive(Clone)]
struct Paged {
    transactions: Vec<ShieldedTransaction>,
    next_cursor: Option<Vec<u8>>,
    scanned_through: Option<Vec<u8>>,
}

/// One ring signature and the deposits it made.
#[derive(Clone)]
struct Examined {
    signature: Signature,
    slot: u64,
    deposits: Vec<DepositRecord>,
}

impl StaticSource {
    fn with_transactions(mut self, transactions: Vec<ShieldedTransaction>) -> Self {
        self.origins = transactions
            .iter()
            .filter_map(|transaction| {
                transaction
                    .event_index
                    .map(|event_index| ((transaction.tx_signature, event_index), true))
            })
            .collect();
        self.transactions = transactions;
        self
    }
}

impl StaticSource {
    /// The page `page` names, else every transaction the source holds under `tagged`.
    fn page_at(
        &self,
        page: &Page,
        tagged: Option<&Vec<ShieldedTransaction>>,
    ) -> GetShieldedTransactionsByTagsResponse {
        assert!(page.limit().get() <= 100);
        let paged = self
            .pages
            .get(&page.cursor().map(ToOwned::to_owned))
            .cloned()
            .unwrap_or_else(|| Paged {
                transactions: tagged.cloned().unwrap_or_else(|| self.transactions.clone()),
                next_cursor: self.next_cursor.clone(),
                scanned_through: self.scanned_through.clone(),
            });
        GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 99,
            },
            transactions: paged.transactions,
            next_cursor: paged.next_cursor,
            scanned_through: paged.scanned_through,
            output_tree_id: Some(TREE_ID),
        }
    }
}

impl TransactionSource for StaticSource {
    async fn merge_audit_page(
        &self,
        _request: MergeAuditRequest<'_>,
    ) -> Result<MergeAuditPage, AuditError> {
        Ok(MergeAuditPage {
            context: spr_indexer_api::Context {
                block_time: 0,
                slot: 99,
            },
            result: MergeAuditResult {
                opened: Vec::new(),
                unresolved: Vec::new(),
            },
            next_cursor: None,
        })
    }

    fn transactions_by_tag(
        &self,
        request: TransactionPage<'_>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send
    {
        let response = self.page_at(request.page, self.by_tag.get(&request.tag));
        async move { Ok(response) }
    }

    fn ring_history(
        &self,
        request: RingHistoryPage<'_>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send
    {
        let capped = self.history_reads.fetch_add(1, Ordering::Relaxed) >= HISTORY_READ_CAP;
        let response = self.page_at(request.page, None);
        async move {
            match capped {
                true => Err(ClientError::Rpc("history read cap".to_owned())),
                false => Ok(response),
            }
        }
    }

    fn transaction_origin(
        &self,
        signature: Signature,
        event_index: u16,
        _ring: Address,
    ) -> impl Future<Output = Result<RingOrigin, AuditError>> + Send {
        let origin = self
            .origins
            .get(&(signature, event_index))
            .copied()
            .map(|ring_invoked| RingOrigin {
                event: self
                    .confirmed_events
                    .get(&(signature, event_index))
                    .cloned()
                    .unwrap_or_else(|| {
                        origin_fixture::event(
                            self.transactions
                                .iter()
                                .chain(self.by_tag.values().flatten())
                                .find(|tx| {
                                    tx.tx_signature == signature
                                        && tx.event_index == Some(event_index)
                                })
                                .expect("confirmed event"),
                        )
                    }),
                ring_invoked,
                signers: vec![SENDER],
                deposits: self.deposits.get(&signature).cloned().unwrap_or_default(),
                merge_disclosure: None,
                transact: self.frames.lock().unwrap().get(&signature).cloned(),
                withdrawals: vec![
                    RingWithdrawal {
                        screened_owner: None,
                        recipient: RECIPIENT,
                        asset: SOL_MINT,
                        amount: WITHDRAWN,
                    },
                    RingWithdrawal {
                        screened_owner: None,
                        recipient: TOKEN_ACCOUNT,
                        asset: MINT,
                        amount: SPL_WITHDRAWN,
                    },
                ],
            })
            .ok_or_else(|| AuditError::Unavailable {
                signature,
                message: "not found".to_owned(),
            });
        async move { origin }
    }

    async fn ring_deposits(&self, page: DepositPage) -> Result<DepositHistory, ClientError> {
        self.examined_limit.store(page.limit, Ordering::Relaxed);
        let start = match page.before {
            Some(before) => self
                .history
                .iter()
                .position(|entry| entry.signature == before)
                .map(|index| index + 1)
                .ok_or_else(|| ClientError::Rpc("unknown cursor".to_owned()))?,
            None => 0,
        };
        let examined: Vec<_> = self
            .history
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take(page.limit)
            .collect();
        Ok(DepositHistory {
            deposits: examined
                .iter()
                .flat_map(|entry| entry.deposits.clone())
                .collect(),
            cursor: examined
                .last()
                .map(|entry| entry.signature)
                .filter(|_| examined.len() == page.limit),
            oldest_slot: examined.last().map(|entry| entry.slot),
        })
    }

    fn ring_config(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<Option<RingConfiguration>, ClientError>> + Send {
        let config = self.configs.get(&ring).copied();
        async move { Ok(config) }
    }

    fn ring_chain_status(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<RingChainStatus, ClientError>> + Send {
        let status = self.chain.get(&ring).cloned().unwrap_or_default();
        async move { Ok(status) }
    }

    async fn slot(&self) -> Result<u64, ClientError> {
        Ok(relay_fixture::SLOT)
    }

    async fn records_root(&self, _ring: Address) -> Result<Option<StorageTip>, ClientError> {
        let root = self.records.root();
        Ok(Some(StorageTip {
            registry: RECORDS,
            root: root.root.0,
            revision: root.revision,
        }))
    }

    async fn storage_member_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingIndexerError> {
        assert_eq!(request.registry.0, RECORDS);
        let root = self.records.root();
        assert_eq!(request.expected_root, root.root);
        Ok(GetStorageMemberOpeningsResponse {
            context: spr_indexer_api::Context {
                block_time: 0,
                slot: 99,
            },
            root,
            openings: request
                .members
                .iter()
                .map(|member| self.records.opening(&member.0))
                .collect(),
        })
    }

    async fn storage_member_records(
        &self,
        request: GetStorageMemberRecordsRequest,
    ) -> Result<GetStorageMemberRecordsResponse, RingIndexerError> {
        self.record_reads.fetch_add(1, Ordering::Relaxed);
        let root = self.records.root();
        assert_eq!(request.expected_root, root.root);
        // A network page never answers in the same poll.
        tokio::task::yield_now().await;
        let records = self.records.page(request.start_index, request.limit);
        let end = request.start_index + records.len() as u64;
        Ok(GetStorageMemberRecordsResponse {
            context: spr_indexer_api::Context {
                block_time: 0,
                slot: 99,
            },
            next_leaf_index: (end < root.next_index).then_some(end),
            root,
            records,
        })
    }

    fn upgrade_authority(
        &self,
        program: Address,
    ) -> impl Future<Output = Result<Option<Address>, ClientError>> + Send {
        let authority = self.upgrade_authorities.get(&program).copied();
        async move { Ok(authority) }
    }

    fn health(&self) -> impl Future<Output = Result<(), ClientError>> + Send {
        let healthy = self.healthy;
        async move {
            healthy
                .then_some(())
                .ok_or_else(|| ClientError::Rpc("unavailable".to_owned()))
        }
    }

    async fn genesis_hash(&self) -> Result<[u8; 32], ClientError> {
        Ok(GENESIS)
    }

    async fn ring_assets(&self) -> Result<RingAssets, ClientError> {
        self.asset_reads.fetch_add(1, Ordering::Relaxed);
        if let Some(delay) = self.asset_delay {
            tokio::time::sleep(delay).await;
        }
        tokio::task::yield_now().await;
        self.assets
            .clone()
            .ok_or_else(|| ClientError::Rpc("asset registry unavailable".to_owned()))
    }
}

/// The transfer whose first nullifier, keys and salt derive from `seed`.
fn ring_transfer(seed: u8) -> Transfer {
    let first_nullifier = field(seed);
    Transfer {
        tx_key: ViewingKey::from_bytes(&[seed; 32]),
        ring: RING,
        first_nullifier,
        salt: [seed; 16],
        tree_id: TREE_ID,
        nullifiers: vec![first_nullifier],
    }
}

fn utxo(owner: u8, asset_address: Address, amount: u64) -> UtxoFields {
    UtxoFields {
        owner_key: [owner; 32],
        nullifier_pk: field(owner ^ 0x80),
        asset_address,
        amount,
        ..UtxoFields::default()
    }
}

fn sol(owner: u8, amount: u64) -> UtxoFields {
    utxo(owner, SOL_MINT, amount)
}

/// A confidential ring output, its recipient published as the owner tag.
fn paid(utxo: UtxoFields, recipient_u: [u8; 32]) -> Output {
    Output::Ring {
        utxo,
        recipient_u,
        tag: None,
    }
}

#[derive(Clone, Copy)]
struct Spend {
    utxo: UtxoFields,
    blinding: [u8; 32],
}

struct Indexed<'a> {
    transfer: &'a Transfer,
    outputs: &'a [Output],
    auditor: &'a X25519Pubkey,
    signature: u8,
    frames: &'a Frames,
}

impl Indexed<'_> {
    fn delivered(self) -> ShieldedTransaction {
        self.delivered_with(false)
    }

    /// Dummies fill the outputs to the narrowest delivered capacity.
    fn delivered_with(self, key_escrow: bool) -> ShieldedTransaction {
        let capacity = DELIVERED_AUDIT_CAPACITIES
            .into_iter()
            .find(|capacity| *capacity >= self.outputs.len())
            .expect("a delivered capacity holds the outputs");
        let mut outputs = self.outputs.to_vec();
        outputs.resize(capacity, Output::Dummy);
        let disclosure = self
            .transfer
            .disclosure(Rail::Delivered, &outputs, key_escrow);
        self.publish(Rail::Delivered, &outputs, &disclosure)
    }

    /// The entry key's disclosure, the first spent UTXO's owner the sender.
    fn anonymous(self, spent: &[Option<Spend>]) -> ShieldedTransaction {
        let sender = spent.iter().flatten().next().expect("a spent UTXO").utxo;
        let inputs = AnonymousInputs::Openings {
            sender_key: sender.owner_key,
            sender_nullifier_pk: sender.nullifier_pk,
            inputs: spent
                .iter()
                .map(|spend| spend.map(|spend| input_opening(&spend.utxo, spend.blinding)))
                .collect(),
        };
        self.anonymous_with(inputs)
    }

    /// The commitment key's disclosure, spent UTXO 0 named by its hash and every later one by its prefix.
    fn anonymous_commitments(self, spent: &[Option<[u8; 32]>]) -> ShieldedTransaction {
        self.anonymous_with(AnonymousInputs::commitments(spent).expect("spent UTXO 0"))
    }

    fn anonymous_with(self, inputs: AnonymousInputs) -> ShieldedTransaction {
        let disclosure = self.transfer.anonymous_disclosure(self.outputs, inputs);
        self.publish(Rail::Anonymous, self.outputs, &disclosure)
    }

    fn publish(
        &self,
        rail: Rail,
        outputs: &[Output],
        disclosure: &AuditDisclosure,
    ) -> ShieldedTransaction {
        let mut transaction = self.transfer.publish(Publish {
            slots: self
                .transfer
                .slots(rail, outputs)
                .into_iter()
                .map(|slot| slot.output)
                .collect(),
            disclosure,
            auditor: self.auditor,
        });
        transaction.slot = 42;
        transaction.tx_signature = Signature::from([self.signature; 64]);
        let frame = self.transfer.frame(Frame {
            tx: &transaction,
            layout: disclosure.layout(),
        });
        self.frames
            .lock()
            .unwrap()
            .insert(transaction.tx_signature, frame);
        transaction
    }
}

struct Fixture {
    auditor: X25519Keypair,
    recipient_u: [u8; 32],
    audited: ShieldedTransaction,
    foreign_key: ShieldedTransaction,
    missing_message: ShieldedTransaction,
    frames: Frames,
}

impl Fixture {
    fn new() -> Self {
        let auditor = X25519Keypair::from_bytes(&FIXTURE_AUDITOR);
        let auditor_pk = auditor.pubkey();
        let recipient_u = x25519_u(0x40);
        let frames = Frames::default();
        let audited = Indexed {
            transfer: &ring_transfer(1),
            outputs: &[
                paid(sol(0xb0, 500), recipient_u),
                paid(sol(0xb1, 7), recipient_u),
            ],
            auditor: &auditor_pk,
            signature: 1,
            frames: &frames,
        }
        .delivered();
        let mut foreign_key = Indexed {
            transfer: &ring_transfer(2),
            outputs: &[paid(sol(0xb2, 9), recipient_u)],
            auditor: &X25519Keypair::new().pubkey(),
            signature: 2,
            frames: &frames,
        }
        .delivered();
        foreign_key.messages[0].view_tag = auditor_view_tag(&auditor_pk);
        let mut missing_message = Indexed {
            transfer: &ring_transfer(3),
            outputs: &[paid(sol(0xb3, 11), recipient_u)],
            auditor: &auditor_pk,
            signature: 3,
            frames: &frames,
        }
        .delivered();
        missing_message.messages.clear();
        Self {
            auditor,
            recipient_u,
            audited,
            foreign_key,
            missing_message,
            frames,
        }
    }

    fn source(&self) -> StaticSource {
        let source = StaticSource {
            transactions: Vec::new(),
            origins: HashMap::new(),
            frames: self.frames.clone(),
            confirmed_events: HashMap::new(),
            deposits: HashMap::new(),
            next_cursor: Some(vec![7, 7]),
            scanned_through: None,
            configs: HashMap::from([(
                RING,
                RingConfiguration {
                    auditor_pubkey: self.auditor.pubkey(),
                    authority: authority().pubkey(),
                    mode: RingMode::Confidential,
                },
            )]),
            chain: HashMap::new(),
            by_tag: HashMap::new(),
            records: Records::listing(&[
                reader_member(ReaderKey::ed25519(delegate().pubkey()).expect("delegate reader")),
                reader_member(ReaderKey::p256(Passkey::new(46).pubkey()).expect("passkey reader")),
            ]),
            upgrade_authorities: HashMap::from([(RING, deployer().pubkey())]),
            healthy: true,
            assets: Some(RingAssets::new([]).expect("ring assets")),
            asset_reads: Arc::new(AtomicUsize::new(0)),
            asset_delay: None,
            history: Vec::new(),
            examined_limit: Arc::new(AtomicUsize::new(0)),
            pages: HashMap::new(),
            record_reads: Arc::new(AtomicUsize::new(0)),
            history_reads: Arc::new(AtomicUsize::new(0)),
        };
        source.with_transactions(vec![
            self.audited.clone(),
            self.foreign_key.clone(),
            self.missing_message.clone(),
        ])
    }

    fn hub(&self, source: StaticSource) -> Hub<StaticSource> {
        Hub::builder(source, GENESIS)
            .with_origins(origins())
            .local(RING, self.auditor.clone())
            .expect("hub")
    }

    fn hub_at(&self, source: StaticSource, now: u64) -> Hub<StaticSource> {
        Hub::builder(source, GENESIS)
            .with_origins(origins())
            .with_clock(Clock::Fixed(now))
            .local(RING, self.auditor.clone())
            .expect("hub")
    }

    async fn read_anonymous(
        &self,
        transactions: Vec<ShieldedTransaction>,
    ) -> GetDecryptedTransactionsResponse {
        let mut source = self.source().with_transactions(transactions);
        source.configs.get_mut(&RING).expect("config").mode = RingMode::Anonymous;
        self.hub(source)
            .service(None)
            .expect("service")
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &auth(&delegate()),
                page: &page(),
                wallet: None,
            })
            .await
            .expect("read")
    }
}

fn amounts(item: &DecryptedTransaction) -> Vec<u64> {
    item.outputs
        .iter()
        .filter(|output| output.kind != DecryptedOutputKind::Dummy)
        .map(|output| output.utxo.as_ref().expect("utxo").amount)
        .collect()
}

fn page() -> Page {
    Page::new(None, None).expect("page")
}

/// A member paid on an anonymous ring, then two transfers that spend the member's UTXO.
struct SpentUtxo {
    paid: ShieldedTransaction,
    /// The commitment key's spend, the input named by its UTXO hash.
    spent: ShieldedTransaction,
    /// The entry key's spend, the input opened in full.
    entry: ShieldedTransaction,
    /// The paid output as the spending input names it.
    commitment: [u8; 32],
    member: UtxoFields,
}

impl SpentUtxo {
    fn new(fixture: &Fixture) -> Self {
        let auditor = &fixture.auditor.pubkey();
        let member = sol(0xa4, 70);
        let paying = ring_transfer(80);
        let payment = [
            Output::Ring {
                utxo: member,
                recipient_u: x25519_u(0x54),
                tag: Some(field(0x55)),
            },
            Output::Dummy,
        ];
        let paid = Indexed {
            transfer: &paying,
            outputs: &payment,
            auditor,
            signature: 80,
            frames: &fixture.frames,
        }
        .anonymous(&[Some(Spend {
            utxo: sol(0xa5, 70),
            blinding: field(0x65),
        })]);
        let received = paying.slot(Rail::Anonymous, 0, &payment[0]);
        let commitment = received.output.output_context.hash;
        let exit = [Output::Exit(sol(0xe8, 70)), Output::Dummy];
        let spent = Indexed {
            transfer: &ring_transfer(81),
            outputs: &exit,
            auditor,
            signature: 81,
            frames: &fixture.frames,
        }
        .anonymous_commitments(&[Some(commitment)]);
        let entry = Indexed {
            transfer: &ring_transfer(82),
            outputs: &exit,
            auditor,
            signature: 82,
            frames: &fixture.frames,
        }
        .anonymous(&[Some(Spend {
            utxo: member,
            blinding: received.blinding,
        })]);
        Self {
            paid,
            spent,
            entry,
            commitment,
            member,
        }
    }

    /// The anonymous ring serving `pages` by cursor.
    fn source(&self, fixture: &Fixture, pages: [(Option<Vec<u8>>, Paged); 2]) -> StaticSource {
        let mut source = fixture.source().with_transactions(vec![
            self.paid.clone(),
            self.spent.clone(),
            self.entry.clone(),
        ]);
        source.configs.get_mut(&RING).expect("config").mode = RingMode::Anonymous;
        source.pages = HashMap::from(pages);
        source
    }
}

fn paged(transactions: Vec<ShieldedTransaction>, next: Option<u8>, frontier: Option<u8>) -> Paged {
    Paged {
        transactions,
        next_cursor: next.map(|byte| vec![byte]),
        scanned_through: frontier.map(|byte| vec![byte]),
    }
}

fn input_ring(response: &GetDecryptedTransactionsResponse) -> Option<DecryptedInputRing> {
    response
        .value
        .items
        .last()
        .expect("spending transfer")
        .inputs[0]
        .opening
        .as_ref()
        .expect("opening")
        .ring
        .clone()
}

/// A read of the page `cursor` names, the attestation covers the cursor.
async fn read_at(
    service: &AuditService<StaticSource>,
    cursor: Option<u8>,
) -> GetDecryptedTransactionsResponse {
    let page = Page::new(cursor.map(|byte| vec![byte].into()), None).expect("page");
    let request = match cursor {
        Some(byte) => GetDecryptedTransactionsRequest::read(target(RING))
            .with_cursor(vec![byte].into())
            .expect("cursor"),
        None => GetDecryptedTransactionsRequest::read(target(RING)),
    }
    .sign(&delegate())
    .expect("request");
    service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request.auth,
            page: &page,
            wallet: None,
        })
        .await
        .expect("read")
}

fn utxos_request(hashes: Vec<Hash>) -> GetAuditedUtxosRequest {
    GetAuditedUtxosRequest::read(target(RING), hashes)
        .expect("UTXO read")
        .sign(&delegate())
        .expect("signed UTXO read")
}

/// The audited deposit of `member` into the ring at `blinding`, its capsule sealed to `auditor`.
fn audited_deposit(
    auditor: &X25519Pubkey,
    member: &UtxoFields,
    blinding: [u8; 32],
) -> (ShieldedTransaction, Vec<ConfirmedDeposit>) {
    let opening = DepositOpening {
        owner_hash: member.owner_hash(),
        blinding: zeroize::Zeroizing::new(blinding),
        owner_key: Some(member.owner_key),
    };
    let owner_utxo_hash =
        spr_transaction::owner_utxo_hash(&opening.owner_hash, &opening.blinding).unwrap();
    let sealed = seal_deposits(&[opening], auditor).unwrap();
    let capsule = custom_ring_interface::RingDepositAuditCapsule {
        slot_index: 0,
        eph_pk: sealed.ephemeral_pk.as_bytes(),
        ciphertext: &sealed.ciphertexts[0],
        recipient_ciphertext: &[],
    }
    .encode();
    let group = deposit_fixture::group(RING, true, vec![(owner_utxo_hash, capsule.clone())]);
    let commitment = member.commitment(Placement {
        blinding,
        ring: Some(RING),
        tree_id: TREE_ID,
    });
    let deposit = ShieldedTransaction {
        slot: 40,
        tx_signature: Signature::from([79; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![spr_transaction::OutputSlot {
            view_tag: field(0x56),
            output_context: spr_transaction::OutputContext {
                hash: commitment,
                tree_id: TREE_ID,
                leaf_index: 3,
            },
            payload: spr_event::encode_encrypted_ring_deposit_output(
                spr_event::EncryptedRingDepositOutput {
                    owner_utxo_hash,
                    asset: member.asset_address.to_bytes(),
                    amount: member.amount,
                    data_hash: None,
                    ring_program_id: RING.to_bytes(),
                    ring_data_hash: [0; 32],
                    encrypted: spr_event::EncryptedRingDepositData {
                        tx_viewing_pk: [0; 33],
                        salt: [0; 16],
                        ciphertext: capsule,
                    },
                },
            ),
        }],
        messages: Vec::new(),
        nullifiers: Vec::new(),
        proofless: true,
        ring_config: None,
        ring_program_id: Some(RING),
    };
    let bindings = ring_event_origin_in(&[group], 0, RING).unwrap().deposits;
    (deposit, bindings)
}

fn reader_member(reader: ReaderKey) -> Member {
    reader.member().expect("reader member")
}

/// The ring's own storage tree, shared by every clone of the source.
#[derive(Clone)]
struct Records(Arc<Mutex<OwnRecords>>);

struct OwnRecords {
    tree: MemberRegistryTree,
    /// The envelope each escrow write published, by member.
    sealed: HashMap<[u8; 32], EscrowWriteData>,
    revision: u64,
    /// Pages leave out the first record.
    short_pages: bool,
}

impl Records {
    fn listing(readers: &[Member]) -> Self {
        let records = Self(Arc::new(Mutex::new(OwnRecords {
            tree: MemberRegistryTree::new().expect("record tree"),
            sealed: HashMap::new(),
            revision: 0,
            short_pages: false,
        })));
        for reader in readers {
            records.list_reader(*reader, true);
        }
        records
    }

    /// The source mirrors the new root at once, as after `SyncRoots`.
    fn list_reader(&self, member: Member, listed: bool) {
        let bit = ListId::Reader.record_bit();
        self.apply(QueueEntry {
            member: *member.as_bytes(),
            mask: bit,
            value: if listed { bit } else { 0 },
            escrow_key: [0; 32],
            mint_policy: None,
        });
    }

    fn write_mint_policy(&self, member: Member, policy: MintPolicy) {
        self.apply(QueueEntry {
            member: *member.as_bytes(),
            mint_policy: Some(policy),
            ..QueueEntry::default()
        });
    }

    /// The writes and envelopes an indexer projects from an update.
    fn escrow(&self, writes: &[EscrowWriteData]) {
        for write in writes {
            self.apply(
                StorageWriteData::Escrow(*write)
                    .entry()
                    .expect("escrow write"),
            );
            let member = write.member().expect("owner tag");
            self.0.lock().unwrap().sealed.insert(member, *write);
        }
    }

    fn shorten_pages(&self) {
        self.0.lock().unwrap().short_pages = true;
    }

    fn apply(&self, entry: QueueEntry) {
        let mut own = self.0.lock().unwrap();
        own.tree.apply([0; 32], &[entry]).expect("record write");
        own.revision += 1;
    }

    fn root(&self) -> StorageRootView {
        let own = self.0.lock().unwrap();
        StorageRootView {
            root: Hash(own.tree.root().expect("root")),
            revision: own.revision,
            next_index: own.tree.records().len() as u64,
        }
    }

    fn opening(&self, member: &[u8; 32]) -> RingMemberOpening {
        let own = self.0.lock().unwrap();
        let (present, record, path) = match own.tree.opening(member).expect("opening") {
            RecordOpening::Present { record, path } => (true, record, path),
            RecordOpening::Absent { low, path } => (false, low, path),
        };
        RingMemberOpening {
            present,
            record: own.view(&record),
            path: path_view(path.index, &path.siblings),
        }
    }

    /// Leaves from `start` under the current root.
    fn page(&self, start: u64, limit: u64) -> Vec<RingIndexedMemberRecordView> {
        let own = self.0.lock().unwrap();
        let skip = usize::try_from(start + u64::from(own.short_pages)).expect("leaf");
        own.tree
            .records()
            .iter()
            .zip(0u64..)
            .skip(skip)
            .take(usize::try_from(limit).expect("limit"))
            .map(|(record, index)| {
                let path = own.tree.path(index).expect("path");
                RingIndexedMemberRecordView {
                    record: own.view(record),
                    path: path_view(index, &path.siblings),
                }
            })
            .collect()
    }
}

impl OwnRecords {
    fn view(&self, record: &MemberRecord) -> RingMemberRecordView {
        let sealed = self.sealed.get(&record.member);
        RingMemberRecordView {
            mint_policy: record.mint_policy,
            member: Hash(record.member),
            next: Hash(record.next),
            lists: record.lists,
            escrow_key: Hash(record.escrow_key),
            owner_pubkey: sealed.map(|write| write.owner.into()),
            nullifier_pk: sealed.map(|write| Hash(write.nullifier_pk)),
            eph_pk: sealed.map(|write| Base64String(tagged_x25519(&write.eph_u).to_vec())),
            ciphertext: sealed.map(|write| Base64String(write.ciphertext.to_vec())),
        }
    }
}

fn path_view(index: u64, siblings: &[[[u8; 32]; 3]]) -> RingRecordPathView {
    RingRecordPathView {
        index,
        siblings: siblings.iter().map(|level| level.map(Hash)).collect(),
    }
}

/// Each owner's escrow write, its envelope sealed to no one.
fn escrow_writes(owners: &[UtxoFields]) -> Vec<EscrowWriteData> {
    let eph_u = X25519Keypair::new().pubkey().u();
    owners
        .iter()
        .map(|utxo| EscrowWriteData {
            owner: Address::new_from_array(utxo.owner_key),
            nullifier_pk: utxo.nullifier_pk,
            eph_u,
            ciphertext: [0x5a; 32],
        })
        .collect()
}

/// A delivered transfer of a Registry-mode ring, its owners' nullifier keys left to the registry.
fn escrowed_source(
    fixture: &Fixture,
    owners: &[UtxoFields],
    registered: &[UtxoFields],
) -> StaticSource {
    let audited = Indexed {
        transfer: &ring_transfer(90),
        outputs: &owners
            .iter()
            .map(|utxo| paid(*utxo, fixture.recipient_u))
            .collect::<Vec<_>>(),
        auditor: &fixture.auditor.pubkey(),
        signature: 90,
        frames: &fixture.frames,
    }
    .delivered_with(true);
    let mut source = fixture.source().with_transactions(vec![audited.clone()]);
    source.configs.get_mut(&RING).expect("config").mode = RingMode::ConfidentialEscrow;
    source.pages = HashMap::from([
        (None, paged(vec![audited], None, Some(1))),
        (Some(vec![1]), paged(Vec::new(), None, Some(1))),
    ]);
    source.records.escrow(&escrow_writes(registered));
    source
}

fn escrow_errors(page: &GetDecryptedTransactionsResponse) -> Vec<OutputPayloadErrorKind> {
    let [item] = page.value.items.as_slice() else {
        panic!("one escrowed transfer, {:?}", page.value.skipped);
    };
    item.payload_errors.iter().map(|error| error.kind).collect()
}

/// The commitment of `owner`'s output on the ring's audited page.
async fn fixture_output_hash(service: &AuditService<StaticSource>, owner: &UtxoFields) -> Hash {
    let page = read_at(service, None).await;
    page.value.items[0]
        .outputs
        .iter()
        .find(|output| {
            output
                .utxo
                .as_ref()
                .is_some_and(|utxo| utxo.owner_key.0.to_bytes() == owner.owner_key)
        })
        .expect("owner output")
        .output_context
        .hash
        .clone()
}

#[test]
fn request_builder_rejects_noncanonical_pages() {
    assert!(matches!(
        GetDecryptedTransactionsRequest::read(target(RING)).with_cursor(Vec::new().into()),
        Err(ReadBuildError::Cursor)
    ));
    assert!(matches!(
        GetDecryptedTransactionsRequest::read(target(RING))
            .with_limit(Limit::new(101).expect("indexer limit")),
        Err(ReadBuildError::Limit)
    ));
    assert!(matches!(
        Page::new(Some(Vec::new().into()), None),
        Err(RingRpcError::InvalidPage)
    ));
}

fn as_object<T: serde::Serialize>(value: T) -> serde_json::Map<String, serde_json::Value> {
    let serde_json::Value::Object(map) = serde_json::to_value(value).expect("JSON object") else {
        panic!("expected JSON object");
    };
    map
}

fn signed_by(authority: &Keypair) -> CreateAuditorKeyRequest {
    CreateAuditorKeyRequest::for_ring(RING, GENESIS)
        .sign(authority)
        .expect("signed request")
}

async fn authorize(
    hub: &Hub<StaticSource>,
    request: &CreateAuditorKeyRequest,
) -> Result<(), RingRpcError> {
    hub.service(Some(RING))
        .expect("service")
        .auditor_key_statement(&request.auth)
        .await
        .map(drop)
}

/// The service signs the cluster and nonce the authority's request names.
fn released(created: &CreateAuditorKeyResponse, request: &CreateAuditorKeyRequest) -> bool {
    let nonce: [u8; 32] = request.auth.nonce.0.as_slice().try_into().expect("nonce");
    let statement = AuditorKeyStatement {
        cluster: &request.auth.genesis_hash.0,
        ring: &request.ring_program_id.0,
        auditor_pubkey: created.auditor_pubkey.as_key(),
        nonce: &nonce,
    };
    created
        .signature
        .0
        .verify(created.service_pubkey.0.as_ref(), &statement.message())
}

fn refused(result: Result<(), RingRpcError>, expected: Unauthorized) -> bool {
    matches!(result, Err(RingRpcError::Unauthorized(reason)) if reason == expected)
}

fn deposit(byte: u8, slot: u64, amount: u64) -> DepositRecord {
    DepositRecord {
        signature: Signature::from([byte; 64]).into(),
        slot,
        depositor: [byte; 32].into(),
        asset: SOL_MINT.to_bytes().into(),
        amount,
    }
}

fn examined(byte: u8, slot: u64, deposits: Vec<DepositRecord>) -> Examined {
    Examined {
        signature: Signature::from([byte; 64]),
        slot,
        deposits,
    }
}

fn deposits_request(limit: Option<u32>, cursor: Option<Base64String>) -> RingDepositsRequest {
    RingDepositsRequest {
        ring_program_id: RING.to_bytes().into(),
        limit,
        cursor,
    }
}
