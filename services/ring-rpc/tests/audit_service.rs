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
#[path = "audit_service/coverage_failures.rs"]
mod coverage_failures;
#[path = "audit_service/frame_repairs.rs"]
mod frame_repairs;
#[path = "audit_service/reader_grants.rs"]
mod reader_grants;
#[path = "audit_service/record_updates.rs"]
mod record_updates;
#[path = "common/relay.rs"]
mod relay_fixture;
#[path = "../../../sdk-libs/client/tests/common/transfer.rs"]
pub mod transfer;

use custom_ring_interface::CoSignScope;
use custom_ring_interface::{RecordWrite, RingMode, RING_TRANSACT_ACCOUNT_PREFIX_LEN};
use spr_keypair::NullifierKey;
use spr_keypair::{X25519Keypair, X25519Pubkey};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    num::NonZeroU32,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use zolana_ring_client::rpc::WalletEnrollment;
use zolana_ring_indexer::tracking::{GetTrackingRecordsRequest, GetTrackingRecordsResponse};
use zolana_ring_member_registry::{MemberRecord, MemberRegistryTree, RecordOpening, RecordTree};
use zolana_ring_policy::{ListId, Member, MintPolicy};
use zolana_ring_rpc::tracking_fixture::{Enrollment, TrackingLedger};

use p256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::Digest;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{
    rpc::{PaginationToken, TransactionEvents},
    ClientError, Context, GetShieldedTransactionsByTagsResponse,
};
use spr_indexer_api::{Base64String, Hash, Limit};
use spr_keypair::ViewingKey;
use spr_transaction::{ShieldedTransaction, SOL_MINT};
use zolana_ring_client::{
    auditor_view_tag,
    history::{HistoryCursor, HistoryPosition, HistoryQuery, HistoryStream},
    rpc::{
        unix_now, AuditorKeyStatement, CreateAuditorKeyRequest, CreateAuditorKeyResponse,
        DecryptedTransaction, DecryptedWithdrawal, GetAuditedMergesResponse,
        GetAuditedUtxosRequest, GetAuditedUtxosResponse, GetDecryptedTransactionsRequest,
        GetDecryptedTransactionsResponse, GetWalletActivityResponse, HealthResponse, KeyMode,
        PagedRead, ReadAttestation, ReadAuth, ReadBuildError, ReadSignature, ReadSigner,
        ReadTarget, ReaderGrantAction, ReaderGrantAttestation, ReaderGrantRequest, RingChainStatus,
        SkippedReason, WalletActivity, WalletStatusRequest, WalletView, WebAuthnAssertion,
        AUDITED_UTXOS_LIMIT, CREATE_AUDITOR_KEY, GET_AUDITED_MERGES, GET_AUDITED_UTXOS,
        GET_DECRYPTED_TRANSACTIONS, HEALTH, SET_READER_GRANT,
    },
    AuditError, MergeAuditPage, ReaderKey, RingOrigin, RingWithdrawal,
};
use zolana_ring_client::{P256ReaderKey, RingIndexerError, StorageTip};
use zolana_ring_indexer::rpc::{
    GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse,
    GetStorageMemberRecordsRequest, GetStorageMemberRecordsResponse, RingIndexedMemberRecordView,
    RingMemberOpening, RingMemberRecordView, RingRecordPathView, StorageRootView,
};
use zolana_ring_rpc::{
    rpc_module, ApproveClass, AuditRead, AuditService, Clock, CoSignerApproval, GrantRowsSecret,
    Hub, MergeAuditRequest, OriginPolicy, Origins, Page, ReadCheck, ReaderGrantStore, RecordsTip,
    RingConfiguration, RingFrame, RingHistoryPage, RingRpcError, RootSecret, ServiceIdentity,
    Store, TransactionPage, TransactionSource, Unauthorized, AUTH_SKEW,
};
use zolana_ring_transaction::RingAssets;

use transfer::{field, x25519_u, Disclosure, Frame, Output, Publish, Rail, Transfer, UtxoFields};

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
/// A zero lead byte as `RegisterKey` proves.
const LIST_SALT: [u8; 32] = {
    let mut salt = [0x12; 32];
    salt[0] = 0;
    salt
};
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

fn service_key() -> Keypair {
    Keypair::new_from_array([46; 32])
}

fn storage_authority() -> Keypair {
    Keypair::new_from_array([48; 32])
}

fn co_signer_key() -> Keypair {
    Keypair::new_from_array([49; 32])
}

fn grant_rows_key() -> GrantRowsSecret {
    GrantRowsSecret::from_bytes([50; 32])
}

fn identity(genesis_hash: [u8; 32]) -> ServiceIdentity {
    ServiceIdentity {
        genesis_hash,
        service: service_key(),
    }
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

fn refusal<T: std::fmt::Debug>(result: Result<T, jsonrpsee::MethodsError>) -> i32 {
    match result {
        Err(jsonrpsee::MethodsError::JsonRpc(error)) => error.code(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn origins() -> Origins {
    OriginPolicy::new(vec![ORIGIN.to_owned()])
        .with_relying_party_id("localhost".to_owned())
        .build()
        .expect("origins")
}

fn target(ring: Address) -> ReadTarget {
    ReadTarget {
        cluster: GENESIS,
        service: service_key().pubkey(),
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
    owner_signers: HashMap<Signature, Vec<Address>>,
    /// Confirmed deposits and merges do not carry transfer auditor messages.
    confirmed_events: HashMap<(Signature, u16), zolana_ring_client::ConfirmedEvent>,
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
    /// Off while the ring's records address holds no storage registry.
    records_registered: bool,
    /// Per program, absent when immutable or not deployed.
    upgrade_authorities: HashMap<Address, Address>,
    healthy: bool,
    /// Rewritten while a hub serves it, a mint registers after the first read.
    assets: Arc<Mutex<Option<RingAssets>>>,
    asset_reads: Arc<AtomicUsize>,
    asset_delay: Option<Duration>,
    /// Per request cursor, empty when every read shares one page.
    pages: HashMap<Option<Vec<u8>>, Paged>,
    record_reads: Arc<AtomicUsize>,
    history_reads: Arc<AtomicUsize>,
    /// Rows whose confirmed call does not decode, shared so a test can repair one.
    undecodable: Arc<Mutex<HashSet<Signature>>>,
    /// Rows whose confirmed call stack names a parent no instruction holds.
    stack_faults: HashSet<Signature>,
    history_cursors: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
    /// The signature of every frame read again.
    frame_reads: Arc<Mutex<Vec<Signature>>>,
    /// The page each served token continues to.
    issued: Arc<Mutex<HashMap<PaginationToken, Vec<u8>>>>,
    /// The page a pass past the last terminal page reads.
    resume: Arc<Mutex<Option<Vec<u8>>>>,
    forged_token: Option<PaginationToken>,
    /// A snapshot behind the floor, the shape of a rollback.
    forced_context: Arc<Mutex<Option<u64>>>,
    history_down: Arc<AtomicBool>,
    config_down: Arc<AtomicBool>,
    registry: Arc<Mutex<Address>>,
    records_down: Arc<AtomicBool>,
    tracking: Tracking,
    co_signers: HashMap<Address, CoSignScope>,
}

/// The indexer page one cursor reads.
#[derive(Clone)]
struct Paged {
    transactions: Vec<ShieldedTransaction>,
    next_cursor: Option<Vec<u8>>,
    scanned_through: Option<Vec<u8>>,
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
    /// SPP's ring transact accounts, SENDER paying and no settlement group.
    fn pool_accounts(&self, signature: Signature) -> Vec<Address> {
        let nullifiers = self
            .transactions
            .iter()
            .chain(self.by_tag.values().flatten())
            .find(|tx| tx.tx_signature == signature)
            .map_or(0, |tx| tx.nullifiers.len());
        let mut accounts = vec![SENDER];
        accounts.resize(
            RING_TRANSACT_ACCOUNT_PREFIX_LEN + 1 + nullifiers,
            Address::default(),
        );
        accounts.extend(self.owner_signers.get(&signature).into_iter().flatten());
        accounts
    }

    /// The `pages` key a read at `position` names, a token at slot 0 is a test cursor.
    fn marker(&self, position: HistoryPosition) -> Option<Vec<u8>> {
        match position.token() {
            Some(token) if token.slot() == 0 => Some(vec![token.signature().as_ref()[0]]),
            Some(token) => self.issued.lock().unwrap().get(&token).cloned(),
            None if position.filters().is_empty() => None,
            // A floor under the terminal slot retries a frame, the history reads from its start.
            None if position.filters().slot.gt.is_some_and(|floor| floor < 99) => None,
            None => self.resume.lock().unwrap().clone(),
        }
    }

    /// The page `position` names, else every transaction under `tagged`, rows take increasing slots past the floor.
    fn page_at(
        &self,
        position: HistoryPosition,
        limit: NonZeroU32,
        tagged: Option<&Vec<ShieldedTransaction>>,
    ) -> GetShieldedTransactionsByTagsResponse {
        assert!(limit.get() <= 100);
        let marker = self.marker(position);
        let past_terminal = position.token().is_none() && !position.filters().is_empty();
        let paged = self.pages.get(&marker).cloned().unwrap_or_else(|| {
            if past_terminal {
                return Paged {
                    transactions: Vec::new(),
                    next_cursor: None,
                    scanned_through: marker.clone(),
                };
            }
            Paged {
                transactions: tagged.cloned().unwrap_or_else(|| self.transactions.clone()),
                next_cursor: self.next_cursor.clone(),
                scanned_through: self.scanned_through.clone(),
            }
        });
        let floor = position
            .filters()
            .slot
            .gt
            .max(position.token().map(|token| token.slot()))
            .unwrap_or_default();
        // A retry keeps the slots the first read gave, a real history never moves a row.
        let first_slot = match marker.is_none() && position.token().is_none() {
            true => 1,
            false => floor + 1,
        };
        let data: Vec<_> = (first_slot..)
            .zip(paged.transactions)
            .filter(|(slot, _)| *slot > floor)
            .map(|(slot, mut row)| {
                row.slot = slot;
                TransactionEvents {
                    slot,
                    signature: row.tx_signature,
                    events: vec![row],
                }
            })
            .collect();
        let next = paged
            .next_cursor
            .filter(|_| paged.scanned_through.is_none());
        let last = data
            .last()
            .map(|item| PaginationToken::new(item.slot, item.signature));
        // A page that names itself as next never advances.
        let pagination_token = self.forged_token.or_else(|| match &next {
            Some(next) if marker.as_ref() == Some(next) => position.token(),
            Some(_) => last,
            None => None,
        });
        match (pagination_token, next) {
            (Some(token), Some(next)) => {
                self.issued.lock().unwrap().insert(token, next);
            }
            (None, _) => *self.resume.lock().unwrap() = paged.scanned_through,
            (Some(_), None) => {}
        }
        let newest = data.last().map_or(floor, |item| item.slot);
        GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: self
                    .forced_context
                    .lock()
                    .unwrap()
                    .unwrap_or(newest.max(99)),
            },
            data,
            pagination_token,
            output_tree_id: Some(TREE_ID),
        }
    }
}

impl TransactionSource for StaticSource {
    async fn co_signer_scope(
        &self,
        _ring: Address,
        signer: Address,
    ) -> Result<Option<CoSignScope>, RingRpcError> {
        Ok(self.co_signers.get(&signer).copied())
    }

    async fn tracking_root(
        &self,
        _ring: Address,
        _finality: zolana_ring_rpc::Finality,
    ) -> Result<Option<zolana_ring_rpc::TrackingRoot>, ClientError> {
        Ok(self.tracking.0.root())
    }

    async fn tracking_records(
        &self,
        request: GetTrackingRecordsRequest,
    ) -> Result<GetTrackingRecordsResponse, RingIndexerError> {
        Ok(self.tracking.0.page(&request))
    }

    async fn tracking_enrollment(
        &self,
        _ring: Address,
        owner: Address,
    ) -> Result<WalletEnrollment, ClientError> {
        Ok(self.tracking.0.enrollment(&owner))
    }

    async fn merge_audit_page(
        &self,
        _request: MergeAuditRequest<'_>,
    ) -> Result<MergeAuditPage, AuditError> {
        Ok(MergeAuditPage {
            context: spr_indexer_api::Context {
                block_time: 0,
                slot: 99,
            },
            merges: Vec::new(),
            next_cursor: None,
        })
    }

    fn transactions_by_tag(
        &self,
        request: TransactionPage,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send
    {
        let response = self.page_at(
            request.position,
            request.limit,
            self.by_tag.get(&request.tag),
        );
        async move { Ok(response) }
    }

    /// The listed rows of the signature, at the slot the frame names.
    fn ring_frame(
        &self,
        frame: RingFrame,
    ) -> impl Future<Output = Result<Vec<ShieldedTransaction>, ClientError>> + Send {
        self.frame_reads.lock().unwrap().push(frame.signature);
        let events = self
            .transactions
            .iter()
            .filter(|tx| tx.tx_signature == frame.signature)
            .map(|tx| ShieldedTransaction {
                slot: frame.slot,
                ..tx.clone()
            })
            .collect();
        async move { Ok(events) }
    }

    fn ring_history(
        &self,
        request: RingHistoryPage,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send
    {
        let capped = self.history_reads.fetch_add(1, Ordering::Relaxed) >= HISTORY_READ_CAP;
        let down = self.history_down.load(Ordering::Relaxed);
        self.history_cursors
            .lock()
            .unwrap()
            .push(self.marker(request.position));
        let response = self.page_at(request.position, request.limit, None);
        async move {
            match capped || down {
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
        let undecodable = self.undecodable.lock().unwrap().contains(&signature);
        let stack_fault = self.stack_faults.contains(&signature);
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
                merge_disclosure: None,
                transact: self.frames.lock().unwrap().get(&signature).cloned(),
                pool_accounts: self.pool_accounts(signature),
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
        async move {
            match (undecodable, stack_fault) {
                (true, _) => Err(AuditError::InvalidTransactData("forged".to_owned())),
                (_, true) => Err(AuditError::InvalidStackHeight(4)),
                (false, false) => origin,
            }
        }
    }

    fn ring_config(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<Option<RingConfiguration>, ClientError>> + Send {
        let config = self.configs.get(&ring).copied();
        let down = self.config_down.load(Ordering::Relaxed);
        async move {
            if down {
                return Err(ClientError::Rpc("config unavailable".to_owned()));
            }
            Ok(config)
        }
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

    async fn records_root(&self, _ring: Address) -> Result<RecordsTip, ClientError> {
        if !self.records_registered {
            return Ok(RecordsTip::NoRegistry);
        }
        let root = self.records.root();
        Ok(RecordsTip::Newest(StorageTip {
            registry: *self.registry.lock().unwrap(),
            root: root.root.0,
            revision: root.revision,
        }))
    }

    async fn storage_member_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingIndexerError> {
        assert_eq!(request.registry.0, *self.registry.lock().unwrap());
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
        if self.records_down.load(Ordering::Relaxed) {
            return Err(ClientError::Rpc("records down".to_owned()).into());
        }
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

    async fn tree_id(&self, _tree: Address) -> Result<u16, custom_ring_sdk::RingError> {
        Ok(TREE_ID)
    }

    async fn ring_assets(&self) -> Result<RingAssets, ClientError> {
        self.asset_reads.fetch_add(1, Ordering::Relaxed);
        if let Some(delay) = self.asset_delay {
            tokio::time::sleep(delay).await;
        }
        tokio::task::yield_now().await;
        self.assets
            .lock()
            .unwrap()
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

/// A transfer spending `nullifiers`, the first opens its output blinding.
fn spending(seed: u8, nullifiers: &[[u8; 32]]) -> Transfer {
    Transfer {
        first_nullifier: nullifiers[0],
        nullifiers: nullifiers.to_vec(),
        ..ring_transfer(seed)
    }
}

/// A note under `key`, published with the nullifier its spend names.
struct KeyedNote<'a> {
    fixture: &'a Fixture,
    seed: u8,
    note: UtxoFields,
    key: &'a NullifierKey,
}

impl KeyedNote<'_> {
    fn delivered(self) -> (ShieldedTransaction, [u8; 32]) {
        let output = paid(self.keyed(), self.fixture.recipient_u);
        self.publish(output, |indexed| indexed.delivered())
    }

    fn anonymous(self) -> (ShieldedTransaction, [u8; 32]) {
        let output = Output::Ring {
            utxo: self.keyed(),
            recipient_u: self.fixture.recipient_u,
            tag: Some(field(self.seed)),
        };
        self.publish(output, |indexed| indexed.anonymous(&[true]))
    }

    fn keyed(&self) -> UtxoFields {
        UtxoFields {
            nullifier_pk: self.key.pubkey().expect("key"),
            ..self.note
        }
    }

    fn publish(
        &self,
        output: Output,
        rail: fn(Indexed<'_>) -> ShieldedTransaction,
    ) -> (ShieldedTransaction, [u8; 32]) {
        let paying = ring_transfer(self.seed);
        let auditor = self.fixture.auditor.pubkey();
        let row = rail(Indexed {
            transfer: &paying,
            outputs: &[output, Output::Dummy],
            auditor: &auditor,
            signature: self.seed,
            frames: &self.fixture.frames,
        });
        let nullifier = self
            .key
            .nullifier(
                &row.output_slots[0].output_context.hash,
                &paying.blinding(0),
            )
            .expect("nullifier");
        (row, nullifier)
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

struct Indexed<'a> {
    transfer: &'a Transfer,
    outputs: &'a [Output],
    auditor: &'a X25519Pubkey,
    signature: u8,
    frames: &'a Frames,
}

impl Indexed<'_> {
    fn delivered(self) -> ShieldedTransaction {
        let disclosure = self.transfer.disclosure(Rail::Delivered, self.outputs);
        self.publish(Rail::Delivered, self.outputs, &disclosure)
    }

    /// `spent` names the real inputs, the record stream carries their count and no hash.
    fn anonymous(self, spent: &[bool]) -> ShieldedTransaction {
        let mut disclosure = self.transfer.disclosure(Rail::Anonymous, self.outputs);
        disclosure.real_inputs = spent.iter().filter(|real| **real).count() as u8;
        self.publish(Rail::Anonymous, self.outputs, &disclosure)
    }

    fn publish(
        &self,
        rail: Rail,
        outputs: &[Output],
        disclosure: &Disclosure,
    ) -> ShieldedTransaction {
        let mut transaction = self.transfer.publish(Publish {
            slots: self
                .transfer
                .slots(outputs)
                .into_iter()
                .map(|slot| slot.output)
                .collect(),
            disclosure,
            auditor: self.auditor,
            rail,
        });
        transaction.slot = 42;
        transaction.tx_signature = Signature::from([self.signature; 64]);
        let frame = self.transfer.frame(Frame {
            tx: &transaction,
            disclosure,
            rail,
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
            outputs: &[paid(sol(0xb2, 9), recipient_u), Output::Dummy],
            auditor: &X25519Keypair::new().pubkey(),
            signature: 2,
            frames: &frames,
        }
        .delivered();
        foreign_key.messages[0].view_tag = auditor_view_tag(&auditor_pk);
        let mut missing_message = Indexed {
            transfer: &ring_transfer(3),
            outputs: &[paid(sol(0xb3, 11), recipient_u), Output::Dummy],
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
            owner_signers: HashMap::new(),
            confirmed_events: HashMap::new(),
            next_cursor: Some(vec![7, 7]),
            scanned_through: None,
            configs: HashMap::from([(
                RING,
                RingConfiguration {
                    auditor_pubkey: self.auditor.pubkey(),
                    roles: custom_ring_interface::RingRoles {
                        policy: authority().pubkey(),
                        ..bytemuck::Zeroable::zeroed()
                    },
                    mode: RingMode::Confidential,
                    delegate: None,
                },
            )]),
            chain: HashMap::new(),
            by_tag: HashMap::new(),
            records: Records::listing(&[
                reader_member(ReaderKey::ed25519(delegate().pubkey()).expect("delegate reader")),
                reader_member(ReaderKey::p256(Passkey::new(46).pubkey()).expect("passkey reader")),
            ]),
            records_registered: true,
            upgrade_authorities: HashMap::from([(RING, deployer().pubkey())]),
            healthy: true,
            assets: Arc::new(Mutex::new(Some(RingAssets::new([]).expect("ring assets")))),
            asset_reads: Arc::new(AtomicUsize::new(0)),
            asset_delay: None,
            pages: HashMap::new(),
            record_reads: Arc::new(AtomicUsize::new(0)),
            history_reads: Arc::new(AtomicUsize::new(0)),
            undecodable: Arc::default(),
            stack_faults: HashSet::new(),
            history_cursors: Arc::default(),
            frame_reads: Arc::default(),
            issued: Arc::default(),
            resume: Arc::default(),
            forged_token: None,
            forced_context: Arc::default(),
            history_down: Arc::default(),
            config_down: Arc::default(),
            registry: Arc::new(Mutex::new(RECORDS)),
            records_down: Arc::default(),
            tracking: Tracking::default(),
            co_signers: HashMap::new(),
        };
        source.with_transactions(vec![
            self.audited.clone(),
            self.foreign_key.clone(),
            self.missing_message.clone(),
        ])
    }

    fn hub(&self, source: StaticSource) -> Hub<StaticSource> {
        Hub::builder(source, identity(GENESIS))
            .with_origins(origins())
            .local(RING, self.auditor.clone())
            .expect("hub")
    }

    fn hub_at(&self, source: StaticSource, now: u64) -> Hub<StaticSource> {
        Hub::builder(source, identity(GENESIS))
            .with_origins(origins())
            .with_clock(Clock::Fixed(now))
            .local(RING, self.auditor.clone())
            .expect("hub")
    }
}

fn amounts(item: &DecryptedTransaction) -> Vec<u64> {
    item.outputs
        .iter()
        .filter_map(|output| output.utxo.as_ref())
        .map(|utxo| utxo.amount)
        .collect()
}

fn page() -> Page {
    Page::new(None, None).expect("page")
}

/// A member paid on an anonymous ring, then two transfers of one real input, neither frame names a note.
struct SpentUtxo {
    paid: ShieldedTransaction,
    spent: ShieldedTransaction,
    entry: ShieldedTransaction,
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
        .anonymous(&[true]);
        let received = paying.slot(0, &payment[0]);
        let commitment = received.output.output_context.hash;
        let exit = [Output::Exit(sol(0xe8, 70)), Output::Dummy];
        let spent = Indexed {
            transfer: &ring_transfer(81),
            outputs: &exit,
            auditor,
            signature: 81,
            frames: &fixture.frames,
        }
        .anonymous(&[true]);
        let entry = Indexed {
            transfer: &ring_transfer(82),
            outputs: &exit,
            auditor,
            signature: 82,
            frames: &fixture.frames,
        }
        .anonymous(&[true]);
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

/// The tag stream cursor of the `pages` entry `byte` keys.
fn audit_cursor(byte: u8) -> Base64String {
    HistoryCursor {
        query: HistoryQuery {
            ring: RING,
            stream: HistoryStream::Tags,
        },
        token: PaginationToken::new(0, Signature::from([byte; 64])),
    }
    .into()
}

/// A read of the page `cursor` names, the attestation covers the cursor.
async fn read_at(
    service: &AuditService<StaticSource>,
    cursor: Option<u8>,
) -> GetDecryptedTransactionsResponse {
    read_at_result(service, cursor).await.expect("read")
}

async fn read_at_result(
    service: &AuditService<StaticSource>,
    cursor: Option<u8>,
) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
    let page = Page::new(cursor.map(audit_cursor), None).expect("page");
    let request = match cursor {
        Some(byte) => GetDecryptedTransactionsRequest::read(target(RING))
            .with_cursor(audit_cursor(byte))
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
}

fn utxos_request(hashes: Vec<Hash>) -> GetAuditedUtxosRequest {
    GetAuditedUtxosRequest::read(target(RING), hashes)
        .expect("UTXO read")
        .sign(&delegate())
        .expect("signed UTXO read")
}

fn reader_member(reader: ReaderKey) -> Member {
    reader.record_key().expect("reader member")
}

/// The ring's own storage tree, shared by every clone of the source.
#[derive(Clone)]
struct Records(Arc<Mutex<OwnRecords>>);

/// The tracking tree of `RING`, shared by every clone of the source.
#[derive(Clone, Default)]
struct Tracking(TrackingLedger);

impl Tracking {
    /// The owner's key and `LIST_SALT`, sealed to `auditor` and applied.
    fn enroll(&self, owner: &[u8; 32], key: &NullifierKey, auditor: &X25519Pubkey) {
        self.0.enroll(Enrollment {
            owner: Address::new_from_array(*owner),
            key,
            list_salt: LIST_SALT,
            auditor,
        });
    }
}

struct OwnRecords {
    tree: MemberRegistryTree,
    revision: u64,
    /// Pages leave out the first record.
    short_pages: bool,
}

impl Records {
    fn listing(readers: &[Member]) -> Self {
        let records = Self(Arc::new(Mutex::new(OwnRecords {
            tree: MemberRegistryTree::new().expect("record tree"),
            revision: 0,
            short_pages: false,
        })));
        for reader in readers {
            records.list_reader(*reader, true);
        }
        records
    }

    /// The source serves the new root at once, as the registry does once storage applies it.
    fn list_reader(&self, member: Member, listed: bool) {
        let bit = ListId::Reader.record_bit();
        self.apply(RecordWrite {
            member: *member.as_bytes(),
            mask: bit,
            value: if listed { bit } else { 0 },
            mint_policy: None,
        });
    }

    fn write_mint_policy(&self, member: Member, policy: MintPolicy) {
        self.apply(RecordWrite {
            member: *member.as_bytes(),
            mint_policy: Some(policy),
            ..RecordWrite::default()
        });
    }

    fn apply(&self, entry: RecordWrite) {
        let mut own = self.0.lock().unwrap();
        own.tree = own
            .tree
            .clone()
            .apply([0; 32], &[entry])
            .expect("record write")
            .tree;
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
        RingMemberRecordView {
            mint_policy: record.mint_policy,
            member: Hash(record.member),
            next: Hash(record.next),
            lists: record.lists,
        }
    }
}

fn path_view(index: u64, siblings: &[[[u8; 32]; 3]]) -> RingRecordPathView {
    RingRecordPathView {
        index,
        siblings: siblings.iter().map(|level| level.map(Hash)).collect(),
    }
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
