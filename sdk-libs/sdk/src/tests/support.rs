//! The chain and indexer every unit test reads, accounts from one map and the queries recorded.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use bytemuck::{Pod, Zeroable};
use custom_ring_interface::{
    storage::{RegistryId, Revision, StorageRegistry},
    storage_instruction::{InitializeIxData, InitializeTrackingIxData},
    tracking::{TrackingAuthorization, TrackingRegistry},
    CoSignScope, CoSigner, CoSignerCounts, NewRing, PolicyUpdate, RingMode, RingPolicy, RingRoles,
    SourceSlot, CO_SIGNER, N_SOURCE_SLOTS, RING_POLICY_PDA_SEED, STORAGE_PROGRAM_ID,
};
use solana_account::Account;
use solana_address::Address;
use spr_client::{
    rpc::STATE_TREE_HEIGHT, AsyncProverClient, AsyncRpc, AsyncSprClient, AsyncWitnessReader,
    ClientError, Context, GetMerkleProofsResponse, IndexerRpcConfig, InputWitnesses, MerkleContext,
    MerkleProof, ProofDataSource,
};
use spr_hasher::{Hasher, Poseidon};
use spr_indexer_api::{Base64String, Hash, SerializablePubkey};
use spr_interface::{
    state::{
        default_tree_fees,
        discriminator::{RING_CONFIG, TREE_ACCOUNT_DISCRIMINATOR},
        nullifier_tree_params, RingConfig,
    },
    RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID,
};
use spr_keypair::ShieldedAddress;
use spr_keypair::{random_blinding, NullifierKey, ShieldedKeypair, SigningKey, X25519Keypair};
use spr_transaction::{utxo::SppProofInputUtxo, Data, Mint, Utxo, WalletUtxo};
use spr_tree::{TreeAccount, TreeFeeSchedule, UTXO_TREE_HEIGHT};
use zolana_ring_client::{AsyncRingIndexer, RingIndexerError};
use zolana_ring_indexer::{
    rpc::{
        GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse,
        GetStorageRecordPoolRequest, GetStorageRecordPoolResponse, RingIndexedMemberRecordView,
        RingMemberOpening, RingMemberRecordView, RingRecordPathView, StorageRootView,
    },
    tracking::{
        GetTrackingOpeningsRequest, GetTrackingOpeningsResponse, GetTrackingRecordPoolRequest,
        GetTrackingRecordPoolResponse, RingIndexedTrackingRecordView, RingTrackingOpening,
        RingTrackingRecordView,
    },
};
use zolana_ring_member_registry::{
    Canopy, MemberRecord, MemberRegistryTree, RecordOpening, RecordTree, TrackingOpening,
    TrackingRecord, TrackingTree,
};
use zolana_ring_policy::{Member, RuleTable};

use crate::client::RingClient;
use crate::{trees::PoolTree, CustomRing, REDACTED};

pub(crate) const SLOT: u64 = 2_359_301;
/// The ring's own `StorageRegistry`, its newest root at `REVISION`.
pub(crate) const RECORDS: Address = Address::new_from_array([0x5a; 32]);
pub(crate) const REVISION: u64 = 1;
pub(crate) const TRACKING: Address = Address::new_from_array([0x5b; 32]);
/// Every `keypair(seed)` below it holds a tracking row under its own nullifier key.
const ENROLLED_SEEDS: u8 = 64;
pub(crate) const TREE_ID: u16 = 0;

pub(crate) fn program() -> Address {
    Address::new_from_array([42; 32])
}

pub(crate) fn ring() -> CustomRing {
    CustomRing::new(program())
}

pub(crate) fn payer() -> Address {
    Address::new_from_array([7; 32])
}

pub(crate) fn authority() -> Address {
    Address::new_from_array([8; 32])
}

pub(crate) fn auditor() -> X25519Keypair {
    X25519Keypair::from_bytes(&[5; 32])
}

pub(crate) fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

pub(crate) fn owner_identity(owner: &ShieldedKeypair) -> Member {
    let identity = owner
        .shielded_address()
        .unwrap()
        .signing_pubkey
        .owner_proof_input_hash()
        .unwrap();
    Member::from_bytes(identity).unwrap()
}

pub(crate) fn owner_record(owner: &ShieldedKeypair) -> Member {
    Member::public(&owner_identity(owner)).unwrap()
}

pub(crate) fn wallet(utxo: Utxo, key: &NullifierKey, tree_id: u16, leaf_index: u64) -> WalletUtxo {
    let nullifier_pubkey = key.pubkey().unwrap();
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)
        .unwrap();
    WalletUtxo {
        nullifier: key.nullifier(&utxo_hash, &utxo.blinding).unwrap(),
        utxo,
        nullifier_pubkey,
        utxo_hash,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id,
        leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Default::default(),
        slot_index: 0,
    }
}

pub(crate) fn ring_utxo(
    owner: &ShieldedKeypair,
    asset: Mint,
    amount: u64,
    leaf: u64,
) -> WalletUtxo {
    wallet(
        Utxo {
            owner: owner.signing_pubkey(),
            asset,
            amount,
            blinding: random_blinding(),
            ring_program_id: Some(program()),
            data: Data::default(),
        },
        &owner.nullifier_key,
        TREE_ID,
        leaf,
    )
}

pub(crate) fn redacts(printed: &str, fields: &[&str]) -> bool {
    fields
        .iter()
        .all(|field| printed.contains(&format!("{field}: {REDACTED:?}")))
}

pub(crate) fn account<T: Pod>(owner: Address, value: &T) -> Account {
    Account {
        lamports: 1,
        data: bytemuck::bytes_of(value).to_vec(),
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

pub(crate) fn empty(owner: Address) -> Account {
    Account {
        lamports: 1,
        data: Vec::new(),
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

struct LeafTree(BTreeMap<u64, [u8; 32]>);

impl LeafTree {
    fn new<'a>(leaves: impl IntoIterator<Item = (&'a [u8; 32], &'a u64)>) -> Self {
        Self(
            leaves
                .into_iter()
                .map(|(leaf, index)| (*index, *leaf))
                .collect(),
        )
    }

    fn node(&self, level: usize, position: u64) -> [u8; 32] {
        let first = position << level;
        if self.0.range(first..first + (1 << level)).next().is_none() {
            return Poseidon::zero_bytes()[level];
        }
        if level == 0 {
            return self.0[&position];
        }
        let child = |offset| self.node(level - 1, 2 * position + offset);
        Poseidon::hashv(&[&child(0), &child(1)]).unwrap()
    }
}

fn tree_account(tree: PoolTree, fees: TreeFeeSchedule) -> Account {
    let mut data = vec![0u8; TreeAccount::account_size()];
    let params = nullifier_tree_params();
    TreeAccount::init(
        &mut data,
        TREE_ACCOUNT_DISCRIMINATOR,
        UTXO_TREE_HEIGHT as u8,
        tree.address.to_bytes(),
        tree.id,
        params,
        fees,
    )
    .unwrap();
    Account {
        lamports: 1,
        data,
        owner: Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RingSettings {
    pub mode: RingMode,
    pub has_policy: bool,
    pub co_signer: Option<(Address, CoSignScope)>,
    pub delegate: Option<Address>,
    pub created_slot: u64,
}

impl RingSettings {
    pub(crate) const fn new(mode: RingMode) -> Self {
        Self {
            mode,
            has_policy: false,
            co_signer: None,
            delegate: None,
            created_slot: 0,
        }
    }

    /// A policy ring's hash is a stand-in until `with_registry` pins its table.
    pub(crate) fn config(&self) -> Box<RingPolicy> {
        let mut config = NewRing {
            bump: Address::find_program_address(&[RING_POLICY_PDA_SEED], &program()).1,
            mode: self.mode,
            roles: RingRoles {
                admin: authority(),
                policy: Address::new_from_array([0xa2; 32]),
                pauser: Address::new_from_array([0xa3; 32]),
                cosign_admin: Address::new_from_array([0xa4; 32]),
            },
            auditor_pubkey: *auditor().pubkey().as_bytes(),
            created_slot: self.created_slot,
            records: Address::default(),
            tracking: TRACKING,
        }
        .account();
        if self.has_policy {
            config.policy_hash = [0x11; 32];
        }
        if let Some((_, scope)) = self.co_signer {
            config.co_signers = CoSignerCounts::default().added(scope).expect("one record");
        }
        if let Some(delegate) = self.delegate {
            config.delegate = delegate;
        }
        config
    }
}

fn policy_update(sources: [SourceSlot; N_SOURCE_SLOTS], rules: &RuleTable) -> PolicyUpdate {
    PolicyUpdate {
        sources,
        rules: rules.encode(),
        slot: SLOT,
    }
}

/// Clones share the query log.
#[derive(Clone, Default)]
pub(crate) struct Chain {
    accounts: HashMap<Address, Account>,
    /// Leaf indexes a Merkle proof request may name, every one settled in the tree's account.
    leaves: HashMap<[u8; 32], u64>,
    /// Leaves the indexer serves that the tree's account lacks.
    unsettled: HashMap<[u8; 32], u64>,
    registry: Option<Arc<Registry>>,
    /// A second registry address the same tree answers for.
    curator: Option<Address>,
    /// The leaves of every Merkle proof request.
    pub proof_requests: Arc<Mutex<Vec<Vec<[u8; 32]>>>>,
    pub witness_requests: Arc<Mutex<Vec<Vec<[u8; 32]>>>>,
    /// The ring of every record opening or pool request.
    pub record_requests: Arc<Mutex<Vec<SerializablePubkey>>>,
    tracking: Option<Arc<TrackingFixture>>,
}

impl Chain {
    pub(crate) fn ring(settings: RingSettings) -> Self {
        let registration = RingConfig {
            discriminator: RING_CONFIG,
            authority: authority(),
            program_id: program(),
            ring_authority_transact_is_enabled: 1,
            paused: 0,
            activated: 1,
            bump: Address::find_program_address(&[RING_AUTH_PDA_SEED], &program()).1,
        };
        let chain = Self::default().with_tracking_fixture(TrackingFixture::enrolled());
        let chain = match settings.co_signer {
            Some((signer, scope)) => chain.with(
                ring().co_signer_pda(&signer),
                account(
                    program(),
                    &CoSigner {
                        discriminator: CO_SIGNER,
                        signer,
                        scope: scope.bits(),
                        bump: Address::find_program_address(
                            &[CoSigner::SEED, signer.as_ref()],
                            &program(),
                        )
                        .1,
                    },
                ),
            ),
            None => chain,
        };
        chain
            .with(ring().policy_pda(), account(program(), &*settings.config()))
            .with(
                ring().ring_auth_pda(),
                account(
                    Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
                    &registration,
                ),
            )
            .with_tree(TREE_ID)
    }

    pub(crate) fn with(mut self, address: Address, account: Account) -> Self {
        self.accounts.insert(address, account);
        self
    }

    pub(crate) fn with_tree(self, id: u16) -> Self {
        self.with_tree_fees(id, default_tree_fees())
    }

    pub(crate) fn with_tree_fees(self, id: u16, fees: TreeFeeSchedule) -> Self {
        let tree = PoolTree {
            address: spr_interface::pda::tree(id),
            id,
        };
        self.with(tree.address, tree_account(tree, fees))
    }

    /// The ring account pinning `rules`, every list read from the ring's records.
    pub(crate) fn with_registry(self, registry: Registry, rules: &RuleTable) -> Self {
        let policy = registry.policy(self.ring_account(), rules);
        self.with_records(registry)
            .with(ring().policy_pda(), policy)
    }

    /// `rules` read the Block list from a curator registry the same tree answers for.
    pub(crate) fn with_curator(self, curator: Address, rules: &RuleTable) -> Self {
        use zolana_ring_policy::ListId;
        let mut ring_account = self.ring_account();
        let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
        for list in rules.referenced().iter() {
            sources[list.slot()].list_id = list as u8;
        }
        sources[ListId::Block.slot()].registry = curator;
        ring_account
            .set_policy(policy_update(sources, rules))
            .unwrap();
        let records = self
            .registry
            .as_ref()
            .expect("the records precede the curator")
            .records();
        Self {
            curator: Some(curator),
            ..self
        }
        .with(ring().policy_pda(), account(program(), &*ring_account))
        .with(curator, records)
    }

    /// The ring's records registry alone, the ring stays audit-only.
    pub(crate) fn with_records(self, registry: Registry) -> Self {
        let mut ring_account = self.ring_account();
        ring_account.records = RECORDS;
        let records = registry.records();
        Self {
            registry: Some(Arc::new(registry)),
            ..self
        }
        .with(ring().policy_pda(), account(program(), &*ring_account))
        .with(RECORDS, records)
    }

    fn ring_account(&self) -> Box<RingPolicy> {
        self.accounts
            .get(&ring().policy_pda())
            .map(|account| Box::new(*bytemuck::from_bytes::<RingPolicy>(&account.data)))
            .expect("Chain::ring writes the ring account")
    }

    /// `addresses` alone hold tracking rows, a test of the output predicate names its keys.
    pub(crate) fn with_tracking(self, addresses: &[ShieldedAddress]) -> Self {
        self.with_tracking_fixture(Arc::new(TrackingFixture::of(addresses)))
    }

    /// One tag on every row, a test of a salt names the tag it hashes to.
    pub(crate) fn with_tracking_tag(
        self,
        addresses: &[ShieldedAddress],
        list_tag: [u8; 32],
    ) -> Self {
        self.with_tracking_fixture(Arc::new(TrackingFixture::tagged(addresses, list_tag)))
    }

    /// The tree's registry and each enrolled owner's authorization holding its address viewing key.
    fn with_tracking_fixture(self, tracking: Arc<TrackingFixture>) -> Self {
        let chain = tracking
            .authorizations
            .iter()
            .fold(self, |chain, (address, account)| {
                chain.with(*address, account.clone())
            });
        Self {
            tracking: Some(Arc::clone(&tracking)),
            ..chain
        }
        .with(TRACKING, tracking.account())
    }

    /// The indexed route, the prover fetches the input proofs and no witness is read here.
    pub(crate) fn client(self) -> RingClient<Chain, Chain> {
        self.client_on(ProofDataSource::Prover)
    }

    /// The client route, an assembly reads its input witnesses here.
    pub(crate) fn witness_client(self) -> RingClient<Chain, Chain> {
        self.client_on(ProofDataSource::Client)
    }

    fn client_on(self, source: ProofDataSource) -> RingClient<Chain, Chain> {
        let prover = || AsyncProverClient::local().with_proof_data_source(source);
        RingClient::new(AsyncSprClient::new(self.clone(), self, prover()), prover())
    }
}

const CONTEXT: Context = Context {
    block_time: 0,
    slot: SLOT,
};

#[async_trait]
impl AsyncRpc for Chain {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Ok(self.accounts.get(&address).cloned())
    }

    async fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        Ok(addresses
            .iter()
            .map(|address| self.accounts.get(address).cloned())
            .collect())
    }

    async fn get_slot(&self) -> Result<u64, ClientError> {
        Ok(SLOT)
    }

    async fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        self.proof_requests.lock().unwrap().push(leaves.clone());
        let mut data = self.accounts[&tree_account].data.clone();
        let mut tree = TreeAccount::from_bytes(&mut data, tree_account.to_bytes()).unwrap();
        let root_index = tree.utxo_tree().current_root_index();
        let served = LeafTree::new(self.leaves.iter().chain(&self.unsettled));
        let proofs = leaves
            .iter()
            .map(|leaf| {
                let leaf_index = self
                    .leaves
                    .get(leaf)
                    .or_else(|| self.unsettled.get(leaf))
                    .copied()
                    .unwrap_or_default();
                MerkleProof {
                    leaf: *leaf,
                    merkle_context: MerkleContext {
                        tree_type: 0,
                        tree: tree_account,
                    },
                    path: (0..STATE_TREE_HEIGHT)
                        .map(|level| served.node(level, (leaf_index >> level) ^ 1))
                        .collect(),
                    leaf_index,
                    root: served.node(STATE_TREE_HEIGHT, 0),
                    root_seq: SLOT,
                    root_index,
                }
            })
            .collect();
        Ok(GetMerkleProofsResponse {
            context: CONTEXT,
            proofs,
        })
    }
}

#[async_trait]
impl AsyncRingIndexer for Chain {
    async fn get_storage_member_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingIndexerError> {
        self.record_requests.lock().unwrap().push(request.registry);
        let registry = self
            .registry
            .as_ref()
            .filter(|_| request.registry == RECORDS.into())
            .ok_or(ClientError::UnsupportedRpcMethod(
                "get_storage_member_openings",
            ))?;
        Ok(GetStorageMemberOpeningsResponse {
            context: spr_indexer_api::Context {
                block_time: 0,
                slot: SLOT,
            },
            root: registry.root_view(),
            openings: request
                .members
                .iter()
                .map(|member| registry.opening(&member.0))
                .collect(),
        })
    }

    async fn get_storage_record_pool(
        &self,
        request: GetStorageRecordPoolRequest,
    ) -> Result<GetStorageRecordPoolResponse, RingIndexerError> {
        self.record_requests.lock().unwrap().push(request.registry);
        let registry = self
            .registry
            .as_ref()
            .filter(|_| {
                request.registry == RECORDS.into()
                    || self.curator.map(Into::into) == Some(request.registry)
            })
            .ok_or(ClientError::UnsupportedRpcMethod("get_storage_record_pool"))?;
        let members: Vec<[u8; 32]> = request.members.iter().map(|member| member.0).collect();
        let pool = registry
            .tree
            .record_pool(
                &members,
                Canopy::covering(request.openings as usize).unwrap(),
            )
            .unwrap();
        Ok(GetStorageRecordPoolResponse {
            context: spr_indexer_api::Context {
                block_time: 0,
                slot: SLOT,
            },
            root: registry.root_view(),
            records: pool
                .records
                .iter()
                .zip(&pool.proof.paths)
                .map(|(record, path)| RingIndexedMemberRecordView {
                    record: registry.view(record),
                    path: RingRecordPathView {
                        index: path.index,
                        siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
                    },
                })
                .collect(),
            canopy: pool.proof.canopy.into_iter().map(Hash).collect(),
            subjects: pool
                .subjects
                .iter()
                .map(|subject| subject.record_index)
                .collect(),
        })
    }

    async fn get_tracking_openings(
        &self,
        request: GetTrackingOpeningsRequest,
    ) -> Result<GetTrackingOpeningsResponse, RingIndexerError> {
        let tracking = self.tracking()?;
        Ok(GetTrackingOpeningsResponse {
            context: spr_indexer_api::Context {
                block_time: 0,
                slot: SLOT,
            },
            root: tracking.root_view(),
            openings: request
                .members
                .iter()
                .map(|member| tracking.opening(&member.0))
                .collect(),
        })
    }

    async fn get_tracking_record_pool(
        &self,
        request: GetTrackingRecordPoolRequest,
    ) -> Result<GetTrackingRecordPoolResponse, RingIndexerError> {
        let tracking = self.tracking()?;
        let members: Vec<[u8; 32]> = request.members.iter().map(|member| member.0).collect();
        let pool = tracking
            .tree
            .record_pool(
                &members,
                Canopy::covering_tracking(request.openings as usize).unwrap(),
            )
            .unwrap();
        Ok(GetTrackingRecordPoolResponse {
            context: spr_indexer_api::Context {
                block_time: 0,
                slot: SLOT,
            },
            root: tracking.root_view(),
            records: pool
                .records
                .iter()
                .zip(&pool.proof.paths)
                .map(|(record, path)| RingIndexedTrackingRecordView {
                    record: record_view(record),
                    path: RingRecordPathView {
                        index: path.index,
                        siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
                    },
                })
                .collect(),
            canopy: pool.proof.canopy.into_iter().map(Hash).collect(),
            subjects: pool
                .subjects
                .iter()
                .map(|subject| subject.record_index)
                .collect(),
        })
    }
}

impl Chain {
    fn tracking(&self) -> Result<&TrackingFixture, RingIndexerError> {
        self.tracking
            .as_deref()
            .ok_or(ClientError::UnsupportedRpcMethod("get_tracking_openings").into())
    }
}

struct TrackingFixture {
    tree: TrackingTree,
    authorizations: Vec<(Address, Account)>,
}

impl TrackingFixture {
    fn enrolled() -> Arc<Self> {
        static FIXTURE: std::sync::OnceLock<Arc<TrackingFixture>> = std::sync::OnceLock::new();
        Arc::clone(FIXTURE.get_or_init(|| {
            let addresses: Vec<_> = (0..ENROLLED_SEEDS)
                .map(|seed| keypair(seed).shielded_address().unwrap())
                .collect();
            Arc::new(Self::of(&addresses))
        }))
    }

    /// Records in leaf order, each owner's own key.
    fn of(addresses: &[ShieldedAddress]) -> Self {
        Self::tagged(addresses, [0x06; 32])
    }

    fn tagged(addresses: &[ShieldedAddress], list_tag: [u8; 32]) -> Self {
        let mut members: Vec<([u8; 32], ShieldedAddress)> = addresses
            .iter()
            .map(|address| {
                (
                    address.signing_pubkey.owner_proof_input_hash().unwrap(),
                    *address,
                )
            })
            .collect();
        members.sort_by_key(|(member, _)| *member);
        let mut records = vec![TrackingRecord {
            next: members
                .first()
                .map_or(TrackingRecord::SENTINEL.next, |(member, _)| *member),
            ..TrackingRecord::SENTINEL
        }];
        let mut authorizations = Vec::with_capacity(members.len());
        for (position, (member, address)) in members.iter().enumerate() {
            records.push(TrackingRecord {
                member: *member,
                next: members
                    .get(position + 1)
                    .map_or(TrackingRecord::SENTINEL.next, |(next, _)| *next),
                nullifier_pk: address.nullifier_pubkey,
                ct_hash: [0x05; 32],
                list_tag,
            });
            let owner =
                Address::new_from_array(address.signing_pubkey.confidential_view_tag().unwrap());
            let authorization = TrackingAuthorization {
                discriminator: TrackingAuthorization::DISCRIMINATOR,
                registry: TRACKING,
                owner,
                nullifier_pk: address.nullifier_pubkey,
                list_tag,
                viewing_u: address.viewing_pubkey.u(),
                eph_u: [0; 32],
                ciphertext: [0; 64],
                applied: 1,
            };
            authorizations.push((
                TrackingAuthorization::find_address(&TRACKING, &owner).0,
                account(STORAGE_PROGRAM_ID, &authorization),
            ));
        }
        Self {
            tree: TrackingTree::from_records(records).unwrap(),
            authorizations,
        }
    }

    fn account(&self) -> Account {
        let mut registry = TrackingRegistry::new(&InitializeTrackingIxData {
            ring_id: ring().ring_id().unwrap(),
            auditor_pubkey: *auditor().pubkey().as_bytes(),
        });
        registry.roots[0].hash = self.tree.root().unwrap();
        registry.roots[0].revision = Revision::from(REVISION);
        account(STORAGE_PROGRAM_ID, &registry)
    }

    fn root_view(&self) -> StorageRootView {
        StorageRootView {
            root: Hash(self.tree.root().unwrap()),
            revision: REVISION,
            next_index: self.tree.records().len() as u64,
        }
    }

    fn opening(&self, member: &[u8; 32]) -> RingTrackingOpening {
        let (present, record, path) = match self.tree.opening(member).unwrap() {
            TrackingOpening::Present { record, path } => (true, record, path),
            TrackingOpening::Absent { low, path } => (false, low, path),
        };
        RingTrackingOpening {
            present,
            record: record_view(&record),
            path: RingRecordPathView {
                index: path.index,
                siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
            },
        }
    }
}

fn record_view(record: &TrackingRecord) -> RingTrackingRecordView {
    RingTrackingRecordView {
        member: Hash(record.member),
        next: Hash(record.next),
        nullifier_pk: Hash(record.nullifier_pk),
        ct_hash: Hash(record.ct_hash),
        list_tag: Hash(record.list_tag),
        seal: None,
    }
}

/// `note` under the zero key, its commitment and nullifier follow.
pub(crate) fn zero_key(mut note: WalletUtxo) -> WalletUtxo {
    let key = NullifierKey::from_secret([0; 31]);
    note.nullifier_pubkey = spr_interface::ZERO_NULLIFIER_PUBKEY;
    note.utxo_hash = note
        .utxo
        .hash(&note.nullifier_pubkey, &[0; 32], &[0; 32], note.tree_id)
        .unwrap();
    note.nullifier = key.nullifier(&note.utxo_hash, &note.utxo.blinding).unwrap();
    note
}

/// No test proves on the client route.
impl AsyncWitnessReader for Chain {
    fn input_witnesses(
        &self,
        inputs: &[&SppProofInputUtxo],
        _dummy_nullifiers: &[[u8; 32]],
        _config: Option<IndexerRpcConfig>,
    ) -> impl std::future::Future<Output = Result<InputWitnesses, ClientError>> + Send {
        self.witness_requests
            .lock()
            .unwrap()
            .push(inputs.iter().map(|input| input.utxo_hash).collect());
        std::future::ready(Err(ClientError::NoInputs))
    }
}

pub(crate) struct Registry {
    tree: MemberRegistryTree,
}

impl Registry {
    /// Each owner's public record with `lists` set, ordered as the linked records require.
    pub(crate) fn new(owners: &[(&ShieldedKeypair, u64)]) -> Self {
        let mut members: Vec<([u8; 32], u64)> = owners
            .iter()
            .map(|(owner, lists)| (*owner_record(owner).as_bytes(), *lists))
            .collect();
        members.sort_by_key(|(member, _)| *member);
        let mut records = vec![MemberRecord {
            next: members
                .first()
                .map_or(MemberRecord::SENTINEL.next, |(member, _)| *member),
            ..MemberRecord::SENTINEL
        }];
        for (position, (member, lists)) in members.iter().enumerate() {
            records.push(MemberRecord {
                mint_policy: Default::default(),
                member: *member,
                next: members
                    .get(position + 1)
                    .map_or(MemberRecord::SENTINEL.next, |(next, _)| *next),
                lists: *lists,
            });
        }
        Self {
            tree: MemberRegistryTree::from_records(records).unwrap(),
        }
    }

    pub(crate) fn with_mint(self, mint: Address, policy: zolana_ring_policy::MintPolicy) -> Self {
        let tree = self
            .tree
            .apply(
                [0; 32],
                &[custom_ring_interface::RecordWrite {
                    member: *zolana_ring_policy::Member::asset(&mint).unwrap().as_bytes(),
                    mask: 0,
                    value: 0,
                    mint_policy: Some(policy),
                }],
            )
            .unwrap()
            .tree;
        Self { tree }
    }

    pub(crate) fn root(&self) -> [u8; 32] {
        self.tree.root().unwrap()
    }

    /// The `RECORDS` registry at `REVISION`.
    fn records(&self) -> Account {
        let mut records = StorageRegistry::new(
            authority(),
            &InitializeIxData {
                registry_id: RegistryId([0; 32]),
                grace_slots: 0u64.to_le_bytes(),
                ring_id: ring().ring_id().unwrap(),
                tracking_registry: Address::default(),
            },
        );
        records.roots[0].hash = self.root();
        records.roots[0].revision = Revision::from(REVISION);
        account(STORAGE_PROGRAM_ID, &records)
    }

    /// `rules` over the records.
    fn policy(&self, mut policy: Box<RingPolicy>, rules: &RuleTable) -> Account {
        policy.records = RECORDS;
        let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
        for list in rules.referenced().iter() {
            sources[list.slot()].list_id = list as u8;
        }
        policy.set_policy(policy_update(sources, rules)).unwrap();
        account(program(), &*policy)
    }

    fn root_view(&self) -> StorageRootView {
        StorageRootView {
            root: Hash(self.root()),
            revision: REVISION,
            next_index: self.tree.records().len() as u64,
        }
    }

    fn opening(&self, member: &[u8; 32]) -> RingMemberOpening {
        let opening = self.tree.opening(member).unwrap();
        let (present, record, path) = match opening {
            RecordOpening::Present { record, path } => (true, record, path),
            RecordOpening::Absent { low, path } => (false, low, path),
        };
        RingMemberOpening {
            present,
            record: self.view(&record),
            path: RingRecordPathView {
                index: path.index,
                siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
            },
        }
    }

    fn view(&self, record: &MemberRecord) -> RingMemberRecordView {
        RingMemberRecordView {
            member: Hash(record.member),
            next: Hash(record.next),
            lists: record.lists,
            mint_policy: record.mint_policy,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct MessageCase {
    pub name: String,
    pub message: Base64String,
    /// A `MessageMismatch` variant, or `Accepted`.
    pub verdict: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct MessageVector<R> {
    pub description: String,
    pub request: R,
    pub cases: Vec<MessageCase>,
}

pub(crate) fn verdict(checked: Result<crate::VerifiedMessage, crate::MessageMismatch>) -> String {
    checked.map_or_else(
        |mismatch| format!("{mismatch:?}"),
        |_| "Accepted".to_owned(),
    )
}

/// Compiled as Ring RPC compiles its relay messages.
pub(crate) fn relay_message(
    fee_payer: &Address,
    instructions: &[solana_instruction::Instruction],
    units: u32,
) -> Base64String {
    spr_client::compile_message(
        fee_payer,
        instructions,
        solana_message::Hash::new_from_array([0x7b; 32]),
        spr_client::ComputeBudgetConfig::new(units),
    )
    .unwrap()
    .serialize()
    .into()
}

/// `UPDATE_RELAY_MESSAGES=1` rewrites the file from `fresh`, the committed file is the one read.
pub(crate) fn pinned_vector<V>(name: &str, fresh: V) -> V
where
    V: serde::Serialize + serde::de::DeserializeOwned,
{
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/rpc")
        .join(name);
    if std::env::var_os("UPDATE_RELAY_MESSAGES").is_some() {
        let json = serde_json::to_string_pretty(&fresh).unwrap();
        std::fs::write(&path, json + "\n").unwrap();
    }
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
