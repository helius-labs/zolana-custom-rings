//! The chain and indexer every unit test reads, accounts from one map and the queries recorded.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use bytemuck::{Pod, Zeroable};
use custom_ring_interface::{
    AppliedAt, CoSignScope, EscrowKey, MemberRegistry, QueueEntry, RecordQueue, RingMode,
    RingProgramConfig, SourceSlot, CONFIG_PDA_SEED, DEFAULT_INSERT_FEE, MEMBER_REGISTRY_PDA_SEED,
    N_SOURCE_SLOTS, RECORD_QUEUE_PDA_SEED, RING_PROGRAM_CONFIG,
};
use solana_account::Account;
use solana_address::Address;
use spr_client::{
    rpc::STATE_TREE_HEIGHT, AsyncProverClient, AsyncRpc, AsyncWitnessReader, AsyncZolanaClient,
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
use spr_keypair::{random_blinding, NullifierKey, ShieldedKeypair, SigningKey, X25519Keypair};
use spr_transaction::{utxo::SppProofInputUtxo, Data, Mint, Utxo, WalletUtxo};
use spr_tree::{TreeAccount, UTXO_TREE_HEIGHT};
use zolana_ring_client::{AsyncRingIndexer, RingIndexerError, ViewingHistory};
use zolana_ring_indexer::rpc::{
    GetRingMemberOpeningsRequest, GetRingMemberOpeningsResponse, GetRingRecordPoolRequest,
    GetRingRecordPoolResponse, RingIndexedMemberRecordView, RingMemberOpening,
    RingMemberRecordView, RingRecordPathView, RingRegistryRootView,
};
use zolana_ring_member_registry::{
    Canopy, MemberRecord, MemberRegistryTree, RecordOpening, RecordTree,
};
use zolana_ring_policy::{Member, RuleTable};

use crate::client::RingClient;
use crate::{trees::PoolTree, CustomRing, REDACTED};

pub(crate) const SLOT: u64 = 2_359_301;
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

pub(crate) fn history(owner: &ShieldedKeypair) -> ViewingHistory {
    ViewingHistory::new(owner.viewing_pubkey(), 0)
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

fn tree_account(tree: PoolTree) -> Account {
    let mut data = vec![0u8; TreeAccount::account_size()];
    let params = nullifier_tree_params();
    TreeAccount::init(
        &mut data,
        TREE_ACCOUNT_DISCRIMINATOR,
        UTXO_TREE_HEIGHT as u8,
        tree.address.to_bytes(),
        tree.id,
        params,
        default_tree_fees(params.input_queue_zkp_batch_size).unwrap(),
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

    pub(crate) fn config(&self) -> RingProgramConfig {
        let mut config = RingProgramConfig::zeroed();
        config.discriminator = RING_PROGRAM_CONFIG;
        config.authority = authority();
        config.auditor_pubkey = *auditor().pubkey().as_bytes();
        config.bump = Address::find_program_address(&[CONFIG_PDA_SEED], &program()).1;
        config.has_policy = u8::from(self.has_policy);
        config.mode = self.mode as u8;
        config.insert_fee = DEFAULT_INSERT_FEE.to_le_bytes();
        config.created_slot = self.created_slot.to_le_bytes();
        if let Some((signer, scope)) = self.co_signer {
            config.co_signer = signer;
            config.co_sign_scope = scope.bits();
        }
        if let Some(delegate) = self.delegate {
            config.delegate = delegate;
        }
        config
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
    /// The leaves of every Merkle proof request.
    pub proof_requests: Arc<Mutex<Vec<Vec<[u8; 32]>>>>,
    pub witness_requests: Arc<Mutex<Vec<Vec<[u8; 32]>>>>,
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
        Self::default()
            .with(ring().config_pda(), account(program(), &settings.config()))
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
        let tree = PoolTree {
            address: spr_interface::pda::tree(id),
            id,
        };
        self.with(tree.address, tree_account(tree))
    }

    /// The ring's own registry pinning `rules`, every list read from it.
    pub(crate) fn with_registry(self, registry: Registry, rules: &RuleTable) -> Self {
        let account = registry.account(rules);
        Self {
            registry: Some(Arc::new(registry)),
            ..self
        }
        .with(ring().registry_pda(), account)
    }

    pub(crate) fn with_queue(
        self,
        entries: &[QueueEntry],
        queued_at: u64,
        next_apply_slot: u64,
    ) -> Self {
        let bump = Address::find_program_address(&[RECORD_QUEUE_PDA_SEED], &program()).1;
        let mut queue = RecordQueue::new(bump);
        for entry in entries {
            queue.push(entry, queued_at).unwrap();
        }
        queue.next_apply_slot = next_apply_slot.to_le_bytes();
        self.with(ring().queue_pda(), account(program(), &queue))
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
        RingClient::new(
            AsyncZolanaClient::new(self.clone(), self, prover()),
            prover(),
        )
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
    async fn get_ring_member_openings(
        &self,
        request: GetRingMemberOpeningsRequest,
    ) -> Result<GetRingMemberOpeningsResponse, RingIndexerError> {
        let registry = self
            .registry
            .as_ref()
            .ok_or(ClientError::UnsupportedRpcMethod(
                "get_ring_member_openings",
            ))?;
        Ok(GetRingMemberOpeningsResponse {
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

    async fn get_ring_record_pool(
        &self,
        request: GetRingRecordPoolRequest,
    ) -> Result<GetRingRecordPoolResponse, RingIndexerError> {
        let registry = self
            .registry
            .as_ref()
            .ok_or(ClientError::UnsupportedRpcMethod("get_ring_record_pool"))?;
        let members: Vec<[u8; 32]> = request.members.iter().map(|member| member.0).collect();
        let pool = registry
            .tree
            .record_pool(
                &members,
                Canopy::covering(request.openings as usize).unwrap(),
            )
            .unwrap();
        Ok(GetRingRecordPoolResponse {
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

/// The ring's own record tree, every member escrowing its nullifier key.
pub(crate) struct Registry {
    tree: MemberRegistryTree,
    views: HashMap<[u8; 32], RingMemberRecordView>,
}

impl Registry {
    /// Each owner with `lists` set, ordered as the linked records require.
    pub(crate) fn new(owners: &[(&ShieldedKeypair, u64)]) -> Self {
        let sealed = [0x5a; 32];
        let mut members: Vec<_> = owners
            .iter()
            .map(|(owner, lists)| {
                let address = owner.shielded_address().unwrap();
                let member = address.signing_pubkey.owner_proof_input_hash().unwrap();
                let escrow_key = EscrowKey {
                    nullifier_pk: &address.nullifier_pubkey,
                    ciphertext: &sealed,
                }
                .hash()
                .unwrap();
                let view = RingMemberRecordView {
                    mint_policy: Default::default(),
                    member: Hash(member),
                    next: Hash([0; 32]),
                    lists: *lists,
                    escrow_key: Hash(escrow_key),
                    owner_pubkey: Some(SerializablePubkey(Address::new_from_array(
                        address.signing_pubkey.as_ed25519().unwrap(),
                    ))),
                    nullifier_pk: Some(Hash(address.nullifier_pubkey)),
                    eph_pk: Some(Base64String(auditor().pubkey().as_bytes().to_vec())),
                    ciphertext: Some(Base64String(sealed.to_vec())),
                };
                (member, view)
            })
            .collect();
        members.sort_by_key(|(member, _)| *member);
        let mut records = vec![MemberRecord {
            next: members
                .first()
                .map_or(MemberRecord::SENTINEL.next, |(member, _)| *member),
            ..MemberRecord::SENTINEL
        }];
        let mut views = HashMap::new();
        for (position, (member, mut view)) in members.iter().cloned().enumerate() {
            let next = members
                .get(position + 1)
                .map_or(MemberRecord::SENTINEL.next, |(next, _)| *next);
            view.next = Hash(next);
            records.push(MemberRecord {
                mint_policy: Default::default(),
                member,
                next,
                lists: view.lists,
                escrow_key: view.escrow_key.0,
            });
            views.insert(member, view);
        }
        Self {
            tree: MemberRegistryTree::from_records(records).unwrap(),
            views,
        }
    }

    pub(crate) fn with_mint(
        mut self,
        mint: Address,
        policy: zolana_ring_policy::MintPolicy,
    ) -> Self {
        self.tree
            .apply(
                [0; 32],
                &[custom_ring_interface::QueueEntry {
                    member: *zolana_ring_policy::Member::asset(&mint).unwrap().as_bytes(),
                    mask: 0,
                    value: 0,
                    escrow_key: [0; 32],
                    mint_policy: Some(policy),
                }],
            )
            .unwrap();
        self
    }

    pub(crate) fn root(&self) -> [u8; 32] {
        self.tree.root().unwrap()
    }

    fn account(&self, rules: &RuleTable) -> Account {
        let bump = Address::find_program_address(&[MEMBER_REGISTRY_PDA_SEED], &program()).1;
        let mut registry = MemberRegistry::new(bump, SLOT);
        registry.push_root(
            self.root(),
            AppliedAt {
                applied: 0,
                slot: SLOT,
            },
        );
        let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
        for list in rules.referenced().iter() {
            sources[list.slot()].list_id = list as u8;
        }
        registry.set_policy(sources, rules.encode(), SLOT).unwrap();
        account(program(), &registry)
    }

    fn root_view(&self) -> RingRegistryRootView {
        RingRegistryRootView {
            root: Hash(self.root()),
            root_index: 1,
            applied: 0,
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
        let mut view = self
            .views
            .get(&record.member)
            .cloned()
            .unwrap_or(RingMemberRecordView {
                member: Hash(record.member),
                next: Hash(record.next),
                lists: record.lists,
                escrow_key: Hash(record.escrow_key),
                mint_policy: record.mint_policy,
                owner_pubkey: None,
                nullifier_pk: None,
                eph_pk: None,
                ciphertext: None,
            });
        view.next = Hash(record.next);
        view.mint_policy = record.mint_policy;
        view
    }
}
