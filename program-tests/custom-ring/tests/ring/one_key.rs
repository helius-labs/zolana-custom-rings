//! One transfer key proven and settled, registries and spent notes seeded.

use std::sync::{Arc, Mutex};

use super::{
    forester_stall::{nullifier_queue_index, tree_data},
    *,
};
use base64::Engine;
use bytemuck::Pod;
use custom_ring_cli::{Zolana, ZolanaServices};
use custom_ring_interface::{
    key_catalog::{RingCircuit, RING_KEYS},
    policy_withdrawal_hash,
    storage::{Revision, Root, StorageRegistry},
    tracking::{TrackingAuthorization, TrackingRegistry},
    verifying_key, RingProof, SignerSet, SlotBody, TransferBinding, TransferRoots,
    ANONYMOUS_PARTIES, MAX_CPI_DATA_LEN, PROVING_KEY_SHA256S, REGISTER_KEY_CIPHERTEXT_LEN,
    STORAGE_PROGRAM_ID, TAGGED_X25519_KEY_LEN,
};
use custom_ring_test_validator::policy::RELEASED;
use serde_json::Value;
use solana_message::v1::MAX_ADDRESSES;
use solana_transaction_status_client_types::EncodedConfirmedTransactionWithStatusMeta;
use spr_api::{HttpClient, HttpFuture, HttpRequest};
use spr_client::{
    prover::{ExpectedProvingKey, ProveRequest},
    rpc::{GetNonInclusionProofsResponse, IndexerRpcConfig, STATE_TREE_HEIGHT},
    ClientError, ConfirmedInstructionGroups, GetMerkleProofsResponse, MerkleContext, MerkleProof,
    Proof, ProofDataSource, WitnessReader,
};
use spr_hasher::{Hasher, HasherError, Poseidon};
use spr_indexer_api::Hash;
use spr_interface::N_PUBLIC_SLOTS;
use spr_keypair::NullifierKey;
use zeroize::Zeroizing;
use zolana_ring_client::{RingIndexer, RingIndexerError};
use zolana_ring_indexer::{
    rpc::{
        GetStorageRecordPoolRequest, GetStorageRecordPoolResponse, RingIndexedMemberRecordView,
        RingMemberRecordView, RingRecordPathView, StorageRootView,
    },
    tracking::{
        GetTrackingRecordPoolRequest, GetTrackingRecordPoolResponse, RingIndexedTrackingRecordView,
        RingTrackingRecordView,
    },
};
use zolana_ring_member_registry::{
    Canopy, MemberRecord, MemberRegistryTree, RecordPoolOf, RecordTree, SharedPath, TrackingRecord,
    TrackingTree,
};

const KEY: RingCircuit = RingCircuit::Transfer {
    outputs: 2,
    inputs: 24,
    withdrawals: 4,
    owners: 4,
    entry: false,
    wide: false,
};
const REVISION: u64 = 1;
const DISCOVERY_DEPOSIT: u64 = 1_000_000;
/// Photon's state kind, the indexed prover refuses another.
const STATE_TREE_TYPE: u16 = 1;
/// The default heap frame, no ring transaction requests a larger one.
const HEAP_LIMIT: u64 = 32 * 1024;
const TRACKING_SECTION: [&str; 6] = [
    "trackingRoot",
    "trackingRecords",
    "trackingProof",
    "trackingSubjects",
    "rowEntries",
    "outputEntries",
];

#[derive(Clone)]
pub(super) struct SeededNotes {
    leaves: Vec<[u8; 32]>,
    first_leaf: u64,
    /// The tree's left nodes ahead of the first note.
    frontier: Vec<[u8; 32]>,
    root: [u8; 32],
    root_index: u16,
    slot: u64,
}

impl SeededNotes {
    fn node(&self, level: usize, position: u64) -> Result<[u8; 32], HasherError> {
        let (start, end) = (position << level, (position + 1) << level);
        if end <= self.first_leaf {
            return Ok(self.frontier[level]);
        }
        if start >= self.first_leaf + self.leaves.len() as u64 {
            return Ok(Poseidon::zero_bytes()[level]);
        }
        if level == 0 {
            return Ok(self.leaves[(position - self.first_leaf) as usize]);
        }
        Poseidon::hashv(&[
            &self.node(level - 1, 2 * position)?,
            &self.node(level - 1, 2 * position + 1)?,
        ])
    }

    pub(super) fn proof(
        &self,
        tree: Address,
        leaf: [u8; 32],
    ) -> Result<Option<MerkleProof>, HasherError> {
        let Some(position) = self.leaves.iter().position(|held| *held == leaf) else {
            return Ok(None);
        };
        let leaf_index = self.first_leaf + position as u64;
        Ok(Some(MerkleProof {
            leaf,
            merkle_context: MerkleContext {
                tree_type: STATE_TREE_TYPE,
                tree,
            },
            path: (0..STATE_TREE_HEIGHT)
                .map(|level| self.node(level, (leaf_index >> level) ^ 1))
                .collect::<Result<_, _>>()?,
            leaf_index,
            root: self.root,
            root_seq: self.slot,
            root_index: self.root_index,
        }))
    }

    fn check_roots(&self) -> Result<()> {
        ensure!(
            self.node(STATE_TREE_HEIGHT, 0)? == self.root,
            "the seeded leaves miss the tree root"
        );
        Ok(())
    }
}

pub(super) struct SeededIndexer {
    pub(super) indexer: SprIndexer,
    pub(super) notes: SeededNotes,
    pub(super) own: MemberRegistryTree,
    /// A curator registry read beside the ring's own.
    pub(super) curator: Option<(Address, MemberRegistryTree)>,
    pub(super) tracking: TrackingTree,
}

pub(super) fn context(notes: &SeededNotes) -> spr_indexer_api::Context {
    spr_indexer_api::Context {
        block_time: 0,
        slot: notes.slot,
    }
}

fn root_view(root: [u8; 32], records: usize) -> StorageRootView {
    StorageRootView {
        root: Hash(root),
        revision: REVISION,
        next_index: records as u64,
    }
}

fn member_bytes(members: &[Hash]) -> Vec<[u8; 32]> {
    members.iter().map(|member| member.0).collect()
}

fn canopy_view<L>(pool: &RecordPoolOf<L>) -> Vec<Hash> {
    pool.proof.canopy.iter().copied().map(Hash).collect()
}

fn subject_indexes<L>(pool: &RecordPoolOf<L>) -> Vec<u32> {
    pool.subjects
        .iter()
        .map(|subject| subject.record_index)
        .collect()
}

fn path_view(path: &SharedPath) -> RingRecordPathView {
    RingRecordPathView {
        index: path.index,
        siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
    }
}

impl Rpc for SeededIndexer {
    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        let notes = &self.notes;
        let proofs = leaves
            .into_iter()
            .map(|leaf| {
                notes
                    .proof(tree_account, leaf)
                    .map_err(|error| ClientError::Rpc(error.to_string()))?
                    .ok_or_else(|| ClientError::Rpc("a leaf no seed holds".to_owned()))
            })
            .collect::<Result<_, _>>()?;
        Ok(GetMerkleProofsResponse {
            context: spr_client::Context {
                block_time: 0,
                slot: notes.slot,
            },
            proofs,
        })
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        self.indexer
            .get_non_inclusion_proofs(tree_account, leaves, config)
    }
}

impl WitnessReader for SeededIndexer {}

impl RingIndexer for SeededIndexer {
    fn get_storage_record_pool(
        &self,
        request: GetStorageRecordPoolRequest,
    ) -> Result<GetStorageRecordPoolResponse, RingIndexerError> {
        let members = member_bytes(&request.members);
        let registry = match &self.curator {
            Some((address, curator)) if request.registry == (*address).into() => curator,
            _ => &self.own,
        };
        let pool = registry
            .record_pool(
                &members,
                Canopy::covering(request.openings as usize).unwrap(),
            )
            .unwrap();
        Ok(GetStorageRecordPoolResponse {
            context: context(&self.notes),
            root: root_view(registry.root().unwrap(), registry.records().len()),
            records: pool
                .records
                .iter()
                .zip(&pool.proof.paths)
                .map(|(record, path)| RingIndexedMemberRecordView {
                    record: RingMemberRecordView {
                        member: Hash(record.member),
                        next: Hash(record.next),
                        lists: record.lists,
                        mint_policy: record.mint_policy,
                    },
                    path: path_view(path),
                })
                .collect(),
            canopy: canopy_view(&pool),
            subjects: subject_indexes(&pool),
        })
    }

    fn get_tracking_record_pool(
        &self,
        request: GetTrackingRecordPoolRequest,
    ) -> Result<GetTrackingRecordPoolResponse, RingIndexerError> {
        let members = member_bytes(&request.members);
        let pool = self
            .tracking
            .record_pool(
                &members,
                Canopy::covering_tracking(request.openings as usize).unwrap(),
            )
            .unwrap();
        Ok(GetTrackingRecordPoolResponse {
            context: context(&self.notes),
            root: root_view(self.tracking.root().unwrap(), self.tracking.records().len()),
            records: pool
                .records
                .iter()
                .zip(&pool.proof.paths)
                .map(|(record, path)| RingIndexedTrackingRecordView {
                    record: RingTrackingRecordView {
                        member: Hash(record.member),
                        next: Hash(record.next),
                        nullifier_pk: Hash(record.nullifier_pk),
                        ct_hash: Hash(record.ct_hash),
                        list_tag: Hash(record.list_tag),
                        seal: None,
                    },
                    path: path_view(path),
                })
                .collect(),
            canopy: canopy_view(&pool),
            subjects: subject_indexes(&pool),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct RingBody(Arc<Mutex<Option<Value>>>);

impl RingBody {
    pub(super) fn take(&self) -> Result<Value> {
        self.0
            .lock()
            .map_err(|_| anyhow!("ring body lock"))?
            .take()
            .context("a ring request reached the prover")
    }
}

#[derive(Debug)]
struct CapturingHttp {
    http: reqwest::Client,
    body: RingBody,
}

impl HttpClient for CapturingHttp {
    fn send<'a>(&'a self, request: HttpRequest) -> HttpFuture<'a> {
        if let (Some(ring_body), Ok(mut held)) =
            (ring_prover_request(&request.body), self.body.0.lock())
        {
            *held = Some(ring_body);
        }
        HttpClient::send(&self.http, request)
    }
}

struct ReplayedBody {
    body: Value,
    key: ExpectedProvingKey,
}

impl ProveRequest for ReplayedBody {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        custom_ring_sdk::secret_json_body(&self.body)
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        Ok(self.key.clone())
    }
}

pub(super) struct SeededChain<'a> {
    pub(super) env: &'a TestEnv,
    pub(super) notes: SeededNotes,
    pub(super) rows: &'a [ShieldedAddress],
    pub(super) body: &'a RingBody,
}

impl SeededChain<'_> {
    pub(super) fn connect(self) -> Result<Zolana<SolanaRpc, SeededIndexer>> {
        let prover = || {
            AsyncProverClient::with_client(
                prover_url(),
                CapturingHttp {
                    http: reqwest::Client::new(),
                    body: self.body.clone(),
                },
            )
            .with_proof_data_source(ProofDataSource::Client)
        };
        Ok(ZolanaServices {
            rpc: SolanaRpc::new(self.env.rpc_url.clone()),
            indexer: SeededIndexer {
                indexer: SprIndexer::new(self.env.indexer_url.clone()),
                notes: self.notes,
                own: own_tree(self.rows, &[])?,
                curator: None,
                tracking: tracking_tree(self.rows)?,
            },
            prover: prover(),
            ring_prover: prover(),
        }
        .connect())
    }
}

struct LinkedRow {
    member: [u8; 32],
    next: [u8; 32],
}

struct LinkedRows {
    first: [u8; 32],
    rows: Vec<LinkedRow>,
}

fn linked(mut members: Vec<[u8; 32]>) -> LinkedRows {
    members.sort_unstable();
    let closing = TrackingRecord::SENTINEL.next;
    LinkedRows {
        first: members.first().copied().unwrap_or(closing),
        rows: members
            .iter()
            .enumerate()
            .map(|(position, member)| LinkedRow {
                member: *member,
                next: members.get(position + 1).copied().unwrap_or(closing),
            })
            .collect(),
    }
}

fn address_member(address: &ShieldedAddress) -> Result<[u8; 32]> {
    Ok(address.signing_pubkey.owner_proof_input_hash()?)
}

/// `extra` holds the allowed members no shielded address names.
pub(super) fn own_tree(rows: &[ShieldedAddress], extra: &[[u8; 32]]) -> Result<MemberRegistryTree> {
    let mut members = rows
        .iter()
        .map(address_member)
        .collect::<Result<Vec<_>>>()?;
    members.extend_from_slice(extra);
    let linked = linked(members);
    let records = std::iter::once(MemberRecord {
        next: linked.first,
        ..MemberRecord::SENTINEL
    })
    .chain(linked.rows.iter().map(|row| MemberRecord {
        member: row.member,
        next: row.next,
        lists: zolana_ring_policy::ListSet::single(ListId::Allow).record_bits(),
        mint_policy: Default::default(),
    }))
    .collect();
    Ok(MemberRegistryTree::from_records(records)?)
}

pub(super) fn tracking_tree(rows: &[ShieldedAddress]) -> Result<TrackingTree> {
    let addresses = rows
        .iter()
        .map(|address| Ok((address_member(address)?, address)))
        .collect::<Result<std::collections::HashMap<_, _>>>()?;
    let linked = linked(addresses.keys().copied().collect());
    let records = std::iter::once(TrackingRecord {
        next: linked.first,
        ..TrackingRecord::SENTINEL
    })
    .chain(linked.rows.iter().map(|row| {
        let address = addresses[&row.member];
        TrackingRecord {
            member: row.member,
            next: row.next,
            nullifier_pk: address.nullifier_pubkey,
            ct_hash: [0x05; 32],
            list_tag: [0x06; 32],
        }
    }))
    .collect();
    Ok(TrackingTree::from_records(records)?)
}

pub(super) fn newest_root(hash: [u8; 32]) -> Root {
    Root {
        hash,
        revision: Revision::from(REVISION),
        expires_at: [0; 8],
    }
}

pub(super) fn tree_layout(tree: Address, data: &mut [u8]) -> Result<TreeAccount<'_>> {
    TreeAccount::from_bytes(data, tree.to_bytes()).map_err(|error| anyhow!("tree layout {error:?}"))
}

pub(super) struct AccountEdit<'a> {
    pub(super) env: &'a TestEnv,
    pub(super) address: Address,
}

impl AccountEdit<'_> {
    pub(super) fn apply<T: Pod>(self, edit: impl FnOnce(&mut T)) -> Result<()> {
        let account = self
            .env
            .client
            .rpc()
            .get_account(self.address)?
            .with_context(|| format!("account {}", self.address))?;
        let mut state: T = bytemuck::pod_read_unaligned(&account.data);
        edit(&mut state);
        self.env
            .set_account_data(self.address, bytemuck::bytes_of(&state))
    }
}

/// The applied authorization of each row, a sender reads the viewing key there.
pub(super) struct SeededAuthorizations<'a> {
    pub(super) env: &'a TestEnv,
    pub(super) registry: Address,
    pub(super) rows: &'a [ShieldedAddress],
}

impl SeededAuthorizations<'_> {
    pub(super) fn write(self) -> Result<()> {
        for row in self.rows {
            let owner = Address::new_from_array(row.signing_pubkey.confidential_view_tag()?);
            let authorization = TrackingAuthorization {
                discriminator: TrackingAuthorization::DISCRIMINATOR,
                registry: self.registry,
                owner,
                nullifier_pk: row.nullifier_pubkey,
                list_tag: [0x06; 32],
                viewing_u: row.viewing_pubkey.u(),
                eph_u: [0; 32],
                ciphertext: [0; REGISTER_KEY_CIPHERTEXT_LEN],
                applied: 1,
            };
            self.env.create_account(
                TrackingAuthorization::find_address(&self.registry, &owner).0,
                STORAGE_PROGRAM_ID,
                bytemuck::bytes_of(&authorization),
            )?;
        }
        Ok(())
    }
}

pub(super) struct Seeded {
    pub(super) wallets: Vec<WalletUtxo>,
    pub(super) notes: SeededNotes,
}

pub(super) struct NoteSeed<'a> {
    pub(super) env: &'a TestEnv,
    pub(super) ring: CustomRing,
    pub(super) owner: &'a ShieldedKeypair,
    pub(super) amounts: &'a [u64],
}

impl NoteSeed<'_> {
    /// No transaction backs the notes.
    pub(super) fn write(self) -> Result<Seeded> {
        let env = self.env;
        let rpc = env.client.rpc();
        // Photon discovers a tree from its first indexed transaction.
        DefaultRingDeposit {
            depositor: &env.recipient.keypair,
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount: DISCOVERY_DEPOSIT,
        }
        .send(rpc, env.client.indexer(), &env.assets)?;
        let mut data = tree_data(env)?;
        let mut tree = tree_layout(env.tree, &mut data)?;
        let tree_id = tree.tree_id();
        let utxo_tree = tree.utxo_tree();
        let first_leaf = utxo_tree.next_index();
        let frontier = utxo_tree.subtrees.to_vec();
        let notes = self
            .amounts
            .iter()
            .zip(first_leaf..)
            .map(|(amount, leaf_index)| {
                spr_test_utils::utxo::wallet(
                    Utxo {
                        owner: self.owner.signing_pubkey(),
                        asset: env.assets.mint(&SOL_MINT)?,
                        amount: *amount,
                        blinding: random_blinding(),
                        ring_program_id: Some(self.ring.program_id()),
                        data: Data::default(),
                    },
                    &self.owner.nullifier_key,
                    tree_id,
                    leaf_index,
                    None,
                    None,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let leaves: Vec<[u8; 32]> = notes.iter().map(|note| note.utxo_hash).collect();
        let slot = rpc.get_slot()?;
        utxo_tree
            .append_batch(leaves.iter(), slot)
            .map_err(|error| anyhow!("seed append {error:?}"))?;
        let seeded = SeededNotes {
            leaves,
            first_leaf,
            frontier,
            root: utxo_tree.root(),
            root_index: utxo_tree.current_root_index(),
            slot,
        };
        seeded.check_roots()?;
        env.set_account_data(env.tree, &data)?;
        Ok(Seeded {
            wallets: notes,
            notes: seeded,
        })
    }
}

struct Binding {
    ring_id: [u8; 32],
    auditor: [u8; TAGGED_X25519_KEY_LEN],
    owner: [u8; 32],
    policy_hash: [u8; 32],
    own_root: [u8; 32],
}

impl Binding {
    fn statement(&self, instruction: &Instruction, tracking_root: [u8; 32]) -> Result<[u8; 32]> {
        let (_, body) = instruction
            .data
            .split_first()
            .context("a tagged ring instruction")?;
        let parsed = RingTransactData::parse(body, RingRail::Confidential)?;
        let zero = [[0; 32]; N_PUBLIC_SLOTS];
        let binding = TransferBinding {
            ring_id: &self.ring_id,
            auditor_pubkey: &self.auditor,
            sender: &[0; 32],
            signers: SignerSet::new(
                std::iter::once(&self.owner),
                parsed.audit_stream().key.signer_slots(),
            )?,
            party_identities: &[[0; 32]; ANONYMOUS_PARTIES],
            roots: &TransferRoots {
                policy_hash: self.policy_hash,
                own_root: self.own_root,
                curator_root: [0; 32],
                tracking_root,
            },
            public_assets: &zero,
            public_amounts: &zero,
            public_gross: &zero,
            withdrawal_hash: &policy_withdrawal_hash(&[])?,
        };
        Ok(parsed.transfer_statement(binding)?.hash()?)
    }
}

fn field(value: &[u8; 32]) -> Value {
    Value::String(format!("0x{}", hex::encode(value)))
}

pub(super) fn with_altered_record(
    instruction: &Instruction,
    rail: RingRail,
) -> Result<Instruction> {
    let mut data = frame(instruction, rail)?;
    let output = data.outputs.first_mut().context("a published output")?;
    // A recipient body leads with its record, both change together.
    let mut record = *output.record;
    record[0] ^= 1;
    let body = match output.body {
        SlotBody::Recipient(body) => [&record[..], &body[record.len()..]].concat(),
        SlotBody::Exit(_) => Vec::new(),
    };
    output.record = &record;
    if let SlotBody::Recipient(_) = output.body {
        output.body = SlotBody::Recipient(&body);
    }
    reframed(instruction, &data)
}

pub(super) struct Landed<'a> {
    pub(super) env: &'a TestEnv,
    pub(super) signature: Signature,
}

impl Landed<'_> {
    fn read(&self, encoding: &str) -> Result<Value> {
        Ok(self.env.client.rpc().client().send(
            solana_rpc_client_api::request::RpcRequest::GetTransaction,
            serde_json::json!([self.signature.to_string(), {
                "encoding": encoding,
                "commitment": "confirmed",
                "maxSupportedTransactionVersion": 1,
            }]),
        )?)
    }

    /// The first instruction's tag, every ring operation sends one instruction.
    pub(super) fn tag(&self) -> Result<Option<u8>> {
        let read = self.read("json")?;
        let groups = ConfirmedInstructionGroups::try_from(serde_json::from_value::<
            EncodedConfirmedTransactionWithStatusMeta,
        >(read)?)?;
        Ok(groups
            .groups
            .first()
            .and_then(|group| group.outer.data.first().copied()))
    }

    /// The heap peak needs `CUSTOM_RING_PROGRAM_SO` naming the heap report build.
    pub(super) fn cost(self, label: &str) -> Result<()> {
        let units_limit = compute_unit_limit(
            self.tag()?
                .and_then(|tag| InstructionTag::try_from(tag).ok())
                .context("a tagged ring instruction")?,
        );
        let addresses = self.read("json")?["transaction"]["message"]["accountKeys"]
            .as_array()
            .context("the message's account keys")?
            .len();
        let confirmed = self.read("base64")?;
        let decode = |encoded: &Value| -> Result<Vec<u8>> {
            let encoded = encoded.as_str().context("a base64 field")?;
            Ok(base64::engine::general_purpose::STANDARD.decode(encoded)?)
        };
        let bytes = decode(&confirmed["transaction"][0])?.len();
        let units = confirmed["meta"]["computeUnitsConsumed"]
            .as_u64()
            .context("the transaction's compute units")?;
        // Surfpool reports empty return data when no program sets one.
        let returned = match confirmed["meta"]["returnData"]["data"][0].is_string() {
            true => decode(&confirmed["meta"]["returnData"]["data"][0])?,
            false => Vec::new(),
        };
        let heap = match returned.is_empty() {
            true => None,
            false => {
                Some(u64::from_le_bytes(returned.try_into().map_err(|_| {
                    anyhow!("{label} returned no eight byte heap peak")
                })?))
            }
        };
        ensure!(bytes <= MAX_TRANSACTION_SIZE, "{label} has {bytes} bytes");
        ensure!(
            addresses <= usize::from(MAX_ADDRESSES),
            "{label} has {addresses} addresses"
        );
        ensure!(
            units <= u64::from(units_limit),
            "{label} took {units} units over {units_limit}"
        );
        if let Some(peak) = heap {
            ensure!(peak <= HEAP_LIMIT, "{label} peaked at {peak} heap bytes");
        }
        println!(
            "{label}: {bytes} bytes of {MAX_TRANSACTION_SIZE}, {addresses} addresses of {MAX_ADDRESSES}, {units} units of {units_limit}, heap {heap:?} of {HEAP_LIMIT}"
        );
        Ok(())
    }
}

pub(super) struct FrameReport<'a> {
    /// The tag and the frame, as the inline instruction carries them.
    pub(super) frame: &'a [u8],
    pub(super) rail: RingRail,
    pub(super) policy: &'a RingPolicy,
}

impl FrameReport<'_> {
    pub(super) fn check(self, label: &str) -> Result<()> {
        let (_, body) = self.frame.split_first().context("a tagged frame")?;
        let parsed = RingTransactData::parse(body, self.rail)?;
        let cpi = parsed.data().spp_instruction_data(self.policy)?.len();
        let frame = self.frame.len();
        ensure!(cpi <= MAX_CPI_DATA_LEN, "{label} SPP CPI takes {cpi} bytes");
        println!("{label}: frame {frame} bytes, SPP CPI data {cpi} bytes of {MAX_CPI_DATA_LEN}");
        Ok(())
    }
}

pub(super) fn nullifier_accounts(
    env: &TestEnv,
    nullifiers: &[[u8; 32]],
) -> Result<Vec<Option<solana_account::Account>>> {
    nullifiers
        .iter()
        .map(|nullifier| {
            let address = spr_interface::pda::nullifier_pda(&env.tree, nullifier).0;
            Ok(env.client.rpc().get_account(address)?)
        })
        .collect()
}

pub(super) struct SettledState<'a> {
    pub(super) env: &'a TestEnv,
    pub(super) before: &'a solana_account::Account,
    pub(super) commitments: Vec<[u8; 32]>,
    pub(super) nullifiers: &'a [[u8; 32]],
}

impl SettledState<'_> {
    pub(super) fn check(self) -> Result<()> {
        let env = self.env;
        let mut expected = self.before.data.clone();
        let mut expected_tree = tree_layout(env.tree, &mut expected)?;
        let queue_before = expected_tree.nullifier_tree().queue_next_index;
        let expected_utxos = expected_tree.utxo_tree();
        expected_utxos
            .append_batch(self.commitments.iter(), u64::MAX)
            .map_err(|error| anyhow!("expected append {error:?}"))?;
        let mut settled = tree_data(env)?;
        let mut settled_tree = tree_layout(env.tree, &mut settled)?;
        let settled_utxos = settled_tree.utxo_tree();
        assert_eq!(settled_utxos.next_index(), expected_utxos.next_index());
        assert_eq!(settled_utxos.root(), expected_utxos.root());
        assert_eq!(
            nullifier_queue_index(env)?,
            queue_before + self.nullifiers.len() as u64
        );
        ensure!(
            nullifier_accounts(env, self.nullifiers)?
                .iter()
                .all(Option::is_some),
            "a settled nullifier has no PDA"
        );
        Ok(())
    }
}

struct Replay<'a> {
    chain: &'a Zolana<SolanaRpc, SeededIndexer>,
    key: &'a ExpectedProvingKey,
}

impl Replay<'_> {
    fn prove(&self, body: Value) -> Result<Proof, ClientError> {
        let request = ReplayedBody {
            body,
            key: self.key.clone(),
        };
        self.chain
            .block_on(self.chain.ring_client().prove_request(&request))
    }

    /// Only a `proving_error` counts as refused.
    fn refuses(&self, label: &str, body: Value) -> Result<()> {
        let refused = self
            .prove(body)
            .err()
            .with_context(|| format!("{label} proved"))?;
        let solving = match &refused {
            ClientError::ProverRejected { code, .. } => code == "proving_error",
            ClientError::ProverServer(text) => text.contains("proving_error"),
            _ => false,
        };
        ensure!(solving, "{label} stopped short of the solve, {refused}");
        println!("{label}: refused by the prover, {refused}");
        Ok(())
    }
}

struct Payment<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    notes: &'a [WalletUtxo],
    recipient: ShieldedAddress,
}

impl Payment<'_> {
    fn prove(
        self,
        chain: &Zolana<SolanaRpc, SeededIndexer>,
    ) -> Result<Result<ProvenRingTransfer, RingError>> {
        let mut transaction = ConfidentialTransaction::new_with_ring(
            self.notes.to_vec(),
            self.sender.pubkey(),
            self.ring.program_id(),
        )?;
        transaction.transfer_sol(&self.recipient, RING_TRANSFER_AMOUNT)?;
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction,
        });
        Ok(chain.block_on(transfer.prove(chain.ring_client())))
    }
}

#[test]
fn one_key_settles_a_real_transfer_and_refuses_three_forgeries() -> Result<()> {
    let mut env = setup()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    let auditor = X25519Keypair::new();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&RELEASED),
    }
    .send(&env.client)?;

    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let recipient_address = recipient.shielded_address()?;
    let wrong_address = ShieldedAddress {
        nullifier_pubkey: NullifierKey::from_secret([0x42; 31]).pubkey()?,
        ..recipient_address
    };
    let honest_rows = [sender.shielded_address()?, recipient_address];
    let wrong_rows = [sender.shielded_address()?, wrong_address];
    let policy = policy_registry(ring, &env)?;
    let honest_root = tracking_tree(&honest_rows)?.root()?;
    let wrong_root = tracking_tree(&wrong_rows)?.root()?;
    let own_root = own_tree(&honest_rows, &[])?.root()?;
    AccountEdit {
        env: &env,
        address: policy.records,
    }
    .apply(|registry: &mut StorageRegistry| registry.roots[0] = newest_root(own_root))?;
    let write_tracking = |root: [u8; 32]| {
        AccountEdit {
            env: &env,
            address: policy.tracking,
        }
        .apply(|registry: &mut TrackingRegistry| registry.roots[0] = newest_root(root))
    };
    write_tracking(honest_root)?;
    SeededAuthorizations {
        env: &env,
        registry: policy.tracking,
        rows: &honest_rows,
    }
    .write()?;
    let Seeded {
        wallets: notes,
        notes: seeded,
    } = NoteSeed {
        env: &env,
        ring,
        owner: sender,
        amounts: &[RING_DEPOSIT_A, RING_DEPOSIT_B],
    }
    .write()?;
    println!("seeded: own and tracking roots, two ring notes");

    let body = RingBody::default();
    let chain = SeededChain {
        env: &env,
        notes: seeded.clone(),
        rows: &honest_rows,
        body: &body,
    }
    .connect()?;
    let wrong_chain = SeededChain {
        env: &env,
        notes: seeded,
        rows: &wrong_rows,
        body: &body,
    }
    .connect()?;
    let name = RING_KEYS
        .iter()
        .find(|key| key.circuit == KEY)
        .context("the key is catalogued")?;
    let file = name.file_name();
    let key = ExpectedProvingKey {
        sha256: PROVING_KEY_SHA256S
            .iter()
            .find(|(pinned, _)| *pinned == file)
            .map(|(_, sha256)| *sha256)
            .context("the run's verifying key pins the proving key")?,
        name: file,
    };
    let replay = Replay {
        chain: &chain,
        key: &key,
    };
    let binding = Binding {
        ring_id: ring.ring_id()?,
        auditor: policy.auditor_pubkey,
        owner: sender.pubkey().to_bytes(),
        policy_hash: policy.policy_hash,
        own_root,
    };
    let payment = |recipient: ShieldedAddress| Payment {
        ring,
        sender,
        notes: &notes,
        recipient,
    };

    let proven = payment(recipient_address).prove(&chain)??;
    let honest_body = body.take()?;
    ensure!(
        honest_body["circuitType"] == name.name,
        "another key proved the transfer"
    );
    let instruction = proven.instruction()?;
    let statement = binding.statement(&instruction, honest_root)?;
    ensure!(
        honest_body["publicInputHash"] == field(&statement),
        "the request's statement differs from the one the program rebuilds"
    );
    let verifying = verifying_key(KEY).context("the run's verifying key")?;
    let data = frame(&instruction, RingRail::Confidential)?;
    RingProof {
        proof: data.proof,
        statement,
        key: verifying,
    }
    .verify()?;
    let mut other_statement = statement;
    other_statement[31] ^= 1;
    assert_eq!(
        RingProof {
            proof: data.proof,
            statement: other_statement,
            key: verifying,
        }
        .verify(),
        Err(CustomRingError::ProofVerificationFailed.into()),
    );
    replay.prove(honest_body.clone())?;
    println!("proven: {} verified off chain and replayed", name.name);

    let rpc = env.client.rpc();
    let tree_before = fetch_account(rpc, &env.tree)?;

    let altered = with_altered_record(&instruction, RingRail::Confidential)?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(0)
        .assert_client(&send_expecting_rejection(rpc, sender, altered.clone())?);
    assert_account_unchanged(rpc, &env.tree, &tree_before)?;
    println!("altered statement: refused at the ring pairing, ProofVerificationFailed");

    let mut wrong_record = honest_body.clone();
    wrong_record["publicInputHash"] = field(&binding.statement(&altered, honest_root)?);
    replay.refuses("wrong auditor record", wrong_record)?;

    write_tracking(wrong_root)?;
    let forged = payment(wrong_address).prove(&wrong_chain)??;
    let wrong_body = body.take()?;
    write_tracking(honest_root)?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(0)
        .assert_client(&send_expecting_rejection(
            rpc,
            sender,
            forged.instruction()?,
        )?);
    assert_account_unchanged(rpc, &env.tree, &tree_before)?;
    println!("wrong tracking key: real proof refused at the ring pairing, ProofVerificationFailed");
    let mut crossed = honest_body.clone();
    for section in TRACKING_SECTION {
        crossed[section] = wrong_body[section].clone();
    }
    crossed["publicInputHash"] = field(&binding.statement(&instruction, wrong_root)?);
    replay.refuses("wrong tracking key", crossed)?;

    let signature = land(&env, instruction.clone(), sender, &[])?;
    Landed {
        env: &env,
        signature,
    }
    .cost("settlement")?;
    FrameReport {
        frame: &instruction.data,
        rail: RingRail::Confidential,
        policy: &policy,
    }
    .check("2 output inline")?;
    assert_eq!(
        data.nullifiers,
        [notes[0].nullifier, notes[1].nullifier].as_slice()
    );
    SettledState {
        env: &env,
        before: &tree_before,
        commitments: data.outputs.iter().map(|output| *output.hash).collect(),
        nullifiers: data.nullifiers,
    }
    .check()?;
    println!("settled: {signature}, commitments and nullifiers match the frame");

    let auditor_tag = auditor_view_tag(&auditor.pubkey());
    let indexed = wait_for_indexed_transaction(env.client.indexer(), auditor_tag, signature);
    let audited = AuditLookup {
        scan: RingScan::new(ring.program_id(), auditor.pubkey()),
        auditor: &auditor,
        signature,
    }
    .run(&env)?;
    let note = |owner, amount, slot| {
        Note {
            owner,
            asset: SOL_MINT,
            amount,
            blinding: output_blinding(&proven.outputs, slot)?,
            ring_program_id: Some(ring.program_id()),
        }
        .opened(slot)
    };
    assert_eq!(
        opened(&audited),
        vec![
            note(recipient, RING_TRANSFER_AMOUNT, RECIPIENT_SLOT)?,
            note(sender, RING_CHANGE, CHANGE_SLOT)?,
        ]
    );
    println!("auditor: reconstructed both outputs");
    let blinding = output_blinding(&proven.outputs, RECIPIENT_SLOT)?;
    let assets = env.ring_assets()?;
    WalletSync {
        wallet: &mut env.recipient.wallet,
        keys: &env.recipient.keypair,
        assets: &assets,
        transactions: std::slice::from_ref(&indexed),
    }
    .sync()?;
    let received = unspent_utxo(&env.recipient.wallet, RING_TRANSFER_AMOUNT)?;
    assert_eq!(received.blinding, blinding);
    println!("recipient: reconstructed the note");
    Ok(())
}
