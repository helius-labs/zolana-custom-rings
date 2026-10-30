use std::{
    collections::HashMap,
    fmt::Display,
    future::Future,
    ops::Range,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use custom_ring_interface::{
    check_member, mint_policy_write,
    storage::{chain_start, Revision, StorageRegistry},
    storage_instruction::StorageWriteData,
    tagged_x25519, CustomRingError, QueueEntry, RecordWriteData, WriteRecordsIxData, APPLY_BATCH,
    QUAD_ARITY, STORAGE_PROGRAM_ID,
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DatabaseTransaction};
use solana_address::Address;
use solana_clock::DEFAULT_MS_PER_SLOT;
use solana_transaction_status_client_types::TransactionDetails;
use spr_indexer_api::{Base64String, Context as ApiContext, Hash, SerializablePubkey};
use tokio::sync::Mutex as AsyncMutex;
use zolana_ring_indexer::{
    rpc::{
        GetStorageApplyProofInputsRequest, GetStorageApplyProofInputsResponse,
        GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse,
        GetStorageMemberRecordsRequest, GetStorageMemberRecordsResponse,
        GetStorageRecordPoolRequest, GetStorageRecordPoolResponse, RingIndexedMemberRecordView,
        RingMemberOpening, RingMemberRecordView, RingRecordPathView, RingRecordWriteView,
        StorageRootView, StorageWriteView, MAX_RING_MEMBER_PAGE_LIMIT,
    },
    tree::{Canopy, MemberRecord, OpeningCheck, RecordOpening, RecordTree, RecordWriteProofInput},
};

use crate::{
    block::BlockMetadata,
    error::RingApiError,
    member_registry::{LoadedRegistry, RecordRead, TreeRead},
    rpc::SolanaRpc,
    storage::{
        self, RegistryStore, RingCursor, StorageRoot, StorageState, StorageStore, StoredRecord,
        TreeVersion,
    },
};

/// The longest a stalled tip misses a chain move.
pub(crate) const CONFIRMATION_AGE: Duration = Duration::from_millis(DEFAULT_MS_PER_SLOT);

pub(crate) trait ChainSource {
    /// Fails unless `tip` is canonical and the registry account is no older.
    fn storage_confirmation(
        &self,
        tip: &BlockMetadata,
        registry: &[u8; 32],
    ) -> impl Future<Output = Result<Confirmation<StorageRegistry>, RingApiError>> + Send;
}

pub(crate) struct Confirmation<T> {
    context: ApiContext,
    chain: Arc<T>,
}

/// Concurrent requests at one tip wait for a single read per account.
pub(crate) struct CachedChain {
    rpc: Arc<SolanaRpc>,
    storage: ReadCache<StorageRegistry>,
}

struct ReadCache<T> {
    reads: Mutex<HashMap<[u8; 32], Arc<CacheEntry<T>>>>,
}

type CacheEntry<T> = AsyncMutex<Option<Cached<T>>>;

struct Cached<T> {
    tip: BlockMetadata,
    read_at: Instant,
    confirmation: Result<Confirmation<T>, RingApiError>,
}

impl<T> Clone for Confirmation<T> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            chain: Arc::clone(&self.chain),
        }
    }
}

impl CachedChain {
    pub fn new(rpc: Arc<SolanaRpc>) -> Self {
        Self {
            rpc,
            storage: ReadCache::default(),
        }
    }
}

impl<T> Default for ReadCache<T> {
    fn default() -> Self {
        Self {
            reads: Mutex::default(),
        }
    }
}

impl<T> ReadCache<T> {
    async fn read(
        &self,
        key: [u8; 32],
        tip: &BlockMetadata,
        fetch: impl Future<Output = Result<Confirmation<T>, RingApiError>>,
    ) -> Result<Confirmation<T>, RingApiError> {
        let entry = {
            let mut reads = self.reads.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(reads.entry(key).or_default())
        };
        let mut cached = entry.lock().await;
        let fresh = |hit: &&Cached<T>| hit.tip == *tip && hit.read_at.elapsed() < CONFIRMATION_AGE;
        if let Some(hit) = cached.as_ref().filter(fresh) {
            return hit.confirmation.clone();
        }
        let read_at = Instant::now();
        let confirmation = fetch.await;
        *cached = Some(Cached {
            tip: tip.clone(),
            read_at,
            confirmation: confirmation.clone(),
        });
        confirmation
    }
}

impl ChainSource for CachedChain {
    async fn storage_confirmation(
        &self,
        tip: &BlockMetadata,
        registry: &[u8; 32],
    ) -> Result<Confirmation<StorageRegistry>, RingApiError> {
        let fetch = self.rpc.storage_confirmation(tip, registry);
        self.storage.read(*registry, tip, fetch).await
    }
}

impl ChainSource for SolanaRpc {
    async fn storage_confirmation(
        &self,
        tip: &BlockMetadata,
        registry: &[u8; 32],
    ) -> Result<Confirmation<StorageRegistry>, RingApiError> {
        let context = canonical_context(self, tip).await.map_err(out_of_sync)?;
        let read = self
            .get_multiple_accounts_from_slot(&[Address::new_from_array(*registry)], tip.slot)
            .await
            .map_err(out_of_sync)?;
        let chain = read
            .into_iter()
            .flatten()
            .find(|account| account.owner == STORAGE_PROGRAM_ID)
            .and_then(|account| StorageRegistry::from_data(&account.data).copied())
            .ok_or_else(|| out_of_sync("storage registry is not an initialized account"))?;
        Ok(Confirmation {
            context,
            chain: Arc::new(chain),
        })
    }
}

pub(crate) async fn storage_member_openings(
    db: &DatabaseConnection,
    chain: &impl ChainSource,
    request: GetStorageMemberOpeningsRequest,
) -> Result<GetStorageMemberOpeningsResponse, RingApiError> {
    check_members(&request.members)?;
    let read = Snapshot::storage(db, &request.registry)
        .await?
        .at_root(&request.expected_root.0)
        .await?;
    let openings = read
        .load(&request.members, None)
        .await?
        .openings(&read.root.root, &request.members)?;
    let root = read.root;
    let context = read
        .snapshot
        .confirm(chain, StorageServed::Root(&root))
        .await?;
    Ok(GetStorageMemberOpeningsResponse {
        context,
        root: storage_root_view(&root),
        openings,
    })
}

/// Contiguous, authenticated leaves under a root the registry history holds.
pub(crate) async fn storage_member_records(
    db: &DatabaseConnection,
    chain: &impl ChainSource,
    request: GetStorageMemberRecordsRequest,
) -> Result<GetStorageMemberRecordsResponse, RingApiError> {
    if request.limit == 0 || request.limit > MAX_RING_MEMBER_PAGE_LIMIT {
        return Err(validation("invalid storage page limit"));
    }
    let read = Snapshot::storage(db, &request.registry)
        .await?
        .at_root(&request.expected_root.0)
        .await?;
    let root = read.root;
    if request.start_index == 0 || request.start_index > root.next_index {
        return Err(validation("invalid storage page start"));
    }
    let end = request
        .start_index
        .saturating_add(request.limit)
        .min(root.next_index);
    let records = LeafPage {
        store: read.snapshot.store().tree(),
        root: &root.root,
        at: root.tree(),
        leaves: request.start_index..end,
    }
    .read()
    .await?;
    let context = read
        .snapshot
        .confirm(chain, StorageServed::Root(&root))
        .await?;
    Ok(GetStorageMemberRecordsResponse {
        context,
        root: storage_root_view(&root),
        records,
        next_leaf_index: (end < root.next_index).then_some(end),
    })
}

pub(crate) async fn storage_record_pool(
    db: &DatabaseConnection,
    chain: &impl ChainSource,
    request: GetStorageRecordPoolRequest,
) -> Result<GetStorageRecordPoolResponse, RingApiError> {
    check_members(&request.members)?;
    let members = request.members.len() as u64;
    if request.openings < members || request.openings > MAX_RING_MEMBER_PAGE_LIMIT {
        return Err(validation("invalid record pool openings"));
    }
    let canopy = Canopy::covering(request.openings as usize).map_err(validation)?;
    let read = Snapshot::storage(db, &request.registry)
        .await?
        .at_root(&request.expected_root.0)
        .await?;
    let pool = read.load(&request.members, Some(canopy)).await?.pool(
        &read.root.root,
        &request.members,
        canopy,
    )?;
    let root = read.root;
    let context = read
        .snapshot
        .confirm(chain, StorageServed::Root(&root))
        .await?;
    Ok(GetStorageRecordPoolResponse {
        context,
        root: storage_root_view(&root),
        records: pool.records,
        canopy: pool.canopy,
        subjects: pool.subjects,
    })
}

/// The writes apply from the current root, as the next `Update` names it.
pub(crate) async fn storage_apply_proof_inputs(
    db: &DatabaseConnection,
    chain: &impl ChainSource,
    request: GetStorageApplyProofInputsRequest,
) -> Result<GetStorageApplyProofInputsResponse, RingApiError> {
    if !(1..=APPLY_BATCH).contains(&request.writes.len()) {
        return Err(validation("invalid storage write count"));
    }
    let entries = request
        .writes
        .iter()
        .map(storage_entry)
        .collect::<Result<Vec<_>, _>>()
        .map_err(validation)?;
    let snapshot = Snapshot::storage(db, &request.registry).await?;
    let root = StorageRoot::current(&snapshot.state.account);
    let chain_start = chain_start(&request.registry.0, root.revision.into()).map_err(internal)?;
    let loaded = TreeRead::batch(root.tree(), &entries)
        .load(snapshot.store().tree())
        .await
        .map_err(internal)?;
    let inputs = loaded
        .tree
        .apply_batch(chain_start, &entries)
        .map_err(internal)?
        .inputs;
    if inputs.old_root != root.root {
        return Err(internal("the loaded tree does not reach the current root"));
    }
    let context = snapshot
        .confirm(chain, StorageServed::Current(&root))
        .await?;
    Ok(GetStorageApplyProofInputsResponse {
        context,
        revision: root.revision,
        old_root: Hash(inputs.old_root),
        new_root: Hash(inputs.new_root),
        old_next_index: inputs.old_next_index,
        new_next_index: inputs.new_next_index,
        chain_start: Hash(inputs.chain_start),
        chain_end: Hash(inputs.chain_end),
        writes: inputs.writes.iter().map(write_view).collect(),
    })
}

fn check_members(members: &[Hash]) -> Result<(), RingApiError> {
    let count = members.len() as u64;
    if count == 0 || count > MAX_RING_MEMBER_PAGE_LIMIT {
        return Err(validation("invalid member count"));
    }
    members
        .iter()
        .try_for_each(|member| check_member(&member.0).map_err(validation))
}

/// One read in a repeatable read transaction at the projection's tip.
struct Snapshot<S> {
    tx: DatabaseTransaction,
    state: S,
    tip: Option<BlockMetadata>,
}

struct Released<S> {
    tip: BlockMetadata,
    state: S,
}

struct StorageRootRead {
    snapshot: Snapshot<StorageState>,
    root: StorageRoot,
}

struct PoolView {
    records: Vec<RingIndexedMemberRecordView>,
    canopy: Vec<Hash>,
    subjects: Vec<u32>,
}

impl Snapshot<()> {
    /// Fails before any RPC while the projection catches up or recovers.
    async fn begin(db: &DatabaseConnection) -> Result<Self, RingApiError> {
        let tx = storage::begin_read(db).await?;
        let cursor = storage::cursor(&tx)
            .await
            .map_err(internal)?
            .filter(RingCursor::is_ready)
            .ok_or_else(|| out_of_sync("indexer is catching up or recovering"))?;
        Ok(Self {
            tx,
            state: (),
            tip: cursor.tip,
        })
    }
}

impl<S> Snapshot<S> {
    /// Commits the read before the RPC calls.
    async fn release(self) -> Result<Released<S>, RingApiError> {
        self.tx.commit().await?;
        let tip = self
            .tip
            .ok_or_else(|| out_of_sync("cursor has no canonical block"))?;
        Ok(Released {
            tip,
            state: self.state,
        })
    }
}

/// `leaves` lie below the tree's next index at `at`.
struct LeafPage<'a, C> {
    store: &'a RegistryStore<'a, C>,
    root: &'a [u8; 32],
    at: TreeVersion,
    leaves: Range<u64>,
}

impl<C: ConnectionTrait> LeafPage<'_, C> {
    async fn read(self) -> Result<Vec<RingIndexedMemberRecordView>, RingApiError> {
        let rows = self
            .store
            .records_by_index(self.leaves.clone(), self.at.version)
            .await
            .map_err(internal)?;
        if !rows.iter().map(|row| row.record.index).eq(self.leaves) {
            return Err(RingApiError::PageGap);
        }
        let members = rows
            .iter()
            .map(|row| row.record.record.member)
            .collect::<Vec<_>>();
        let read = TreeRead {
            at: self.at,
            records: RecordRead::Leaves(rows),
            inserts: 0,
            canopy: None,
        };
        let loaded = read.load(self.store).await.map_err(internal)?;
        members
            .iter()
            .map(|member| {
                let opening = loaded.opening(self.root, member)?;
                Ok(RingIndexedMemberRecordView {
                    record: opening.record,
                    path: opening.path,
                })
            })
            .collect()
    }
}

impl Snapshot<StorageState> {
    /// Fails before any RPC while the projection catches up or holds the registry quarantined.
    async fn storage(
        db: &DatabaseConnection,
        registry: &SerializablePubkey,
    ) -> Result<Self, RingApiError> {
        let Snapshot { tx, tip, .. } = Snapshot::begin(db).await?;
        let state = StorageStore::new(&tx, registry.0.to_bytes())
            .state()
            .await
            .map_err(internal)?
            .ok_or_else(|| out_of_sync("initialization has not been indexed"))?;
        if let Some(fault) = &state.fault {
            return Err(out_of_sync(format!(
                "storage registry quarantined, {fault}"
            )));
        }
        Ok(Self { tx, state, tip })
    }

    fn store(&self) -> StorageStore<'_, DatabaseTransaction> {
        StorageStore::new(&self.tx, self.state.registry)
    }

    /// The newest revision the registry verifies `root` under at the tip.
    async fn at_root(self, root: &[u8; 32]) -> Result<StorageRootRead, RingApiError> {
        let slot = self.tip.as_ref().map_or(0, |tip| tip.slot);
        let account = &self.state.account;
        let revision = account
            .roots
            .iter()
            .map(|held| held.revision)
            .filter(|revision| account.root(*revision, slot) == Ok(*root))
            .max_by_key(|revision| revision.value())
            .ok_or(RingApiError::RootChanged)?;
        let root = self
            .store()
            .root(revision.value())
            .await
            .map_err(internal)?
            .filter(|stored| stored.root == *root)
            .ok_or_else(|| internal("a history root is missing from the projection"))?;
        Ok(StorageRootRead {
            snapshot: self,
            root,
        })
    }

    async fn confirm(
        self,
        chain: &impl ChainSource,
        served: StorageServed<'_>,
    ) -> Result<ApiContext, RingApiError> {
        let Released { tip, state } = self.release().await?;
        let confirmation = chain.storage_confirmation(&tip, &state.registry).await?;
        if !served.agrees(&confirmation.chain, tip.slot) {
            return Err(RingApiError::RootChanged);
        }
        Ok(confirmation.context)
    }
}

impl StorageRootRead {
    async fn load(
        &self,
        members: &[Hash],
        canopy: Option<Canopy>,
    ) -> Result<LoadedRegistry, RingApiError> {
        let read = TreeRead {
            at: self.root.tree(),
            records: RecordRead::Members(members.iter().map(|member| member.0).collect()),
            inserts: 0,
            canopy,
        };
        read.load(self.snapshot.store().tree())
            .await
            .map_err(internal)
    }
}

enum StorageServed<'r> {
    Root(&'r StorageRoot),
    /// Apply proof inputs hold while the current root stays.
    Current(&'r StorageRoot),
}

impl StorageServed<'_> {
    fn agrees(&self, chain: &StorageRegistry, slot: u64) -> bool {
        match self {
            Self::Root(root) => chain.root(Revision::from(root.revision), slot) == Ok(root.root),
            Self::Current(root) => StorageRoot::current(chain) == **root,
        }
    }
}

impl LoadedRegistry {
    fn openings(
        &self,
        root: &[u8; 32],
        members: &[Hash],
    ) -> Result<Vec<RingMemberOpening>, RingApiError> {
        members
            .iter()
            .map(|member| self.opening(root, &member.0))
            .collect()
    }

    fn pool(
        &self,
        root: &[u8; 32],
        members: &[Hash],
        canopy: Canopy,
    ) -> Result<PoolView, RingApiError> {
        let members: Vec<[u8; 32]> = members.iter().map(|member| member.0).collect();
        let pool = self.tree.record_pool(&members, canopy).map_err(internal)?;
        pool.verify(root)
            .map_err(|error| internal(format!("member registry pool disagrees ({error})")))?;
        let records = pool
            .records
            .iter()
            .zip(&pool.proof.paths)
            .map(|(record, path)| {
                let stored = self
                    .stored
                    .get(&record.member)
                    .ok_or_else(|| internal("pooled record was not loaded"))?;
                Ok(RingIndexedMemberRecordView {
                    record: record_view(stored),
                    path: path_view(path.index, &path.siblings),
                })
            })
            .collect::<Result<Vec<_>, RingApiError>>()?;
        Ok(PoolView {
            records,
            canopy: pool.proof.canopy.into_iter().map(Hash).collect(),
            subjects: pool
                .subjects
                .iter()
                .map(|subject| subject.record_index)
                .collect(),
        })
    }

    fn opening(
        &self,
        root: &[u8; 32],
        member: &[u8; 32],
    ) -> Result<RingMemberOpening, RingApiError> {
        let opening = self.tree.opening(member).map_err(internal)?;
        OpeningCheck {
            opening: &opening,
            root,
            member,
        }
        .verify()
        .map_err(|error| internal(format!("member registry opening disagrees ({error})")))?;
        let (present, record, path) = match opening {
            RecordOpening::Present { record, path } => (true, record, path),
            RecordOpening::Absent { low, path } => (false, low, path),
        };
        let stored = self
            .stored
            .get(&record.member)
            .ok_or_else(|| internal("opened record was not loaded"))?;
        Ok(RingMemberOpening {
            present,
            record: record_view(stored),
            path: path_view(path.index, &path.siblings),
        })
    }
}

fn record_view(stored: &StoredRecord) -> RingMemberRecordView {
    let seal = stored.seal;
    RingMemberRecordView {
        owner_pubkey: seal.map(|seal| Address::new_from_array(seal.owner_pubkey).into()),
        nullifier_pk: seal.map(|seal| Hash(seal.nullifier_pk)),
        eph_pk: seal.map(|seal| Base64String(tagged_x25519(&seal.eph_u).to_vec())),
        ciphertext: seal.map(|seal| Base64String(seal.ciphertext.to_vec())),
        ..member_view(&stored.record.record)
    }
}

fn member_view(record: &MemberRecord) -> RingMemberRecordView {
    RingMemberRecordView {
        member: Hash(record.member),
        next: Hash(record.next),
        lists: record.lists,
        escrow_key: Hash(record.escrow_key),
        mint_policy: record.mint_policy,
        owner_pubkey: None,
        nullifier_pk: None,
        eph_pk: None,
        ciphertext: None,
    }
}

fn write_view(write: &RecordWriteProofInput) -> RingRecordWriteView {
    RingRecordWriteView {
        member: Hash(write.entry.member),
        mask: write.entry.mask,
        value: write.entry.value,
        escrow_key: Hash(write.entry.escrow_key),
        mint_policy: write.entry.mint_policy,
        exists: write.exists,
        old_next: Hash(write.old_next),
        old_lists: write.old_lists,
        old_escrow: Hash(write.old_escrow),
        old_mint_policy: write.old_mint_policy,
        slot: path_view(write.slot.index, &write.slot.siblings),
        low: member_view(&write.low),
        low_path: path_view(write.low_path.index, &write.low_path.siblings),
    }
}

fn path_view(index: u64, siblings: &[[[u8; 32]; QUAD_ARITY - 1]]) -> RingRecordPathView {
    RingRecordPathView {
        index,
        siblings: siblings.iter().map(|level| level.map(Hash)).collect(),
    }
}

fn storage_root_view(root: &StorageRoot) -> StorageRootView {
    StorageRootView {
        root: Hash(root.root),
        revision: root.revision,
        next_index: root.next_index,
    }
}

/// An escrow write names its leaf by the key hash, never by its envelope.
fn storage_entry(write: &StorageWriteView) -> Result<QueueEntry, CustomRingError> {
    if write.escrow_key.0 == [0; 32] {
        return StorageWriteData::Record(RecordWriteData {
            member: write.member.0,
            lists: WriteRecordsIxData {
                mask: write.mask.to_le_bytes(),
                value: write.value.to_le_bytes(),
            },
            mint_policy: mint_policy_write(write.mint_policy),
        })
        .entry();
    }
    let entry = QueueEntry::escrow_hash(write.member.0, write.escrow_key.0)?;
    if (write.mask, write.value, write.mint_policy) != (entry.mask, entry.value, None) {
        return Err(CustomRingError::InvalidInstructionData);
    }
    Ok(entry)
}

async fn canonical_context(rpc: &SolanaRpc, tip: &BlockMetadata) -> anyhow::Result<ApiContext> {
    let block = rpc.get_block(tip.slot, TransactionDetails::None).await?;
    anyhow::ensure!(
        block.blockhash == tip.blockhash.to_string(),
        "cursor is on an orphaned block"
    );
    Ok(ApiContext {
        slot: tip.slot,
        block_time: tip.block_time,
    })
}

fn out_of_sync(reason: impl Display) -> RingApiError {
    RingApiError::OutOfSync(reason.to_string())
}

fn validation(reason: impl Display) -> RingApiError {
    RingApiError::InvalidRequest(reason.to_string())
}

fn internal(error: impl Display) -> RingApiError {
    RingApiError::Internal(format!("{error:#}"))
}
