use std::{
    collections::HashMap,
    fmt::Display,
    future::Future,
    ops::Range,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use custom_ring_interface::{
    check_member,
    key_catalog::{RecordPools, RING_KEYS},
    mint_policy_write,
    storage::{chain_start, Revision, StorageRegistry},
    tracking::TrackingRegistry,
    CustomRingError, RecordWrite, RecordWriteData, WriteRecordsIxData, APPLY_BATCH, QUAD_ARITY,
    QUAD_HEIGHT, STORAGE_PROGRAM_ID,
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DatabaseTransaction};
use solana_address::Address;
use solana_clock::DEFAULT_MS_PER_SLOT;
use solana_transaction_status_client_types::TransactionDetails;
use spr_indexer_api::{Context as ApiContext, Hash, SerializablePubkey};
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
    tree::{
        Canopy, IndexedLeaf, MemberRecord, OpeningCheck, RecordOpening, RecordPoolOf, RecordTree,
        RecordWriteProofInput,
    },
};

use crate::{
    block::BlockMetadata,
    error::RingApiError,
    member_registry::{LoadedRegistry, RecordRead, TreeRead},
    rpc::SolanaRpc,
    storage::{
        self, ProjectedAccount, ProjectedStore, RegistryState, RegistryStore, RingCursor,
        StorageRoot, StorageState, StoredLeaf, TreeVersion,
    },
};

mod tracking;

pub(crate) use tracking::{
    pending_enrollments, tracking_apply_proof_inputs, tracking_openings, tracking_record_pool,
    tracking_records,
};

/// The longest a stalled tip misses a chain move.
pub(crate) const CONFIRMATION_AGE: Duration = Duration::from_millis(DEFAULT_MS_PER_SLOT);

pub(crate) trait ChainSource {
    /// Fails unless `tip` is canonical and the registry account is no older.
    fn confirmation<A: CachedAccount>(
        &self,
        tip: &BlockMetadata,
        registry: &[u8; 32],
    ) -> impl Future<Output = Result<Confirmation<A>, RingApiError>> + Send;
}

pub(crate) trait CachedAccount: ProjectedAccount + 'static {
    fn cache(chain: &CachedChain) -> &ReadCache<Self>;
}

impl CachedAccount for StorageRegistry {
    fn cache(chain: &CachedChain) -> &ReadCache<Self> {
        &chain.storage
    }
}

impl CachedAccount for TrackingRegistry {
    fn cache(chain: &CachedChain) -> &ReadCache<Self> {
        &chain.tracking
    }
}

pub(crate) struct Confirmation<T> {
    context: ApiContext,
    chain: Arc<T>,
}

/// Concurrent requests at one tip wait for a single read per account.
pub(crate) struct CachedChain {
    rpc: Arc<SolanaRpc>,
    storage: ReadCache<StorageRegistry>,
    tracking: ReadCache<TrackingRegistry>,
}

pub(crate) struct ReadCache<T> {
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
            context: self.context,
            chain: Arc::clone(&self.chain),
        }
    }
}

impl CachedChain {
    pub fn new(rpc: Arc<SolanaRpc>) -> Self {
        Self {
            rpc,
            storage: ReadCache::default(),
            tracking: ReadCache::default(),
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
    async fn confirmation<A: CachedAccount>(
        &self,
        tip: &BlockMetadata,
        registry: &[u8; 32],
    ) -> Result<Confirmation<A>, RingApiError> {
        let fetch = self.rpc.confirmation(tip, registry);
        A::cache(self).read(*registry, tip, fetch).await
    }
}

impl ChainSource for SolanaRpc {
    async fn confirmation<A: CachedAccount>(
        &self,
        tip: &BlockMetadata,
        registry: &[u8; 32],
    ) -> Result<Confirmation<A>, RingApiError> {
        let context = canonical_context(self, tip).await.map_err(out_of_sync)?;
        let read = self
            .get_multiple_accounts_from_slot(&[Address::new_from_array(*registry)], tip.slot)
            .await
            .map_err(out_of_sync)?;
        let chain = read
            .into_iter()
            .flatten()
            .find(|account| account.owner == STORAGE_PROGRAM_ID)
            .and_then(|account| A::from_image(&account.data).copied())
            .ok_or_else(|| out_of_sync("the registry is not an initialized account"))?;
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
    let read = Snapshot::<StorageState>::registry(db, &request.registry)
        .await?
        .at_root(&request.expected_root.0)
        .await?;
    let loaded: LoadedRegistry = read.load(&request.members, None).await?;
    let openings = request
        .members
        .iter()
        .map(|member| {
            let opened = loaded.opening(&read.root.root, &member.0)?;
            Ok(RingMemberOpening {
                present: opened.present,
                record: member_view(&opened.record),
                path: opened.path,
            })
        })
        .collect::<Result<Vec<_>, RingApiError>>()?;
    let root = read.root;
    let context = read.snapshot.confirm(chain, Served::Root(&root)).await?;
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
    check_page_limit(request.limit)?;
    let read = Snapshot::<StorageState>::registry(db, &request.registry)
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
    .read::<QUAD_HEIGHT>()
    .await?
    .iter()
    .map(indexed_member_view)
    .collect();
    let context = read.snapshot.confirm(chain, Served::Root(&root)).await?;
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
    check_openings(&request.members, request.openings, |pools| {
        pools.own.max(pools.curator)
    })?;
    let canopy = Canopy::covering(request.openings as usize).map_err(validation)?;
    let read = Snapshot::<StorageState>::registry(db, &request.registry)
        .await?
        .at_root(&request.expected_root.0)
        .await?;
    let loaded: LoadedRegistry = read.load(&request.members, Some(canopy)).await?;
    let pool = loaded.pool(&read.root.root, &request.members, canopy)?;
    let root = read.root;
    let context = read.snapshot.confirm(chain, Served::Root(&root)).await?;
    Ok(GetStorageRecordPoolResponse {
        context,
        root: storage_root_view(&root),
        records: pool.records.iter().map(indexed_member_view).collect(),
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
    let snapshot = Snapshot::<StorageState>::registry(db, &request.registry).await?;
    let root = StorageRoot::current(&*snapshot.state.account);
    let chain_start = chain_start(&request.registry.0, root.revision.into()).map_err(internal)?;
    let loaded: LoadedRegistry = TreeRead::batch::<QUAD_HEIGHT>(root.tree(), &entries)
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
    let context = snapshot.confirm(chain, Served::Current(&root)).await?;
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

fn check_page_limit(limit: u64) -> Result<(), RingApiError> {
    if limit == 0 || limit > MAX_RING_MEMBER_PAGE_LIMIT {
        return Err(validation("invalid page limit"));
    }
    Ok(())
}

/// A key reads one pool at its catalog width, past every member and never past the widest key.
fn check_openings(
    members: &[Hash],
    openings: u64,
    width: impl Fn(RecordPools) -> usize,
) -> Result<(), RingApiError> {
    let widest = RING_KEYS
        .iter()
        .filter_map(|key| key.circuit.record_pools())
        .map(width)
        .max()
        .unwrap_or(0);
    if openings < members.len() as u64 || openings > widest as u64 {
        return Err(validation("invalid record pool openings"));
    }
    Ok(())
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

struct RootRead<A> {
    snapshot: Snapshot<RegistryState<A>>,
    root: StorageRoot,
}

/// A verified leaf under one root.
struct OpenedLeaf<L> {
    present: bool,
    record: L,
    path: RingRecordPathView,
}

struct PoolView<L> {
    records: Vec<OpenedLeaf<L>>,
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
struct LeafPage<'a, C, L> {
    store: &'a RegistryStore<'a, C, L>,
    root: &'a [u8; 32],
    at: TreeVersion,
    leaves: Range<u64>,
}

impl<C: ConnectionTrait, L: StoredLeaf> LeafPage<'_, C, L> {
    async fn read<const H: usize>(self) -> Result<Vec<OpenedLeaf<L>>, RingApiError> {
        let rows = self
            .store
            .records_by_index(self.leaves.clone(), self.at.version)
            .await
            .map_err(internal)?;
        if !rows.iter().map(|row| row.index).eq(self.leaves) {
            return Err(RingApiError::PageGap);
        }
        let members = rows
            .iter()
            .map(|row| *row.record.member())
            .collect::<Vec<_>>();
        let read = TreeRead {
            at: self.at,
            records: RecordRead::Leaves(rows),
            inserts: 0,
            canopy: None,
        };
        let loaded: LoadedRegistry<L, H> = read.load(self.store).await.map_err(internal)?;
        members
            .iter()
            .map(|member| loaded.opening(self.root, member))
            .collect()
    }
}

impl<A: CachedAccount> Snapshot<RegistryState<A>> {
    /// Fails before any RPC while the projection catches up or holds the registry quarantined.
    async fn registry(
        db: &DatabaseConnection,
        registry: &SerializablePubkey,
    ) -> Result<Self, RingApiError> {
        let Snapshot { tx, tip, .. } = Snapshot::begin(db).await?;
        let state = ProjectedStore::<_, A>::new(&tx, registry.0.to_bytes())
            .state()
            .await
            .map_err(internal)?
            .ok_or_else(|| out_of_sync("initialization has not been indexed"))?;
        if let Some(fault) = &state.fault {
            return Err(out_of_sync(format!("registry quarantined, {fault}")));
        }
        Ok(Self { tx, state, tip })
    }

    fn store(&self) -> ProjectedStore<'_, DatabaseTransaction, A> {
        ProjectedStore::new(&self.tx, self.state.registry)
    }

    /// The newest revision the registry verifies `root` under at the tip.
    async fn at_root(self, root: &[u8; 32]) -> Result<RootRead<A>, RingApiError> {
        let slot = self.tip.as_ref().map_or(0, |tip| tip.slot);
        let account = &*self.state.account;
        let revision = account
            .roots()
            .iter()
            .map(|held| held.revision)
            .filter(|revision| account.root_at(*revision, slot) == Ok(*root))
            .max_by_key(|revision| revision.value())
            .ok_or(RingApiError::RootChanged)?;
        let root = self
            .store()
            .root(revision.value())
            .await
            .map_err(internal)?
            .filter(|stored| stored.root == *root)
            .ok_or_else(|| internal("a history root is missing from the projection"))?;
        Ok(RootRead {
            snapshot: self,
            root,
        })
    }

    async fn confirm(
        self,
        chain: &impl ChainSource,
        served: Served<'_>,
    ) -> Result<ApiContext, RingApiError> {
        let Released { tip, state } = self.release().await?;
        let confirmation = chain.confirmation::<A>(&tip, &state.registry).await?;
        if !served.agrees(&*confirmation.chain, tip.slot) {
            return Err(RingApiError::RootChanged);
        }
        Ok(confirmation.context)
    }
}

impl<A: CachedAccount> RootRead<A> {
    async fn load<const H: usize>(
        &self,
        members: &[Hash],
        canopy: Option<Canopy>,
    ) -> Result<LoadedRegistry<A::Leaf, H>, RingApiError> {
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

enum Served<'r> {
    Root(&'r StorageRoot),
    /// Apply proof inputs hold while the current root stays.
    Current(&'r StorageRoot),
    /// Pending state names no root.
    Tip,
}

impl Served<'_> {
    fn agrees<A: ProjectedAccount>(&self, chain: &A, slot: u64) -> bool {
        match self {
            Self::Root(root) => chain.root_at(Revision::from(root.revision), slot) == Ok(root.root),
            Self::Current(root) => StorageRoot::current(chain) == **root,
            Self::Tip => true,
        }
    }
}

impl<L: IndexedLeaf + Default, const H: usize> LoadedRegistry<L, H> {
    fn pool(
        &self,
        root: &[u8; 32],
        members: &[Hash],
        canopy: Canopy,
    ) -> Result<PoolView<L>, RingApiError> {
        let members: Vec<[u8; 32]> = members.iter().map(|member| member.0).collect();
        let pool: RecordPoolOf<L> = self.tree.record_pool(&members, canopy).map_err(internal)?;
        pool.verify(root)
            .map_err(|error| internal(format!("registry pool disagrees ({error})")))?;
        let records = pool
            .records
            .iter()
            .zip(&pool.proof.paths)
            .map(|(record, path)| OpenedLeaf {
                present: true,
                record: *record,
                path: path_view(path.index, &path.siblings),
            })
            .collect();
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

    fn opening(&self, root: &[u8; 32], member: &[u8; 32]) -> Result<OpenedLeaf<L>, RingApiError> {
        let opening = self.tree.opening(member).map_err(internal)?;
        OpeningCheck {
            opening: &opening,
            root,
            member,
        }
        .verify()
        .map_err(|error| internal(format!("registry opening disagrees ({error})")))?;
        let (present, record, path) = match opening {
            RecordOpening::Present { record, path } => (true, record, path),
            RecordOpening::Absent { low, path } => (false, low, path),
        };
        Ok(OpenedLeaf {
            present,
            record,
            path: path_view(path.index, &path.siblings),
        })
    }
}

fn member_view(record: &MemberRecord) -> RingMemberRecordView {
    RingMemberRecordView {
        member: Hash(record.member),
        next: Hash(record.next),
        lists: record.lists,
        mint_policy: record.mint_policy,
    }
}

fn indexed_member_view(leaf: &OpenedLeaf<MemberRecord>) -> RingIndexedMemberRecordView {
    RingIndexedMemberRecordView {
        record: member_view(&leaf.record),
        path: leaf.path.clone(),
    }
}

fn write_view(write: &RecordWriteProofInput) -> RingRecordWriteView {
    RingRecordWriteView {
        member: Hash(write.entry.member),
        mask: write.entry.mask,
        value: write.entry.value,
        mint_policy: write.entry.mint_policy,
        exists: write.exists,
        old_next: Hash(write.old_next),
        old_lists: write.old_lists,
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

fn storage_entry(write: &StorageWriteView) -> Result<RecordWrite, CustomRingError> {
    RecordWriteData {
        member: write.member.0,
        lists: WriteRecordsIxData {
            mask: write.mask.to_le_bytes(),
            value: write.value.to_le_bytes(),
        },
        mint_policy: mint_policy_write(write.mint_policy),
    }
    .entry()
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
