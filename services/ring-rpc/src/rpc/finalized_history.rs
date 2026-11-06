//! Ascending pages of one ring's finalized history, read over an immutable snapshot.
//!
//! `getSignaturesForAddress` walks newest first only, so a refresh walks from the
//! finalized tip down to the floor, or to the tip of the snapshot it extends, and keeps a
//! sparse index of runs. A page seeks the run holding its cursor and refetches the runs
//! around its window, each refused unless it matches its walk digest. The newest run stays in memory
//! when no signature above it bounds a refetch. Read `Refresh` and `SnapshotIndex` for the
//! walk, then `Snapshot::window` for the page.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    num::NonZeroU32,
    ops::Range,
    sync::Arc,
};

use async_trait::async_trait;
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client_api::{
    request::RpcRequest, response::RpcConfirmedTransactionStatusWithSignature,
};
use solana_signature::Signature;
use spr_client::{
    AsyncRpc, AsyncSolanaRpc, AsyncSprIndexer, ClientError,
    GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse,
    IndexedShieldedTransaction,
};
use spr_indexer_api::{Context, PaginationToken, TransactionEvents};
use spr_transaction::ShieldedTransaction;
use tokio::sync::Mutex;
use zolana_ring_client::{
    history::HistoryPosition, AuditError, ConfirmedRingOrigins, RingOrigin,
    ORIGIN_TRANSACTION_CONFIG,
};

use crate::upstream::RingFrame;

const SIGNATURE_PAGE_SIZE: usize = 1_000;
/// Index size falls with a longer run, a page refetches up to a few runs past its limit.
const RUN_LEN: usize = 100;

#[derive(Default)]
pub(crate) struct FinalizedHistory {
    rings: Mutex<HashMap<Address, Arc<RingHistory>>>,
}

/// Readers clone `published` under a short lock, only a refresh waits on `refresh`.
#[derive(Default)]
struct RingHistory {
    published: Mutex<Option<Arc<Snapshot>>>,
    refresh: Mutex<()>,
}

#[derive(Clone, Copy)]
pub(crate) enum HistorySelection {
    Ring,
    Tag([u8; 32]),
}

pub(crate) struct FinalizedPage {
    pub ring: Address,
    pub position: HistoryPosition,
    pub limit: NonZeroU32,
    pub selection: HistorySelection,
}

pub(crate) struct FinalizedUpstreams<'a> {
    pub rpc: &'a AsyncSolanaRpc,
    pub indexer: &'a AsyncSprIndexer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignatureEntry {
    signature: Signature,
    slot: u64,
    succeeded: bool,
}

struct SignatureRead {
    ring: Address,
    before: Option<Signature>,
    snapshot: u64,
    limit: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct OriginRead {
    pub ring: Address,
    pub signature: Signature,
}

pub(crate) struct CanonicalOrigins {
    slot: u64,
    pub origins: BTreeMap<u16, RingOrigin>,
}

/// Finalized signatures above `floor` through `context.slot`.
struct Snapshot {
    floor: Option<u64>,
    context: Context,
    /// Directly above the newest run, absent when nothing was newer at the walk.
    top: Option<PaginationToken>,
    /// Oldest first, a run refetches from the oldest signature of the next newer run.
    runs: Vec<Run>,
}

#[derive(Clone)]
struct Run {
    oldest_slot: u64,
    newest_slot: u64,
    oldest: Signature,
    body: RunBody,
}

#[derive(Clone)]
enum RunBody {
    /// The newest run without a `top`, no signature above it bounds a refetch.
    Resident(Box<[SignatureEntry]>),
    Anchored {
        len: usize,
        digest: [u8; 32],
    },
}

struct Window {
    entries: Vec<SignatureEntry>,
    more: bool,
}

#[async_trait]
trait FinalizedSource: Sync {
    async fn context(&self) -> Result<Context, ClientError>;
    async fn signatures(&self, read: SignatureRead) -> Result<Vec<SignatureEntry>, ClientError>;
    async fn origins(&self, read: OriginRead) -> Result<CanonicalOrigins, AuditError>;
    async fn indexed(
        &self,
        signature: Signature,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError>;
}

impl FinalizedHistory {
    pub(crate) async fn page(
        &self,
        request: FinalizedPage,
        source: &FinalizedUpstreams<'_>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.read(request, source).await
    }

    async fn read<S: FinalizedSource>(
        &self,
        request: FinalizedPage,
        source: &S,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        // 1. No lock survives the snapshot read, a slow origin or indexer read stalls no other
        //    page of the ring.
        let snapshot = self.snapshot(&request, source).await?;
        let window = snapshot.window(&request, source).await?;
        // 2. Every returned signature binds its canonical origins to its indexed events.
        let mut data = Vec::with_capacity(window.entries.len());
        for entry in window.entries {
            let mut events = request.events(entry, source).await?;
            events.retain(|transaction| request.selection.includes(transaction));
            data.push(TransactionEvents {
                slot: entry.slot,
                signature: entry.signature,
                events,
            });
        }
        let pagination_token = if window.more {
            data.last()
                .map(|row| PaginationToken::new(row.slot, row.signature))
        } else {
            None
        };
        Ok(GetShieldedTransactionsByTagsResponse {
            context: snapshot.context,
            output_tree_id: None,
            data,
            pagination_token,
        })
    }

    /// A continuation reuses the published snapshot covering its floor, any other read refreshes.
    async fn snapshot<S: FinalizedSource>(
        &self,
        request: &FinalizedPage,
        source: &S,
    ) -> Result<Arc<Snapshot>, ClientError> {
        let ring = self
            .rings
            .lock()
            .await
            .entry(request.ring)
            .or_default()
            .clone();
        let published = ring.published.lock().await.clone();
        if let Some(snapshot) = published.filter(|snapshot| request.continues(snapshot)) {
            return Ok(snapshot);
        }
        let _refresh = ring.refresh.lock().await;
        // A refresh finished while waiting can already cover a continuation.
        let previous = ring.published.lock().await.clone();
        if let Some(snapshot) = previous
            .as_ref()
            .filter(|snapshot| request.continues(snapshot))
        {
            return Ok(snapshot.clone());
        }
        let snapshot = Refresh {
            ring: request.ring,
            floor: request.floor(),
            token: request.position.token(),
            previous,
        }
        .run(source)
        .await?;
        *ring.published.lock().await = Some(snapshot.clone());
        Ok(snapshot)
    }
}

impl FinalizedPage {
    /// The newest slot the page excludes.
    fn floor(&self) -> Option<u64> {
        self.position.token().map_or_else(
            || self.position.filters().slot.floor(),
            |token| token.slot().checked_sub(1),
        )
    }

    fn continues(&self, snapshot: &Snapshot) -> bool {
        self.position
            .token()
            .is_some_and(|token| token.slot() <= snapshot.context.slot)
            && snapshot.covers(self.floor())
    }

    fn includes(&self, entry: &SignatureEntry) -> bool {
        self.position.filters().slot.contains(entry.slot)
            && self
                .position
                .token()
                .is_none_or(|token| entry.position() > token)
    }

    async fn events<S: FinalizedSource>(
        &self,
        entry: SignatureEntry,
        source: &S,
    ) -> Result<Vec<ShieldedTransaction>, ClientError> {
        bound_events(self.ring, entry, source).await
    }
}

/// The events of one finalized signature of `ring`, each bound to its confirmed origin.
async fn bound_events<S: FinalizedSource>(
    ring: Address,
    entry: SignatureEntry,
    source: &S,
) -> Result<Vec<ShieldedTransaction>, ClientError> {
    if !entry.succeeded {
        return Ok(Vec::new());
    }
    let mut canonical = source
        .origins(OriginRead {
            ring,
            signature: entry.signature,
        })
        .await
        .map_err(history_error)?;
    if canonical.slot != entry.slot {
        return Err(invalid_history());
    }
    canonical.origins.retain(|_, origin| origin.ring_invoked);
    if canonical.origins.is_empty() {
        return Ok(Vec::new());
    }
    let indexed = source.indexed(entry.signature).await?;
    BoundEvents {
        ring,
        entry,
        canonical,
        indexed: indexed.transactions,
    }
    .read()
}

impl HistorySelection {
    fn includes(self, transaction: &ShieldedTransaction) -> bool {
        match self {
            Self::Ring => true,
            Self::Tag(tag) => {
                transaction
                    .messages
                    .iter()
                    .any(|message| message.view_tag == tag)
                    || transaction
                        .output_slots
                        .iter()
                        .any(|output| output.view_tag == tag)
            }
        }
    }
}

impl SignatureEntry {
    fn position(&self) -> PaginationToken {
        PaginationToken::new(self.slot, self.signature)
    }
}

struct Refresh {
    ring: Address,
    floor: Option<u64>,
    token: Option<PaginationToken>,
    previous: Option<Arc<Snapshot>>,
}

impl Refresh {
    async fn run<S: FinalizedSource>(self, source: &S) -> Result<Arc<Snapshot>, ClientError> {
        // 1. A finalized tip below the floor, the cursor or the published tip is a lagging
        //    or rolled back node.
        let context = source.context().await?;
        if self.floor.is_some_and(|floor| context.slot < floor)
            || self.token.is_some_and(|token| token.slot() > context.slot)
            || self
                .previous
                .as_ref()
                .is_some_and(|previous| previous.context.slot > context.slot)
        {
            return Err(invalid_history());
        }
        // 2. A snapshot reaching the floor is extended, walking only above its tip.
        let previous = self
            .previous
            .filter(|previous| previous.floor <= self.floor);
        if let Some(previous) = &previous {
            if previous.context == context {
                return Ok(previous.clone());
            }
        }
        let from = previous
            .as_ref()
            .map_or(self.floor, |previous| Some(previous.context.slot));
        let mut index = SnapshotIndex::default();
        if from != Some(context.slot) {
            Walk {
                ring: self.ring,
                floor: from,
                context,
            }
            .run(source, &mut index)
            .await?;
        }
        Ok(Arc::new(
            index.finish(Snapshot {
                floor: previous
                    .as_ref()
                    .map_or(self.floor, |previous| previous.floor),
                context,
                top: previous.as_ref().and_then(|previous| previous.top),
                runs: previous
                    .as_ref()
                    .map_or_else(Vec::new, |previous| previous.runs.clone()),
            }),
        ))
    }
}

struct Walk {
    ring: Address,
    floor: Option<u64>,
    context: Context,
}

impl Walk {
    /// Streams the signatures above the floor into `index`, newest first.
    async fn run<S: FinalizedSource>(
        self,
        source: &S,
        index: &mut SnapshotIndex,
    ) -> Result<(), ClientError> {
        let mut before = None;
        let mut slot = None;
        // Dropped with the walk, the snapshot keeps no signature set.
        let mut seen = HashSet::new();
        loop {
            let page = source
                .signatures(SignatureRead {
                    ring: self.ring,
                    before,
                    snapshot: self.context.slot,
                    limit: SIGNATURE_PAGE_SIZE,
                })
                .await?;
            if page.len() > SIGNATURE_PAGE_SIZE {
                return Err(invalid_history());
            }
            let ended = page.len() < SIGNATURE_PAGE_SIZE;
            for entry in page {
                if slot.is_some_and(|slot| entry.slot > slot) || !seen.insert(entry.signature) {
                    return Err(invalid_history());
                }
                slot = Some(entry.slot);
                before = Some(entry.signature);
                if self.floor.is_some_and(|floor| entry.slot <= floor) {
                    return Ok(());
                }
                index.push(entry, self.context.slot);
            }
            if ended {
                return Ok(());
            }
        }
    }
}

/// Runs in walk order, newest first, sealed every `RUN_LEN` entries.
#[derive(Default)]
struct SnapshotIndex {
    top: Option<PaginationToken>,
    sealed: Vec<Run>,
    open: Vec<SignatureEntry>,
}

impl SnapshotIndex {
    fn push(&mut self, entry: SignatureEntry, snapshot: u64) {
        if entry.slot > snapshot {
            // Above the snapshot, the last one anchors the newest run.
            self.top = Some(entry.position());
            return;
        }
        self.open.push(entry);
        if self.open.len() == RUN_LEN {
            self.seal();
        }
    }

    fn seal(&mut self) {
        let resident = self.top.is_none() && self.sealed.is_empty();
        self.sealed.extend(Run::new(&self.open, resident));
        self.open.clear();
    }

    /// Lays the walked runs over `below`, the snapshot the walk stopped at.
    fn finish(mut self, mut below: Snapshot) -> Snapshot {
        self.seal();
        // The walk stopped at the newest entry of `below`, the signature above it is
        // the oldest walked one or the walk `top`.
        if self.top.is_some() || !self.sealed.is_empty() {
            below.top = self.top;
            if let Some(newest) = below.runs.last_mut() {
                newest.anchor();
            }
        }
        below.runs.reserve_exact(self.sealed.len());
        below.runs.extend(self.sealed.into_iter().rev());
        below
    }
}

impl Run {
    /// `entries` newest first.
    fn new(entries: &[SignatureEntry], resident: bool) -> Option<Self> {
        let (newest, oldest) = (entries.first()?, entries.last()?);
        Some(Self {
            oldest_slot: oldest.slot,
            newest_slot: newest.slot,
            oldest: oldest.signature,
            body: if resident {
                RunBody::Resident(entries.into())
            } else {
                RunBody::Anchored {
                    len: entries.len(),
                    digest: run_digest(entries),
                }
            },
        })
    }

    fn len(&self) -> usize {
        match &self.body {
            RunBody::Resident(entries) => entries.len(),
            RunBody::Anchored { len, .. } => *len,
        }
    }

    fn is_resident(&self) -> bool {
        matches!(self.body, RunBody::Resident(_))
    }

    fn anchor(&mut self) {
        if let RunBody::Resident(entries) = &self.body {
            self.body = RunBody::Anchored {
                len: entries.len(),
                digest: run_digest(entries),
            };
        }
    }

    fn check(&self, entries: &[SignatureEntry]) -> Result<(), ClientError> {
        let matches = match &self.body {
            RunBody::Resident(resident) => **resident == *entries,
            RunBody::Anchored { len, digest } => {
                *len == entries.len() && *digest == run_digest(entries)
            }
        };
        matches.then_some(()).ok_or_else(invalid_history)
    }
}

impl Snapshot {
    fn covers(&self, floor: Option<u64>) -> bool {
        self.floor <= floor && floor.is_none_or(|floor| floor <= self.context.slot)
    }

    async fn window<S: FinalizedSource>(
        &self,
        request: &FinalizedPage,
        source: &S,
    ) -> Result<Window, ClientError> {
        let limit = request.limit.get() as usize;
        // 1. Seek the oldest run reaching the first slot the page can return.
        let start = request.floor().map_or(0, |floor| floor.saturating_add(1));
        let mut next = self.runs.partition_point(|run| run.newest_slot < start);
        let mut pool: Vec<SignatureEntry> = Vec::new();
        loop {
            // 2. A slot can straddle runs. Entries below the oldest slot of the next
            //    unread run are complete, and the page needs one past its limit.
            pool.sort_unstable_by_key(SignatureEntry::position);
            let complete = self.runs.get(next).map_or(pool.len(), |run| {
                pool.partition_point(|entry| entry.slot < run.oldest_slot)
            });
            if complete > limit || next == self.runs.len() {
                pool.truncate(limit);
                return Ok(Window {
                    entries: pool,
                    more: complete > limit,
                });
            }
            // 3. Each call refetches the missing entries plus a run for the cursor run
            //    and a straddled slot.
            let batch = self.batch(next, limit + 1 - complete + RUN_LEN);
            let entries = self.load(batch.clone(), request.ring, source).await?;
            pool.extend(entries.into_iter().filter(|entry| request.includes(entry)));
            next = batch.end;
        }
    }

    /// Runs from `first` upward, one call long, a resident run alone.
    fn batch(&self, first: usize, wanted: usize) -> Range<usize> {
        if self.runs[first].is_resident() {
            return first..first + 1;
        }
        let mut end = first;
        let mut total = 0;
        while let Some(run) = self.runs.get(end) {
            if run.is_resident() || total >= wanted || total + run.len() > SIGNATURE_PAGE_SIZE {
                break;
            }
            total += run.len();
            end += 1;
        }
        first..end
    }

    /// Entries of `runs` newest first, each run checked against its walk.
    async fn load<S: FinalizedSource>(
        &self,
        runs: Range<usize>,
        ring: Address,
        source: &S,
    ) -> Result<Vec<SignatureEntry>, ClientError> {
        let batch = &self.runs[runs.clone()];
        if let [Run {
            body: RunBody::Resident(entries),
            ..
        }] = batch
        {
            return Ok(entries.to_vec());
        }
        let anchor = self
            .runs
            .get(runs.end)
            .map_or(self.top, |newer| {
                Some(PaginationToken::new(newer.oldest_slot, newer.oldest))
            })
            .ok_or_else(invalid_history)?;
        let limit = batch.iter().map(Run::len).sum();
        let entries = source
            .signatures(SignatureRead {
                ring,
                before: Some(anchor.signature()),
                // A node behind the anchor slot cannot find it, and `top` lies above the snapshot.
                snapshot: self.context.slot.max(anchor.slot()),
                limit,
            })
            .await?;
        if entries.len() != limit {
            return Err(invalid_history());
        }
        let mut rest = entries.as_slice();
        for run in batch.iter().rev() {
            let (read, older) = rest.split_at(run.len());
            run.check(read)?;
            rest = older;
        }
        Ok(entries)
    }
}

/// Binds every entry field, a refetch answering other history fails its run.
fn run_digest(entries: &[SignatureEntry]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for entry in entries {
        hasher.update(entry.signature);
        hasher.update(entry.slot.to_le_bytes());
        hasher.update([u8::from(entry.succeeded)]);
    }
    hasher.finalize().into()
}

struct BoundEvents {
    ring: Address,
    entry: SignatureEntry,
    canonical: CanonicalOrigins,
    indexed: Vec<IndexedShieldedTransaction>,
}

impl BoundEvents {
    fn read(mut self) -> Result<Vec<ShieldedTransaction>, ClientError> {
        let mut events = BTreeMap::new();
        let mut seen = HashSet::new();
        for indexed in self.indexed {
            let mut transaction = indexed.transaction;
            if !seen.insert(indexed.event_index)
                || transaction.event_index != Some(indexed.event_index)
                || transaction.tx_signature != self.entry.signature
                || transaction.slot != self.entry.slot
            {
                return Err(invalid_history());
            }
            match self.canonical.origins.remove(&indexed.event_index) {
                Some(origin) => {
                    origin
                        .bind_transaction(&mut transaction, self.ring)
                        .map_err(history_error)?;
                    events.insert(indexed.event_index, transaction);
                }
                None if transaction.ring_program_id == Some(self.ring) => {
                    return Err(invalid_history())
                }
                None => {}
            }
        }
        if !self.canonical.origins.is_empty() {
            return Err(invalid_history());
        }
        Ok(events.into_values().collect())
    }
}

impl FinalizedUpstreams<'_> {
    pub(crate) async fn origins(&self, read: OriginRead) -> Result<CanonicalOrigins, AuditError> {
        <Self as FinalizedSource>::origins(self, read).await
    }

    /// A finalized read of one signature, its confirmed slot must equal the frame's.
    pub(crate) async fn frame(
        &self,
        frame: RingFrame,
    ) -> Result<Vec<ShieldedTransaction>, ClientError> {
        let entry = SignatureEntry {
            signature: frame.signature,
            slot: frame.slot,
            succeeded: true,
        };
        bound_events(frame.ring, entry, self).await
    }
}

#[async_trait]
impl FinalizedSource for FinalizedUpstreams<'_> {
    async fn context(&self) -> Result<Context, ClientError> {
        let slot = self
            .rpc
            .client()
            .get_slot_with_commitment(CommitmentConfig::finalized())
            .await
            .map_err(rpc_error)?;
        let block_time = self
            .rpc
            .client()
            .get_block_time(slot)
            .await
            .map_err(rpc_error)?;
        Ok(Context { slot, block_time })
    }

    async fn signatures(&self, read: SignatureRead) -> Result<Vec<SignatureEntry>, ClientError> {
        let entries: Vec<RpcConfirmedTransactionStatusWithSignature> = self
            .rpc
            .client()
            .send(
                RpcRequest::GetSignaturesForAddress,
                json!([read.ring.to_string(), {
                    "commitment": "finalized",
                    "minContextSlot": read.snapshot,
                    "limit": read.limit,
                    "before": read.before.map(|signature| signature.to_string()),
                }]),
            )
            .await
            .map_err(rpc_error)?;
        entries
            .into_iter()
            .map(|entry| {
                Ok(SignatureEntry {
                    signature: entry.signature.parse().map_err(|_| invalid_history())?,
                    slot: entry.slot,
                    succeeded: entry.err.is_none(),
                })
            })
            .collect()
    }

    async fn origins(&self, read: OriginRead) -> Result<CanonicalOrigins, AuditError> {
        let mut config = ORIGIN_TRANSACTION_CONFIG;
        config.commitment = Some(CommitmentConfig::finalized());
        let transaction = self
            .rpc
            .client()
            .get_transaction_with_config(&read.signature, config)
            .await
            .map_err(|error| AuditError::Unavailable {
                signature: read.signature,
                message: error.to_string(),
            })?;
        let slot = transaction.slot;
        let origins = ConfirmedRingOrigins {
            signature: read.signature,
            transaction,
            ring: read.ring,
        }
        .read()?;
        Ok(CanonicalOrigins { slot, origins })
    }

    async fn indexed(
        &self,
        signature: Signature,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        self.indexer
            .get_shielded_transactions_by_signature(signature, None)
            .await
    }
}

fn history_error(error: impl std::fmt::Display) -> ClientError {
    ClientError::Rpc(format!("finalized ring history refused because {error}"))
}

fn rpc_error(error: impl std::fmt::Display) -> ClientError {
    ClientError::Rpc(format!("finalized history RPC failed because {error}"))
}

fn invalid_history() -> ClientError {
    ClientError::Rpc("finalized ring history is incomplete or inconsistent".into())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Mutex as StdMutex,
        },
        time::Duration,
    };

    use tokio::sync::Notify;
    use zolana_ring_client::history::PageEnd;

    use super::*;
    use crate::upstream::origin_fixture;

    const RING: Address = Address::new_from_array([8; 32]);

    struct Source {
        through: AtomicU64,
        /// Newest slot first, the `getSignaturesForAddress` order.
        signatures: StdMutex<Vec<SignatureEntry>>,
        transactions: HashMap<Signature, Vec<ShieldedTransaction>>,
        indexed: StdMutex<HashMap<Signature, Vec<IndexedShieldedTransaction>>>,
        walks: AtomicUsize,
        tips: AtomicUsize,
        min_context: AtomicU64,
        signature_calls: AtomicUsize,
        signature_entries: AtomicUsize,
        origin_calls: AtomicUsize,
        held: Option<Signature>,
        hold_walk: std::sync::atomic::AtomicBool,
        release: Notify,
    }

    impl Source {
        fn new(entries: &[SignatureEntry]) -> Self {
            let transactions: HashMap<_, _> = entries
                .iter()
                .map(|entry| (entry.signature, vec![transaction(*entry)]))
                .collect();
            let indexed = transactions
                .iter()
                .map(|(signature, transactions)| {
                    (
                        *signature,
                        transactions
                            .iter()
                            .map(|transaction| IndexedShieldedTransaction {
                                event_index: transaction.event_index.unwrap(),
                                transaction: transaction.clone(),
                            })
                            .collect(),
                    )
                })
                .collect();
            // Inside a slot the walk order opposes position order, the case the window
            // completeness rule exists for.
            let mut signatures = entries.to_vec();
            signatures
                .sort_unstable_by_key(|entry| (std::cmp::Reverse(entry.slot), entry.signature));
            Self {
                through: AtomicU64::new(entries.iter().map(|entry| entry.slot).max().unwrap_or(0)),
                signatures: StdMutex::new(signatures),
                transactions,
                indexed: StdMutex::new(indexed),
                walks: AtomicUsize::new(0),
                tips: AtomicUsize::new(0),
                min_context: AtomicU64::new(0),
                signature_calls: AtomicUsize::new(0),
                signature_entries: AtomicUsize::new(0),
                origin_calls: AtomicUsize::new(0),
                held: None,
                hold_walk: std::sync::atomic::AtomicBool::new(false),
                release: Notify::new(),
            }
        }

        fn fetched(&self) -> (usize, usize) {
            (
                self.signature_calls.load(Ordering::SeqCst),
                self.signature_entries.load(Ordering::SeqCst),
            )
        }
    }

    #[async_trait]
    impl FinalizedSource for Source {
        async fn context(&self) -> Result<Context, ClientError> {
            self.tips.fetch_add(1, Ordering::SeqCst);
            Ok(Context {
                slot: self.through.load(Ordering::SeqCst),
                block_time: 0,
            })
        }

        async fn signatures(
            &self,
            read: SignatureRead,
        ) -> Result<Vec<SignatureEntry>, ClientError> {
            assert_eq!(read.ring, RING);
            assert!(read.limit <= SIGNATURE_PAGE_SIZE);
            if read.before.is_none() {
                self.walks.fetch_add(1, Ordering::SeqCst);
                if self.hold_walk.swap(false, Ordering::SeqCst) {
                    self.release.notified().await;
                }
            }
            self.min_context.store(read.snapshot, Ordering::SeqCst);
            let entries = self.signatures.lock().unwrap();
            let start = read.before.map_or(0, |before| {
                entries
                    .iter()
                    .position(|entry| entry.signature == before)
                    .unwrap()
                    + 1
            });
            let page: Vec<_> = entries
                .iter()
                .skip(start)
                .take(read.limit)
                .copied()
                .collect();
            self.signature_calls.fetch_add(1, Ordering::SeqCst);
            self.signature_entries
                .fetch_add(page.len(), Ordering::SeqCst);
            Ok(page)
        }

        async fn origins(&self, read: OriginRead) -> Result<CanonicalOrigins, AuditError> {
            self.origin_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(read.ring, RING);
            if self.held == Some(read.signature) {
                self.release.notified().await;
            }
            let transactions = &self.transactions[&read.signature];
            Ok(CanonicalOrigins {
                slot: transactions[0].slot,
                origins: transactions
                    .iter()
                    .map(|transaction| {
                        (
                            transaction.event_index.unwrap(),
                            RingOrigin {
                                ring_invoked: true,
                                event: origin_fixture::event(transaction)
                                    .with_slot(transaction.slot),
                                signers: Vec::new(),
                                withdrawals: Vec::new(),
                                merge_disclosure: None,
                                transact: None,
                                pool_accounts: Vec::new(),
                            },
                        )
                    })
                    .collect(),
            })
        }

        async fn indexed(
            &self,
            signature: Signature,
        ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
            Ok(GetShieldedTransactionsBySignatureResponse {
                context: Context {
                    slot: self.through.load(Ordering::SeqCst),
                    block_time: 0,
                },
                output_tree_id: None,
                transactions: self
                    .indexed
                    .lock()
                    .unwrap()
                    .get(&signature)
                    .cloned()
                    .unwrap_or_default(),
            })
        }
    }

    fn entry(index: u8) -> SignatureEntry {
        SignatureEntry {
            signature: Signature::from([index; 64]),
            slot: u64::from(index),
            succeeded: true,
        }
    }

    /// Ascending, three per slot, two run boundaries in three split a slot.
    fn long_history(count: usize) -> Vec<SignatureEntry> {
        let mut history: Vec<_> = (0..count)
            .map(|index| {
                let mut signature = [7; 64];
                signature[..8].copy_from_slice(&(index as u64).to_be_bytes());
                SignatureEntry {
                    signature: Signature::from(signature),
                    slot: (index / 3) as u64 + 1,
                    succeeded: false,
                }
            })
            .collect();
        history.sort_unstable_by_key(SignatureEntry::position);
        history
    }

    fn transaction(entry: SignatureEntry) -> ShieldedTransaction {
        ShieldedTransaction {
            slot: entry.slot,
            tx_signature: entry.signature,
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: Vec::new(),
            messages: Vec::new(),
            nullifiers: Vec::new(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        }
    }

    fn request(position: HistoryPosition) -> FinalizedPage {
        sized(position, 1)
    }

    fn sized(position: HistoryPosition, limit: u32) -> FinalizedPage {
        FinalizedPage {
            ring: RING,
            position,
            limit: NonZeroU32::new(limit).unwrap(),
            selection: HistorySelection::Ring,
        }
    }

    #[tokio::test]
    async fn continuation_reuses_the_canonical_manifest() {
        let history = FinalizedHistory::default();
        let source = Source::new(&[entry(1), entry(2), entry(3)]);
        let mut position = HistoryPosition::default();
        for slot in 1..=3 {
            let page = history.read(request(position), &source).await.unwrap();
            assert_eq!(page.data[0].slot, slot);
            let _ = position.advance(&page, 1).unwrap();
        }
        assert_eq!(position.checkpoint(), Some(3));
        assert_eq!(source.signature_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_newer_backfill_does_not_evict_an_older_reader() {
        let history = FinalizedHistory::default();
        let source = Source::new(&[entry(1), entry(2), entry(3), entry(4)]);
        source.through.store(3, Ordering::SeqCst);
        let first = history
            .read(request(HistoryPosition::default()), &source)
            .await
            .unwrap();
        let old_cursor = first.pagination_token.unwrap();
        source.through.store(4, Ordering::SeqCst);
        let new = history
            .read(request(HistoryPosition::after_slot(3)), &source)
            .await
            .unwrap();
        assert_eq!(new.data[0].slot, 4);
        let old = history
            .read(request(HistoryPosition::resume(old_cursor)), &source)
            .await
            .unwrap();
        assert_eq!(old.data[0].slot, 2);
        assert_eq!(source.walks.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_previous_tip_readable() {
        let history = FinalizedHistory::default();
        let source = Source::new(&[entry(1), entry(2), entry(3), entry(4)]);
        let newest = source.signatures.lock().unwrap().remove(0);
        source.through.store(3, Ordering::SeqCst);
        let first = history
            .read(request(HistoryPosition::default()), &source)
            .await
            .unwrap();
        source.signatures.lock().unwrap().insert(0, newest);
        source.through.store(4, Ordering::SeqCst);
        let new = history
            .read(request(HistoryPosition::after_slot(3)), &source)
            .await
            .unwrap();
        assert_eq!(new.data[0].slot, 4);
        let old = history
            .read(
                request(HistoryPosition::resume(first.pagination_token.unwrap())),
                &source,
            )
            .await
            .unwrap();
        assert_eq!(old.data[0].slot, 2);
        assert_eq!(old.context.slot, 4);
        assert_eq!(source.walks.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn pages_return_a_long_history_once_and_in_order() {
        let ascending = long_history(2_500);
        let history = FinalizedHistory::default();
        let source = Source::new(&ascending);
        let mut position = HistoryPosition::default();
        let mut read = Vec::new();
        loop {
            let page = history.read(sized(position, 37), &source).await.unwrap();
            read.extend(page.data.iter().map(|row| row.signature));
            if position.advance(&page, 37).unwrap() != PageEnd::More {
                break;
            }
        }
        let expected: Vec<_> = ascending.iter().map(|entry| entry.signature).collect();
        assert_eq!(read, expected);
        assert_eq!(source.walks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_later_page_refetches_its_runs_and_not_the_history() {
        let ascending = long_history(20_000);
        let history = FinalizedHistory::default();
        let source = Source::new(&ascending);
        history
            .read(sized(HistoryPosition::default(), 100), &source)
            .await
            .unwrap();
        let (calls, entries) = source.fetched();
        let page = history
            .read(
                sized(HistoryPosition::resume(ascending[17_999].position()), 100),
                &source,
            )
            .await
            .unwrap();
        let rows: Vec<_> = page.data.iter().map(|row| row.signature).collect();
        let expected: Vec<_> = ascending[18_000..18_100]
            .iter()
            .map(|entry| entry.signature)
            .collect();
        assert_eq!(rows, expected);
        assert_eq!(page.pagination_token, Some(ascending[18_099].position()));
        let (later_calls, later_entries) = source.fetched();
        assert!(later_calls - calls <= 2);
        assert!(later_entries - entries < 100 + 1 + 4 * RUN_LEN);
    }

    #[tokio::test]
    async fn a_page_at_the_call_cap_waits_for_its_straddled_slot() {
        let ascending = long_history(3_000);
        let history = FinalizedHistory::default();
        let source = Source::new(&ascending);
        let limit = SIGNATURE_PAGE_SIZE - RUN_LEN;
        history
            .read(sized(HistoryPosition::default(), 1), &source)
            .await
            .unwrap();
        for cursor in 0..2 * RUN_LEN {
            let page = history
                .read(
                    sized(
                        HistoryPosition::resume(ascending[cursor].position()),
                        limit as u32,
                    ),
                    &source,
                )
                .await
                .unwrap();
            let rows: Vec<_> = page.data.iter().map(|row| row.signature).collect();
            let expected: Vec<_> = ascending[cursor + 1..cursor + 1 + limit]
                .iter()
                .map(|entry| entry.signature)
                .collect();
            assert_eq!(rows, expected, "cursor {cursor}");
        }
    }

    #[tokio::test]
    async fn a_failed_signature_repeated_in_another_slot_is_refused() {
        let mut failed = entry(1);
        failed.succeeded = false;
        let source = Source::new(&[failed, entry(2)]);
        let mut repeat = failed;
        repeat.slot = 3;
        source.signatures.lock().unwrap().insert(0, repeat);
        source.through.store(3, Ordering::SeqCst);
        assert!(FinalizedHistory::default()
            .read(request(HistoryPosition::default()), &source)
            .await
            .is_err());
        source.signatures.lock().unwrap().remove(0);
        let page = FinalizedHistory::default()
            .read(sized(HistoryPosition::default(), 2), &source)
            .await
            .unwrap();
        assert_eq!(page.data.len(), 2);
        assert!(page.pagination_token.is_none());
    }

    #[tokio::test]
    async fn a_refetched_run_must_match_its_walk() {
        let ascending = long_history(5_000);
        let history = FinalizedHistory::default();
        let source = Source::new(&ascending);
        history
            .read(sized(HistoryPosition::default(), 100), &source)
            .await
            .unwrap();
        source
            .signatures
            .lock()
            .unwrap()
            .iter_mut()
            .find(|entry| entry.signature == ascending[2_550].signature)
            .unwrap()
            .succeeded = true;
        assert!(history
            .read(
                sized(HistoryPosition::resume(ascending[2_499].position()), 100),
                &source,
            )
            .await
            .is_err());
        let untouched = history
            .read(
                sized(HistoryPosition::resume(ascending[3_999].position()), 100),
                &source,
            )
            .await
            .unwrap();
        assert_eq!(untouched.data[0].signature, ascending[4_000].signature);
    }

    #[tokio::test]
    async fn a_slow_page_does_not_block_another_page_of_the_snapshot() {
        let history = FinalizedHistory::default();
        let mut source = Source::new(&[entry(1), entry(2), entry(3)]);
        source.held = Some(entry(2).signature);
        history
            .read(request(HistoryPosition::default()), &source)
            .await
            .unwrap();
        let slow = history.read(
            request(HistoryPosition::resume(entry(1).position())),
            &source,
        );
        let fast = async {
            let page = tokio::time::timeout(
                Duration::from_secs(2),
                history.read(
                    request(HistoryPosition::resume(entry(2).position())),
                    &source,
                ),
            )
            .await;
            source.release.notify_one();
            page
        };
        let (slow, fast) = tokio::join!(slow, fast);
        assert_eq!(
            fast.expect("the slow page blocked").unwrap().data[0].slot,
            3
        );
        assert_eq!(slow.unwrap().data[0].slot, 2);
    }

    #[tokio::test]
    async fn continuations_waiting_on_one_refresh_reuse_it() {
        let history = FinalizedHistory::default();
        let source = Source::new(&[entry(1), entry(2), entry(3)]);
        source.hold_walk.store(true, Ordering::SeqCst);
        let first = history.read(
            request(HistoryPosition::resume(entry(1).position())),
            &source,
        );
        let second = history.read(
            request(HistoryPosition::resume(entry(2).position())),
            &source,
        );
        let release = async {
            tokio::task::yield_now().await;
            source.release.notify_one();
        };
        let (first, second, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(first, second, release)
        })
        .await
        .unwrap();
        assert_eq!(first.unwrap().data[0].slot, 2);
        assert_eq!(second.unwrap().data[0].slot, 3);
        assert_eq!(source.tips.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tag_pages_bound_work_by_examined_signatures() {
        let history = FinalizedHistory::default();
        let source = Source::new(&[entry(1), entry(2), entry(3)]);
        let mut page = request(HistoryPosition::default());
        page.selection = HistorySelection::Tag([9; 32]);
        let page = history.read(page, &source).await.unwrap();
        assert_eq!(page.data.len(), 1);
        assert!(page.data[0].events.is_empty());
        assert_eq!(page.pagination_token, Some(entry(1).position()));
        assert_eq!(source.origin_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_omitted_event_stops_the_page_and_can_retry() {
        let history = FinalizedHistory::default();
        let mut source = Source::new(&[entry(1)]);
        let mut second = transaction(entry(1));
        second.event_index = Some(1);
        source
            .transactions
            .get_mut(&entry(1).signature)
            .unwrap()
            .push(second.clone());
        assert!(history
            .read(request(HistoryPosition::default()), &source)
            .await
            .is_err());
        source
            .indexed
            .lock()
            .unwrap()
            .get_mut(&entry(1).signature)
            .unwrap()
            .push(IndexedShieldedTransaction {
                event_index: 1,
                transaction: second,
            });
        let page = history
            .read(request(HistoryPosition::default()), &source)
            .await
            .unwrap();
        assert_eq!(page.data[0].events.len(), 2);
        assert_eq!(source.signature_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_duplicate_indexed_event_stops_the_page() {
        let history = FinalizedHistory::default();
        let source = Source::new(&[entry(1)]);
        {
            let mut indexed = source.indexed.lock().unwrap();
            let rows = indexed.get_mut(&entry(1).signature).unwrap();
            rows.push(rows[0].clone());
        }
        assert!(history
            .read(request(HistoryPosition::default()), &source)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn an_orphaned_index_row_cannot_replace_a_canonical_event() {
        let history = FinalizedHistory::default();
        let source = Source::new(&[entry(2)]);
        source.indexed.lock().unwrap().insert(
            entry(2).signature,
            vec![IndexedShieldedTransaction {
                event_index: 0,
                transaction: transaction(entry(1)),
            }],
        );
        assert!(history
            .read(request(HistoryPosition::default()), &source)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn restart_reads_only_canonical_signatures_after_the_checkpoint() {
        let source = Source::new(&[entry(1), entry(3)]);
        source.indexed.lock().unwrap().insert(
            entry(2).signature,
            vec![IndexedShieldedTransaction {
                event_index: 0,
                transaction: transaction(entry(2)),
            }],
        );
        let page = FinalizedHistory::default()
            .read(request(HistoryPosition::after_slot(1)), &source)
            .await
            .unwrap();
        assert_eq!(page.data[0].signature, entry(3).signature);
        assert_eq!(page.context.slot, 3);
        assert!(page.pagination_token.is_none());
    }

    #[tokio::test]
    async fn a_finalized_snapshot_excludes_later_signatures() {
        let source = Source::new(&[entry(1), entry(2)]);
        source.through.store(1, Ordering::SeqCst);
        let page = FinalizedHistory::default()
            .read(request(HistoryPosition::default()), &source)
            .await
            .unwrap();
        assert_eq!(page.data.len(), 1);
        assert_eq!(page.data[0].slot, 1);
        assert!(page.pagination_token.is_none());
        assert_eq!(page.context.slot, 1);
        assert_eq!(source.min_context.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn production_reads_require_finality_and_the_snapshot_slot() {
        use jsonrpsee::{server::ServerBuilder, types::ErrorObjectOwned, RpcModule};

        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let mut module = RpcModule::new(());
        module
            .register_method("getSlot", |params, _, _| {
                let value: serde_json::Value = params.parse().unwrap();
                assert_eq!(value[0]["commitment"], "finalized");
                Ok::<_, ErrorObjectOwned>(9u64)
            })
            .unwrap();
        module
            .register_method("getBlockTime", |params, _, _| {
                let value: serde_json::Value = params.parse().unwrap();
                assert_eq!(value[0], 9);
                Ok::<_, ErrorObjectOwned>(99i64)
            })
            .unwrap();
        module
            .register_method("getSignaturesForAddress", |params, _, _| {
                let value: serde_json::Value = params.parse().unwrap();
                assert_eq!(value[0], RING.to_string());
                assert_eq!(value[1]["commitment"], "finalized");
                assert_eq!(value[1]["minContextSlot"], 9);
                assert_eq!(value[1]["limit"], SIGNATURE_PAGE_SIZE);
                Ok::<_, ErrorObjectOwned>(json!([{
                    "signature": entry(1).signature.to_string(), "slot": 1,
                    "err": null, "memo": null, "blockTime": 1,
                    "confirmationStatus": "finalized"
                }]))
            })
            .unwrap();
        module.register_method("getTransaction", |params, _, _| {
            let value: serde_json::Value = params.parse().unwrap();
            assert_eq!(value[0], entry(1).signature.to_string());
            assert_eq!(value[1]["commitment"], "finalized");
            assert_eq!(value[1]["maxSupportedTransactionVersion"], 1);
            Ok::<_, ErrorObjectOwned>(json!({
                "slot": 1, "blockTime": 1,
                "transaction": {
                    "signatures": [entry(1).signature.to_string()],
                    "message": {
                        "header": {"numRequiredSignatures": 1, "numReadonlySignedAccounts": 0, "numReadonlyUnsignedAccounts": 0},
                        "accountKeys": [RING.to_string()],
                        "recentBlockhash": Address::default().to_string(),
                        "instructions": []
                    }
                },
                "meta": {"err": null, "status": {"Ok": null}, "fee": 0, "preBalances": [1], "postBalances": [1], "innerInstructions": []},
                "version": "legacy"
            }))
        }).unwrap();
        let handle = server.start(module);
        let url = format!("http://{address}");
        let rpc = AsyncSolanaRpc::new(&url);
        let indexer = AsyncSprIndexer::new(&url);
        let page = FinalizedHistory::default()
            .page(
                request(HistoryPosition::default()),
                &FinalizedUpstreams {
                    rpc: &rpc,
                    indexer: &indexer,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            page.context,
            Context {
                slot: 9,
                block_time: 99
            }
        );
        assert_eq!(page.data.len(), 1);
        assert!(page.data[0].events.is_empty());
        handle.stop().unwrap();
        handle.stopped().await;
    }
}
