use std::{
    collections::BTreeSet,
    future::Future,
    ops::RangeInclusive,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use custom_ring_interface::{
    instruction::tag, MemberRegistry, RecordQueue, RingAccount, STORAGE_PROGRAM_ID,
};
use futures::{stream, StreamExt};
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use solana_account::Account;
use solana_address::Address;
use solana_transaction_status_client_types::TransactionDetails;
use spr_interface::state::{discriminator::RING_CONFIG, RingConfig};
use thiserror::Error;
use zolana_ring_indexer::records::{self, RecordCall, RecordChange, RegistryAccounts};

use crate::{
    block::{BlockInfo, BlockMetadata, Instruction, TransactionInfo},
    member_registry::{self, Projection},
    rpc::{RpcError, SolanaRpc},
    storage::{
        self, BlockJournal, BlockUndo, HistoryRoot, PendingRing, RegistryState, RegistryStore,
        RingCursor, StorageState, StorageStore, StorageUndo, Undo,
    },
    storage_registry::{self, StorageCall, StorageProjection},
};

const MAX_RETRY_DELAY_SECS: u64 = 15;
const GET_BLOCKS_PAGE: u64 = 4096;
/// Lower bound on the blocks fetched before a batch is applied.
pub(crate) const MIN_BLOCK_BATCH: usize = 32;
const ACCOUNTS_PER_REQUEST: usize = 100;
/// Journal rows older than the deepest confirmed fork are pruned.
const JOURNAL_RETENTION_SLOTS: u64 = 8_192;
/// Only a pending ring without its registry and queue on chain expires.
pub(crate) const PENDING_TTL_SLOTS: u64 = 43_200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartSlot {
    /// Refused when the stored cursor started elsewhere.
    Slot(u64),
    /// The confirmed slot when the index is created.
    Latest,
}

impl FromStr for StartSlot {
    type Err = std::num::ParseIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "latest" => Ok(Self::Latest),
            slot => slot.parse().map(Self::Slot),
        }
    }
}

/// Set once the index first reaches the confirmed tip.
#[derive(Clone, Debug, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn mark(&self) {
        self.0.store(true, Ordering::Release);
    }
}

pub(crate) struct Indexer {
    pub db: Arc<DatabaseConnection>,
    pub rpc: Arc<SolanaRpc>,
    /// `None` resumes the stored cursor only.
    pub start: Option<StartSlot>,
    /// Concurrent `getBlock` requests.
    pub block_fetches: usize,
    pub readiness: Readiness,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Progress {
    CaughtUp,
    Behind,
}

impl Indexer {
    /// Two rounds of fetches per batch bound the blocks held in memory.
    fn batch_len(&self) -> usize {
        MIN_BLOCK_BATCH.max(self.block_fetches.saturating_mul(2))
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut delay = 1;
            loop {
                match self.synchronize().await {
                    Ok(Progress::Behind) => {
                        delay = 1;
                        continue;
                    }
                    Ok(Progress::CaughtUp) => {
                        self.readiness.mark();
                        delay = 1;
                    }
                    Err(error) => {
                        log::error!("ring indexer failed ({error:#})");
                        if let Err(error) = self.suspend().await {
                            log::error!("cannot mark ring lookups unavailable ({error:#})");
                        }
                        delay = (delay * 2).min(MAX_RETRY_DELAY_SECS);
                    }
                }
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        })
    }

    pub(crate) async fn synchronize(&self) -> Result<Progress> {
        let db = self.db.as_ref();
        let mut cursor = self.cursor().await?;
        // Orphaned commits rewind before any per-ring replay resumes.
        while let Some(tip) = &cursor.tip {
            if self.canonical(tip).await? {
                break;
            }
            self.rewind_tip(&mut cursor).await?;
        }
        self.replay_pending(&cursor).await?;
        // Scanning from the canonical tip includes slots a fork filled.
        cursor.scanned_slot = cursor.tip_slot();
        let target = self.rpc.get_slot().await?;
        if cursor.scanned_slot < target {
            cursor.suspend(db).await?;
            let batch = block_batch(
                &self.rpc,
                cursor.scanned_slot + 1..=target,
                self.batch_len(),
            )
            .await?;
            for block in self.fetch_blocks(batch.slots).await {
                let block = block?;
                if cursor
                    .tip
                    .as_ref()
                    .is_some_and(|tip| !tip.is_parent_of(&block.metadata))
                {
                    bail!("ring block parent mismatch");
                }
                let tx = db.begin().await?;
                self.apply_block(&tx, &block, &mut cursor).await?;
                tx.commit().await?;
            }
            cursor.scanned_slot = batch.scanned_slot;
            storage::save_cursor(db, &cursor).await?;
            let pruned_below = cursor.scanned_slot.saturating_sub(JOURNAL_RETENTION_SLOTS);
            storage::prune(db, pruned_below).await?;
        }
        if cursor.scanned_slot < target {
            return Ok(Progress::Behind);
        }
        // Invalid ring accounts must not serve proofs.
        self.check_registries(&cursor, target).await?;
        cursor.resume(db).await?;
        Ok(Progress::CaughtUp)
    }

    /// The cursor stores the last scanned slot, one before the first indexed one.
    pub(crate) async fn cursor(&self) -> Result<RingCursor> {
        let db = self.db.as_ref();
        match (storage::cursor(db).await?, self.start) {
            (Some(cursor), Some(StartSlot::Slot(slot)))
                if cursor.start_slot != slot.saturating_sub(1) =>
            {
                bail!(
                    "the stored ring index starts after slot {}, not before slot {slot}",
                    cursor.start_slot
                )
            }
            (Some(cursor), _) => Ok(cursor),
            (None, start) => {
                let scanned = match start.context("the ring index is empty, pass a start slot")? {
                    StartSlot::Slot(slot) => slot.saturating_sub(1),
                    StartSlot::Latest => self.rpc.get_slot().await?,
                };
                let cursor = RingCursor::new(scanned);
                storage::save_cursor(db, &cursor).await?;
                Ok(cursor)
            }
        }
    }

    async fn suspend(&self) -> Result<()> {
        let db = self.db.as_ref();
        if let Some(mut cursor) = storage::cursor(db).await? {
            cursor.suspend(db).await?;
        }
        Ok(())
    }

    pub(crate) async fn rewind_tip(&self, cursor: &mut RingCursor) -> Result<()> {
        let db = self.db.as_ref();
        cursor.suspend(db).await?;
        let tx = db.begin().await?;
        storage::rollback(&tx, cursor).await?;
        tx.commit().await?;
        Ok(())
    }

    /// A pruned slot reads as noncanonical.
    async fn canonical(&self, meta: &BlockMetadata) -> Result<bool> {
        match self
            .rpc
            .get_block(meta.slot, TransactionDetails::None)
            .await
        {
            Ok(block) => Ok(block.blockhash == meta.blockhash.to_string()),
            Err(error) if error.is_slot_skipped() => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    async fn replay_pending(&self, cursor: &RingCursor) -> Result<()> {
        let db = self.db.as_ref();
        let Some(tip) = &cursor.tip else {
            return Ok(());
        };
        let pending = storage::pending(db).await?;
        let programs = pending
            .iter()
            .map(|candidate| Address::new_from_array(candidate.program))
            .collect::<Vec<_>>();
        let registered = registered_rings(&self.rpc, &programs).await?;
        for (candidate, registered) in pending.into_iter().zip(registered) {
            if !registered {
                if candidate.replayed_tip.is_none()
                    && !candidate.registry_seen
                    && candidate.slot < tip.slot.saturating_sub(PENDING_TTL_SLOTS)
                {
                    match registry_on_chain(&self.rpc, &candidate).await {
                        Ok(true) => {
                            let seen = PendingRing {
                                registry_seen: true,
                                ..candidate
                            };
                            storage::checkpoint_pending(db, &seen).await?;
                        }
                        Ok(false) => storage::delete_pending(db, &candidate.program).await?,
                        // A failed read defers the candidate alone.
                        Err(error) => log::warn!(
                            "ring {} registry check deferred ({error:#})",
                            Address::new_from_array(candidate.program)
                        ),
                    }
                }
                continue;
            }
            if let Err(error) = self.replay_ring(&candidate, tip).await {
                // The checkpoint confines replay retries to the affected ring.
                log::warn!(
                    "ring {} replay paused ({error:#})",
                    Address::new_from_array(candidate.program)
                );
            }
        }
        Ok(())
    }

    /// Other rings keep serving, only the candidate's instructions are applied.
    async fn replay_ring(&self, candidate: &PendingRing, tip: &BlockMetadata) -> Result<()> {
        let db = self.db.as_ref();
        let mut candidate = candidate.clone();
        // Resume only while the last durable replay block remains canonical.
        if let Some(checkpoint) = &candidate.replayed_tip {
            if !self.canonical(checkpoint).await? {
                bail!("ring replay checkpoint is no longer canonical, waiting for rollback");
            }
        }
        let mut start = candidate
            .replayed_tip
            .as_ref()
            .map_or(Ok(candidate.slot), |tip| {
                tip.slot.checked_add(1).context("slot overflow")
            })?;
        while start <= tip.slot {
            let end = tip.slot.min(start.saturating_add(GET_BLOCKS_PAGE - 1));
            let page = confirmed_page(&self.rpc, start..=end).await?;
            if candidate.replayed_tip.is_none() && page.first() != Some(&candidate.slot) {
                bail!("ring initialization is missing from archive history");
            }
            for chunk in page.chunks(self.batch_len()) {
                for block in self.fetch_blocks(chunk.to_vec()).await {
                    let block = block?;
                    if candidate.replayed_tip.is_none()
                        && block.metadata.blockhash != candidate.blockhash
                    {
                        bail!("ring initialization is no longer canonical");
                    }
                    if candidate
                        .replayed_tip
                        .as_ref()
                        .is_some_and(|checkpoint| !checkpoint.is_parent_of(&block.metadata))
                    {
                        bail!("ring replay parent mismatch");
                    }
                    let journal = storage::journal(db, block.metadata.slot).await?;
                    if journal.as_ref().is_some_and(|journal| {
                        journal.metadata.blockhash != block.metadata.blockhash
                    }) {
                        bail!("ring replay crossed a confirmed fork");
                    }
                    // Replay progress and undo data must commit together.
                    let tx = db.begin().await?;
                    let undo = self
                        .index_block(&tx, &block, Scope::Ring(candidate.program))
                        .await?;
                    if let Some(mut journal) = journal {
                        journal.undo.extend(undo);
                        storage::save_journal(&tx, &journal).await?;
                    }
                    candidate.replayed_tip = Some(block.metadata.clone());
                    storage::checkpoint_pending(&tx, &candidate).await?;
                    tx.commit().await?;
                }
            }
            start = end.checked_add(1).context("slot overflow")?;
        }
        // Serve the ring only after replay reaches the global tip.
        if !candidate.replayed_tip.as_ref().is_some_and(|checkpoint| {
            checkpoint.slot == tip.slot && checkpoint.blockhash == tip.blockhash
        }) {
            bail!("ring replay has not reached the confirmed ring tip");
        }
        storage::delete_pending(db, &candidate.program).await
    }

    async fn fetch_blocks(&self, slots: Vec<u64>) -> Vec<Result<BlockInfo>> {
        stream::iter(slots)
            .map(|slot| async move {
                let block = self.rpc.get_block(slot, TransactionDetails::Full).await?;
                Ok(BlockInfo::parse(block, slot)?)
            })
            .buffered(self.block_fetches.max(1))
            .collect()
            .await
    }

    pub(crate) async fn apply_block(
        &self,
        tx: &DatabaseTransaction,
        block: &BlockInfo,
        cursor: &mut RingCursor,
    ) -> Result<()> {
        let scope = Scope::every(tx).await?;
        let undo = self.index_block(tx, block, scope).await?;
        storage::save_journal(
            tx,
            &BlockJournal {
                metadata: block.metadata.clone(),
                previous_tip: cursor.tip.clone(),
                undo,
            },
        )
        .await?;
        cursor.tip = Some(block.metadata.clone());
        cursor.scanned_slot = block.metadata.slot;
        cursor.suspend(tx).await
    }

    async fn index_block(
        &self,
        tx: &DatabaseTransaction,
        block: &BlockInfo,
        scope: Scope,
    ) -> Result<BlockUndo> {
        BlockWork {
            tx,
            block,
            scope,
            env: BlockEnv { rpc: &self.rpc },
        }
        .run()
        .await
    }

    async fn check_registries(&self, cursor: &RingCursor, target: u64) -> Result<()> {
        let db = self.db.as_ref();
        for state in storage::registries(db).await? {
            if state.fault.is_some() || storage::pending_ring(db, &state.program).await?.is_some() {
                continue;
            }
            let read = ChainRead {
                state: &state,
                min_slot: target,
            };
            match read.load(&self.rpc).await {
                // Each read checks the exact accounts it serves.
                Ok(_) => {}
                Err(ApplyError::Retry(error)) => return Err(error),
                Err(ApplyError::Fault(reason)) => {
                    if self.rpc.get_slot().await? > target {
                        continue;
                    }
                    let tip = cursor
                        .tip
                        .as_ref()
                        .context("registry exists without a ring index tip")?;
                    let tx = db.begin().await?;
                    let mut journal = storage::journal(&tx, tip.slot)
                        .await?
                        .context("ring journal gap")?;
                    let undo = RegistryStore::new(&tx, state.program)
                        .quarantine(state, reason)
                        .await?;
                    journal.undo.records.push(undo);
                    storage::save_journal(&tx, &journal).await?;
                    tx.commit().await?;
                }
            }
        }
        Ok(())
    }
}

enum Scope {
    /// A pending ring waits for its own replay.
    Every {
        registries: BTreeSet<[u8; 32]>,
        pending: BTreeSet<[u8; 32]>,
    },
    Ring([u8; 32]),
}

impl Scope {
    async fn every(tx: &DatabaseTransaction) -> Result<Self> {
        Ok(Self::Every {
            registries: storage::registry_programs(tx).await?,
            pending: storage::pending_programs(tx).await?,
        })
    }

    fn covers(&self, instruction: &Instruction) -> bool {
        let program = instruction.program_id.as_array();
        match self {
            Self::Every {
                registries,
                pending,
            } => {
                let creation = instruction.data.first() == Some(&tag::CREATE_MEMBER_REGISTRY);
                !pending.contains(program) && (creation || registries.contains(program))
            }
            Self::Ring(ring) => ring == program,
        }
    }

    fn holds(&self, program: &[u8; 32]) -> bool {
        match self {
            Self::Every { registries, .. } => registries.contains(program),
            Self::Ring(ring) => ring == program,
        }
    }

    fn hold(&mut self, program: [u8; 32]) {
        if let Self::Every { registries, .. } = self {
            registries.insert(program);
        }
    }

    fn park(&mut self, program: [u8; 32]) {
        if let Self::Every { pending, .. } = self {
            pending.insert(program);
        }
    }

    /// A ring replay leaves storage registries to the global pass.
    fn projects_storage(&self) -> bool {
        matches!(self, Self::Every { .. })
    }
}

fn instruction_view(instruction: &Instruction) -> zolana_ring_indexer::InstructionView<'_> {
    zolana_ring_indexer::InstructionView {
        program_id: &instruction.program_id,
        accounts: &instruction.accounts,
        data: &instruction.data,
    }
}

#[derive(Debug, Error)]
pub(crate) enum ApplyError {
    /// Confined to one ring.
    #[error("{0}")]
    Fault(String),
    #[error(transparent)]
    Retry(#[from] anyhow::Error),
}

impl From<sea_orm::DbErr> for ApplyError {
    fn from(error: sea_orm::DbErr) -> Self {
        Self::Retry(error.into())
    }
}

impl From<RpcError> for ApplyError {
    fn from(error: RpcError) -> Self {
        Self::Retry(error.into())
    }
}

pub(crate) fn fault(reason: impl Into<String>) -> ApplyError {
    ApplyError::Fault(reason.into())
}

pub(crate) trait Quarantine {
    type State;
    type Undo;

    fn undo(&self, before: Option<Self::State>) -> Self::Undo;

    fn quarantine(
        &self,
        before: Self::State,
        reason: String,
    ) -> impl Future<Output = Result<Self::Undo>> + Send;
}

async fn settle<Q: Quarantine>(
    store: &Q,
    before: Q::State,
    outcome: Result<(), ApplyError>,
) -> Result<Q::Undo> {
    match outcome {
        Ok(()) => Ok(store.undo(Some(before))),
        Err(ApplyError::Fault(reason)) => store.quarantine(before, reason).await,
        Err(ApplyError::Retry(error)) => Err(error),
    }
}

/// A refused change writes no row.
async fn keep(
    savepoint: DatabaseTransaction,
    saved: Result<(), ApplyError>,
) -> Result<(), ApplyError> {
    match saved {
        Ok(()) => savepoint.commit().await?,
        Err(_) => savepoint.rollback().await?,
    }
    saved
}

/// A database failure retries, any other storage error is the ring's deterministic inconsistency.
pub(crate) fn from_storage(error: anyhow::Error) -> ApplyError {
    if error.chain().any(|cause| cause.is::<sea_orm::DbErr>()) {
        return ApplyError::Retry(error);
    }
    fault(format!("{error:#}"))
}

pub(crate) struct ChainRegistry {
    pub registry: Box<MemberRegistry>,
    pub queue: Box<RecordQueue>,
}

impl ChainRegistry {
    pub fn holds(&self, root: &HistoryRoot) -> bool {
        self.registry
            .history
            .get(usize::from(root.history_index))
            .is_some_and(|entry| entry.root == root.root && entry.applied() == root.applied)
    }

    /// Every field outside the policy, the projection replays no policy write.
    pub fn records_match(&self, state: &RegistryState) -> bool {
        let projected = &*state.registry;
        let chain = MemberRegistry {
            policy_hash: projected.policy_hash,
            sources: projected.sources,
            rules: projected.rules,
            generation: projected.generation,
            generation_slot: projected.generation_slot,
            ..*self.registry
        };
        chain == *projected
    }

    pub fn queue_matches(&self, state: &RegistryState) -> bool {
        self.queue == state.queue
            && self.registry.current_root() == state.registry.current_root()
            && self.registry.next_index == state.registry.next_index
    }
}

pub(crate) struct ChainRead<'s> {
    pub state: &'s RegistryState,
    pub min_slot: u64,
}

impl ChainRead<'_> {
    /// A missing or foreign registry or queue account is the ring's fault.
    pub async fn load(self, rpc: &SolanaRpc) -> Result<ChainRegistry, ApplyError> {
        let program = Address::new_from_array(self.state.program);
        let addresses =
            [self.state.registry_address, self.state.queue_address].map(Address::new_from_array);
        let read = rpc
            .get_multiple_accounts_from_slot(&addresses, self.min_slot)
            .await?;
        let [registry, queue] = <[Option<Account>; 2]>::try_from(read)
            .map_err(|accounts| anyhow!("RPC answered {} accounts for 2", accounts.len()))?;
        let registry = registry
            .and_then(|account| MemberRegistry::decode(&account.owner, &program, &account.data))
            .ok_or_else(|| fault("member registry is not the ring's initialized account"))?;
        let queue = queue
            .and_then(|account| RecordQueue::decode(&account.owner, &program, &account.data))
            .ok_or_else(|| fault("record queue is not the ring's initialized account"))?;
        Ok(ChainRegistry {
            registry: Box::new(registry),
            queue: Box::new(queue),
        })
    }
}

pub(crate) struct BlockEnv<'a> {
    rpc: &'a SolanaRpc,
}

struct BlockWork<'a> {
    tx: &'a DatabaseTransaction,
    block: &'a BlockInfo,
    scope: Scope,
    env: BlockEnv<'a>,
}

impl BlockWork<'_> {
    async fn run(mut self) -> Result<BlockUndo> {
        let mut undo = BlockUndo::default();
        let block = self.block;
        for transaction in block.transactions.iter().filter(|tx| tx.error.is_none()) {
            for instruction in instructions(transaction) {
                if instruction.program_id == STORAGE_PROGRAM_ID {
                    self.project_storage(instruction, &mut undo.storage).await?;
                } else {
                    self.project(instruction, &mut undo.records).await?;
                }
            }
        }
        Ok(undo)
    }

    async fn project(&mut self, instruction: &Instruction, undo: &mut Vec<Undo>) -> Result<()> {
        if !self.scope.covers(instruction) {
            return Ok(());
        }
        let program = instruction.program_id.to_bytes();
        let Some(call) = records::decode(instruction_view(instruction)).transpose() else {
            return Ok(());
        };
        let store = RegistryStore::new(self.tx, program);
        let change = match call {
            Ok(RecordCall::Create(accounts)) => {
                undo.extend(self.initialize(&store, &accounts).await?);
                return Ok(());
            }
            Ok(RecordCall::Change(change)) => Ok(*change),
            Err(_) if !self.scope.holds(&program) => return Ok(()),
            Err(error) => Err(fault(error.to_string())),
        };
        let Some(state) = store.state().await?.filter(|state| state.fault.is_none()) else {
            return Ok(());
        };
        let outcome = match change {
            Ok(change) => self.advance(state.clone(), change).await,
            Err(error) => Err(error),
        };
        undo.push(settle(&store, state, outcome).await?);
        Ok(())
    }

    async fn project_storage(
        &mut self,
        instruction: &Instruction,
        undo: &mut Vec<StorageUndo>,
    ) -> Result<()> {
        let Some(decoded) =
            storage_registry::decode(instruction).filter(|_| self.scope.projects_storage())
        else {
            return Ok(());
        };
        let store = StorageStore::new(self.tx, decoded.registry.to_bytes());
        let Some(state) = store.state().await? else {
            if let Ok(StorageCall::Initialize(init)) = &decoded.call {
                if let Some(created) = init.state(decoded.registry) {
                    storage_registry::create(&store, &created).await?;
                    undo.push(store.undo(None));
                }
            }
            return Ok(());
        };
        if state.fault.is_some() {
            return Ok(());
        }
        let outcome = match decoded.call {
            Ok(call) => self.advance_storage(state.clone(), call).await,
            Err(error) => Err(fault(error.to_string())),
        };
        undo.push(settle(&store, state, outcome).await?);
        Ok(())
    }

    /// `false` parks an inactive ring for replay once it activates.
    async fn admit(&mut self, program: [u8; 32]) -> Result<bool> {
        if registered_ring(self.env.rpc, &Address::new_from_array(program)).await? {
            return Ok(true);
        }
        if matches!(self.scope, Scope::Ring(_)) {
            bail!("ring became inactive during replay");
        }
        storage::save_pending(
            self.tx,
            &PendingRing {
                program,
                slot: self.block.metadata.slot,
                blockhash: self.block.metadata.blockhash.clone(),
                replayed_tip: None,
                registry_seen: false,
            },
        )
        .await?;
        self.scope.park(program);
        Ok(false)
    }

    async fn initialize(
        &mut self,
        store: &RegistryStore<'_, DatabaseTransaction>,
        accounts: &RegistryAccounts,
    ) -> Result<Option<Undo>> {
        let slot = self.block.metadata.slot;
        let state = member_registry::created(store.program, slot);
        if *accounts != state.accounts() || !self.admit(store.program).await? {
            return Ok(None);
        }
        if let Some(existing) = store.state().await? {
            let reason = "initialized twice".into();
            return Ok(Some(store.quarantine(existing, reason).await?));
        }
        let read = ChainRead {
            state: &state,
            min_slot: slot,
        };
        match read.load(self.env.rpc).await {
            Ok(_) => member_registry::create(store, &state).await?,
            Err(ApplyError::Fault(reason)) => {
                store.quarantine(state, reason).await?;
            }
            Err(ApplyError::Retry(error)) => return Err(error),
        }
        self.scope.hold(store.program);
        Ok(Some(store.undo(None)))
    }

    /// A refused change writes no row.
    async fn advance(
        &mut self,
        mut state: RegistryState,
        change: RecordChange,
    ) -> Result<(), ApplyError> {
        let savepoint = self.tx.begin().await?;
        let store = RegistryStore::new(&savepoint, state.program);
        let projection = Projection {
            store: &store,
            state: &mut state,
            slot: self.block.metadata.slot,
        };
        let saved = match projection.project(change).await {
            Ok(()) => store.save_state(&state).await.map_err(ApplyError::Retry),
            Err(error) => Err(error),
        };
        keep(savepoint, saved).await
    }

    async fn advance_storage(
        &self,
        mut state: StorageState,
        call: StorageCall<'_>,
    ) -> Result<(), ApplyError> {
        let savepoint = self.tx.begin().await?;
        let store = StorageStore::new(&savepoint, state.registry);
        let projection = StorageProjection {
            store: &store,
            state: &mut state,
            slot: self.block.metadata.slot,
        };
        let saved = match projection.project(call).await {
            Ok(()) => store.save_state(&state).await.map_err(ApplyError::Retry),
            Err(error) => Err(error),
        };
        keep(savepoint, saved).await
    }
}

/// Collected, an iterator held across an await leaves the block future not `Send`.
fn instructions(transaction: &TransactionInfo) -> Vec<&Instruction> {
    transaction
        .instruction_groups
        .iter()
        .flat_map(|group| {
            std::iter::once(&group.outer_instruction).chain(group.inner_instructions.iter())
        })
        .collect()
}

async fn registered_ring(rpc: &SolanaRpc, program: &Address) -> Result<bool> {
    Ok(registered_rings(rpc, std::slice::from_ref(program)).await? == [true])
}

async fn registry_on_chain(rpc: &SolanaRpc, ring: &PendingRing) -> Result<bool> {
    let state = member_registry::created(ring.program, ring.slot);
    let read = ChainRead {
        state: &state,
        min_slot: ring.slot,
    };
    match read.load(rpc).await {
        Ok(_) => Ok(true),
        Err(ApplyError::Fault(_)) => Ok(false),
        Err(ApplyError::Retry(error)) => Err(error),
    }
}

async fn registered_rings(rpc: &SolanaRpc, programs: &[Address]) -> Result<Vec<bool>> {
    let mut registered = Vec::with_capacity(programs.len());
    for chunk in programs.chunks(ACCOUNTS_PER_REQUEST) {
        let addresses = chunk
            .iter()
            .map(|program| spr_interface::pda::ring_auth(program).0)
            .collect::<Vec<_>>();
        let accounts = rpc.get_multiple_accounts(&addresses).await?;
        registered.extend(chunk.iter().zip(accounts).map(|(program, account)| {
            account.is_some_and(|account| activated_ring_config(&account, program))
        }));
    }
    Ok(registered)
}

fn activated_ring_config(account: &Account, program: &Address) -> bool {
    account.owner == spr_interface::pda::shielded_pool_program_id()
        && bytemuck::try_from_bytes::<RingConfig>(&account.data).is_ok_and(|config| {
            config.discriminator == RING_CONFIG
                && config.program_id == *program
                && config.is_activated()
        })
}

pub(crate) struct BlockBatch {
    pub slots: Vec<u64>,
    pub scanned_slot: u64,
}

pub(crate) async fn block_batch(
    rpc: &SolanaRpc,
    slots: RangeInclusive<u64>,
    batch_len: usize,
) -> Result<BlockBatch> {
    let mut start = *slots.start();
    let target = *slots.end();
    let mut batch = Vec::new();
    loop {
        let end = target.min(start.saturating_add(GET_BLOCKS_PAGE - 1));
        let page = confirmed_page(rpc, start..=end).await?;
        let available = batch_len - batch.len();
        if page.len() > available {
            batch.extend(page.into_iter().take(available));
            let scanned = *batch.last().context("empty block batch")?;
            return Ok(BlockBatch {
                slots: batch,
                scanned_slot: scanned,
            });
        }
        batch.extend(page);
        if end == target || batch.len() == batch_len {
            return Ok(BlockBatch {
                slots: batch,
                scanned_slot: end,
            });
        }
        start = end.checked_add(1).context("slot overflow")?;
    }
}

async fn confirmed_page(rpc: &SolanaRpc, range: RangeInclusive<u64>) -> Result<Vec<u64>> {
    let page = rpc.get_blocks(range.clone()).await?;
    if page.iter().any(|slot| !range.contains(slot))
        || page.windows(2).any(|pair| pair[0] >= pair[1])
    {
        bail!("invalid confirmed block order");
    }
    Ok(page)
}
