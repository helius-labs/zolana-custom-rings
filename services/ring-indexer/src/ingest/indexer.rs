use std::{
    future::Future,
    ops::RangeInclusive,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context, Result};
use custom_ring_interface::STORAGE_PROGRAM_ID;
use futures::{stream, StreamExt};
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use solana_transaction_status_client_types::TransactionDetails;
use thiserror::Error;

use crate::{
    block::{BlockInfo, BlockMetadata, Instruction, TransactionInfo},
    rpc::{RpcError, SolanaRpc},
    storage::{self, BlockJournal, BlockUndo, RingCursor, StorageState, StorageStore, StorageUndo},
    storage_registry::{self, StorageCall, StorageProjection},
};

const MAX_RETRY_DELAY_SECS: u64 = 15;
const GET_BLOCKS_PAGE: u64 = 4096;
/// Lower bound on the blocks fetched before a batch is applied.
pub(crate) const MIN_BLOCK_BATCH: usize = 32;
/// Journal rows older than the deepest confirmed fork are pruned.
const JOURNAL_RETENTION_SLOTS: u64 = 8_192;

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
        // Orphaned commits rewind before the scan resumes.
        while let Some(tip) = &cursor.tip {
            if self.canonical(tip).await? {
                break;
            }
            self.rewind_tip(&mut cursor).await?;
        }
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
        let undo = BlockWork { tx, block }.run().await?;
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

struct BlockWork<'a> {
    tx: &'a DatabaseTransaction,
    block: &'a BlockInfo,
}

impl BlockWork<'_> {
    async fn run(self) -> Result<BlockUndo> {
        let mut undo = BlockUndo::default();
        let block = self.block;
        for transaction in block.transactions.iter().filter(|tx| tx.error.is_none()) {
            for instruction in instructions(transaction) {
                if instruction.program_id == STORAGE_PROGRAM_ID {
                    self.project_storage(instruction, &mut undo.storage).await?;
                }
            }
        }
        Ok(undo)
    }

    async fn project_storage(
        &self,
        instruction: &Instruction,
        undo: &mut Vec<StorageUndo>,
    ) -> Result<()> {
        let Some(decoded) = storage_registry::decode(instruction) else {
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
