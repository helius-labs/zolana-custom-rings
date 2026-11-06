//! Photon matches the auditor tag on outputs and messages alike, the message match is re-applied.

use std::{
    future::Future,
    num::{NonZeroU32, NonZeroUsize},
};

use custom_ring_interface::RingMode;
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    rpc::{GetShieldedTransactionsByTagsResponse, HistoryFilters, PaginationToken},
    AsyncRpc, ClientError, IndexerRpcConfig, RingHistoryOptions,
};
use spr_keypair::{X25519Keypair, X25519Pubkey};
use spr_transaction::ShieldedTransaction;

use crate::{
    decrypt::TransactionAudit,
    encryption::auditor_view_tag,
    error::RowDisposition,
    history::{HistoryCursor, HistoryPosition, HistoryQuery, HistoryStream, PageEnd},
    origin::{ConfirmedEventKind, RingOrigin, TransactionOrigin},
    types::AuditedTransaction,
    AuditError,
};

/// One bounded read, `next_cursor` is live only when the page cap stopped it.
pub struct ScanPage<T> {
    pub transactions: Vec<T>,
    pub next_cursor: Option<HistoryCursor>,
    pub skipped: Vec<SkippedRow>,
}

/// A row that opened nothing, the read goes past it.
#[derive(Debug)]
pub struct SkippedRow {
    pub tx_signature: Signature,
    pub event_index: u16,
    pub error: AuditError,
}

pub type RingScanPage = ScanPage<ShieldedTransaction>;
pub type AuditedPage = ScanPage<AuditedTransaction>;

/// What a bounded read reached, `next` is live only when the cap stopped it.
pub(crate) struct PagesRead {
    pub transactions: Vec<ShieldedTransaction>,
    pub next: Option<PaginationToken>,
}

/// Reads until the terminal page or the cap, a page that does not answer its request fails.
pub(crate) struct Pages {
    pub position: HistoryPosition,
    pub max_pages: NonZeroUsize,
    pub page_size: NonZeroU32,
}

impl Pages {
    pub(crate) async fn read<F, Fut>(self, mut fetch: F) -> Result<PagesRead, AuditError>
    where
        F: FnMut(Option<PaginationToken>, HistoryFilters) -> Fut,
        Fut: Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>>,
    {
        let Self {
            mut position,
            max_pages,
            page_size,
        } = self;
        let mut transactions = Vec::new();
        for _ in 0..max_pages.get() {
            let page = fetch(position.token(), position.filters()).await?;
            let end = position
                .advance(&page, page_size.get())
                .map_err(|_| AuditError::InvalidHistoryPage)?;
            transactions.extend(page.data.into_iter().flat_map(|item| item.events));
            if let PageEnd::Terminal(_) = end {
                break;
            }
        }
        Ok(PagesRead {
            transactions,
            next: position.token(),
        })
    }
}

impl SkippedRow {
    /// `Err` when `error` must stop the read instead.
    pub(crate) fn of(row: &ShieldedTransaction, error: AuditError) -> Result<Self, AuditError> {
        match error.disposition() {
            RowDisposition::Retry => Err(error),
            RowDisposition::Invalid => Ok(Self {
                tx_signature: row.tx_signature,
                event_index: row.event_index.ok_or(AuditError::MissingEventIndex)?,
                error,
            }),
        }
    }
}

pub(crate) struct RowOrigins<'a, O> {
    pub origin: &'a O,
    pub ring: Address,
    pub skipped: Vec<SkippedRow>,
}

impl<O: TransactionOrigin> RowOrigins<'_, O> {
    /// `None` once the row is in `skipped`.
    pub(crate) async fn read(
        &mut self,
        row: &ShieldedTransaction,
    ) -> Result<Option<RingOrigin>, AuditError> {
        let event_index = row.event_index.ok_or(AuditError::MissingEventIndex)?;
        match self
            .origin
            .origin(row.tx_signature, event_index, self.ring)
            .await
        {
            Ok(confirmed) => Ok(Some(confirmed)),
            Err(error) => {
                self.skipped.push(SkippedRow::of(row, error)?);
                Ok(None)
            }
        }
    }
}

const DEFAULT_PAGE_SIZE: NonZeroU32 = NonZeroU32::new(100).unwrap();
const DEFAULT_MAX_PAGES: NonZeroUsize = NonZeroUsize::new(32).unwrap();
pub(crate) const RING_HISTORY_PAGE_SIZE: NonZeroU32 = NonZeroU32::new(1000).unwrap();
pub(crate) const RING_HISTORY_MAX_PAGES: NonZeroUsize = NonZeroUsize::new(4096).unwrap();

/// The ring history rows of `kinds` the ring invoked, each bound to its confirmed event.
pub(crate) struct RingHistory<'a> {
    pub ring: Address,
    pub kinds: &'a [ConfirmedEventKind],
    pub cursor: Option<HistoryCursor>,
    pub page_size: NonZeroU32,
    pub max_pages: NonZeroUsize,
    pub indexer_config: Option<IndexerRpcConfig>,
}

impl RingHistory<'_> {
    pub(crate) async fn bound<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
    ) -> Result<ScanPage<(ShieldedTransaction, RingOrigin)>, AuditError> {
        let Self {
            ring,
            kinds,
            cursor,
            page_size,
            max_pages,
            indexer_config,
        } = self;
        let query = HistoryQuery {
            ring,
            stream: HistoryStream::Ring,
        };
        let page = Pages {
            position: query.position(cursor)?,
            max_pages,
            page_size,
        }
        .read(|pagination_token, filters| async move {
            let options = RingHistoryOptions {
                ring_program_id: ring,
                pagination_token,
                limit: Some(page_size.get()),
                filters,
            };
            indexer
                .get_shielded_transactions_by_ring(options, indexer_config)
                .await
        })
        .await?;
        let mut bound = Vec::new();
        let mut origins = RowOrigins {
            origin,
            ring,
            skipped: Vec::new(),
        };
        for mut transaction in page.transactions {
            if transaction.ring_program_id != Some(ring) {
                continue;
            }
            let Some(confirmed) = origins.read(&transaction).await? else {
                continue;
            };
            if !confirmed.ring_invoked || !kinds.contains(&confirmed.event.kind()) {
                continue;
            }
            confirmed.bind_transaction(&mut transaction, ring)?;
            bound.push((transaction, confirmed));
        }
        Ok(ScanPage {
            transactions: bound,
            next_cursor: page.next.map(|token| HistoryCursor { query, token }),
            skipped: origins.skipped,
        })
    }
}

/// A confirmed ring transfer without its mandatory disclosure fails the scan.
#[must_use = "run or discard the scan explicitly"]
pub struct RingScan {
    ring_program_id: Address,
    auditor_key: X25519Pubkey,
    mode: RingMode,
    cursor: Option<HistoryCursor>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

impl RingScan {
    pub fn new(ring_program_id: Address, auditor_key: X25519Pubkey) -> Self {
        Self {
            ring_program_id,
            auditor_key,
            mode: RingMode::Confidential,
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
            indexer_config: None,
        }
    }

    /// The rail a ring `Transact` frame parses under.
    pub fn with_mode(mut self, mode: RingMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_cursor(mut self, cursor: HistoryCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    /// Every page waits until the indexer has persisted `config.require_slot`.
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    pub async fn run<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
    ) -> Result<RingScanPage, AuditError> {
        let page = self.confirmed(indexer, origin).await?;
        Ok(ScanPage {
            transactions: page
                .transactions
                .into_iter()
                .map(|(transaction, _)| transaction)
                .collect(),
            next_cursor: page.next_cursor,
            skipped: page.skipped,
        })
    }

    /// Reads no earlier page.
    pub async fn audit<I: AsyncRpc, O: TransactionOrigin>(
        mut self,
        auditor: &X25519Keypair,
        indexer: &I,
        origin: &O,
    ) -> Result<AuditedPage, AuditError> {
        self.auditor_key = auditor.pubkey();
        let mode = self.mode;
        let page = self.confirmed(indexer, origin).await?;
        let mut transactions = Vec::with_capacity(page.transactions.len());
        let mut skipped = page.skipped;
        for (transaction, confirmed) in &page.transactions {
            let opened = confirmed
                .audit_frame(mode)
                .and_then(|frame| TransactionAudit::new(transaction, frame).run(auditor));
            match opened {
                Ok(audited) => transactions.push(audited),
                Err(error) => skipped.push(SkippedRow::of(transaction, error)?),
            }
        }
        Ok(ScanPage {
            transactions,
            next_cursor: page.next_cursor,
            skipped,
        })
    }

    /// The page's ring transfers that require an audit, each bound to its confirmed event.
    pub(crate) async fn confirmed<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
    ) -> Result<ScanPage<(ShieldedTransaction, RingOrigin)>, AuditError> {
        let view_tag = auditor_view_tag(&self.auditor_key);
        let query = HistoryQuery {
            ring: self.ring_program_id,
            stream: HistoryStream::Tags,
        };
        let page = Pages {
            position: query.position(self.cursor)?,
            max_pages: self.max_pages,
            page_size: self.page_size,
        }
        .read(|pagination_token, filters| async move {
            indexer
                .get_shielded_transactions_by_tags(
                    vec![view_tag],
                    pagination_token,
                    Some(self.page_size.get()),
                    filters,
                    self.indexer_config,
                )
                .await
        })
        .await?;
        let mut transactions = Vec::new();
        let mut origins = RowOrigins {
            origin,
            ring: self.ring_program_id,
            skipped: Vec::new(),
        };
        for mut tx in page.transactions {
            // A row of another ring never reaches the origin read.
            if tx.ring_program_id != Some(self.ring_program_id) {
                continue;
            }
            let Some(confirmed) = origins.read(&tx).await? else {
                continue;
            };
            if confirmed.requires_audit() {
                confirmed.bind_transaction(&mut tx, self.ring_program_id)?;
                if !tx
                    .messages
                    .iter()
                    .any(|message| message.view_tag == view_tag)
                {
                    return Err(AuditError::MissingAuditorMessage);
                }
                transactions.push((tx, confirmed));
            }
        }
        Ok(ScanPage {
            transactions,
            next_cursor: page.next.map(|token| HistoryCursor { query, token }),
            skipped: origins.skipped,
        })
    }
}

#[cfg(test)]
mod tests {
    use spr_client::rpc::{Context, TransactionEvents};

    use super::*;

    fn row(slot: u64, signature: u8) -> ShieldedTransaction {
        ShieldedTransaction {
            slot,
            tx_signature: Signature::from([signature; 64]),
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: Vec::new(),
            messages: Vec::new(),
            nullifiers: Vec::new(),
            proofless: false,
            ring_config: None,
            ring_program_id: None,
        }
    }

    /// Rows of one page, the token names the last when `more` holds.
    fn served(rows: Vec<ShieldedTransaction>, more: bool) -> GetShieldedTransactionsByTagsResponse {
        let pagination_token = rows
            .last()
            .filter(|_| more)
            .map(|last| PaginationToken::new(last.slot, last.tx_signature));
        GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 9,
            },
            output_tree_id: None,
            data: rows
                .into_iter()
                .map(|row| TransactionEvents {
                    slot: row.slot,
                    signature: row.tx_signature,
                    events: vec![row],
                })
                .collect(),
            pagination_token,
        }
    }

    async fn read(
        pages: Vec<GetShieldedTransactionsByTagsResponse>,
        page_size: u32,
        max_pages: usize,
    ) -> (Result<PagesRead, AuditError>, usize) {
        let fetched = std::cell::Cell::new(0);
        let result = Pages {
            position: HistoryPosition::default(),
            max_pages: NonZeroUsize::new(max_pages).unwrap(),
            page_size: NonZeroU32::new(page_size).unwrap(),
        }
        .read(|_, _| {
            let page = pages[fetched.get()].clone();
            fetched.set(fetched.get() + 1);
            async move { Ok(page) }
        })
        .await;
        (result, fetched.get())
    }

    #[tokio::test]
    async fn the_last_page_at_the_cap_completes_the_read() {
        let pages = vec![
            served(vec![row(1, 1)], true),
            served(vec![row(1, 2)], false),
        ];
        let (read, fetched) = read(pages, 2, 2).await;
        let read = read.unwrap();
        assert_eq!((read.next, read.transactions.len(), fetched), (None, 2, 2));
    }

    #[tokio::test]
    async fn the_cap_returns_the_live_token() {
        let pages = vec![served(vec![row(1, 1)], true), served(vec![row(1, 2)], true)];
        let (read, fetched) = read(pages, 2, 2).await;
        assert_eq!(
            (read.unwrap().next, fetched),
            (Some(PaginationToken::new(1, Signature::from([2; 64]))), 2)
        );
    }

    #[tokio::test]
    async fn an_empty_terminal_page_completes_the_read() {
        let (read, fetched) = read(vec![served(Vec::new(), false)], 2, 4).await;
        assert_eq!((read.unwrap().next, fetched), (None, 1));
    }

    #[tokio::test]
    async fn a_page_longer_than_its_limit_fails_the_read() {
        let pages = vec![served(vec![row(1, 1), row(1, 2)], false)];
        let (read, _) = read(pages, 1, 4).await;
        assert!(matches!(read, Err(AuditError::InvalidHistoryPage)));
    }

    #[tokio::test]
    async fn a_row_served_again_fails_the_read() {
        let pages = vec![
            served(vec![row(1, 1)], true),
            served(vec![row(1, 1), row(1, 2)], false),
        ];
        let (read, _) = read(pages, 2, 4).await;
        assert!(matches!(read, Err(AuditError::InvalidHistoryPage)));
    }

    #[tokio::test]
    async fn a_token_that_does_not_move_fails_the_read() {
        let repeated = served(vec![row(1, 1)], true);
        let (read, _) = read(vec![repeated.clone(), repeated], 2, 4).await;
        assert!(matches!(read, Err(AuditError::InvalidHistoryPage)));
    }
}
