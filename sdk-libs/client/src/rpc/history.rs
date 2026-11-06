use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_indexer_api::{
    Base64String, Context, HistoryFilters, InvalidPage, Page, PageRequest, PaginationToken,
    Positioned,
};
use thiserror::Error;

/// Valid for one query, a floor taken from a row or a token loses the rest of its slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistoryPosition {
    after_slot: Option<u64>,
    token: Option<PaginationToken>,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageEnd {
    More,
    /// The final page's snapshot held every match through its slot, an earlier page's may be higher.
    Terminal(Context),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryStream {
    Tags,
    Ring,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryQuery {
    pub ring: Address,
    pub stream: HistoryStream,
}

/// A token alone is accepted under any query, where it skips that query's rows before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryCursor {
    pub query: HistoryQuery,
    pub token: PaginationToken,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum HistoryCursorError {
    #[error("history cursor is malformed")]
    Malformed,
    #[error("history cursor belongs to another ring or stream")]
    OtherQuery,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RecoveryWindow {
    pub page_limit: Option<u32>,
    pub after_slot: Option<u64>,
    pub target_slot: Option<u64>,
    pub token: Option<PaginationToken>,
}

impl RecoveryWindow {
    pub fn filters(self) -> HistoryFilters {
        let mut filters = self
            .after_slot
            .map_or_else(HistoryFilters::default, HistoryFilters::after_slot);
        filters.slot.lte = self.target_slot;
        filters
    }

    pub fn advance<T: Positioned>(
        &mut self,
        page: &Page<T>,
        limit: u32,
    ) -> Result<bool, InvalidPage> {
        page.validate_indexed(&PageRequest {
            pagination_token: self.token,
            limit: limit.into(),
            filters: self.filters(),
            min_context_slot: self.target_slot,
        })?;
        self.token = page.pagination_token;
        Ok(self.token.is_none())
    }
}

impl HistoryPosition {
    pub const fn resume(token: PaginationToken) -> Self {
        Self {
            after_slot: None,
            token: Some(token),
        }
    }

    /// Reads every slot above `slot`, a terminal page's `context.slot` or an enrollment floor.
    pub const fn after_slot(slot: u64) -> Self {
        Self {
            after_slot: Some(slot),
            token: None,
        }
    }

    pub const fn token(&self) -> Option<PaginationToken> {
        self.token
    }

    /// The durable form, stored in the write of the notes it covers, `None` inside a read.
    pub const fn checkpoint(&self) -> Option<u64> {
        match self.token {
            Some(_) => None,
            None => self.after_slot,
        }
    }

    pub fn filters(&self) -> HistoryFilters {
        self.after_slot
            .map_or_else(HistoryFilters::default, HistoryFilters::after_slot)
    }

    /// A refused page leaves the position in place.
    pub fn advance<T: Positioned>(
        &mut self,
        page: &Page<T>,
        limit: u32,
    ) -> Result<PageEnd, InvalidPage> {
        page.validate_indexed(&PageRequest {
            pagination_token: self.token,
            limit: limit.into(),
            filters: self.filters(),
            min_context_slot: None,
        })?;
        Ok(match page.pagination_token {
            Some(token) => {
                self.token = Some(token);
                PageEnd::More
            }
            None => {
                *self = Self {
                    after_slot: Some(page.context.slot),
                    token: None,
                };
                PageEnd::Terminal(page.context)
            }
        })
    }
}

impl HistoryStream {
    const fn name(self) -> &'static str {
        match self {
            Self::Tags => "tags",
            Self::Ring => "ring",
        }
    }
}

impl HistoryQuery {
    /// Where a read of the query starts, from `cursor` when one is given.
    pub fn position(
        self,
        cursor: Option<HistoryCursor>,
    ) -> Result<HistoryPosition, HistoryCursorError> {
        cursor.map_or(Ok(HistoryPosition::default()), |cursor| {
            if cursor.query == self {
                Ok(HistoryPosition::resume(cursor.token))
            } else {
                Err(HistoryCursorError::OtherQuery)
            }
        })
    }

    /// The cursor of a read the page cap stopped, `None` past a terminal page.
    pub fn next_cursor(self, position: &HistoryPosition) -> Option<HistoryCursor> {
        position
            .token()
            .map(|token| HistoryCursor { query: self, token })
    }
}

impl fmt::Display for HistoryCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.query.ring,
            self.query.stream.name(),
            self.token
        )
    }
}

impl FromStr for HistoryCursor {
    type Err = HistoryCursorError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut parts = text.splitn(3, ':');
        let (Some(ring), Some(stream), Some(token)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(HistoryCursorError::Malformed);
        };
        let stream = match stream {
            "tags" => HistoryStream::Tags,
            "ring" => HistoryStream::Ring,
            _ => return Err(HistoryCursorError::Malformed),
        };
        Ok(Self {
            query: HistoryQuery {
                ring: ring.parse().map_err(|_| HistoryCursorError::Malformed)?,
                stream,
            },
            token: token.parse().map_err(|_| HistoryCursorError::Malformed)?,
        })
    }
}

impl TryFrom<&[u8]> for HistoryCursor {
    type Error = HistoryCursorError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(bytes)
            .map_err(|_| HistoryCursorError::Malformed)?
            .parse()
    }
}

impl From<HistoryCursor> for Base64String {
    fn from(cursor: HistoryCursor) -> Self {
        cursor.to_string().into_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use solana_signature::Signature;
    use spr_indexer_api::TransactionEvents;

    use super::*;

    const LIMIT: u32 = 10;
    const RING: Address = Address::new_from_array([7; 32]);

    type Events = TransactionEvents<(), Signature>;

    fn token(slot: u64, signature: u8) -> PaginationToken {
        PaginationToken::new(slot, Signature::from([signature; 64]))
    }

    fn row(slot: u64, signature: u8) -> Events {
        TransactionEvents {
            slot,
            signature: Signature::from([signature; 64]),
            events: Vec::new(),
        }
    }

    fn page(context: u64, data: Vec<Events>, next: Option<PaginationToken>) -> Page<Events> {
        Page {
            context: Context {
                block_time: 0,
                slot: context,
            },
            output_tree_id: None,
            data,
            pagination_token: next,
        }
    }

    fn query(stream: HistoryStream) -> HistoryQuery {
        HistoryQuery { ring: RING, stream }
    }

    fn cursor(stream: HistoryStream) -> HistoryCursor {
        HistoryCursor {
            query: query(stream),
            token: token(5, 1),
        }
    }

    #[test]
    fn a_page_inside_a_slot_moves_only_the_token() {
        let mut position = HistoryPosition::default();
        let first = page(9, vec![row(5, 1)], Some(token(5, 1)));
        assert_eq!(position.advance(&first, LIMIT), Ok(PageEnd::More));
        assert_eq!(position.token(), Some(token(5, 1)));
        assert_eq!(position.filters(), HistoryFilters::default());
    }

    #[test]
    fn the_final_page_sets_the_floor_even_below_an_earlier_context() {
        let mut position = HistoryPosition::default();
        let first = page(9, vec![row(5, 1)], Some(token(5, 1)));
        assert_eq!(position.advance(&first, LIMIT), Ok(PageEnd::More));
        let last = page(8, vec![row(5, 2)], None);
        assert_eq!(
            position.advance(&last, LIMIT),
            Ok(PageEnd::Terminal(last.context))
        );
        assert_eq!(position.token(), None);
        assert_eq!(position.filters(), HistoryFilters::after_slot(8));
    }

    #[test]
    fn a_checkpoint_exists_only_past_a_terminal_page() {
        let mut position = HistoryPosition::after_slot(4);
        assert_eq!(position.checkpoint(), Some(4));
        let split = page(9, vec![row(5, 1)], Some(token(5, 1)));
        assert_eq!(position.advance(&split, LIMIT), Ok(PageEnd::More));
        assert_eq!(position.checkpoint(), None);
        let last = page(9, vec![row(5, 2)], None);
        assert!(position.advance(&last, LIMIT).is_ok());
        assert_eq!(position.checkpoint(), Some(9));
        assert_eq!(HistoryPosition::after_slot(9), position);
    }

    #[test]
    fn an_empty_terminal_page_still_sets_the_floor() {
        let mut position = HistoryPosition::default();
        let empty = page(4, Vec::new(), None);
        assert_eq!(
            position.advance(&empty, LIMIT),
            Ok(PageEnd::Terminal(empty.context))
        );
        assert_eq!(position.filters(), HistoryFilters::after_slot(4));
    }

    #[test]
    fn a_refused_page_leaves_the_position() {
        let mut position = HistoryPosition::default();
        let caught_up = page(8, Vec::new(), None);
        assert!(position.advance(&caught_up, LIMIT).is_ok());
        let floor = position;
        for refused in [
            // A snapshot below the floor, a rollback or a lagging replica.
            page(7, Vec::new(), None),
            // A token at the floor names a row outside the query.
            page(9, vec![row(8, 1)], Some(token(8, 1))),
            // A token with no row behind it.
            page(9, Vec::new(), Some(token(9, 1))),
        ] {
            assert_eq!(position.advance(&refused, LIMIT), Err(InvalidPage));
            assert_eq!(position, floor);
        }
    }

    #[test]
    fn a_repeated_page_is_refused() {
        let mut position = HistoryPosition::default();
        let first = page(9, vec![row(5, 1)], Some(token(5, 1)));
        assert_eq!(position.advance(&first, LIMIT), Ok(PageEnd::More));
        assert_eq!(position.advance(&first, LIMIT), Err(InvalidPage));
        assert_eq!(position.token(), Some(token(5, 1)));
    }

    #[test]
    fn a_cursor_of_another_query_is_refused() {
        let tags = Some(cursor(HistoryStream::Tags));
        assert_eq!(
            query(HistoryStream::Tags).position(tags),
            Ok(HistoryPosition::resume(token(5, 1)))
        );
        assert_eq!(
            query(HistoryStream::Ring).position(tags),
            Err(HistoryCursorError::OtherQuery)
        );
        let other_ring = HistoryQuery {
            ring: Address::new_from_array([8; 32]),
            stream: HistoryStream::Tags,
        };
        assert_eq!(
            other_ring.position(tags),
            Err(HistoryCursorError::OtherQuery)
        );
    }

    #[test]
    fn a_cursor_reads_back_from_its_text() {
        let ring = cursor(HistoryStream::Ring);
        assert_eq!(ring.to_string().parse(), Ok(ring));
        assert_eq!(
            HistoryCursor::try_from(ring.to_string().as_bytes()),
            Ok(ring)
        );
    }

    #[test]
    fn a_bare_token_or_an_old_byte_cursor_is_refused() {
        let mut old = vec![2];
        old.extend_from_slice(&5u64.to_be_bytes());
        old.extend_from_slice(&[1; 64]);
        old.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            HistoryCursor::try_from(old.as_slice()),
            Err(HistoryCursorError::Malformed)
        );
        assert_eq!(
            token(5, 1).to_string().parse::<HistoryCursor>(),
            Err(HistoryCursorError::Malformed)
        );
    }
}
