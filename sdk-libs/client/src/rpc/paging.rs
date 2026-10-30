//! Mirrors spr-client's private paging rules, a cursor the read already followed fails it.

use std::collections::HashSet;

use spr_client::ClientError;

pub(crate) const PAGE_LIMIT: u32 = 1_000;

/// A paged read's position, a cursor the read already followed fails it.
#[derive(Debug, Default)]
pub(crate) struct PageCursor {
    current: Option<Vec<u8>>,
    followed: HashSet<Vec<u8>>,
}

impl PageCursor {
    pub(crate) fn current(&self) -> Option<Vec<u8>> {
        self.current.clone()
    }

    /// Moves past the page read at the current cursor, `false` once that page was the last.
    pub(crate) fn advance(
        &mut self,
        next: Option<Vec<u8>>,
        scanned_through: &Option<Vec<u8>>,
    ) -> Result<bool, ClientError> {
        let Some(next) = next_page(&self.current, next, scanned_through)? else {
            return Ok(false);
        };
        if !self.followed.insert(next.clone()) {
            return Err(ClientError::IndexerCursorNotAdvanced);
        }
        self.current = Some(next);
        Ok(true)
    }
}

/// The cursor after the page read with `cursor`, `None` after the last page.
pub(crate) fn next_page(
    cursor: &Option<Vec<u8>>,
    next: Option<Vec<u8>>,
    scanned_through: &Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, ClientError> {
    let Some(next) = next.filter(|_| scanned_through.is_none()) else {
        return Ok(None);
    };
    if cursor.as_ref() == Some(&next) {
        return Err(ClientError::IndexerCursorNotAdvanced);
    }
    Ok(Some(next))
}
