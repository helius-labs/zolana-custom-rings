//! Indexer pages as Photon answers them, rows in position order and a token only ahead of more.

use spr_client::{
    Context, GetShieldedTransactionsByTagsResponse, PaginationToken, ShieldedTransaction,
    TransactionEvents,
};

pub fn position(row: &ShieldedTransaction) -> PaginationToken {
    PaginationToken::new(row.slot, row.tx_signature)
}

pub struct EventsPage {
    pub context: Context,
    pub output_tree_id: Option<u16>,
    pub rows: Vec<ShieldedTransaction>,
    pub more: bool,
}

impl EventsPage {
    pub fn response(self) -> GetShieldedTransactionsByTagsResponse {
        let mut rows = self.rows;
        rows.sort_by_key(position);
        let mut data: Vec<TransactionEvents<_, _>> = Vec::new();
        for row in rows {
            match data.last_mut() {
                Some(last) if PaginationToken::new(last.slot, last.signature) == position(&row) => {
                    last.events.push(row)
                }
                _ => data.push(TransactionEvents {
                    slot: row.slot,
                    signature: row.tx_signature,
                    events: vec![row],
                }),
            }
        }
        let pagination_token = data
            .last()
            .filter(|_| self.more)
            .map(|last| PaginationToken::new(last.slot, last.signature));
        GetShieldedTransactionsByTagsResponse {
            context: self.context,
            output_tree_id: self.output_tree_id,
            data,
            pagination_token,
        }
    }
}
