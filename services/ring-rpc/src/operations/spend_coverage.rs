use std::collections::BTreeMap;

use bytemuck::{Pod, Zeroable};
use sea_orm::{ConnectionTrait, DbErr, Statement, Value};
use solana_address::Address;
use solana_signature::Signature;
use spr_indexer_api::{Base64String, Hash};
use zolana_ring_client::rpc::{
    GetSpendCoverageResponse, SpendCoverageFrame, SpendCoverageRow, SpendCoverageTotals,
    AUDIT_PAGE_LIMIT,
};

use crate::{
    error::RingRpcError,
    projection_reads::ProjectionReads,
    spend_machine::{SpendRow, SpendState},
    spent_index::{
        first_unread, read_bytes, read_frame, read_snapshot, read_spend_row, state_name,
        ROW_COLUMNS,
    },
    utxos::{history_through, CreatedIn},
};

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub(crate) struct CoverageCursor {
    version: u8,
    unresolved_state: u8,
    unread_state: u8,
    fault_state: u8,
    ring: [u8; 32],
    unresolved: [u8; 32],
    unread_slot: [u8; 8],
    unread_signature: [u8; 64],
    unread_event: [u8; 2],
    fault_nullifier: [u8; 32],
    fault_signature: [u8; 64],
    fault_event: [u8; 2],
}

pub(crate) struct CoverageDetails {
    pub cursor: CoverageCursor,
    pub unresolved: Vec<SpendRow>,
    pub unread: Vec<CreatedIn>,
    pub faults: Vec<SpendRow>,
}

enum DetailPosition<K> {
    Start,
    After(K),
    Done,
}

struct DetailPage<T, K> {
    rows: Vec<T>,
    next: DetailPosition<K>,
}

impl CoverageCursor {
    pub(crate) fn new(ring: Address) -> Self {
        Self {
            version: 1,
            ring: ring.to_bytes(),
            ..Self::zeroed()
        }
    }

    pub(crate) fn decode(bytes: &[u8], ring: Address) -> Result<Self, RingRpcError> {
        let cursor = bytemuck::try_from_bytes::<Self>(bytes)
            .copied()
            .map_err(|_| RingRpcError::InvalidCursor)?;
        if cursor.version != 1
            || cursor.ring != ring.to_bytes()
            || [
                cursor.unresolved_state,
                cursor.unread_state,
                cursor.fault_state,
            ]
            .iter()
            .any(|state| *state > 2)
        {
            return Err(RingRpcError::InvalidCursor);
        }
        Ok(cursor)
    }

    pub(crate) fn is_first(&self) -> bool {
        [self.unresolved_state, self.unread_state, self.fault_state] == [0; 3]
    }

    fn unresolved_position(&self) -> DetailPosition<[u8; 32]> {
        DetailPosition::new(self.unresolved_state, self.unresolved)
    }

    fn unread_position(&self) -> DetailPosition<CreatedIn> {
        DetailPosition::new(
            self.unread_state,
            CreatedIn {
                slot: u64::from_le_bytes(self.unread_slot),
                tx_signature: Signature::from(self.unread_signature),
                event_index: u16::from_le_bytes(self.unread_event),
            },
        )
    }

    fn fault_position(&self) -> DetailPosition<([u8; 32], Signature, u16)> {
        DetailPosition::new(
            self.fault_state,
            (
                self.fault_nullifier,
                Signature::from(self.fault_signature),
                u16::from_le_bytes(self.fault_event),
            ),
        )
    }

    fn token(&self) -> Option<Base64String> {
        ([self.unresolved_state, self.unread_state, self.fault_state] != [2; 3])
            .then(|| bytemuck::bytes_of(self).to_vec().into())
    }
}

impl CoverageDetails {
    pub(crate) fn new(cursor: CoverageCursor) -> Self {
        Self {
            cursor,
            unresolved: Vec::new(),
            unread: Vec::new(),
            faults: Vec::new(),
        }
    }

    pub(crate) fn unresolved(&mut self, rows: impl IntoIterator<Item = SpendRow>) {
        let page = self
            .cursor
            .unresolved_position()
            .select(rows, |row| row.nullifier);
        self.cursor.unresolved_state = page.next.state();
        if let DetailPosition::After(nullifier) = page.next {
            self.cursor.unresolved = nullifier;
        }
        self.unresolved = page.rows;
    }

    pub(crate) fn unread(&mut self, rows: impl IntoIterator<Item = CreatedIn>) {
        let page = self.cursor.unread_position().select(rows, |frame| *frame);
        self.cursor.unread_state = page.next.state();
        if let DetailPosition::After(frame) = page.next {
            self.cursor.unread_slot = frame.slot.to_le_bytes();
            self.cursor.unread_signature = frame.tx_signature.into();
            self.cursor.unread_event = frame.event_index.to_le_bytes();
        }
        self.unread = page.rows;
    }

    pub(crate) fn faults(&mut self, rows: impl IntoIterator<Item = SpendRow>) {
        let page = self.cursor.fault_position().select(rows, |row| {
            (row.nullifier, row.frame.tx_signature, row.frame.event_index)
        });
        self.cursor.fault_state = page.next.state();
        if let DetailPosition::After((nullifier, signature, event)) = page.next {
            self.cursor.fault_nullifier = nullifier;
            self.cursor.fault_signature = signature.into();
            self.cursor.fault_event = event.to_le_bytes();
        }
        self.faults = page.rows;
    }

    pub(crate) fn apply(self, response: &mut GetSpendCoverageResponse) {
        let frame = |frame: CreatedIn| SpendCoverageFrame {
            slot: frame.slot,
            tx_signature: frame.tx_signature.into(),
            event_index: frame.event_index,
        };
        let row = |row: SpendRow| SpendCoverageRow {
            nullifier: Hash(row.nullifier),
            frame: frame(row.frame),
        };
        response.cursor = self.cursor.token();
        response.unresolved_real = self.unresolved.into_iter().map(row).collect();
        response.unreadable = self.unread.into_iter().map(frame).collect();
        response.integrity_faults = self.faults.into_iter().map(row).collect();
    }
}

impl<K: Ord + Clone> DetailPosition<K> {
    fn new(state: u8, key: K) -> Self {
        match state {
            0 => Self::Start,
            1 => Self::After(key),
            _ => Self::Done,
        }
    }

    fn state(&self) -> u8 {
        match self {
            Self::Start => 0,
            Self::After(_) => 1,
            Self::Done => 2,
        }
    }

    fn select<T>(
        self,
        rows: impl IntoIterator<Item = T>,
        key: impl Fn(&T) -> K,
    ) -> DetailPage<T, K> {
        let mut selected = BTreeMap::new();
        if !matches!(self, Self::Done) {
            for row in rows {
                let key = key(&row);
                if matches!(&self, Self::After(after) if key <= *after) {
                    continue;
                }
                selected.insert(key, row);
                if selected.len() > AUDIT_PAGE_LIMIT as usize + 1 {
                    selected.pop_last();
                }
            }
        }
        let more = selected.len() > AUDIT_PAGE_LIMIT as usize;
        if more {
            selected.pop_last();
        }
        let next = if more {
            selected
                .last_key_value()
                .map_or(Self::Done, |(key, _)| Self::After(key.clone()))
        } else {
            Self::Done
        };
        DetailPage {
            rows: selected.into_values().collect(),
            next,
        }
    }
}

impl ProjectionReads<'_> {
    pub(crate) async fn coverage(
        &self,
        cursor: CoverageCursor,
    ) -> Result<GetSpendCoverageResponse, DbErr> {
        let snapshot = read_snapshot(self.db).await?;
        let query = |sql: &str, values: Vec<Value>| {
            let mut bound = vec![Value::from(self.ring.as_ref().to_vec())];
            bound.extend(values);
            Statement::from_sql_and_values(snapshot.get_database_backend(), sql, bound)
        };
        let mut response = GetSpendCoverageResponse::default();
        if cursor.is_first() {
            let mut totals = SpendCoverageTotals::default();
            for row in snapshot.query_all(query(
                "SELECT state,COUNT(*) AS rows FROM finalized_spent_nullifiers WHERE ring=$1 GROUP BY state",
                Vec::new(),
            )).await? {
                let count = u64::try_from(row.try_get::<i64>("", "rows")?)
                    .map_err(|_| DbErr::Custom("negative row count".into()))?;
                match row.try_get::<String>("", "state")?.as_str() {
                    "observed" => totals.observed = count,
                    "padding" => totals.padding = count,
                    "address" => totals.address = count,
                    "external" => totals.external = count,
                    "resolved" => totals.resolved = count,
                    _ => {}
                }
            }
            response.totals = Some(totals);
        }
        if let Some(row) = snapshot
            .query_one(query(
                "SELECT after_slot,through_slot FROM spend_checkpoints WHERE ring=$1",
                Vec::new(),
            ))
            .await?
        {
            response.position_slot = row
                .try_get::<Option<i64>>("", "after_slot")?
                .map(u64::try_from)
                .transpose()
                .map_err(|_| DbErr::Custom("negative checkpoint slot".into()))?;
            let through = u64::try_from(row.try_get::<i64>("", "through_slot")?)
                .map_err(|_| DbErr::Custom("negative checkpoint slot".into()))?;
            response.history_through = history_through(
                first_unread(&snapshot, self.ring)
                    .await?
                    .map(|frame| frame.slot),
                through,
            );
        }
        let mut details = CoverageDetails::new(cursor);
        let limit = Value::from(AUDIT_PAGE_LIMIT as i64 + 1);
        if !matches!(cursor.unresolved_position(), DetailPosition::Done) {
            let mut values = vec![state_name(SpendState::UnresolvedReal).into()];
            let filter = if let DetailPosition::After(key) = cursor.unresolved_position() {
                values.push(key.to_vec().into());
                " AND nullifier>$3"
            } else {
                ""
            };
            values.push(limit.clone());
            let sql = format!("SELECT {ROW_COLUMNS} FROM finalized_spent_nullifiers WHERE ring=$1 AND state=$2{filter} ORDER BY nullifier LIMIT ${}", values.len() + 1);
            let rows = snapshot.query_all(query(&sql, values)).await?;
            details.unresolved(
                rows.iter()
                    .map(|row| read_spend_row(row, self.seal))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        if !matches!(cursor.unread_position(), DetailPosition::Done) {
            let mut values = Vec::new();
            let filter = if let DetailPosition::After(frame) = cursor.unread_position() {
                values.extend([
                    i64::try_from(frame.slot)
                        .map_err(|_| DbErr::Custom("frame slot exceeds the column range".into()))?
                        .into(),
                    frame.tx_signature.as_ref().to_vec().into(),
                    i64::from(frame.event_index).into(),
                ]);
                " AND (slot,tx_signature,event_index)>($2,$3,$4)"
            } else {
                ""
            };
            values.push(limit.clone());
            let sql = format!("SELECT slot,tx_signature,event_index FROM spend_unread_frames WHERE ring=$1{filter} ORDER BY slot,tx_signature,event_index LIMIT ${}", values.len() + 1);
            let rows = snapshot.query_all(query(&sql, values)).await?;
            details.unread(rows.iter().map(read_frame).collect::<Result<Vec<_>, _>>()?);
        }
        if !matches!(cursor.fault_position(), DetailPosition::Done) {
            let mut values = Vec::new();
            let filter = if let DetailPosition::After((nullifier, signature, event)) =
                cursor.fault_position()
            {
                values.extend([
                    nullifier.to_vec().into(),
                    signature.as_ref().to_vec().into(),
                    i64::from(event).into(),
                ]);
                " AND (nullifier,tx_signature,event_index)>($2,$3,$4)"
            } else {
                ""
            };
            values.push(limit);
            let sql = format!("SELECT nullifier,slot,tx_signature,event_index FROM spend_integrity_faults WHERE ring=$1{filter} ORDER BY nullifier,tx_signature,event_index LIMIT ${}", values.len() + 1);
            let rows = snapshot.query_all(query(&sql, values)).await?;
            details.faults(
                rows.iter()
                    .map(|row| {
                        Ok(SpendRow {
                            nullifier: read_bytes(row, "nullifier")?,
                            frame: read_frame(row)?,
                            position: 0,
                            state: SpendState::Observed,
                        })
                    })
                    .collect::<Result<Vec<_>, DbErr>>()?,
            );
        }
        details.apply(&mut response);
        snapshot.commit().await?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_cursor_stays_within_the_signed_read_bound() {
        let ring = Address::new_from_array([7; 32]);
        let cursor = CoverageCursor::new(ring);
        let bytes = bytemuck::bytes_of(&cursor);
        assert_eq!(bytes.len(), 240);
        assert!(zolana_ring_client::rpc::cursor_in_bounds(bytes));
        assert!(CoverageCursor::decode(bytes, ring).is_ok());
        let mut invalid = cursor;
        invalid.unread_state = 3;
        assert!(CoverageCursor::decode(bytemuck::bytes_of(&invalid), ring).is_err());
        assert!(CoverageCursor::decode(&bytes[..bytes.len() - 1], ring).is_err());
    }
}
