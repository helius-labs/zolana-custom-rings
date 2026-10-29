use sea_orm::{ConnectionTrait, DatabaseConnection, DbErr, QueryResult, Statement, Value};
use solana_address::Address;
use zolana_ring_client::rpc::MergeSettings;

use crate::error::RingRpcError;

#[must_use]
pub(crate) struct SignedMergeSettings<'a> {
    pub ring: Address,
    pub owner: Address,
    pub settings: &'a MergeSettings,
    /// The request timestamp, a later one replaces the row.
    pub signed_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WalletMergeSettings {
    pub owner: Address,
    pub settings: MergeSettings,
}

/// A zero target stays stored, an older request never revives it.
pub(crate) struct MergeSettingsBook<'a> {
    db: &'a DatabaseConnection,
}

impl<'a> MergeSettingsBook<'a> {
    pub(crate) fn new(db: &'a DatabaseConnection) -> Self {
        Self { db }
    }

    /// `false` when the stored row was signed at or after `signed_at`.
    pub(crate) async fn save(&self, signed: SignedMergeSettings<'_>) -> Result<bool, RingRpcError> {
        let sql = "INSERT INTO merge_settings \
                   (ring, owner, mint, target_note_count, min_average_amount, signed_at) \
                   VALUES ($1, $2, $3, $4, $5, $6) \
                   ON CONFLICT(ring, owner, mint) DO UPDATE SET \
                   target_note_count=excluded.target_note_count, \
                   min_average_amount=excluded.min_average_amount, signed_at=excluded.signed_at \
                   WHERE merge_settings.signed_at < excluded.signed_at";
        let signed_at = i64::try_from(signed.signed_at)
            .map_err(|_| DbErr::Type("merge settings timestamp exceeds i64".to_owned()))?;
        let result = self
            .db
            .execute(self.statement(
                sql,
                vec![
                    address(&signed.ring),
                    address(&signed.owner),
                    address(&signed.settings.mint.0),
                    i64::from(signed.settings.target_note_count).into(),
                    signed.settings.min_average_amount.to_be_bytes().to_vec().into(),
                    signed_at.into(),
                ],
            ))
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub(crate) async fn rings(&self) -> Result<Vec<Address>, RingRpcError> {
        let sql = "SELECT DISTINCT ring FROM merge_settings WHERE target_note_count > 0";
        let rows = self.db.query_all(self.statement(sql, vec![])).await?;
        Ok(rows
            .iter()
            .map(|row| read_address(row, "ring"))
            .collect::<Result<_, _>>()?)
    }

    pub(crate) async fn active(
        &self,
        ring: Address,
    ) -> Result<Vec<WalletMergeSettings>, RingRpcError> {
        let sql = "SELECT owner, mint, target_note_count, min_average_amount FROM merge_settings \
                   WHERE ring=$1 AND target_note_count > 0";
        let rows = self
            .db
            .query_all(self.statement(sql, vec![address(&ring)]))
            .await?;
        Ok(rows.iter().map(wallet_settings).collect::<Result<_, _>>()?)
    }

    fn statement(&self, sql: &str, values: Vec<Value>) -> Statement {
        Statement::from_sql_and_values(self.db.get_database_backend(), sql, values)
    }
}

fn wallet_settings(row: &QueryResult) -> Result<WalletMergeSettings, DbErr> {
    let target = row.try_get::<i64>("", "target_note_count")?;
    let average: [u8; 8] = row
        .try_get::<Vec<u8>>("", "min_average_amount")?
        .try_into()
        .map_err(|_| malformed("min_average_amount"))?;
    Ok(WalletMergeSettings {
        owner: read_address(row, "owner")?,
        settings: MergeSettings {
            mint: read_address(row, "mint")?.into(),
            target_note_count: u32::try_from(target).map_err(|_| malformed("target_note_count"))?,
            min_average_amount: u64::from_be_bytes(average),
        },
    })
}

fn read_address(row: &QueryResult, column: &str) -> Result<Address, DbErr> {
    let bytes: [u8; 32] = row
        .try_get::<Vec<u8>>("", column)?
        .try_into()
        .map_err(|_| malformed(column))?;
    Ok(Address::new_from_array(bytes))
}

fn address(value: &Address) -> Value {
    value.to_bytes().to_vec().into()
}

fn malformed(column: &str) -> DbErr {
    DbErr::Type(format!("merge settings {column} is malformed"))
}
