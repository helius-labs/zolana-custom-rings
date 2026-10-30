use sea_orm::{ConnectionTrait, DbErr, Statement, Value};
use solana_address::Address;
use zolana_ring_client::rpc::RelayId;

use crate::relays::RelayPhase;

/// One row per nullifier, a second merge of the same note fails its insert.
pub(crate) struct MergeInputs<'a, C> {
    pub conn: &'a C,
}

#[must_use]
pub(crate) struct HoldInputs<'a> {
    pub ring: &'a Address,
    pub relay_id: &'a RelayId,
    pub nullifiers: &'a [[u8; 32]],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeldInput {
    pub nullifier: [u8; 32],
    pub phase: RelayPhase,
}

impl<C: ConnectionTrait> MergeInputs<'_, C> {
    pub async fn hold(&self, hold: HoldInputs<'_>) -> Result<(), DbErr> {
        let sql = "INSERT INTO merge_inputs(nullifier,ring,relay_id) VALUES($1,$2,$3)";
        for nullifier in hold.nullifiers {
            let values = vec![
                nullifier.to_vec().into(),
                hold.ring.to_bytes().to_vec().into(),
                hold.relay_id.0 .0.to_vec().into(),
            ];
            self.conn.execute(self.statement(sql, values)).await?;
        }
        Ok(())
    }

    pub async fn held(&self, ring: &Address) -> Result<Vec<HeldInput>, DbErr> {
        let sql = "SELECT merge_inputs.nullifier, relay_relays.status FROM merge_inputs \
                   JOIN relay_relays ON relay_relays.relay_id = merge_inputs.relay_id \
                   WHERE merge_inputs.ring=$1";
        let values = vec![ring.to_bytes().to_vec().into()];
        self.conn
            .query_all(self.statement(sql, values))
            .await?
            .iter()
            .map(|row| {
                let nullifier: Vec<u8> = row.try_get("", "nullifier")?;
                let status: String = row.try_get("", "status")?;
                Ok(HeldInput {
                    nullifier: nullifier.try_into().map_err(|_| {
                        DbErr::Custom("merge_inputs nullifier is corrupt".to_owned())
                    })?,
                    phase: RelayPhase::of_status(&status)?,
                })
            })
            .collect()
    }

    pub async fn release(&self, nullifiers: &[[u8; 32]]) -> Result<(), DbErr> {
        let sql = "DELETE FROM merge_inputs WHERE nullifier=$1";
        for nullifier in nullifiers {
            let values = vec![nullifier.to_vec().into()];
            self.conn.execute(self.statement(sql, values)).await?;
        }
        Ok(())
    }

    fn statement(&self, sql: &str, values: Vec<Value>) -> Statement {
        Statement::from_sql_and_values(self.conn.get_database_backend(), sql, values)
    }
}
