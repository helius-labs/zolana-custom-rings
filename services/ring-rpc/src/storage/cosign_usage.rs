use sea_orm::{ConnectionTrait, DbErr, QueryResult, Statement, Value};
use solana_address::Address;
use solana_signature::Signature;
use zolana_ring_policy::Member;

use crate::cosign::AssetFlow;

/// Counts until its window passes or an unconfirmed failure frees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    pub sender: [u8; 32],
    pub slot: u64,
    pub flow: AssetFlow,
}

pub(crate) struct UsageWindow<'a> {
    pub ring: &'a Address,
    pub assets: &'a [Address],
    pub since_slot: u64,
}

/// Keyed by the co-signature, one row per flow.
pub(crate) struct Reserve<'a> {
    pub signature: &'a Signature,
    pub ring: &'a Address,
    pub sender: &'a Member,
    pub slot: u64,
    pub flows: &'a [AssetFlow],
}

pub(crate) struct UsageLedger<'a, C> {
    pub conn: &'a C,
}

impl<C: ConnectionTrait> UsageLedger<'_, C> {
    /// The no-op update locks each row until the transaction ends, in address order.
    pub async fn admit(&self, ring: &Address, assets: &[Address]) -> Result<(), DbErr> {
        let sql = "INSERT INTO cosign_admission(ring,asset) VALUES($1,$2) \
                   ON CONFLICT(ring,asset) DO UPDATE SET asset=excluded.asset";
        let mut ordered = assets.to_vec();
        ordered.sort_unstable();
        for asset in &ordered {
            let values = vec![address_value(ring), address_value(asset)];
            self.conn.execute(self.statement(sql, values)).await?;
        }
        Ok(())
    }

    pub async fn reserved(&self, signature: &Signature) -> Result<bool, DbErr> {
        let sql = "SELECT 1 AS reserved FROM cosign_usage WHERE signature=$1";
        let row = self
            .conn
            .query_one(self.statement(sql, vec![signature_value(signature)]))
            .await?;
        Ok(row.is_some())
    }

    pub async fn window(&self, window: UsageWindow<'_>) -> Result<Vec<Reservation>, DbErr> {
        let sql =
            "SELECT asset, sender, slot, transferred, deposited, withdrawn FROM cosign_usage \
                   WHERE ring=$1 AND asset=$2 AND slot>=$3";
        let mut reservations = Vec::new();
        for asset in window.assets {
            let values = vec![
                address_value(window.ring),
                address_value(asset),
                slot_value(window.since_slot)?,
            ];
            for row in self.conn.query_all(self.statement(sql, values)).await? {
                reservations.push(reservation(&row)?);
            }
        }
        Ok(reservations)
    }

    pub async fn reserve(&self, reserve: Reserve<'_>) -> Result<(), DbErr> {
        let sql =
            "INSERT INTO cosign_usage(signature,asset,ring,sender,slot,transferred,deposited,\
                   withdrawn,confirmed) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)";
        for flow in reserve.flows {
            let values = vec![
                signature_value(reserve.signature),
                address_value(&flow.asset),
                address_value(reserve.ring),
                Value::from(reserve.sender.as_bytes().to_vec()),
                slot_value(reserve.slot)?,
                amount_value(flow.transferred),
                amount_value(flow.deposited),
                amount_value(flow.withdrawn),
                Value::from(false),
            ];
            self.conn.execute(self.statement(sql, values)).await?;
        }
        Ok(())
    }

    pub async fn confirm(&self, signature: &Signature) -> Result<(), DbErr> {
        let sql = "UPDATE cosign_usage SET confirmed=$2 WHERE signature=$1";
        let values = vec![signature_value(signature), Value::from(true)];
        self.conn.execute(self.statement(sql, values)).await?;
        Ok(())
    }

    /// A confirmed transaction keeps its usage.
    pub async fn free(&self, signature: &Signature) -> Result<(), DbErr> {
        let sql = "DELETE FROM cosign_usage WHERE signature=$1 AND confirmed=$2";
        let values = vec![signature_value(signature), Value::from(false)];
        self.conn.execute(self.statement(sql, values)).await?;
        Ok(())
    }

    fn statement(&self, sql: &str, values: Vec<Value>) -> Statement {
        Statement::from_sql_and_values(self.conn.get_database_backend(), sql, values)
    }
}

fn reservation(row: &QueryResult) -> Result<Reservation, DbErr> {
    let amount = |column| bytes::<8>(row, column).map(u64::from_be_bytes);
    let slot = row.try_get::<i64>("", "slot")?;
    Ok(Reservation {
        sender: bytes(row, "sender")?,
        slot: u64::try_from(slot).map_err(|_| DbErr::Custom("negative usage slot".into()))?,
        flow: AssetFlow {
            asset: Address::new_from_array(bytes(row, "asset")?),
            transferred: amount("transferred")?,
            deposited: amount("deposited")?,
            withdrawn: amount("withdrawn")?,
        },
    })
}

fn bytes<const N: usize>(row: &QueryResult, column: &str) -> Result<[u8; N], DbErr> {
    row.try_get::<Vec<u8>>("", column)?
        .try_into()
        .map_err(|_| DbErr::Custom(format!("usage column {column} has another length")))
}

fn signature_value(signature: &Signature) -> Value {
    Value::from(signature.as_ref().to_vec())
}

fn address_value(address: &Address) -> Value {
    Value::from(address.as_ref().to_vec())
}

fn amount_value(amount: u64) -> Value {
    Value::from(amount.to_be_bytes().to_vec())
}

fn slot_value(slot: u64) -> Result<Value, DbErr> {
    i64::try_from(slot)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("usage slot exceeds the column range".into()))
}
