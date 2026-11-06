use std::collections::{BTreeMap, BTreeSet, HashMap};

use sea_orm::{ConnectionTrait, DatabaseTransaction, DbErr, QueryResult, Statement, Value};
use solana_address::Address;
use solana_signature::Signature;

use crate::cosign::{AssetFlow, CoSignSettlement, OwnerFlow};

#[path = "cosign_window_index.rs"]
mod window_index;

use window_index::{
    range_totals, Amounts, ChangeKind, Point, PointChange, Scope, WindowRange, EPOCH_SLOTS,
};

const MEASURE_CEILING: u128 = 1 << 64;
const RESERVATION_BATCH: usize = 64;
const PRUNE_NODES: usize = 64;
pub(crate) const MAX_USAGE_FLOWS: usize =
    spr_interface::MAX_TRANSACT_INPUTS + spr_interface::MAX_INTERFACE_TRANSFERS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Measure {
    Outflow,
    Volume,
    Deposited,
    Withdrawn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReservationState {
    Held,
    Confirmed,
    Released,
}

#[derive(Clone, Copy)]
pub(crate) struct AssetScope<'a> {
    pub ring: &'a Address,
    pub assets: &'a [Address],
}

#[derive(Clone, Copy)]
pub(crate) struct AdmissionSlot<'a> {
    pub scope: AssetScope<'a>,
    pub slot: u64,
}

pub(crate) struct SettlementScope {
    ring: Address,
    assets: Vec<Address>,
}

#[derive(Clone, Copy)]
pub(crate) struct WindowSum<'a> {
    pub ring: &'a Address,
    pub asset: &'a Address,
    pub measure: Measure,
    pub slot: u64,
    pub window_slots: u64,
}

pub(crate) struct Reserve<'a> {
    pub signature: &'a Signature,
    pub ring: &'a Address,
    pub slot: u64,
    pub flows: &'a [OwnerFlow],
}

pub(crate) struct UsageLedger<'a, C> {
    pub conn: &'a C,
}

struct Reservation {
    ring: Address,
    owner: [u8; 32],
    asset: Address,
    slot: u64,
    state: ReservationState,
    amounts: Amounts,
}

struct AssetFilter {
    sql: String,
    values: Vec<Value>,
}

impl Measure {
    pub fn of(self, flow: &AssetFlow) -> Option<u128> {
        Amounts::from(flow).measure(self)
    }
}

impl ReservationState {
    fn read(value: &str) -> Result<Self, DbErr> {
        match value {
            "held" => Ok(Self::Held),
            "confirmed" => Ok(Self::Confirmed),
            "released" => Ok(Self::Released),
            _ => Err(DbErr::Custom("invalid usage state".into())),
        }
    }

    const fn stored(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Confirmed => "confirmed",
            Self::Released => "released",
        }
    }
}

impl AssetScope<'_> {
    fn filter(self) -> AssetFilter {
        let mut values = vec![address_value(self.ring)];
        values.extend(self.assets.iter().map(address_value));
        let named = (2..values.len() + 1)
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
            .join(",");
        AssetFilter {
            sql: format!("ring=$1 AND asset IN ({named})"),
            values,
        }
    }
}

impl SettlementScope {
    pub(crate) fn as_scope(&self) -> AssetScope<'_> {
        AssetScope {
            ring: &self.ring,
            assets: &self.assets,
        }
    }
}

impl<C: ConnectionTrait> UsageLedger<'_, C> {
    pub async fn reservation_state(
        &self,
        signature: &Signature,
    ) -> Result<Option<ReservationState>, DbErr> {
        let row = self
            .conn
            .query_one(self.statement(
                "SELECT state FROM cosign_usage WHERE signature=$1 LIMIT 1",
                vec![signature_value(signature)],
            ))
            .await?;
        row.map(|row| ReservationState::read(&row.try_get::<String>("", "state")?))
            .transpose()
    }

    pub async fn settlement_scope(
        &self,
        signature: &Signature,
    ) -> Result<Option<SettlementScope>, DbErr> {
        let rows = self.reservations(signature).await?;
        let Some(first) = rows.first() else {
            return Ok(None);
        };
        if rows
            .iter()
            .any(|row| row.ring != first.ring || row.state != first.state)
        {
            return Err(DbErr::Custom("inconsistent usage reservation".into()));
        }
        Ok(Some(SettlementScope {
            ring: first.ring,
            assets: rows
                .iter()
                .map(|row| row.asset)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }))
    }

    pub async fn slot_allowed(&self, admission: AdmissionSlot<'_>) -> Result<bool, DbErr> {
        slot_value(admission.slot)?;
        Ok(self
            .watermarks(admission.scope)
            .await?
            .values()
            .all(|slot| *slot <= admission.slot))
    }

    pub async fn ring_total(&self, sum: WindowSum<'_>) -> Result<u128, DbErr> {
        let ranges = [sum.range(None)];
        let totals = range_totals(self.conn, &ranges).await?;
        totals
            .first()
            .copied()
            .ok_or_else(|| DbErr::Custom("missing usage total".into()))?
            .measure(sum.measure)
            .ok_or_else(|| DbErr::Custom("usage measure exceeds its counter range".into()))
    }

    pub async fn owner_totals(
        &self,
        sum: WindowSum<'_>,
        owners: &[[u8; 32]],
    ) -> Result<HashMap<[u8; 32], u128>, DbErr> {
        let ranges: Vec<_> = owners.iter().map(|owner| sum.range(Some(*owner))).collect();
        owners
            .iter()
            .copied()
            .zip(range_totals(self.conn, &ranges).await?)
            .map(|(owner, amounts)| {
                amounts
                    .measure(sum.measure)
                    .map(|total| (owner, total))
                    .ok_or_else(|| DbErr::Custom("usage measure exceeds its counter range".into()))
            })
            .collect()
    }

    async fn watermarks(&self, scope: AssetScope<'_>) -> Result<BTreeMap<Address, u64>, DbErr> {
        if scope.assets.is_empty() {
            return Ok(BTreeMap::new());
        }
        let filter = scope.filter();
        let sql = format!(
            "SELECT asset,last_slot FROM cosign_admission WHERE {}",
            filter.sql
        );
        let mut slots = BTreeMap::new();
        for row in self
            .conn
            .query_all(self.statement(&sql, filter.values))
            .await?
        {
            let slot = u64::try_from(row.try_get::<i64>("", "last_slot")?)
                .map_err(|_| DbErr::Custom("negative usage slot".into()))?;
            slots.insert(Address::new_from_array(bytes(&row, "asset")?), slot);
        }
        if slots.len() != scope.assets.len() {
            return Err(DbErr::Custom("missing usage admission lock".into()));
        }
        Ok(slots)
    }

    async fn reservations(&self, signature: &Signature) -> Result<Vec<Reservation>, DbErr> {
        let sql = format!(
            "SELECT ring,owner,asset,slot,state,outflow_hi,outflow_lo,deposited_hi,deposited_lo,withdrawn_hi,withdrawn_lo FROM cosign_usage WHERE signature=$1 LIMIT {}",
            MAX_USAGE_FLOWS + 1
        );
        let rows = self
            .conn
            .query_all(self.statement(&sql, vec![signature_value(signature)]))
            .await?;
        if rows.len() > MAX_USAGE_FLOWS {
            return Err(DbErr::Custom(
                "usage reservation exceeds its flow bound".into(),
            ));
        }
        rows.iter().map(Reservation::read).collect()
    }

    fn statement(&self, sql: &str, values: Vec<Value>) -> Statement {
        Statement::from_sql_and_values(self.conn.get_database_backend(), sql, values)
    }
}

impl UsageLedger<'_, DatabaseTransaction> {
    pub async fn admit(&self, scope: AssetScope<'_>) -> Result<(), DbErr> {
        let sql = "INSERT INTO cosign_admission(ring,asset) VALUES($1,$2) ON CONFLICT(ring,asset) DO UPDATE SET asset=excluded.asset";
        for asset in scope.assets.iter().collect::<BTreeSet<_>>() {
            self.conn
                .execute(self.statement(sql, vec![address_value(scope.ring), address_value(asset)]))
                .await?;
        }
        Ok(())
    }

    pub async fn reserve(&self, reserve: Reserve<'_>) -> Result<(), DbErr> {
        if reserve.flows.len() > MAX_USAGE_FLOWS {
            return Err(DbErr::Custom(
                "usage reservation exceeds its flow bound".into(),
            ));
        }
        let rows: Vec<_> = reserve
            .flows
            .iter()
            .map(|flow| Reservation {
                ring: *reserve.ring,
                owner: *flow.owner.as_bytes(),
                asset: flow.flow.asset,
                slot: reserve.slot,
                state: ReservationState::Held,
                amounts: Amounts::from(&flow.flow).clipped(),
            })
            .collect();
        let assets: Vec<_> = rows
            .iter()
            .map(|row| row.asset)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let admission = AdmissionSlot {
            scope: AssetScope {
                ring: reserve.ring,
                assets: &assets,
            },
            slot: reserve.slot,
        };
        self.advance(admission).await?;
        for batch in rows.chunks(RESERVATION_BATCH) {
            let mut values = Vec::new();
            let mut slots = Vec::new();
            for row in batch {
                let start = values.len() + 1;
                slots.push(format!(
                    "({})",
                    (start..start + 12)
                        .map(|index| format!("${index}"))
                        .collect::<Vec<_>>()
                        .join(",")
                ));
                values.extend([
                    signature_value(reserve.signature),
                    address_value(&row.asset),
                    address_value(&row.ring),
                    Value::from(row.owner.to_vec()),
                    slot_value(row.slot)?,
                ]);
                for amount in [
                    row.amounts.outflow,
                    row.amounts.deposited,
                    row.amounts.withdrawn,
                ] {
                    values.extend(halves(amount));
                }
                values.push(Value::from(ReservationState::Held.stored()));
            }
            let sql = format!(
                "INSERT INTO cosign_usage(signature,asset,ring,owner,slot,outflow_hi,outflow_lo,deposited_hi,deposited_lo,withdrawn_hi,withdrawn_lo,state) VALUES {}",
                slots.join(",")
            );
            self.conn.execute(self.statement(&sql, values)).await?;
        }
        PointChange {
            points: rows.iter().flat_map(Reservation::points).collect(),
            kind: ChangeKind::Add,
        }
        .apply(self.conn)
        .await?;
        self.prune(admission.scope, admission.slot).await
    }

    pub async fn settle(&self, settlement: CoSignSettlement) -> Result<(), DbErr> {
        let (signature, next) = match settlement {
            CoSignSettlement::Confirmed(signature) => (signature, ReservationState::Confirmed),
            CoSignSettlement::Failed(signature) => (signature, ReservationState::Released),
        };
        let rows = self.reservations(&signature).await?;
        let Some(first) = rows.first() else {
            return Ok(());
        };
        if rows
            .iter()
            .any(|row| row.ring != first.ring || row.state != first.state)
        {
            return Err(DbErr::Custom("inconsistent usage reservation".into()));
        }
        match first.state {
            ReservationState::Confirmed => return Ok(()),
            ReservationState::Released => {
                return if next == ReservationState::Released {
                    Ok(())
                } else {
                    Err(DbErr::Custom(
                        "a released usage reservation cannot confirm".into(),
                    ))
                };
            }
            ReservationState::Held => {}
        }
        if next == ReservationState::Released {
            let assets: Vec<_> = rows
                .iter()
                .map(|row| row.asset)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let watermarks = self
                .watermarks(AssetScope {
                    ring: &first.ring,
                    assets: &assets,
                })
                .await?;
            let mut points = Vec::new();
            for row in &rows {
                let watermark = watermarks
                    .get(&row.asset)
                    .ok_or_else(|| DbErr::Custom("missing usage admission lock".into()))?;
                if row.slot / EPOCH_SLOTS >= (watermark / EPOCH_SLOTS).saturating_sub(1) {
                    points.extend(row.points());
                }
            }
            PointChange {
                points,
                kind: ChangeKind::Remove,
            }
            .apply(self.conn)
            .await?;
        }
        let sql = "UPDATE cosign_usage SET state=$2 WHERE signature=$1 AND state=$3";
        let changed = self
            .conn
            .execute(self.statement(
                sql,
                vec![
                    signature_value(&signature),
                    Value::from(next.stored()),
                    Value::from(ReservationState::Held.stored()),
                ],
            ))
            .await?;
        if changed.rows_affected() != rows.len() as u64 {
            return Err(DbErr::Custom(
                "usage reservation changed during settlement".into(),
            ));
        }
        Ok(())
    }

    async fn advance(&self, admission: AdmissionSlot<'_>) -> Result<(), DbErr> {
        if admission.scope.assets.is_empty() {
            return Ok(());
        }
        let mut filter = admission.scope.filter();
        filter.values.push(slot_value(admission.slot)?);
        let parameter = filter.values.len();
        let sql = format!("UPDATE cosign_admission SET last_slot=${parameter} WHERE {} AND last_slot<=${parameter}", filter.sql);
        let changed = self
            .conn
            .execute(self.statement(&sql, filter.values))
            .await?;
        if changed.rows_affected() != admission.scope.assets.len() as u64 {
            return Err(DbErr::Custom("usage admission slot regressed".into()));
        }
        Ok(())
    }

    async fn prune(&self, scope: AssetScope<'_>, slot: u64) -> Result<(), DbErr> {
        let minimum_epoch = (slot / EPOCH_SLOTS).saturating_sub(1);
        if minimum_epoch == 0 {
            return Ok(());
        }
        let sql = format!("DELETE FROM cosign_totals WHERE (ring,asset,epoch,scope_kind,owner,node) IN (SELECT ring,asset,epoch,scope_kind,owner,node FROM cosign_totals WHERE ring=$1 AND asset=$2 AND epoch<$3 ORDER BY epoch,scope_kind,owner,node LIMIT {PRUNE_NODES})");
        for asset in scope.assets {
            self.conn
                .execute(self.statement(
                    &sql,
                    vec![
                        address_value(scope.ring),
                        address_value(asset),
                        slot_value(minimum_epoch)?,
                    ],
                ))
                .await?;
        }
        Ok(())
    }
}

impl WindowSum<'_> {
    fn range(self, owner: Option<[u8; 32]>) -> WindowRange {
        WindowRange {
            scope: Scope {
                ring: *self.ring,
                asset: *self.asset,
                owner,
            },
            slot: self.slot,
            window_slots: self.window_slots,
        }
    }
}

impl Reservation {
    fn read(row: &QueryResult) -> Result<Self, DbErr> {
        let amount = |name| {
            let high = u128::try_from(row.try_get::<i64>("", &format!("{name}_hi"))?)
                .map_err(|_| DbErr::Custom("negative usage contribution".into()))?;
            let low = u128::try_from(row.try_get::<i64>("", &format!("{name}_lo"))?)
                .map_err(|_| DbErr::Custom("negative usage contribution".into()))?;
            let amount = (high << 32) + low;
            if low > u128::from(u32::MAX) || amount > MEASURE_CEILING {
                return Err(DbErr::Custom("invalid usage contribution".into()));
            }
            Ok(amount)
        };
        Ok(Self {
            ring: Address::new_from_array(bytes(row, "ring")?),
            owner: bytes(row, "owner")?,
            asset: Address::new_from_array(bytes(row, "asset")?),
            slot: u64::try_from(row.try_get::<i64>("", "slot")?)
                .map_err(|_| DbErr::Custom("negative usage slot".into()))?,
            state: ReservationState::read(&row.try_get::<String>("", "state")?)?,
            amounts: Amounts {
                outflow: amount("outflow")?,
                deposited: amount("deposited")?,
                withdrawn: amount("withdrawn")?,
            },
        })
    }

    fn points(&self) -> [Point; 2] {
        [
            Point {
                scope: Scope {
                    ring: self.ring,
                    asset: self.asset,
                    owner: None,
                },
                slot: self.slot,
                amounts: self.amounts,
            },
            Point {
                scope: Scope {
                    ring: self.ring,
                    asset: self.asset,
                    owner: Some(self.owner),
                },
                slot: self.slot,
                amounts: self.amounts.owner(),
            },
        ]
    }
}

fn halves(amount: u128) -> [Value; 2] {
    [amount >> 32, amount & u128::from(u32::MAX)].map(|half| Value::from(half as i64))
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

fn slot_value(slot: u64) -> Result<Value, DbErr> {
    i64::try_from(slot)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("usage slot exceeds the column range".into()))
}
