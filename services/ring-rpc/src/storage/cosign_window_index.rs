use std::collections::{BTreeMap, BTreeSet};

use sea_orm::{ConnectionTrait, DatabaseTransaction, DbErr, QueryResult, Statement, Value};
use solana_address::Address;

use super::{address_value, bytes, slot_value, Measure, MEASURE_CEILING};
use crate::{cosign::AssetFlow, record_update::MAX_LIMIT_WINDOW_SLOTS};

pub(super) const EPOCH_SLOTS: u64 = MAX_LIMIT_WINDOW_SLOTS.next_power_of_two();
const NODE_BATCH: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Amounts {
    pub outflow: u128,
    pub deposited: u128,
    pub withdrawn: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Scope {
    pub ring: Address,
    pub asset: Address,
    pub owner: Option<[u8; 32]>,
}

#[derive(Clone, Copy)]
pub(super) struct WindowRange {
    pub scope: Scope,
    pub slot: u64,
    pub window_slots: u64,
}

pub(super) struct Point {
    pub scope: Scope,
    pub slot: u64,
    pub amounts: Amounts,
}

pub(super) enum ChangeKind {
    Add,
    Remove,
}

pub(super) struct PointChange {
    pub points: Vec<Point>,
    pub kind: ChangeKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct NodeKey {
    scope: Scope,
    epoch: u64,
    node: u32,
}

struct Prefix {
    scope: Scope,
    epoch: u64,
    end: u32,
}

struct Segment {
    scope: Scope,
    epoch: u64,
    start: u32,
    end: u32,
}

struct RangePlan(Vec<Segment>);

struct Nodes<'a, C> {
    conn: &'a C,
}

impl From<&AssetFlow> for Amounts {
    fn from(flow: &AssetFlow) -> Self {
        Self {
            outflow: flow.charged_outflow,
            deposited: flow.deposited,
            withdrawn: flow.withdrawn,
        }
    }
}

impl Amounts {
    pub(super) fn clipped(self) -> Self {
        Self {
            outflow: self.outflow.min(MEASURE_CEILING),
            deposited: self.deposited.min(MEASURE_CEILING),
            withdrawn: self.withdrawn.min(MEASURE_CEILING),
        }
    }

    pub(super) fn owner(self) -> Self {
        Self {
            outflow: self.outflow,
            ..Self::default()
        }
    }

    pub(super) fn measure(self, measure: Measure) -> Option<u128> {
        match measure {
            Measure::Outflow => Some(self.outflow),
            Measure::Volume => self.outflow.checked_add(self.deposited),
            Measure::Deposited => Some(self.deposited),
            Measure::Withdrawn => Some(self.withdrawn),
        }
    }

    fn checked_add(self, other: Self) -> Result<Self, DbErr> {
        Ok(Self {
            outflow: self
                .outflow
                .checked_add(other.outflow)
                .ok_or_else(overflow)?,
            deposited: self
                .deposited
                .checked_add(other.deposited)
                .ok_or_else(overflow)?,
            withdrawn: self
                .withdrawn
                .checked_add(other.withdrawn)
                .ok_or_else(overflow)?,
        })
    }

    fn checked_sub(self, other: Self) -> Result<Self, DbErr> {
        Ok(Self {
            outflow: self
                .outflow
                .checked_sub(other.outflow)
                .ok_or_else(underflow)?,
            deposited: self
                .deposited
                .checked_sub(other.deposited)
                .ok_or_else(underflow)?,
            withdrawn: self
                .withdrawn
                .checked_sub(other.withdrawn)
                .ok_or_else(underflow)?,
        })
    }

    fn read(row: &QueryResult) -> Result<Self, DbErr> {
        Ok(Self {
            outflow: u128::from_be_bytes(bytes(row, "outflow")?),
            deposited: u128::from_be_bytes(bytes(row, "deposited")?),
            withdrawn: u128::from_be_bytes(bytes(row, "withdrawn")?),
        })
    }

    fn values(self) -> [Value; 3] {
        [self.outflow, self.deposited, self.withdrawn]
            .map(|amount| Value::from(amount.to_be_bytes().to_vec()))
    }
}

impl WindowRange {
    fn plan(self) -> Result<RangePlan, DbErr> {
        if self.window_slots > MAX_LIMIT_WINDOW_SLOTS {
            return Err(DbErr::Custom(
                "usage window exceeds its supported range".into(),
            ));
        }
        if self.window_slots == 0 {
            return Ok(RangePlan(Vec::new()));
        }
        let start = self.slot.saturating_sub(self.window_slots - 1);
        let first_epoch = start / EPOCH_SLOTS;
        let last_epoch = self.slot / EPOCH_SLOTS;
        let mut segments = vec![Segment {
            scope: self.scope,
            epoch: first_epoch,
            start: (start % EPOCH_SLOTS) as u32,
            end: if first_epoch == last_epoch {
                (self.slot % EPOCH_SLOTS + 1) as u32
            } else {
                EPOCH_SLOTS as u32
            },
        }];
        if first_epoch != last_epoch {
            segments.push(Segment {
                scope: self.scope,
                epoch: last_epoch,
                start: 0,
                end: (self.slot % EPOCH_SLOTS + 1) as u32,
            });
        }
        Ok(RangePlan(segments))
    }
}

impl Prefix {
    fn nodes(self) -> Vec<NodeKey> {
        let mut index = self.end;
        let mut nodes = Vec::new();
        while index != 0 {
            nodes.push(NodeKey {
                scope: self.scope,
                epoch: self.epoch,
                node: index,
            });
            index &= index - 1;
        }
        nodes
    }
}

impl Segment {
    fn prefix(&self, end: u32) -> Vec<NodeKey> {
        Prefix {
            scope: self.scope,
            epoch: self.epoch,
            end,
        }
        .nodes()
    }

    fn read(&self, nodes: &BTreeMap<NodeKey, Amounts>) -> Result<Amounts, DbErr> {
        let sum = |end| {
            self.prefix(end)
                .into_iter()
                .try_fold(Amounts::default(), |total, key| {
                    total.checked_add(nodes.get(&key).copied().unwrap_or_default())
                })
        };
        sum(self.end)?.checked_sub(sum(self.start)?)
    }
}

impl RangePlan {
    fn keys(&self) -> impl Iterator<Item = NodeKey> + '_ {
        self.0.iter().flat_map(|segment| {
            segment
                .prefix(segment.end)
                .into_iter()
                .chain(segment.prefix(segment.start))
        })
    }

    fn read(&self, nodes: &BTreeMap<NodeKey, Amounts>) -> Result<Amounts, DbErr> {
        self.0
            .iter()
            .try_fold(Amounts::default(), |total, segment| {
                total.checked_add(segment.read(nodes)?)
            })
    }
}

impl Point {
    fn keys(&self) -> Vec<NodeKey> {
        let mut node = (self.slot % EPOCH_SLOTS + 1) as u32;
        let mut keys = Vec::new();
        while u64::from(node) <= EPOCH_SLOTS {
            keys.push(NodeKey {
                scope: self.scope,
                epoch: self.slot / EPOCH_SLOTS,
                node,
            });
            node += node.isolate_lowest_one();
        }
        keys
    }
}

impl PointChange {
    pub(super) async fn apply(self, conn: &DatabaseTransaction) -> Result<(), DbErr> {
        let mut changes = BTreeMap::<NodeKey, Amounts>::new();
        for point in self.points {
            if point.amounts == Amounts::default() {
                continue;
            }
            for key in point.keys() {
                let amount = changes.entry(key).or_default();
                *amount = amount.checked_add(point.amounts)?;
            }
        }
        let store = Nodes { conn };
        let held = store.read(&changes.keys().copied().collect()).await?;
        for (key, amount) in &mut changes {
            let previous = held.get(key).copied().unwrap_or_default();
            *amount = match self.kind {
                ChangeKind::Add => previous.checked_add(*amount)?,
                ChangeKind::Remove => previous.checked_sub(*amount)?,
            };
        }
        store.write(changes).await
    }
}

impl NodeKey {
    fn values(self) -> Result<Vec<Value>, DbErr> {
        Ok(vec![
            address_value(&self.scope.ring),
            address_value(&self.scope.asset),
            slot_value(self.epoch)?,
            Value::from(if self.scope.owner.is_some() { 1_i64 } else { 0 }),
            Value::from(self.scope.owner.unwrap_or_default().to_vec()),
            Value::from(i64::from(self.node)),
        ])
    }

    fn read(row: &QueryResult) -> Result<Self, DbErr> {
        let owner = bytes(row, "owner")?;
        let owner = match row.try_get::<i64>("", "scope_kind")? {
            0 if owner == [0; 32] => None,
            1 => Some(owner),
            _ => return Err(DbErr::Custom("invalid usage scope".into())),
        };
        let epoch = u64::try_from(row.try_get::<i64>("", "epoch")?)
            .map_err(|_| DbErr::Custom("negative usage epoch".into()))?;
        let node = u32::try_from(row.try_get::<i64>("", "node")?)
            .map_err(|_| DbErr::Custom("invalid usage node".into()))?;
        if node == 0 || u64::from(node) > EPOCH_SLOTS {
            return Err(DbErr::Custom("invalid usage node".into()));
        }
        Ok(Self {
            scope: Scope {
                ring: Address::new_from_array(bytes(row, "ring")?),
                asset: Address::new_from_array(bytes(row, "asset")?),
                owner,
            },
            epoch,
            node,
        })
    }
}

impl<C: ConnectionTrait> Nodes<'_, C> {
    async fn read(&self, keys: &BTreeSet<NodeKey>) -> Result<BTreeMap<NodeKey, Amounts>, DbErr> {
        let keys: Vec<_> = keys.iter().copied().collect();
        let mut nodes = BTreeMap::new();
        for batch in keys.chunks(NODE_BATCH) {
            let mut values = Vec::new();
            let mut conditions = Vec::new();
            for key in batch {
                let start = values.len() + 1;
                conditions.push(format!(
                    "(ring=${start} AND asset=${} AND epoch=${} AND scope_kind=${} AND owner=${} AND node=${})",
                    start + 1, start + 2, start + 3, start + 4, start + 5
                ));
                values.extend(key.values()?);
            }
            let sql = format!(
                "SELECT ring,asset,epoch,scope_kind,owner,node,outflow,deposited,withdrawn FROM cosign_totals WHERE {}",
                conditions.join(" OR ")
            );
            for row in self.conn.query_all(self.statement(sql, values)).await? {
                nodes.insert(NodeKey::read(&row)?, Amounts::read(&row)?);
            }
        }
        Ok(nodes)
    }

    fn statement(&self, sql: String, values: Vec<Value>) -> Statement {
        Statement::from_sql_and_values(self.conn.get_database_backend(), sql, values)
    }
}

impl Nodes<'_, DatabaseTransaction> {
    async fn write(&self, nodes: BTreeMap<NodeKey, Amounts>) -> Result<(), DbErr> {
        let rows: Vec<_> = nodes.into_iter().collect();
        for batch in rows.chunks(NODE_BATCH) {
            let mut values = Vec::new();
            let mut slots = Vec::new();
            for (key, amount) in batch {
                let start = values.len() + 1;
                slots.push(format!(
                    "({})",
                    (start..start + 9)
                        .map(|index| format!("${index}"))
                        .collect::<Vec<_>>()
                        .join(",")
                ));
                values.extend(key.values()?);
                values.extend(amount.values());
            }
            let sql = format!(
                "INSERT INTO cosign_totals(ring,asset,epoch,scope_kind,owner,node,outflow,deposited,withdrawn) VALUES {} ON CONFLICT(ring,asset,epoch,scope_kind,owner,node) DO UPDATE SET outflow=excluded.outflow,deposited=excluded.deposited,withdrawn=excluded.withdrawn",
                slots.join(",")
            );
            self.conn.execute(self.statement(sql, values)).await?;
        }
        Ok(())
    }
}

pub(super) async fn range_totals<C: ConnectionTrait>(
    conn: &C,
    ranges: &[WindowRange],
) -> Result<Vec<Amounts>, DbErr> {
    let plans = ranges
        .iter()
        .map(|range| range.plan())
        .collect::<Result<Vec<_>, _>>()?;
    let keys = plans.iter().flat_map(RangePlan::keys).collect();
    let nodes = Nodes { conn }.read(&keys).await?;
    plans.iter().map(|plan| plan.read(&nodes)).collect()
}

fn overflow() -> DbErr {
    DbErr::Custom("usage total exceeds its counter range".into())
}

fn underflow() -> DbErr {
    DbErr::Custom("usage correction exceeds the stored total".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCOPE: Scope = Scope {
        ring: Address::new_from_array([1; 32]),
        asset: Address::new_from_array([2; 32]),
        owner: None,
    };

    #[test]
    fn supported_windows_have_bounded_point_and_range_work() {
        assert_eq!(EPOCH_SLOTS, 16_777_216);
        let mut slots = vec![0, 1, EPOCH_SLOTS - 1, EPOCH_SLOTS, i64::MAX as u64];
        let mut windows = vec![0, 1, MAX_LIMIT_WINDOW_SLOTS];
        for bit in 1..24 {
            let boundary = 1_u64 << bit;
            slots.extend([boundary - 1, boundary, EPOCH_SLOTS + boundary - 1]);
            windows.extend([boundary - 1, boundary, boundary + 1]);
        }
        for slot in slots {
            let point = Point {
                scope: SCOPE,
                slot,
                amounts: Amounts::default(),
            };
            assert!(point.keys().len() <= 25);
            for &window_slots in &windows {
                let plan = WindowRange {
                    scope: SCOPE,
                    slot,
                    window_slots,
                }
                .plan()
                .expect("range");
                assert!(plan.keys().count() <= 49);
            }
        }
        assert_eq!(
            Point {
                scope: SCOPE,
                slot: 0,
                amounts: Amounts::default()
            }
            .keys()
            .len(),
            25
        );
    }

    #[test]
    fn node_arithmetic_refuses_overflow_and_missing_refund_value() {
        let full = Amounts {
            outflow: u128::MAX,
            deposited: 0,
            withdrawn: 0,
        };
        let one = Amounts {
            outflow: 1,
            deposited: 0,
            withdrawn: 0,
        };
        assert!(full.checked_add(one).is_err());
        assert!(Amounts::default().checked_sub(one).is_err());
        assert_eq!(
            full.checked_sub(one)
                .expect("subtract")
                .checked_add(one)
                .expect("restore"),
            full
        );
    }
}
