//! One replica writes a ring's projection, every other replica reloads what it committed.
//!
//! A claim takes the lease row when its instance renews it, when a restart of its replica returns,
//! or when its expiry passed, and every new instance moves the fencing token. Every projection
//! transaction first renews the row by replica and token.
//! The row lock orders that write against a concurrent claim, so a writer whose token moved
//! commits nothing. Read before `storage/spent_index.rs`.

use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbErr, Statement, TransactionTrait,
    Value,
};
use solana_address::Address;

/// Seconds a lease outlives its last claim or commit, a few backfill intervals.
pub(crate) const PROJECTION_LEASE_TTL: u64 = 90;

/// `replica` survives a restart, `instance` is drawn per open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LeaseHolder {
    pub replica: [u8; 32],
    pub instance: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProjectionLease {
    ring: Address,
    holder: LeaseHolder,
    token: i64,
}

#[must_use]
pub(crate) struct LeaseClaim<'a> {
    pub db: &'a DatabaseConnection,
    pub ring: Address,
    pub holder: LeaseHolder,
    /// Unix seconds.
    pub now: u64,
}

impl LeaseClaim<'_> {
    /// `None` while another replica's lease has not expired.
    pub(crate) async fn claim(self) -> Result<Option<ProjectionLease>, DbErr> {
        let Self {
            db,
            ring,
            holder,
            now,
        } = self;
        let transaction = db.begin().await?;
        let backend = transaction.get_database_backend();
        // 1. The same instance renews in place. A restart of its replica takes the lease at once and
        //    any other replica only after expiry, both bump the token every older commit names.
        transaction
            .execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO projection_leases(ring,holder,instance,token,expires_at) \
                 VALUES($1,$2,$3,1,$4) ON CONFLICT(ring) DO UPDATE SET \
                 token=CASE WHEN projection_leases.holder=excluded.holder \
                 AND projection_leases.instance=excluded.instance \
                 THEN projection_leases.token ELSE projection_leases.token+1 END, \
                 holder=excluded.holder, instance=excluded.instance, \
                 expires_at=excluded.expires_at \
                 WHERE projection_leases.holder=excluded.holder OR projection_leases.expires_at<=$5",
                vec![
                    ring.as_ref().to_vec().into(),
                    holder.replica.to_vec().into(),
                    holder.instance.to_vec().into(),
                    seconds(now.saturating_add(PROJECTION_LEASE_TTL))?,
                    seconds(now)?,
                ],
            ))
            .await?;
        // 2. The row read back names the holder, a refused update leaves the other holder in it.
        let row = transaction
            .query_one(Statement::from_sql_and_values(
                backend,
                "SELECT holder,instance,token FROM projection_leases WHERE ring=$1",
                vec![ring.as_ref().to_vec().into()],
            ))
            .await?
            .ok_or_else(|| DbErr::Custom("projection lease row is missing".into()))?;
        transaction.commit().await?;
        let held = row.try_get::<Vec<u8>>("", "holder")? == holder.replica
            && row.try_get::<Vec<u8>>("", "instance")? == holder.instance;
        Ok(held.then_some(ProjectionLease {
            ring,
            holder,
            token: row.try_get("", "token")?,
        }))
    }
}

impl ProjectionLease {
    /// The first write of every projection transaction, it renews the lease or refuses the commit.
    pub(crate) async fn fence(
        &self,
        transaction: &DatabaseTransaction,
        now: u64,
    ) -> Result<(), DbErr> {
        let renewed = transaction
            .execute(Statement::from_sql_and_values(
                transaction.get_database_backend(),
                "UPDATE projection_leases SET expires_at=$1 WHERE ring=$2 AND holder=$3 \
                 AND token=$4 AND expires_at>$5",
                vec![
                    seconds(now.saturating_add(PROJECTION_LEASE_TTL))?,
                    self.ring.as_ref().to_vec().into(),
                    self.holder.replica.to_vec().into(),
                    self.token.into(),
                    seconds(now)?,
                ],
            ))
            .await?
            .rows_affected();
        if renewed != 1 {
            return Err(DbErr::Custom(
                "the projection lease expired or moved to another replica".into(),
            ));
        }
        Ok(())
    }
}

fn seconds(unix: u64) -> Result<Value, DbErr> {
    i64::try_from(unix)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("lease time exceeds the column range".into()))
}
