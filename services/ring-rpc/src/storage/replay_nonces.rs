use sea_orm::{ConnectionTrait, DbErr, Statement, Value};

use crate::{authorize::AUTH_SKEW, replay::ReplayCheck};

pub(crate) struct NonceBook<'a, C> {
    pub conn: &'a C,
}

impl<C: ConnectionTrait> NonceBook<'_, C> {
    /// False when any process sharing the store already spent the nonce.
    pub async fn spend(&self, check: &ReplayCheck) -> Result<bool, DbErr> {
        // A replica whose clock lags by up to one skew still finds the nonce.
        let expired = check.now.saturating_sub(2 * AUTH_SKEW.as_secs());
        let prune = "DELETE FROM replay_nonces WHERE signed_at<$1";
        self.conn
            .execute(self.statement(prune, vec![seconds_value(expired)?]))
            .await?;
        let insert = "INSERT INTO replay_nonces(ring,nonce,signed_at) VALUES($1,$2,$3) \
                      ON CONFLICT(ring,nonce) DO NOTHING";
        let values = vec![
            Value::from(check.ring.as_ref().to_vec()),
            Value::from(check.nonce.to_vec()),
            seconds_value(check.timestamp)?,
        ];
        let inserted = self.conn.execute(self.statement(insert, values)).await?;
        Ok(inserted.rows_affected() == 1)
    }

    fn statement(&self, sql: &str, values: Vec<Value>) -> Statement {
        Statement::from_sql_and_values(self.conn.get_database_backend(), sql, values)
    }
}

fn seconds_value(seconds: u64) -> Result<Value, DbErr> {
    i64::try_from(seconds)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("nonce timestamp exceeds the column range".into()))
}
