use custom_ring_interface::storage_instruction::StorageWriteData;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbErr, QueryResult, Statement, TransactionTrait, Value,
};
use solana_address::Address;
use solana_signature::Signature;
use zolana_ring_client::rpc::{RecordUpdateStatus, SubmitRecordUpdateRequest};

use crate::record_update::{CheckedUpdate, QueuedUpdate};

const QUEUED: &str = "queued";
const SUBMITTED: &str = "submitted";
const APPLIED: &str = "applied";
const REFUSED: &str = "refused";
const FAILED: &str = "failed";

/// Every update keyed by its statement hash.
pub(crate) struct UpdateQueue<'a> {
    db: &'a DatabaseConnection,
}

#[must_use]
pub(crate) struct NewUpdate<'a> {
    pub request: &'a SubmitRecordUpdateRequest,
    pub update: &'a CheckedUpdate,
    pub queued_slot: u64,
}

/// Recorded and not yet settled, its updates wait on its signature.
pub(crate) struct OpenBatch {
    pub id: i64,
    pub signature: Signature,
    pub last_valid_block_height: u64,
}

#[must_use]
pub(crate) struct NewBatch<'a> {
    pub registry: Address,
    pub signature: Signature,
    /// The registry revision the `Update` names.
    pub revision: u64,
    pub last_valid_block_height: u64,
    pub updates: &'a [QueuedUpdate],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchOutcome {
    Applied,
    /// The transaction failed or can no longer land, its updates queue again.
    Requeued,
}

impl<'a> UpdateQueue<'a> {
    pub fn new(db: &'a DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn contains(&self, id: &[u8; 32]) -> Result<bool, DbErr> {
        let sql = "SELECT 1 AS found FROM records_updates WHERE id=$1";
        Ok(self.query_one(sql, vec![bytes(id)]).await?.is_some())
    }

    /// A resubmitted update keeps its first row.
    pub async fn insert(&self, new: NewUpdate<'_>) -> Result<(), DbErr> {
        let request =
            serde_json::to_string(new.request).map_err(|error| DbErr::Custom(error.to_string()))?;
        let sql = "INSERT INTO records_updates(id,registry,ring,request,writes,urgent,queued_slot,\
                   valid_until_slot,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) \
                   ON CONFLICT(id) DO NOTHING";
        self.exec(
            sql,
            vec![
                bytes(&new.update.id.0 .0),
                bytes(new.request.registry.0.as_array()),
                bytes(new.request.update.ring.0.as_array()),
                request.into(),
                StorageWriteData::encode_all(&new.update.writes).into(),
                new.update.urgent.into(),
                integer(new.queued_slot)?,
                integer(new.request.update.valid_until_slot)?,
                QUEUED.into(),
            ],
        )
        .await
    }

    pub async fn status(&self, id: &[u8; 32]) -> Result<Option<RecordUpdateStatus>, DbErr> {
        let sql = "SELECT u.status, u.reason, b.signature, b.revision FROM records_updates AS u \
                   LEFT JOIN records_batches AS b ON b.id = u.batch WHERE u.id=$1";
        let Some(row) = self.query_one(sql, vec![bytes(id)]).await? else {
            return Ok(None);
        };
        let status = row.try_get::<String>("", "status")?;
        Ok(Some(match status.as_str() {
            QUEUED => RecordUpdateStatus::Queued,
            SUBMITTED => RecordUpdateStatus::Submitted {
                signature: signature(&row)?.into(),
            },
            APPLIED => RecordUpdateStatus::Applied {
                signature: signature(&row)?.into(),
                revision: unsigned(&row, "revision")?
                    .checked_add(1)
                    .ok_or_else(|| corrupt("revision"))?,
            },
            REFUSED => RecordUpdateStatus::Refused {
                reason: row
                    .try_get::<Option<String>>("", "reason")?
                    .unwrap_or_default(),
            },
            _ => return Err(corrupt("status")),
        }))
    }

    /// Every registry with a queued update or an open batch.
    pub async fn registries(&self) -> Result<Vec<Address>, DbErr> {
        let sql = "SELECT DISTINCT registry FROM records_updates WHERE status IN ($1,$2)";
        self.query_all(sql, vec![QUEUED.into(), SUBMITTED.into()])
            .await?
            .iter()
            .map(|row| address(row, "registry"))
            .collect()
    }

    pub async fn open_batch(&self, registry: Address) -> Result<Option<OpenBatch>, DbErr> {
        let sql = "SELECT id, signature, last_valid_block_height FROM records_batches \
                   WHERE registry=$1 AND status=$2";
        let values = vec![bytes(registry.as_array()), SUBMITTED.into()];
        let Some(row) = self.query_one(sql, values).await? else {
            return Ok(None);
        };
        Ok(Some(OpenBatch {
            id: row.try_get("", "id")?,
            signature: signature(&row)?,
            last_valid_block_height: unsigned(&row, "last_valid_block_height")?,
        }))
    }

    /// Submit order.
    pub async fn queued(&self, registry: Address) -> Result<Vec<QueuedUpdate>, DbErr> {
        let sql = "SELECT id, ring, writes, urgent, queued_slot, valid_until_slot \
                   FROM records_updates WHERE registry=$1 AND status=$2 ORDER BY seq";
        let values = vec![bytes(registry.as_array()), QUEUED.into()];
        self.query_all(sql, values)
            .await?
            .iter()
            .map(|row| {
                let writes = row.try_get::<Vec<u8>>("", "writes")?;
                Ok(QueuedUpdate {
                    id: column_bytes(row, "id")?,
                    ring: address(row, "ring")?,
                    writes: StorageWriteData::parse_all(&writes).map_err(|_| corrupt("writes"))?,
                    urgent: row.try_get("", "urgent")?,
                    queued_slot: unsigned(row, "queued_slot")?,
                    valid_until_slot: unsigned(row, "valid_until_slot")?,
                })
            })
            .collect()
    }

    pub async fn refuse(&self, id: &[u8; 32], reason: &str) -> Result<(), DbErr> {
        let sql = "UPDATE records_updates SET status=$2, reason=$3 WHERE id=$1 AND status=$4";
        self.exec(
            sql,
            vec![bytes(id), REFUSED.into(), reason.into(), QUEUED.into()],
        )
        .await
    }

    /// Recorded before the transaction is sent, a restart settles it by its signature.
    pub async fn record_batch(&self, batch: NewBatch<'_>) -> Result<(), DbErr> {
        let transaction = self.db.begin().await?;
        let sql =
            "INSERT INTO records_batches(registry,signature,revision,last_valid_block_height,\
                   status) VALUES($1,$2,$3,$4,$5) RETURNING id";
        let values = vec![
            bytes(batch.registry.as_array()),
            batch.signature.as_ref().to_vec().into(),
            integer(batch.revision)?,
            integer(batch.last_valid_block_height)?,
            SUBMITTED.into(),
        ];
        let id: i64 = transaction
            .query_one(statement(&transaction, sql, values))
            .await?
            .ok_or_else(|| corrupt("batch id"))?
            .try_get("", "id")?;
        for update in batch.updates {
            let sql = "UPDATE records_updates SET status=$1, batch=$2 WHERE id=$3 AND status=$4";
            let values = vec![
                SUBMITTED.into(),
                id.into(),
                bytes(&update.id),
                QUEUED.into(),
            ];
            transaction
                .execute(statement(&transaction, sql, values))
                .await?;
        }
        transaction.commit().await
    }

    pub async fn settle(&self, batch: i64, outcome: BatchOutcome) -> Result<(), DbErr> {
        let (batch_status, update_status, kept) = match outcome {
            BatchOutcome::Applied => (APPLIED, APPLIED, Some(batch)),
            BatchOutcome::Requeued => (FAILED, QUEUED, None),
        };
        let transaction = self.db.begin().await?;
        let sql = "UPDATE records_batches SET status=$1 WHERE id=$2";
        transaction
            .execute(statement(
                &transaction,
                sql,
                vec![batch_status.into(), batch.into()],
            ))
            .await?;
        let sql = "UPDATE records_updates SET status=$1, batch=$2 WHERE batch=$3";
        let values = vec![update_status.into(), kept.into(), batch.into()];
        transaction
            .execute(statement(&transaction, sql, values))
            .await?;
        transaction.commit().await
    }

    async fn exec(&self, sql: &str, values: Vec<Value>) -> Result<(), DbErr> {
        self.db.execute(statement(self.db, sql, values)).await?;
        Ok(())
    }

    async fn query_one(&self, sql: &str, values: Vec<Value>) -> Result<Option<QueryResult>, DbErr> {
        self.db.query_one(statement(self.db, sql, values)).await
    }

    async fn query_all(&self, sql: &str, values: Vec<Value>) -> Result<Vec<QueryResult>, DbErr> {
        self.db.query_all(statement(self.db, sql, values)).await
    }
}

fn statement<C: ConnectionTrait>(connection: &C, sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(connection.get_database_backend(), sql, values)
}

fn bytes(value: &[u8; 32]) -> Value {
    value.to_vec().into()
}

fn integer(value: u64) -> Result<Value, DbErr> {
    i64::try_from(value)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("value exceeds the store integer range".to_owned()))
}

fn column_bytes(row: &QueryResult, column: &str) -> Result<[u8; 32], DbErr> {
    row.try_get::<Vec<u8>>("", column)?
        .try_into()
        .map_err(|_| corrupt(column))
}

fn address(row: &QueryResult, column: &str) -> Result<Address, DbErr> {
    column_bytes(row, column).map(Address::new_from_array)
}

fn unsigned(row: &QueryResult, column: &str) -> Result<u64, DbErr> {
    u64::try_from(row.try_get::<i64>("", column)?).map_err(|_| corrupt(column))
}

fn signature(row: &QueryResult) -> Result<Signature, DbErr> {
    Signature::try_from(row.try_get::<Vec<u8>>("", "signature")?.as_slice())
        .map_err(|_| corrupt("signature"))
}

fn corrupt(column: &str) -> DbErr {
    DbErr::Custom(format!("stored record update {column} is invalid"))
}
