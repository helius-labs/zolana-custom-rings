use custom_ring_interface::{RecordWriteData, APPLY_BATCH};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbErr, QueryResult, Statement, TransactionTrait, Value,
};
use solana_address::Address;
use solana_signature::Signature;
use zolana_ring_client::rpc::{RecordUpdateStatus, SubmitRecordUpdateRequest};
use zolana_ring_policy::ListSet;

use crate::{
    landing::Attempt,
    record_update::{
        authority_batch, ApprovalGrant, AuthorityHead, CheckedUpdate, PendingApproval,
        QueuedUpdate, RecordUpdateRefusal, UpdateSigner, WalletBatch, MAX_BATCH_ATTEMPTS,
    },
};

/// Held off chain for list approval, never in a batch until an approval joins it.
const PENDING_APPROVAL: &str = "pending_approval";
const QUEUED: &str = "queued";
const SUBMITTED: &str = "submitted";
const APPLIED: &str = "applied";
const REFUSED: &str = "refused";
const FAILED: &str = "failed";
const PENDING_APPROVAL_COLUMNS: &str = "id, signer, member, writes, awaited, valid_until_slot";
const HEAD_COLUMNS: &str =
    "u.seq, u.id, u.ring, u.registry, u.writes, u.signer, u.role, u.queued_slot, \
                            u.valid_until_slot";
/// Keys bound into one delete, under every backend's parameter ceiling.
const KEYS_PER_DELETE: usize = 256;
/// One update past a full batch, the planner reads whether more wallet updates wait behind it.
const OLDEST_HEADS: usize = APPLY_BATCH + 1;
const EXPIRY_HEADS_PER_STATUS: usize = APPLY_BATCH;
const WALLET_ROLE: &str = "wallet";
const POLICY_ROLE: &str = "policy";

/// Every update keyed by its statement hash.
pub(crate) struct UpdateQueue<'a> {
    db: &'a DatabaseConnection,
    #[cfg(test)]
    read: std::sync::atomic::AtomicUsize,
}

#[must_use]
pub(crate) struct NewUpdate<'a> {
    pub request: &'a SubmitRecordUpdateRequest,
    pub update: &'a CheckedUpdate,
    pub queued_slot: u64,
    /// Updates pending list approval the update approves, they queue joined to it.
    pub approves: &'a [[u8; 32]],
}

/// Recorded and not yet settled, its updates wait on its signature.
pub(crate) struct OpenBatch {
    pub id: i64,
    pub attempt: Attempt,
}

#[must_use]
pub(crate) struct NewBatch<'a> {
    pub registry: Address,
    pub attempt: Attempt,
    /// The registry revision the `Update` names.
    pub revision: u64,
    pub updates: &'a [QueuedUpdate],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApprovalScope {
    pub ring: Address,
    pub registry: Address,
}

pub(crate) struct ApprovalCandidates<'a> {
    pub scope: ApprovalScope,
    pub grants: &'a [ApprovalGrant],
    pub slot: u64,
}

pub(crate) struct PendingApprovalPage {
    pub scope: ApprovalScope,
    pub cursor: Option<[u8; 32]>,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchOutcome {
    Applied,
    /// The transaction failed or can no longer land, its updates queue again until `MAX_BATCH_ATTEMPTS`.
    Requeued,
}

impl<'a> UpdateQueue<'a> {
    pub fn new(db: &'a DatabaseConnection) -> Self {
        Self {
            db,
            #[cfg(test)]
            read: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub async fn contains(&self, id: &[u8; 32]) -> Result<bool, DbErr> {
        let sql = "SELECT 1 AS found FROM records_updates WHERE id=$1";
        Ok(self.query_one(sql, vec![bytes(id)]).await?.is_some())
    }

    /// A resubmitted update keeps its first row.
    pub async fn insert(&self, new: NewUpdate<'_>) -> Result<(), DbErr> {
        let request =
            serde_json::to_string(new.request).map_err(|error| DbErr::Custom(error.to_string()))?;
        let id = bytes(&new.update.id.0 .0);
        let (status, awaited, member) = match new.update.awaited {
            Some(awaited) => (
                PENDING_APPROVAL,
                awaited.lists.record_bits(),
                bytes(&awaited.member),
            ),
            None => (QUEUED, 0, Value::Bytes(None)),
        };
        let transaction = self.db.begin().await?;
        let sql = "INSERT INTO records_updates(id,registry,ring,request,writes,signer,role,\
                   queued_slot,valid_until_slot,status,awaited,member) \
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) \
                   ON CONFLICT(id) DO NOTHING RETURNING seq";
        let registry = bytes(new.request.registry.0.as_array());
        let values = vec![
            id.clone(),
            registry.clone(),
            bytes(new.request.update.ring.0.as_array()),
            request.into(),
            bytemuck::cast_slice::<RecordWriteData, u8>(&new.update.writes)
                .to_vec()
                .into(),
            bytes(new.update.signer.address().as_array()),
            role(new.update.signer).into(),
            integer(new.queued_slot)?,
            integer(new.request.update.valid_until_slot)?,
            status.into(),
            integer(awaited)?,
            member,
        ];
        let inserted: Option<i64> = transaction
            .query_one(statement(&transaction, sql, values))
            .await?
            .map(|row| row.try_get("", "seq"))
            .transpose()?;
        // A resubmit that lost the insert race joins nothing.
        let Some(seq) = inserted else {
            return transaction.commit().await;
        };
        // 1. Each record the update writes, the planner finds an earlier update on it by index.
        let members = new
            .update
            .written_members()
            .map_err(|refusal| DbErr::Custom(refusal.to_string()))?;
        for member in &members {
            let sql = "INSERT INTO records_update_members(seq,registry,member) VALUES($1,$2,$3)";
            transaction
                .execute(statement(
                    &transaction,
                    sql,
                    vec![seq.into(), registry.clone(), bytes(member)],
                ))
                .await?;
        }
        let approves = new.approves;
        for pending in approves {
            let sql = "UPDATE records_updates SET status=$1, joined=$2 \
                       WHERE id=$3 AND status=$4 AND registry=$5 AND ring=$6";
            let values = vec![
                QUEUED.into(),
                id.clone(),
                bytes(pending),
                PENDING_APPROVAL.into(),
                registry.clone(),
                bytes(new.request.update.ring.0.as_array()),
            ];
            let joined = transaction
                .execute(statement(&transaction, sql, values))
                .await?;
            if joined.rows_affected() != 1 {
                transaction.rollback().await?;
                return Err(corrupt("pending approval scope"));
            }
        }
        // 2. An approval expires with the earliest update it joined, so expiry reads one column.
        if !approves.is_empty() {
            let sql = "UPDATE records_updates SET valid_until_slot=(SELECT MIN(valid_until_slot) \
                       FROM records_updates WHERE id=$1 OR joined=$1) WHERE id=$1";
            transaction
                .execute(statement(&transaction, sql, vec![id]))
                .await?;
        }
        transaction.commit().await
    }

    pub async fn status(&self, id: &[u8; 32]) -> Result<Option<RecordUpdateStatus>, DbErr> {
        let sql = "SELECT u.status, u.reason, b.signature, b.revision FROM records_updates AS u \
                   LEFT JOIN records_batches AS b ON b.id = u.batch WHERE u.id=$1";
        let Some(row) = self.query_one(sql, vec![bytes(id)]).await? else {
            return Ok(None);
        };
        let status = row.try_get::<String>("", "status")?;
        Ok(Some(match status.as_str() {
            PENDING_APPROVAL => RecordUpdateStatus::PendingListApproval,
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

    /// Every registry with an update pending list approval, a queued update or an open batch.
    pub async fn registries(&self) -> Result<Vec<Address>, DbErr> {
        let sql = "SELECT DISTINCT registry FROM records_updates WHERE status IN ($1,$2,$3)";
        self.query_all(
            sql,
            vec![PENDING_APPROVAL.into(), QUEUED.into(), SUBMITTED.into()],
        )
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
            attempt: Attempt {
                signature: signature(&row)?,
                last_valid_block_height: unsigned(&row, "last_valid_block_height")?,
            },
        }))
    }

    /// Authority updates first, wallet ones otherwise, read from the oldest queued heads alone.
    pub async fn plan(
        &self,
        registry: Address,
        slot: u64,
    ) -> Result<Option<Vec<QueuedUpdate>>, DbErr> {
        let authority = self.authority_heads(registry).await?;
        let blocking = !authority.is_empty();
        let batch = authority_batch(authority);
        if !batch.is_empty() {
            return Ok(Some(batch));
        }
        let oldest = self.oldest_heads(registry).await?;
        Ok(WalletBatch {
            oldest,
            blocking,
            slot,
        }
        .decide())
    }

    /// The oldest authority updates, each marked when an earlier queued wallet update writes one of
    /// its records, its joined updates' records included.
    async fn authority_heads(&self, registry: Address) -> Result<Vec<AuthorityHead>, DbErr> {
        let sql = format!(
            "SELECT {HEAD_COLUMNS}, EXISTS(SELECT 1 FROM records_updates AS j \
             JOIN records_update_members AS m ON m.seq = j.seq \
             JOIN records_update_members AS w ON w.registry = m.registry AND w.member = m.member \
             AND w.seq < u.seq \
             JOIN records_updates AS h ON h.seq = w.seq \
             WHERE (j.seq = u.seq OR j.joined = u.id) AND h.status = $2 AND h.role = $3 \
             AND h.joined IS NULL) AS blocked \
             FROM records_updates AS u WHERE u.registry=$1 AND u.role=$4 AND u.status=$2 \
             ORDER BY u.seq LIMIT $5"
        );
        let values = vec![
            bytes(registry.as_array()),
            QUEUED.into(),
            WALLET_ROLE.into(),
            POLICY_ROLE.into(),
            count(APPLY_BATCH)?,
        ];
        let rows = self.query_all(&sql, values).await?;
        let blocked = rows
            .iter()
            .map(|row| row.try_get::<bool>("", "blocked"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .heads(&rows)
            .await?
            .into_iter()
            .zip(blocked)
            .map(|(update, blocked)| AuthorityHead { update, blocked })
            .collect())
    }

    /// The oldest updates of either role, one past a full batch.
    async fn oldest_heads(&self, registry: Address) -> Result<Vec<QueuedUpdate>, DbErr> {
        let sql = format!(
            "SELECT {HEAD_COLUMNS} FROM records_updates AS u WHERE u.registry=$1 AND u.status=$2 \
             AND u.joined IS NULL ORDER BY u.seq LIMIT $3"
        );
        let values = vec![
            bytes(registry.as_array()),
            QUEUED.into(),
            count(OLDEST_HEADS)?,
        ];
        let rows = self.query_all(&sql, values).await?;
        self.heads(&rows).await
    }

    /// Each joined update's writes ahead of the approval it joined, in submit order.
    async fn heads(&self, rows: &[QueryResult]) -> Result<Vec<QueuedUpdate>, DbErr> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let ids = rows
            .iter()
            .map(|row| column_bytes(row, "id"))
            .collect::<Result<Vec<_>, _>>()?;
        let sql = format!(
            "SELECT id, joined, ring, registry, writes FROM records_updates WHERE status=$1 AND joined IN ({}) \
             ORDER BY seq",
            placeholders(2, ids.len())
        );
        let values = std::iter::once(QUEUED.into())
            .chain(ids.iter().map(bytes))
            .collect();
        let joined = self.query_all(&sql, values).await?;
        rows.iter()
            .zip(ids)
            .map(|(row, id)| {
                let scope = ApprovalScope::from_row(row)?;
                let mut writes = Vec::new();
                let mut members = Vec::new();
                for joined in &joined {
                    if column_bytes(joined, "joined")? == id {
                        if ApprovalScope::from_row(joined)? != scope {
                            return Err(corrupt("joined approval scope"));
                        }
                        members.push(column_bytes(joined, "id")?);
                        writes.extend(stored_writes(joined)?);
                    }
                }
                writes.extend(stored_writes(row)?);
                Ok(QueuedUpdate {
                    id,
                    ring: scope.ring,
                    registry: scope.registry,
                    joined: members,
                    writes,
                    signer: update_signer(row)?,
                    queued_slot: unsigned(row, "queued_slot")?,
                    valid_until_slot: unsigned(row, "valid_until_slot")?,
                })
            })
            .collect()
    }

    pub async fn pending_approvals(
        &self,
        query: ApprovalCandidates<'_>,
    ) -> Result<Vec<PendingApproval>, DbErr> {
        let mut values = vec![
            bytes(query.scope.ring.as_array()),
            bytes(query.scope.registry.as_array()),
            PENDING_APPROVAL.into(),
            integer(query.slot)?,
            count(APPLY_BATCH)?,
        ];
        let mut buckets = Vec::new();
        for grant in query.grants {
            let granted = grant.lists.record_bits();
            let mut awaited = granted;
            while awaited != 0 {
                let member_index = values.len() + 1;
                let awaited_index = member_index + 1;
                values.push(bytes(&grant.member));
                values.push(integer(awaited)?);
                buckets.push(format!(
                    "SELECT * FROM (SELECT {PENDING_APPROVAL_COLUMNS}, seq FROM records_updates \
                     WHERE ring=$1 AND registry=$2 AND status=$3 AND valid_until_slot >= $4 \
                     AND member=${member_index} AND awaited=${awaited_index} \
                     ORDER BY valid_until_slot, seq LIMIT $5) AS pending_{}",
                    buckets.len()
                ));
                awaited = (awaited - 1) & granted;
            }
        }
        if buckets.is_empty() {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {PENDING_APPROVAL_COLUMNS} FROM ({}) AS pending ORDER BY seq LIMIT $5",
            buckets.join(" UNION ALL ")
        );
        self.query_all(&sql, values)
            .await?
            .iter()
            .map(pending_approval)
            .collect()
    }

    pub async fn pending_approval_page(
        &self,
        page: PendingApprovalPage,
    ) -> Result<Option<Vec<PendingApproval>>, DbErr> {
        let ring = bytes(page.scope.ring.as_array());
        let registry = bytes(page.scope.registry.as_array());
        let after = match page.cursor {
            None => 0,
            Some(cursor) => {
                let sql = "SELECT seq FROM records_updates WHERE id=$1 AND ring=$2 AND registry=$3";
                match self
                    .query_one(sql, vec![bytes(&cursor), ring.clone(), registry.clone()])
                    .await?
                {
                    Some(row) => row.try_get::<i64>("", "seq")?,
                    None => return Ok(None),
                }
            }
        };
        let limit = i64::try_from(page.limit)
            .map_err(|_| DbErr::Custom("page limit exceeds the store integer range".to_owned()))?;
        let sql = format!(
            "SELECT {PENDING_APPROVAL_COLUMNS} FROM records_updates \
             WHERE ring=$1 AND registry=$2 AND status=$3 AND seq>$4 ORDER BY seq LIMIT $5"
        );
        let values = vec![
            ring,
            registry,
            PENDING_APPROVAL.into(),
            after.into(),
            limit.into(),
        ];
        self.query_all(&sql, values)
            .await?
            .iter()
            .map(pending_approval)
            .collect::<Result<_, _>>()
            .map(Some)
    }

    pub async fn refuse_pending_approval(
        &self,
        scope: ApprovalScope,
        id: &[u8; 32],
    ) -> Result<bool, DbErr> {
        let sql = "UPDATE records_updates SET status=$1, reason=$2 \
                   WHERE id=$3 AND ring=$4 AND registry=$5 AND status=$6";
        let values = vec![
            REFUSED.into(),
            RecordUpdateRefusal::ListApprovalRefused.to_string().into(),
            bytes(id),
            bytes(scope.ring.as_array()),
            bytes(scope.registry.as_array()),
            PENDING_APPROVAL.into(),
        ];
        let transaction = self.db.begin().await?;
        let refused = finish_updates(&transaction, sql, values).await?;
        transaction.commit().await?;
        Ok(refused == 1)
    }

    pub async fn expire(&self, registry: Address, slot: u64) -> Result<(), DbErr> {
        let transaction = self.db.begin().await?;
        for status in [PENDING_APPROVAL, QUEUED] {
            let sql = "SELECT id, ring, registry FROM records_updates \
                       WHERE registry=$1 AND status=$2 AND joined IS NULL AND valid_until_slot<$3 \
                       ORDER BY valid_until_slot, seq LIMIT $4";
            let heads = transaction
                .query_all(statement(
                    &transaction,
                    sql,
                    vec![
                        bytes(registry.as_array()),
                        status.into(),
                        integer(slot)?,
                        count(EXPIRY_HEADS_PER_STATUS)?,
                    ],
                ))
                .await?;
            for head in heads {
                let scope = ApprovalScope::from_row(&head)?;
                let sql = "UPDATE records_updates SET status=$1, reason=$2 \
                           WHERE (id=$3 OR joined=$3) AND ring=$4 AND registry=$5 AND status IN ($6,$7)";
                let values = vec![
                    REFUSED.into(),
                    RecordUpdateRefusal::Expired.to_string().into(),
                    bytes(&column_bytes(&head, "id")?),
                    bytes(scope.ring.as_array()),
                    bytes(scope.registry.as_array()),
                    PENDING_APPROVAL.into(),
                    QUEUED.into(),
                ];
                finish_updates(&transaction, sql, values).await?;
            }
        }
        transaction.commit().await
    }

    /// The updates joined to `id` share its refusal, or turn pending list approval again when its approver lost the policy role.
    pub async fn refuse(&self, id: &[u8; 32], refusal: RecordUpdateRefusal) -> Result<(), DbErr> {
        let transaction = self.db.begin().await?;
        if refusal == RecordUpdateRefusal::AuthorityLapsed {
            let sql =
                "UPDATE records_updates SET status=$1, joined=NULL WHERE joined=$2 AND status=$3";
            let values = vec![PENDING_APPROVAL.into(), bytes(id), QUEUED.into()];
            transaction
                .execute(statement(&transaction, sql, values))
                .await?;
        }
        let sql = "UPDATE records_updates SET status=$2, reason=$3 \
                   WHERE (id=$1 OR joined=$1) AND status=$4";
        let values = vec![
            bytes(id),
            REFUSED.into(),
            refusal.to_string().into(),
            QUEUED.into(),
        ];
        finish_updates(&transaction, sql, values).await?;
        transaction.commit().await
    }

    /// Recorded before the transaction is sent, a restart settles it by its signature.
    pub async fn record_batch(&self, batch: NewBatch<'_>) -> Result<(), DbErr> {
        let transaction = self.db.begin().await?;
        let sql =
            "INSERT INTO records_batches(registry,signature,revision,last_valid_block_height,\
                   status) VALUES($1,$2,$3,$4,$5) RETURNING id";
        let values = vec![
            bytes(batch.registry.as_array()),
            batch.attempt.signature.as_ref().to_vec().into(),
            integer(batch.revision)?,
            integer(batch.attempt.last_valid_block_height)?,
            SUBMITTED.into(),
        ];
        let id: i64 = transaction
            .query_one(statement(&transaction, sql, values))
            .await?
            .ok_or_else(|| corrupt("batch id"))?
            .try_get("", "id")?;
        for update in batch.updates {
            if update.registry != batch.registry {
                transaction.rollback().await?;
                return Err(corrupt("batch registry"));
            }
            let sql = "UPDATE records_updates SET status=$1, batch=$2 \
                       WHERE ((id=$3 AND joined IS NULL) OR joined=$3) AND status=$4 \
                       AND registry=$5 AND ring=$6 RETURNING id, joined";
            let values = vec![
                SUBMITTED.into(),
                id.into(),
                bytes(&update.id),
                QUEUED.into(),
                bytes(update.registry.as_array()),
                bytes(update.ring.as_array()),
            ];
            let claimed = transaction
                .query_all(statement(&transaction, sql, values))
                .await?;
            let mut matches = claimed.len() == update.joined.len() + 1;
            for row in claimed {
                let member = column_bytes(&row, "id")?;
                let joined = row.try_get::<Option<Vec<u8>>>("", "joined")?;
                matches &= if member == update.id {
                    joined.is_none()
                } else {
                    update.joined.contains(&member)
                        && joined.as_deref() == Some(update.id.as_slice())
                };
            }
            if !matches {
                transaction.rollback().await?;
                return Err(corrupt("batch selection"));
            }
        }
        transaction.commit().await
    }

    pub async fn settle(&self, batch: i64, outcome: BatchOutcome) -> Result<(), DbErr> {
        let batch_status = match outcome {
            BatchOutcome::Applied => APPLIED,
            BatchOutcome::Requeued => FAILED,
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
        match outcome {
            BatchOutcome::Applied => {
                let sql = "UPDATE records_updates SET status=$1 WHERE batch=$2";
                finish_updates(&transaction, sql, vec![APPLIED.into(), batch.into()]).await?;
            }
            BatchOutcome::Requeued => {
                let sql = "UPDATE records_updates SET status=$1, reason=$2, batch=NULL, \
                           attempts=attempts+1 WHERE batch=$3 AND attempts+1>=$4";
                let values = vec![
                    REFUSED.into(),
                    RecordUpdateRefusal::BatchFailed.to_string().into(),
                    batch.into(),
                    integer(MAX_BATCH_ATTEMPTS)?,
                ];
                finish_updates(&transaction, sql, values).await?;
                let sql = "UPDATE records_updates SET status=$1, batch=NULL, \
                           attempts=attempts+1 WHERE batch=$2";
                transaction
                    .execute(statement(
                        &transaction,
                        sql,
                        vec![QUEUED.into(), batch.into()],
                    ))
                    .await?;
            }
        }
        transaction.commit().await
    }

    async fn query_one(&self, sql: &str, values: Vec<Value>) -> Result<Option<QueryResult>, DbErr> {
        self.db.query_one(statement(self.db, sql, values)).await
    }

    async fn query_all(&self, sql: &str, values: Vec<Value>) -> Result<Vec<QueryResult>, DbErr> {
        let rows = self.db.query_all(statement(self.db, sql, values)).await?;
        #[cfg(test)]
        self.read
            .fetch_add(rows.len(), std::sync::atomic::Ordering::Relaxed);
        Ok(rows)
    }
}

impl ApprovalScope {
    fn from_row(row: &QueryResult) -> Result<Self, DbErr> {
        Ok(Self {
            ring: address(row, "ring")?,
            registry: address(row, "registry")?,
        })
    }
}

/// Drops the member rows of the updates `sql` finishes in its transaction, so the blocking check
/// reads the live queue alone.
async fn finish_updates<C: ConnectionTrait>(
    connection: &C,
    sql: &str,
    values: Vec<Value>,
) -> Result<usize, DbErr> {
    let finished = connection
        .query_all(statement(
            connection,
            &format!("{sql} RETURNING seq"),
            values,
        ))
        .await?;
    let seqs = finished
        .iter()
        .map(|row| row.try_get::<i64>("", "seq"))
        .collect::<Result<Vec<_>, _>>()?;
    for chunk in seqs.chunks(KEYS_PER_DELETE) {
        let sql = format!(
            "DELETE FROM records_update_members WHERE seq IN ({})",
            placeholders(1, chunk.len())
        );
        let values = chunk.iter().map(|seq| Value::from(*seq)).collect();
        connection
            .execute(statement(connection, &sql, values))
            .await?;
    }
    Ok(seqs.len())
}

/// `$first` onward, NULL for none so an empty list matches no row.
fn placeholders(first: usize, count: usize) -> String {
    match count {
        0 => "NULL".to_owned(),
        _ => (first..first + count)
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn pending_approval(row: &QueryResult) -> Result<PendingApproval, DbErr> {
    let lists =
        ListSet::from_record_bits(unsigned(row, "awaited")?).ok_or_else(|| corrupt("awaited"))?;
    Ok(PendingApproval {
        id: column_bytes(row, "id")?,
        wallet: address(row, "signer")?,
        member: column_bytes(row, "member")?,
        lists,
        writes: stored_writes(row)?.len(),
        valid_until_slot: unsigned(row, "valid_until_slot")?,
    })
}

pub(crate) fn role(signer: UpdateSigner) -> &'static str {
    match signer {
        UpdateSigner::Wallet(_) => WALLET_ROLE,
        UpdateSigner::PolicyAuthority(_) => POLICY_ROLE,
    }
}

fn update_signer(row: &QueryResult) -> Result<UpdateSigner, DbErr> {
    let signer = address(row, "signer")?;
    match row.try_get::<String>("", "role")?.as_str() {
        WALLET_ROLE => Ok(UpdateSigner::Wallet(signer)),
        POLICY_ROLE => Ok(UpdateSigner::PolicyAuthority(signer)),
        _ => Err(corrupt("role")),
    }
}

fn statement<C: ConnectionTrait>(connection: &C, sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(connection.get_database_backend(), sql, values)
}

fn bytes(value: &[u8; 32]) -> Value {
    value.to_vec().into()
}

fn count(value: usize) -> Result<Value, DbErr> {
    i64::try_from(value)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("count exceeds the store integer range".to_owned()))
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

fn stored_writes(row: &QueryResult) -> Result<Vec<RecordWriteData>, DbErr> {
    bytemuck::try_cast_slice::<u8, RecordWriteData>(&row.try_get::<Vec<u8>>("", "writes")?)
        .map(<[RecordWriteData]>::to_vec)
        .map_err(|_| corrupt("writes"))
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use spr_indexer_api::Hash;
    use zolana_ring_client::rpc::{RecordUpdate, RecordUpdateId};

    use super::*;
    use crate::{database::Store, record_update::AwaitedLists};
    use zolana_ring_policy::ListId;

    const REGISTRY: Address = Address::new_from_array([0x52; 32]);
    const RING: Address = Address::new_from_array([8; 32]);
    const UPDATES: u32 = 5_000;

    fn member(index: u32) -> [u8; 32] {
        let mut member = [0; 32];
        member[..4].copy_from_slice(&index.to_be_bytes());
        member
    }

    struct UpdateFixture {
        request: SubmitRecordUpdateRequest,
        update: CheckedUpdate,
    }

    impl UpdateFixture {
        fn new(index: u32, signer: UpdateSigner) -> Self {
            let mut id = member(index);
            id[31] = u8::from(signer.is_authority()) + 1;
            Self {
                request: SubmitRecordUpdateRequest {
                    registry: REGISTRY.into(),
                    update: RecordUpdate {
                        genesis_hash: Hash([0; 32]),
                        ring: RING.into(),
                        entries: Vec::new(),
                        valid_until_slot: u64::from(u32::MAX),
                        awaited_lists: 0,
                    },
                    signer: signer.address().into(),
                    signature: Signature::default().into(),
                },
                update: CheckedUpdate {
                    id: RecordUpdateId(Hash(id)),
                    writes: vec![RecordWriteData {
                        member: member(index),
                        ..RecordWriteData::default()
                    }],
                    entries: Vec::new(),
                    signer,
                    awaited: None,
                },
            }
        }

        fn pending(index: u32) -> Self {
            let mut fixture = Self::new(
                index,
                UpdateSigner::Wallet(Address::new_from_array([1; 32])),
            );
            fixture.update.awaited = Some(AwaitedLists {
                lists: ListSet::single(ListId::Allow),
                member: member(0),
            });
            fixture.request.update.awaited_lists = ListId::Allow.record_bit();
            fixture
        }

        async fn insert(
            &self,
            queue: &UpdateQueue<'_>,
            approves: &[[u8; 32]],
        ) -> Result<(), DbErr> {
            queue
                .insert(NewUpdate {
                    request: &self.request,
                    update: &self.update,
                    queued_slot: 0,
                    approves,
                })
                .await
        }
    }

    async fn insert(queue: &UpdateQueue<'_>, index: u32, signer: UpdateSigner) {
        UpdateFixture::new(index, signer)
            .insert(queue, &[])
            .await
            .expect("insert");
    }

    #[tokio::test]
    async fn approval_insert_rolls_back_when_pending_scope_changes() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let queue = UpdateQueue::new(store.connection());
        let pending = UpdateFixture::pending(0);
        pending.insert(&queue, &[]).await.expect("pending");
        let approval = UpdateFixture::new(
            1,
            UpdateSigner::PolicyAuthority(Address::new_from_array([2; 32])),
        );
        queue
            .db
            .execute(statement(
                queue.db,
                "UPDATE records_updates SET registry=$1 WHERE id=$2",
                vec![
                    bytes(Address::new_from_array([3; 32]).as_array()),
                    bytes(&pending.update.id.0 .0),
                ],
            ))
            .await
            .expect("change scope");
        assert!(approval
            .insert(&queue, &[pending.update.id.0 .0])
            .await
            .is_err());
        assert!(!queue
            .contains(&approval.update.id.0 .0)
            .await
            .expect("lookup"));
        assert_eq!(
            queue.status(&pending.update.id.0 .0).await.expect("status"),
            Some(RecordUpdateStatus::PendingListApproval)
        );
        assert_eq!(member_rows(&queue).await, 1);
    }

    #[tokio::test]
    async fn batch_claim_rolls_back_when_a_selected_member_changes() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let queue = UpdateQueue::new(store.connection());
        let pending = UpdateFixture::pending(0);
        pending.insert(&queue, &[]).await.expect("pending");
        let approval = UpdateFixture::new(
            1,
            UpdateSigner::PolicyAuthority(Address::new_from_array([2; 32])),
        );
        approval
            .insert(&queue, &[pending.update.id.0 .0])
            .await
            .expect("approval");
        let batch = queue.plan(REGISTRY, 0).await.expect("plan").expect("batch");
        queue
            .db
            .execute(statement(
                queue.db,
                "UPDATE records_updates SET registry=$1 WHERE id=$2",
                vec![
                    bytes(Address::new_from_array([3; 32]).as_array()),
                    bytes(&pending.update.id.0 .0),
                ],
            ))
            .await
            .expect("change scope");
        assert!(queue.plan(REGISTRY, 0).await.is_err());
        assert!(queue
            .record_batch(NewBatch {
                registry: REGISTRY,
                attempt: Attempt {
                    signature: Signature::default(),
                    last_valid_block_height: 10
                },
                revision: 0,
                updates: &batch,
            })
            .await
            .is_err());
        assert!(queue
            .open_batch(REGISTRY)
            .await
            .expect("open batch")
            .is_none());
        assert_eq!(
            queue
                .status(&approval.update.id.0 .0)
                .await
                .expect("status"),
            Some(RecordUpdateStatus::Queued)
        );
        assert_eq!(member_rows(&queue).await, 2);
    }

    #[tokio::test]
    async fn expiry_and_batch_claim_keep_one_group_status() {
        for expiry_first in [true, false] {
            let store = Store::open("sqlite::memory:", 1).await.expect("store");
            let queue = UpdateQueue::new(store.connection());
            let mut pending = UpdateFixture::pending(0);
            pending.request.update.valid_until_slot = 10;
            pending.insert(&queue, &[]).await.expect("pending");
            let approval = UpdateFixture::new(
                1,
                UpdateSigner::PolicyAuthority(Address::new_from_array([2; 32])),
            );
            approval
                .insert(&queue, &[pending.update.id.0 .0])
                .await
                .expect("approval");
            let batch = queue.plan(REGISTRY, 0).await.expect("plan").expect("batch");
            if expiry_first {
                queue.expire(REGISTRY, 11).await.expect("expire");
            }
            let claimed = queue
                .record_batch(NewBatch {
                    registry: REGISTRY,
                    attempt: Attempt {
                        signature: Signature::default(),
                        last_valid_block_height: 20,
                    },
                    revision: 0,
                    updates: &batch,
                })
                .await;
            if expiry_first {
                assert!(claimed.is_err());
                assert!(queue
                    .open_batch(REGISTRY)
                    .await
                    .expect("open batch")
                    .is_none());
                assert_eq!(member_rows(&queue).await, 0);
            } else {
                claimed.expect("claim");
                queue.expire(REGISTRY, 11).await.expect("expire");
                let open = queue
                    .open_batch(REGISTRY)
                    .await
                    .expect("open batch")
                    .expect("claimed batch");
                queue
                    .settle(open.id, BatchOutcome::Applied)
                    .await
                    .expect("settle");
            }
            for id in [pending.update.id.0 .0, approval.update.id.0 .0] {
                let status = queue.status(&id).await.expect("status").expect("row");
                if expiry_first {
                    assert!(matches!(status, RecordUpdateStatus::Refused { .. }));
                } else {
                    assert!(matches!(
                        status,
                        RecordUpdateStatus::Applied { revision: 1, .. }
                    ));
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    enum QueueWinner {
        Claim,
        Expiry,
    }

    #[tokio::test]
    #[ignore = "needs RING_RPC_TEST_POSTGRES_URL"]
    async fn overlapping_expiry_and_claim_preserve_the_winning_transaction_on_postgres() {
        let url = std::env::var("RING_RPC_TEST_POSTGRES_URL").expect("postgres url");
        let winner_store = Store::open(&url, 1).await.expect("winner store");
        let contender_store = Store::open(&url, 1).await.expect("contender store");
        let observer_store = Store::open(&url, 1).await.expect("observer store");
        for winner in [QueueWinner::Claim, QueueWinner::Expiry] {
            let registry = Address::new_from_array(rand::random());
            let queue = UpdateQueue::new(winner_store.connection());
            let mut pending = UpdateFixture::pending(0);
            pending.request.registry = registry.into();
            pending.request.update.valid_until_slot = 10;
            pending.update.id = RecordUpdateId(Hash(rand::random()));
            pending.insert(&queue, &[]).await.expect("pending");
            let mut approval = UpdateFixture::new(
                1,
                UpdateSigner::PolicyAuthority(Address::new_from_array([2; 32])),
            );
            approval.request.registry = registry.into();
            approval.update.id = RecordUpdateId(Hash(rand::random()));
            approval
                .insert(&queue, &[pending.update.id.0 .0])
                .await
                .expect("approval");
            let batch = queue.plan(registry, 0).await.expect("plan").expect("batch");
            let contender_pid = backend_pid(contender_store.connection()).await;
            let transaction = winner_store
                .connection()
                .begin()
                .await
                .expect("winning transaction");
            let winner_pid = backend_pid(&transaction).await;
            match winner {
                QueueWinner::Claim => {
                    let claimed_batch: i64 = transaction.query_one(statement(&transaction,
                        "INSERT INTO records_batches(registry,signature,revision,last_valid_block_height,status) \
                         VALUES($1,$2,0,20,$3) RETURNING id",
                        vec![bytes(registry.as_array()), Signature::default().as_ref().to_vec().into(), SUBMITTED.into()],
                    )).await.expect("winning batch").expect("batch row").try_get("", "id").expect("batch id");
                    let claimed = transaction.execute(statement(&transaction,
                        "UPDATE records_updates SET status=$1,batch=$2 WHERE registry=$3 AND status=$4",
                        vec![SUBMITTED.into(), claimed_batch.into(), bytes(registry.as_array()), QUEUED.into()],
                    )).await.expect("winning claim");
                    assert_eq!(claimed.rows_affected(), 2);
                }
                QueueWinner::Expiry => {
                    let expired = finish_updates(&transaction,
                        "UPDATE records_updates SET status=$1,reason=$2 WHERE registry=$3 AND status=$4",
                        vec![REFUSED.into(), RecordUpdateRefusal::Expired.to_string().into(), bytes(registry.as_array()), QUEUED.into()],
                    ).await.expect("winning expiry");
                    assert_eq!(expired, 2);
                }
            }
            let contender = contender_store.clone();
            let operation = tokio::spawn(async move {
                let queue = UpdateQueue::new(contender.connection());
                match winner {
                    QueueWinner::Claim => queue.expire(registry, 11).await,
                    QueueWinner::Expiry => {
                        queue
                            .record_batch(NewBatch {
                                registry,
                                attempt: Attempt {
                                    signature: Signature::default(),
                                    last_valid_block_height: 20,
                                },
                                revision: 0,
                                updates: &batch,
                            })
                            .await
                    }
                }
            });
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    let observer = observer_store.connection();
                    let blocked: bool = observer
                        .query_one(statement(
                            observer,
                            "SELECT $1 = ANY(pg_blocking_pids($2)) AS blocked",
                            vec![winner_pid.into(), contender_pid.into()],
                        ))
                        .await
                        .expect("lock wait")
                        .expect("lock row")
                        .try_get("", "blocked")
                        .expect("blocked");
                    if blocked {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("contender must reach the winning row lock");
            transaction.commit().await.expect("release winner");
            let result = tokio::time::timeout(std::time::Duration::from_secs(10), operation)
                .await
                .expect("contender must finish after release")
                .expect("contender task");
            let open = queue.open_batch(registry).await.expect("open batch");
            let expected_batch = match winner {
                QueueWinner::Claim => {
                    result.expect("expiry skips the claimed group");
                    Some(open.expect("claimed batch").id)
                }
                QueueWinner::Expiry => {
                    assert!(result.is_err());
                    assert!(open.is_none());
                    None
                }
            };
            let rows = queue
                .query_all(
                    "SELECT id,joined,status,batch FROM records_updates WHERE registry=$1",
                    vec![bytes(registry.as_array())],
                )
                .await
                .expect("group rows");
            assert_eq!(rows.len(), 2);
            for row in rows {
                let id = column_bytes(&row, "id").expect("update id");
                let joined = row
                    .try_get::<Option<Vec<u8>>>("", "joined")
                    .expect("joined head");
                if id == pending.update.id.0 .0 {
                    assert_eq!(joined.as_deref(), Some(approval.update.id.0 .0.as_slice()));
                } else {
                    assert_eq!(id, approval.update.id.0 .0);
                    assert!(joined.is_none());
                }
                assert_eq!(
                    row.try_get::<Option<i64>>("", "batch").expect("batch link"),
                    expected_batch
                );
                assert_eq!(
                    row.try_get::<String>("", "status").expect("status"),
                    if expected_batch.is_some() {
                        SUBMITTED
                    } else {
                        REFUSED
                    }
                );
            }
            let batch_count: i64 = queue
                .query_one(
                    "SELECT COUNT(*) AS count FROM records_batches WHERE registry=$1",
                    vec![bytes(registry.as_array())],
                )
                .await
                .expect("batches")
                .expect("count row")
                .try_get("", "count")
                .expect("count");
            assert_eq!(batch_count, if expected_batch.is_some() { 1 } else { 0 });
            assert_eq!(
                registry_member_rows(&queue, registry).await,
                if expected_batch.is_some() { 2 } else { 0 }
            );
            if let Some(batch_id) = expected_batch {
                queue
                    .settle(batch_id, BatchOutcome::Applied)
                    .await
                    .expect("settle winner");
                for id in [pending.update.id.0 .0, approval.update.id.0 .0] {
                    assert!(matches!(
                        queue.status(&id).await.expect("status"),
                        Some(RecordUpdateStatus::Applied { revision: 1, .. })
                    ));
                }
                assert_eq!(registry_member_rows(&queue, registry).await, 0);
            }
            for sql in [
                "DELETE FROM records_update_members WHERE registry=$1",
                "DELETE FROM records_updates WHERE registry=$1",
                "DELETE FROM records_batches WHERE registry=$1",
            ] {
                queue
                    .db
                    .execute(statement(queue.db, sql, vec![bytes(registry.as_array())]))
                    .await
                    .expect("remove fixture rows");
            }
        }
    }

    #[tokio::test]
    async fn expired_backlog_leaves_live_approval_reads_bounded() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let queue = UpdateQueue::new(store.connection());
        let backlog = 3 * EXPIRY_HEADS_PER_STATUS;
        for index in 0..backlog {
            let mut pending = UpdateFixture::pending(index as u32);
            pending.request.update.valid_until_slot = 10;
            pending.insert(&queue, &[]).await.expect("expired pending");
        }
        let live = UpdateFixture::pending(backlog as u32);
        live.insert(&queue, &[]).await.expect("live pending");
        queue.expire(REGISTRY, 11).await.expect("bounded expiry");
        assert_eq!(
            member_rows(&queue).await,
            (backlog + 1 - EXPIRY_HEADS_PER_STATUS) as i64
        );
        let grants = [ApprovalGrant {
            member: member(0),
            lists: ListSet::single(ListId::Allow),
        }];
        queue.read.store(0, Ordering::Relaxed);
        let pending = queue
            .pending_approvals(ApprovalCandidates {
                scope: ApprovalScope {
                    ring: RING,
                    registry: REGISTRY,
                },
                grants: &grants,
                slot: 11,
            })
            .await
            .expect("eligible pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, live.update.id.0 .0);
        assert_eq!(queue.read.load(Ordering::Relaxed), 1);
        for _ in 1..3 {
            queue.expire(REGISTRY, 11).await.expect("drain expiry");
        }
        assert_eq!(member_rows(&queue).await, 1);
    }

    #[tokio::test]
    async fn a_ten_thousand_update_queue_plans_each_flush_from_a_bounded_read() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        plans_from_a_bounded_read(&store).await;
    }

    #[tokio::test]
    #[ignore = "needs RING_RPC_TEST_POSTGRES_URL"]
    async fn a_ten_thousand_update_queue_plans_each_flush_from_a_bounded_read_on_postgres() {
        let url = std::env::var("RING_RPC_TEST_POSTGRES_URL").expect("postgres url");
        let store = Store::open(&url, 1).await.expect("store");
        plans_from_a_bounded_read(&store).await;
    }

    async fn backend_pid(connection: &impl ConnectionTrait) -> i32 {
        connection
            .query_one(statement(
                connection,
                "SELECT pg_backend_pid() AS pid",
                Vec::new(),
            ))
            .await
            .expect("backend pid")
            .expect("pid row")
            .try_get("", "pid")
            .expect("pid")
    }

    async fn registry_member_rows(queue: &UpdateQueue<'_>, registry: Address) -> i64 {
        queue
            .query_one(
                "SELECT COUNT(*) AS count FROM records_update_members WHERE registry=$1",
                vec![bytes(registry.as_array())],
            )
            .await
            .expect("members")
            .expect("count row")
            .try_get("", "count")
            .expect("count")
    }

    async fn member_rows(queue: &UpdateQueue<'_>) -> i64 {
        queue
            .query_one(
                "SELECT COUNT(*) AS rows FROM records_update_members",
                Vec::new(),
            )
            .await
            .expect("count")
            .expect("row")
            .try_get("", "rows")
            .expect("rows")
    }

    async fn plans_from_a_bounded_read(store: &Store) {
        let queue = UpdateQueue::new(store.connection());
        let wallet = UpdateSigner::Wallet(Address::new_from_array([1; 32]));
        let authority = UpdateSigner::PolicyAuthority(Address::new_from_array([2; 32]));
        for index in 0..UPDATES {
            insert(&queue, index, wallet).await;
        }
        for index in 0..UPDATES {
            insert(&queue, index, authority).await;
        }

        // Each authority batch waits for the wallet batch on its records, then goes before the next.
        for flush in 0..4 {
            queue.read.store(0, Ordering::Relaxed);
            let batch = queue
                .plan(REGISTRY, 0)
                .await
                .expect("plan")
                .expect("a batch");
            let read = queue.read.load(Ordering::Relaxed);
            assert!(
                read <= APPLY_BATCH + OLDEST_HEADS,
                "flush {flush} read {read} rows"
            );
            let first = u32::try_from(flush / 2 * APPLY_BATCH).expect("index");
            let members: Vec<[u8; 32]> =
                batch.iter().map(|update| update.writes[0].member).collect();
            assert_eq!(
                members,
                (first..first + APPLY_BATCH as u32)
                    .map(member)
                    .collect::<Vec<_>>()
            );
            assert!(batch
                .iter()
                .all(|update| update.signer.is_authority() == (flush % 2 == 1)));
            queue
                .record_batch(NewBatch {
                    registry: REGISTRY,
                    attempt: Attempt {
                        signature: Signature::default(),
                        last_valid_block_height: 0,
                    },
                    revision: 0,
                    updates: &batch,
                })
                .await
                .expect("batch");
            let open = queue
                .open_batch(REGISTRY)
                .await
                .expect("open")
                .expect("a batch");
            queue
                .settle(open.id, BatchOutcome::Applied)
                .await
                .expect("settle");
            // Each update writes one record, an applied update keeps no member row.
            let queued = 2 * UPDATES as usize - (flush + 1) * APPLY_BATCH;
            assert_eq!(
                member_rows(&queue).await,
                i64::try_from(queued).expect("count")
            );
        }
    }
}
