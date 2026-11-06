use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, IsolationLevel,
    Statement, TransactionTrait, Value,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use zolana_ring_client::rpc::{WalletBalance, WalletEnrollment};

use crate::{
    error::RingRpcError,
    owner_notes::{snapshot_history_through, OwnerNotesPage, OWNER_ROW_BATCH},
    spent_index::{read_revision, read_snapshot, slot_value, NoteSeal},
    utxos::{
        Balances, IndexedNote, OwnerPage, OwnerRange, WalletCursor, WalletCursorScope,
        WalletStatusQuery,
    },
};

const SNAPSHOT_TTL_SECONDS: u64 = 300;

#[derive(Clone, Copy, Debug)]
pub struct WalletSnapshotLimits {
    pub store: NonZeroUsize,
    pub principal_wallet: NonZeroUsize,
}

impl Default for WalletSnapshotLimits {
    fn default() -> Self {
        Self {
            store: const { NonZeroUsize::new(1024).expect("nonzero snapshot limit") },
            principal_wallet: const { NonZeroUsize::new(2).expect("nonzero wallet snapshot limit") },
        }
    }
}

pub(crate) type SharedWalletSnapshots = Arc<Mutex<MemoryWalletSnapshots>>;

#[derive(Default)]
pub(crate) struct MemoryWalletSnapshots {
    sessions: BTreeMap<[u8; 32], MemorySnapshot>,
}

struct MemorySnapshot {
    ring: Address,
    metadata: SnapshotMetadata,
    chunks: VecDeque<Vec<IndexedNote>>,
    released: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotMetadata {
    principal: Vec<u8>,
    wallet: [u8; 32],
    pub expires_at: u64,
    pub through: u64,
    revision: Option<i64>,
    pub enrollment: WalletEnrollment,
    pub balances: Vec<WalletBalance>,
}

pub(crate) struct SnapshotPage {
    pub page: OwnerPage,
    pub metadata: SnapshotMetadata,
    pub id: Option<[u8; 32]>,
}

pub(crate) struct WalletSnapshotRelease {
    pub ring: Address,
    pub wallet: Address,
    pub principal: [u8; 34],
    pub cursor: WalletCursor,
    pub now: u64,
}

pub(crate) struct WalletSnapshots<'a> {
    pub db: &'a DatabaseConnection,
    pub seal: &'a NoteSeal,
    pub limits: WalletSnapshotLimits,
}

pub(crate) struct WalletSnapshotCleanup<'a> {
    pub db: &'a DatabaseConnection,
    pub now: u64,
}

impl SnapshotMetadata {
    fn new(query: WalletStatusQuery, through: u64) -> Result<Self, RingRpcError> {
        Ok(Self {
            principal: query.principal.to_vec(),
            wallet: query.wallet.to_bytes(),
            expires_at: query
                .now
                .checked_add(SNAPSHOT_TTL_SECONDS)
                .ok_or(RingRpcError::StateUnavailable)?,
            through,
            revision: None,
            enrollment: query.enrollment,
            balances: Vec::new(),
        })
    }

    fn page_metadata(&self) -> Self {
        Self {
            principal: self.principal.clone(),
            wallet: self.wallet,
            expires_at: self.expires_at,
            through: self.through,
            revision: self.revision,
            enrollment: self.enrollment,
            balances: Vec::new(),
        }
    }

    fn authorize(&self, principal: &[u8; 34], wallet: &Address) -> Result<(), RingRpcError> {
        if self.principal != principal.as_slice() || self.wallet != wallet.to_bytes() {
            return Err(RingRpcError::InvalidCursor);
        }
        Ok(())
    }
}

impl WalletSnapshotRelease {
    pub(crate) fn validate(&self) -> Result<(), RingRpcError> {
        self.cursor.validate_scope(WalletCursorScope {
            ring: self.ring,
            wallet: self.wallet,
        })
    }
}

impl MemoryWalletSnapshots {
    pub(crate) fn read(&self, query: WalletStatusQuery) -> Result<SnapshotPage, RingRpcError> {
        let cursor = query.after.ok_or(RingRpcError::InvalidCursor)?;
        let session = self
            .sessions
            .get(&cursor.snapshot)
            .ok_or(RingRpcError::WalletSnapshotExpired)?;
        if session.ring != query.ring {
            return Err(RingRpcError::InvalidCursor);
        }
        session
            .metadata
            .authorize(&query.principal, &query.wallet)?;
        if session.released || session.metadata.expires_at <= query.now {
            return Err(RingRpcError::WalletSnapshotExpired);
        }
        let start = session
            .chunks
            .partition_point(|chunk| chunk.last().is_some_and(|note| note.key <= cursor.after));
        let mut notes: Vec<_> = session
            .chunks
            .iter()
            .skip(start)
            .flatten()
            .filter(|note| note.key > cursor.after)
            .take(query.limit.saturating_add(1))
            .copied()
            .collect();
        let more = notes.len() > query.limit;
        notes.truncate(query.limit);
        Ok(SnapshotPage {
            page: OwnerPage { notes, more },
            metadata: session.metadata.page_metadata(),
            id: Some(cursor.snapshot),
        })
    }

    pub(crate) fn capture(
        &mut self,
        capture: MemoryCapture,
        mut read: impl FnMut(OwnerRange) -> OwnerPage,
    ) -> Result<SnapshotPage, RingRpcError> {
        let MemoryCapture {
            query,
            through,
            member,
            limits,
        } = capture;
        let range = OwnerRange {
            member,
            after: None,
            limit: query.limit,
        };
        let page = read(range);
        let mut metadata = SnapshotMetadata::new(query, through)?;
        let mut balances = Balances::default();
        if !page.more {
            for note in &page.notes {
                balances.add(note, through);
            }
            metadata.balances = balances.into_values();
            return Ok(SnapshotPage {
                page,
                metadata,
                id: None,
            });
        }
        let scope_count = self
            .sessions
            .values()
            .filter(|session| {
                session.ring == query.ring
                    && session.metadata.principal == query.principal.as_slice()
                    && session.metadata.wallet == query.wallet.to_bytes()
            })
            .count();
        if self.sessions.len() >= limits.store.get() || scope_count >= limits.principal_wallet.get()
        {
            return Err(RingRpcError::WalletSnapshotCapacity);
        }
        let mut chunks = VecDeque::new();
        let mut range = OwnerRange {
            limit: OWNER_ROW_BATCH,
            ..range
        };
        loop {
            let captured = read(range);
            for note in &captured.notes {
                balances.add(note, through);
            }
            let last = captured.notes.last().map(|note| note.key);
            if !captured.notes.is_empty() {
                chunks.push_back(captured.notes);
            }
            if !captured.more {
                break;
            }
            range.after = Some(last.ok_or(RingRpcError::StateUnavailable)?);
        }
        metadata.balances = balances.into_values();
        let id = loop {
            let id = rand::random();
            if !self.sessions.contains_key(&id) {
                break id;
            }
        };
        self.sessions.insert(
            id,
            MemorySnapshot {
                ring: query.ring,
                metadata: metadata.clone(),
                chunks,
                released: false,
            },
        );
        Ok(SnapshotPage {
            page,
            metadata,
            id: Some(id),
        })
    }

    pub(crate) fn release(&mut self, release: WalletSnapshotRelease) -> Result<(), RingRpcError> {
        release.validate()?;
        let Some(session) = self.sessions.get_mut(&release.cursor.snapshot) else {
            return Ok(());
        };
        if session.ring != release.ring {
            return Err(RingRpcError::InvalidCursor);
        }
        session
            .metadata
            .authorize(&release.principal, &release.wallet)?;
        session.released = true;
        self.cleanup(release.now);
        Ok(())
    }

    pub(crate) fn cleanup(&mut self, now: u64) -> usize {
        let expired = self.sessions.iter().find_map(|(id, session)| {
            (session.released || session.metadata.expires_at <= now).then_some(*id)
        });
        let Some(id) = expired else { return 0 };
        let Some(session) = self.sessions.get_mut(&id) else {
            return 0;
        };
        let removed = session.chunks.pop_front().map_or(0, |chunk| chunk.len());
        if session.chunks.is_empty() {
            self.sessions.remove(&id);
        }
        removed
    }
}

pub(crate) struct MemoryCapture {
    pub query: WalletStatusQuery,
    pub through: u64,
    pub member: [u8; 32],
    pub limits: WalletSnapshotLimits,
}

impl WalletSnapshots<'_> {
    pub(crate) async fn read(
        &self,
        query: WalletStatusQuery,
    ) -> Result<SnapshotPage, RingRpcError> {
        let cursor = query.after.ok_or(RingRpcError::InvalidCursor)?;
        let transaction = read_snapshot(self.db).await?;
        let metadata = self
            .metadata(
                &transaction,
                SnapshotLookup {
                    id: cursor.snapshot,
                    ring: query.ring,
                },
            )
            .await?
            .ok_or(RingRpcError::WalletSnapshotExpired)?;
        metadata.authorize(&query.principal, &query.wallet)?;
        if metadata.expires_at <= query.now {
            return Err(RingRpcError::WalletSnapshotExpired);
        }
        let member = zolana_ring_policy::Member::owner_tag(query.wallet.as_array())
            .map_err(|_| RingRpcError::InvalidCursor)?;
        let range = OwnerRange {
            member: *member.as_bytes(),
            after: Some(cursor.after),
            limit: query.limit,
        };
        let fetched =
            i64::try_from(query.limit.saturating_add(1)).map_err(|_| RingRpcError::InvalidPage)?;
        let rows = transaction.query_all(Statement::from_sql_and_values(
            transaction.get_database_backend(),
            "SELECT note_tag,sealed,spent_slot FROM wallet_snapshot_notes WHERE snapshot_id=$1 AND note_tag>$2 ORDER BY note_tag LIMIT $3",
            vec![cursor.snapshot.to_vec().into(), cursor.after.to_vec().into(), fetched.into()],
        )).await?;
        let reader = OwnerNotesPage {
            ring: query.ring,
            seal: self.seal,
            range,
        };
        let page = OwnerPage {
            more: rows.len() > query.limit,
            notes: rows
                .iter()
                .take(query.limit)
                .map(|row| reader.open(row, &range.member))
                .collect::<Result<_, _>>()?,
        };
        transaction.commit().await?;
        Ok(SnapshotPage {
            page,
            metadata,
            id: Some(cursor.snapshot),
        })
    }

    pub(crate) async fn capture(
        &self,
        query: WalletStatusQuery,
    ) -> Result<SnapshotPage, RingRpcError> {
        let member = zolana_ring_policy::Member::owner_tag(query.wallet.as_array())
            .map_err(|_| RingRpcError::InvalidCursor)?;
        let range = OwnerRange {
            member: *member.as_bytes(),
            after: None,
            limit: query.limit,
        };
        let reader = OwnerNotesPage {
            ring: query.ring,
            seal: self.seal,
            range,
        };
        let initial = read_snapshot(self.db).await?;
        let page = reader.read(&initial).await?;
        if !page.more {
            let through = snapshot_history_through(&initial, query.ring).await?;
            let mut metadata = SnapshotMetadata::new(query, through)?;
            metadata.revision = Some(read_revision(&initial, &query.ring).await?);
            let mut balances = Balances::default();
            for note in &page.notes {
                balances.add(note, through);
            }
            metadata.balances = balances.into_values();
            initial.commit().await?;
            return Ok(SnapshotPage {
                page,
                metadata,
                id: None,
            });
        }
        initial.commit().await?;
        let transaction = match self.db.get_database_backend() {
            DatabaseBackend::Postgres => {
                let transaction = self
                    .db
                    .begin_with_config(Some(IsolationLevel::RepeatableRead), None)
                    .await?;
                // Before the snapshot starts, a row update waited on inside it fails to serialize.
                transaction
                    .execute_unprepared("LOCK TABLE wallet_snapshot_admission IN EXCLUSIVE MODE")
                    .await?;
                transaction
            }
            DatabaseBackend::Sqlite | DatabaseBackend::MySql => {
                let transaction = self.db.begin().await?;
                let admitted = transaction
                    .execute_unprepared("UPDATE wallet_snapshot_admission SET id=id WHERE id=1")
                    .await?;
                if admitted.rows_affected() != 1 {
                    return Err(RingRpcError::StateUnavailable);
                }
                transaction
            }
        };
        let page = reader.read(&transaction).await?;
        let through = snapshot_history_through(&transaction, query.ring).await?;
        let mut metadata = SnapshotMetadata::new(query, through)?;
        metadata.revision = Some(read_revision(&transaction, &query.ring).await?);
        let mut balances = Balances::default();
        if !page.more {
            for note in &page.notes {
                balances.add(note, through);
            }
            metadata.balances = balances.into_values();
            transaction.commit().await?;
            return Ok(SnapshotPage {
                page,
                metadata,
                id: None,
            });
        }
        let scope = self
            .seal
            .tags
            .snapshot_scope(&query.principal, &query.wallet)?;
        self.admit(
            &transaction,
            SnapshotAdmission {
                ring: query.ring,
                scope,
            },
        )
        .await?;
        let id: [u8; 32] = rand::random();
        transaction.execute(Statement::from_sql_and_values(
            transaction.get_database_backend(),
            "INSERT INTO wallet_snapshots(id,ring,scope_tag,expires_at,sealed) VALUES($1,$2,$3,$4,$5)",
            vec![id.to_vec().into(), query.ring.as_ref().to_vec().into(), scope.to_vec().into(), slot_value(metadata.expires_at)?, Vec::<u8>::new().into()],
        )).await?;
        let owner_tag = self.seal.tags.owner_tag(&range.member)?;
        let mut batch = OwnerNotesPage {
            range: OwnerRange {
                limit: OWNER_ROW_BATCH,
                ..range
            },
            ..reader
        };
        loop {
            let captured = batch.read(&transaction).await?;
            for note in &captured.notes {
                balances.add(note, through);
            }
            let Some(last) = captured.notes.last() else {
                break;
            };
            let mut values: Vec<Value> = vec![
                id.to_vec().into(),
                query.ring.as_ref().to_vec().into(),
                owner_tag.to_vec().into(),
                last.key.to_vec().into(),
            ];
            let after_clause = match batch.range.after {
                Some(after) => {
                    values.push(after.to_vec().into());
                    " AND note_tag>$5"
                }
                None => "",
            };
            transaction.execute(Statement::from_sql_and_values(
                transaction.get_database_backend(),
                format!("INSERT INTO wallet_snapshot_notes(snapshot_id,note_tag,sealed,spent_slot) SELECT $1,note_tag,sealed,spent_slot FROM owner_notes WHERE ring=$2 AND owner_tag=$3 AND note_tag<=$4{after_clause}"),
                values,
            )).await?;
            if !captured.more {
                break;
            }
            batch.range.after = Some(last.key);
        }
        metadata.balances = balances.into_values();
        let body = serde_json::to_vec(&metadata).map_err(|_| RingRpcError::StateUnavailable)?;
        let key = self.seal.tags.snapshot_metadata(&id)?;
        let sealed = self.seal.seal(&key, &body)?;
        transaction
            .execute(Statement::from_sql_and_values(
                transaction.get_database_backend(),
                "UPDATE wallet_snapshots SET sealed=$2 WHERE id=$1",
                vec![id.to_vec().into(), sealed.into()],
            ))
            .await?;
        transaction.commit().await?;
        Ok(SnapshotPage {
            page,
            metadata,
            id: Some(id),
        })
    }

    pub(crate) async fn release(&self, release: WalletSnapshotRelease) -> Result<(), RingRpcError> {
        release.validate()?;
        let transaction = self.db.begin().await?;
        let metadata = self
            .metadata(
                &transaction,
                SnapshotLookup {
                    id: release.cursor.snapshot,
                    ring: release.ring,
                },
            )
            .await?;
        if let Some(metadata) = metadata {
            metadata.authorize(&release.principal, &release.wallet)?;
            transaction
                .execute(Statement::from_sql_and_values(
                    transaction.get_database_backend(),
                    "UPDATE wallet_snapshots SET expires_at=0 WHERE id=$1 AND ring=$2",
                    vec![
                        release.cursor.snapshot.to_vec().into(),
                        release.ring.as_ref().to_vec().into(),
                    ],
                ))
                .await?;
        }
        transaction.commit().await?;
        WalletSnapshotCleanup {
            db: self.db,
            now: release.now,
        }
        .run()
        .await?;
        Ok(())
    }

    async fn metadata(
        &self,
        db: &impl ConnectionTrait,
        lookup: SnapshotLookup,
    ) -> Result<Option<SnapshotMetadata>, RingRpcError> {
        let row = db
            .query_one(Statement::from_sql_and_values(
                db.get_database_backend(),
                "SELECT expires_at,sealed FROM wallet_snapshots WHERE id=$1 AND ring=$2",
                vec![
                    lookup.id.to_vec().into(),
                    lookup.ring.as_ref().to_vec().into(),
                ],
            ))
            .await?;
        let Some(row) = row else { return Ok(None) };
        let stored_expiry = row.try_get::<i64>("", "expires_at")?;
        let key = self.seal.tags.snapshot_metadata(&lookup.id)?;
        let body = self
            .seal
            .open(&key, &row.try_get::<Vec<u8>>("", "sealed")?)?;
        let mut metadata: SnapshotMetadata =
            serde_json::from_slice(&body).map_err(|_| RingRpcError::StateUnavailable)?;
        if stored_expiry == 0 {
            metadata.expires_at = 0;
        } else if u64::try_from(stored_expiry).ok() != Some(metadata.expires_at) {
            return Err(RingRpcError::StateUnavailable);
        }
        Ok(Some(metadata))
    }

    async fn admit(
        &self,
        db: &DatabaseTransaction,
        admission: SnapshotAdmission,
    ) -> Result<(), RingRpcError> {
        let row = db.query_one(Statement::from_sql_and_values(
            db.get_database_backend(),
            "SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN ring=$1 AND scope_tag=$2 THEN 1 ELSE 0 END),0) AS scoped FROM wallet_snapshots",
            vec![admission.ring.as_ref().to_vec().into(), admission.scope.to_vec().into()],
        )).await?.ok_or(RingRpcError::StateUnavailable)?;
        let total = row.try_get::<i64>("", "total")?;
        let scoped = row.try_get::<i64>("", "scoped")?;
        if usize::try_from(total).map_err(|_| RingRpcError::StateUnavailable)?
            >= self.limits.store.get()
            || usize::try_from(scoped).map_err(|_| RingRpcError::StateUnavailable)?
                >= self.limits.principal_wallet.get()
        {
            return Err(RingRpcError::WalletSnapshotCapacity);
        }
        Ok(())
    }
}

struct SnapshotLookup {
    id: [u8; 32],
    ring: Address,
}

struct SnapshotAdmission {
    ring: Address,
    scope: [u8; 32],
}

impl WalletSnapshotCleanup<'_> {
    pub(crate) async fn run(self) -> Result<usize, RingRpcError> {
        let transaction = self.db.begin().await?;
        let row = transaction.query_one(Statement::from_sql_and_values(
            transaction.get_database_backend(),
            "SELECT id FROM wallet_snapshots WHERE expires_at<=$1 ORDER BY expires_at,id LIMIT 1",
            vec![slot_value(self.now)?],
        )).await?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(0);
        };
        let id = row.try_get::<Vec<u8>>("", "id")?;
        let deleted = transaction.execute(Statement::from_sql_and_values(
            transaction.get_database_backend(),
            "DELETE FROM wallet_snapshot_notes WHERE snapshot_id=$1 AND note_tag IN (SELECT note_tag FROM wallet_snapshot_notes WHERE snapshot_id=$1 ORDER BY note_tag LIMIT $2)",
            vec![id.clone().into(), i64::try_from(OWNER_ROW_BATCH).map_err(|_| RingRpcError::StateUnavailable)?.into()],
        )).await?.rows_affected();
        transaction.execute(Statement::from_sql_and_values(
            transaction.get_database_backend(),
            "DELETE FROM wallet_snapshots WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM wallet_snapshot_notes WHERE snapshot_id=$1)",
            vec![id.into()],
        )).await?;
        transaction.commit().await?;
        usize::try_from(deleted).map_err(|_| RingRpcError::StateUnavailable)
    }
}
