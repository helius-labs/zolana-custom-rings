use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use anyhow::{Context, Result};
use custom_ring_interface::storage::StorageRegistry;
use sea_orm::{
    AccessMode, ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction,
    IsolationLevel, QueryResult, Statement, TransactionTrait, Value,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use solana_address::Address;
use zolana_ring_indexer::{
    records::SealedKey,
    tree::{IndexedRecord, MemberRecord, NodePosition},
};

use crate::{block::BlockMetadata, indexer::Quarantine};

/// A read takes each row's newest version at or below `version`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TreeVersion {
    pub version: u64,
    pub next_index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredRecord {
    pub record: IndexedRecord,
    pub seal: Option<SealedKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RingCursor {
    pub start_slot: u64,
    pub scanned_slot: u64,
    pub tip: Option<BlockMetadata>,
    ready: bool,
}

impl RingCursor {
    pub fn new(start_slot: u64) -> Self {
        Self {
            start_slot,
            scanned_slot: start_slot,
            tip: None,
            ready: false,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn tip_slot(&self) -> u64 {
        self.tip.as_ref().map_or(self.start_slot, |tip| tip.slot)
    }

    pub async fn suspend<C: ConnectionTrait>(&mut self, conn: &C) -> Result<()> {
        self.ready = false;
        save_cursor(conn, self).await
    }

    pub async fn resume<C: ConnectionTrait>(&mut self, conn: &C) -> Result<()> {
        self.ready = true;
        save_cursor(conn, self).await
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct BlockUndo {
    #[serde(default)]
    pub storage: Vec<StorageUndo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct BlockJournal {
    pub metadata: BlockMetadata,
    pub previous_tip: Option<BlockMetadata>,
    pub undo: BlockUndo,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StorageState {
    pub registry: [u8; 32],
    #[serde(
        serialize_with = "account_image::serialize",
        deserialize_with = "account_image::storage"
    )]
    pub account: Box<StorageRegistry>,
    /// Cleared only by a rollback.
    pub fault: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StorageRoot {
    pub root: [u8; 32],
    pub revision: u64,
    pub next_index: u64,
}

impl StorageRoot {
    pub fn current(account: &StorageRegistry) -> Self {
        let current = account.roots[0];
        Self {
            root: current.hash,
            revision: current.revision.value(),
            next_index: account.next_index().into(),
        }
    }

    pub fn tree(&self) -> TreeVersion {
        TreeVersion {
            version: self.revision,
            next_index: self.next_index,
        }
    }
}

/// Rows of one storage registry newer than `before`, `None` for a registry the block created.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct StorageUndo {
    pub registry: [u8; 32],
    pub before: Option<StorageState>,
}

const RECORD_COLUMNS: &str =
    "leaf_index, member, next_member, lists, escrow_key, seal, mint_policy";

/// Lookups read every table from one Postgres snapshot.
pub(crate) async fn begin_read(
    db: &DatabaseConnection,
) -> Result<DatabaseTransaction, sea_orm::DbErr> {
    match db.get_database_backend() {
        DatabaseBackend::Postgres => {
            db.begin_with_config(
                Some(IsolationLevel::RepeatableRead),
                Some(AccessMode::ReadOnly),
            )
            .await
        }
        _ => db.begin().await,
    }
}

pub(crate) async fn cursor<C: ConnectionTrait>(conn: &C) -> Result<Option<RingCursor>> {
    let sql = "SELECT state FROM ring_cursor WHERE id=1";
    read_json(conn, sql, vec![]).await
}

pub(crate) async fn save_cursor<C: ConnectionTrait>(conn: &C, value: &RingCursor) -> Result<()> {
    let sql = "INSERT INTO ring_cursor(id,state) VALUES(1,$1) \
               ON CONFLICT(id) DO UPDATE SET state=excluded.state";
    exec(conn, sql, vec![json(value)?]).await
}

pub(crate) async fn journal<C: ConnectionTrait>(
    conn: &C,
    slot: u64,
) -> Result<Option<BlockJournal>> {
    let sql = "SELECT state FROM ring_blocks WHERE slot=$1";
    read_json(conn, sql, vec![int(slot)?]).await
}

pub(crate) async fn save_journal<C: ConnectionTrait>(
    conn: &C,
    journal: &BlockJournal,
) -> Result<()> {
    let sql = "INSERT INTO ring_blocks(slot,state) VALUES($1,$2) \
               ON CONFLICT(slot) DO UPDATE SET state=excluded.state";
    exec(conn, sql, vec![int(journal.metadata.slot)?, json(journal)?]).await
}

/// Blocks below `below` never roll back.
pub(crate) async fn prune<C: ConnectionTrait>(conn: &C, below: u64) -> Result<()> {
    exec(
        conn,
        "DELETE FROM ring_blocks WHERE slot<$1",
        vec![int(below)?],
    )
    .await
}

pub(crate) async fn rollback(tx: &DatabaseTransaction, cursor: &mut RingCursor) -> Result<()> {
    let tip = cursor
        .tip
        .as_ref()
        .context("cannot rewind before the ring index start")?;
    let journal = journal(tx, tip.slot).await?.context("ring journal gap")?;
    for undo in journal.undo.storage.iter().rev() {
        StorageStore::new(tx, undo.registry).restore(undo).await?;
    }
    let slot = vec![int(journal.metadata.slot)?];
    exec(tx, "DELETE FROM ring_blocks WHERE slot=$1", slot).await?;
    cursor.tip = journal.previous_tip;
    cursor.scanned_slot = cursor.tip_slot();
    cursor.suspend(tx).await
}

/// One registry's record tree, every statement binds the registry as `$1`.
pub(crate) struct RegistryStore<'c, C> {
    conn: &'c C,
    pub(crate) program: [u8; 32],
}

impl<'c, C: ConnectionTrait> RegistryStore<'c, C> {
    pub fn new(conn: &'c C, program: [u8; 32]) -> Self {
        Self { conn, program }
    }

    pub async fn record(&self, member: &[u8; 32], applied: u64) -> Result<Option<StoredRecord>> {
        let sql = format!(
            "SELECT {RECORD_COLUMNS} FROM ring_records WHERE program=$1 AND member=$2 \
             AND applied<=$3 ORDER BY applied DESC LIMIT 1"
        );
        let values = vec![bytes(member), int(applied)?];
        let row = self.query_one(&sql, values).await?;
        row.as_ref().map(stored_record).transpose()
    }

    pub async fn low_record(&self, member: &[u8; 32], applied: u64) -> Result<StoredRecord> {
        let sql = format!(
            "SELECT {RECORD_COLUMNS} FROM ring_records WHERE program=$1 AND member<$2 \
             AND applied<=$3 ORDER BY member DESC, applied DESC LIMIT 1"
        );
        let values = vec![bytes(member), int(applied)?];
        let row = self.query_one(&sql, values).await?;
        stored_record(&row.context("member registry has no sentinel")?)
    }

    /// A gap shortens the result.
    pub async fn records_by_index(
        &self,
        leaves: Range<u64>,
        applied: u64,
    ) -> Result<Vec<StoredRecord>> {
        let sql = format!(
            "SELECT {RECORD_COLUMNS} FROM ring_records AS r WHERE program=$1 \
             AND leaf_index>=$2 AND leaf_index<$3 AND applied=(SELECT MAX(applied) \
             FROM ring_records AS m WHERE m.program=r.program AND m.leaf_index=r.leaf_index \
             AND m.applied<=$4) ORDER BY leaf_index"
        );
        let values = vec![int(leaves.start)?, int(leaves.end)?, int(applied)?];
        let rows = self.query_all(&sql, values).await?;
        rows.iter().map(stored_record).collect()
    }

    pub async fn save_records(&self, records: &[StoredRecord], applied: u64) -> Result<()> {
        for stored in records {
            let record = &stored.record.record;
            let sql = "INSERT INTO ring_records(program,leaf_index,applied,member,next_member,\
                       lists,escrow_key,seal,mint_policy) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)";
            let values = vec![
                int(stored.record.index)?,
                int(applied)?,
                bytes(&record.member),
                bytes(&record.next),
                int(record.lists)?,
                bytes(&record.escrow_key),
                seal_value(stored.seal.as_ref())?,
                serde_json::to_string(&record.mint_policy)?.into(),
            ];
            self.exec(sql, values).await?;
        }
        Ok(())
    }

    pub async fn nodes(
        &self,
        keys: &BTreeSet<NodePosition>,
        applied: u64,
    ) -> Result<BTreeMap<NodePosition, [u8; 32]>> {
        let mut by_level = BTreeMap::<usize, Vec<u64>>::new();
        for key in keys {
            by_level.entry(key.level).or_default().push(key.position);
        }
        let mut values = vec![int(applied)?];
        let mut levels = Vec::new();
        for (level, positions) in by_level {
            values.push(int(u64::try_from(level)?)?);
            let level_param = values.len() + 1;
            let mut params = Vec::with_capacity(positions.len());
            for position in positions {
                values.push(int(position)?);
                params.push(format!("${}", values.len() + 1));
            }
            levels.push(format!(
                "(level=${level_param} AND position IN ({}))",
                params.join(",")
            ));
        }
        if levels.is_empty() {
            return Ok(BTreeMap::new());
        }
        let sql = format!(
            "SELECT level, position, hash FROM ring_record_nodes AS n WHERE program=$1 \
             AND applied=(SELECT MAX(applied) FROM ring_record_nodes AS m \
             WHERE m.program=n.program AND m.level=n.level AND m.position=n.position \
             AND m.applied<=$2) AND ({})",
            levels.join(" OR ")
        );
        let rows = self.query_all(&sql, values).await?;
        rows.iter()
            .map(|row| {
                let at = NodePosition {
                    level: usize::try_from(uint(row, "level")?)?,
                    position: uint(row, "position")?,
                };
                Ok((at, field(row, "hash")?))
            })
            .collect()
    }

    pub async fn save_nodes(
        &self,
        nodes: &BTreeMap<NodePosition, [u8; 32]>,
        applied: u64,
    ) -> Result<()> {
        for (at, hash) in nodes {
            let sql = "INSERT INTO ring_record_nodes(program,level,position,applied,hash) \
                       VALUES($1,$2,$3,$4,$5)";
            let values = vec![
                int(u64::try_from(at.level)?)?,
                int(at.position)?,
                int(applied)?,
                bytes(hash),
            ];
            self.exec(sql, values).await?;
        }
        Ok(())
    }

    fn statement(&self, sql: &str, values: Vec<Value>) -> Statement {
        let program = std::iter::once(bytes(&self.program));
        statement(self.conn, sql, program.chain(values).collect())
    }

    async fn exec(&self, sql: &str, values: Vec<Value>) -> Result<()> {
        self.conn.execute(self.statement(sql, values)).await?;
        Ok(())
    }

    async fn query_one(&self, sql: &str, values: Vec<Value>) -> Result<Option<QueryResult>> {
        Ok(self.conn.query_one(self.statement(sql, values)).await?)
    }

    async fn query_all(&self, sql: &str, values: Vec<Value>) -> Result<Vec<QueryResult>> {
        Ok(self.conn.query_all(self.statement(sql, values)).await?)
    }
}

/// Tree rows share the ring record tables under the registry address, versioned by revision.
pub(crate) struct StorageStore<'c, C> {
    tree: RegistryStore<'c, C>,
}

impl<'c, C: ConnectionTrait> StorageStore<'c, C> {
    pub fn new(conn: &'c C, registry: [u8; 32]) -> Self {
        Self {
            tree: RegistryStore::new(conn, registry),
        }
    }

    pub fn tree(&self) -> &RegistryStore<'c, C> {
        &self.tree
    }

    pub async fn state(&self) -> Result<Option<StorageState>> {
        let sql = "SELECT state FROM storage_registries WHERE registry=$1";
        let row = self.tree.query_one(sql, vec![]).await?;
        row.as_ref().map(stored_state).transpose()
    }

    pub async fn save_state(&self, value: &StorageState) -> Result<()> {
        let sql = "INSERT INTO storage_registries(registry,state) VALUES($1,$2) \
                   ON CONFLICT(registry) DO UPDATE SET state=excluded.state";
        self.tree.exec(sql, vec![json(value)?]).await
    }

    pub async fn root(&self, revision: u64) -> Result<Option<StorageRoot>> {
        let sql = "SELECT root, revision, next_index FROM storage_roots \
                   WHERE registry=$1 AND revision=$2";
        let row = self.tree.query_one(sql, vec![int(revision)?]).await?;
        row.as_ref()
            .map(|row| {
                Ok(StorageRoot {
                    root: field(row, "root")?,
                    revision: uint(row, "revision")?,
                    next_index: uint(row, "next_index")?,
                })
            })
            .transpose()
    }

    pub async fn save_root(&self, root: &StorageRoot) -> Result<()> {
        let sql = "INSERT INTO storage_roots(registry,revision,root,next_index) \
                   VALUES($1,$2,$3,$4)";
        let values = vec![
            int(root.revision)?,
            bytes(&root.root),
            int(root.next_index)?,
        ];
        self.tree.exec(sql, values).await
    }

    async fn restore(&self, undo: &StorageUndo) -> Result<()> {
        let Some(before) = &undo.before else {
            for sql in [
                "DELETE FROM ring_records WHERE program=$1",
                "DELETE FROM ring_record_nodes WHERE program=$1",
                "DELETE FROM storage_roots WHERE registry=$1",
                "DELETE FROM storage_registries WHERE registry=$1",
            ] {
                self.tree.exec(sql, vec![]).await?;
            }
            return Ok(());
        };
        let revision = vec![int(StorageRoot::current(&before.account).revision)?];
        for sql in [
            "DELETE FROM ring_records WHERE program=$1 AND applied>$2",
            "DELETE FROM ring_record_nodes WHERE program=$1 AND applied>$2",
            "DELETE FROM storage_roots WHERE registry=$1 AND revision>$2",
        ] {
            self.tree.exec(sql, revision.clone()).await?;
        }
        self.save_state(before).await
    }
}

impl<C: ConnectionTrait> Quarantine for StorageStore<'_, C> {
    type State = StorageState;
    type Undo = StorageUndo;

    fn undo(&self, before: Option<StorageState>) -> StorageUndo {
        StorageUndo {
            registry: self.tree.program,
            before,
        }
    }

    /// Stops the registry's projection, a rollback of the block resumes it.
    async fn quarantine(&self, before: StorageState, reason: String) -> Result<StorageUndo> {
        log::error!(
            "storage registry {} stopped projecting ({reason})",
            Address::new_from_array(self.tree.program)
        );
        self.save_state(&StorageState {
            fault: Some(reason),
            ..before.clone()
        })
        .await?;
        Ok(self.undo(Some(before)))
    }
}

fn stored_record(row: &QueryResult) -> Result<StoredRecord> {
    Ok(StoredRecord {
        record: IndexedRecord {
            index: uint(row, "leaf_index")?,
            record: MemberRecord {
                member: field(row, "member")?,
                next: field(row, "next_member")?,
                lists: uint(row, "lists")?,
                escrow_key: field(row, "escrow_key")?,
                mint_policy: read_mint_policy(row)?.unwrap_or_default(),
            },
        },
        seal: seal(row)?,
    })
}

fn seal(row: &QueryResult) -> Result<Option<SealedKey>> {
    let text = row.try_get::<Option<String>>("", "seal")?;
    Ok(text.as_deref().map(serde_json::from_str).transpose()?)
}

fn field(row: &QueryResult, column: &str) -> Result<[u8; 32]> {
    row.try_get::<Vec<u8>>("", column)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{column} is not 32 bytes"))
}

fn uint(row: &QueryResult, column: &str) -> Result<u64> {
    Ok(u64::try_from(row.try_get::<i64>("", column)?)?)
}

fn statement<C: ConnectionTrait>(conn: &C, sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(conn.get_database_backend(), sql, values)
}

async fn exec<C: ConnectionTrait>(conn: &C, sql: &str, values: Vec<Value>) -> Result<()> {
    conn.execute(statement(conn, sql, values)).await?;
    Ok(())
}

fn bytes(value: &[u8; 32]) -> Value {
    value.to_vec().into()
}

fn json<T: Serialize>(value: &T) -> Result<Value> {
    Ok(serde_json::to_string(value)?.into())
}

fn int(value: u64) -> Result<Value> {
    Ok(i64::try_from(value)?.into())
}

fn seal_value(seal: Option<&SealedKey>) -> Result<Value> {
    Ok(seal.map(json).transpose()?.unwrap_or(Value::String(None)))
}

async fn read_json<T: DeserializeOwned, C: ConnectionTrait>(
    conn: &C,
    sql: &str,
    values: Vec<Value>,
) -> Result<Option<T>> {
    let row = conn.query_one(statement(conn, sql, values)).await?;
    row.as_ref().map(stored_state).transpose()
}

fn stored_state<T: DeserializeOwned>(row: &QueryResult) -> Result<T> {
    Ok(serde_json::from_str(&row.try_get::<String>("", "state")?)?)
}

/// An account image as base64 of its bytes, decoded through the account's own checks.
mod account_image {
    use std::ops::Deref;

    use bytemuck::Pod;
    use custom_ring_interface::storage::StorageRegistry;
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
    use spr_indexer_api::Base64String;

    pub fn serialize<S: Serializer, A: Deref<Target = T>, T: Pod>(
        value: &A,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Base64String(bytemuck::bytes_of(&**value).to_vec()).serialize(serializer)
    }

    pub fn storage<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Box<StorageRegistry>, D::Error> {
        decode(deserializer, StorageRegistry::from_data)
    }

    fn decode<'de, D: Deserializer<'de>, T: Pod>(
        deserializer: D,
        checked: fn(&[u8]) -> Option<&T>,
    ) -> Result<Box<T>, D::Error> {
        let Base64String(bytes) = Base64String::deserialize(deserializer)?;
        checked(&bytes)
            .map(|account| Box::new(*account))
            .ok_or_else(|| D::Error::custom("invalid account image"))
    }
}

fn read_mint_policy(row: &QueryResult) -> Result<Option<zolana_ring_policy::MintPolicy>> {
    let value = row.try_get::<Option<String>>("", "mint_policy")?;
    Ok(value.as_deref().map(serde_json::from_str).transpose()?)
}
