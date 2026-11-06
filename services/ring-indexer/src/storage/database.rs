use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    ops::Range,
};

use anyhow::{Context, Result};
use bytemuck::Pod;
use custom_ring_interface::{
    state::ROOT_HISTORY,
    storage::{Revision, Root, StorageError, StorageRegistry},
    tracking::TrackingRegistry,
};
use sea_orm::{
    AccessMode, ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction,
    IsolationLevel, QueryResult, Statement, TransactionTrait, Value,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use solana_address::Address;
use zolana_ring_indexer::tree::{
    IndexedLeaf, IndexedRecord, MemberRecord, NodePosition, TrackingRecord,
};

use crate::{block::BlockMetadata, indexer::Quarantine};

mod tracking;

pub(crate) use tracking::Enrollment;

/// A read takes each row's newest version at or below `version`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TreeVersion {
    pub version: u64,
    pub next_index: u64,
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
    #[serde(default)]
    pub tracking: Vec<TrackingUndo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct BlockJournal {
    pub metadata: BlockMetadata,
    pub previous_tip: Option<BlockMetadata>,
    pub undo: BlockUndo,
}

/// A leaf a registry's table stores, versioned by the revision that wrote it.
pub(crate) trait StoredLeaf: IndexedLeaf + Default + Send + Sync {
    const TABLE: &'static str;
    const COLUMNS: &'static str;

    fn from_row(row: &QueryResult) -> Result<Self>;
    /// In the order of `COLUMNS`.
    fn values(&self) -> Result<Vec<Value>>;
}

impl StoredLeaf for MemberRecord {
    const TABLE: &'static str = "ring_records";
    const COLUMNS: &'static str = "member, next_member, lists, mint_policy";

    fn from_row(row: &QueryResult) -> Result<Self> {
        Ok(Self {
            member: field(row, "member")?,
            next: field(row, "next_member")?,
            lists: uint(row, "lists")?,
            mint_policy: read_mint_policy(row)?.unwrap_or_default(),
        })
    }

    fn values(&self) -> Result<Vec<Value>> {
        Ok(vec![
            bytes(&self.member),
            bytes(&self.next),
            int(self.lists)?,
            serde_json::to_string(&self.mint_policy)?.into(),
        ])
    }
}

impl StoredLeaf for TrackingRecord {
    const TABLE: &'static str = "tracking_records";
    const COLUMNS: &'static str = "member, next_member, nullifier_pk, ct_hash, list_tag";

    fn from_row(row: &QueryResult) -> Result<Self> {
        Ok(Self {
            member: field(row, "member")?,
            next: field(row, "next_member")?,
            nullifier_pk: field(row, "nullifier_pk")?,
            ct_hash: field(row, "ct_hash")?,
            list_tag: field(row, "list_tag")?,
        })
    }

    fn values(&self) -> Result<Vec<Value>> {
        Ok(vec![
            bytes(&self.member),
            bytes(&self.next),
            bytes(&self.nullifier_pk),
            bytes(&self.ct_hash),
            bytes(&self.list_tag),
        ])
    }
}

/// A registry account the projection mirrors, one state table and one leaf table per kind.
pub(crate) trait ProjectedAccount: Pod + Eq + Send + Sync {
    type Leaf: StoredLeaf;
    const STATES: &'static str;

    fn from_image(data: &[u8]) -> Option<&Self>;
    fn roots(&self) -> &[Root; ROOT_HISTORY];
    fn root_at(&self, revision: Revision, slot: u64) -> Result<[u8; 32], StorageError>;
    fn leaves(&self) -> u64;
}

impl ProjectedAccount for StorageRegistry {
    type Leaf = MemberRecord;
    const STATES: &'static str = "storage_registries";

    fn from_image(data: &[u8]) -> Option<&Self> {
        Self::from_data(data)
    }

    fn roots(&self) -> &[Root; ROOT_HISTORY] {
        &self.roots
    }

    fn root_at(&self, revision: Revision, slot: u64) -> Result<[u8; 32], StorageError> {
        self.root(revision, slot)
    }

    fn leaves(&self) -> u64 {
        u64::from(self.next_index())
    }
}

impl ProjectedAccount for TrackingRegistry {
    type Leaf = TrackingRecord;
    const STATES: &'static str = "tracking_registries";

    fn from_image(data: &[u8]) -> Option<&Self> {
        Self::from_data(data)
    }

    fn roots(&self) -> &[Root; ROOT_HISTORY] {
        &self.roots
    }

    fn root_at(&self, revision: Revision, slot: u64) -> Result<[u8; 32], StorageError> {
        self.root(revision, slot)
    }

    fn leaves(&self) -> u64 {
        self.next_index()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "A: ProjectedAccount", deserialize = "A: ProjectedAccount"))]
pub(crate) struct RegistryState<A> {
    pub registry: [u8; 32],
    #[serde(
        serialize_with = "account_image::serialize",
        deserialize_with = "account_image::deserialize"
    )]
    pub account: Box<A>,
    /// Cleared only by a rollback.
    pub fault: Option<String>,
}

pub(crate) type StorageState = RegistryState<StorageRegistry>;
pub(crate) type TrackingState = RegistryState<TrackingRegistry>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StorageRoot {
    pub root: [u8; 32],
    pub revision: u64,
    pub next_index: u64,
}

impl StorageRoot {
    pub fn current<A: ProjectedAccount>(account: &A) -> Self {
        let current = account.roots()[0];
        Self {
            root: current.hash,
            revision: current.revision.value(),
            next_index: account.leaves(),
        }
    }

    pub fn tree(&self) -> TreeVersion {
        TreeVersion {
            version: self.revision,
            next_index: self.next_index,
        }
    }
}

/// Rows of one registry newer than `before`, `None` for a registry the block created.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "A: ProjectedAccount", deserialize = "A: ProjectedAccount"))]
pub(crate) struct RegistryUndo<A> {
    pub registry: [u8; 32],
    pub before: Option<RegistryState<A>>,
}

pub(crate) type StorageUndo = RegistryUndo<StorageRegistry>;
pub(crate) type TrackingUndo = RegistryUndo<TrackingRegistry>;

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
    for undo in journal.undo.tracking.iter().rev() {
        TrackingStore::new(tx, undo.registry).restore(undo).await?;
    }
    let slot = vec![int(journal.metadata.slot)?];
    tracking::rollback_slot(tx, journal.metadata.slot).await?;
    exec(tx, "DELETE FROM ring_blocks WHERE slot=$1", slot).await?;
    cursor.tip = journal.previous_tip;
    cursor.scanned_slot = cursor.tip_slot();
    cursor.suspend(tx).await
}

/// One registry's record tree, every statement binds the registry as `$1`.
pub(crate) struct RegistryStore<'c, C, L = MemberRecord> {
    conn: &'c C,
    pub(crate) program: [u8; 32],
    leaf: PhantomData<L>,
}

impl<'c, C: ConnectionTrait, L: StoredLeaf> RegistryStore<'c, C, L> {
    pub fn new(conn: &'c C, program: [u8; 32]) -> Self {
        Self {
            conn,
            program,
            leaf: PhantomData,
        }
    }

    pub async fn record(
        &self,
        member: &[u8; 32],
        applied: u64,
    ) -> Result<Option<IndexedRecord<L>>> {
        let sql = format!(
            "SELECT leaf_index, {} FROM {} WHERE program=$1 AND member=$2 \
             AND applied<=$3 ORDER BY applied DESC LIMIT 1",
            L::COLUMNS,
            L::TABLE
        );
        let values = vec![bytes(member), int(applied)?];
        let row = self.query_one(&sql, values).await?;
        row.as_ref().map(stored_record).transpose()
    }

    pub async fn low_record(&self, member: &[u8; 32], applied: u64) -> Result<IndexedRecord<L>> {
        let sql = format!(
            "SELECT leaf_index, {} FROM {} WHERE program=$1 AND member<$2 \
             AND applied<=$3 ORDER BY member DESC, applied DESC LIMIT 1",
            L::COLUMNS,
            L::TABLE
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
    ) -> Result<Vec<IndexedRecord<L>>> {
        let (columns, table) = (L::COLUMNS, L::TABLE);
        let sql = format!(
            "SELECT leaf_index, {columns} FROM {table} AS r WHERE program=$1 \
             AND leaf_index>=$2 AND leaf_index<$3 AND applied=(SELECT MAX(applied) \
             FROM {table} AS m WHERE m.program=r.program AND m.leaf_index=r.leaf_index \
             AND m.applied<=$4) ORDER BY leaf_index"
        );
        let values = vec![int(leaves.start)?, int(leaves.end)?, int(applied)?];
        let rows = self.query_all(&sql, values).await?;
        rows.iter().map(stored_record).collect()
    }

    pub async fn save_records(&self, records: &[IndexedRecord<L>], applied: u64) -> Result<()> {
        for indexed in records {
            let mut values = vec![int(indexed.index)?, int(applied)?];
            values.extend(indexed.record.values()?);
            let params = (1..=values.len() + 1)
                .map(|param| format!("${param}"))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "INSERT INTO {}(program,leaf_index,applied,{}) VALUES({params})",
                L::TABLE,
                L::COLUMNS
            );
            self.exec(&sql, values).await?;
        }
        Ok(())
    }

    pub async fn nodes(
        &self,
        keys: &BTreeSet<NodePosition>,
        applied: u64,
    ) -> Result<BTreeMap<NodePosition, [u8; 32]>> {
        const BATCH_LIMIT: usize = 256;

        let applied = int(applied)?;
        let mut keys = keys.iter();
        let mut nodes = BTreeMap::new();
        loop {
            let batch: Vec<_> = keys.by_ref().take(BATCH_LIMIT).collect();
            if batch.is_empty() {
                return Ok(nodes);
            }
            let statement = self.node_statement(&batch, applied.clone())?;
            for row in self.conn.query_all(statement).await? {
                let Some(hash) = row.try_get::<Option<Vec<u8>>>("", "hash")? else {
                    continue;
                };
                let at = NodePosition {
                    level: usize::try_from(uint(&row, "level")?)?,
                    position: uint(&row, "position")?,
                };
                nodes.insert(
                    at,
                    hash.try_into()
                        .map_err(|_| anyhow::anyhow!("invalid node hash length"))?,
                );
            }
        }
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

    fn node_statement(&self, keys: &[&NodePosition], applied: Value) -> Result<Statement> {
        let mut values = vec![applied];
        let mut requested = Vec::with_capacity(keys.len());
        for (index, at) in keys.iter().enumerate() {
            values.push(int(u64::try_from(at.level)?)?);
            values.push(int(at.position)?);
            let level_param = index * 2 + 3;
            let position_param = level_param + 1;
            requested.push(format!(
                "(CAST(${level_param} AS BIGINT),CAST(${position_param} AS BIGINT))"
            ));
        }
        let sql = format!(
            "WITH requested(level,position) AS (VALUES {}) \
             SELECT level, position, \
             (SELECT hash FROM ring_record_nodes AS n WHERE n.program=$1 \
             AND n.level=requested.level AND n.position=requested.position \
             AND n.applied<=$2 ORDER BY n.applied DESC LIMIT 1) AS hash \
             FROM requested",
            requested.join(",")
        );
        Ok(self.statement(&sql, values))
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

/// Tree rows share the node and root tables under the registry address, versioned by revision.
pub(crate) struct ProjectedStore<'c, C, A: ProjectedAccount> {
    tree: RegistryStore<'c, C, A::Leaf>,
}

pub(crate) type StorageStore<'c, C> = ProjectedStore<'c, C, StorageRegistry>;
pub(crate) type TrackingStore<'c, C> = ProjectedStore<'c, C, TrackingRegistry>;

impl<'c, C: ConnectionTrait, A: ProjectedAccount> ProjectedStore<'c, C, A> {
    pub fn new(conn: &'c C, registry: [u8; 32]) -> Self {
        Self {
            tree: RegistryStore::new(conn, registry),
        }
    }

    pub fn tree(&self) -> &RegistryStore<'c, C, A::Leaf> {
        &self.tree
    }

    pub async fn state(&self) -> Result<Option<RegistryState<A>>> {
        let sql = format!("SELECT state FROM {} WHERE registry=$1", A::STATES);
        let row = self.tree.query_one(&sql, vec![]).await?;
        row.as_ref().map(stored_state).transpose()
    }

    pub async fn save_state(&self, value: &RegistryState<A>) -> Result<()> {
        let sql = format!(
            "INSERT INTO {}(registry,state) VALUES($1,$2) \
             ON CONFLICT(registry) DO UPDATE SET state=excluded.state",
            A::STATES
        );
        self.tree.exec(&sql, vec![json(value)?]).await
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

    async fn restore(&self, undo: &RegistryUndo<A>) -> Result<()> {
        let leaves = format!("{} WHERE program=$1", <A::Leaf as StoredLeaf>::TABLE);
        let Some(before) = &undo.before else {
            for sql in [
                format!("DELETE FROM {leaves}"),
                "DELETE FROM ring_record_nodes WHERE program=$1".into(),
                "DELETE FROM storage_roots WHERE registry=$1".into(),
                format!("DELETE FROM {} WHERE registry=$1", A::STATES),
            ] {
                self.tree.exec(&sql, vec![]).await?;
            }
            return Ok(());
        };
        let revision = vec![int(StorageRoot::current(&*before.account).revision)?];
        for sql in [
            format!("DELETE FROM {leaves} AND applied>$2"),
            "DELETE FROM ring_record_nodes WHERE program=$1 AND applied>$2".into(),
            "DELETE FROM storage_roots WHERE registry=$1 AND revision>$2".into(),
        ] {
            self.tree.exec(&sql, revision.clone()).await?;
        }
        self.save_state(before).await
    }
}

impl<C: ConnectionTrait, A: ProjectedAccount> Quarantine for ProjectedStore<'_, C, A> {
    type State = RegistryState<A>;
    type Undo = RegistryUndo<A>;

    fn undo(&self, before: Option<RegistryState<A>>) -> RegistryUndo<A> {
        RegistryUndo {
            registry: self.tree.program,
            before,
        }
    }

    /// Stops the registry's projection, a rollback of the block resumes it.
    async fn quarantine(
        &self,
        before: RegistryState<A>,
        reason: String,
    ) -> Result<RegistryUndo<A>> {
        log::error!(
            "registry {} stopped projecting ({reason})",
            Address::new_from_array(self.tree.program)
        );
        self.save_state(&RegistryState {
            fault: Some(reason),
            ..before.clone()
        })
        .await?;
        Ok(self.undo(Some(before)))
    }
}

fn stored_record<L: StoredLeaf>(row: &QueryResult) -> Result<IndexedRecord<L>> {
    Ok(IndexedRecord {
        index: uint(row, "leaf_index")?,
        record: L::from_row(row)?,
    })
}

fn field<const N: usize>(row: &QueryResult, column: &str) -> Result<[u8; N]> {
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

fn bytes<const N: usize>(value: &[u8; N]) -> Value {
    value.to_vec().into()
}

fn json<T: Serialize>(value: &T) -> Result<Value> {
    Ok(serde_json::to_string(value)?.into())
}

fn int(value: u64) -> Result<Value> {
    Ok(i64::try_from(value)?.into())
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
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
    use spr_indexer_api::Base64String;

    pub fn serialize<S: Serializer, A: Deref<Target = T>, T: Pod>(
        value: &A,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Base64String(bytemuck::bytes_of(&**value).to_vec()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, A: super::ProjectedAccount>(
        deserializer: D,
    ) -> Result<Box<A>, D::Error> {
        let Base64String(bytes) = Base64String::deserialize(deserializer)?;
        A::from_image(&bytes)
            .map(|account| Box::new(*account))
            .ok_or_else(|| D::Error::custom("invalid account image"))
    }
}

fn read_mint_policy(row: &QueryResult) -> Result<Option<zolana_ring_policy::MintPolicy>> {
    let value = row.try_get::<Option<String>>("", "mint_policy")?;
    Ok(value.as_deref().map(serde_json::from_str).transpose()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::database;

    #[tokio::test]
    async fn historical_nodes_span_batches_without_crossing_registry_or_revision() {
        let db = database().await;
        let initial: BTreeMap<_, _> = (0..513u64)
            .map(|position| {
                let mut hash = [0; 32];
                hash[..8].copy_from_slice(&position.to_be_bytes());
                (
                    NodePosition {
                        level: usize::try_from(position % 3).unwrap(),
                        position,
                    },
                    hash,
                )
            })
            .collect();
        let changed: BTreeMap<_, _> = initial
            .keys()
            .filter(|at| at.position % 2 == 0)
            .map(|at| (*at, [7; 32]))
            .collect();
        let future = NodePosition {
            level: 4,
            position: 900,
        };
        let missing = NodePosition {
            level: 5,
            position: 901,
        };
        let keys = initial.keys().copied().chain([future, missing]).collect();
        let store = RegistryStore::<_, MemberRecord>::new(&db, [1; 32]);
        store.save_nodes(&initial, 3).await.unwrap();
        store.save_nodes(&changed, 7).await.unwrap();
        store
            .save_nodes(&BTreeMap::from([(future, [8; 32])]), 8)
            .await
            .unwrap();
        RegistryStore::<_, MemberRecord>::new(&db, [2; 32])
            .save_nodes(&BTreeMap::from([(missing, [9; 32])]), 1)
            .await
            .unwrap();

        let tx = begin_read(&db).await.unwrap();
        let snapshot = RegistryStore::<_, MemberRecord>::new(&tx, [1; 32]);
        assert!(snapshot.nodes(&keys, 2).await.unwrap().is_empty());
        assert_eq!(snapshot.nodes(&keys, 3).await.unwrap(), initial);
        assert_eq!(snapshot.nodes(&keys, 6).await.unwrap(), initial);
        let mut expected = initial;
        expected.extend(changed);
        assert_eq!(snapshot.nodes(&keys, 7).await.unwrap(), expected);
        expected.insert(future, [8; 32]);
        assert_eq!(snapshot.nodes(&keys, 8).await.unwrap(), expected);
        assert!(snapshot
            .nodes(&BTreeSet::new(), 8)
            .await
            .unwrap()
            .is_empty());
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn historical_node_plan_seeks_the_sqlite_primary_key() {
        let db = database().await;
        let store = RegistryStore::<_, MemberRecord>::new(&db, [1; 32]);
        let keys = [
            NodePosition::root(0),
            NodePosition {
                level: 0,
                position: 1,
            },
        ];
        store
            .save_nodes(&BTreeMap::from([(keys[0], [3; 32])]), 3)
            .await
            .unwrap();
        let mut query = store
            .node_statement(&keys.iter().collect::<Vec<_>>(), int(7).unwrap())
            .unwrap();
        query.sql.insert_str(0, "EXPLAIN QUERY PLAN ");
        let plan: Vec<String> = db
            .query_all(query)
            .await
            .unwrap()
            .iter()
            .map(|row| row.try_get("", "detail").unwrap())
            .collect();
        let seeks: Vec<_> = plan
            .iter()
            .filter(|line| line.contains("SEARCH n USING INDEX"))
            .collect();
        assert_eq!(seeks.len(), 1, "{plan:?}");
        for term in [
            "sqlite_autoindex_ring_record_nodes_1",
            "program",
            "level",
            "position",
            "applied",
        ] {
            assert!(seeks[0].contains(term), "{plan:?}");
        }
        assert_eq!(
            plan.iter()
                .filter(|line| line.contains("ring_record_nodes"))
                .count(),
            1,
            "{plan:?}"
        );
        assert!(!plan.iter().any(|line| line.contains("SCAN n")), "{plan:?}");
        assert!(
            !plan.iter().any(|line| line.contains("USE TEMP B-TREE")),
            "{plan:?}"
        );
    }

    #[tokio::test]
    #[ignore = "needs RING_INDEXER_TEST_POSTGRES_URL"]
    async fn postgres_historical_node_seeks_keep_the_caller_snapshot() {
        let db = crate::savepoint_tests::postgres("historical_node_seeks").await;
        let store = RegistryStore::<_, MemberRecord>::new(&db, [1; 32]);
        store
            .exec(
                "INSERT INTO ring_record_nodes(program,level,position,applied,hash) \
                 SELECT $1,0,positions.position,revisions.applied,$2 \
                 FROM generate_series(0,512) AS positions(position) \
                 CROSS JOIN generate_series(0,31) AS revisions(applied)",
                vec![bytes(&[3; 32])],
            )
            .await
            .unwrap();
        db.execute_unprepared("ANALYZE ring_record_nodes")
            .await
            .unwrap();
        let keys: BTreeSet<_> = (0..513)
            .map(|position| NodePosition { level: 0, position })
            .collect();
        let plan_keys: Vec<_> = keys.iter().take(2).collect();
        let mut query = store.node_statement(&plan_keys, int(31).unwrap()).unwrap();
        query.sql.insert_str(0, "EXPLAIN (COSTS OFF) ");
        let plan: Vec<String> = db
            .query_all(query)
            .await
            .unwrap()
            .iter()
            .map(|row| row.try_get("", "QUERY PLAN").unwrap())
            .collect();
        assert!(
            plan.iter()
                .any(|line| line.contains("Index Scan Backward using ring_record_nodes_pkey")),
            "{plan:?}"
        );
        let conditions: Vec<_> = plan
            .iter()
            .filter(|line| line.contains("Index Cond:"))
            .collect();
        assert_eq!(conditions.len(), 1, "{plan:?}");
        for term in ["program", "level", "position", "applied"] {
            assert!(conditions[0].contains(term), "{plan:?}");
        }
        assert!(
            !plan
                .iter()
                .any(|line| line.contains("Seq Scan") || line.contains("Sort")),
            "{plan:?}"
        );

        let tx = begin_read(&db).await.unwrap();
        let snapshot = RegistryStore::<_, MemberRecord>::new(&tx, [1; 32]);
        let expected: BTreeMap<_, _> = keys.iter().map(|key| (*key, [3; 32])).collect();
        assert_eq!(snapshot.nodes(&keys, 32).await.unwrap(), expected);
        let updates: BTreeMap<_, _> = [0, 256, 512]
            .map(|position| (NodePosition { level: 0, position }, [4; 32]))
            .into_iter()
            .collect();
        let writer = db.begin().await.unwrap();
        RegistryStore::<_, MemberRecord>::new(&writer, [1; 32])
            .save_nodes(&updates, 32)
            .await
            .unwrap();
        writer.commit().await.unwrap();
        assert_eq!(snapshot.nodes(&keys, 32).await.unwrap(), expected);
        tx.commit().await.unwrap();
        let mut current = expected;
        current.extend(updates);
        let fresh = begin_read(&db).await.unwrap();
        let store = RegistryStore::<_, MemberRecord>::new(&fresh, [1; 32]);
        assert_eq!(store.nodes(&keys, 32).await.unwrap(), current);
        fresh.commit().await.unwrap();
    }

    #[tokio::test]
    async fn historical_nodes_reject_malformed_stored_hashes() {
        let db = database().await;
        let store = RegistryStore::<_, MemberRecord>::new(&db, [1; 32]);
        store
            .exec(
                "INSERT INTO ring_record_nodes(program,level,position,applied,hash) \
                 VALUES($1,$2,$3,$4,$5)",
                vec![0i64.into(), 0i64.into(), 1i64.into(), vec![1u8].into()],
            )
            .await
            .unwrap();
        assert!(store
            .nodes(&BTreeSet::from([NodePosition::root(0)]), 1)
            .await
            .is_err());
    }
}
