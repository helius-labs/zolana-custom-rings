use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

mod m20261024_000001_drop_ring_spend_records;
mod m20261024_000002_record_tree;
mod m20261025_000001_mint_policy;
mod m20261029_000001_storage_registries;
mod m20261029_000002_retire_record_queue;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(RingTables),
            Box::new(m20261024_000001_drop_ring_spend_records::Migration),
            Box::new(m20261024_000002_record_tree::Migration),
            Box::new(m20261025_000001_mint_policy::Migration),
            Box::new(m20261029_000001_storage_registries::Migration),
            Box::new(m20261029_000002_retire_record_queue::Migration),
        ]
    }
}

struct RingTables;

impl MigrationName for RingTables {
    fn name(&self) -> &str {
        "m20261023_000001_ring_tables"
    }
}

const TABLES: [&str; 8] = [
    "ring_cursor",
    "ring_blocks",
    "ring_pending",
    "ring_registry_roots",
    "ring_registry_members",
    "ring_registry_nodes",
    "ring_spend_rings",
    "ring_spend_records",
];

#[async_trait::async_trait]
impl MigrationTrait for RingTables {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = match manager.get_database_backend() {
            DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
        for sql in [
            "CREATE TABLE ring_cursor (id INTEGER PRIMARY KEY, state TEXT NOT NULL)".to_string(),
            "CREATE TABLE ring_blocks (slot BIGINT PRIMARY KEY, state TEXT NOT NULL)".to_string(),
            format!(
                "CREATE TABLE ring_pending (program {blob} PRIMARY KEY, \
                 slot BIGINT NOT NULL, state TEXT NOT NULL)"
            ),
            format!("CREATE TABLE ring_registry_roots (program {blob} PRIMARY KEY, state TEXT NOT NULL)"),
            format!(
                "CREATE TABLE ring_registry_members (program {blob} NOT NULL, \
                 member {blob} NOT NULL, leaf_index BIGINT NOT NULL, state TEXT NOT NULL, \
                 PRIMARY KEY(program, member), UNIQUE(program, leaf_index))"
            ),
            format!(
                "CREATE TABLE ring_registry_nodes (program {blob} NOT NULL, \
                 node_idx BIGINT NOT NULL, hash {blob} NOT NULL, PRIMARY KEY(program, node_idx))"
            ),
            format!("CREATE TABLE ring_spend_rings (program {blob} PRIMARY KEY, fault TEXT)"),
            format!(
                "CREATE TABLE ring_spend_records (program {blob} NOT NULL, member {blob} NOT NULL, \
                 nullifier {blob} NOT NULL, output_index INTEGER NOT NULL, \
                 shielded_transaction TEXT NOT NULL, PRIMARY KEY(program, member))"
            ),
            "CREATE INDEX ring_spend_records_nullifier ON ring_spend_records(program, nullifier)"
                .to_string(),
        ] {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in TABLES.iter().rev() {
            manager
                .get_connection()
                .execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
        }
        Ok(())
    }
}
