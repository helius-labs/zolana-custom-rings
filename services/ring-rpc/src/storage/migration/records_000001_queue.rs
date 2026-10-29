use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLES: [&str; 2] = ["records_batches", "records_updates"];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let (blob, serial) = match manager.get_database_backend() {
            DatabaseBackend::Postgres => ("BYTEA", "BIGSERIAL PRIMARY KEY"),
            _ => ("BLOB", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        };
        for sql in [
            format!(
                "CREATE TABLE records_batches (id {serial}, registry {blob} NOT NULL, \
                 signature {blob} NOT NULL, revision BIGINT NOT NULL, \
                 last_valid_block_height BIGINT NOT NULL, status TEXT NOT NULL)"
            ),
            // One open batch per registry keeps its updates in revision order.
            "CREATE UNIQUE INDEX records_batches_open ON records_batches(registry) \
             WHERE status = 'submitted'"
                .to_string(),
            format!(
                "CREATE TABLE records_updates (seq {serial}, id {blob} NOT NULL UNIQUE, \
                 registry {blob} NOT NULL, ring {blob} NOT NULL, request TEXT NOT NULL, \
                 writes {blob} NOT NULL, urgent BOOLEAN NOT NULL, queued_slot BIGINT NOT NULL, \
                 valid_until_slot BIGINT NOT NULL, status TEXT NOT NULL, \
                 batch BIGINT REFERENCES records_batches(id), reason TEXT)"
            ),
            "CREATE INDEX records_updates_queue ON records_updates(registry, status, seq)"
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
