use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = match manager.get_database_backend() {
            DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
        for sql in [
            "ALTER TABLE records_updates ADD COLUMN awaited BIGINT NOT NULL DEFAULT 0".to_string(),
            format!("ALTER TABLE records_updates ADD COLUMN joined {blob}"),
            "CREATE INDEX records_updates_joined ON records_updates(joined)".to_string(),
            format!("ALTER TABLE records_updates ADD COLUMN member {blob}"),
            "CREATE INDEX records_updates_member ON records_updates(ring, member)".to_string(),
            "CREATE INDEX records_updates_ring ON records_updates(ring, status, seq)".to_string(),
        ] {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for sql in [
            "DROP INDEX records_updates_ring",
            "DROP INDEX records_updates_member",
            "ALTER TABLE records_updates DROP COLUMN member",
            "DROP INDEX records_updates_joined",
            "ALTER TABLE records_updates DROP COLUMN joined",
            "ALTER TABLE records_updates DROP COLUMN awaited",
        ] {
            manager.get_connection().execute_unprepared(sql).await?;
        }
        Ok(())
    }
}
