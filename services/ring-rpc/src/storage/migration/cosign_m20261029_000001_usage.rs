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
            format!(
                "CREATE TABLE cosign_usage (signature {blob} NOT NULL, asset {blob} NOT NULL, \
                 ring {blob} NOT NULL, sender {blob} NOT NULL, slot BIGINT NOT NULL, \
                 transferred {blob} NOT NULL, deposited {blob} NOT NULL, withdrawn {blob} NOT NULL, \
                 confirmed BOOLEAN NOT NULL, PRIMARY KEY(signature, asset))"
            ),
            "CREATE INDEX cosign_usage_window ON cosign_usage(ring, asset, slot)".to_string(),
        ] {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE cosign_usage")
            .await?;
        Ok(())
    }
}
