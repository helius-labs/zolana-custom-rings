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
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "CREATE TABLE merge_settings (ring {blob} NOT NULL, owner {blob} NOT NULL, \
                 mint {blob} NOT NULL, target_note_count BIGINT NOT NULL, \
                 min_average_amount {blob} NOT NULL, signed_at BIGINT NOT NULL, \
                 PRIMARY KEY(ring, owner, mint))"
            ))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE merge_settings")
            .await?;
        Ok(())
    }
}
