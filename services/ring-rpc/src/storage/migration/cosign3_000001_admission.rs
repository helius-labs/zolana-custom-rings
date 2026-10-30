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
                "CREATE TABLE cosign_admission (ring {blob} NOT NULL, asset {blob} NOT NULL, \
                 PRIMARY KEY(ring, asset))"
            ))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE cosign_admission")
            .await?;
        Ok(())
    }
}
