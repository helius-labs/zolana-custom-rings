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
                "CREATE TABLE merge_inputs (nullifier {blob} PRIMARY KEY, ring {blob} NOT NULL, \
                 relay_id {blob} NOT NULL)"
            ),
            "CREATE INDEX merge_inputs_ring ON merge_inputs(ring)".to_string(),
        ] {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE merge_inputs")
            .await?;
        Ok(())
    }
}
