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
                "CREATE TABLE replay_nonces (ring {blob} NOT NULL, nonce {blob} NOT NULL, \
                 signed_at BIGINT NOT NULL, PRIMARY KEY(ring, nonce))"
            ),
            "CREATE INDEX replay_nonces_signed_at ON replay_nonces(signed_at)".to_string(),
        ] {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE replay_nonces")
            .await?;
        Ok(())
    }
}
