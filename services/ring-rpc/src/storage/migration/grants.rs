use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

pub(super) struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m_grants_000001_rows"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let (id, blob) = match manager.get_database_backend() {
            DatabaseBackend::Postgres => ("BIGSERIAL PRIMARY KEY", "BYTEA"),
            _ => ("INTEGER PRIMARY KEY AUTOINCREMENT", "BLOB"),
        };
        let connection = manager.get_connection();
        connection
            .execute_unprepared(&format!(
                "CREATE TABLE grants (id {id}, reader {blob} NOT NULL, sealed {blob} NOT NULL)"
            ))
            .await?;
        connection
            .execute_unprepared("CREATE INDEX grants_reader ON grants(reader)")
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE grants")
            .await?;
        Ok(())
    }
}
