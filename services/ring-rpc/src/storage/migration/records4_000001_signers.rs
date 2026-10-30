use sea_orm::{DatabaseBackend, Statement};
use sea_orm_migration::prelude::*;
use zolana_ring_client::rpc::SubmitRecordUpdateRequest;

use crate::{record_update::UpdateSigner, update_queue::role};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        let backend = manager.get_database_backend();
        let blob = match backend {
            DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
        for sql in [
            format!("ALTER TABLE records_updates ADD COLUMN signer {blob}"),
            "ALTER TABLE records_updates ADD COLUMN role TEXT".to_string(),
        ] {
            connection.execute_unprepared(&sql).await?;
        }
        // Settled rows keep a NULL signer, the flush never reads them.
        let unsettled = connection
            .query_all(Statement::from_string(
                backend,
                "SELECT id, request FROM records_updates \
                 WHERE status IN ('awaiting', 'queued', 'submitted')",
            ))
            .await?;
        for row in unsettled {
            let id: Vec<u8> = row.try_get("", "id")?;
            let request: SubmitRecordUpdateRequest =
                serde_json::from_str(&row.try_get::<String>("", "request")?)
                    .map_err(|error| DbErr::Migration(error.to_string()))?;
            let signer = UpdateSigner::of(&request)
                .map_err(|refusal| DbErr::Migration(refusal.to_string()))?;
            connection
                .execute(Statement::from_sql_and_values(
                    backend,
                    "UPDATE records_updates SET signer=$1, role=$2 WHERE id=$3",
                    [
                        signer.address().as_array().to_vec().into(),
                        role(signer).into(),
                        id.into(),
                    ],
                ))
                .await?;
        }
        connection
            .execute_unprepared("ALTER TABLE records_updates DROP COLUMN urgent")
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for sql in [
            "ALTER TABLE records_updates ADD COLUMN urgent BOOLEAN NOT NULL DEFAULT FALSE",
            "UPDATE records_updates SET urgent = COALESCE(role = 'policy', FALSE)",
            "ALTER TABLE records_updates DROP COLUMN role",
            "ALTER TABLE records_updates DROP COLUMN signer",
        ] {
            manager.get_connection().execute_unprepared(sql).await?;
        }
        Ok(())
    }
}
