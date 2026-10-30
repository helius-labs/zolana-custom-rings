use sea_orm_migration::prelude::*;

use super::m20261024_000002_record_tree::{blob, execute};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = blob(manager);
        execute(
            manager,
            vec![
                format!(
                    "CREATE TABLE storage_registries (registry {blob} PRIMARY KEY, \
                     state TEXT NOT NULL)"
                ),
                format!(
                    "CREATE TABLE storage_roots (registry {blob} NOT NULL, \
                     revision BIGINT NOT NULL, root {blob} NOT NULL, next_index BIGINT NOT NULL, \
                     PRIMARY KEY(registry, revision))"
                ),
            ],
        )
        .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut statements = ["ring_records", "ring_record_nodes"]
            .map(|table| {
                format!("DELETE FROM {table} WHERE program IN (SELECT registry FROM storage_registries)")
            })
            .to_vec();
        statements.extend(
            ["storage_roots", "storage_registries"].map(|table| format!("DROP TABLE {table}")),
        );
        execute(manager, statements).await
    }
}
