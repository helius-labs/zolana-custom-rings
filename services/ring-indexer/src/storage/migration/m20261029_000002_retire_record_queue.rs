use sea_orm_migration::prelude::*;

use super::m20261024_000002_record_tree::{blob, execute};

#[derive(DeriveMigrationName)]
pub struct Migration;

const RING_TABLES: [&str; 4] = [
    "ring_pending",
    "ring_registries",
    "ring_registry_roots",
    "ring_record_queue",
];

/// Storage registries keep their tree rows, the down migration restores empty ring tables.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut statements = ["ring_records", "ring_record_nodes"]
            .map(|table| {
                format!(
                    "DELETE FROM {table} WHERE program NOT IN (SELECT registry FROM storage_registries)"
                )
            })
            .to_vec();
        statements.extend(RING_TABLES.map(|table| format!("DROP TABLE {table}")));
        execute(manager, statements).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = blob(manager);
        execute(
            manager,
            vec![
                format!(
                    "CREATE TABLE ring_pending (program {blob} PRIMARY KEY, \
                     slot BIGINT NOT NULL, state TEXT NOT NULL)"
                ),
                format!(
                    "CREATE TABLE ring_registries (program {blob} PRIMARY KEY, state TEXT NOT NULL, \
                     pruned BIGINT NOT NULL DEFAULT 0)"
                ),
                format!(
                    "CREATE TABLE ring_registry_roots (program {blob} NOT NULL, \
                     applied BIGINT NOT NULL, root {blob} NOT NULL, next_index BIGINT NOT NULL, \
                     slot BIGINT NOT NULL, history_index BIGINT NOT NULL, \
                     PRIMARY KEY(program, applied))"
                ),
                format!(
                    "CREATE TABLE ring_record_queue (program {blob} NOT NULL, position BIGINT NOT NULL, \
                     member {blob} NOT NULL, mask BIGINT NOT NULL, value BIGINT NOT NULL, \
                     escrow_key {blob} NOT NULL, slot BIGINT NOT NULL, chain {blob} NOT NULL, \
                     seal TEXT, mint_policy TEXT, PRIMARY KEY(program, position))"
                ),
            ],
        )
        .await
    }
}
