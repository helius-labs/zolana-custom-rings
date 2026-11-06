use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(Schema)]
    }
}

#[derive(DeriveMigrationName)]
struct Schema;

const TABLES: [&str; 9] = [
    "tracking_registries",
    "tracking_records",
    "tracking_authorizations",
    "storage_roots",
    "storage_registries",
    "ring_records",
    "ring_record_nodes",
    "ring_cursor",
    "ring_blocks",
];

#[async_trait::async_trait]
impl MigrationTrait for Schema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = match manager.get_database_backend() {
            DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
        for sql in [
            "CREATE TABLE ring_blocks (slot BIGINT PRIMARY KEY, state TEXT NOT NULL)".to_owned(),
            "CREATE TABLE ring_cursor (id INTEGER PRIMARY KEY, state TEXT NOT NULL)".to_owned(),
            format!("CREATE TABLE ring_record_nodes (program {blob} NOT NULL, level BIGINT NOT NULL, position BIGINT NOT NULL, applied BIGINT NOT NULL, hash {blob} NOT NULL, PRIMARY KEY(program, level, position, applied))"),
            format!("CREATE TABLE ring_records (program {blob} NOT NULL, leaf_index BIGINT NOT NULL, applied BIGINT NOT NULL, member {blob} NOT NULL, next_member {blob} NOT NULL, lists BIGINT NOT NULL, mint_policy TEXT, PRIMARY KEY(program, leaf_index, applied))"),
            format!("CREATE TABLE storage_registries (registry {blob} PRIMARY KEY, state TEXT NOT NULL)"),
            format!("CREATE TABLE storage_roots (registry {blob} NOT NULL, revision BIGINT NOT NULL, root {blob} NOT NULL, next_index BIGINT NOT NULL, PRIMARY KEY(registry, revision))"),
            format!("CREATE TABLE tracking_authorizations (registry {blob} NOT NULL, owner {blob} NOT NULL, authorization_account {blob} NOT NULL, member {blob} NOT NULL, nullifier_pk {blob} NOT NULL, ct_hash {blob} NOT NULL, list_tag {blob} NOT NULL, eph_u {blob} NOT NULL, ciphertext {blob} NOT NULL, slot BIGINT NOT NULL, applied_slot BIGINT, PRIMARY KEY(registry, owner))"),
            format!("CREATE TABLE tracking_records (program {blob} NOT NULL, leaf_index BIGINT NOT NULL, applied BIGINT NOT NULL, member {blob} NOT NULL, next_member {blob} NOT NULL, nullifier_pk {blob} NOT NULL, ct_hash {blob} NOT NULL, list_tag {blob} NOT NULL, PRIMARY KEY(program, leaf_index, applied))"),
            format!("CREATE TABLE tracking_registries (registry {blob} PRIMARY KEY, state TEXT NOT NULL)"),
            "CREATE INDEX ring_record_nodes_applied ON ring_record_nodes(program, applied)".to_owned(),
            "CREATE INDEX ring_records_applied ON ring_records(program, applied)".to_owned(),
            "CREATE INDEX ring_records_member ON ring_records(program, member, applied)".to_owned(),
            "CREATE INDEX tracking_authorizations_account ON tracking_authorizations(registry, authorization_account)".to_owned(),
            "CREATE INDEX tracking_authorizations_member ON tracking_authorizations(registry, member)".to_owned(),
            "CREATE INDEX tracking_authorizations_slot ON tracking_authorizations(slot)".to_owned(),
            "CREATE INDEX tracking_authorizations_applied_slot ON tracking_authorizations(applied_slot)".to_owned(),
            "CREATE INDEX tracking_records_applied ON tracking_records(program, applied)".to_owned(),
            "CREATE INDEX tracking_records_member ON tracking_records(program, member, applied)".to_owned(),
        ] {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in TABLES {
            manager
                .get_connection()
                .execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
        }
        Ok(())
    }
}
