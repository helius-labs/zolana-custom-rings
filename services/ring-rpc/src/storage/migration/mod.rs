use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[path = "../migration_cosign.rs"]
mod cosign;
mod wallet_snapshots;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(Schema)]
    }
}

#[derive(DeriveMigrationName)]
struct Schema;

const TABLES: [&str; 24] = [
    "records_update_members",
    "projection_revisions",
    "owner_notes",
    "projection_leases",
    "pending_derivations",
    "held_enrollments",
    "tracking_cursors",
    "spend_unread_frames",
    "spend_integrity_faults",
    "spend_checkpoints",
    "replay_nonces",
    "relay_relays",
    "relay_reservations",
    "relay_reserved",
    "records_updates",
    "merge_settings",
    "merge_inputs",
    "grants",
    "finalized_spent_nullifiers",
    "finalized_notes",
    "cosign_totals",
    "cosign_usage",
    "cosign_admission",
    "records_batches",
];

#[async_trait::async_trait]
impl MigrationTrait for Schema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let (blob, serial) = match manager.get_database_backend() {
            DatabaseBackend::Postgres => ("BYTEA", "BIGSERIAL PRIMARY KEY"),
            _ => ("BLOB", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        };
        for sql in [
            format!("CREATE TABLE records_batches (id {serial}, registry {blob} NOT NULL, signature {blob} NOT NULL, revision BIGINT NOT NULL, last_valid_block_height BIGINT NOT NULL, status TEXT NOT NULL)"),
            format!("CREATE TABLE finalized_notes (ring {blob} NOT NULL, commitment {blob} NOT NULL, sealed {blob} NOT NULL, nullifier_tag {blob}, revision BIGINT NOT NULL, PRIMARY KEY(ring, commitment))"),
            format!("CREATE TABLE projection_revisions (ring {blob} NOT NULL PRIMARY KEY, revision BIGINT NOT NULL)"),
            format!("CREATE TABLE owner_notes (ring {blob} NOT NULL, owner_tag {blob} NOT NULL, note_tag {blob} NOT NULL, sealed {blob} NOT NULL, spent_slot BIGINT, PRIMARY KEY(ring, owner_tag, note_tag))"),
            format!("CREATE TABLE finalized_spent_nullifiers (ring {blob} NOT NULL, nullifier {blob} NOT NULL, slot BIGINT NOT NULL, tx_signature {blob} NOT NULL, event_index INTEGER NOT NULL, position INTEGER NOT NULL, state VARCHAR(16) NOT NULL, sealed_note {blob}, revision BIGINT NOT NULL, PRIMARY KEY(ring, nullifier))"),
            format!("CREATE TABLE grants (id {serial}, reader {blob} NOT NULL, sealed {blob} NOT NULL)"),
            format!("CREATE TABLE merge_inputs (nullifier {blob} PRIMARY KEY, ring {blob} NOT NULL, relay_id {blob} NOT NULL)"),
            format!("CREATE TABLE merge_settings (ring {blob} NOT NULL, owner {blob} NOT NULL, mint {blob} NOT NULL, target_note_count BIGINT NOT NULL, min_average_amount {blob} NOT NULL, signed_at BIGINT NOT NULL, PRIMARY KEY(ring, owner, mint))"),
            format!("CREATE TABLE records_updates (seq {serial}, id {blob} NOT NULL UNIQUE, registry {blob} NOT NULL, ring {blob} NOT NULL, request TEXT NOT NULL, writes {blob} NOT NULL, queued_slot BIGINT NOT NULL, valid_until_slot BIGINT NOT NULL, status TEXT NOT NULL, batch BIGINT REFERENCES records_batches(id), reason TEXT, attempts BIGINT NOT NULL DEFAULT 0, awaited BIGINT NOT NULL DEFAULT 0, joined {blob}, member {blob}, signer {blob}, role TEXT)"),
            format!(
                "CREATE TABLE relay_reservations (key {blob} NOT NULL PRIMARY KEY, relay_id {blob} NOT NULL, \
                 signer {blob} NOT NULL, lamports BIGINT NOT NULL, fee_allowance BIGINT NOT NULL, \
                 landing_rent BIGINT NOT NULL, spent BIGINT NOT NULL, phase TEXT NOT NULL, \
                 generation BIGINT NOT NULL, lease_until_slot BIGINT NOT NULL, touched_slot BIGINT NOT NULL)"
            ),
            format!(
                "CREATE TABLE relay_reserved (scope {blob} NOT NULL PRIMARY KEY, committed BIGINT NOT NULL)"
            ),
            "CREATE UNIQUE INDEX relay_reservations_relay ON relay_reservations(relay_id)".to_owned(),
            "CREATE INDEX relay_reservations_touched ON relay_reservations(touched_slot)".to_owned(),
            format!("CREATE TABLE relay_relays (relay_id {blob} PRIMARY KEY, status TEXT NOT NULL, state TEXT NOT NULL, revision BIGINT NOT NULL)"),
            format!("CREATE TABLE replay_nonces (ring {blob} NOT NULL, nonce {blob} NOT NULL, signed_at BIGINT NOT NULL, PRIMARY KEY(ring, nonce))"),
            format!("CREATE TABLE spend_checkpoints (ring {blob} NOT NULL PRIMARY KEY, after_slot BIGINT, token VARCHAR(256), through_slot BIGINT NOT NULL, block_time BIGINT NOT NULL)"),
            format!("CREATE TABLE spend_integrity_faults (ring {blob} NOT NULL, nullifier {blob} NOT NULL, slot BIGINT NOT NULL, tx_signature {blob} NOT NULL, event_index INTEGER NOT NULL, PRIMARY KEY(ring, nullifier, tx_signature, event_index))"),
            format!("CREATE TABLE spend_unread_frames (ring {blob} NOT NULL, slot BIGINT NOT NULL, tx_signature {blob} NOT NULL, event_index INTEGER NOT NULL, attempts BIGINT NOT NULL DEFAULT 0, retry_after BIGINT NOT NULL DEFAULT 0, PRIMARY KEY(ring, tx_signature, event_index))"),
            format!("CREATE TABLE tracking_cursors (ring {blob} NOT NULL PRIMARY KEY, next_leaf BIGINT NOT NULL)"),
            format!("CREATE TABLE held_enrollments (ring {blob} NOT NULL, member {blob} NOT NULL, sealed {blob} NOT NULL, owner_hash_tag {blob} NOT NULL, list_key_tag {blob} NOT NULL, revision BIGINT NOT NULL, PRIMARY KEY(ring, member))"),
            format!("CREATE TABLE pending_derivations (ring {blob} NOT NULL, member {blob} NOT NULL, after_tag {blob}, PRIMARY KEY(ring, member))"),
            format!("CREATE TABLE projection_leases (ring {blob} NOT NULL PRIMARY KEY, holder {blob} NOT NULL, instance {blob} NOT NULL, token BIGINT NOT NULL, expires_at BIGINT NOT NULL)"),
            "CREATE INDEX spend_unread_order ON spend_unread_frames(ring, slot, tx_signature, event_index)".to_owned(),
            "CREATE INDEX spend_unread_due ON spend_unread_frames(ring, retry_after, slot, tx_signature, event_index)".to_owned(),
            "CREATE INDEX grants_reader ON grants(reader)".to_owned(),
            "CREATE INDEX finalized_notes_nullifier ON finalized_notes(ring, nullifier_tag)".to_owned(),
            "CREATE INDEX finalized_notes_revision ON finalized_notes(ring, revision)".to_owned(),
            "CREATE INDEX finalized_spent_nullifiers_revision ON finalized_spent_nullifiers(ring, revision)".to_owned(),
            "CREATE INDEX finalized_spent_nullifiers_state ON finalized_spent_nullifiers(ring, state, nullifier)".to_owned(),
            "CREATE INDEX held_enrollments_revision ON held_enrollments(ring, revision)".to_owned(),
            "CREATE INDEX held_enrollments_owner_hash ON held_enrollments(ring, owner_hash_tag)".to_owned(),
            "CREATE INDEX held_enrollments_list_key ON held_enrollments(ring, list_key_tag)".to_owned(),
            "CREATE INDEX merge_inputs_ring ON merge_inputs(ring)".to_owned(),
            "CREATE INDEX owner_notes_spent ON owner_notes(ring, spent_slot)".to_owned(),
            "CREATE INDEX records_updates_joined ON records_updates(joined)".to_owned(),
            "CREATE INDEX records_updates_approval ON records_updates(ring, registry, status, member, awaited, valid_until_slot, seq)".to_owned(),
            "CREATE INDEX records_updates_queue ON records_updates(registry, status, seq)".to_owned(),
            "CREATE INDEX records_updates_role ON records_updates(registry, role, status, seq)".to_owned(),
            "CREATE INDEX records_updates_expiry ON records_updates(registry, status, valid_until_slot, seq) WHERE joined IS NULL".to_owned(),
            format!("CREATE TABLE records_update_members (seq BIGINT NOT NULL, registry {blob} NOT NULL, member {blob} NOT NULL, PRIMARY KEY(seq, member))"),
            "CREATE INDEX records_update_members_member ON records_update_members(registry, member, seq)".to_owned(),
            "CREATE INDEX records_updates_ring ON records_updates(ring, registry, status, seq)".to_owned(),
            "CREATE INDEX relay_relays_status ON relay_relays(status)".to_owned(),
            "CREATE INDEX replay_nonces_signed_at ON replay_nonces(signed_at)".to_owned(),
            "CREATE UNIQUE INDEX records_batches_open ON records_batches(registry) WHERE status = 'submitted'".to_owned(),
        ] {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        for sql in cosign::statements(blob)
            .into_iter()
            .chain(wallet_snapshots::statements(blob))
        {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in wallet_snapshots::TABLES.iter().copied().chain(TABLES) {
            manager
                .get_connection()
                .execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
        }
        Ok(())
    }
}
