pub(super) const TABLES: &[&str] = &[
    "wallet_snapshot_notes",
    "wallet_snapshots",
    "wallet_snapshot_admission",
];

pub(super) fn statements(blob: &str) -> Vec<String> {
    vec![
        "CREATE TABLE wallet_snapshot_admission (id INTEGER PRIMARY KEY CHECK(id=1))".to_owned(),
        "INSERT INTO wallet_snapshot_admission(id) VALUES(1)".to_owned(),
        format!("CREATE TABLE wallet_snapshots (id {blob} PRIMARY KEY, ring {blob} NOT NULL, scope_tag {blob} NOT NULL, expires_at BIGINT NOT NULL, sealed {blob} NOT NULL)"),
        format!("CREATE TABLE wallet_snapshot_notes (snapshot_id {blob} NOT NULL REFERENCES wallet_snapshots(id), note_tag {blob} NOT NULL, sealed {blob} NOT NULL, spent_slot BIGINT, PRIMARY KEY(snapshot_id,note_tag))"),
        "CREATE INDEX wallet_snapshots_scope ON wallet_snapshots(ring,scope_tag)".to_owned(),
        "CREATE INDEX wallet_snapshots_expiry ON wallet_snapshots(expires_at,id)".to_owned(),
    ]
}
