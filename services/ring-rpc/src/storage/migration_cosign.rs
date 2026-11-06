pub(super) fn statements(blob: &str) -> [String; 3] {
    [
        format!("CREATE TABLE cosign_admission (ring {blob} NOT NULL, asset {blob} NOT NULL, last_slot BIGINT NOT NULL DEFAULT 0, PRIMARY KEY(ring, asset))"),
        format!("CREATE TABLE cosign_usage (signature {blob} NOT NULL, ring {blob} NOT NULL, owner {blob} NOT NULL, asset {blob} NOT NULL, slot BIGINT NOT NULL, outflow_hi BIGINT NOT NULL, outflow_lo BIGINT NOT NULL, deposited_hi BIGINT NOT NULL, deposited_lo BIGINT NOT NULL, withdrawn_hi BIGINT NOT NULL, withdrawn_lo BIGINT NOT NULL, state TEXT NOT NULL CHECK(state IN ('held','confirmed','released')), PRIMARY KEY(signature, owner, asset))"),
        format!("CREATE TABLE cosign_totals (ring {blob} NOT NULL, asset {blob} NOT NULL, epoch BIGINT NOT NULL, scope_kind BIGINT NOT NULL, owner {blob} NOT NULL, node BIGINT NOT NULL, outflow {blob} NOT NULL, deposited {blob} NOT NULL, withdrawn {blob} NOT NULL, PRIMARY KEY(ring, asset, epoch, scope_kind, owner, node))"),
    ]
}
