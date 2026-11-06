/** Rust `RingError::is_projection_lag`, the answer holds only for the state it was asked under. */
export const MEMBER_REGISTRY_PROJECTION_ERRORS: ReadonlySet<string> = new Set([
  "CLIENT_INDEXER_PROOF_DATA_NOT_READY",
  "RING_REGISTRY_OUT_OF_SYNC",
  "RING_REGISTRY_ROOT_CHANGED",
]);
