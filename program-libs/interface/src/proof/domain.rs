//! Domain tags of the ring hashes, distinct ASCII tags absorbed as the first
//! Poseidon input and mirrored by Go `prover/circuits/shared/derivation.go`.

use spr_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};

/// `"CRAU"`
pub const AUDIT_STATEMENT: u32 = 0x4352_4155;
/// `"CRDS"`
pub const DELIVERED_SLOT_SECRET: u32 = 0x4352_4453;
/// `"CRBS"`
pub const BLINDING_SEED: u32 = 0x4352_4253;
/// `"CRSC"`
pub const SENDER_COMMITMENT: u32 = 0x4352_5343;
/// `"CROD"`
pub const DISCLOSURE_PAD: u32 = 0x4352_4f44;
/// `"CRPO"`
pub const POLICY_STATEMENT: u32 = 0x4352_504f;
/// `"CRTB"`, defined beside the table hash in the policy crate the interface depends on.
pub use zolana_ring_policy::POLICY_TABLE_DOMAIN as POLICY_TABLE;
/// `"CRQW"`
pub const QUEUE_WRITE: u32 = 0x4352_5157;
/// `"CRAP"`
pub const APPLY_RECORDS: u32 = 0x4352_4150;
/// `"CRRG"`
pub const REGISTER_KEY: u32 = 0x4352_5247;
/// `"CRDB"`
pub const DEPOSIT_BLINDING: u32 = 0x4352_4442;
/// `"CRDP"`
pub const DEPOSIT_STATEMENT: u32 = 0x4352_4450;
/// `"CRMG"`
pub const MERGE_STATEMENT: u32 = 0x4352_4d47;
/// `"CRPW"`
pub const WITHDRAWALS: u32 = 0x4352_5057;
/// `"CRWX"`
pub const WITHDRAWAL_EXEMPTION: u32 = 0x4352_5758;

/// Bound into every policy statement, a layout change raises it.
pub const POLICY_STATEMENT_VERSION: u8 = 4;

pub fn field(domain: u32) -> [u8; 32] {
    right_align(&domain.to_be_bytes())
}

/// `Poseidon(CRDB, blinding_secret)`.
pub fn deposit_blinding(blinding_secret: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[&field(DEPOSIT_BLINDING), blinding_secret])
}
