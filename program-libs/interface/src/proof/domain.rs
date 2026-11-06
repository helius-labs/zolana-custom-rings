//! Domain tags of the ring hashes, distinct ASCII tags absorbed as the first
//! Poseidon input and mirrored by Go `prover/circuits/shared/derivation.go`.
//!
//! A tag reused across two hashes would let a preimage of one answer for the other.
//!
//! Read after `program-libs/interface/src/proof/statement.rs`. Read before `program-libs/interface/src/proof/audit_stream.rs`.

use spr_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};

/// `"CRDS"`
pub const DELIVERED_SLOT_SECRET: u32 = 0x4352_4453;
/// `"CRRT"`, a recipient or dummy slot's view tag.
pub const RECIPIENT_TAG: u32 = 0x4352_5254;
/// `"CRST"`, the sender bundle's view tag.
pub const SENDER_TAG: u32 = 0x4352_5354;
/// `"CRBS"`
pub const BLINDING_SEED: u32 = 0x4352_4253;
/// `"CR_S"`, the root of every auditor stream.
pub const AUDIT_SHARED_SECRET: u32 = 0x4352_5f53;
/// `"CRTB"`, defined beside the table hash in the policy crate the interface depends on.
pub use zolana_ring_policy::POLICY_TABLE_DOMAIN as POLICY_TABLE;
/// `"CRQW"`
pub const RECORD_WRITE: u32 = 0x4352_5157;
/// `"CRAP"`
pub const APPLY_RECORDS: u32 = 0x4352_4150;
/// `"CRRG"`
pub const REGISTER_KEY: u32 = 0x4352_5247;
/// `"CRTK"`
pub const TRACKING_LEAF: u32 = 0x4352_544b;
/// `"CRTQ"`
pub const TRACKING_ENTRY: u32 = 0x4352_5451;
/// `"CRTA"`
pub const APPLY_ENROLLMENTS: u32 = 0x4352_5441;
/// `"CRMG"`
pub const MERGE_STATEMENT: u32 = 0x4352_4d47;
/// `"CRPW"`
pub const WITHDRAWALS: u32 = 0x4352_5057;
/// `"CRRU"`
pub const RECORD_UPDATE: u32 = 0x4352_5255;
/// `"CRWG"`
pub use zolana_ring_policy::WALLET_GRANT_DOMAIN as WALLET_GRANT;
/// `"CRPT"`
pub const LIST_TAG: u32 = 0x4352_5054;

/// `"CRTX"`
pub const TRANSFER_STATEMENT: u32 = 0x4352_5458;

pub const AUDIT_STREAM_LABEL: &[u8; 9] = b"CRING/adt";
pub const RECIPIENT_BODY_LABEL: &[u8; 9] = b"CRING/rcp";
pub const REPLY_LABEL: &[u8; 9] = b"CRING/rpl";
pub const SENDER_BUNDLE_LABEL: &[u8; 9] = b"CRING/snd";
pub const REGISTER_KEY_LABEL: &[u8; 9] = b"CRING/nfk";
pub const MERGE_RECORD_LABEL: &[u8; 9] = b"CRING/mrg";

pub fn field(domain: u32) -> [u8; 32] {
    right_align(&domain.to_be_bytes())
}

/// `Poseidon(CRPT, list_salt)`, final in the tracking leaf.
pub fn list_tag(list_salt: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[&field(LIST_TAG), list_salt])
}
