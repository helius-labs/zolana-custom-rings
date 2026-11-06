//! The ring side of SPP's output blinding.
//!
//! An auditor holding the sealed key and the salt rebuilds the seed, and through it each ring output's blinding.
//!
//! Read after `program-libs/interface/src/proof/audit_stream.rs`. Read before `program-libs/interface/src/codec/stream.rs`.

use spr_hasher::{
    primitives::{pack_be, right_align},
    Hasher, HasherError, Poseidon,
};

use crate::domain;

/// SPP's `blinding_seed`, the seed of every ring output's TXOB blinding.
pub fn ring_blinding_seed(
    tx_viewing_secret: &[u8; 32],
    salt: &[u8; 16],
) -> Result<[u8; 32], HasherError> {
    let [key0, key1] = pack_be(tx_viewing_secret);
    Poseidon::hashv(&[
        &domain::field(domain::BLINDING_SEED),
        &key0,
        &key1,
        &right_align(salt),
    ])
}
