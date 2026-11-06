//! The recipient key a dummy slot seals its zero record to, derived from the transaction viewing secret.
//!
//! A relay that proves a sealed transfer holds the viewing secret and rederives every dummy key, no
//! wire carries them. An observer without the secret reads each key as random. The derivation is
//! not proven, the circuit takes the key as a witness and the auditor reads it from the stream.

use custom_ring_interface::domain;
use spr_hasher::{
    primitives::{pack_be, right_align},
    Hasher, Poseidon,
};
use spr_keypair::{X25519Keypair, X25519Pubkey};
use zeroize::Zeroizing;

use crate::RingKeyError;

/// `"CRDK"`, apart from every ring domain.
pub const DUMMY_KEY_DOMAIN: u32 = 0x4352_444b;

/// `clamp(Poseidon(CRDK, pack_be(tx_viewing_sk), slot))` as an X25519 secret, the public key of
/// dummy slot `slot`.
pub fn dummy_recipient_key(
    tx_viewing_secret: &[u8; 32],
    slot: u32,
) -> Result<X25519Pubkey, RingKeyError> {
    let [key0, key1] = pack_be(tx_viewing_secret);
    let mut secret = Zeroizing::new(Poseidon::hashv(&[
        &domain::field(DUMMY_KEY_DOMAIN),
        &key0,
        &key1,
        &right_align(&slot.to_be_bytes()),
    ])?);
    // RFC 7748 clamping, the little endian scalar the multiplication reads.
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    Ok(X25519Keypair::from_bytes(&secret).pubkey())
}
