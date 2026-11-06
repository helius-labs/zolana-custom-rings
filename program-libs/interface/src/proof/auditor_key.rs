//! The one check on an auditor key, run by every instruction that stores one.
//!
//! A ring pins the key for its life and its tracking registry seals enrollment to it. The X25519
//! gadget clamps the ephemeral scalar and refuses a zero agreement, and a clamped scalar agrees zero
//! with every low-order key. No proof can seal to such a key, a ring under it could neither enroll
//! an owner nor settle a transfer.
//!
//! Read after `program-libs/interface/src/accounts/tracking.rs`. Read before
//! `programs/custom-ring/src/instructions/configuration/setup/initialize.rs`, `programs/storage/src/instructions/initialize_tracking.rs`.

use spr_hasher::primitives::is_canonical_x25519_public_key;

use crate::{TAGGED_X25519_KEY_LEN, VIEWING_PUBKEY_TAG};

/// The canonical low-order u coordinates on the curve and its twist.
const LOW_ORDER_U: [[u8; 32]; 5] = [
    [0; 32],
    {
        let mut u = [0; 32];
        u[0] = 1;
        u
    },
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    {
        let mut u = [0xff; 32];
        u[0] = 0xec;
        u[31] = 0x7f;
        u
    },
];

/// Tagged, canonical and of large order.
pub fn is_auditor_key(key: &[u8; TAGGED_X25519_KEY_LEN]) -> bool {
    let Some((&tag, u)) = key.split_first() else {
        return false;
    };
    tag == VIEWING_PUBKEY_TAG
        && <&[u8; 32]>::try_from(u).is_ok_and(is_canonical_x25519_public_key)
        && !LOW_ORDER_U.iter().any(|low_order| u == low_order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tagged_x25519;

    #[test]
    fn auditor_keys_must_be_tagged_canonical_and_of_large_order() {
        let secret = x25519_dalek::StaticSecret::from([9u8; 32]);
        let public = *x25519_dalek::PublicKey::from(&secret).as_bytes();
        assert!(is_auditor_key(&tagged_x25519(&public)));
        let mut sec1 = tagged_x25519(&public);
        sec1[0] = 2;
        assert!(!is_auditor_key(&sec1));
        let mut modulus = [0xff; 32];
        modulus[0] = 0xed;
        modulus[31] = 0x7f;
        assert!(!is_auditor_key(&tagged_x25519(&modulus)));
        for u in LOW_ORDER_U {
            let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(u));
            assert!(!shared.was_contributory());
            assert!(!is_auditor_key(&tagged_x25519(&u)));
        }
    }
}
