use custom_ring_interface::{RingAccount, VIEWING_PUBKEY_TAG};
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use spr_hasher::primitives::is_canonical_x25519_public_key;

pub(crate) struct Init<'a, T>(pub &'a T);

impl<T: RingAccount> Init<'_, T> {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account
            .try_borrow_mut()
            .map_err(|_| ProgramError::AccountBorrowFailed)?;
        if data.len() != T::SIZE {
            return Err(T::INVALID.into());
        }
        // A nonzero first byte is a live discriminator, never overwrite it.
        if data[0] != 0 {
            return Err(T::EXISTS.into());
        }
        data.copy_from_slice(bytemuck::bytes_of(self.0));
        Ok(())
    }
}

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

/// Accepts a canonical auditor key only when clamped ECDH can be contributory.
/// Low-order peers yield zero DH for every secret and cannot satisfy the proof.
pub(crate) fn is_x25519_key(key: &[u8; 33]) -> bool {
    key[0] == VIEWING_PUBKEY_TAG
        && <&[u8; 32]>::try_from(&key[1..]).is_ok_and(is_canonical_x25519_public_key)
        && !LOW_ORDER_U.iter().any(|u| key[1..] == *u)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auditor_keys_must_be_tagged_canonical_and_of_large_order() {
        let key = |u: [u8; 32]| {
            let mut key = [VIEWING_PUBKEY_TAG; 33];
            key[1..].copy_from_slice(&u);
            key
        };
        let secret = x25519_dalek::StaticSecret::from([9u8; 32]);
        let public = *x25519_dalek::PublicKey::from(&secret).as_bytes();
        assert!(is_x25519_key(&key(public)));
        let mut sec1 = key(public);
        sec1[0] = 2;
        assert!(!is_x25519_key(&sec1));
        let mut modulus = [0xff; 32];
        modulus[0] = 0xed;
        modulus[31] = 0x7f;
        assert!(!is_x25519_key(&key(modulus)));
        for u in LOW_ORDER_U {
            let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(u));
            assert!(!shared.was_contributory());
            assert!(!is_x25519_key(&key(u)));
        }
    }
}
