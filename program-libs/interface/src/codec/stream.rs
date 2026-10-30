//! Slot secrets and the sender commitment of ring transfers, mirrored by the
//! Go package `prover/circuits/shared`.

use spr_hasher::{
    primitives::{is_canonical_bn254_scalar_be, pack_be, right_align},
    Hasher, HasherError, Poseidon,
};
use thiserror::Error;

use crate::{domain, TAGGED_X25519_KEY_LEN, VIEWING_PUBKEY_TAG};

#[derive(Debug, Error, PartialEq)]
pub enum StreamError {
    #[error("value is not a canonical field element")]
    NoncanonicalField,
    #[error("viewing key is not tagged 0x04")]
    UntaggedKey,
    #[error(transparent)]
    Hasher(#[from] HasherError),
}

/// Its secret is rebuilt by the recipient from `X25519(u_sk, tx_u)`.
pub struct DeliveredSlot<'a> {
    /// `X25519(tx_sk, u)`.
    pub agreement: &'a [u8; 32],
    pub tx_viewing_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub recipient_viewing_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub salt: &'a [u8; 16],
    pub output_index: u32,
    pub first_nullifier: &'a [u8; 32],
}

impl DeliveredSlot<'_> {
    /// `Poseidon(CRDS, pack_be(dh), pack_be(tx_viewing_pk), pack_be(recipient_viewing_pk), salt, i, n0)`.
    pub fn secret(self) -> Result<SlotSecret, StreamError> {
        let [dh0, dh1] = pack_be(self.agreement);
        let [tx0, tx1] = tagged_key_fields(self.tx_viewing_pk)?;
        let [r0, r1] = tagged_key_fields(self.recipient_viewing_pk)?;
        Ok(SlotSecret(Poseidon::hashv(&[
            &domain::field(domain::DELIVERED_SLOT_SECRET),
            &dh0,
            &dh1,
            &tx0,
            &tx1,
            &r0,
            &r1,
            &right_align(self.salt),
            &right_align(&self.output_index.to_be_bytes()),
            self.first_nullifier,
        ])?))
    }
}

/// The root of a delivered ring output's body key.
#[derive(Clone)]
pub struct SlotSecret([u8; 32]);

impl SlotSecret {
    /// Every slot secret is a Poseidon output, a non-canonical value is refused.
    pub fn new(bytes: [u8; 32]) -> Result<Self, StreamError> {
        canonical(bytes).map(Self)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `Poseidon(CRSC, sender_pk_hash, private_tx_blinding)`, binding the audit and
/// policy proofs to one hidden sender.
pub struct SenderCommitment {
    pub sender_pk_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
}

impl SenderCommitment {
    pub fn derive(self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &domain::field(domain::SENDER_COMMITMENT),
            &self.sender_pk_hash,
            &self.private_tx_blinding,
        ])
    }
}

fn tagged_key_fields(key: &[u8; TAGGED_X25519_KEY_LEN]) -> Result<[[u8; 32]; 2], StreamError> {
    if key[0] != VIEWING_PUBKEY_TAG {
        return Err(StreamError::UntaggedKey);
    }
    Ok(pack_be(key))
}

fn canonical(value: [u8; 32]) -> Result<[u8; 32], StreamError> {
    if is_canonical_bn254_scalar_be(&value) {
        Ok(value)
    } else {
        Err(StreamError::NoncanonicalField)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untagged_viewing_keys_are_refused() {
        let tagged = [VIEWING_PUBKEY_TAG; TAGGED_X25519_KEY_LEN];
        let mut untagged = tagged;
        untagged[0] = 0x02;
        let slot = |recipient_viewing_pk| DeliveredSlot {
            agreement: &[1; 32],
            tx_viewing_pk: &tagged,
            recipient_viewing_pk,
            salt: &[2; 16],
            output_index: 0,
            first_nullifier: &[0; 32],
        };
        assert!(slot(&tagged).secret().is_ok());
        assert!(matches!(
            slot(&untagged).secret(),
            Err(StreamError::UntaggedKey)
        ));
    }
}
