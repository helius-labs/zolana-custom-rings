//! Slot secrets and the sender commitment of ring transfers, mirrored by the
//! Go package `prover/circuits/shared`.
//!
//! Read after `program-libs/interface/src/codec/output.rs`. Read before `program-libs/interface/src/proof/key_catalog.rs`.

use spr_hasher::{
    primitives::{is_canonical_bn254_scalar_be, pack_be, right_align},
    Hasher, HasherError, Poseidon,
};
use thiserror::Error;

use crate::{domain, TAGGED_X25519_KEY_LEN, VIEWING_PUBKEY_TAG};

/// The bytes of a ring slot tag a frame carries, a false match costs one trial open.
pub const SLOT_TAG_LEN: usize = 8;

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

    /// `Poseidon(CRRT, secret)`, the published output of the secret that also keys the body.
    pub fn recipient_tag(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[&domain::field(domain::RECIPIENT_TAG), &self.0])
    }

    /// `Poseidon(CRST, secret)` under the secret at index `m`.
    pub fn sender_tag(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[&domain::field(domain::SENDER_TAG), &self.0])
    }

    /// An anonymous payment's tag, fresh per transaction and slot, since a tag stable per
    /// recipient would link every payment to one recipient in public.
    pub fn anonymous_slot_tag(&self) -> Result<[u8; 32], HasherError> {
        self.recipient_tag().map(slot_tag)
    }
}

/// A confidential output's tag, stable per recipient key, since the confidential rail hides
/// amounts and leaves the recipient linkable to anyone who holds its address.
pub fn confidential_slot_tag(viewing_u: [u8; 32]) -> [u8; 32] {
    slot_tag(viewing_u)
}

/// A ring slot's tag reaches the indexer alone, its leading bytes stay zero and off the frame.
pub fn slot_tag(tag: [u8; 32]) -> [u8; 32] {
    unframed_slot_tag(&framed_slot_tag(&tag))
}

pub fn framed_slot_tag(tag: &[u8; 32]) -> [u8; SLOT_TAG_LEN] {
    let mut framed = [0; SLOT_TAG_LEN];
    framed.copy_from_slice(&tag[32 - SLOT_TAG_LEN..]);
    framed
}

pub fn unframed_slot_tag(framed: &[u8; SLOT_TAG_LEN]) -> [u8; 32] {
    let mut tag = [0; 32];
    tag[32 - SLOT_TAG_LEN..].copy_from_slice(framed);
    tag
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
    fn the_tags_of_one_secret_differ_by_domain() {
        let secret = SlotSecret::new(right_align(&[9])).unwrap();
        let recipient = secret.recipient_tag().unwrap();
        assert_eq!(
            recipient,
            Poseidon::hashv(&[&right_align(b"CRRT"), secret.as_bytes()]).unwrap()
        );
        assert_eq!(
            secret.sender_tag().unwrap(),
            Poseidon::hashv(&[&right_align(b"CRST"), secret.as_bytes()]).unwrap()
        );
        assert_ne!(recipient, secret.sender_tag().unwrap());
        assert!(is_canonical_bn254_scalar_be(&recipient));
    }

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
