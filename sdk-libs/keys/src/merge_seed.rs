use solana_address::Address;
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_keypair::{shielded::ShieldedKeypair, X25519Pubkey};
use spr_transaction::instructions::merge::MergeSeed;

use crate::{keys::HeldKeys, RingKeyError, RotatingRingKeys};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeSeedRequest {
    pub viewing_pubkey: X25519Pubkey,
    pub ring_program_id: Address,
    pub first_nullifier: [u8; 32],
}

/// No viewing key leaves the holder.
pub trait MergeSeedHolder {
    fn merge_seeds(&self, requests: &[MergeSeedRequest]) -> Result<Vec<MergeSeed>, RingKeyError>;
}

impl MergeSeedHolder for ShieldedKeypair {
    fn merge_seeds(&self, requests: &[MergeSeedRequest]) -> Result<Vec<MergeSeed>, RingKeyError> {
        held_seeds(self, requests)
    }
}

impl MergeSeedHolder for RotatingRingKeys {
    fn merge_seeds(&self, requests: &[MergeSeedRequest]) -> Result<Vec<MergeSeed>, RingKeyError> {
        held_seeds(self, requests)
    }
}

fn held_seeds<H: HeldKeys>(
    holder: &H,
    requests: &[MergeSeedRequest],
) -> Result<Vec<MergeSeed>, RingKeyError> {
    requests
        .iter()
        .map(|request| {
            // A real nullifier is canonical, the list salt's label is not.
            if !is_canonical_bn254_scalar_be(&request.first_nullifier) {
                return Err(RingKeyError::InvalidMergeSeed);
            }
            MergeSeed::derive(
                holder.held(&request.viewing_pubkey)?,
                &request.ring_program_id,
                &request.first_nullifier,
            )
            .map_err(|_| RingKeyError::InvalidMergeSeed)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use spr_keypair::{SigningKey, ViewingKey};

    use super::*;

    const RING: Address = Address::new_from_array([4; 32]);
    const FIRST: [u8; 32] = [8; 32];

    fn wallet(byte: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[byte; 32])).unwrap()
    }

    fn seed(holder: &impl MergeSeedHolder, viewing_pubkey: X25519Pubkey) -> [u8; 32] {
        let answers = holder
            .merge_seeds(&[MergeSeedRequest {
                viewing_pubkey,
                ring_program_id: RING,
                first_nullifier: FIRST,
            }])
            .unwrap();
        *answers[0].as_bytes()
    }

    #[test]
    fn a_rotated_holder_derives_under_each_key_and_refuses_another() {
        let owner = wallet(3);
        let first_key = owner.viewing_key.pubkey();
        let next = ViewingKey::new();
        let next_key = next.pubkey();
        let rotated = RotatingRingKeys::new(&owner).unwrap().rotate(next).unwrap();
        assert_eq!(seed(&rotated, first_key), seed(&owner, first_key));
        assert_ne!(seed(&rotated, next_key), seed(&rotated, first_key));
        let refused = rotated.merge_seeds(&[MergeSeedRequest {
            viewing_pubkey: ViewingKey::new().pubkey(),
            ring_program_id: RING,
            first_nullifier: FIRST,
        }]);
        assert_eq!(refused.err(), Some(RingKeyError::UnknownViewingKey));
    }

    #[test]
    fn the_holder_answers_the_derivation_of_the_key_it_holds() {
        let owner = wallet(3);
        let key = &owner.viewing_key;
        let expected = MergeSeed::derive(key, &RING, &FIRST).unwrap();
        assert_eq!(seed(&owner, key.pubkey()), *expected.as_bytes());
    }
}
