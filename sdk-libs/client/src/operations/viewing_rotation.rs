//! The local half of a viewing key rotation, `custom_ring_sdk::RotateViewingKey` publishes it.

use spr_keypair::ViewingKey;
use thiserror::Error;
use zolana_ring_keys::{RingKeyError, RotatingRingKeys};

use crate::{AnonymousError, ViewingHistory};

/// [`Self::rotate`] moves both to one current key.
#[must_use]
pub struct ViewingRotation {
    pub keys: RotatingRingKeys,
    pub history: ViewingHistory,
}

#[derive(Debug, Error)]
pub enum ViewingRotationError {
    #[error(transparent)]
    Keys(#[from] RingKeyError),
    #[error(transparent)]
    History(#[from] AnonymousError),
}

impl ViewingRotation {
    /// `next` becomes current in both, every earlier key stays held and scanned.
    pub fn rotate(self, next: ViewingKey, rotated_at: i64) -> Result<Self, ViewingRotationError> {
        let history = self.history.with_rotated_key(next.pubkey(), rotated_at)?;
        let keys = self.keys.rotate(next)?;
        Ok(Self { keys, history })
    }
}

#[cfg(test)]
mod tests {
    use spr_keypair::{shielded::ShieldedKeypair, SigningKey, X25519Pubkey};
    use spr_transaction::{DecryptLabel, DecryptRequest, ShieldedKeys, TransactionError};

    use super::*;

    fn identity(seed: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
    }

    fn rotation(identity: &ShieldedKeypair) -> ViewingRotation {
        ViewingRotation {
            keys: RotatingRingKeys::new(identity).unwrap(),
            history: ViewingHistory::new(identity.viewing_pubkey(), 0),
        }
    }

    fn sealed_note(tx: &ViewingKey, recipient: &X25519Pubkey) -> Vec<u8> {
        tx.encrypt_slot(recipient, b"old note", [5; 16], 0).unwrap()
    }

    fn open<K: ShieldedKeys>(
        keys: &K,
        tx: &ViewingKey,
        recipient: X25519Pubkey,
        ciphertext: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransactionError> {
        keys.decrypt(&[DecryptRequest {
            ciphertext,
            viewing_pubkey: recipient,
            tx_viewing_pubkey: tx.pubkey(),
            salt: [5; 16],
            slot_index: 0,
            label: DecryptLabel::Utxo,
        }])
    }

    #[test]
    fn a_note_sealed_to_the_old_key_opens_only_with_the_retained_key() {
        let identity = identity(2);
        let next = ViewingKey::new();
        let rotated = rotation(&identity).rotate(next.clone(), 1).unwrap();
        let (tx, old) = (ViewingKey::new(), identity.viewing_pubkey());
        let ciphertext = sealed_note(&tx, &old);
        let opened = open(&rotated.keys, &tx, old, &ciphertext).unwrap();
        assert_eq!(opened, [b"old note".to_vec()]);
        let mut current_only = identity.clone();
        current_only.viewing_key = next;
        let forgotten = RotatingRingKeys::new(&current_only).unwrap();
        assert!(open(&forgotten, &tx, old, &ciphertext).is_err());
    }
}
