use solana_address::Address;
use spr_keypair::{shielded::ShieldedKeypair, ViewingKey};

use crate::{RingKeyError, RotatingRingKeys};

/// Above the field modulus, so no merge of a real nullifier derives a salt.
pub const LIST_SALT_LABEL: [u8; 32] = *b"CRING/list_salt\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// No root the auditor holds reaches another ring's salt.
pub trait ListSaltHolder {
    fn list_salt(&self, ring_program_id: &Address) -> Result<[u8; 32], RingKeyError>;
}

impl ListSaltHolder for ShieldedKeypair {
    fn list_salt(&self, ring_program_id: &Address) -> Result<[u8; 32], RingKeyError> {
        derive(&self.viewing_key, ring_program_id)
    }
}

impl ListSaltHolder for RotatingRingKeys {
    fn list_salt(&self, ring_program_id: &Address) -> Result<[u8; 32], RingKeyError> {
        derive(self.list_root(), ring_program_id)
    }
}

fn derive(root: &ViewingKey, ring_program_id: &Address) -> Result<[u8; 32], RingKeyError> {
    root.merge_seed(ring_program_id.as_array(), &LIST_SALT_LABEL)
        .map_err(|_| RingKeyError::InvalidListSalt)
}
