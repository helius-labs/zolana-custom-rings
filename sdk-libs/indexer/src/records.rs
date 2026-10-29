use custom_ring_interface::QueueEntry;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueuedWrite {
    pub entry: QueueEntry,
    pub seal: Option<SealedKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKey {
    /// The escrow write's owner, its owner identity is the record's member.
    pub owner_pubkey: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub eph_u: [u8; 32],
    pub ciphertext: [u8; 32],
}
