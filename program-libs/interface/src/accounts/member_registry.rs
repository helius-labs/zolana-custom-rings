//! Record tree constants and the record writes an apply proof chains, the tree
//! lives in `zolana-ring-member-registry`.

use spr_hasher::{
    primitives::{hash_bytes, right_align, BN254_SCALAR_MODULUS_BE},
    Hasher, HasherError, Poseidon,
};
use zolana_ring_policy::{ListId, MintPolicy};

use crate::{domain, error::CustomRingError, AUDIT_CIPHERTEXT_LEN};

pub const QUAD_ARITY: usize = 4;
pub const QUAD_HEIGHT: usize = 10;
pub const MEMBER_REGISTRY_CAPACITY: u64 = 1 << (2 * QUAD_HEIGHT);
/// Writes the larger apply key proves.
pub const APPLY_BATCH: usize = 16;
/// Slots the ring's records keep an outgoing root readable.
pub const GRACE_SLOTS: u64 = 750;

/// `q - 1`, the sentinel's next, every member sorts strictly below it.
pub const FIELD_MAX: [u8; 32] = {
    let mut max = BN254_SCALAR_MODULUS_BE;
    max[31] -= 1;
    max
};

/// Root of the tree holding only the sentinel, the first history entry of a registry.
pub const MEMBER_REGISTRY_EMPTY_ROOT: [u8; 32] = [
    0x00, 0xc0, 0xb0, 0x7d, 0x78, 0x02, 0x4d, 0x98, 0x5b, 0x99, 0x5b, 0xd9, 0xdb, 0x52, 0x5f, 0x32,
    0x9d, 0x0b, 0xfb, 0x28, 0x5f, 0x75, 0xcc, 0x22, 0x2f, 0x90, 0x0d, 0x8f, 0x6f, 0xaf, 0x51, 0x30,
];

/// The sentinel `(0, q - 1)` brackets every member in `[1, q - 2]` strictly.
pub fn check_member(member: &[u8; 32]) -> Result<(), CustomRingError> {
    if *member == [0; 32] || *member >= FIELD_MAX {
        return Err(CustomRingError::MemberOutOfRange);
    }
    Ok(())
}

/// The record field a registered key sets, `Poseidon(nullifier_pk, hash_bytes(ciphertext))`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscrowKey<'a> {
    pub nullifier_pk: &'a [u8; 32],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
}

impl EscrowKey<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[self.nullifier_pk, &hash_bytes(self.ciphertext)?])
    }
}

/// One queued masked write, `lists' = (lists & !mask) | value`, the escrow key fills once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueEntry {
    pub member: [u8; 32],
    pub mask: u64,
    pub value: u64,
    pub escrow_key: [u8; 32],
    /// Only authority writes replace mint settings; list and key writes preserve them.
    pub mint_policy: Option<MintPolicy>,
}

impl QueueEntry {
    pub fn escrow(member: [u8; 32], key: &EscrowKey<'_>) -> Result<Self, CustomRingError> {
        Self::escrow_hash(member, key.hash()?)
    }

    /// `escrow_key` is the [`EscrowKey::hash`] of a key checked elsewhere.
    pub fn escrow_hash(member: [u8; 32], escrow_key: [u8; 32]) -> Result<Self, CustomRingError> {
        check_member(&member)?;
        let bit = ListId::Escrow.record_bit();
        Ok(Self {
            member,
            mask: bit,
            value: bit,
            escrow_key,
            mint_policy: None,
        })
    }

    /// `Poseidon(CRQW, member, mask, value, escrow_key, mint_policy_write, withdrawal_threshold, limits_0, limits_1, limits_2)`, mirror
    /// `prover/circuits/registry/apply_records.go`.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let policy = self.mint_policy.unwrap_or_default();
        let [limits_0, limits_1, limits_2] = policy.limits.fields();
        Poseidon::hashv(&[
            &domain::field(domain::QUEUE_WRITE),
            &self.member,
            &right_align(&self.mask.to_be_bytes()),
            &right_align(&self.value.to_be_bytes()),
            &self.escrow_key,
            &self.mint_policy_field(),
            &right_align(&policy.withdrawal_threshold.to_be_bytes()),
            &limits_0,
            &limits_1,
            &limits_2,
        ])
    }

    /// Bit 192 distinguishes a replacement (including clearing) from no change.
    pub fn mint_policy_field(&self) -> [u8; 32] {
        self.mint_policy.map_or([0; 32], |policy| {
            let mut field = policy.field();
            field[7] = 1;
            field
        })
    }
}

/// `chain(p) = Poseidon(chain(p - 1), entry_p)` from `chain(-1) = 0`.
pub fn queue_chain(previous: &[u8; 32], entry: &QueueEntry) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[previous, &entry.hash()?])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(byte: u8) -> [u8; 32] {
        right_align(&[byte])
    }

    #[test]
    fn members_lie_strictly_between_the_sentinel_bounds() {
        // `q - 2`, the modulus ends in `f0000001`.
        let mut below_max = FIELD_MAX;
        below_max[28] -= 1;
        below_max[29..].fill(0xff);
        assert_eq!(check_member(&member(1)), Ok(()));
        assert_eq!(check_member(&below_max), Ok(()));
        for outside in [[0; 32], FIELD_MAX, BN254_SCALAR_MODULUS_BE] {
            assert_eq!(
                check_member(&outside),
                Err(CustomRingError::MemberOutOfRange)
            );
        }
    }

    #[test]
    fn an_escrow_entry_sets_the_escrow_bit_and_the_key() {
        let key = EscrowKey {
            nullifier_pk: &member(4),
            ciphertext: &[5; AUDIT_CIPHERTEXT_LEN],
        };
        let entry = QueueEntry::escrow(member(3), &key).unwrap();
        let bit = ListId::Escrow.record_bit();
        assert_eq!(
            (entry.mask, entry.value, entry.escrow_key),
            (bit, bit, key.hash().unwrap())
        );
        assert_ne!(
            entry.hash(),
            QueueEntry {
                escrow_key: [0; 32],
                ..entry
            }
            .hash()
        );
    }
}
