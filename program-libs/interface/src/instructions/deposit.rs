use spr_hasher::{
    hash_chain::create_hash_chain_from_slice,
    primitives::{hash_bytes, pack_be, right_align, PACK_BE_CHUNK_BYTES},
    HasherError,
};

use crate::{
    deposit_audit::{MAX_RING_DEPOSIT_AUDIT_SLOTS, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN},
    TAGGED_X25519_KEY_LEN,
};

pub struct DepositContext<'a> {
    pub program_id: &'a [u8; 32],
    pub tree: &'a [u8; 32],
    pub spp_data: &'a [u8],
}

impl DepositContext<'_> {
    /// The length separates byte strings whose 31-byte chunks pack to equal fields.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let chunks: Vec<_> = self
            .spp_data
            .chunks(PACK_BE_CHUNK_BYTES)
            .map(|chunk| {
                let mut field = [0; 32];
                field[32 - chunk.len()..].copy_from_slice(chunk);
                field
            })
            .collect();
        create_hash_chain_from_slice(&[
            hash_bytes(self.program_id)?,
            hash_bytes(self.tree)?,
            right_align(&(self.spp_data.len() as u64).to_be_bytes()),
            create_hash_chain_from_slice(&chunks)?,
        ])
    }
}

/// `asset` is SPP's asset field of the entry's group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositedAsset {
    pub asset: [u8; 32],
    pub amount: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositRegistry<'a> {
    pub own_root: &'a [u8; 32],
    /// Every deposited owner's record escrows the deposited nullifier key.
    pub key_escrow: bool,
    /// Its table's asset rules screen every deposited asset, `None` before the first policy write.
    pub policy_hash: Option<&'a [u8; 32]>,
}

pub struct DepositPublicInput<'a> {
    pub context_hash: &'a [u8; 32],
    /// Binds the proof to the ring's on-chain owner admission rule.
    pub anonymous: bool,
    pub owner_utxo_hashes: &'a [[u8; 32]],
    pub ciphertexts: &'a [[u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]],
    pub assets: &'a [DepositedAsset],
    pub auditor_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    /// `None` off an escrow or policy ring.
    pub registry: Option<DepositRegistry<'a>>,
}

/// Every deposit slot padded to the maximum.
pub const DEPOSIT_PUBLIC_INPUT_ELEMENTS: usize = 4 + MAX_RING_DEPOSIT_AUDIT_SLOTS * 4 + 7;

impl DepositPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_from_slice(&self.elements()?)
    }

    pub fn elements(&self) -> Result<[[u8; 32]; DEPOSIT_PUBLIC_INPUT_ELEMENTS], HasherError> {
        let count = self.owner_utxo_hashes.len();
        if !(1..=MAX_RING_DEPOSIT_AUDIT_SLOTS).contains(&count)
            || self.ciphertexts.len() != count
            || self.assets.len() != count
        {
            return Err(HasherError::InvalidNumFields);
        }
        let [auditor_lo, auditor_hi] = pack_be(self.auditor_pk);
        let [ephemeral_lo, ephemeral_hi] = pack_be(self.eph_pk);
        let mut chain = [[0; 32]; DEPOSIT_PUBLIC_INPUT_ELEMENTS];
        chain[0] = crate::domain::field(crate::domain::DEPOSIT_STATEMENT);
        chain[1] = *self.context_hash;
        chain[2] = right_align(&(count as u64).to_be_bytes());
        chain[3] = right_align(&[u8::from(self.anonymous)]);
        for (slot, (owner, ciphertext)) in self
            .owner_utxo_hashes
            .iter()
            .zip(self.ciphertexts)
            .enumerate()
        {
            chain[4 + slot * 2] = *owner;
            chain[5 + slot * 2] = hash_bytes(ciphertext)?;
        }
        let keys = 4 + MAX_RING_DEPOSIT_AUDIT_SLOTS * 2;
        chain[keys..keys + 4].copy_from_slice(&[
            auditor_lo,
            auditor_hi,
            ephemeral_lo,
            ephemeral_hi,
        ]);
        let registry = self.registry.as_ref();
        chain[keys + 4] = right_align(&[u8::from(
            registry.is_some_and(|registry| registry.key_escrow),
        )]);
        chain[keys + 5] = registry.map_or([0; 32], |registry| *registry.own_root);
        chain[keys + 6] = registry
            .and_then(|registry| registry.policy_hash)
            .copied()
            .unwrap_or_default();
        let assets = keys + 7;
        for (slot, deposited) in self.assets.iter().enumerate() {
            chain[assets + slot * 2] = deposited.asset;
            chain[assets + slot * 2 + 1] = right_align(&deposited.amount.to_be_bytes());
        }
        Ok(chain)
    }
}
