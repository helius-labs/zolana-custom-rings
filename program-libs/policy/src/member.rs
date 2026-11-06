//! The keys a record sits under, an owner's identity, a mint's asset field, a wallet's reader grant and an owner's salted key.
//!
//! A salted key names its owner only to a holder of the salt, so a private list entry shows no wallet in public.
//!
//! Read after `program-libs/policy/src/list.rs`. Read before `program-libs/policy/src/mint.rs`.

use solana_address::Address;
use spr_hasher::{
    primitives::{hash_bytes, right_align, solana_owner_identity},
    Hasher, Poseidon,
};
use thiserror::Error;

/// `"CRWG"`, keys the record holding a wallet's grants to one reader.
pub const WALLET_GRANT_DOMAIN: u32 = 0x4352_5747;

/// `"CRPL"`, keys an owner's salted record, mirror `shared.ListKeyDomain`.
pub const LIST_KEY_DOMAIN: u32 = 0x4352_504c;

/// A list subject, the field element the transfer openings carry for it, never zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member([u8; 32]);

/// A tag fails to derive a usable member.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MemberError {
    #[error("hashing failed")]
    Hashing,
    #[error("member derives to zero")]
    Zero,
}

impl Member {
    /// The tagged identity SPP derives for a Solana owner.
    pub fn owner_tag(tag: &[u8; 32]) -> Result<Self, MemberError> {
        let identity = solana_owner_identity(tag).map_err(|_| MemberError::Hashing)?;
        Self::from_bytes(identity)
    }

    /// The mint, encoded exactly as the `Asset` field of the UTXO hash.
    pub fn asset(mint: &Address) -> Result<Self, MemberError> {
        Self::from_hash_bytes(mint.as_array())
    }

    /// `Poseidon(CRWG, wallet, reader)`, its `Reader` list is the wallet's grant to `reader`.
    pub fn wallet_grant(wallet: &Self, reader: &Self) -> Result<Self, MemberError> {
        let key = Poseidon::hashv(&[
            &right_align(&WALLET_GRANT_DOMAIN.to_be_bytes()),
            &wallet.0,
            &reader.0,
        ])
        .map_err(|_| MemberError::Hashing)?;
        Self::from_bytes(key)
    }

    /// Pseudorandom to anyone without the salt.
    pub fn salted(owner: &Self, list_salt: &[u8; 32]) -> Result<Self, MemberError> {
        let key = Poseidon::hashv(&[
            &right_align(&LIST_KEY_DOMAIN.to_be_bytes()),
            &owner.0,
            list_salt,
        ])
        .map_err(|_| MemberError::Hashing)?;
        Self::from_bytes(key)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Only the zero pad is rejected, a non-canonical value fails its own
    /// membership proof closed.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, MemberError> {
        if bytes == [0u8; 32] {
            return Err(MemberError::Zero);
        }
        Ok(Self(bytes))
    }

    fn from_hash_bytes(bytes: &[u8; 32]) -> Result<Self, MemberError> {
        let field = hash_bytes(bytes).map_err(|_| MemberError::Hashing)?;
        if field == [0u8; 32] {
            return Err(MemberError::Zero);
        }
        Ok(Self(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_salted_key_matches_the_circuit_derivation() {
        let owner = Member::from_bytes(right_align(&[7])).unwrap();
        let key = Member::salted(&owner, &right_align(&[9])).unwrap();
        assert_eq!(
            hex::encode(key.as_bytes()),
            "0cd39067a2c6eff923c63afab8a8d09543bdcc320bcb82dfd063b7da2826d248"
        );
    }

    #[test]
    fn member_matches_the_owner_proof_input_derivation() {
        let tag = [7u8; 32];
        let member = Member::owner_tag(&tag).unwrap();
        assert_eq!(member.as_bytes(), &solana_owner_identity(&tag).unwrap());
        assert_eq!(Member::from_bytes(*member.as_bytes()).unwrap(), member);
    }

    #[test]
    fn an_asset_and_an_owner_with_equal_bytes_are_different_members() {
        let address = Address::new_from_array([9u8; 32]);
        assert_eq!(
            Member::asset(&address).unwrap().as_bytes(),
            &hash_bytes(&[9u8; 32]).unwrap()
        );
        assert_ne!(
            Member::asset(&address).unwrap(),
            Member::owner_tag(&[9u8; 32]).unwrap()
        );
    }
}
