//! The keys a record sits under, an owner's lookup key, a mint's asset field and a wallet's reader grant.
//!
//! An owner's lists sit under `Poseidon(CRPL, owner, salt)`, salt zero for its public record and its
//! enrolled salt for its private one. A salted key names its owner only to a holder of the salt, so a
//! private list entry shows no wallet in public. The registration circuit refuses a zero salt, so no
//! private record shares the public key.
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

/// `"CRPL"`, keys an owner's records, mirror `shared.ListKeyDomain`.
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
    #[error("a zero list salt names the public key")]
    ZeroSalt,
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

    /// The key of the owner's public lists, anyone who knows the owner derives it.
    pub fn public(owner: &Self) -> Result<Self, MemberError> {
        Self::lookup(owner, &[0; 32])
    }

    /// Pseudorandom to anyone without the salt.
    pub fn salted(owner: &Self, list_salt: &[u8; 32]) -> Result<Self, MemberError> {
        if *list_salt == [0; 32] {
            return Err(MemberError::ZeroSalt);
        }
        Self::lookup(owner, list_salt)
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

    fn lookup(owner: &Self, list_salt: &[u8; 32]) -> Result<Self, MemberError> {
        let key = Poseidon::hashv(&[
            &right_align(&LIST_KEY_DOMAIN.to_be_bytes()),
            &owner.0,
            list_salt,
        ])
        .map_err(|_| MemberError::Hashing)?;
        Self::from_bytes(key)
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
    fn a_public_key_matches_the_circuit_derivation() {
        let owner = Member::from_bytes(right_align(&[7])).unwrap();
        assert_eq!(
            hex::encode(Member::public(&owner).unwrap().as_bytes()),
            "18eb3f0cf43fb318e0ab77c3d2fc13af04d5ef7fa7afd1f47909f087ff748fe3"
        );
    }

    #[test]
    fn a_zero_salt_is_refused_and_the_public_key_differs_from_the_identity() {
        let owner = Member::from_bytes(right_align(&[7])).unwrap();
        assert_eq!(Member::salted(&owner, &[0; 32]), Err(MemberError::ZeroSalt));
        assert_ne!(Member::public(&owner).unwrap(), owner);
        assert_ne!(
            Member::public(&owner).unwrap(),
            Member::salted(&owner, &right_align(&[9])).unwrap()
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
