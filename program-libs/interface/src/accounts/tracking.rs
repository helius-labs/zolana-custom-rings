//! The tracking registry, one sorted tree per ring naming each enrolled owner's nullifier key, ciphertext hash and list tag.
//!
//! An SPP sender names any nullifier key on an output, and SPP never sees the secret behind it. A
//! ring's auditor must compute each nullifier, so each owner enrolls once with a proof that seals the
//! nullifier secret and the list salt to the auditor key. Every transfer, deposit and merge proof then
//! holds a live ring slot's key, other than `ZERO_NULLIFIER_PUBKEY`, to its owner's row under the tracking
//! root, and a transfer or deposit output under that key to an absent row. Without the row a sender could
//! pay a key the auditor cannot open, and a wallet could skip its salted lists.
//!
//! A ring pins its tracking registry's address, `ring_id` and the seeds authenticate nothing.
//!
//! Read after `docs/design/records-and-roots.md`, `program-libs/interface/src/accounts/storage.rs`.
//! Read before `programs/storage/src/instructions/enroll.rs`, `programs/storage/src/instructions/apply_enrollments.rs`,
//! `prover/circuits/registry/tracking.go`, `prover/circuits/policy/tracking.go`.
//!
//! Invariants:
//! 1. An authorization's nullifier key, list tag, ephemeral key and ciphertext never move after creation, `rotate` refuses a change. A row holds the owner, the nullifier key, the list tag and the ciphertext hash, so only its successor link moves after insert and an owner holds one row.
//! 2. Enrollment refuses `ZERO_NULLIFIER_PUBKEY` and proves every key a Poseidon output, so a present row's key is nonzero, and the policy circuit reads presence from the literal zero an absent query returns.
//! 3. A pending authorization grants nothing, because every check reads the root. Only a first enrollment is pending, and each applies once.
//! 4. The viewing key lives only on the authorization. A rotation writes that account alone, so it moves no root and leaves no tracking work. A sender authenticates the key from the account, no proof reads it.
//! 5. A retired tracking root serves its whole grace, an apply that would evict an unexpired root refuses and its accounts stay pending. A source's `tracking_floor` is the one exception, and only on a salted read.

use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use spr_hasher::{
    hash_chain::create_hash_chain_4_from_slice,
    primitives::{
        hash_bytes, is_canonical_bn254_scalar_be, is_canonical_x25519_public_key, right_align,
        solana_owner_identity,
    },
    Hasher, HasherError, Poseidon,
};
pub use spr_interface::ZERO_NULLIFIER_PUBKEY;
use zolana_ring_policy::registry_field;

use crate::{
    auditor_key::is_auditor_key,
    domain,
    member_registry::GRACE_SLOTS,
    state::ROOT_HISTORY,
    storage::{advance_roots, root_at, Retirement, Revision, Root, StorageError},
    storage_instruction::{EnrollIxData, InitializeTrackingIxData},
    REGISTER_KEY_CIPHERTEXT_LEN, STORAGE_PROGRAM_ID, TAGGED_X25519_KEY_LEN,
};

/// Taller than a policy tree, anyone can pay to fill it and no tree replaces a full one.
pub const TRACKING_QUAD_HEIGHT: usize = 16;
pub const TRACKING_CAPACITY: u64 = 1 << (2 * TRACKING_QUAD_HEIGHT);
/// Fixed by the program, every retired tracking root serves it in full.
pub const TRACKING_GRACE_SLOTS: u64 = GRACE_SLOTS;

/// Root of the tree holding only the sentinel.
pub const TRACKING_EMPTY_ROOT: [u8; 32] = [
    0x24, 0x25, 0xfb, 0x18, 0x96, 0x30, 0xd5, 0xf8, 0x4b, 0xcc, 0x34, 0xf4, 0x28, 0x04, 0x37, 0x7d,
    0x85, 0x64, 0xa5, 0x59, 0x59, 0xc9, 0x2a, 0xd1, 0xfa, 0x6f, 0xee, 0x86, 0xa5, 0x90, 0x61, 0x4e,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct TrackingRegistry {
    pub discriminator: u8,
    /// Immutable, enrollment proofs bind it.
    pub ring_id: [u8; 32],
    /// Immutable, enrollment proofs seal to it.
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
    /// Little endian, the leaf the next new owner takes, at most `TRACKING_CAPACITY`.
    pub next_index: [u8; 8],
    /// Newest first, only retired roots have an expiry.
    pub roots: [Root; ROOT_HISTORY],
}

/// One owner's enrollment, retained so an auditor recovers every secret from accounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct TrackingAuthorization {
    pub discriminator: u8,
    pub registry: Address,
    pub owner: Address,
    /// Final after creation, with `list_tag` and the ciphertext.
    pub nullifier_pk: [u8; 32],
    /// `Poseidon(CRPT, list_salt)`, a policy proof opens the owner's salted key through it.
    pub list_tag: [u8; 32],
    /// Moves at each rotation, no leaf or proof reads it.
    pub viewing_u: [u8; 32],
    pub eph_u: [u8; 32],
    /// The nullifier secret and the list salt sealed to the registry's auditor key.
    pub ciphertext: [u8; REGISTER_KEY_CIPHERTEXT_LEN],
    /// Zero until an apply inserts the owner's row, one after.
    pub applied: u8,
}

/// The write an apply proof chains, computed from the owner's account and never from data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackingEntry {
    pub member: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub ct_hash: [u8; 32],
    pub list_tag: [u8; 32],
}

/// The account state of a first enrollment, nothing applied.
#[must_use]
pub struct FirstEnrollment<'a> {
    pub registry: Address,
    pub owner: Address,
    pub ix: &'a EnrollIxData,
}

/// A proven application of pending authorizations.
#[must_use]
pub struct TrackingRootUpdate {
    /// The revision the proof was made against.
    pub revision: Revision,
    pub slot: u64,
    pub new_root: [u8; 32],
    pub new_next_index: u64,
}

impl TrackingRegistry {
    pub const DISCRIMINATOR: u8 = 3;
    pub const SEED: &'static [u8] = b"tracking_registry";
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// The creator in the seeds keeps every other signer off its addresses.
    pub fn seeds<'a>(creator: &'a Address, ring_id: &'a [u8; 32]) -> [&'a [u8]; 3] {
        [Self::SEED, creator.as_ref(), ring_id]
    }

    pub fn find_address(creator: &Address, ring_id: &[u8; 32]) -> (Address, u8) {
        Address::find_program_address(&Self::seeds(creator, ring_id), &STORAGE_PROGRAM_ID)
    }

    /// Holds only the sentinel root at revision zero.
    pub fn new(ix: &InitializeTrackingIxData) -> Self {
        let mut registry = Self::zeroed();
        registry.discriminator = Self::DISCRIMINATOR;
        registry.ring_id = ix.ring_id;
        registry.auditor_pubkey = ix.auditor_pubkey;
        registry.next_index = 1u64.to_le_bytes();
        registry.roots[0].hash = TRACKING_EMPTY_ROOT;
        registry
    }

    pub fn from_data(data: &[u8]) -> Option<&Self> {
        bytemuck::try_from_bytes::<Self>(data)
            .ok()
            .filter(|registry| registry.valid())
    }

    pub fn from_data_mut(data: &mut [u8]) -> Option<&mut Self> {
        bytemuck::try_from_bytes_mut::<Self>(data)
            .ok()
            .filter(|registry| registry.valid())
    }

    pub fn decode(owner: &Address, data: &[u8]) -> Option<Self> {
        (*owner == STORAGE_PROGRAM_ID)
            .then(|| Self::from_data(data).copied())
            .flatten()
    }

    pub const fn next_index(&self) -> u64 {
        u64::from_le_bytes(self.next_index)
    }

    pub const fn newest(&self) -> Root {
        self.roots[0]
    }

    pub fn root(&self, revision: Revision, slot: u64) -> Result<[u8; 32], StorageError> {
        root_at(&self.roots, revision, slot)
    }

    /// Writes nothing on a refusal, a retired root stays served for its whole grace.
    pub fn update(&mut self, update: TrackingRootUpdate) -> Result<(), StorageError> {
        // The circuit opens no leaf past the capacity, a larger index would name a leaf no path reaches.
        if !(1..=TRACKING_CAPACITY).contains(&update.new_next_index) {
            return Err(StorageError::TrackingTreeFull);
        }
        advance_roots(
            &mut self.roots,
            update.revision,
            Retirement::Retained {
                slot: update.slot,
                grace_slots: TRACKING_GRACE_SLOTS,
            },
            update.new_root,
        )?;
        self.next_index = update.new_next_index.to_le_bytes();
        Ok(())
    }

    fn valid(&self) -> bool {
        self.discriminator == Self::DISCRIMINATOR
            && (1..=TRACKING_CAPACITY).contains(&self.next_index())
    }
}

impl TrackingAuthorization {
    pub const DISCRIMINATOR: u8 = 4;
    pub const SEED: &'static [u8] = b"tracking";
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// One enrollment per owner per registry.
    pub fn seeds<'a>(registry: &'a Address, owner: &'a Address) -> [&'a [u8]; 3] {
        [Self::SEED, registry.as_ref(), owner.as_ref()]
    }

    pub fn find_address(registry: &Address, owner: &Address) -> (Address, u8) {
        Address::find_program_address(&Self::seeds(registry, owner), &STORAGE_PROGRAM_ID)
    }

    pub fn from_data(data: &[u8]) -> Option<&Self> {
        bytemuck::try_from_bytes::<Self>(data)
            .ok()
            .filter(|account| account.discriminator == Self::DISCRIMINATOR)
    }

    pub fn from_data_mut(data: &mut [u8]) -> Option<&mut Self> {
        bytemuck::try_from_bytes_mut::<Self>(data)
            .ok()
            .filter(|account| account.discriminator == Self::DISCRIMINATOR)
    }

    pub fn decode(owner: &Address, data: &[u8]) -> Option<Self> {
        (*owner == STORAGE_PROGRAM_ID)
            .then(|| Self::from_data(data).copied())
            .flatten()
    }

    /// Its row has not reached a root yet.
    pub const fn is_pending(&self) -> bool {
        self.applied == 0
    }

    /// Writes nothing on a refusal, the owner's signature alone authorizes it so no sealed field
    /// moves.
    pub fn rotate(&mut self, ix: &EnrollIxData) -> Result<(), StorageError> {
        if ix.nullifier_pk != self.nullifier_pk
            || ix.list_tag != self.list_tag
            || ix.eph_u != self.eph_u
            || ix.ciphertext != self.ciphertext
        {
            return Err(StorageError::EnrollmentKeyFinal);
        }
        self.viewing_u = ix.viewing_u;
        Ok(())
    }

    pub fn entry(&self) -> Result<TrackingEntry, StorageError> {
        Ok(TrackingEntry {
            member: owner_member(&self.owner)?,
            nullifier_pk: self.nullifier_pk,
            ct_hash: hash_bytes(&self.ciphertext).map_err(|_| StorageError::HashingFailed)?,
            list_tag: self.list_tag,
        })
    }

    /// The entry the apply proof chains, an applied account refused so one owner never chains twice.
    pub fn apply(&mut self) -> Result<TrackingEntry, StorageError> {
        if !self.is_pending() {
            return Err(StorageError::EnrollmentAlreadyApplied);
        }
        let entry = self.entry()?;
        self.applied = 1;
        Ok(entry)
    }
}

impl FirstEnrollment<'_> {
    pub fn account(self) -> TrackingAuthorization {
        TrackingAuthorization {
            discriminator: TrackingAuthorization::DISCRIMINATOR,
            registry: self.registry,
            owner: self.owner,
            nullifier_pk: self.ix.nullifier_pk,
            list_tag: self.ix.list_tag,
            viewing_u: self.ix.viewing_u,
            eph_u: self.ix.eph_u,
            ciphertext: self.ix.ciphertext,
            applied: 0,
        }
    }
}

impl TrackingEntry {
    /// `Poseidon(CRTQ, member, nullifier_pk, ct_hash, list_tag)`, mirror
    /// `prover/circuits/registry/apply_enrollments.go`.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &domain::field(domain::TRACKING_ENTRY),
            &self.member,
            &self.nullifier_pk,
            &self.ct_hash,
            &self.list_tag,
        ])
    }

    /// `Poseidon(previous, entry)`.
    pub fn chained(&self, previous: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[previous, &self.hash()?])
    }
}

impl InitializeTrackingIxData {
    /// A key no proof can seal to would lock enrollment for good.
    pub fn check(&self) -> Result<(), StorageError> {
        if self.ring_id == [0; 32] || !is_canonical_bn254_scalar_be(&self.ring_id) {
            return Err(StorageError::InvalidTrackingRegistry);
        }
        if !is_auditor_key(&self.auditor_pubkey) {
            return Err(StorageError::InvalidAuditorKey);
        }
        Ok(())
    }
}

impl EnrollIxData {
    /// A zero key has no secret to seal, a program owner stays unenrolled instead.
    pub fn check(&self) -> Result<(), StorageError> {
        if self.viewing_u == [0; 32] || !is_canonical_x25519_public_key(&self.viewing_u) {
            return Err(StorageError::NonCanonicalViewingKey);
        }
        if self.nullifier_pk == ZERO_NULLIFIER_PUBKEY {
            return Err(StorageError::ZeroNullifierKey);
        }
        if !is_canonical_bn254_scalar_be(&self.nullifier_pk)
            || !is_canonical_bn254_scalar_be(&self.list_tag)
        {
            return Err(StorageError::InvalidInstructionData);
        }
        Ok(())
    }
}

/// The leaf member of a signer, a wallet or a PDA alike.
pub fn owner_member(owner: &Address) -> Result<[u8; 32], StorageError> {
    solana_owner_identity(owner.as_array()).map_err(|_| StorageError::HashingFailed)
}

/// `[CRTA, registry, revision]`, an apply proof serves one registry at one revision.
pub fn tracking_chain_start(
    registry: &Address,
    revision: Revision,
) -> Result<[u8; 32], StorageError> {
    let registry = registry_field(registry.as_array()).map_err(|_| StorageError::HashingFailed)?;
    create_hash_chain_4_from_slice(&[
        domain::field(domain::APPLY_ENROLLMENTS),
        registry,
        right_align(&revision.value().to_be_bytes()),
    ])
    .map_err(|_| StorageError::HashingFailed)
}

// Byte fields only, the `Pod` image is the account data with no padding.
const _: () = assert!(core::mem::align_of::<TrackingRegistry>() == 1);
const _: () = assert!(TrackingRegistry::SIZE == 1610);
const _: () = assert!(core::mem::align_of::<TrackingAuthorization>() == 1);
const _: () = assert!(TrackingAuthorization::SIZE == 258);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_root_folds_the_sentinel_through_every_level() {
        let mut node = Poseidon::hashv(&[
            &domain::field(domain::TRACKING_LEAF),
            &[0; 32],
            &crate::FIELD_MAX,
            &[0; 32],
            &[0; 32],
            &[0; 32],
        ])
        .unwrap();
        let mut zero = [0u8; 32];
        for _ in 0..TRACKING_QUAD_HEIGHT {
            node = Poseidon::hashv(&[&node, &zero, &zero, &zero]).unwrap();
            zero = Poseidon::hashv(&[&zero, &zero, &zero, &zero]).unwrap();
        }
        assert_eq!(node, TRACKING_EMPTY_ROOT);
    }
}
