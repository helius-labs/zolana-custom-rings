use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use solana_program_error::ProgramError;
use spr_hasher::{hash_chain::create_hash_chain_4_from_slice, primitives::right_align};
use thiserror::Error;
use zolana_ring_policy::registry_field;

use crate::{
    domain,
    member_registry::{MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_EMPTY_ROOT},
    state::ROOT_HISTORY,
    storage_instruction::{StorageUpdateIxData, UpdateMode},
    STORAGE_PROGRAM_ID,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct Revision(pub [u8; 8]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct Root {
    pub hash: [u8; 32],
    pub revision: Revision,
    pub expires_at: [u8; 8],
}

/// Names one of a creator's registries in its address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct RegistryId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct StorageRegistry {
    pub discriminator: u8,
    pub authority: Address,
    pub grace_slots: [u8; 8],
    pub next_index: [u8; 4],
    /// Newest first, only retired roots have an expiry.
    pub roots: [Root; ROOT_HISTORY],
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum StorageError {
    #[error("invalid registry")]
    InvalidRegistry = 9000,
    #[error("authority does not match")]
    Unauthorized = 9001,
    #[error("revision changed")]
    RevisionChanged = 9002,
    #[error("root expired or absent")]
    RootExpired = 9003,
    #[error("root history is full")]
    HistoryFull = 9004,
    #[error("instruction data is invalid")]
    InvalidInstructionData = 9005,
    #[error("update carries more writes than one apply proof takes")]
    BatchTooLarge = 9006,
    #[error("write is neither a record write nor an escrow write")]
    InvalidWrite = 9007,
    #[error("apply proof does not verify")]
    ProofVerificationFailed = 9008,
    #[error("hashing failed")]
    HashingFailed = 9009,
    #[error("accounts are missing")]
    MissingAccounts = 9010,
    #[error("required signer did not sign")]
    MissingSignature = 9011,
    #[error("registry account is not writable")]
    ReadOnlyRegistry = 9012,
    #[error("system program account is invalid")]
    InvalidSystemProgram = 9013,
    #[error("registry is already initialized")]
    AlreadyInitialized = 9014,
    #[error("revision overflows u64")]
    RevisionOverflow = 9015,
    #[error("no apply key serves the write count")]
    UnsupportedBatch = 9016,
}

#[must_use]
pub struct RootUpdate<'a> {
    pub mode: UpdateMode,
    pub slot: u64,
    pub data: &'a StorageUpdateIxData<'a>,
}

impl From<u64> for Revision {
    fn from(value: u64) -> Self {
        Self(value.to_le_bytes())
    }
}

impl Revision {
    pub const fn value(self) -> u64 {
        u64::from_le_bytes(self.0)
    }
}

impl Root {
    pub const fn expires_at(&self) -> u64 {
        u64::from_le_bytes(self.expires_at)
    }
}

impl StorageRegistry {
    /// Zero marks an uninitialized account.
    pub const DISCRIMINATOR: u8 = 1;
    pub const SEED: &'static [u8] = b"storage";
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// The creator in the seeds keeps every other signer off its addresses.
    pub fn seeds<'a>(creator: &'a Address, registry_id: &'a RegistryId) -> [&'a [u8]; 3] {
        [Self::SEED, creator.as_ref(), &registry_id.0]
    }

    pub fn find_address(creator: &Address, registry_id: &RegistryId) -> (Address, u8) {
        Address::find_program_address(&Self::seeds(creator, registry_id), &STORAGE_PROGRAM_ID)
    }

    /// Holds only the sentinel root at revision zero.
    pub fn new(authority: Address, grace_slots: u64) -> Self {
        let mut registry = Self::zeroed();
        registry.discriminator = Self::DISCRIMINATOR;
        registry.authority = authority;
        registry.grace_slots = grace_slots.to_le_bytes();
        registry.next_index = 1u32.to_le_bytes();
        registry.roots[0].hash = MEMBER_REGISTRY_EMPTY_ROOT;
        registry
    }

    pub fn from_data(data: &[u8]) -> Option<&Self> {
        bytemuck::try_from_bytes::<Self>(data)
            .ok()
            .filter(|registry| registry.valid())
    }

    pub fn decode(owner: &Address, data: &[u8]) -> Option<Self> {
        (*owner == STORAGE_PROGRAM_ID)
            .then(|| Self::from_data(data).copied())
            .flatten()
    }

    pub fn from_data_mut(data: &mut [u8]) -> Option<&mut Self> {
        bytemuck::try_from_bytes_mut::<Self>(data)
            .ok()
            .filter(|registry| registry.valid())
    }

    pub const fn grace_slots(&self) -> u64 {
        u64::from_le_bytes(self.grace_slots)
    }

    pub const fn next_index(&self) -> u32 {
        u32::from_le_bytes(self.next_index)
    }

    pub const fn newest(&self) -> Root {
        self.roots[0]
    }

    pub fn root(&self, revision: Revision, slot: u64) -> Result<[u8; 32], StorageError> {
        root_at(&self.roots, revision, slot)
    }

    /// Writes nothing on a refusal.
    pub fn update(&mut self, update: RootUpdate<'_>) -> Result<(), StorageError> {
        let RootUpdate { mode, slot, data } = update;
        if data.revision != self.roots[0].revision {
            return Err(StorageError::RevisionChanged);
        }
        let revision = data
            .revision
            .value()
            .checked_add(1)
            .ok_or(StorageError::RevisionOverflow)?;
        match mode {
            UpdateMode::Graced if slot < self.roots[ROOT_HISTORY - 1].expires_at() => {
                return Err(StorageError::HistoryFull);
            }
            UpdateMode::Graced => {
                // A saturated expiry never lapses.
                self.roots[0].expires_at = slot.saturating_add(self.grace_slots()).to_le_bytes();
                self.roots.rotate_right(1);
            }
            UpdateMode::Immediate => self.roots.fill(Root::zeroed()),
        }
        self.roots[0] = Root {
            hash: data.apply.new_root,
            revision: revision.into(),
            expires_at: [0; 8],
        };
        self.next_index = data.apply.new_next_index;
        Ok(())
    }

    fn valid(&self) -> bool {
        self.discriminator == Self::DISCRIMINATOR
            && (1..=MEMBER_REGISTRY_CAPACITY).contains(&u64::from(self.next_index()))
    }
}

/// `APPLY_RECORDS` binds the registry address and revision before the ordered writes.
pub fn chain_start(registry: &Address, revision: Revision) -> Result<[u8; 32], StorageError> {
    let registry = registry_field(registry.as_array()).map_err(|_| StorageError::HashingFailed)?;
    create_hash_chain_4_from_slice(&[
        domain::field(domain::APPLY_RECORDS),
        registry,
        right_align(&revision.value().to_be_bytes()),
    ])
    .map_err(|_| StorageError::HashingFailed)
}

/// The current root, or a retired one before its expiry.
fn root_at(
    roots: &[Root; ROOT_HISTORY],
    revision: Revision,
    slot: u64,
) -> Result<[u8; 32], StorageError> {
    roots
        .iter()
        .find(|root| {
            root.hash != [0; 32]
                && root.revision == revision
                && (revision == roots[0].revision || slot < root.expires_at())
        })
        .map(|root| root.hash)
        .ok_or(StorageError::RootExpired)
}

impl From<StorageError> for ProgramError {
    fn from(error: StorageError) -> Self {
        Self::Custom(error as u32)
    }
}

// Byte fields only, the `Pod` image is the account data with no padding.
const _: () = assert!(core::mem::align_of::<StorageRegistry>() == 1);
const _: () = assert!(StorageRegistry::SIZE == 1581);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable() {
        use StorageError::*;
        for error in [
            InvalidRegistry,
            Unauthorized,
            RevisionChanged,
            RootExpired,
            HistoryFull,
            InvalidInstructionData,
            BatchTooLarge,
            InvalidWrite,
            ProofVerificationFailed,
            HashingFailed,
            MissingAccounts,
            MissingSignature,
            ReadOnlyRegistry,
            InvalidSystemProgram,
            AlreadyInitialized,
            RevisionOverflow,
            UnsupportedBatch,
        ] {
            let code = match error {
                InvalidRegistry => 9000,
                Unauthorized => 9001,
                RevisionChanged => 9002,
                RootExpired => 9003,
                HistoryFull => 9004,
                InvalidInstructionData => 9005,
                BatchTooLarge => 9006,
                InvalidWrite => 9007,
                ProofVerificationFailed => 9008,
                HashingFailed => 9009,
                MissingAccounts => 9010,
                MissingSignature => 9011,
                ReadOnlyRegistry => 9012,
                InvalidSystemProgram => 9013,
                AlreadyInitialized => 9014,
                RevisionOverflow => 9015,
                UnsupportedBatch => 9016,
            };
            assert_eq!(error as u32, code);
        }
    }
}
