use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use solana_program_error::ProgramError;
use thiserror::Error;

use crate::{
    member_registry::{MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_EMPTY_ROOT},
    state::ROOT_HISTORY,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct Registry {
    pub discriminator: u8,
    pub writer: Address,
    pub grace_slots: [u8; 8],
    pub next_index: [u8; 4],
    /// Newest first, only retired roots have an expiry.
    pub roots: [Root; ROOT_HISTORY],
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum PolicyStoreError {
    #[error("invalid registry")]
    InvalidRegistry = 9000,
    #[error("writer does not match")]
    Unauthorized = 9001,
    #[error("revision changed")]
    RevisionChanged = 9002,
    #[error("root expired or absent")]
    RootExpired = 9003,
    #[error("root history is full")]
    HistoryFull = 9004,
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

impl Registry {
    /// Zero marks an uninitialized account.
    pub const DISCRIMINATOR: u8 = 1;
    pub const SEED: &'static [u8] = b"policy-store";
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Holds only the sentinel root at revision zero.
    pub fn new(writer: Address, grace_slots: u64) -> Self {
        let mut registry = Self::zeroed();
        registry.discriminator = Self::DISCRIMINATOR;
        registry.writer = writer;
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

    /// The current root, or a retired one before its expiry.
    pub fn root(&self, revision: Revision, slot: u64) -> Result<[u8; 32], PolicyStoreError> {
        self.roots
            .iter()
            .find(|root| {
                root.hash != [0; 32]
                    && root.revision == revision
                    && (revision == self.roots[0].revision || slot < root.expires_at())
            })
            .map(|root| root.hash)
            .ok_or(PolicyStoreError::RootExpired)
    }

    fn valid(&self) -> bool {
        self.discriminator == Self::DISCRIMINATOR
            && (1..=MEMBER_REGISTRY_CAPACITY).contains(&u64::from(self.next_index()))
    }
}

impl From<PolicyStoreError> for ProgramError {
    fn from(error: PolicyStoreError) -> Self {
        Self::Custom(error as u32)
    }
}

// Byte fields only, the `Pod` image is the account data with no padding.
const _: () = assert!(core::mem::align_of::<Registry>() == 1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable() {
        use PolicyStoreError::*;
        for error in [
            InvalidRegistry,
            Unauthorized,
            RevisionChanged,
            RootExpired,
            HistoryFull,
        ] {
            let code = match error {
                InvalidRegistry => 9000,
                Unauthorized => 9001,
                RevisionChanged => 9002,
                RootExpired => 9003,
                HistoryFull => 9004,
            };
            assert_eq!(error as u32, code);
        }
    }
}
