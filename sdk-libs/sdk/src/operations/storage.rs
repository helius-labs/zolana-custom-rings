use custom_ring_interface::{
    storage::{RegistryId, StorageRegistry},
    storage_instruction::{tag, InitializeIxData, StorageUpdateIxData, UpdateMode},
    tag::SYNC_ROOTS,
    STORAGE_PROGRAM_ID, SYSTEM_PROGRAM_ID,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::{CustomRing, RingError};

/// The creator signs and becomes the authority, the payer funds the account.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitializeStorage {
    pub payer: Address,
    pub creator: Address,
    pub registry_id: RegistryId,
    pub grace_slots: u64,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateStorage<'a> {
    pub authority: Address,
    pub registry: Address,
    pub mode: UpdateMode,
    pub data: StorageUpdateIxData<'a>,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateStorageAuthority {
    pub authority: Address,
    pub new_authority: Address,
    pub registry: Address,
}

/// Permissionless, `registry` is the ring's records or its curator.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncRoots {
    pub ring: CustomRing,
    pub registry: Address,
}

impl InitializeStorage {
    pub fn registry(&self) -> Address {
        StorageRegistry::find_address(&self.creator, &self.registry_id).0
    }

    pub fn instruction(self) -> Instruction {
        let data = InitializeIxData {
            registry_id: self.registry_id,
            grace_slots: self.grace_slots.to_le_bytes(),
        };
        storage_ix(
            vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.creator, true),
                AccountMeta::new(self.registry(), false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            [&[tag::INITIALIZE], bytemuck::bytes_of(&data)].concat(),
        )
    }
}

impl UpdateStorage<'_> {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        Ok(storage_ix(
            vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(self.registry, false),
            ],
            [vec![self.mode.tag()], self.data.encode()?].concat(),
        ))
    }
}

impl UpdateStorageAuthority {
    pub fn instruction(self) -> Instruction {
        storage_ix(
            vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new_readonly(self.new_authority, true),
                AccountMeta::new(self.registry, false),
            ],
            vec![tag::UPDATE_AUTHORITY],
        )
    }
}

impl SyncRoots {
    pub fn instruction(self) -> Instruction {
        Instruction {
            program_id: self.ring.program_id(),
            accounts: vec![
                AccountMeta::new(self.ring.policy_pda(), false),
                AccountMeta::new_readonly(self.registry, false),
            ],
            data: vec![SYNC_ROOTS],
        }
    }
}

fn storage_ix(accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: STORAGE_PROGRAM_ID,
        accounts,
        data,
    }
}
