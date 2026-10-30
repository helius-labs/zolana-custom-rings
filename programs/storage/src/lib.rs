//! Transfer authorization remains the consumer's responsibility.

use bytemuck::Pod;
use custom_ring_interface::{
    storage::StorageError,
    storage_instruction::{tag, UpdateMode},
};
use pinocchio::{AccountView, Address, ProgramResult};

use instructions::{process_initialize_ix, process_update_authority_ix, process_update_ix};

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

mod instructions;
mod loader;

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (instruction, data) = data
        .split_first()
        .ok_or(StorageError::InvalidInstructionData)?;
    match *instruction {
        tag::INITIALIZE => process_initialize_ix(program_id, accounts, data),
        tag::UPDATE => process_update_ix(program_id, accounts, data, UpdateMode::Graced),
        tag::UPDATE_IMMEDIATE => {
            process_update_ix(program_id, accounts, data, UpdateMode::Immediate)
        }
        tag::UPDATE_AUTHORITY => process_update_authority_ix(program_id, accounts, data),
        _ => Err(StorageError::InvalidInstructionData.into()),
    }
}

pub(crate) fn parse<T: Pod>(data: &[u8]) -> Result<&T, StorageError> {
    bytemuck::try_from_bytes(data).map_err(|_| StorageError::InvalidInstructionData)
}
