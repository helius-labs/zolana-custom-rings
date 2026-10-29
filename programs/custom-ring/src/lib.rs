//! Verifies the ring's proofs over an SPP transaction and forwards it signed by the ring PDA.

mod instructions;
mod state;

use custom_ring_interface::{CustomRingError, InstructionTag};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::*;

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (ix_tag, ix_data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let ix_tag = InstructionTag::try_from(*ix_tag)?;

    match ix_tag {
        InstructionTag::Initialize => process_initialize_ix(program_id, accounts, ix_data),
        InstructionTag::Transfer | InstructionTag::AuthorityTransfer => {
            process_transfer_ix(program_id, accounts, ix_data, ix_tag)
        }
        InstructionTag::LegacyTransact | InstructionTag::LegacyDelegateTransact => {
            Err(CustomRingError::InvalidInstructionData.into())
        }
        // The deposit prefix layout starts at the tag byte.
        InstructionTag::Deposit => process_deposit_ix(program_id, accounts, instruction_data),
        // SPP proves that owner, asset, value and ring ownership stay unchanged.
        InstructionTag::Merge => process_merge_ix(program_id, accounts, ix_data),
        InstructionTag::UpdateAuthority => {
            process_update_authority_ix(program_id, accounts, ix_data)
        }
        InstructionTag::UpdatePolicy => process_update_policy_ix(program_id, accounts, ix_data),
        InstructionTag::SetPaused => process_set_paused_ix(program_id, accounts, ix_data),
        InstructionTag::SetCoSigner => process_set_cosigner_ix(program_id, accounts, ix_data),
        InstructionTag::ClearCoSigner => process_clear_cosigner_ix(program_id, accounts, ix_data),
        InstructionTag::SetDelegate => process_set_delegate_ix(program_id, accounts, ix_data),
        InstructionTag::SyncRoots => process_sync_roots_ix(program_id, accounts, ix_data),
    }
}
