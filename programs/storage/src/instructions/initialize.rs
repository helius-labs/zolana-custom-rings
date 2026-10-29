use custom_ring_interface::storage_instruction::InitializeIxData;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use spr_account_checks::AccountIterator;

use crate::{loader::RegistryInit, parse};

pub fn process_initialize_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: &InitializeIxData = parse(data)?;
    let mut accounts = AccountIterator::new(accounts);
    let payer_account = accounts.next_signer_mut("payer")?;
    let creator_account = accounts.next_signer("creator")?;
    let registry_account = accounts.next_mut("registry")?;
    let system_program_account = accounts.next_account("system")?;
    if !pinocchio_system::check_id(system_program_account.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    RegistryInit {
        program_id,
        payer: payer_account,
        creator: creator_account.address(),
        registry_id: &ix.registry_id,
        grace_slots: ix.grace_slots(),
    }
    .init(registry_account)
}
