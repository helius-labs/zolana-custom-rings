use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use spr_account_checks::AccountIterator;

use crate::loader::{check_authority, load_registry_mut};

pub fn process_update_authority_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut accounts = AccountIterator::new(accounts);
    let authority_account = accounts.next_signer("authority")?;
    let new_authority_account = accounts.next_signer("new_authority")?;
    let registry_account = accounts.next_mut("registry")?;
    let mut registry = load_registry_mut(program_id, registry_account)?;
    check_authority(&registry, authority_account)?;
    registry.authority = *new_authority_account.address();
    Ok(())
}
