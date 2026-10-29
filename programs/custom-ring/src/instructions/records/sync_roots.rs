use pinocchio::{AccountView, Address, ProgramResult};
use spr_account_checks::AccountIterator;

use crate::instructions::{
    instruction_runtime::no_data,
    loader::{load_policy_mut, load_storage_registry},
};

/// Permissionless, the copy is the registry's state at this slot.
#[inline(never)]
pub fn process_sync_roots_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    no_data(data)?;
    let mut iter = AccountIterator::new(accounts);
    let policy = iter.next_mut("policy")?;
    let registry = iter.next_account("registry")?;

    let roots = load_storage_registry(registry)?;
    load_policy_mut(program_id, policy)?.sync(registry.address(), &roots)?;
    Ok(())
}
