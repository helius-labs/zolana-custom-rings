use custom_ring_interface::{CustomRingError, RingMode};
use pinocchio::{AccountView, Address, ProgramResult};
use spr_account_checks::AccountIterator;

use crate::instructions::{
    instruction_runtime::no_data,
    loader::{load_authorized_config_mut, load_registry},
};

#[inline(never)]
pub fn process_set_delegate_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    no_data(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    let delegate = iter.next_signer("delegate")?;
    let registry = iter.next_account("registry")?;

    // 1. The delegate is permanent for the instructions of the deployed binary.
    let mut config = load_authorized_config_mut(program_id, config, authority)?;
    if config.delegate().is_some() {
        return Err(CustomRingError::DelegateAlreadySet.into());
    }
    // 2. An anonymous ring hides the owner a delegate would sign for.
    if config.mode()? == RingMode::Anonymous {
        return Err(CustomRingError::AnonymousRingRefused.into());
    }
    if !config.has_policy() {
        return Err(CustomRingError::DelegateRequiresPolicy.into());
    }
    // 3. `ConfidentialEscrow` mode escrows every output nullifier key in the member registry.
    load_registry(program_id, registry)?;
    config.delegate = *delegate.address();
    config.mode = RingMode::ConfidentialEscrow as u8;
    Ok(())
}
