use custom_ring_interface::SetCoSignerIxData;
use pinocchio::{AccountView, Address, ProgramResult};
use spr_account_checks::AccountIterator;

use crate::instructions::{
    instruction_runtime::{no_data, parse},
    loader::load_authorized_config_mut,
};

#[inline(never)]
pub fn process_set_cosigner_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: SetCoSignerIxData = parse(data)?;
    let scope = ix.check()?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    // 2. The config authority replaces the co-signer and scope.
    let mut config = load_authorized_config_mut(program_id, config, authority)?;
    config.co_signer = Address::new_from_array(ix.signer);
    config.co_sign_scope = scope.bits();
    Ok(())
}

#[inline(never)]
pub fn process_clear_cosigner_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    no_data(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    let mut config = load_authorized_config_mut(program_id, config, authority)?;
    config.co_signer = Address::default();
    config.co_sign_scope = 0;
    Ok(())
}
