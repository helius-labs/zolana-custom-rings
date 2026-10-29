use custom_ring_interface::{CustomRingError, SetPolicySourceIxData, SourceSlot};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;
use zolana_ring_policy::ListId;

use crate::instructions::{
    instruction_runtime::parse,
    loader::{load_authorized_config, load_policy_mut},
    policy_binding::curator_source,
};

#[inline(never)]
pub fn process_set_policy_source_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: SetPolicySourceIxData = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let policy = iter.next_mut("policy")?;
    let curators = iter.remaining_unchecked()?;

    // 1. The authority moves one list to its own records or one curator.
    load_authorized_config(program_id, config, authority)?;
    let list_id = ListId::try_from(ix.list_id).map_err(|_| CustomRingError::InvalidListId)?;
    let mut policy = load_policy_mut(program_id, policy)?;
    let source = match (ix.source, curators) {
        (0, []) => Address::default(),
        (1, [curator]) => curator_source(&policy.records, curator)?,
        _ => return Err(CustomRingError::InvalidSource.into()),
    };
    // 2. Only a list the rules reference has a source.
    let mut sources = policy.sources;
    if sources[list_id.slot()].list_id == 0 {
        return Err(CustomRingError::InvalidSource.into());
    }
    sources[list_id.slot()] = SourceSlot {
        list_id: list_id as u8,
        registry: source,
    };
    // 3. The rehashed source map refuses a second distinct curator.
    let rules = policy.rules;
    policy.set_policy(sources, rules, Clock::get()?.slot)?;
    Ok(())
}
