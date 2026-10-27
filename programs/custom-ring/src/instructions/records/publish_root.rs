use custom_ring_interface::PublishRootIxData;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::instructions::loader::{load_authorized_config, load_registry_mut};

/// Moves the registry to a root computed off chain, no queue and no proof.
#[inline(never)]
pub fn process_publish_root_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix = PublishRootIxData::parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let registry = iter.next_mut("registry")?;
    // 1. The config authority signs, a published root may rewrite the lists members write.
    load_authorized_config(program_id, config, authority)?;
    // 2. The root enters the history and floors the ring, older roots keep `OWN_GRACE_SLOTS`.
    load_registry_mut(program_id, registry)?.publish(ix.root, Clock::get()?.slot);
    Ok(())
}
