use custom_ring_interface::{CustomRingError, RingMode, RingRole};
use pinocchio::{AccountView, Address, ProgramResult};
use spr_account_checks::AccountIterator;

use crate::instructions::{instruction_runtime::no_data, loader::RoleHolder};

#[inline(never)]
pub fn process_set_delegate_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    no_data(data)?;
    let mut iter = AccountIterator::new(accounts);
    let admin = iter.next_signer("admin")?;
    let ring = iter.next_mut("ring")?;
    let delegate = iter.next_signer("delegate")?;

    // 1. The delegate is permanent for the instructions of the deployed binary.
    let mut ring = RoleHolder {
        program_id,
        role: RingRole::Admin,
        signer: admin,
    }
    .load_mut(ring)?;
    if ring.delegate().is_some() {
        return Err(CustomRingError::DelegateAlreadySet.into());
    }
    // 2. An anonymous ring hides the owner a delegate would sign for.
    if ring.mode()? == RingMode::Anonymous {
        return Err(CustomRingError::AnonymousRingRefused.into());
    }
    if !ring.has_policy() {
        return Err(CustomRingError::DelegateRequiresPolicy.into());
    }
    // 3. The delegate holds no role, and `ConfidentialEscrow` mode escrows every output nullifier key in the records.
    ring.roles.check(Some(delegate.address()))?;
    ring.delegate = *delegate.address();
    ring.mode = RingMode::ConfidentialEscrow as u8;
    Ok(())
}
