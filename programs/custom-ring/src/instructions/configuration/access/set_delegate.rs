//! Sets the ring's permanent delegate, once.
//!
//! SPP's authority rail moves notes with no owner signature, and governance opens it per ring in `RingConfig`.
//! The delegate is the ring's own gate on the rail. A delegate frame reads no policy root, owes no co-signer,
//! carries no approval bit and takes no deposit leg. The ring proof still shows the auditor opens its slots.
//!
//! The instruction guarantees:
//!
//! 1. The admin and the delegate both sign, a mistyped address cannot enable the rail.
//! 2. No instruction replaces or clears a set delegate.
//! 3. The delegate stays apart from every role, and `RingPolicy::rotate_role` keeps the split.
//!
//! Read after `instructions/transfer/accounts.rs`. Read before `instructions/configuration/access/set_paused.rs`.

use custom_ring_interface::{CustomRingError, RingRole};
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
    // 2. The delegate holds no role, and the tracking rows every ring holds serve its proof the victim's key.
    ring.roles.check(Some(delegate.address()))?;
    ring.delegate = *delegate.address();
    Ok(())
}
