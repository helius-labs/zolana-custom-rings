use custom_ring_interface::{RingRole, UpdateAuthorityIxData};
use pinocchio::{AccountView, Address, ProgramResult};
use spr_account_checks::AccountIterator;

use crate::instructions::{instruction_runtime::parse, loader::RoleHolder};

/// The new key signs too, a mistyped address cannot strand the role.
#[inline(never)]
pub fn process_update_authority_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let UpdateAuthorityIxData { role } = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let admin = iter.next_signer("admin")?;
    let new_key = iter.next_signer("new_key")?;
    let ring = iter.next_mut("ring")?;

    // 1. The admin signs, and the new key stays apart from every other role and the delegate.
    let mut ring = RoleHolder {
        program_id,
        role: RingRole::Admin,
        signer: admin,
    }
    .load_mut(ring)?;
    ring.rotate_role(role, *new_key.address())?;
    Ok(())
}
