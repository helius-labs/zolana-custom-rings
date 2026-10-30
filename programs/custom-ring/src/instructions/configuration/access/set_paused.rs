use custom_ring_interface::{RingRole, SetPausedIxData};
use pinocchio::{AccountView, Address, ProgramResult};
use spr_account_checks::AccountIterator;
use spr_interface::instruction::{encode_instruction, tag, UpdateRingConfigData};

use crate::instructions::{
    instruction_runtime::{parse, RingAuth},
    loader::{validate_spp_program, RoleHolder},
};

#[inline(never)]
pub fn process_set_paused_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let SetPausedIxData { paused } = parse(data)?;

    let mut iter = AccountIterator::new(accounts);
    let pauser = iter.next_signer("pauser")?;
    let ring = iter.next_account("ring")?;
    let ring_auth = iter.next_mut("ring_auth")?;
    let spp_program = iter.next_account("spp_program")?;

    // 1. The pauser pauses or resumes the ring's SPP rail.
    RoleHolder {
        program_id,
        role: RingRole::Pauser,
        signer: pauser,
    }
    .load(ring)?;
    validate_spp_program(core::slice::from_ref(spp_program))?;
    let placed = RingAuth::derive(program_id)?.check_account(ring_auth)?;
    let data = encode_instruction(tag::UPDATE_RING_CONFIG, &UpdateRingConfigData { paused });
    // 2. The ring auth PDA is also SPP's ring authority.
    placed.invoke(&[&*ring_auth, &*ring_auth], &data)
}
