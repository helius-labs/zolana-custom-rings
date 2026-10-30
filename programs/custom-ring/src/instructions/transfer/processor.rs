use custom_ring_interface::{CustomRingError, InstructionTag, RailSigner, RingTransactData};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use super::{
    accounts::TransactCheck,
    verify::{escrows_keys, RingStatements},
};
use crate::instructions::loader::{load_policy, validate_spp_program};

#[inline(never)]
pub fn process_transfer_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
    tag: InstructionTag,
) -> ProgramResult {
    let slot = Clock::get()?.slot;
    // 1. The ring's mode and delegate fix the rail and the signer it trusts.
    let accounts = &*accounts;
    let ring = load_policy(
        program_id,
        accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?,
    )?;
    let signer = RailSigner::new(tag, &ring)?;
    // 2. Every length follows from the flags and the shape, trailing bytes refused.
    let transfer = RingTransactData::parse(data, signer.rail())?;
    let data = transfer.data();
    // 3. The disclosure chain hashes trailing zeros alike, honest fields are padded nonzero.
    if data.disclosure.contains(&[0; 32]) {
        return Err(CustomRingError::ZeroDisclosureField.into());
    }
    // 4. Each account sits in the slot the statements and SPP read it from.
    let validated = TransactCheck {
        program_id,
        ring: &ring,
        data,
        signer,
        slot,
    }
    .validate(accounts)?;
    // 5. A bad SPP proof point is refused before either pairing.
    let spp_data = data.spp_instruction_data(&ring)?;
    // 6. The audit proof and the policy proof verify over values the program derives.
    RingStatements {
        program_id,
        ring: &ring,
        transfer: &transfer,
        accounts: &validated,
        key_escrow: escrows_keys(&ring)?,
    }
    .verify()?;
    // 7. SPP verifies its own proof over the expanded data the ring PDA signs.
    let spp = accounts
        .get(validated.spp..)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    validate_spp_program(spp)?;
    validated.ring_auth.invoke(spp, &spp_data)
}
