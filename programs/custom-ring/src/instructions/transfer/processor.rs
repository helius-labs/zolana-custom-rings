//! Runs one transfer, the ring's checks in order and then the call into SPP's ring rail.
//!
//! SPP settles what `ring_auth` signs and its own proof accepts. The run adds rail selection, account
//! placement and the ring proof. A defect here settles a transfer no ring rule covered.
//!
//! The run guarantees:
//!
//! 1. The tag, the ring's mode and its delegate fix the rail, frame flags select only the owner form SPP's selector reads.
//! 2. `ring_auth` signs only after the ring proof verifies, over the data the frame expands to.
//!
//! The run relies on SPP for note membership, unspent nullifiers, value conservation, expiry, and the
//! activation and pause of `RingConfig`. SPP's proof covers the expanded data through its external data hash.
//!
//! Read after `lib.rs`. Read before `instructions/transfer/accounts.rs`, `instructions/transfer/verify.rs`.

use custom_ring_interface::{InstructionTag, RailSigner, RingTransactData};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use super::{accounts::TransactCheck, verify::RingStatements};
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
    let ring = load_policy(
        program_id,
        accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?,
    )?;
    let signer = RailSigner::new(tag, &ring)?;
    // 2. Every length follows from the flags and the shape, trailing bytes refused.
    let transfer = RingTransactData::parse(data, signer.rail())?;
    let data = transfer.data();
    // 3. Each account sits in the slot the statements and SPP read it from.
    let validated = TransactCheck {
        program_id,
        ring: &ring,
        transfer: &transfer,
        signer,
        slot,
    }
    .validate(accounts)?;
    // 4. A bad SPP proof point is refused before either pairing.
    let spp_data = data.spp_instruction_data(&ring)?;
    // 5. The ring proof verifies the frame's approval mask and spend bit before the SPP call.
    // Step 3 demanded co-signers from those bits, the demand holds only because the proof fixes them.
    RingStatements {
        program_id,
        ring: &ring,
        transfer: &transfer,
        accounts: &validated,
    }
    .verify()?;
    // 6. SPP verifies its own proof over the expanded data the ring PDA signs. The ring proof and
    // the SPP proof meet at the values `lib.rs` names, a refusal by SPP reverts the whole transfer.
    let spp = accounts
        .get(validated.spp..)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    validate_spp_program(spp)?;
    validated.ring_auth.invoke(spp, &spp_data)
}
