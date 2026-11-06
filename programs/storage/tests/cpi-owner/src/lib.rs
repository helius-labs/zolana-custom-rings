//! Forwards one instruction under its `owner` PDA to the final executable account.

use pinocchio::{
    address::address_eq,
    cpi::{invoke_signed_with_slice, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};

pinocchio::entrypoint!(process_instruction);

const OWNER_SEED: &[u8] = b"owner";

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (owner, bump) = Address::derive_program_address(&[OWNER_SEED], program_id)
        .ok_or(ProgramError::InvalidSeeds)?;
    let (target, forwarded) = accounts
        .split_last()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !target.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    let metas: Vec<InstructionAccount> = forwarded
        .iter()
        .map(|account| {
            InstructionAccount::new(
                account.address(),
                account.is_writable(),
                account.is_signer() || address_eq(account.address(), &owner),
            )
        })
        .collect();
    let bump = [bump];
    let seeds = [Seed::from(OWNER_SEED), Seed::from(&bump)];
    let instruction = InstructionView {
        program_id: target.address(),
        accounts: &metas,
        data,
    };
    invoke_signed_with_slice(&instruction, accounts, &[Signer::from(seeds.as_slice())])
}
