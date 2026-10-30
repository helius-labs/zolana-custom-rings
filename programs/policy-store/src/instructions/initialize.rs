use custom_ring_interface::policy_store::{PolicyStoreError, Registry};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;

use crate::{loader::init_registry, parse, InitializeIxData};

pub fn process_initialize_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: &InitializeIxData = parse(data)?;
    let mut accounts = AccountIterator::new(accounts);
    let writer_account = accounts.next_signer_mut("writer")?;
    let registry_account = accounts.next_mut("registry")?;
    let system_program_account = accounts.next_account("system")?;
    if !pinocchio_system::check_id(system_program_account.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (registry_pda, bump) = Address::derive_program_address(
        &[Registry::SEED, writer_account.address().as_ref()],
        program_id,
    )
    .ok_or(PolicyStoreError::InvalidRegistry)?;
    if registry_account.address() != &registry_pda {
        return Err(PolicyStoreError::InvalidRegistry.into());
    }
    if registry_account.data_len() != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    let bump = [bump];
    let seeds = [
        Seed::from(Registry::SEED),
        Seed::from(writer_account.address().as_ref()),
        Seed::from(&bump),
    ];
    pinocchio_system::create_account_with_minimum_balance_signed(
        registry_account,
        Registry::SIZE,
        program_id,
        writer_account,
        None,
        &[Signer::from(seeds.as_slice())],
    )?;
    init_registry(
        registry_account,
        &Registry::new(
            *writer_account.address(),
            u64::from_le_bytes(ix.grace_slots),
        ),
    )
}
