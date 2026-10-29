use custom_ring_interface::storage::{StorageError, StorageRegistry};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;

use crate::{loader::init_registry, parse, InitializeIxData, REGISTRY_SEED};

pub fn process_initialize_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: &InitializeIxData = parse(data)?;
    let mut accounts = AccountIterator::new(accounts);
    let authority_account = accounts.next_signer_mut("authority")?;
    let registry_account = accounts.next_mut("registry")?;
    let system_program_account = accounts.next_account("system")?;
    if !pinocchio_system::check_id(system_program_account.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (registry_pda, bump) = Address::derive_program_address(
        &[REGISTRY_SEED, authority_account.address().as_ref()],
        program_id,
    )
    .ok_or(StorageError::InvalidRegistry)?;
    if registry_account.address() != &registry_pda {
        return Err(StorageError::InvalidRegistry.into());
    }
    if registry_account.data_len() != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    let bump = [bump];
    let seeds = [
        Seed::from(REGISTRY_SEED),
        Seed::from(authority_account.address().as_ref()),
        Seed::from(&bump),
    ];
    pinocchio_system::create_account_with_minimum_balance_signed(
        registry_account,
        StorageRegistry::SIZE,
        program_id,
        authority_account,
        None,
        &[Signer::from(seeds.as_slice())],
    )?;
    init_registry(
        registry_account,
        &StorageRegistry::new(
            *authority_account.address(),
            u64::from_le_bytes(ix.grace_slots),
        ),
    )
}
