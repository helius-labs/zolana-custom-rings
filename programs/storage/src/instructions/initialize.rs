//! Creates a policy registry at `[storage, creator, registry_id]`, holding the sentinel root at revision zero.
//!
//! Read after `programs/storage/src/lib.rs`, `program-libs/interface/src/accounts/storage.rs`. Read
//! before `programs/storage/src/instructions/update.rs`.
//!
//! Guarantees:
//! 1. The creator signs and becomes the authority, its key in the seeds keeps every other signer off the address.
//! 2. `grace_slots`, `ring_id` and `tracking_registry` are final, no instruction writes them again.
//!
//! Relies on:
//! 1. The ring checks `ring_id` in `load_records_registry` and `tracking_registry` in `RingPolicy::check_source_pair`, neither is checked here.
//! 2. A pin that names no tracking registry fails its own private writes and harms its creator alone.

use custom_ring_interface::{storage::StorageError, storage_instruction::InitializeIxData};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    loader::{check_signer, RegistryInit},
    parse,
};

pub fn process_initialize_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: &InitializeIxData = parse(data)?;
    let [payer_account, creator_account, registry_account, system_program_account, ..] = accounts
    else {
        return Err(StorageError::MissingAccounts.into());
    };
    check_signer(payer_account)?;
    check_signer(creator_account)?;
    if !pinocchio_system::check_id(system_program_account.address()) {
        return Err(StorageError::InvalidSystemProgram.into());
    }
    RegistryInit {
        program_id,
        payer: payer_account,
        creator: creator_account.address(),
        ix,
    }
    .init(registry_account)
}
