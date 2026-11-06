//! Creates a tracking registry at `[tracking_registry, creator, ring_id]`, holding the sentinel root at revision zero.
//!
//! The ring's `Initialize` signs its ring PDA as creator through CPI and pins the address. Anyone
//! else may create a registry naming any ring, and no ring reads it.
//!
//! Read after `programs/storage/src/lib.rs`, `program-libs/interface/src/accounts/tracking.rs`. Read
//! before `programs/storage/src/instructions/enroll.rs`, `programs/custom-ring/src/instructions/configuration/setup/initialize.rs`.
//!
//! Guarantees:
//! 1. `ring_id` and `auditor_pubkey` are final, and every first enrollment seals to that key.
//! 2. `is_auditor_key` refuses a key no proof can seal to, it would lock enrollment for good, and ring `Initialize` runs the same check.
//!
//! Relies on:
//! 1. The ring compares the registry's address on every read, its seeds and `ring_id` authenticate nothing.

use custom_ring_interface::{storage::StorageError, storage_instruction::InitializeTrackingIxData};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    loader::{check_signer, TrackingRegistryInit},
    parse,
};

pub fn process_initialize_tracking_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: &InitializeTrackingIxData = parse(data)?;
    let [payer_account, creator_account, registry_account, system_program_account, ..] = accounts
    else {
        return Err(StorageError::MissingAccounts.into());
    };
    check_signer(payer_account)?;
    check_signer(creator_account)?;
    if !pinocchio_system::check_id(system_program_account.address()) {
        return Err(StorageError::InvalidSystemProgram.into());
    }
    ix.check()?;
    TrackingRegistryInit {
        program_id,
        payer: payer_account,
        creator: creator_account.address(),
        ix,
    }
    .init(registry_account)
}
