//! Keeps the roots a ring proof opens records under, and verifies the apply proof behind every root it accepts.
//!
//! SPP proves a spend against its own trees and knows no list, mint setting or enrolled key. A ring
//! proof opens those from the two trees kept here, and the ring program hands it the root it read
//! from the account. A policy registry holds an authority's lists and mint settings. A tracking
//! registry holds one ring's enrolled owners, and anyone may apply its pending enrollments. The two
//! stay apart because a stale apply proof fails on revision, and one shared tree would let
//! enrollment traffic delay a restrictive write.
//!
//! Read after `docs/design/records-and-roots.md`, `program-libs/interface/src/accounts/storage.rs`,
//! `program-libs/interface/src/accounts/tracking.rs`. Read before
//! `programs/storage/src/loader.rs`, `programs/storage/src/instructions/update.rs`,
//! `programs/storage/src/instructions/enroll.rs`, `programs/storage/src/instructions/apply_enrollments.rs`.
//!
//! Guarantees:
//! 1. A root enters a registry only with an apply proof over the registry's current root, next index and revision, and the program chains the writes that proof covers.
//! 2. A policy root moves under the registry authority's signature alone. A tracking root moves with no signature, over entries the program computes from authorization accounts.
//! 3. A revision names at most one root at a slot, `StorageRegistry::root` and `TrackingRegistry::root` share one rule.
//!
//! Relies on:
//! 1. The consumer pins a registry by address and reads its root itself. Nothing here knows the ring reading a registry, and transfer authorization remains the consumer's responsibility.
//! 2. The apply circuits in `prover/circuits/registry` keep each tree sorted and move only what the chained writes name.

use bytemuck::Pod;
use custom_ring_interface::{storage::StorageError, storage_instruction::tag};
use pinocchio::{AccountView, Address, ProgramResult};

use instructions::{
    process_apply_enrollments_ix, process_enroll_ix, process_initialize_ix,
    process_initialize_tracking_ix, process_owner_grant_ix, process_update_authority_ix,
    process_update_ix,
};

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

mod instructions;
mod loader;

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (instruction, data) = data
        .split_first()
        .ok_or(StorageError::InvalidInstructionData)?;
    match *instruction {
        tag::INITIALIZE => process_initialize_ix(program_id, accounts, data),
        tag::UPDATE => process_update_ix(program_id, accounts, data),
        tag::UPDATE_AUTHORITY => process_update_authority_ix(program_id, accounts, data),
        tag::ENROLL => process_enroll_ix(program_id, accounts, data),
        tag::APPLY_ENROLLMENTS => process_apply_enrollments_ix(program_id, accounts, data),
        tag::OWNER_GRANT => process_owner_grant_ix(program_id, accounts, data),
        tag::INITIALIZE_TRACKING => process_initialize_tracking_ix(program_id, accounts, data),
        _ => Err(StorageError::InvalidInstructionData.into()),
    }
}

pub(crate) fn parse<T: Pod>(data: &[u8]) -> Result<&T, StorageError> {
    bytemuck::try_from_bytes(data).map_err(|_| StorageError::InvalidInstructionData)
}
