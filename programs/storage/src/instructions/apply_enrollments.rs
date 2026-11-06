//! Applies pending enrollments to a ring's tracking tree.
//!
//! Enrollment never waits on an authority. Anyone may apply, so the program computes each entry from
//! its account and the applier chooses only the accounts and their order. A stale proof fails and
//! the accounts stay pending for the next applier.
//!
//! Read after `programs/storage/src/instructions/enroll.rs`, `program-libs/interface/src/accounts/tracking.rs`.
//! Read before `prover/circuits/registry/apply_enrollments.go`.
//!
//! Guarantees:
//! 1. The new root and next index follow from the current ones by exactly the entries of the named accounts, in the named order, and the next index stays within `TRACKING_CAPACITY`.
//! 2. Each authorization applies once, a duplicate account in one instruction included.
//! 3. The outgoing root keeps its full grace. An apply that would evict an unexpired root refuses, and its accounts stay pending.
//!
//! Relies on:
//! 1. `ApplyEnrollmentsCircuit` keeps the tree sorted and only inserts absent owners.
//! 2. The ring pins the registry by address.

use custom_ring_interface::{
    key_catalog::RingCircuit,
    storage::StorageError,
    storage_instruction::ApplyEnrollmentsIxData,
    tracking::{tracking_chain_start, TrackingRootUpdate},
    verifying_key, ApplyEnrollmentsStatement, RingProof,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use crate::{
    loader::{load_owned_tracking_authorization_mut, load_tracking_registry_mut},
    parse,
};

pub fn process_apply_enrollments_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: &ApplyEnrollmentsIxData = parse(data)?;
    let [registry_account, authorizations @ ..] = accounts else {
        return Err(StorageError::MissingAccounts.into());
    };
    // 1. One to `APPLY_BATCH` accounts, and the chain starts from the registry and revision the proof names.
    ApplyEnrollmentsIxData::check_count(authorizations.len())?;
    let registry_address = *registry_account.address();
    let chain_start = tracking_chain_start(&registry_address, ix.revision)?;
    let mut registry = load_tracking_registry_mut(program_id, registry_account)?;
    // 2. The statement's old values come from the account, and a stale revision fails ahead of the proof.
    let (old_root, old_next_index) = (registry.roots[0].hash, registry.next_index());
    registry.update(TrackingRootUpdate {
        revision: ix.revision,
        slot: Clock::get()?.slot,
        new_root: ix.new_root,
        new_next_index: ix.new_next_index(),
    })?;
    // 3. Each entry comes from its account, marked applied as it enters the chain.
    let count = authorizations.len() as u64;
    let chain_end = authorizations.iter_mut().try_fold(
        chain_start,
        |chain, account| -> Result<[u8; 32], ProgramError> {
            // A duplicate account reads its own apply and refuses.
            let entry =
                load_owned_tracking_authorization_mut(program_id, &registry_address, account)?
                    .apply()?;
            entry
                .chained(&chain)
                .map_err(|_| StorageError::HashingFailed.into())
        },
    )?;
    // 4. A failed proof reverts the root and every account step 3 marked.
    let statement = ApplyEnrollmentsStatement {
        old_root,
        new_root: ix.new_root,
        old_next_index,
        new_next_index: ix.new_next_index(),
        chain_start,
        chain_end,
        count,
    };
    RingProof {
        proof: &ix.proof,
        statement: statement.hash().map_err(|_| StorageError::HashingFailed)?,
        key: verifying_key(RingCircuit::apply_enrollments(count))
            .ok_or(StorageError::UnsupportedBatch)?,
    }
    .verify()
    .map_err(|_| StorageError::ProofVerificationFailed)?;
    Ok(())
}
