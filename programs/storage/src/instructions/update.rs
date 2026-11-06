//! Moves a policy registry to a new root, the one write path of its lists and mint settings.
//!
//! An SPP note never changes once written, a policy record does. The program therefore keeps only the
//! root and verifies a proof of each batch of writes. Every write travels in instruction data, and a
//! reader rebuilds the tree from them.
//!
//! Read after `programs/storage/src/lib.rs`, `program-libs/interface/src/accounts/storage.rs`,
//! `program-libs/interface/src/instructions/storage.rs`. Read before
//! `prover/circuits/registry/apply_records.go`.
//!
//! Guarantees:
//! 1. The new root and next index follow from the current ones by exactly the instruction's writes, in order.
//! 2. A batch the proof marks restrictive retires every earlier root in the instruction, any other batch keeps the outgoing root for the registry's grace.
//! 3. Every private owner write proves its owner's row under the pinned tracking registry's root at the named revision.
//! 4. The classified writes pick the key family, a batch with a private owner write never verifies under a public key.
//! 5. Proof acceptance precedes the new policy root and the raised tracking floor, both land in one instruction.
//!
//! Relies on:
//! 1. `RecordWriteData::storage_entry` keeps each value inside its mask and each mask inside the accepted list bits.
//! 2. `ApplyRecordsCircuit` keeps list bits outside each mask, moves mint settings only under the entry's flag, keeps the records sorted and sets the restrictive bit exactly when a write tightens a policy field or changes an asset limit.

use custom_ring_interface::{
    storage::{chain_start, RootUpdate, StorageError},
    storage_instruction::StorageUpdateIxData,
    verifying_key, write_chain, ApplyRecordsStatement, PrivateWrites, RingProof,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use crate::loader::{check_authority, check_signer, load_registry_mut, PinnedTrackingRoot};

pub fn process_update_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix = StorageUpdateIxData::parse(data)?;
    let [authority_account, registry_account, tracking_accounts @ ..] = accounts else {
        return Err(StorageError::MissingAccounts.into());
    };
    // 1. The authority and current revision fix the registry state and the start of the write chain.
    check_signer(authority_account)?;
    let chain_start = chain_start(registry_account.address(), ix.revision)?;
    let registry = load_registry_mut(program_id, registry_account)?;
    check_authority(&registry, authority_account)?;
    if registry.newest().revision != ix.revision {
        return Err(StorageError::RevisionChanged.into());
    }
    let slot = Clock::get()?.slot;
    // 2. The bitmap derives from private masks and authenticated asset preimages, and parsing paired it
    // with the tracking revision. The pinned registry serves the root the selected rows open under.
    let private = match (
        ix.private_writes()?,
        ix.tracking_revision,
        tracking_accounts,
    ) {
        (0, None, []) => None,
        (private_writes, Some(revision), [tracking]) if private_writes != 0 => {
            if !registry.is_private() {
                return Err(StorageError::PrivateWriteWithoutTracking.into());
            }
            Some(PrivateWrites {
                private_writes,
                tracking_root: PinnedTrackingRoot {
                    program_id,
                    registry: &registry,
                    revision,
                    slot,
                }
                .load(tracking)?,
            })
        }
        _ => return Err(StorageError::InvalidTrackingRegistry.into()),
    };
    // 3. The chain binds every write in instruction order, including writes with unchanged leaves.
    let chain_end = ix.entries().try_fold(
        chain_start,
        |chain, entry| -> Result<[u8; 32], ProgramError> {
            let entry = entry.map_err(|_| StorageError::InvalidWrite)?;
            write_chain(&chain, &entry).map_err(|_| StorageError::HashingFailed.into())
        },
    )?;
    let statement = ApplyRecordsStatement {
        old_root: registry.newest().hash,
        new_root: ix.apply.new_root,
        old_next_index: registry.next_index(),
        new_next_index: ix.apply.new_next_index(),
        chain_start,
        chain_end,
        count: ix.writes.len() as u64,
        restrictive: ix.apply.restrictive(),
        private,
    };
    // 4. One proof under the mode's key binds the policy transition and every selected tracking row.
    RingProof {
        proof: &ix.apply.proof,
        statement: statement.hash().map_err(|_| StorageError::HashingFailed)?,
        key: verifying_key(statement.circuit()).ok_or(StorageError::UnsupportedBatch)?,
    }
    .verify()
    .map_err(|_| StorageError::ProofVerificationFailed)?;
    // 5. The policy root and the tracking floor move together after verification.
    let mut registry = registry;
    registry.update(RootUpdate { slot, data: &ix })?;
    Ok(())
}
