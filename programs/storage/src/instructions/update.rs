use custom_ring_interface::{
    key_catalog::RingCircuit,
    queue_chain,
    storage::{chain_start, RootUpdate, StorageError},
    storage_instruction::{StorageUpdateIxData, UpdateMode},
    verifying_key, ApplyRecordsStatement, RingProof,
};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use crate::loader::{check_authority, check_signer, load_registry_mut};

pub fn process_update_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
    mode: UpdateMode,
) -> ProgramResult {
    let ix = StorageUpdateIxData::parse(data)?;
    let [authority_account, registry_account, ..] = accounts else {
        return Err(StorageError::MissingAccounts.into());
    };
    check_signer(authority_account)?;
    let chain_start = chain_start(registry_account.address(), ix.revision)?;
    let mut registry = load_registry_mut(program_id, registry_account)?;
    check_authority(&registry, authority_account)?;
    let (old_root, old_next_index) = (registry.roots[0].hash, registry.next_index());
    // A stale revision fails here, ahead of the proof made against its old root.
    registry.update(RootUpdate {
        mode,
        slot: Clock::get()?.slot,
        data: &ix,
    })?;
    let chain_end = ix.writes.iter().try_fold(chain_start, |chain, write| {
        let entry = write.entry().map_err(|_| StorageError::InvalidWrite)?;
        queue_chain(&chain, &entry).map_err(|_| StorageError::HashingFailed)
    })?;
    let statement = ApplyRecordsStatement {
        old_root,
        new_root: ix.apply.new_root,
        old_next_index,
        new_next_index: ix.apply.new_next_index(),
        chain_start,
        chain_end,
        count: ix.writes.len() as u64,
    };
    RingProof {
        proof: &ix.apply.proof,
        statement: statement.hash().map_err(|_| StorageError::HashingFailed)?,
        key: verifying_key(RingCircuit::apply_records(statement.count))
            .ok_or(StorageError::UnsupportedBatch)?,
    }
    .verify()
    .map_err(|_| StorageError::ProofVerificationFailed)?;
    Ok(())
}
