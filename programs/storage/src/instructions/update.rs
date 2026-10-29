use bytemuck::Zeroable;
use custom_ring_interface::{
    key_catalog::RingCircuit,
    queue_chain,
    storage::{Revision, Root, StorageError},
    storage_instruction::UpdateMode,
    verifying_key, ApplyRecordsStatement, AuthorityWriteRecordsIxData, CustomRingError, RingProof,
    ROOT_HISTORY,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;

use crate::{chain_start, loader::load_registry_mut, parse};

pub fn process_update_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
    mode: UpdateMode,
) -> ProgramResult {
    let (revision, data) = data
        .split_at_checked(core::mem::size_of::<Revision>())
        .ok_or(ProgramError::InvalidInstructionData)?;
    let revision = *parse::<Revision>(revision)?;
    let ix = AuthorityWriteRecordsIxData::parse(data)?;
    let mut accounts = AccountIterator::new(accounts);
    let authority_account = accounts.next_signer("authority")?;
    let registry_account = accounts.next_mut("registry")?;
    let chain_start = chain_start(registry_account.address(), revision)?;
    let mut registry = load_registry_mut(program_id, registry_account)?;
    if authority_account.address() != &registry.authority {
        return Err(StorageError::Unauthorized.into());
    }
    if revision != registry.roots[0].revision {
        return Err(StorageError::RevisionChanged.into());
    }
    let next_revision = revision
        .value()
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let slot = Clock::get()?.slot;
    if mode == UpdateMode::Graced && slot < registry.roots[ROOT_HISTORY - 1].expires_at() {
        return Err(StorageError::HistoryFull.into());
    }
    // `APPLY_RECORDS` binds the registry address and revision before the ordered writes.
    let chain_end = ix.writes.iter().try_fold(chain_start, |chain, write| {
        Ok::<_, CustomRingError>(queue_chain(&chain, &write.entry()?)?)
    })?;
    let statement = ApplyRecordsStatement {
        old_root: registry.roots[0].hash,
        new_root: ix.apply.new_root,
        old_next_index: registry.next_index(),
        new_next_index: ix.apply.new_next_index(),
        chain_start,
        chain_end,
        count: ix.writes.len() as u64,
    };
    RingProof {
        proof: &ix.apply.proof,
        statement: statement.hash()?,
        key: verifying_key(RingCircuit::apply_records(statement.count))
            .ok_or(CustomRingError::UnsupportedCircuit)?,
    }
    .verify()?;
    match mode {
        UpdateMode::Graced => {
            // A saturated expiry never lapses.
            registry.roots[0].expires_at =
                slot.saturating_add(registry.grace_slots()).to_le_bytes();
            registry.roots.rotate_right(1);
        }
        UpdateMode::Immediate => registry.roots.fill(Root::zeroed()),
    }
    registry.roots[0] = Root {
        hash: statement.new_root,
        revision: next_revision.into(),
        expires_at: [0; 8],
    };
    registry.next_index = ix.apply.new_next_index;
    Ok(())
}
