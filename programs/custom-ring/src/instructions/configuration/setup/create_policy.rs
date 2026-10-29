use custom_ring_interface::{CreatePolicyIxData, CustomRingError, RingPolicy};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;

use crate::{
    instructions::{
        instruction_runtime::{check_system_program, parse, Pda},
        loader::{load_authorized_config, load_policy_mut, load_storage_registry},
        policy_binding::TableBinding,
    },
    state::Init,
};

#[inline(never)]
pub fn process_create_policy_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: CreatePolicyIxData = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let policy = iter.next_mut("policy")?;
    let records = iter.next_account("records")?;
    let system_program = iter.next_account("system_program")?;
    let curators = iter.remaining_unchecked()?;

    // 1. An audit-only ring takes the records binding alone, for its withdrawal exemptions.
    check_system_program(system_program)?;
    let config = load_authorized_config(program_id, config, authority)?;
    let has_table = !(ix.table.sources.is_empty() && ix.table.rules.is_empty());
    if !config.has_policy() && has_table {
        return Err(CustomRingError::PolicyOnAuditOnlyRing.into());
    }
    // 2. The records answer to the config authority or to the storage authority it names.
    let records_authority = load_storage_registry(records)?.authority;
    if records_authority != config.authority && records_authority != ix.storage_authority {
        return Err(CustomRingError::StorageAuthorityMismatch.into());
    }
    let bump = Pda {
        program_id,
        seeds: &[RingPolicy::SEED],
    }
    .create::<RingPolicy>(payer, policy)?;
    Init(&*RingPolicy::new(bump, *records.address())).init(policy)?;
    if !config.has_policy() {
        return Ok(());
    }
    // 3. Sources name exactly the lists the rules reference.
    let bound = TableBinding {
        records: records.address(),
        table: &ix.table,
        curators,
    }
    .bind()?;
    // 4. The pinned hash binds every later policy proof.
    load_policy_mut(program_id, policy)?.set_policy(bound.sources, bound.rules, Clock::get()?.slot)?;
    Ok(())
}
