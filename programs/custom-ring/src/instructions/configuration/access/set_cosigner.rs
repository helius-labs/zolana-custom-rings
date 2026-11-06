//! Adds, moves and removes the co-signer records a ring's operations demand.
//!
//! SPP reads no co-signer. An optional class demands a signer only while a record covers it, so the
//! ring's counts decide whether the class is on. An approval class stays demanded with no record, and a frame proving its bit then fails.
//!
//! The instructions guarantee:
//!
//! 1. Only the co-signer admin writes, and each write moves the counts with the record.
//! 2. A record sits at its signer's canonical PDA, so one signer holds one record.
//!
//! Read after `instructions/transfer/accounts.rs`. Read before `program-libs/interface/src/instructions/cosign.rs`.

use custom_ring_interface::{CoSigner, RingAccount, RingRole, SetCoSignerRecordIxData, CO_SIGNER};
use pinocchio::{AccountView, Address, ProgramResult};
use spr_account_checks::AccountIterator;

use crate::{
    instructions::{
        instruction_runtime::{check_system_program, close_into, no_data, parse, Pda},
        loader::{load, load_mut, RoleHolder},
    },
    state::Init,
};

#[inline(never)]
pub fn process_set_cosigner_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: SetCoSignerRecordIxData = parse(data)?;
    let scope = ix.check()?;
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let cosign_admin = iter.next_signer("cosign_admin")?;
    let ring = iter.next_mut("ring")?;
    let record = iter.next_mut("co_signer_record")?;
    let system_program = iter.next_account("system_program")?;

    // 1. The co-signer admin signs, and an existing record moves its counts to the new scope.
    check_system_program(system_program)?;
    let mut ring = RoleHolder {
        program_id,
        role: RingRole::CosignAdmin,
        signer: cosign_admin,
    }
    .load_mut(ring)?;
    if record.data_len() != 0 {
        let mut stored = load_mut::<CoSigner>(program_id, record)?;
        if stored.signer != ix.signer {
            return Err(CoSigner::INVALID.into());
        }
        let previous = stored.scope().ok_or(CoSigner::INVALID)?;
        ring.co_signers = ring.co_signers.removed(previous)?.added(scope)?;
        stored.scope = scope.bits();
        return Ok(());
    }
    // 2. A new record sits at the signer's canonical PDA.
    ring.co_signers = ring.co_signers.added(scope)?;
    let bump = Pda {
        program_id,
        seeds: &[CoSigner::SEED, ix.signer.as_ref()],
    }
    .create::<CoSigner>(payer, record)?;
    Init(&CoSigner {
        discriminator: CO_SIGNER,
        signer: ix.signer,
        scope: scope.bits(),
        bump,
    })
    .init(record)
}

#[inline(never)]
pub fn process_clear_cosigner_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    no_data(data)?;
    let mut iter = AccountIterator::new(accounts);
    let cosign_admin = iter.next_signer("cosign_admin")?;
    let ring = iter.next_mut("ring")?;
    let record = iter.next_mut("co_signer_record")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;

    // 1. The co-signer admin signs, and the counts drop the record's classes.
    let mut ring = RoleHolder {
        program_id,
        role: RingRole::CosignAdmin,
        signer: cosign_admin,
    }
    .load_mut(ring)?;
    let scope = load::<CoSigner>(program_id, record)?
        .scope()
        .ok_or(CoSigner::INVALID)?;
    ring.co_signers = ring.co_signers.removed(scope)?;
    // 2. The rent goes to a recipient other than the record.
    close_into(record, rent_recipient, CoSigner::INVALID)
}
