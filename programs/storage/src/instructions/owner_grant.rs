//! Writes one owner's consent to one reader, for an owner with no key to sign off chain.
//!
//! A wallet signs its Reader grant off chain. A PDA cannot, so its program signs here through CPI.
//!
//! Read after `programs/storage/src/lib.rs`, `program-libs/interface/src/accounts/tracking.rs`. Read
//! before `services/ring-rpc/src/rpc/upstream.rs`.
//!
//! Guarantees:
//! 1. The grant sits at an address that names the registry, the owner and the reader, and the owner alone writes it.
//! 2. A later call changes only whether the grant is active.
//!
//! Relies on:
//! 1. Ring RPC reads the account at the grant's address. No proof and no ring instruction reads it, so a grant moves no funds.

use custom_ring_interface::{storage::StorageError, storage_instruction::OwnerGrantIxData};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    loader::{check_signer, load_tracking_registry, OwnerGrantWrite},
    parse,
};

/// The owner's signature alone authorizes, a program signs its PDA through CPI.
pub fn process_owner_grant_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: &OwnerGrantIxData = parse(data)?;
    let [payer_account, owner_account, registry_account, grant_account, system_program_account, ..] =
        accounts
    else {
        return Err(StorageError::MissingAccounts.into());
    };
    check_signer(payer_account)?;
    check_signer(owner_account)?;
    if !pinocchio_system::check_id(system_program_account.address()) {
        return Err(StorageError::InvalidSystemProgram.into());
    }
    ix.check()?;
    load_tracking_registry(program_id, registry_account)?;
    OwnerGrantWrite {
        program_id,
        payer: payer_account,
        owner: owner_account.address(),
        registry: registry_account.address(),
        ix,
    }
    .write(grant_account)
}
