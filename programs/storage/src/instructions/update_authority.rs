//! Hands a policy registry to a new authority.
//!
//! Read after `programs/storage/src/lib.rs`, `program-libs/interface/src/accounts/storage.rs`. Read
//! before `programs/storage/src/instructions/update.rs`.
//!
//! Guarantees:
//! 1. Both keys sign, so a mistyped key cannot lock the registry.
//! 2. The old authority loses every right in the instruction, and no root moves.

use custom_ring_interface::storage::StorageError;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::loader::{check_authority, check_signer, load_registry_mut};

pub fn process_update_authority_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(StorageError::InvalidInstructionData.into());
    }
    let [authority_account, new_authority_account, registry_account, ..] = accounts else {
        return Err(StorageError::MissingAccounts.into());
    };
    check_signer(authority_account)?;
    check_signer(new_authority_account)?;
    let mut registry = load_registry_mut(program_id, registry_account)?;
    check_authority(&registry, authority_account)?;
    registry.authority = *new_authority_account.address();
    Ok(())
}
