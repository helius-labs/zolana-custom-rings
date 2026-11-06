//! Enrolls an owner's keys in a ring's tracking registry, or rotates its viewing key.
//!
//! An SPP sender names any nullifier key on an output, and SPP never sees the secret behind it. A ring
//! needs its auditor able to compute each nullifier and needs an owner's salted lists to bind. Enrollment
//! proves both secrets are sealed to the auditor, once, before any proof can read the row.
//!
//! Read after `programs/storage/src/lib.rs`, `program-libs/interface/src/accounts/tracking.rs`. Read
//! before `prover/circuits/registry/register_key.go`, `programs/storage/src/instructions/apply_enrollments.rs`.
//!
//! Guarantees:
//! 1. The owner signs, a program signs its PDA through CPI, and any payer may fund the account.
//! 2. A first enrollment verifies `RegisterKey` with the ring id, member and auditor key the program supplies, a proof for another ring, member or auditor fails.
//! 3. A rotation carries no proof and moves only the viewing key, it leaves the account's applied state and every root as they were.
//! 4. The instruction moves no root and reads the registry alone, so enrollment traffic takes no write lock on it.
//!
//! Relies on:
//! 1. The ring pins the registry by address. The registry's ring id and auditor key are its creator's word.
//! 2. An account grants nothing until an apply places it under a root, because every check reads the root.

use custom_ring_interface::{
    storage::StorageError, storage_instruction::EnrollRequest, RegisterKeyCheck,
};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::loader::{
    check_signer, load_owned_tracking_authorization_mut, load_tracking_registry,
    TrackingAuthorizationInit,
};

pub fn process_enroll_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let EnrollRequest { ix, proof } = EnrollRequest::parse(data)?;
    let [payer_account, owner_account, registry_account, authorization_account, system_program_account, ..] =
        accounts
    else {
        return Err(StorageError::MissingAccounts.into());
    };
    // 1. The owner's signature authorizes, the payer only funds.
    check_signer(payer_account)?;
    check_signer(owner_account)?;
    if !pinocchio_system::check_id(system_program_account.address()) {
        return Err(StorageError::InvalidSystemProgram.into());
    }
    ix.check()?;
    // 2. An existing account is a rotation, its stored registry and owner stand for the PDA derivation.
    if authorization_account.data_len() != 0 {
        if proof.is_some() {
            return Err(StorageError::EnrollmentProofShape.into());
        }
        let mut authorization = load_owned_tracking_authorization_mut(
            program_id,
            registry_account.address(),
            authorization_account,
        )?;
        if &authorization.owner != owner_account.address() {
            return Err(StorageError::InvalidTrackingAuthorization.into());
        }
        return authorization.rotate(ix).map_err(Into::into);
    }
    // 3. A first enrollment proves the seal, then takes its account at the PDA that names registry and owner.
    let proof = proof.ok_or(StorageError::EnrollmentProofShape)?;
    let registry = load_tracking_registry(program_id, registry_account)?;
    RegisterKeyCheck {
        ring_id: &registry.ring_id,
        auditor_pubkey: &registry.auditor_pubkey,
        owner: owner_account.address(),
        ix,
        proof,
    }
    .verify()?;
    TrackingAuthorizationInit {
        program_id,
        payer: payer_account,
        owner: owner_account.address(),
        registry: registry_account.address(),
        ix,
    }
    .init(authorization_account)
}
