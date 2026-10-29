//! Transfer authorization remains the consumer's responsibility.

use bytemuck::{Pod, Zeroable};
use custom_ring_interface::{
    domain,
    storage::Revision,
    storage_instruction::{tag, UpdateMode},
    CustomRingError, CustomRingProof,
};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use spr_hasher::{hash_chain::create_hash_chain_4_from_slice, primitives::right_align};
use zolana_ring_policy::{registry_field, EncodedRuleTable};

use instructions::{process_initialize_ix, process_update_ix, process_verify_policy_ix};

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

mod instructions;
mod loader;

/// With the authority's address.
pub const REGISTRY_SEED: &[u8] = b"policy-store";

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct InitializeIxData {
    pub grace_slots: [u8; 8],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct VerifyPolicyIxData {
    pub revision: Revision,
    pub table: EncodedRuleTable,
    pub action: [u8; 32],
    pub sender: [u8; 32],
    pub proof: CustomRingProof,
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (instruction, data) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match *instruction {
        tag::INITIALIZE => process_initialize_ix(program_id, accounts, data),
        tag::UPDATE => process_update_ix(program_id, accounts, data, UpdateMode::Graced),
        tag::UPDATE_IMMEDIATE => {
            process_update_ix(program_id, accounts, data, UpdateMode::Immediate)
        }
        tag::VERIFY_POLICY => process_verify_policy_ix(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

pub fn chain_start(registry: &Address, revision: Revision) -> Result<[u8; 32], CustomRingError> {
    Ok(create_hash_chain_4_from_slice(&[
        domain::field(domain::APPLY_RECORDS),
        registry_field(registry.as_array())?,
        right_align(&revision.value().to_be_bytes()),
    ])?)
}

pub(crate) fn parse<T: Pod>(data: &[u8]) -> Result<&T, ProgramError> {
    bytemuck::try_from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)
}
