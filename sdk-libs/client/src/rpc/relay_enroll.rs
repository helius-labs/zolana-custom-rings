use custom_ring_interface::{tracking::TrackingAuthorization, STORAGE_PROGRAM_ID};
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use wincode::{SchemaRead, SchemaWrite};

use super::RelayProofInputsError;

/// `Enroll` data as the wallet built it, its proof proven and its owner's signature still due.
#[derive(Clone, Debug, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct RelayEnrollInputs {
    pub ring_program_id: Address,
    pub owner: Address,
    pub tracking_registry: Address,
    /// Tag 6 first, the program holds every field to the owner's signature and proof.
    pub instruction_data: Vec<u8>,
}

const ENROLL_REQUEST_DOMAIN: &[u8] = b"zolana/ring-rpc-relay-enroll";

/// The ceiling a relayed enrollment asks and its owner checks.
pub const ENROLL_COMPUTE_UNITS: u32 = 400_000;

impl RelayEnrollInputs {
    /// The owner's signature over it spends the relay's budget, it names no quote so a retry keeps it.
    pub fn request_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(ENROLL_REQUEST_DOMAIN)
            .chain_update(self.ring_program_id.as_ref())
            .chain_update(self.owner.as_ref())
            .chain_update(self.tracking_registry.as_ref())
            .chain_update(&self.instruction_data)
            .finalize()
            .into()
    }

    /// `payer, owner, tracking_registry, authorization, system_program`.
    pub fn instruction(&self, fee_payer: Address) -> Instruction {
        let (authorization, _) =
            TrackingAuthorization::find_address(&self.tracking_registry, &self.owner);
        Instruction {
            program_id: STORAGE_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(fee_payer, true),
                AccountMeta::new_readonly(self.owner, true),
                AccountMeta::new(self.tracking_registry, false),
                AccountMeta::new(authorization, false),
                AccountMeta::new_readonly(Address::default(), false),
            ],
            data: self.instruction_data.clone(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, RelayProofInputsError> {
        Ok(wincode::serialize(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelayProofInputsError> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
