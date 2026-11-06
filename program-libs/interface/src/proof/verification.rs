//! The one Groth16 check behind every ring proof, and the enrollment check the storage program runs.
//!
//! A ring proof has one public input, the statement hash the caller rebuilt, and a wrong element fails here.
//!
//! Read after `program-libs/interface/src/proof/key_catalog.rs`. Read before
//! `programs/custom-ring/src/instructions/verification/verifier.rs`, `programs/storage/src/instructions/enroll.rs`.

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use solana_program_error::ProgramError;

use crate::{
    key_catalog::RingCircuit, storage::StorageError, storage_instruction::EnrollIxData,
    tracking::owner_member, verifying_key, CustomRingError, CustomRingProof, RegisterKeyStatement,
};

type ProgramResult = Result<(), ProgramError>;

#[must_use]
pub struct RingProof<'a> {
    pub proof: &'a CustomRingProof,
    pub statement: [u8; 32],
    pub key: &'a Groth16Verifyingkey<'a>,
}

impl RingProof<'_> {
    /// Every ring key carries a BSB22 commitment, a proof without one never verifies.
    #[inline(never)]
    pub fn verify(self) -> ProgramResult {
        let points = &self.proof.groth16;
        Groth16Verifier::new_with_commitment(
            &decompress_g1(&points.proof_a).map_err(undecodable)?,
            &decompress_g2(&points.proof_b).map_err(undecodable)?,
            &decompress_g1(&points.proof_c).map_err(undecodable)?,
            &decompress_g1(&self.proof.commitment).map_err(undecodable)?,
            &decompress_g1(&self.proof.commitment_pok).map_err(undecodable)?,
            &[self.statement],
            self.key,
        )
        .map_err(|_| CustomRingError::UnsupportedCircuit)?
        .verify()
        .map_err(|_| CustomRingError::ProofVerificationFailed)?;
        Ok(())
    }
}

/// The registry supplies ring and auditor key and the signer the member, a proof for any other one fails here.
#[must_use]
pub struct RegisterKeyCheck<'a> {
    pub ring_id: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; crate::TAGGED_X25519_KEY_LEN],
    pub owner: &'a solana_address::Address,
    pub ix: &'a EnrollIxData,
    pub proof: &'a CustomRingProof,
}

impl RegisterKeyCheck<'_> {
    pub fn verify(self) -> ProgramResult {
        let member = owner_member(self.owner)?;
        let statement = RegisterKeyStatement {
            ring_id: self.ring_id,
            member: &member,
            nullifier_pk: &self.ix.nullifier_pk,
            list_tag: &self.ix.list_tag,
            auditor_pubkey: self.auditor_pubkey,
            eph_u: &self.ix.eph_u,
            ciphertext: &self.ix.ciphertext,
        }
        .hash()
        .map_err(|_| StorageError::HashingFailed)?;
        RingProof {
            proof: self.proof,
            statement,
            key: verifying_key(RingCircuit::RegisterKey).ok_or(StorageError::UnsupportedBatch)?,
        }
        .verify()
        .map_err(|_| StorageError::ProofVerificationFailed.into())
    }
}

fn undecodable<E>(_: E) -> CustomRingError {
    CustomRingError::InvalidRingProofPoint
}

#[cfg(test)]
mod tests {
    use bytemuck::Zeroable;

    use super::*;

    fn verify(proof: &CustomRingProof, key: &Groth16Verifyingkey<'_>) -> ProgramResult {
        RingProof {
            proof,
            statement: [7; 32],
            key,
        }
        .verify()
    }

    #[test]
    fn each_proof_stage_fails_with_its_own_code() {
        let key = verifying_key(RingCircuit::RegisterKey).unwrap();
        let identity = CustomRingProof::zeroed();
        assert_eq!(
            verify(&identity, key),
            Err(CustomRingError::ProofVerificationFailed.into())
        );
        let mut off_curve = identity;
        off_curve.groth16.proof_a = [0x10; 32];
        assert_eq!(
            verify(&off_curve, key),
            Err(CustomRingError::InvalidRingProofPoint.into())
        );
        let without_commitment = Groth16Verifyingkey {
            nr_pubinputs: key.nr_pubinputs,
            vk_alpha_g1: key.vk_alpha_g1,
            vk_beta_g2: key.vk_beta_g2,
            vk_gamma_g2: key.vk_gamma_g2,
            vk_delta_g2: key.vk_delta_g2,
            vk_ic: key.vk_ic,
            vk_commitment: None,
        };
        assert_eq!(
            verify(&identity, &without_commitment),
            Err(CustomRingError::UnsupportedCircuit.into())
        );
    }
}
