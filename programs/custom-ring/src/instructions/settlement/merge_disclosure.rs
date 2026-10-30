use custom_ring_interface::{
    key_catalog::RingCircuit, merge_disclosure_field_count, CustomRingError,
    MergeAnonymousPublicInput, MergeDisclosureRef, RingProgramConfig, VIEWING_PUBKEY_TAG,
};
use pinocchio::{Address, ProgramResult};
use spr_interface::instruction::instruction_data::merge_transact::{
    merge_circuit_width, MergeOutputEncryption, MergeTransactIxDataRef,
};
use zolana_ring_policy::ring_id_field;

use crate::instructions::verifier::{ring_key, RingProof};

/// An anonymous merge names its owner only to the auditor, the proof binds that opening to the SPP body.
#[must_use]
pub(crate) struct MergeAudit<'a> {
    pub party_identities: &'a [[u8; 32]; 3],
    pub program_id: &'a Address,
    pub config: &'a RingProgramConfig,
    pub anonymous: bool,
    pub member_registry_root: &'a [u8; 32],
    pub output_ring_data_hash: &'a [u8; 32],
    pub disclosure: Option<MergeDisclosureRef<'a>>,
    pub spp_body: &'a [u8],
}

impl MergeAudit<'_> {
    #[inline(never)]
    pub fn verify(self) -> ProgramResult {
        let disclosure = match (self.anonymous, self.disclosure) {
            (false, None) => return verify_escrow_merge(self.member_registry_root, self.spp_body),
            (false, Some(_)) => return Err(CustomRingError::InvalidMergeDisclosure.into()),
            (true, None) => return Err(CustomRingError::MissingMergeDisclosure.into()),
            (true, Some(disclosure)) => disclosure,
        };
        let merge = MergeTransactIxDataRef::from_bytes(self.spp_body)
            .map_err(|_| CustomRingError::InvalidInstructionData)?;
        let width = merge_circuit_width(merge.nullifiers.len())
            .ok_or(CustomRingError::InvalidInstructionData)?;
        if disclosure.fields.len() != merge_disclosure_field_count(width) {
            return Err(CustomRingError::MergeDisclosureWidth.into());
        }
        if disclosure.eph_pk[0] != VIEWING_PUBKEY_TAG {
            return Err(CustomRingError::InvalidMergeDisclosure.into());
        }
        if self.output_ring_data_hash != &[0; 32] {
            return Err(CustomRingError::AnonymousRingDataNotZero.into());
        }
        let first_nullifier = merge
            .nullifiers
            .first()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let MergeOutputEncryption::PoseidonCtrV1 { salt, .. } = &merge.output_encryption;
        let public_input = MergeAnonymousPublicInput {
            party_identities: self.party_identities,
            private_tx_hash: merge.private_tx_hash,
            output_utxo_hash: merge.output_utxo_hash,
            first_nullifier,
            ring_id: &ring_id_field(self.program_id.as_array()).map_err(CustomRingError::from)?,
            auditor_pk: &self.config.auditor_pubkey,
            eph_pk: disclosure.eph_pk,
            ciphertext: disclosure.ciphertext,
            salt,
            fields: disclosure.fields,
        }
        .hash()
        .map_err(CustomRingError::from)?;
        let width = u8::try_from(width).map_err(|_| CustomRingError::InvalidInstructionData)?;
        RingProof {
            proof: disclosure.proof,
            statement: public_input,
            key: ring_key(RingCircuit::AnonymousMerge { width })?,
        }
        .verify()
    }
}

/// The escrow-mode merge statement, refused without a ring merge proof.
fn verify_escrow_merge(_member_registry_root: &[u8; 32], _spp_body: &[u8]) -> ProgramResult {
    Err(CustomRingError::EscrowMergeUnverified.into())
}
