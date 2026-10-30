use custom_ring_interface::{
    key_catalog::RingCircuit, merge_disclosure_field_count, CustomRingError, MergeDisclosureRef,
    MergePublicInput, RingPolicy, VIEWING_PUBKEY_TAG,
};
use pinocchio::{Address, ProgramResult};
use spr_interface::instruction::instruction_data::merge_transact::{
    merge_circuit_width, MergeOutputEncryption, MergeTransactIxDataRef,
};
use zolana_ring_policy::ring_id_field;

use crate::instructions::verifier::{ring_key, RingProof};

/// A merge names its owner only to the auditor, the proof binds that opening to the SPP body and any key escrow record.
#[must_use]
pub(crate) struct MergeAudit<'a> {
    pub party_identities: &'a [[u8; 32]; 3],
    pub program_id: &'a Address,
    pub ring: &'a RingPolicy,
    pub anonymous: bool,
    /// `Some` on a key escrow ring alone.
    pub member_registry_root: Option<&'a [u8; 32]>,
    pub output_ring_data_hash: &'a [u8; 32],
    pub disclosure: MergeDisclosureRef<'a>,
    pub spp_body: &'a [u8],
}

impl MergeAudit<'_> {
    #[inline(never)]
    pub fn verify(self) -> ProgramResult {
        let disclosure = self.disclosure;
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
        if self.anonymous && self.output_ring_data_hash != &[0; 32] {
            return Err(CustomRingError::AnonymousRingDataNotZero.into());
        }
        let first_nullifier = merge
            .nullifiers
            .first()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let MergeOutputEncryption::PoseidonCtrV1 { salt, .. } = &merge.output_encryption;
        let public_input = MergePublicInput {
            party_identities: self.party_identities,
            private_tx_hash: merge.private_tx_hash,
            output_utxo_hash: merge.output_utxo_hash,
            first_nullifier,
            ring_id: &ring_id_field(self.program_id.as_array()).map_err(CustomRingError::from)?,
            auditor_pk: &self.ring.auditor_pubkey,
            eph_pk: disclosure.eph_pk,
            ciphertext: disclosure.ciphertext,
            salt,
            fields: disclosure.fields,
            member_registry_root: self.member_registry_root,
        }
        .hash()
        .map_err(CustomRingError::from)?;
        let width = u8::try_from(width).map_err(|_| CustomRingError::InvalidInstructionData)?;
        RingProof {
            proof: disclosure.proof,
            statement: public_input,
            key: ring_key(RingCircuit::Merge { width })?,
        }
        .verify()
    }
}
