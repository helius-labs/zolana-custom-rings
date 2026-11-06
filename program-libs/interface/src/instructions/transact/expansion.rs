//! Compact ring frames expand into canonical SPP bytes for settlement and external data hashing.
//!
//! Read after `program-libs/interface/src/instructions/transact.rs` and `program-libs/interface/src/codec/output.rs`.
//! Read before `programs/custom-ring/src/instructions/transfer/processor.rs`.

use spr_interface::instruction::{
    instruction_data::transact::validate_interface_transfers, ExternalDataPreimage, InputUtxo,
    MessageData, OwnerTag, TransactIxData, TransactIxDataRef, TransactOutput, TransactProof,
};

use super::{invalid, RingOutput, RingTransactData, Settlement, SlotBody};
use crate::{
    error::CustomRingError,
    output::{encode_ring_sender_bundle_output, OutputPayload},
    tagged_x25519, AuditorMessage, RingPolicy,
};

impl<'a> RingOutput<'a> {
    pub fn transact_output(&self, reply: &[u8]) -> Result<TransactOutput, CustomRingError> {
        Ok(TransactOutput {
            utxo_hash: *self.hash,
            owner_tag: OwnerTag::Inline(self.owner_tag),
            data: self.payload(reply).map(OutputPayload::encode).transpose()?,
        })
    }

    fn payload<'reply>(&self, reply: &'reply [u8]) -> Option<OutputPayload<'reply>>
    where
        'a: 'reply,
    {
        match self.body {
            SlotBody::None => None,
            SlotBody::Recipient(body) => Some(OutputPayload::Recipient { body, reply }),
            SlotBody::Exit(body) => Some(OutputPayload::Confidential(body)),
        }
    }
}

impl RingTransactData<'_> {
    pub fn auditor_message(&self) -> Vec<u8> {
        AuditorMessage::data(self.tx_viewing_u, self.auditor_ciphertexts())
    }

    /// The SPP data the program forwards, `b` decompressed for SPP's verifier.
    pub fn expand(&self, ring: &RingPolicy) -> Result<TransactIxData, CustomRingError> {
        self.transact_ix_data(ring, self.spp_proof_points()?)
    }

    pub fn spp_instruction_data(&self, ring: &RingPolicy) -> Result<Vec<u8>, CustomRingError> {
        self.spp_instruction_data_under(ring, self.spp_proof_points()?)
    }

    fn spp_proof_points(&self) -> Result<TransactProof, CustomRingError> {
        let b = groth16_solana::decompression::decompress_g2(&self.spp_proof.proof_b)
            .map_err(|_| CustomRingError::InvalidSppProofPoint)?;
        Ok(TransactProof {
            a: self.spp_proof.proof_a,
            b,
            c: self.spp_proof.proof_c,
        })
    }

    /// The tag and the expansion under `proof` in one buffer, the program's heap holds no second copy.
    pub fn spp_instruction_data_under(
        &self,
        ring: &RingPolicy,
        proof: TransactProof,
    ) -> Result<Vec<u8>, CustomRingError> {
        let expanded = self.transact_ix_data(ring, proof)?;
        // The refusal `TransactIxData::serialize` applies, here behind the SPP tag.
        validate_interface_transfers(&expanded.interface_transfers).map_err(invalid)?;
        let len = wincode::serialized_size(&expanded).map_err(invalid)?;
        let mut data = Vec::with_capacity(usize::try_from(len).map_err(invalid)?.saturating_add(1));
        data.push(self.rail.spp_tag());
        wincode::serialize_into(&mut data, &expanded).map_err(invalid)?;
        Ok(data)
    }

    /// The external data hash the SPP proof binds, computable before either proof exists.
    pub fn external_data_hash(
        &self,
        ring: &RingPolicy,
        settlements: &[Settlement<'_>],
    ) -> Result<[u8; 32], CustomRingError> {
        let data = self.spp_instruction_data_under(ring, TransactProof::zeroed())?;
        let (tag, expanded) = data
            .split_first()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        // 1. SPP's own parser fixes the prefix boundary, the bytes before `private_tx_hash`.
        let (_, prefix) =
            TransactIxDataRef::parse_with_external_data_prefix(expanded).map_err(invalid)?;
        let tag = [*tag];
        let mut preimage = ExternalDataPreimage::new(&tag, prefix);
        // 2. The caller must supply settlements in transfer order. Each pair binds asset then user after the prefix.
        // Inline owner tags are already in the prefix.
        for settlement in settlements {
            preimage.push_settlement(settlement.asset_account, settlement.user_account)?;
        }
        Ok(preimage.finish()?)
    }

    /// The expansion under `proof`, a client sizes the transaction with a zeroed one.
    pub fn transact_ix_data(
        &self,
        ring: &RingPolicy,
        proof: TransactProof,
    ) -> Result<TransactIxData, CustomRingError> {
        self.validate_under(self.audit_stream()?)?;
        // The auditor's `u` without its tag, the program takes it from the account and a frame names no reader.
        let view_tag = auditor_tag(ring);
        Ok(TransactIxData {
            expiry_unix_ts: u64::from(self.expiry_unix_ts),
            tx_viewing_pk: tagged_x25519(self.tx_viewing_u),
            salt: *self.salt,
            interface_transfers: self.interface_transfers.clone(),
            data_hash: self.extensions.data_hash.copied(),
            ring_data_hash: self.extensions.ring_data_hash.copied(),
            outputs: {
                let mut outputs = Vec::with_capacity(self.outputs.len());
                for (output, reply) in self.outputs.iter().zip(self.slot_replies()) {
                    outputs.push(output.transact_output(reply)?);
                }
                outputs
            },
            // The auditor message stays last.
            messages: self
                .sender
                .map(|sender| {
                    encode_ring_sender_bundle_output(sender.body).map(|data| MessageData {
                        view_tag: *sender.tag,
                        data,
                    })
                })
                .transpose()?
                .into_iter()
                .chain(self.extensions.messages.iter().map(|message| MessageData {
                    view_tag: *message.view_tag,
                    data: message.data.to_vec(),
                }))
                .chain([MessageData {
                    view_tag,
                    data: self.auditor_message(),
                }])
                .collect(),
            private_tx_hash: *self.private_tx_hash,
            circuit: self.circuit(),
            proof,
            inputs: self.input_utxos().collect(),
            tree_contexts: self.input_trees.contexts(),
        })
    }

    fn input_utxos(&self) -> impl Iterator<Item = InputUtxo> + '_ {
        self.nullifiers
            .iter()
            .enumerate()
            .map(|(input, nullifier)| InputUtxo {
                nullifier_hash: *nullifier,
                tree_index: self.input_trees.tree_index(input),
            })
    }

    fn auditor_ciphertexts(&self) -> impl Iterator<Item = &[u8]> + Clone {
        let records = self.outputs.iter().map(|output| output.record);
        let tails = self
            .outputs
            .iter()
            .filter_map(|output| output.tail.map(|tail| &tail[..]));
        core::iter::once(self.envelope).chain(records).chain(tails)
    }
}

fn auditor_tag(ring: &RingPolicy) -> [u8; 32] {
    core::array::from_fn(|index| ring.auditor_pubkey[index + 1])
}
