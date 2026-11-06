//! The one ring proof of a transfer, one request over the audit and policy sections.

use custom_ring_interface::{key_catalog::RingCircuit, CustomRingProof, ParsedTransact};
use spr_client::AsyncRpc;
use spr_hasher::primitives::solana_owner_identity;
use spr_transaction::TransactionError;

use super::{audit::AuditSection, policy::PolicyProving, Assembled};
use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    prover::{to_instruction_proof, RingRequest},
    request::TransferParams,
    RingError,
};

pub(crate) struct TransferRequest<'a> {
    pub circuit: RingCircuit,
    pub public_input_hash: [u8; 32],
    pub body: Box<TransferParams<'a>>,
}

impl Assembled {
    pub(crate) fn request(&self) -> Result<TransferRequest<'_>, RingError> {
        let frame = &self.frame;
        let parts = &frame.parts;
        let circuit = frame.policy.circuit();
        let audit = AuditSection {
            rail: &frame.rail,
            sealed: &frame.sealed,
            inputs: &frame.proof_inputs,
            auditor: &self.auditor,
        };
        let too_many = |got: usize| TransactionError::TooManyInputs {
            got,
            max: usize::from(u8::MAX),
        };
        let byte = |count: usize| u8::try_from(count).map_err(|_| too_many(count));
        let owner_run = &frame.accounts.owner_signers;
        let parsed = ParsedTransact::new(parts.data()?)?;
        let stream = parsed.audit_stream();
        let class = stream.key.class();
        let input_nullifiers = parsed.padded_nullifiers().copied().collect();
        let entries = match parts.entry {
            true => audit.entry_openings(class)?,
            false => Vec::new(),
        };
        let transfer = TransferParams {
            public_input_hash: self.public_input_hash,
            audit: audit.params()?,
            approval_mask: frame.policy.approval.bits(),
            approval_totals: parts.extensions.approval_totals,
            signer_data_counts: parts
                .extensions
                .signer_data_counts
                .map(|counts| counts.packed()),
            approval_blinder: frame
                .approval_opening
                .as_ref()
                .map(|opening| opening.blinder.0),
            output_count: byte(parts.outputs.len())?,
            outputs: audit.output_openings(stream.capacity)?,
            input_count: byte(frame.published_inputs)?,
            inputs: audit.input_openings(class)?,
            input_nullifiers,
            input_nullifier_chain: parsed.input_nullifier_chain()?,
            entries,
            signer_count: byte(owner_run.len())?,
            signers: signer_identities(owner_run, class)?,
            rows: frame.policy.rows.clone(),
            private_tx_hash: parts.private_tx_hash,
            private_tx_blinding: frame.private_tx_blinding,
            in_proof: parts.in_proof_owner.is_some(),
            hidden: parts.anonymous.is_some(),
            delegate: parts.rail.is_delegate(),
            sender: self.sender,
            party_identities: self.party_identities.to_vec(),
            tracking: frame.policy.tracking_params()?,
            policy: frame.policy.params(&PolicyProving {
                ring_id: frame.ring_id,
                public_assets: &frame.public_assets,
                public_amounts: &frame.public_amount_fields,
                public_gross: &frame.public_gross,
            })?,
        };
        Ok(TransferRequest {
            circuit,
            public_input_hash: self.public_input_hash,
            body: Box::new(transfer),
        })
    }
}

/// The owner run in its order, zero past the run.
fn signer_identities(
    owners: &[solana_address::Address],
    slots: usize,
) -> Result<Vec<[u8; 32]>, RingError> {
    let mut identities = owners
        .iter()
        .map(|owner| Ok(solana_owner_identity(owner.as_array())?))
        .collect::<Result<Vec<_>, RingError>>()?;
    identities.resize(slots, [0; 32]);
    Ok(identities)
}

impl TransferRequest<'_> {
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<CustomRingProof, RingError> {
        let proof = RingRequest::new(self.circuit, &self.body)?
            .prove(client, self.public_input_hash)
            .await?;
        to_instruction_proof(proof)
    }
}
