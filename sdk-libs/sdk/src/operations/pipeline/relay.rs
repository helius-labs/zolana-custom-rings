//! The wallet half of a relayed transfer, Ring RPC reads the Merkle paths and records and proves.

use solana_signature::Signature;
use spr_client::AsyncRpc;
use spr_indexer_api::{SerializablePubkey, SerializableSignature};
use spr_keypair::NullifierKey;
use zolana_ring_client::rpc::{
    PrepareRelayRequest, ProofInputBytes, RelayIntent, RelayProofInputs, RelayQuote, RelayRail,
};
use zolana_ring_transaction::RingDelivery;

use super::{Anonymous, Delegated, RingTransfer, Sealed};
use crate::{PreparedRelay, RingError};

impl RingTransfer<Anonymous<'_>> {
    /// The hidden owner signs the message hash, the wallet reads no Merkle path and no record.
    pub async fn prepare_relay<C: AsyncRpc + ?Sized>(
        &self,
        client: &C,
        quote: RelayQuote,
    ) -> Result<PreparedRelay, RingError> {
        let payer = self.rail.owner.transaction.payer();
        if payer != quote.fee_payer.0 {
            return Err(RingError::RelayPayerMismatch {
                payer,
                fee_payer: quote.fee_payer.0,
            });
        }
        let sealed = self.seal(client).await?;
        let staged = &sealed.pipeline.staged;
        let inputs = &staged.proof_inputs;
        let RingDelivery::Anonymous(plan) = staged.rail.delivery() else {
            return Err(RingError::NotAnonymousRing);
        };
        let nullifier_key = staged
            .authority
            .owner
            .clone()
            .ok_or(RingError::MissingAnonymousSigner)?;
        let owner_signature = self.rail.signer.sign_message(&inputs.message_hash()?)?;
        let proof_inputs = sealed
            .relay_proof_inputs(
                RelayRail::Anonymous {
                    plan: plan.clone(),
                    exit_token_owner: self.rail.exit_token_owner,
                },
                nullifier_key,
            )
            .encode()?;
        Ok(PreparedRelay::new(PrepareRelayRequest {
            ring: SerializablePubkey(self.ring.program_id()),
            quote,
            intent: RelayIntent::Anonymous {
                proof_inputs: ProofInputBytes::new(proof_inputs),
                owner_signature: SerializableSignature(Signature::from(owner_signature)),
                token_account_setup: self.rail.token_account_setup.clone(),
            },
        }))
    }
}

impl RingTransfer<Delegated<'_>> {
    /// Reads accounts only, the relayed delegate rail proves the result.
    pub async fn relay_proof_inputs<C: AsyncRpc + ?Sized>(
        &self,
        client: &C,
    ) -> Result<RelayProofInputs, RingError> {
        let sealed = self.seal(client).await?;
        Ok(sealed.relay_proof_inputs(
            RelayRail::Delegate {
                delegate: self.rail.delegate,
            },
            self.rail.source_key.clone(),
        ))
    }
}

impl Sealed<'_> {
    fn relay_proof_inputs(&self, rail: RelayRail, nullifier_key: NullifierKey) -> RelayProofInputs {
        let staged = &self.pipeline.staged;
        let inputs = &staged.proof_inputs;
        RelayProofInputs {
            rail,
            ring_program_id: self.pipeline.ring.program_id(),
            sender: staged.sender,
            nullifier_key,
            tx_viewing_key: staged.rail.tx_viewing_key().clone(),
            audit_ephemeral_key: self.sealed.ephemeral_secret().clone(),
            inputs: inputs.input_utxos.clone(),
            outputs: inputs.output_utxos.clone(),
            external_data: inputs.external_data.clone(),
            interface_transfer_accounts: staged.interface_transfer_accounts.clone(),
            blinding_seed: inputs.blinding_seed,
            output_tree_id: inputs.output_tree_id,
        }
    }
}

#[cfg(test)]
#[path = "../../tests/operations/relay.rs"]
mod tests;
