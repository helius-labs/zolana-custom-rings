//! The wallet half of a relayed transfer, Ring RPC reads the Merkle paths and records and proves.

use solana_signature::Signature;
use spr_client::AsyncRpc;
use spr_indexer_api::{Base64String, SerializablePubkey, SerializableSignature};
use zolana_ring_client::rpc::{
    PrepareRelayRequest, RelayIntent, RelayProofInputs, RelayQuote, RelayRail,
};
use zolana_ring_transaction::RingDelivery;

use super::{Anonymous, RingTransfer};
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
        let proof_inputs = RelayProofInputs {
            rail: RelayRail::Anonymous {
                plan: plan.clone(),
                exit_token_owner: self.rail.exit_token_owner,
            },
            ring_program_id: self.ring.program_id(),
            sender: staged.sender,
            nullifier_key,
            tx_viewing_key: staged.rail.tx_viewing_key().clone(),
            audit_ephemeral_key: sealed.sealed.ephemeral_secret().clone(),
            inputs: inputs.input_utxos.clone(),
            outputs: inputs.output_utxos.clone(),
            external_data: inputs.external_data.clone(),
            interface_transfer_accounts: staged.interface_transfer_accounts.clone(),
            blinding_seed: inputs.blinding_seed,
            output_tree_id: inputs.output_tree_id,
        }
        .encode()?;
        Ok(PreparedRelay::new(PrepareRelayRequest {
            ring: SerializablePubkey(self.ring.program_id()),
            quote,
            intent: RelayIntent::Anonymous {
                proof_inputs: Base64String(proof_inputs.to_vec()),
                owner_signature: SerializableSignature(Signature::from(owner_signature)),
                token_account_setup: self.rail.token_account_setup.clone(),
            },
        }))
    }
}

#[cfg(test)]
#[path = "../../tests/operations/relay.rs"]
mod tests;
