//! The wallet half of a relayed transfer, Ring RPC reads the Merkle paths and records and proves.

use solana_address::Address;
use solana_signature::Signature;
use spr_client::AsyncRpc;
use spr_indexer_api::{Base64String, SerializablePubkey, SerializableSignature};
use spr_keypair::SigningKey;
use zolana_ring_client::rpc::{
    PrepareRelayRequest, RelayIntent, RelayProofInputs, RelayQuote, RelayRail,
};
use zolana_ring_transaction::RingDelivery;

use super::{Anonymous, Owner, Rail, RingTransfer};
use crate::{PreparedRelay, RingError};

impl RingTransfer<Anonymous<'_>> {
    /// The hidden owner signs the message hash, the wallet reads no Merkle path and no record.
    pub async fn prepare_relay<C: AsyncRpc + ?Sized>(
        &self,
        client: &C,
        quote: RelayQuote,
    ) -> Result<PreparedRelay, RingError> {
        WalletRelay {
            transfer: self,
            payer: self.rail.owner.transaction.payer(),
            signer: self.rail.signer,
            exit_token_owner: self.rail.exit_token_owner,
        }
        .prepare(client, quote)
        .await
    }
}

impl RingTransfer<Owner<'_>> {
    /// The in-proof owner signs the message hash, the wallet reads no Merkle path and no record.
    pub async fn prepare_relay<C: AsyncRpc + ?Sized>(
        &self,
        client: &C,
        quote: RelayQuote,
    ) -> Result<PreparedRelay, RingError> {
        WalletRelay {
            transfer: self,
            payer: self.rail.transaction.payer(),
            signer: self
                .rail
                .in_proof_owner
                .ok_or(RingError::MissingInProofOwnerSignature)?,
            exit_token_owner: None,
        }
        .prepare(client, quote)
        .await
    }
}

struct WalletRelay<'t, R: Rail> {
    transfer: &'t RingTransfer<R>,
    payer: Address,
    signer: &'t SigningKey,
    exit_token_owner: Option<Address>,
}

impl<R: Rail> WalletRelay<'_, R> {
    async fn prepare<C: AsyncRpc + ?Sized>(
        self,
        client: &C,
        quote: RelayQuote,
    ) -> Result<PreparedRelay, RingError> {
        if self.payer != quote.fee_payer.0 {
            return Err(RingError::RelayPayerMismatch {
                payer: self.payer,
                fee_payer: quote.fee_payer.0,
            });
        }
        let ring = self.transfer.ring;
        let sealed = self.transfer.seal(client).await?;
        let staged = &sealed.pipeline.staged;
        let inputs = &staged.proof_inputs;
        let rail = match staged.rail.delivery() {
            RingDelivery::Anonymous(plan) => RelayRail::Anonymous {
                plan: plan.clone(),
                exit_token_owner: self.exit_token_owner,
            },
            RingDelivery::Owned => RelayRail::Confidential,
            RingDelivery::Delivered => return Err(RingError::MissingInProofOwnerSignature),
        };
        let nullifier_key = staged
            .authority
            .owner
            .clone()
            .ok_or(RingError::MissingAnonymousSigner)?;
        let owner_signature = SerializableSignature(Signature::from(
            self.signer.sign_message(&inputs.message_hash()?)?,
        ));
        let anonymous = matches!(rail, RelayRail::Anonymous { .. });
        let proof_inputs = RelayProofInputs {
            rail,
            ring_program_id: ring.program_id(),
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
            ring: SerializablePubkey(ring.program_id()),
            quote,
            intent: match (anonymous, Base64String(proof_inputs.to_vec())) {
                (true, proof_inputs) => RelayIntent::Anonymous {
                    proof_inputs,
                    owner_signature,
                },
                (false, proof_inputs) => RelayIntent::Confidential {
                    proof_inputs,
                    owner_signature,
                },
            },
        }))
    }
}

#[cfg(test)]
#[path = "../../tests/operations/relay.rs"]
mod tests;
