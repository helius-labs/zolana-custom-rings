//! The wallet half of a relayed transfer, Ring RPC reads the Merkle paths and records and proves.

use solana_address::Address;
use solana_signature::Signature;
use spr_client::AsyncRpc;
use spr_indexer_api::{SerializablePubkey, SerializableSignature};
use spr_keypair::{NullifierKey, SigningKey};
use zolana_ring_client::rpc::{
    PrepareRelayRequest, ProofInputBytes, RelayIntent, RelayProofInputs, RelayQuote, RelayRail,
    TokenAccountSetup,
};
use zolana_ring_transaction::RingDelivery;

use super::{Anonymous, Delegated, Owner, Rail, RingTransfer, Sealed};
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
            token_account_setup: self.rail.token_account_setup.clone(),
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
            token_account_setup: Vec::new(),
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
    token_account_setup: Vec<TokenAccountSetup>,
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
        let sealed = self.transfer.seal(client).await?;
        let staged = &sealed.pipeline.staged;
        let inputs = &staged.proof_inputs;
        let nullifier_key = staged
            .authority
            .owner
            .clone()
            .ok_or(RingError::MissingAnonymousSigner)?;
        let owner_signature = SerializableSignature(Signature::from(
            self.signer.sign_message(&inputs.message_hash()?)?,
        ));
        let encode = |rail| {
            sealed
                .relay_proof_inputs(rail, nullifier_key)
                .encode()
                .map(ProofInputBytes::new)
        };
        let token_account_setup = self.token_account_setup;
        let intent = match staged.rail.delivery() {
            RingDelivery::Anonymous(plan) => RelayIntent::Anonymous {
                proof_inputs: encode(RelayRail::Anonymous {
                    plan: plan.clone(),
                    exit_token_owner: self.exit_token_owner,
                })?,
                owner_signature,
                token_account_setup,
            },
            RingDelivery::Owned => RelayIntent::Confidential {
                proof_inputs: encode(RelayRail::Confidential)?,
                owner_signature,
                token_account_setup,
            },
            RingDelivery::Delivered => return Err(RingError::MissingInProofOwnerSignature),
        };
        Ok(PreparedRelay::new(PrepareRelayRequest {
            ring: SerializablePubkey(self.transfer.ring.program_id()),
            quote,
            intent,
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
