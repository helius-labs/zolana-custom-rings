use std::sync::Arc;

use async_trait::async_trait;
use solana_address::Address;
use solana_commitment_config::CommitmentLevel;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::{PresignerError, Signer, SignerError};
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use solana_transaction_status_client_types::TransactionConfirmationStatus;
use spr_client::{sign_transaction, AsyncRpc, ClientError, RpcSendTransactionConfig};

use crate::{
    error::RingRpcError,
    relay::RelayError,
    relay_submit::{CollectedSignature, RelaySubmit, RelayTransaction},
    storage_chain::LatestBlockhash,
};

#[async_trait]
pub trait RelayChain: Send + Sync {
    async fn slot(&self) -> Result<u64, RingRpcError>;

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError>;

    async fn block_height(&self) -> Result<u64, RingRpcError>;

    /// A transaction the cluster already processed counts as sent, one its preflight refuses fails.
    async fn send(&self, transaction: &VersionedTransaction) -> Result<(), RingRpcError>;

    /// `None` until the transaction is confirmed or failed.
    async fn outcome(&self, signature: Signature) -> Result<Option<ChainOutcome>, RingRpcError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainOutcome {
    Confirmed { slot: u64 },
    Failed { reason: String },
}

pub struct SolanaRelayChain<R> {
    rpc: R,
}

/// Signs as the fee payer, every other signature arrives collected.
pub struct FeePayerSubmit {
    fee_payer: Keypair,
    chain: Arc<dyn RelayChain>,
}

/// A collected signature, refused unless it signs the message.
struct Presigned(CollectedSignature);

impl<R: AsyncRpc> SolanaRelayChain<R> {
    pub fn new(rpc: R) -> Self {
        Self { rpc }
    }
}

#[async_trait]
impl<R: AsyncRpc> RelayChain for SolanaRelayChain<R> {
    async fn slot(&self) -> Result<u64, RingRpcError> {
        Ok(self.rpc.get_slot().await?)
    }

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError> {
        Ok(self.rpc.get_latest_blockhash().await?.into())
    }

    async fn block_height(&self) -> Result<u64, RingRpcError> {
        Ok(self.rpc.get_block_height().await?)
    }

    async fn send(&self, transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
        let config = RpcSendTransactionConfig {
            preflight_commitment: Some(CommitmentLevel::Confirmed),
            ..RpcSendTransactionConfig::default()
        };
        let Err(error) = self
            .rpc
            .send_transaction_with_config(transaction, config)
            .await
        else {
            return Ok(());
        };
        let refusal = match &error {
            ClientError::SolanaRpcTransaction { source, .. } => source.get_transaction_error(),
            _ => None,
        };
        match refusal {
            Some(TransactionError::AlreadyProcessed) => Ok(()),
            Some(refused) => Err(RelayError::SendRefused {
                reason: refused.to_string(),
            }
            .into()),
            None => Err(error.into()),
        }
    }

    async fn outcome(&self, signature: Signature) -> Result<Option<ChainOutcome>, RingRpcError> {
        let statuses = self.rpc.get_signature_statuses(vec![signature]).await?;
        let Some(Some(status)) = statuses.into_iter().next() else {
            return Ok(None);
        };
        if !matches!(
            status.confirmation_status,
            Some(
                TransactionConfirmationStatus::Confirmed | TransactionConfirmationStatus::Finalized
            )
        ) {
            return Ok(None);
        }
        Ok(Some(match status.err {
            None => ChainOutcome::Confirmed { slot: status.slot },
            Some(error) => ChainOutcome::Failed {
                reason: error.to_string(),
            },
        }))
    }
}

impl FeePayerSubmit {
    pub fn new(fee_payer: Keypair, chain: Arc<dyn RelayChain>) -> Self {
        Self { fee_payer, chain }
    }
}

#[async_trait]
impl RelaySubmit for FeePayerSubmit {
    fn fee_payer(&self) -> Address {
        self.fee_payer.pubkey()
    }

    async fn submit(&self, transaction: RelayTransaction) -> Result<Signature, RingRpcError> {
        let presigned: Vec<Presigned> = transaction.signatures.into_iter().map(Presigned).collect();
        let signed = {
            let mut signers: Vec<&dyn Signer> = vec![&self.fee_payer];
            signers.extend(presigned.iter().map(|signer| signer as &dyn Signer));
            sign_transaction(transaction.message, &signers)?
        };
        self.chain.send(&signed).await?;
        Ok(signed.signatures[0])
    }
}

impl Signer for Presigned {
    fn try_pubkey(&self) -> Result<Address, SignerError> {
        Ok(self.0.signer)
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        match self.0.signature.verify(self.0.signer.as_ref(), message) {
            true => Ok(self.0.signature),
            false => Err(PresignerError::VerificationFailure.into()),
        }
    }

    fn is_interactive(&self) -> bool {
        false
    }
}
