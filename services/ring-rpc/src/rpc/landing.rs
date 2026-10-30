use async_trait::async_trait;
use solana_commitment_config::CommitmentLevel;
use solana_hash::Hash;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use solana_transaction_status_client_types::TransactionConfirmationStatus;
use spr_client::{AsyncRpc, AsyncSolanaRpc, ClientError, RpcSendTransactionConfig};

use crate::{error::RingRpcError, relay::RelayError};

#[async_trait]
pub trait ChainSubmit: Send + Sync {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatestBlockhash {
    pub blockhash: Hash,
    pub last_valid_block_height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Attempt {
    pub signature: Signature,
    pub last_valid_block_height: u64,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Landing {
    Pending,
    Landed(ChainOutcome),
    /// Final, the blockhash can no longer land the signature.
    Expired,
}

pub struct SolanaChain {
    rpc: AsyncSolanaRpc,
}

impl From<(Hash, u64)> for LatestBlockhash {
    fn from((blockhash, last_valid_block_height): (Hash, u64)) -> Self {
        Self {
            blockhash,
            last_valid_block_height,
        }
    }
}

impl Attempt {
    pub async fn landing(self, chain: &dyn ChainSubmit) -> Result<Landing, RingRpcError> {
        if let Some(outcome) = chain.outcome(self.signature).await? {
            return Ok(Landing::Landed(outcome));
        }
        if chain.block_height().await? <= self.last_valid_block_height {
            return Ok(Landing::Pending);
        }
        // The signature can land between the first lookup and the height read.
        Ok(chain
            .outcome(self.signature)
            .await?
            .map_or(Landing::Expired, Landing::Landed))
    }
}

impl SolanaChain {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc: AsyncSolanaRpc::new(rpc_url),
        }
    }
}

#[async_trait]
impl ChainSubmit for SolanaChain {
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
        // Without history a landed signature reads as expired once the status cache drops it.
        let statuses = self
            .rpc
            .client()
            .get_signature_statuses_with_history(&[signature])
            .await
            .map_err(|error| ClientError::Rpc(format!("get_signature_statuses: {error}")))?
            .value;
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
