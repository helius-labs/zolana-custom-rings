use async_trait::async_trait;
use custom_ring_interface::ApplyRecordsIxData;
use custom_ring_sdk::{RingClient, StorageApplyProof};
use solana_account::Account;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use spr_client::{
    AsyncProverClient, AsyncRpc, AsyncSolanaRpc, AsyncZolanaClient, AsyncZolanaIndexer,
    RpcSendTransactionConfig,
};
use zolana_ring_client::AsyncRingIndexer;
use zolana_ring_indexer::rpc::{
    GetStorageApplyProofInputsRequest, GetStorageApplyProofInputsResponse,
};
use zolana_ring_member_registry::ApplyProofInputs;

use crate::{
    error::RingRpcError,
    upstream::{ChainSource, RingConfiguration, TransactionSource, Upstreams},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionOutcome {
    Unknown,
    Succeeded,
    Failed,
}

#[async_trait]
pub trait StorageChain: Send + Sync {
    async fn slot(&self) -> Result<u64, RingRpcError>;

    async fn block_height(&self) -> Result<u64, RingRpcError>;

    async fn account(&self, address: Address) -> Result<Option<Account>, RingRpcError>;

    async fn ring_config(&self, ring: Address) -> Result<Option<RingConfiguration>, RingRpcError>;

    async fn apply_inputs(
        &self,
        request: GetStorageApplyProofInputsRequest,
    ) -> Result<GetStorageApplyProofInputsResponse, RingRpcError>;

    async fn prove_apply(
        &self,
        inputs: &ApplyProofInputs,
    ) -> Result<ApplyRecordsIxData, RingRpcError>;

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError>;

    async fn send(&self, transaction: &VersionedTransaction) -> Result<Signature, RingRpcError>;

    async fn outcome(&self, signature: Signature) -> Result<TransactionOutcome, RingRpcError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatestBlockhash {
    pub blockhash: Hash,
    pub last_valid_block_height: u64,
}

pub struct LiveStorageChain {
    source: ChainSource,
    client: RingClient<AsyncSolanaRpc, AsyncZolanaIndexer>,
}

impl LiveStorageChain {
    /// The prover serves the ring apply proofs.
    pub fn connect(upstreams: Upstreams<'_>, prover_url: &str) -> Result<Self, RingRpcError> {
        let source = ChainSource::connect(upstreams)?;
        let zolana = AsyncZolanaClient::new(
            AsyncSolanaRpc::new(upstreams.rpc_url),
            AsyncZolanaIndexer::new(upstreams.indexer_url),
            AsyncProverClient::new(prover_url.to_owned()),
        );
        Ok(Self {
            source,
            client: RingClient::new(zolana, AsyncProverClient::new(prover_url.to_owned())),
        })
    }
}

#[async_trait]
impl StorageChain for LiveStorageChain {
    async fn slot(&self) -> Result<u64, RingRpcError> {
        Ok(self.client.get_slot().await?)
    }

    async fn block_height(&self) -> Result<u64, RingRpcError> {
        Ok(self.client.get_block_height().await?)
    }

    async fn account(&self, address: Address) -> Result<Option<Account>, RingRpcError> {
        Ok(self.client.get_account(address).await?)
    }

    async fn ring_config(&self, ring: Address) -> Result<Option<RingConfiguration>, RingRpcError> {
        Ok(self.source.ring_config(ring).await?)
    }

    async fn apply_inputs(
        &self,
        request: GetStorageApplyProofInputsRequest,
    ) -> Result<GetStorageApplyProofInputsResponse, RingRpcError> {
        Ok(self
            .client
            .indexer()
            .get_storage_apply_proof_inputs(request)
            .await?)
    }

    async fn prove_apply(
        &self,
        inputs: &ApplyProofInputs,
    ) -> Result<ApplyRecordsIxData, RingRpcError> {
        StorageApplyProof { inputs }
            .prove(&self.client)
            .await
            .map_err(|error| RingRpcError::StorageUpdate(error.into()))
    }

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError> {
        let (blockhash, last_valid_block_height) = self.client.get_latest_blockhash().await?;
        Ok(LatestBlockhash {
            blockhash,
            last_valid_block_height,
        })
    }

    async fn send(&self, transaction: &VersionedTransaction) -> Result<Signature, RingRpcError> {
        Ok(self
            .client
            .send_transaction_with_config(transaction, RpcSendTransactionConfig::default())
            .await?)
    }

    async fn outcome(&self, signature: Signature) -> Result<TransactionOutcome, RingRpcError> {
        let statuses = self.client.get_signature_statuses(vec![signature]).await?;
        Ok(match statuses.into_iter().next().flatten() {
            Some(status) if status.err.is_some() => TransactionOutcome::Failed,
            Some(status) if status.satisfies_commitment(CommitmentConfig::confirmed()) => {
                TransactionOutcome::Succeeded
            }
            _ => TransactionOutcome::Unknown,
        })
    }
}
