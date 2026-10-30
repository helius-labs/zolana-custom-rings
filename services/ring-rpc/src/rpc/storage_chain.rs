use std::future::Future;

use async_trait::async_trait;
use custom_ring_interface::ApplyRecordsIxData;
use custom_ring_sdk::{RingClient, StorageApplyProof};
use solana_account::Account;
use solana_address::Address;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use spr_client::{
    AsyncProverClient, AsyncRpc, AsyncSolanaRpc, AsyncZolanaClient, AsyncZolanaIndexer,
};
use zolana_ring_client::AsyncRingIndexer;
use zolana_ring_indexer::rpc::{
    GetStorageApplyProofInputsRequest, GetStorageApplyProofInputsResponse,
    GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse,
};
use zolana_ring_member_registry::ApplyProofInputs;

use crate::{
    error::RingRpcError,
    landing::{ChainOutcome, ChainSubmit, LatestBlockhash, SolanaChain},
    upstream::{ChainSource, OpeningFetch, RingConfiguration, TransactionSource, Upstreams},
};

#[async_trait]
pub trait StorageChain: ChainSubmit {
    async fn account(&self, address: Address) -> Result<Option<Account>, RingRpcError>;

    async fn ring_config(&self, ring: Address) -> Result<Option<RingConfiguration>, RingRpcError>;

    async fn member_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingRpcError>;

    async fn apply_inputs(
        &self,
        request: GetStorageApplyProofInputsRequest,
    ) -> Result<GetStorageApplyProofInputsResponse, RingRpcError>;

    async fn prove_apply(
        &self,
        inputs: &ApplyProofInputs,
    ) -> Result<ApplyRecordsIxData, RingRpcError>;
}

impl OpeningFetch for dyn StorageChain {
    fn fetch_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> impl Future<Output = Result<GetStorageMemberOpeningsResponse, RingRpcError>> + Send {
        self.member_openings(request)
    }
}

pub struct LiveStorageChain {
    source: ChainSource,
    client: RingClient<AsyncSolanaRpc, AsyncZolanaIndexer>,
    submit: SolanaChain,
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
            submit: SolanaChain::new(upstreams.rpc_url),
        })
    }
}

#[async_trait]
impl ChainSubmit for LiveStorageChain {
    async fn slot(&self) -> Result<u64, RingRpcError> {
        self.submit.slot().await
    }

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError> {
        self.submit.latest_blockhash().await
    }

    async fn block_height(&self) -> Result<u64, RingRpcError> {
        self.submit.block_height().await
    }

    async fn send(&self, transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
        self.submit.send(transaction).await
    }

    async fn outcome(&self, signature: Signature) -> Result<Option<ChainOutcome>, RingRpcError> {
        self.submit.outcome(signature).await
    }
}

#[async_trait]
impl StorageChain for LiveStorageChain {
    async fn account(&self, address: Address) -> Result<Option<Account>, RingRpcError> {
        Ok(self.client.get_account(address).await?)
    }

    async fn ring_config(&self, ring: Address) -> Result<Option<RingConfiguration>, RingRpcError> {
        Ok(self.source.ring_config(ring).await?)
    }

    async fn member_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingRpcError> {
        Ok(self.source.storage_member_openings(request).await?)
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
}
