use std::future::Future;

use async_trait::async_trait;
use custom_ring_interface::{
    storage::{Revision, StorageRegistry},
    ApplyRecordsIxData,
};
use custom_ring_sdk::{tracking_apply_inputs, ApplyEnrollments, RingClient, StorageApplyProof};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use spr_client::{AsyncProverClient, AsyncRpc, AsyncSolanaRpc, AsyncSprClient, AsyncSprIndexer};
use zolana_ring_client::AsyncRingIndexer;
use zolana_ring_indexer::rpc::{
    GetStorageApplyProofInputsRequest, GetStorageApplyProofInputsResponse,
    GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse,
};
use zolana_ring_indexer::tracking::{
    GetPendingEnrollmentsRequest, GetPendingEnrollmentsResponse, GetTrackingApplyProofInputsRequest,
};
use zolana_ring_member_registry::ApplyProofInputs;

use crate::{
    error::RingRpcError,
    landing::{ChainOutcome, ChainSubmit, LatestBlockhash, Simulation, SolanaChain},
    upstream::{ChainSource, OpeningFetch, RingConfiguration, TransactionSource, Upstreams},
};

#[must_use]
pub struct ProvedEnrollments {
    pub instruction: Instruction,
    /// The registry revision the proof starts from.
    pub revision: Revision,
}

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
        registry: &StorageRegistry,
    ) -> Result<ApplyRecordsIxData, RingRpcError>;

    async fn pending_enrollments(
        &self,
        request: GetPendingEnrollmentsRequest,
    ) -> Result<GetPendingEnrollmentsResponse, RingRpcError>;

    /// `owners` applied in order from the current root.
    async fn prove_enrollments(
        &self,
        registry: Address,
        owners: &[Address],
    ) -> Result<ProvedEnrollments, RingRpcError>;
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
    client: RingClient<AsyncSolanaRpc, AsyncSprIndexer>,
    submit: SolanaChain,
}

impl LiveStorageChain {
    /// The prover serves the ring apply proofs.
    pub fn connect(upstreams: Upstreams<'_>, prover_url: &str) -> Result<Self, RingRpcError> {
        Ok(Self {
            source: ChainSource::connect(upstreams)?,
            client: live_ring_client(upstreams, prover_url),
            submit: SolanaChain::new(upstreams.rpc_url),
        })
    }
}

pub fn live_ring_client(
    upstreams: Upstreams<'_>,
    prover_url: &str,
) -> RingClient<AsyncSolanaRpc, AsyncSprIndexer> {
    let zolana = AsyncSprClient::new(
        AsyncSolanaRpc::new(upstreams.rpc_url),
        AsyncSprIndexer::new(upstreams.indexer_url),
        AsyncProverClient::new(prover_url.to_owned()),
    );
    RingClient::new(zolana, AsyncProverClient::new(prover_url.to_owned()))
}

#[async_trait]
impl ChainSubmit for LiveStorageChain {
    async fn account_data(&self, address: Address) -> Result<Option<Vec<u8>>, RingRpcError> {
        self.submit.account_data(address).await
    }

    async fn rent_exempt_lamports(&self, data_len: usize) -> Result<u64, RingRpcError> {
        self.submit.rent_exempt_lamports(data_len).await
    }

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

    async fn simulate(
        &self,
        message: &solana_message::VersionedMessage,
    ) -> Result<Simulation, RingRpcError> {
        self.submit.simulate(message).await
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
        registry: &StorageRegistry,
    ) -> Result<ApplyRecordsIxData, RingRpcError> {
        StorageApplyProof {
            inputs,
            registry,
            asset_writes: &[],
        }
        .prove(&self.client)
        .await
        .map_err(|error| RingRpcError::StorageUpdate(error.into()))
    }

    async fn pending_enrollments(
        &self,
        request: GetPendingEnrollmentsRequest,
    ) -> Result<GetPendingEnrollmentsResponse, RingRpcError> {
        Ok(self
            .client
            .indexer()
            .get_pending_enrollments(request)
            .await?)
    }

    async fn prove_enrollments(
        &self,
        registry: Address,
        owners: &[Address],
    ) -> Result<ProvedEnrollments, RingRpcError> {
        let response = self
            .client
            .indexer()
            .get_tracking_apply_proof_inputs(GetTrackingApplyProofInputsRequest {
                registry: registry.into(),
                owners: owners.iter().copied().map(Into::into).collect(),
            })
            .await?;
        let storage = |error: custom_ring_sdk::RingError| RingRpcError::StorageUpdate(error.into());
        let inputs = tracking_apply_inputs(&response).map_err(storage)?;
        let revision = Revision::from(response.revision);
        let instruction = ApplyEnrollments {
            tracking_registry: registry,
            revision,
            owners,
            inputs: &inputs,
        }
        .prove(&self.client)
        .await
        .map_err(storage)?;
        Ok(ProvedEnrollments {
            instruction,
            revision,
        })
    }
}
