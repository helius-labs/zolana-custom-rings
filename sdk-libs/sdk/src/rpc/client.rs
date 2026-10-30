//! The zolana client beside the ring prover a ring operation needs.

use core::ops::Deref;

use spr_client::{
    prover::{indexed::ProofDataSource, ProveRequest},
    AsyncIndexer, AsyncProverClient, AsyncZolanaClient, ClientError, Proof,
};
use zolana_ring_client::AsyncRingIndexer;

pub trait RingIndexerBackend: AsyncIndexer + AsyncRingIndexer {}

impl<I: AsyncIndexer + AsyncRingIndexer> RingIndexerBackend for I {}

/// Dereferences to the zolana client, the pinned client keeps its prover private.
pub struct RingClient<R, I> {
    zolana: AsyncZolanaClient<R, I>,
    prover: AsyncProverClient,
}

impl<R, I> RingClient<R, I> {
    pub fn new(zolana: AsyncZolanaClient<R, I>, prover: AsyncProverClient) -> Self {
        Self { zolana, prover }
    }

    pub fn zolana(&self) -> &AsyncZolanaClient<R, I> {
        &self.zolana
    }

    pub fn prover(&self) -> &AsyncProverClient {
        &self.prover
    }

    /// The prover server when it fetches the proof data, `None` when the client fetches it.
    pub fn indexed_prover(&self) -> Option<&AsyncProverClient> {
        (self.prover.proof_data_source() == ProofDataSource::Prover).then_some(&self.prover)
    }

    pub async fn prove_request(
        &self,
        request: &(impl ProveRequest + Sync + ?Sized),
    ) -> Result<Proof, ClientError> {
        self.prover.prove(request).await
    }
}

impl<R, I> Deref for RingClient<R, I> {
    type Target = AsyncZolanaClient<R, I>;

    fn deref(&self) -> &Self::Target {
        &self.zolana
    }
}
