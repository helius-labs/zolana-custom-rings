//! The blocking front the CLI runs the SDK's `async` ring operations through.

use std::future::Future;

use custom_ring_sdk::RingClient;
use solana_signature::Signature;
use solana_transaction_error::TransactionError;
use spr_api::{BlockingInsideRuntime, BlockingRuntime};
use spr_client::{
    AsyncProverClient, AsyncRpc, AsyncZolanaClient, Blocking, ClientError, IndexerPollConfig,
    SolanaRpc, ZolanaIndexer,
};

pub struct Zolana<R = SolanaRpc, I = ZolanaIndexer> {
    chain: RingClient<Blocking<R>, Blocking<I>>,
    runtime: BlockingRuntime,
}

pub type Chain<R = SolanaRpc, I = ZolanaIndexer> = AsyncZolanaClient<Blocking<R>, Blocking<I>>;

/// `prover` proves the SPP statements and `ring_prover` the ring statements.
pub struct ZolanaServices<R, I> {
    pub rpc: R,
    pub indexer: I,
    pub prover: AsyncProverClient,
    pub ring_prover: AsyncProverClient,
}

impl<R, I> ZolanaServices<R, I> {
    pub fn connect(self) -> Zolana<R, I> {
        let Self {
            rpc,
            indexer,
            prover,
            ring_prover,
        } = self;
        let zolana = AsyncZolanaClient::new(Blocking::new(rpc), Blocking::new(indexer), prover);
        Zolana {
            chain: RingClient::new(zolana, ring_prover),
            runtime: BlockingRuntime::new(),
        }
    }
}

impl<R, I> Zolana<R, I> {
    pub fn rpc(&self) -> &R {
        self.chain.zolana().rpc().inner()
    }

    pub fn indexer(&self) -> &I {
        self.chain.zolana().indexer().inner()
    }

    pub fn as_async(&self) -> &Chain<R, I> {
        self.chain.zolana()
    }

    pub fn ring_client(&self) -> &RingClient<Blocking<R>, Blocking<I>> {
        &self.chain
    }

    pub fn block_on<T, E: From<BlockingInsideRuntime>>(
        &self,
        future: impl Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        self.runtime.block_on(future)
    }
}

pub fn transaction_error(error: &ClientError) -> Option<TransactionError> {
    match error {
        ClientError::SolanaRpcTransaction { source, .. } => source.get_transaction_error(),
        _ => None,
    }
}

/// A transient refusal is polled again, any other refusal returns at once.
pub async fn wait_for_indexed_transaction<I: AsyncRpc + ?Sized>(
    indexer: &I,
    signature: Signature,
    retry: IndexerPollConfig,
) -> Result<(), ClientError> {
    let mut last_error = None;
    for delay in std::iter::once(std::time::Duration::ZERO).chain(retry.backoff()) {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        match indexer
            .get_shielded_transactions_by_signature(signature, None)
            .await
        {
            Ok(response) if !response.transactions.is_empty() => return Ok(()),
            Ok(_) => last_error = None,
            Err(error) if indexer.should_retry(&error) => last_error = Some(error.to_string()),
            Err(error) => return Err(error),
        }
    }
    Err(ClientError::IndexerUnavailable(last_error.unwrap_or_else(
        || format!("{signature} is not indexed yet"),
    )))
}
