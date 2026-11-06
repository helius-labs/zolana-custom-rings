//! Signature statuses read from the ledger past the status cache, the pinned `AsyncRpc` reads the cache alone.

use async_trait::async_trait;
use solana_signature::Signature;
use solana_transaction_status_client_types::TransactionStatus;
use spr_client::{AsyncSprClient, ClientError};

/// Without history a landed signature the cache dropped reads absent, and releasing on that answer pays twice.
#[async_trait]
pub trait SignatureHistory: Send + Sync {
    async fn signature_statuses_with_history(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError>;
}

#[async_trait]
impl<R: SignatureHistory, I: Send + Sync> SignatureHistory for AsyncSprClient<R, I> {
    async fn signature_statuses_with_history(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.rpc().signature_statuses_with_history(signatures).await
    }
}

#[cfg(feature = "solana-rpc")]
#[async_trait]
impl SignatureHistory for spr_client::AsyncSolanaRpc {
    async fn signature_statuses_with_history(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.client()
            .get_signature_statuses_with_history(&signatures)
            .await
            .map(|response| response.value)
            .map_err(|error| {
                ClientError::Rpc(format!("get_signature_statuses_with_history: {error}"))
            })
    }
}

/// The blocking client would start its own runtime inside the caller's.
#[cfg(feature = "solana-rpc")]
#[async_trait]
impl SignatureHistory for spr_client::Blocking<spr_client::SolanaRpc> {
    async fn signature_statuses_with_history(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        spr_client::AsyncSolanaRpc::new(self.inner().client().url())
            .signature_statuses_with_history(signatures)
            .await
    }
}
