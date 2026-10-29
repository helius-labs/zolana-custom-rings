use async_trait::async_trait;
use solana_address::Address;
use solana_message::VersionedMessage;
use solana_signature::Signature;

use crate::error::RingRpcError;

/// Lacks the fee payer signature, `RelaySubmit` adds it.
pub struct RelayTransaction {
    pub message: VersionedMessage,
    pub signatures: Vec<CollectedSignature>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectedSignature {
    pub signer: Address,
    pub signature: Signature,
}

#[async_trait]
pub trait RelaySubmit: Send + Sync {
    /// The signature names the sent transaction, confirmation is the caller's to track.
    async fn submit(&self, transaction: RelayTransaction) -> Result<Signature, RingRpcError>;
}
