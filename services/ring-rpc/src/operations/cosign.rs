use async_trait::async_trait;
use custom_ring_interface::cosign::CoSignDemand;
use solana_address::Address;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use zolana_ring_policy::Member;

use crate::error::RingRpcError;

pub struct CoSignRequest {
    pub ring: Address,
    pub message: VersionedMessage,
    pub sender: Member,
    pub demand: CoSignDemand,
    /// Each asset once.
    pub flows: Vec<AssetFlow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetFlow {
    pub asset: Address,
    pub transferred: u64,
    pub deposited: u64,
    pub withdrawn: u64,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoSignDecision {
    /// Over `CoSignRequest::message`.
    Signed(Signature),
    Refused(CoSignRefusal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoSignRefusal {
    Disabled,
    OverLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoSignSettlement {
    Confirmed(Signature),
    Failed(Signature),
}

#[async_trait]
pub trait CoSigner: Send + Sync {
    async fn decide(&self, request: &CoSignRequest) -> Result<CoSignDecision, RingRpcError>;

    /// Keeps or frees the usage `decide` reserved for the transaction.
    async fn settle(&self, settlement: CoSignSettlement) -> Result<(), RingRpcError>;
}

pub struct RefusingCoSigner;

#[async_trait]
impl CoSigner for RefusingCoSigner {
    async fn decide(&self, _request: &CoSignRequest) -> Result<CoSignDecision, RingRpcError> {
        Ok(CoSignDecision::Refused(CoSignRefusal::Disabled))
    }

    async fn settle(&self, _settlement: CoSignSettlement) -> Result<(), RingRpcError> {
        Ok(())
    }
}
