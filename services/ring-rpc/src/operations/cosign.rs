use std::collections::BTreeSet;

use async_trait::async_trait;
use clap::ValueEnum;
use custom_ring_interface::CoSignScope;
use jsonrpsee::types::ErrorObjectOwned;
use solana_address::Address;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use thiserror::Error;
use zolana_ring_policy::Member;

use crate::error::RingRpcError;

/// One class of the five a ring's `CoSigner` records hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ApproveClass {
    Outflow,
    Withdrawal,
    Transfers,
    Deposits,
    Withdrawals,
}

/// Explicit, an empty set refuses every operation whatever its limits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoSignerApproval(BTreeSet<ApproveClass>);

pub struct CoSignRequest {
    pub ring: Address,
    pub message: VersionedMessage,
    pub flows: CoSignFlows,
}

/// A caller names no transfer debit, the co-signer reads each from the frame it signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoSignFlows {
    Frame,
    /// A deposit's public leg, or nothing on a merge.
    Published(Vec<OwnerFlow>),
}

/// One reservation row, each owner and asset once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerFlow {
    pub owner: Member,
    pub flow: AssetFlow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetFlow {
    pub asset: Address,
    /// The owner's net outflow from `zolana_ring_policy::owner_debits`.
    pub debit: u128,
    /// `debit` plus the owner's charge, compared with owner caps and `cosign_above`.
    pub charged_outflow: u128,
    /// A sum of u64 legs, past `u64::MAX` while the net stays a u64 magnitude.
    pub deposited: u128,
    pub withdrawn: u128,
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
    /// No class the operation demands sits in the explicit approval.
    NotApproved,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[repr(i32)]
pub enum CoSignError {
    #[error("co-signing is disabled")]
    Disabled = -32160,
    #[error("the transaction exceeds a co-signer limit")]
    OverLimit = -32161,
    #[error("the co-sign flows name an owner and asset twice")]
    RepeatedAsset = -32162,
    #[error("the asset limits or an input opening are unreadable")]
    LimitsUnavailable = -32163,
    #[error("the message holds anything but one ring transfer the co-signer can read")]
    MessageScope = -32164,
    #[error("the co-signer approves no class the operation demands")]
    NotApproved = -32165,
    #[error("the co-sign reservation is already released")]
    ReleasedReservation = -32166,
    #[error("the co-sign request names an asset with no record")]
    UnrecordedAsset = -32296,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoSignSettlement {
    Confirmed(Signature),
    Failed(Signature),
}

impl ApproveClass {
    const fn scope(self) -> CoSignScope {
        match self {
            Self::Outflow => CoSignScope::APPROVE_OUTFLOW,
            Self::Withdrawal => CoSignScope::APPROVE_WITHDRAWAL,
            Self::Transfers => CoSignScope::TRANSFERS,
            Self::Deposits => CoSignScope::DEPOSITS,
            Self::Withdrawals => CoSignScope::WITHDRAWALS,
        }
    }
}

impl CoSignerApproval {
    pub fn new(classes: impl IntoIterator<Item = ApproveClass>) -> Self {
        Self(classes.into_iter().collect())
    }

    pub(crate) fn scope(&self) -> CoSignScope {
        self.0
            .iter()
            .fold(CoSignScope::NONE, |scope, class| scope | class.scope())
    }
}

impl CoSignError {
    pub const fn code(self) -> i32 {
        self as i32
    }
}

impl From<CoSignRefusal> for CoSignError {
    fn from(refusal: CoSignRefusal) -> Self {
        match refusal {
            CoSignRefusal::Disabled => Self::Disabled,
            CoSignRefusal::OverLimit => Self::OverLimit,
            CoSignRefusal::NotApproved => Self::NotApproved,
        }
    }
}

impl From<CoSignError> for ErrorObjectOwned {
    fn from(error: CoSignError) -> Self {
        Self::owned(error.code(), error.to_string(), None::<()>)
    }
}

#[async_trait]
pub trait CoSignPolicy: Send + Sync {
    /// `None` when the policy never signs.
    fn signer(&self) -> Option<Address>;

    async fn decide(&self, request: &CoSignRequest) -> Result<CoSignDecision, RingRpcError>;

    /// Keeps or frees the usage `decide` reserved for the transaction.
    async fn settle(&self, settlement: CoSignSettlement) -> Result<(), RingRpcError>;
}

pub struct RefusingCoSigner;

#[async_trait]
impl CoSignPolicy for RefusingCoSigner {
    fn signer(&self) -> Option<Address> {
        None
    }

    async fn decide(&self, _request: &CoSignRequest) -> Result<CoSignDecision, RingRpcError> {
        Ok(CoSignDecision::Refused(CoSignRefusal::Disabled))
    }

    async fn settle(&self, _settlement: CoSignSettlement) -> Result<(), RingRpcError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosign_error_codes_are_stable() {
        use CoSignError::*;
        for (error, code) in [
            (Disabled, -32160),
            (OverLimit, -32161),
            (RepeatedAsset, -32162),
            (LimitsUnavailable, -32163),
            (MessageScope, -32164),
            (NotApproved, -32165),
            (UnrecordedAsset, -32296),
        ] {
            assert_eq!(ErrorObjectOwned::from(error).code(), code);
        }
    }
}
