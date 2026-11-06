//! The Ring RPC relay a wallet sends its transfer through.

use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use solana_address::Address;
use solana_signer::Signer;
use spr_indexer_api::{SerializablePubkey, SerializableSignature};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareAuthorityTransferRequest,
    PrepareRelayRequest, RelayId, RelayQuote, RelayStatus, RelayStep, SubmitRelayRequest,
};

use zolana_ring_policy::OwnerDebit;

use crate::{
    relay_message::{
        ApprovalOpening, ExpectedDelegate, ExpectedMessage, RelayFunderTerms, RelayTransferTerms,
    },
    AllowedNullifiers, CustomRingConfig, MessageMismatch, RingError, VerifiedMessage,
};

#[async_trait]
pub trait RingRelay: Send + Sync {
    async fn get_relay_quote(&self, request: GetRelayQuoteRequest)
        -> Result<RelayQuote, RingError>;

    async fn prepare_relay(&self, request: PrepareRelayRequest) -> Result<RelayStep, RingError>;

    async fn prepare_authority_transfer(
        &self,
        request: PrepareAuthorityTransferRequest,
    ) -> Result<RelayStep, RingError>;

    async fn submit_relay(&self, request: SubmitRelayRequest) -> Result<RelayStatus, RingError>;

    async fn get_relay_status(
        &self,
        request: GetRelayStatusRequest,
    ) -> Result<RelayStatus, RingError>;
}

#[must_use = "send the relay"]
pub struct PreparedRelay {
    request: PrepareRelayRequest,
    /// `None` on the rails that sign inside the proof.
    expected: Option<ExpectedMessage>,
    sent: AtomicBool,
}

#[must_use = "prepare the authority transfer"]
pub struct RequestedAuthorityTransfer<'a> {
    pub request: PrepareAuthorityTransferRequest,
    pub quote: &'a RelayQuote,
    pub config: &'a CustomRingConfig,
    /// Every note of each requested source, a note Ring RPC selects outside it is refused.
    pub allowed: AllowedNullifiers,
}

/// Ring RPC selects the source's notes and proves, the delegate signs the message it returns.
#[must_use = "send the authority transfer"]
pub struct PreparedAuthorityTransfer {
    request: PrepareAuthorityTransferRequest,
    expected: ExpectedDelegate,
}

/// The relay Ring RPC accepted, a `SignMessage` step waits for its signer.
#[must_use = "a relay waiting for a signature stays unsent"]
pub enum RelaySent {
    Submitted(RelayId),
    SignMessage(PendingSignature),
}

#[must_use = "sign the relay message"]
pub struct PendingSignature {
    relay_id: RelayId,
    message: Vec<u8>,
    expected: Option<Box<ExpectedMessage>>,
}

impl PreparedRelay {
    pub(crate) fn new(request: PrepareRelayRequest) -> Self {
        Self {
            request,
            expected: None,
            sent: AtomicBool::new(false),
        }
    }

    #[must_use = "use the updated relay"]
    pub(crate) fn expecting(mut self, expected: ExpectedMessage) -> Self {
        self.expected = Some(expected);
        self
    }

    /// A retried request names the same relay.
    pub fn relay_id(&self) -> Result<RelayId, RingError> {
        Ok(self.request.relay_id()?)
    }

    #[cfg(test)]
    pub(crate) fn request(&self) -> &PrepareRelayRequest {
        &self.request
    }

    /// Per owner and asset, read before `send` hands the owner's signature over.
    pub fn charged_outflows(&self) -> &[OwnerDebit] {
        self.expected
            .as_ref()
            .map_or(&[], ExpectedMessage::charged_outflows)
    }

    /// Repeatable after a lost answer, Ring RPC keys every stored relay by its id.
    pub async fn send<R: RingRelay + ?Sized>(&self, relay: &R) -> Result<RelaySent, RingError> {
        let relay_id = self.relay_id()?;
        // 1. A retry reconciles by the relay id first, a relay Ring RPC sent never prepares again.
        if self.sent.swap(true, Ordering::AcqRel) {
            match relay
                .get_relay_status(GetRelayStatusRequest {
                    relay_id: relay_id.clone(),
                })
                .await
            {
                Ok(RelayStatus::Sent { .. } | RelayStatus::Confirmed { .. }) => {
                    return Ok(RelaySent::Submitted(relay_id))
                }
                Ok(RelayStatus::Failed { reason }) => {
                    return Err(RingError::RelayFailed { reason })
                }
                // 2. Ring RPC answers a stored relay from its store, an unknown one proves once.
                Ok(RelayStatus::AwaitingSignature) | Err(_) => {}
            }
        }
        let step = relay.prepare_relay(self.request.clone()).await?;
        Ok(RelaySent::accepted(step, &relay_id)?.expecting(self.expected.clone()))
    }
}

impl RequestedAuthorityTransfer<'_> {
    /// The delegate signs only a message the quoted fee payer pays.
    pub fn prepare(self) -> Result<PreparedAuthorityTransfer, RingError> {
        let expected = ExpectedDelegate::new(&self)?;
        Ok(PreparedAuthorityTransfer {
            request: self.request,
            expected,
        })
    }
}

impl PreparedAuthorityTransfer {
    /// A retried request names the same relay.
    pub fn relay_id(&self) -> Result<RelayId, RingError> {
        Ok(self.request.relay_id()?)
    }

    pub async fn send<R: RingRelay + ?Sized>(self, relay: &R) -> Result<RelaySent, RingError> {
        let relay_id = self.relay_id()?;
        let step = relay.prepare_authority_transfer(self.request).await?;
        let expected = ExpectedMessage::Delegate(self.expected);
        Ok(RelaySent::accepted(step, &relay_id)?.expecting(Some(expected)))
    }
}

impl RelaySent {
    fn accepted(step: RelayStep, expected: &RelayId) -> Result<Self, RingError> {
        let sent = match step {
            RelayStep::Submitted { relay_id } => Self::Submitted(relay_id),
            RelayStep::SignMessage { relay_id, message } => Self::SignMessage(PendingSignature {
                relay_id,
                message: message.0,
                expected: None,
            }),
        };
        match sent.relay_id() == expected {
            true => Ok(sent),
            false => Err(RingError::RelayIdMismatch),
        }
    }

    fn expecting(self, expected: Option<ExpectedMessage>) -> Self {
        match self {
            Self::SignMessage(pending) => Self::SignMessage(PendingSignature {
                expected: expected.map(Box::new),
                ..pending
            }),
            submitted @ Self::Submitted(_) => submitted,
        }
    }

    pub fn relay_id(&self) -> &RelayId {
        match self {
            Self::Submitted(relay_id) => relay_id,
            Self::SignMessage(pending) => &pending.relay_id,
        }
    }

    /// The owner-signed rails sign inside the proof, a public signature would name the owner.
    pub fn submitted(self) -> Result<RelayId, RingError> {
        match self {
            Self::Submitted(relay_id) => Ok(relay_id),
            Self::SignMessage(_) => Err(RingError::RelayAskedOwnerSignature),
        }
    }
}

impl PendingSignature {
    pub fn relay_id(&self) -> &RelayId {
        &self.relay_id
    }

    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// What the wallet sealed for one public owner, an outside co-signer holds none.
    pub fn transfer_terms(&self, signer: Address) -> Option<&RelayTransferTerms> {
        self.expected.as_deref()?.terms_for(signer)
    }

    /// What the wallet sealed for one public funder of a deposit leg.
    pub fn funder_terms(&self, signer: Address) -> Option<&RelayFunderTerms> {
        self.expected.as_deref()?.funder_terms_for(signer)
    }

    pub(crate) fn expecting(
        relay_id: RelayId,
        message: Vec<u8>,
        expected: ExpectedMessage,
    ) -> Self {
        Self {
            relay_id,
            message,
            expected: Some(Box::new(expected)),
        }
    }

    /// For a named co-signer that reads exact totals, the terms of no slot.
    pub fn approval_opening(&self) -> Option<&ApprovalOpening> {
        self.expected.as_deref()?.approval_opening()
    }

    /// Per owner and asset, read before a public owner signs.
    pub fn charged_outflows(&self) -> &[OwnerDebit] {
        self.expected
            .as_deref()
            .map_or(&[], ExpectedMessage::charged_outflows)
    }

    /// The expectation comes from the wallet's own request, never from Ring RPC's answer.
    pub fn verify(&self, signer: Address) -> Result<VerifiedMessage, RingError> {
        let expected = self
            .expected
            .as_deref()
            .ok_or(MessageMismatch::Unrequested)?;
        Ok(expected.check(&self.message, signer)?)
    }

    pub async fn sign<R: RingRelay + ?Sized>(
        &self,
        relay: &R,
        signer: &dyn Signer,
    ) -> Result<RelayStatus, RingError> {
        let verified = self.verify(signer.try_pubkey()?)?;
        self.submit(relay, &verified, signer).await
    }

    async fn submit<R: RingRelay + ?Sized>(
        &self,
        relay: &R,
        verified: &VerifiedMessage,
        signer: &dyn Signer,
    ) -> Result<RelayStatus, RingError> {
        let signature = verified.sign(signer)?;
        relay
            .submit_relay(SubmitRelayRequest {
                relay_id: self.relay_id.clone(),
                signer: SerializablePubkey(verified.signer()),
                signature: SerializableSignature(signature),
            })
            .await
    }
}
