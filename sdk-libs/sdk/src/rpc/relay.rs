//! The Ring RPC relay a wallet sends its transfer through.

use async_trait::async_trait;
use solana_signer::Signer;
use spr_indexer_api::{SerializablePubkey, SerializableSignature};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareAuthorityTransferRequest,
    PrepareRelayRequest, RelayId, RelayQuote, RelayStatus, RelayStep, SubmitRelayRequest,
};

use crate::{
    relay_message::{ExpectedDelegate, ExpectedMessage},
    MessageMismatch, RingError, VerifiedMessage,
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
    expected: Option<ExpectedMessage>,
}

impl PreparedRelay {
    pub(crate) fn new(request: PrepareRelayRequest) -> Self {
        Self {
            request,
            expected: None,
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

    pub async fn send<R: RingRelay + ?Sized>(self, relay: &R) -> Result<RelaySent, RingError> {
        let relay_id = self.relay_id()?;
        let step = relay.prepare_relay(self.request).await?;
        Ok(RelaySent::accepted(step, &relay_id)?.expecting(self.expected))
    }
}

impl PreparedAuthorityTransfer {
    /// The delegate signs only a message the quoted fee payer pays.
    pub fn new(
        request: PrepareAuthorityTransferRequest,
        quote: &RelayQuote,
    ) -> Result<Self, RingError> {
        let expected = ExpectedDelegate::new(&request, quote)?;
        Ok(Self { request, expected })
    }

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
                expected,
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

    /// The expectation comes from the wallet's own request, never from Ring RPC's answer.
    pub fn verify(&self) -> Result<VerifiedMessage, RingError> {
        let expected = self.expected.as_ref().ok_or(MessageMismatch::Unrequested)?;
        Ok(expected.check(&self.message)?)
    }

    pub async fn sign<R: RingRelay + ?Sized>(
        self,
        relay: &R,
        signer: &dyn Signer,
    ) -> Result<RelayStatus, RingError> {
        let verified = self.verify()?;
        let signature = verified.sign(signer)?;
        relay
            .submit_relay(SubmitRelayRequest {
                relay_id: self.relay_id,
                signer: SerializablePubkey(verified.signer()),
                signature: SerializableSignature(signature),
            })
            .await
    }
}
