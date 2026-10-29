//! The Ring RPC relay a wallet sends its transfer through.

use async_trait::async_trait;
use solana_message::VersionedMessage;
use solana_signer::Signer;
use spr_indexer_api::{SerializablePubkey, SerializableSignature};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, RelayId, RelayQuote,
    RelayStatus, RelayStep, SubmitRelayRequest,
};

use crate::RingError;

#[async_trait]
pub trait RingRelay: Send + Sync {
    async fn get_relay_quote(&self, request: GetRelayQuoteRequest)
        -> Result<RelayQuote, RingError>;

    async fn prepare_relay(&self, request: PrepareRelayRequest) -> Result<RelayStep, RingError>;

    async fn submit_relay(&self, request: SubmitRelayRequest) -> Result<RelayStatus, RingError>;

    async fn get_relay_status(
        &self,
        request: GetRelayStatusRequest,
    ) -> Result<RelayStatus, RingError>;
}

#[must_use = "send the relay"]
pub struct PreparedRelay {
    request: PrepareRelayRequest,
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
}

impl PreparedRelay {
    pub(crate) fn new(request: PrepareRelayRequest) -> Self {
        Self { request }
    }

    /// A retried request names the same relay.
    pub fn relay_id(&self) -> Result<RelayId, RingError> {
        Ok(self.request.relay_id()?)
    }

    pub async fn send<R: RingRelay + ?Sized>(self, relay: &R) -> Result<RelaySent, RingError> {
        let expected = self.relay_id()?;
        let sent = match relay.prepare_relay(self.request).await? {
            RelayStep::Submitted { relay_id } => RelaySent::Submitted(relay_id),
            RelayStep::SignMessage { relay_id, message } => {
                RelaySent::SignMessage(PendingSignature {
                    relay_id,
                    message: message.0,
                })
            }
        };
        match *sent.relay_id() == expected {
            true => Ok(sent),
            false => Err(RingError::RelayIdMismatch),
        }
    }
}

impl RelaySent {
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

    /// Signs only a v1 message that names `signer` among its signers.
    pub async fn sign<R: RingRelay + ?Sized>(
        self,
        relay: &R,
        signer: &dyn Signer,
    ) -> Result<RelayStatus, RingError> {
        let pubkey = signer.try_pubkey()?;
        let message: VersionedMessage =
            wincode::deserialize(&self.message).map_err(|_| RingError::RelayMessageInvalid)?;
        let signs = match &message {
            VersionedMessage::V1(message) => message
                .account_keys
                .iter()
                .position(|key| *key == pubkey)
                .is_some_and(|index| message.is_signer(index)),
            VersionedMessage::Legacy(_) | VersionedMessage::V0(_) => false,
        };
        if !signs || message.serialize() != self.message {
            return Err(RingError::RelayMessageInvalid);
        }
        let signature = signer.try_sign_message(&self.message)?;
        relay
            .submit_relay(SubmitRelayRequest {
                relay_id: self.relay_id,
                signer: SerializablePubkey(pubkey),
                signature: SerializableSignature(signature),
            })
            .await
    }
}
