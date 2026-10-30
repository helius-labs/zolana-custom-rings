use custom_ring_interface::stream::DeliveredSlot;
use spr_keypair::{
    shielded::ShieldedKeypair,
    viewing_key::{Salt, ViewTag},
    SharedViewTags, ViewingKey, X25519Pubkey,
};

use crate::RingKeyError;

/// The public context of one delivered ring output slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDeliveryRequest {
    pub viewing_pubkey: X25519Pubkey,
    pub tx_viewing_pk: X25519Pubkey,
    pub salt: Salt,
    pub output_index: u32,
    pub first_nullifier: [u8; 32],
}

/// One own-key spec view tag of an anonymous ring under a wallet viewing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewTagStream {
    Sender { tx_count: u64 },
    Request { request_count: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewTagRequest {
    pub viewing_pubkey: X25519Pubkey,
    pub stream: ViewTagStream,
}

/// The counterparty one direction of shared view tags is agreed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SharedTagPair {
    /// Tags the wallet pays `recipient` under.
    ToRecipient(X25519Pubkey),
    /// Tags `sender` pays the wallet under, `sender` the viewing key its recipient bodies name.
    FromSender(X25519Pubkey),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedTagsRequest {
    pub viewing_pubkey: X25519Pubkey,
    pub pair: SharedTagPair,
}

/// The ring derivations of a key holder, every one answered from a viewing key it never exports.
pub trait RingKeys {
    /// One CRDS slot secret per request.
    fn ring_delivery_secrets(
        &self,
        requests: &[RingDeliveryRequest],
    ) -> Result<Vec<[u8; 32]>, RingKeyError>;

    /// One tag per request.
    fn view_tags(&self, requests: &[ViewTagRequest]) -> Result<Vec<ViewTag>, RingKeyError>;

    /// One pair domain per request, the one ECDH its pair costs.
    fn shared_view_tags(
        &self,
        requests: &[SharedTagsRequest],
    ) -> Result<Vec<SharedViewTags>, RingKeyError>;
}

impl RingKeys for ShieldedKeypair {
    fn ring_delivery_secrets(
        &self,
        requests: &[RingDeliveryRequest],
    ) -> Result<Vec<[u8; 32]>, RingKeyError> {
        requests
            .iter()
            .map(|request| {
                let recipient = held(self, &request.viewing_pubkey)?;
                let agreement = recipient.ecdh(&request.tx_viewing_pk)?;
                let secret = DeliveredSlot {
                    agreement: &agreement,
                    tx_viewing_pk: request.tx_viewing_pk.as_bytes(),
                    recipient_viewing_pk: request.viewing_pubkey.as_bytes(),
                    salt: &request.salt,
                    output_index: request.output_index,
                    first_nullifier: &request.first_nullifier,
                }
                .secret()?;
                Ok(*secret.as_bytes())
            })
            .collect()
    }

    fn view_tags(&self, requests: &[ViewTagRequest]) -> Result<Vec<ViewTag>, RingKeyError> {
        requests
            .iter()
            .map(|request| {
                let key = held(self, &request.viewing_pubkey)?;
                Ok(match request.stream {
                    ViewTagStream::Sender { tx_count } => key.get_sender_view_tag(tx_count)?,
                    ViewTagStream::Request { request_count } => {
                        key.get_recipient_request_view_tag(request_count)?
                    }
                })
            })
            .collect()
    }

    fn shared_view_tags(
        &self,
        requests: &[SharedTagsRequest],
    ) -> Result<Vec<SharedViewTags>, RingKeyError> {
        requests
            .iter()
            .map(|request| {
                let key = held(self, &request.viewing_pubkey)?;
                Ok(match request.pair {
                    SharedTagPair::ToRecipient(recipient) => {
                        key.send_shared_view_tags(&recipient)?
                    }
                    SharedTagPair::FromSender(sender) => key.recipient_shared_view_tags(&sender)?,
                })
            })
            .collect()
    }
}

fn held<'a>(
    keypair: &'a ShieldedKeypair,
    pubkey: &X25519Pubkey,
) -> Result<&'a ViewingKey, RingKeyError> {
    match keypair.viewing_key.pubkey() == *pubkey {
        true => Ok(&keypair.viewing_key),
        false => Err(RingKeyError::UnknownViewingKey),
    }
}
