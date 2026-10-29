use std::fmt::Write as _;

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use solana_address::Address;
use solana_signer::Signer;
use spr_indexer_api::{Base64String, SerializablePubkey, SerializableSignature};
use spr_keypair::ShieldedAddress;

use super::{base64, relay_id, Attestation, ReadTarget, RelayId, RequestBuildError, SignedRequest};

const AUTHORITY_TRANSFER_DOMAIN: &str = "zolana/ring-rpc-authority-transfer/v1";

/// The base58 text of `ShieldedAddress::to_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerializableShieldedAddress(pub ShieldedAddress);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorityPayment {
    pub recipient: SerializableShieldedAddress,
    pub amount: u64,
}

/// The change returns to `source`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorityTransfer {
    pub source: SerializableShieldedAddress,
    pub mint: SerializablePubkey,
    pub payments: Vec<AuthorityPayment>,
}

/// `prepareAuthorityTransfer` answers with a `RelayStep::SignMessage` until the delegate signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrepareAuthorityTransferRequest {
    pub ring: SerializablePubkey,
    pub delegate: SerializablePubkey,
    pub transfer: AuthorityTransfer,
    pub timestamp: u64,
    pub nonce: Base64String,
    /// Raw Ed25519 over the `AuthorityTransferAttestation` message.
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityTransferAttestation {
    pub target: ReadTarget,
    pub delegate: Address,
    pub transfer: AuthorityTransfer,
}

pub type AuthorityTransferRequest = SignedRequest<AuthorityTransferAttestation>;

impl Serialize for SerializableShieldedAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SerializableShieldedAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map(Self).map_err(D::Error::custom)
    }
}

impl From<ShieldedAddress> for SerializableShieldedAddress {
    fn from(address: ShieldedAddress) -> Self {
        Self(address)
    }
}

impl Attestation for AuthorityTransferAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        let transfer = &self.transfer;
        let payments = transfer
            .payments
            .iter()
            .fold(String::new(), |mut lines, payment| {
                let _ = write!(
                    lines,
                    "\npayment: {} {}",
                    payment.recipient.0, payment.amount
                );
                lines
            });
        format!(
            "{AUTHORITY_TRANSFER_DOMAIN}\n{}\ndelegate: {}\nsource: {}\nmint: {}{payments}\ntimestamp: {timestamp}\nnonce: {}",
            self.target.lines(),
            self.delegate,
            transfer.source.0,
            transfer.mint.0,
            base64(nonce),
        )
        .into_bytes()
    }
}

impl AuthorityTransferRequest {
    /// `delegate` must be the attestation's delegate, the service checks the signature against it.
    pub fn sign<S: Signer + ?Sized>(
        self,
        delegate: &S,
    ) -> Result<PrepareAuthorityTransferRequest, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        let signature = delegate
            .try_sign_message(&message)
            .map_err(RequestBuildError::Signature)?;
        Ok(PrepareAuthorityTransferRequest {
            ring: self.attestation.target.ring.into(),
            delegate: self.attestation.delegate.into(),
            transfer: self.attestation.transfer,
            timestamp,
            nonce: self.nonce.to_vec().into(),
            signature: signature.into(),
        })
    }
}

impl PrepareAuthorityTransferRequest {
    /// A retried request names the same relay.
    pub fn relay_id(&self) -> Result<RelayId, serde_json::Error> {
        relay_id(self)
    }
}
