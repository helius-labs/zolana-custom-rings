use std::fmt::Write as _;

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use solana_address::Address;
use solana_signer::Signer;
use spr_indexer_api::{Base64String, SerializablePubkey, SerializableSignature};
use spr_keypair::{KeypairError, ShieldedAddress, ViewingKey};
use zeroize::Zeroizing;

use super::{base64, relay_id, Attestation, ReadTarget, RelayId, RequestBuildError, SignedRequest};

const AUTHORITY_TRANSFER_DOMAIN: &str = "zolana/ring-rpc-authority-transfer";

/// The base58 text of `ShieldedAddress::to_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerializableShieldedAddress(pub ShieldedAddress);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorityPayment {
    pub recipient: SerializableShieldedAddress,
    pub mint: SerializablePubkey,
    pub amount: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorityWithdrawal {
    pub recipient: SerializablePubkey,
    pub mint: SerializablePubkey,
    pub amount: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_program: Option<SerializablePubkey>,
}

/// A delegate moves the notes of any member, its own among them, change returns to an input's owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorityTransfer {
    pub sources: Vec<SerializableShieldedAddress>,
    pub payments: Vec<AuthorityPayment>,
    pub exits: Vec<AuthorityPayment>,
    pub withdrawals: Vec<AuthorityWithdrawal>,
}

/// The delegate picks the transaction key, the frame's proof binds each record to it.
#[derive(Clone, PartialEq, Eq)]
pub struct TxViewingSecret(Zeroizing<[u8; 32]>);

/// `prepareAuthorityTransfer` answers with a `RelayStep::SignMessage` until the delegate signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrepareAuthorityTransferRequest {
    pub ring: SerializablePubkey,
    pub delegate: SerializablePubkey,
    pub transfer: AuthorityTransfer,
    pub tx_viewing_key: TxViewingSecret,
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

impl TxViewingSecret {
    /// An unclamped alias keeps the stream key under another CRBS seed.
    pub fn key(&self) -> Result<ViewingKey, KeypairError> {
        ViewingKey::from_canonical_bytes(&self.0)
    }
}

impl From<&ViewingKey> for TxViewingSecret {
    fn from(key: &ViewingKey) -> Self {
        Self(key.secret_bytes())
    }
}

impl core::fmt::Debug for TxViewingSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TxViewingSecret(..)")
    }
}

impl Serialize for TxViewingSecret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Base64String(self.0.to_vec()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TxViewingSecret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = Base64String::deserialize(deserializer)?;
        <[u8; 32]>::try_from(bytes.0.as_slice())
            .map(|secret| Self(Zeroizing::new(secret)))
            .map_err(|_| D::Error::custom("a transaction key is 32 bytes"))
    }
}

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
        let outputs = [("payment", &transfer.payments), ("exit", &transfer.exits)]
            .into_iter()
            .fold(String::new(), |mut lines, (kind, outputs)| {
                for output in outputs {
                    let _ = write!(
                        lines,
                        "\n{kind}: {} {} {}",
                        output.recipient.0, output.mint.0, output.amount
                    );
                }
                lines
            });
        let withdrawals =
            transfer
                .withdrawals
                .iter()
                .fold(String::new(), |mut lines, withdrawal| {
                    let program = withdrawal
                        .token_program
                        .map_or_else(|| "-".to_owned(), |program| program.0.to_string());
                    let _ = write!(
                        lines,
                        "\nwithdrawal: {} {} {} {}",
                        withdrawal.recipient.0, withdrawal.mint.0, withdrawal.amount, program
                    );
                    lines
                });
        let sources = transfer
            .sources
            .iter()
            .fold(String::new(), |mut lines, source| {
                let _ = write!(lines, "\nsource: {}", source.0);
                lines
            });
        format!(
            "{AUTHORITY_TRANSFER_DOMAIN}\n{}\ndelegate: {}{sources}{outputs}{withdrawals}\ntimestamp: {timestamp}\nnonce: {}",
            self.target.lines(),
            self.delegate,
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
        tx_viewing_key: &ViewingKey,
    ) -> Result<PrepareAuthorityTransferRequest, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        let signature = delegate
            .try_sign_message(&message)
            .map_err(RequestBuildError::Signature)?;
        Ok(PrepareAuthorityTransferRequest {
            ring: self.attestation.target.ring.into(),
            delegate: self.attestation.delegate.into(),
            transfer: self.attestation.transfer,
            tx_viewing_key: TxViewingSecret::from(tx_viewing_key),
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
