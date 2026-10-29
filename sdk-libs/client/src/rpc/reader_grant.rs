use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signer::Signer;
use spr_indexer_api::{Base64String, SerializablePubkey, SerializableSignature};

use super::{base64, wallet_line, Attestation, ReadTarget, RequestBuildError, SignedRequest};
use crate::ReaderKey;

const READER_GRANT_DOMAIN: &str = "zolana/ring-rpc-reader-grant/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReaderGrantAction {
    Grant,
    Revoke,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SetReaderGrantRequest {
    pub ring: SerializablePubkey,
    /// Absent for a ring-wide grant, the ring config authority signs it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<SerializablePubkey>,
    /// Canonical tagged reader key bytes.
    pub reader: Base64String,
    pub action: ReaderGrantAction,
    pub timestamp: u64,
    pub nonce: Base64String,
    /// Raw Ed25519 of `wallet` or the config authority over the `ReaderGrantAttestation` message.
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderGrantAttestation {
    pub target: ReadTarget,
    pub wallet: Option<Address>,
    pub reader: ReaderKey,
    pub action: ReaderGrantAction,
}

pub type ReaderGrantRequest = SignedRequest<ReaderGrantAttestation>;
/// The action the service holds for the grant after the write.
pub type SetReaderGrantResponse = ReaderGrantAction;

impl ReaderGrantAction {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Revoke => "revoke",
        }
    }
}

impl Attestation for ReaderGrantAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        format!(
            "{READER_GRANT_DOMAIN}\n{}{}\nreader: {}\naction: {}\ntimestamp: {timestamp}\nnonce: {}",
            self.target.lines(),
            wallet_line(self.wallet),
            base64(&self.reader.to_bytes()),
            self.action.name(),
            base64(nonce),
        )
        .into_bytes()
    }
}

impl ReaderGrantRequest {
    /// `signer` must be the attestation's wallet, or the ring config authority for a ring-wide grant.
    pub fn sign<S: Signer + ?Sized>(
        self,
        signer: &S,
    ) -> Result<SetReaderGrantRequest, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        let signature = signer
            .try_sign_message(&message)
            .map_err(RequestBuildError::Signature)?;
        let ReaderGrantAttestation {
            target,
            wallet,
            reader,
            action,
        } = self.attestation;
        Ok(SetReaderGrantRequest {
            ring: target.ring.into(),
            wallet: wallet.map(Into::into),
            reader: reader.to_bytes().to_vec().into(),
            action,
            timestamp,
            nonce: self.nonce.to_vec().into(),
            signature: signature.into(),
        })
    }
}
