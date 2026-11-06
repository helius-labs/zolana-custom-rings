//! `getListSalt`, an owner's salt for the writers of the ring's salted lists, never its nullifier secret.

use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signer::Signer;
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};

use super::{base64, Attestation, ReadTarget, RequestBuildError, SignedRequest};

pub const GET_LIST_SALT: &str = "getListSalt";
const LIST_SALT_DOMAIN: &str = "zolana/ring-rpc-list-salt";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetListSaltRequest {
    pub ring: SerializablePubkey,
    pub writer: SerializablePubkey,
    pub owner: SerializablePubkey,
    pub timestamp: u64,
    pub nonce: Base64String,
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetListSaltResponse {
    /// Absent while the owner has no tracking row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_salt: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSaltAttestation {
    pub target: ReadTarget,
    pub writer: Address,
    pub owner: Address,
}

pub type ListSaltRequest = SignedRequest<ListSaltAttestation>;

impl Attestation for ListSaltAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        format!(
            "{LIST_SALT_DOMAIN}\n{}\nwriter: {}\nowner: {}\ntimestamp: {timestamp}\nnonce: {}",
            self.target.lines(),
            self.writer,
            self.owner,
            base64(nonce),
        )
        .into_bytes()
    }
}

impl ListSaltRequest {
    /// `writer` must be the attestation's writer.
    pub fn sign<S: Signer + ?Sized>(
        self,
        writer: &S,
    ) -> Result<GetListSaltRequest, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        let signature = writer
            .try_sign_message(&message)
            .map_err(RequestBuildError::Signature)?;
        Ok(GetListSaltRequest {
            ring: self.attestation.target.ring.into(),
            writer: self.attestation.writer.into(),
            owner: self.attestation.owner.into(),
            timestamp,
            nonce: self.nonce.to_vec().into(),
            signature: signature.into(),
        })
    }
}
