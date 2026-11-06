//! `getDelegateNotes`, a victim's openings and secret for the ring's configured delegate alone.

use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signer::Signer;
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};

use super::{
    base64, Attestation, GetWalletStatusResponse, ReadBuildError, ReadTarget, RequestBuildError,
    SignedRequest,
};

pub const GET_DELEGATE_NOTES: &str = "getDelegateNotes";
pub const RELEASE_DELEGATE_SNAPSHOT: &str = "releaseDelegateSnapshot";
const DELEGATE_SNAPSHOT_RELEASE_DOMAIN: &str = "zolana/ring-rpc-delegate-snapshot-release";
const DELEGATE_NOTES_DOMAIN: &str = "zolana/ring-rpc-delegate-notes";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetDelegateNotesRequest {
    pub ring: SerializablePubkey,
    pub delegate: SerializablePubkey,
    pub owner: SerializablePubkey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Base64String>,
    pub timestamp: u64,
    pub nonce: Base64String,
    /// Raw Ed25519 over the `DelegateNotesAttestation` message.
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetDelegateNotesResponse {
    /// Absent while the owner holds only zero key notes or its seal is unread, right aligned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier_secret: Option<Hash>,
    pub status: GetWalletStatusResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateNotesAttestation {
    pub target: ReadTarget,
    pub delegate: Address,
    pub owner: Address,
    pub cursor: Option<Base64String>,
}

pub type DelegateNotesRequest = SignedRequest<DelegateNotesAttestation>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateSnapshotReleaseAttestation {
    pub target: ReadTarget,
    pub delegate: Address,
    pub owner: Address,
    pub cursor: Base64String,
}

#[must_use]
pub struct DelegateSnapshotReleaseRequest {
    signed: SignedRequest<DelegateSnapshotReleaseAttestation>,
}

struct DelegateNotesMessage<'a> {
    domain: &'a str,
    target: &'a ReadTarget,
    delegate: Address,
    owner: Address,
    cursor: &'a [u8],
    timestamp: u64,
    nonce: &'a [u8; 32],
}

struct DelegateRequestSigning {
    attestation: DelegateNotesAttestation,
    timestamp: u64,
    nonce: [u8; 32],
    message: Vec<u8>,
}

impl Attestation for DelegateNotesAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        DelegateNotesMessage {
            domain: DELEGATE_NOTES_DOMAIN,
            target: &self.target,
            delegate: self.delegate,
            owner: self.owner,
            cursor: self.cursor.as_ref().map_or(&[], |cursor| &cursor.0),
            timestamp,
            nonce,
        }
        .encode()
    }
}

impl Attestation for DelegateSnapshotReleaseAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        DelegateNotesMessage {
            domain: DELEGATE_SNAPSHOT_RELEASE_DOMAIN,
            target: &self.target,
            delegate: self.delegate,
            owner: self.owner,
            cursor: &self.cursor.0,
            timestamp,
            nonce,
        }
        .encode()
    }
}

impl DelegateSnapshotReleaseRequest {
    pub fn new(attestation: DelegateSnapshotReleaseAttestation) -> Result<Self, ReadBuildError> {
        super::wallet_snapshot::validate_snapshot_cursor(&attestation.cursor)?;
        Ok(Self {
            signed: SignedRequest::new(attestation),
        })
    }

    pub fn at(self, timestamp: u64) -> Self {
        Self {
            signed: self.signed.at(timestamp),
        }
    }

    pub fn sign<S: Signer + ?Sized>(
        self,
        delegate: &S,
    ) -> Result<GetDelegateNotesRequest, RequestBuildError> {
        let (timestamp, message) = self.signed.message()?;
        let attestation = self.signed.attestation;
        DelegateRequestSigning {
            attestation: DelegateNotesAttestation {
                target: attestation.target,
                delegate: attestation.delegate,
                owner: attestation.owner,
                cursor: Some(attestation.cursor),
            },
            timestamp,
            nonce: self.signed.nonce,
            message,
        }
        .sign(delegate)
    }
}

impl DelegateNotesRequest {
    /// `delegate` must be the attestation's delegate, the service checks the signature against it.
    pub fn sign<S: Signer + ?Sized>(
        self,
        delegate: &S,
    ) -> Result<GetDelegateNotesRequest, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        DelegateRequestSigning {
            attestation: self.attestation,
            timestamp,
            nonce: self.nonce,
            message,
        }
        .sign(delegate)
    }
}

impl DelegateNotesMessage<'_> {
    fn encode(self) -> Vec<u8> {
        format!(
            "{}\n{}\ndelegate: {}\nowner: {}\ncursor: {}\ntimestamp: {}\nnonce: {}",
            self.domain,
            self.target.lines(),
            self.delegate,
            self.owner,
            base64(self.cursor),
            self.timestamp,
            base64(self.nonce),
        )
        .into_bytes()
    }
}

impl DelegateRequestSigning {
    fn sign<S: Signer + ?Sized>(
        self,
        delegate: &S,
    ) -> Result<GetDelegateNotesRequest, RequestBuildError> {
        let signature = delegate
            .try_sign_message(&self.message)
            .map_err(RequestBuildError::Signature)?;
        Ok(GetDelegateNotesRequest {
            ring: self.attestation.target.ring.into(),
            delegate: self.attestation.delegate.into(),
            owner: self.attestation.owner.into(),
            cursor: self.attestation.cursor,
            timestamp: self.timestamp,
            nonce: self.nonce.to_vec().into(),
            signature: signature.into(),
        })
    }
}
