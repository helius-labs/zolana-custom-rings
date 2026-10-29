use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signer::Signer;
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};

use super::{base64, Attestation, ReadTarget, RecordUpdateId, RequestBuildError, SignedRequest};

const ENROLMENT_DOMAIN: &str = "zolana/ring-rpc-enrolment/v1";

/// Raw Ed25519 over the `EnrolmentAttestation` message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConfigAuthorityAuth {
    pub authority: SerializablePubkey,
    pub timestamp: u64,
    pub nonce: Base64String,
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetPendingEnrolmentsRequest {
    pub ring: SerializablePubkey,
    pub auth: ConfigAuthorityAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RefuseEnrolmentRequest {
    pub ring: SerializablePubkey,
    pub update_id: RecordUpdateId,
    pub auth: ConfigAuthorityAuth,
}

/// Oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetPendingEnrolmentsResponse {
    pub enrolments: Vec<PendingEnrolment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PendingEnrolment {
    pub update_id: RecordUpdateId,
    pub wallet: SerializablePubkey,
    /// The owner identity of `wallet`, the record an approval writes.
    pub member: Hash,
    pub awaited_lists: u64,
    pub valid_until_slot: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListEnrolments;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefuseEnrolment(pub RecordUpdateId);

/// The service rebuilds it from its own target and the request fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolmentAttestation<A> {
    pub target: ReadTarget,
    pub authority: Address,
    pub action: A,
}

pub trait EnrolmentAction: sealed::Sealed {
    type Request;

    fn line(&self) -> String;

    fn request(self, ring: Address, auth: ConfigAuthorityAuth) -> Self::Request;
}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::ListEnrolments {}
    impl Sealed for super::RefuseEnrolment {}
}

impl EnrolmentAction for ListEnrolments {
    type Request = GetPendingEnrolmentsRequest;

    fn line(&self) -> String {
        "list".to_owned()
    }

    fn request(self, ring: Address, auth: ConfigAuthorityAuth) -> GetPendingEnrolmentsRequest {
        GetPendingEnrolmentsRequest {
            ring: ring.into(),
            auth,
        }
    }
}

impl EnrolmentAction for RefuseEnrolment {
    type Request = RefuseEnrolmentRequest;

    fn line(&self) -> String {
        format!("refuse {}", self.0 .0.to_base58())
    }

    fn request(self, ring: Address, auth: ConfigAuthorityAuth) -> RefuseEnrolmentRequest {
        RefuseEnrolmentRequest {
            ring: ring.into(),
            update_id: self.0,
            auth,
        }
    }
}

impl<A: EnrolmentAction> Attestation for EnrolmentAttestation<A> {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        format!(
            "{ENROLMENT_DOMAIN}\n{}\nauthority: {}\naction: {}\ntimestamp: {timestamp}\nnonce: {}",
            self.target.lines(),
            self.authority,
            self.action.line(),
            base64(nonce),
        )
        .into_bytes()
    }
}

impl<A: EnrolmentAction> SignedRequest<EnrolmentAttestation<A>> {
    /// `authority` must be the attestation's authority, the service checks the signature against it.
    pub fn sign<S: Signer + ?Sized>(self, authority: &S) -> Result<A::Request, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        let signature = authority
            .try_sign_message(&message)
            .map_err(RequestBuildError::Signature)?;
        let EnrolmentAttestation {
            target,
            authority,
            action,
        } = self.attestation;
        Ok(action.request(
            target.ring,
            ConfigAuthorityAuth {
                authority: authority.into(),
                timestamp,
                nonce: self.nonce.to_vec().into(),
                signature: signature.into(),
            },
        ))
    }
}

impl GetPendingEnrolmentsRequest {
    pub fn read(
        target: ReadTarget,
        authority: Address,
    ) -> SignedRequest<EnrolmentAttestation<ListEnrolments>> {
        SignedRequest::new(EnrolmentAttestation {
            target,
            authority,
            action: ListEnrolments,
        })
    }
}

impl RefuseEnrolmentRequest {
    pub fn refusal(
        target: ReadTarget,
        authority: Address,
        update_id: RecordUpdateId,
    ) -> SignedRequest<EnrolmentAttestation<RefuseEnrolment>> {
        SignedRequest::new(EnrolmentAttestation {
            target,
            authority,
            action: RefuseEnrolment(update_id),
        })
    }
}
