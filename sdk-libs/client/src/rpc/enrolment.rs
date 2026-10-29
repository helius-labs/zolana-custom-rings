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
    /// The last enrolment of the previous page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<RecordUpdateId>,
    pub auth: ConfigAuthorityAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RefuseEnrolmentRequest {
    pub ring: SerializablePubkey,
    pub update_id: RecordUpdateId,
    pub auth: ConfigAuthorityAuth,
}

/// Signed by the config authority, or by the upgrade authority while no config exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateRecordsRegistryRequest {
    pub ring: SerializablePubkey,
    pub auth: ConfigAuthorityAuth,
}

/// `registry` is the ring's records PDA under `storage_authority`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateRecordsRegistryResponse {
    pub registry: SerializablePubkey,
    pub storage_authority: SerializablePubkey,
}

/// Oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetPendingEnrolmentsResponse {
    pub enrolments: Vec<PendingEnrolment>,
    /// Absent on the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<RecordUpdateId>,
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

/// The page after `cursor`, the first page without one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListEnrolments {
    pub cursor: Option<RecordUpdateId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefuseEnrolment(pub RecordUpdateId);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CreateRecords;

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
    impl Sealed for super::CreateRecords {}
}

impl EnrolmentAction for ListEnrolments {
    type Request = GetPendingEnrolmentsRequest;

    fn line(&self) -> String {
        match &self.cursor {
            None => "list".to_owned(),
            Some(cursor) => format!("list after {}", cursor.0.to_base58()),
        }
    }

    fn request(self, ring: Address, auth: ConfigAuthorityAuth) -> GetPendingEnrolmentsRequest {
        GetPendingEnrolmentsRequest {
            ring: ring.into(),
            cursor: self.cursor,
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

impl EnrolmentAction for CreateRecords {
    type Request = CreateRecordsRegistryRequest;

    fn line(&self) -> String {
        "create records".to_owned()
    }

    fn request(self, ring: Address, auth: ConfigAuthorityAuth) -> CreateRecordsRegistryRequest {
        CreateRecordsRegistryRequest {
            ring: ring.into(),
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
            action: ListEnrolments::default(),
        })
    }
}

impl SignedRequest<EnrolmentAttestation<ListEnrolments>> {
    pub fn with_cursor(mut self, cursor: RecordUpdateId) -> Self {
        self.attestation.action.cursor = Some(cursor);
        self
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

impl CreateRecordsRegistryRequest {
    pub fn create(
        target: ReadTarget,
        authority: Address,
    ) -> SignedRequest<EnrolmentAttestation<CreateRecords>> {
        SignedRequest::new(EnrolmentAttestation {
            target,
            authority,
            action: CreateRecords,
        })
    }
}
