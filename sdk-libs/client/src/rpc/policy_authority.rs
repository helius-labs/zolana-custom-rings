//! Ring RPC requests the ring policy authority signs, over wallet updates pending list approval and the records registry.

use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signer::Signer;
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};

use super::{base64, Attestation, ReadTarget, RecordUpdateId, RequestBuildError, SignedRequest};

const POLICY_AUTHORITY_DOMAIN: &str = "zolana/ring-rpc-policy-authority";

/// Raw Ed25519 over the `PolicyAuthorityAttestation` message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyAuthorityAuth {
    pub authority: SerializablePubkey,
    pub timestamp: u64,
    pub nonce: Base64String,
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetPendingListApprovalsRequest {
    pub ring: SerializablePubkey,
    pub registry: SerializablePubkey,
    /// The last update of the previous page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<RecordUpdateId>,
    pub auth: PolicyAuthorityAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RefuseListApprovalRequest {
    pub ring: SerializablePubkey,
    pub registry: SerializablePubkey,
    pub update_id: RecordUpdateId,
    pub auth: PolicyAuthorityAuth,
}

/// Signed by the policy authority, or by the upgrade authority before `Initialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateRecordsRegistryRequest {
    pub ring: SerializablePubkey,
    pub auth: PolicyAuthorityAuth,
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
pub struct GetPendingListApprovalsResponse {
    pub pending: Vec<PendingListApproval>,
    /// Absent on the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<RecordUpdateId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PendingListApproval {
    pub update_id: RecordUpdateId,
    pub wallet: SerializablePubkey,
    /// The owner identity of `wallet`, the record an approval writes.
    pub member: Hash,
    pub awaited_lists: u64,
    pub valid_until_slot: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListApprovalScope {
    pub target: ReadTarget,
    pub authority: Address,
    pub registry: Address,
}

/// The page after `cursor`, the first page without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPendingApprovals {
    pub registry: Address,
    pub cursor: Option<RecordUpdateId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefuseListApproval {
    pub registry: Address,
    pub update_id: RecordUpdateId,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CreateRecords;

/// The service rebuilds it from its own target and the request fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAuthorityAttestation<A> {
    pub target: ReadTarget,
    pub authority: Address,
    pub action: A,
}

pub trait PolicyAuthorityAction: sealed::Sealed {
    type Request;

    fn line(&self) -> String;

    fn request(self, ring: Address, auth: PolicyAuthorityAuth) -> Self::Request;
}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::ListPendingApprovals {}
    impl Sealed for super::RefuseListApproval {}
    impl Sealed for super::CreateRecords {}
}

impl PolicyAuthorityAction for ListPendingApprovals {
    type Request = GetPendingListApprovalsRequest;

    fn line(&self) -> String {
        match &self.cursor {
            None => format!("list {}", self.registry),
            Some(cursor) => format!("list {} after {}", self.registry, cursor.0.to_base58()),
        }
    }

    fn request(self, ring: Address, auth: PolicyAuthorityAuth) -> GetPendingListApprovalsRequest {
        GetPendingListApprovalsRequest {
            ring: ring.into(),
            registry: self.registry.into(),
            cursor: self.cursor,
            auth,
        }
    }
}

impl PolicyAuthorityAction for RefuseListApproval {
    type Request = RefuseListApprovalRequest;

    fn line(&self) -> String {
        format!("refuse {} {}", self.registry, self.update_id.0.to_base58())
    }

    fn request(self, ring: Address, auth: PolicyAuthorityAuth) -> RefuseListApprovalRequest {
        RefuseListApprovalRequest {
            ring: ring.into(),
            registry: self.registry.into(),
            update_id: self.update_id,
            auth,
        }
    }
}

impl PolicyAuthorityAction for CreateRecords {
    type Request = CreateRecordsRegistryRequest;

    fn line(&self) -> String {
        "create records".to_owned()
    }

    fn request(self, ring: Address, auth: PolicyAuthorityAuth) -> CreateRecordsRegistryRequest {
        CreateRecordsRegistryRequest {
            ring: ring.into(),
            auth,
        }
    }
}

impl<A: PolicyAuthorityAction> Attestation for PolicyAuthorityAttestation<A> {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        format!(
            "{POLICY_AUTHORITY_DOMAIN}\n{}\nauthority: {}\naction: {}\ntimestamp: {timestamp}\nnonce: {}",
            self.target.lines(),
            self.authority,
            self.action.line(),
            base64(nonce),
        )
        .into_bytes()
    }
}

impl<A: PolicyAuthorityAction> SignedRequest<PolicyAuthorityAttestation<A>> {
    /// `authority` must be the attestation's authority, the service checks the signature against it.
    pub fn sign<S: Signer + ?Sized>(self, authority: &S) -> Result<A::Request, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        let signature = authority
            .try_sign_message(&message)
            .map_err(RequestBuildError::Signature)?;
        let PolicyAuthorityAttestation {
            target,
            authority,
            action,
        } = self.attestation;
        Ok(action.request(
            target.ring,
            PolicyAuthorityAuth {
                authority: authority.into(),
                timestamp,
                nonce: self.nonce.to_vec().into(),
                signature: signature.into(),
            },
        ))
    }
}

impl GetPendingListApprovalsRequest {
    pub fn read(
        scope: ListApprovalScope,
    ) -> SignedRequest<PolicyAuthorityAttestation<ListPendingApprovals>> {
        SignedRequest::new(PolicyAuthorityAttestation {
            target: scope.target,
            authority: scope.authority,
            action: ListPendingApprovals {
                registry: scope.registry,
                cursor: None,
            },
        })
    }
}

impl SignedRequest<PolicyAuthorityAttestation<ListPendingApprovals>> {
    pub fn with_cursor(mut self, cursor: RecordUpdateId) -> Self {
        self.attestation.action.cursor = Some(cursor);
        self
    }
}

impl RefuseListApprovalRequest {
    pub fn refusal(
        scope: ListApprovalScope,
        update_id: RecordUpdateId,
    ) -> SignedRequest<PolicyAuthorityAttestation<RefuseListApproval>> {
        SignedRequest::new(PolicyAuthorityAttestation {
            target: scope.target,
            authority: scope.authority,
            action: RefuseListApproval {
                registry: scope.registry,
                update_id,
            },
        })
    }
}

impl CreateRecordsRegistryRequest {
    pub fn create(
        target: ReadTarget,
        authority: Address,
    ) -> SignedRequest<PolicyAuthorityAttestation<CreateRecords>> {
        SignedRequest::new(PolicyAuthorityAttestation {
            target,
            authority,
            action: CreateRecords,
        })
    }
}
