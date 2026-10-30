use std::{borrow::Cow, fmt::Display};

use jsonrpsee::types::{error::ErrorCode, ErrorObjectOwned};
use log::error;
use spr_client::ClientError;
use spr_transaction::TransactionError;
use thiserror::Error;
use zolana_ring_client::{
    rpc::{KeyFileError, AUDITED_UTXOS_LIMIT},
    AuditError, RingIndexerError, RingRpcError as RingRefusal,
};
use zolana_ring_policy::MemberError;

use crate::{
    authority_transfer::AuthorityTransferError, authorize::Unauthorized, cosign::CoSignError,
    record_update::RecordUpdateRefusal, relay::RelayError,
};

#[derive(Debug, Error)]
pub enum RingRpcError {
    #[error("ring_program_id is required when keys are derived per ring")]
    RingRequired,
    #[error("ring is not served by the local auditor key")]
    RingNotServed,
    #[error("audit page is invalid")]
    InvalidPage,
    #[error("a UTXO read names 1 to {AUDITED_UTXOS_LIMIT} UTXO hashes")]
    InvalidUtxoRequest,
    #[error("request is unauthorized because {0}")]
    Unauthorized(#[from] Unauthorized),
    #[error("key derivation failed because {0}")]
    Derivation(#[from] spr_keypair::KeypairError),
    #[error("auditor key is unusable because {0}")]
    AuditorKey(#[from] KeyFileError),
    #[error(transparent)]
    Upstream(#[from] ClientError),
    #[error(transparent)]
    Refused(RingRefusal),
    #[error("asset registry is unusable because {0}")]
    Assets(#[from] TransactionError),
    #[error(transparent)]
    Origin(#[from] AuditError),
    #[error("indexer returned data outside the audit bounds")]
    InvalidIndexerResponse,
    #[error("audit service state is unavailable")]
    StateUnavailable,
    #[error("audit service is busy")]
    Busy,
    #[error("service store failed because {0}")]
    Store(#[from] sea_orm::DbErr),
    #[error(transparent)]
    RecordUpdate(#[from] RecordUpdateRefusal),
    #[error("indexer records lag the storage registry")]
    StaleRecords,
    #[error("storage update failed because {0}")]
    StorageUpdate(Box<custom_ring_sdk::RingError>),
    #[error(transparent)]
    Grant(#[from] GrantRefusal),
    #[error("grant identity failed because {0}")]
    Member(#[from] MemberError),
    #[error("stored grant row does not open under the grant rows key")]
    InvalidGrantRow,
    #[error("database reader grants need a service store")]
    GrantStoreMissing,
    #[error("database reader grants need a grant rows key")]
    GrantRowsKeyMissing,
    #[error(transparent)]
    Relay(#[from] RelayError),
    #[error(transparent)]
    AuthorityTransfer(#[from] AuthorityTransferError),
    #[error(transparent)]
    CoSign(#[from] CoSignError),
    #[error("merge settings need a service store")]
    MergeSettingsUnavailable,
    #[error("stored merge settings are signed at the same time or later")]
    StaleMergeSettings,
    #[error("escrowed nullifier key does not open to its registered key")]
    EscrowedKey,
    #[error("merge build failed because {0}")]
    MergeBuild(Box<custom_ring_sdk::RingError>),
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(i32)]
pub enum GrantRefusal {
    #[error("ring has no initialized records registry")]
    RecordsUnavailable = -32130,
    #[error("service keeps reader grants in the storage tree")]
    GrantsInTree = -32131,
}

impl GrantRefusal {
    pub const fn code(self) -> i32 {
        self as i32
    }
}

const MERGE_SETTINGS_UNAVAILABLE: i32 = -32170;
const STALE_MERGE_SETTINGS: i32 = -32171;

impl From<RingIndexerError> for RingRpcError {
    fn from(error: RingIndexerError) -> Self {
        match error {
            RingIndexerError::Refused(refused) => Self::Refused(refused),
            RingIndexerError::Client(error) => Self::Upstream(error),
        }
    }
}

pub(crate) const API_KEY_PARAMETER: &str = "api-key=";

/// Upstream errors quote request URLs, a log never carries their API key.
pub(crate) fn redacted(error: &impl Display) -> String {
    redact_api_key(&error.to_string()).into_owned()
}

/// The value after every `api-key=` masked, ending at the first byte a query value leaves encoded.
fn redact_api_key(text: &str) -> Cow<'_, str> {
    let lowercase = text.to_ascii_lowercase();
    if !lowercase.contains(API_KEY_PARAMETER) {
        return Cow::Borrowed(text);
    }
    let mut redacted = String::with_capacity(text.len());
    let mut start = 0;
    while let Some(found) = lowercase
        .get(start..)
        .and_then(|rest| rest.find(API_KEY_PARAMETER))
    {
        let value_start = start + found + API_KEY_PARAMETER.len();
        let rest = text.get(value_start..).unwrap_or_default();
        let value_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || "-._~%+/=".contains(c)))
            .unwrap_or(rest.len());
        redacted.push_str(text.get(start..value_start).unwrap_or_default());
        redacted.push_str("redacted");
        start = value_start + value_len;
    }
    redacted.push_str(text.get(start..).unwrap_or_default());
    Cow::Owned(redacted)
}

/// A client sees its own request errors, and only a generic message for a server fault.
impl From<RingRpcError> for ErrorObjectOwned {
    fn from(failure: RingRpcError) -> Self {
        use RingRpcError::*;
        let (code, message) = match &failure {
            Relay(relay) => return relay.into(),
            RingRequired | RingNotServed | InvalidPage | InvalidUtxoRequest | Unauthorized(_) => {
                let message = failure.to_string();
                return ErrorObjectOwned::owned(
                    ErrorCode::InvalidRequest.code(),
                    message,
                    None::<()>,
                );
            }
            MergeSettingsUnavailable => {
                let message = failure.to_string();
                return ErrorObjectOwned::owned(MERGE_SETTINGS_UNAVAILABLE, message, None::<()>);
            }
            StaleMergeSettings => {
                let message = failure.to_string();
                return ErrorObjectOwned::owned(STALE_MERGE_SETTINGS, message, None::<()>);
            }
            Grant(refusal) => {
                return ErrorObjectOwned::owned(refusal.code(), refusal.to_string(), None::<()>);
            }
            Busy => (ErrorCode::ServerIsBusy, "audit service is busy"),
            Upstream(inner) => {
                error!("upstream request failed {}", redacted(inner));
                (ErrorCode::InternalError, "upstream request failed")
            }
            Refused(inner) => {
                error!("indexer refused the registry read {inner}");
                (ErrorCode::InternalError, "upstream request failed")
            }
            Assets(inner) => {
                error!("asset registry is unusable {inner}");
                (ErrorCode::InternalError, "upstream request failed")
            }
            Origin(AuditError::MergeAuditWorkBudget) => (
                ErrorCode::InternalError,
                "audit scan exceeded its per-request work budget",
            ),
            Origin(inner) => {
                error!("transaction origin lookup failed {}", redacted(inner));
                (ErrorCode::InternalError, "upstream request failed")
            }
            InvalidIndexerResponse => {
                error!("indexer returned data outside the audit bounds");
                (ErrorCode::InternalError, "indexer response is invalid")
            }
            Derivation(_) | AuditorKey(_) => {
                error!("auditor key derivation failed");
                (ErrorCode::InternalError, "auditor key is unavailable")
            }
            StateUnavailable => {
                error!("audit service state is unavailable");
                (ErrorCode::InternalError, "audit service is unavailable")
            }
            Store(inner) => {
                error!("service store failed {}", redacted(inner));
                (ErrorCode::InternalError, "audit service is unavailable")
            }
            RecordUpdate(refusal) => {
                return ErrorObjectOwned::owned(refusal.code(), refusal.to_string(), None::<()>);
            }
            StaleRecords | StorageUpdate(_) => {
                error!("storage update failed {}", redacted(&failure));
                (ErrorCode::InternalError, "record writer is unavailable")
            }
            Member(inner) => {
                error!("grant identity failed {inner}");
                (ErrorCode::InternalError, "audit service is unavailable")
            }
            InvalidGrantRow | GrantStoreMissing | GrantRowsKeyMissing => {
                error!("{failure}");
                (ErrorCode::InternalError, "audit service is unavailable")
            }
            CoSign(inner) => return (*inner).into(),
            AuthorityTransfer(refusal) => return (*refusal).into(),
            EscrowedKey => {
                error!("escrowed nullifier key does not open");
                (ErrorCode::InternalError, "escrowed key is unusable")
            }
            MergeBuild(_) => {
                error!("managed merge failed {}", redacted(&failure));
                (ErrorCode::InternalError, "managed merge failed")
            }
        };
        ErrorObjectOwned::owned(code.code(), message, None::<()>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_logged_upstream_error_drops_the_api_key() {
        let upstream = ClientError::Rpc(
            "request to https://rpc.example/?api-key=f00dcafe&x=1 failed".to_owned(),
        );
        let logged = redacted(&RingRpcError::Upstream(upstream));
        assert!(!logged.contains("f00dcafe"), "{logged}");
        assert!(logged.contains("api-key="), "{logged}");
    }

    #[test]
    fn grant_refusal_codes_are_stable() {
        use GrantRefusal::*;
        for refusal in [RecordsUnavailable, GrantsInTree] {
            let code = match refusal {
                RecordsUnavailable => -32130,
                GrantsInTree => -32131,
            };
            assert_eq!(
                ErrorObjectOwned::from(RingRpcError::Grant(refusal)).code(),
                code
            );
        }
    }

    #[test]
    fn exhausted_merge_scan_has_an_explicit_rpc_error() {
        let response =
            ErrorObjectOwned::from(RingRpcError::Origin(AuditError::MergeAuditWorkBudget));
        assert_eq!(response.code(), ErrorCode::InternalError.code());
        assert_eq!(
            response.message(),
            "audit scan exceeded its per-request work budget"
        );
    }
}
