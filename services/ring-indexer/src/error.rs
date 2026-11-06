use jsonrpsee::types::{error::ErrorCode, ErrorObjectOwned};
use thiserror::Error;
use zolana_ring_indexer::rpc::RingRpcError;

#[derive(Error, Clone, Debug, PartialEq, Eq)]
pub enum RingApiError {
    #[error("member registry is out of sync ({0})")]
    OutOfSync(String),
    #[error("member registry root changed")]
    RootChanged,
    #[error("member registry page has an index gap or inconsistent leaf")]
    PageGap,
    #[error("invalid request ({0})")]
    InvalidRequest(String),
    #[error("internal error ({0})")]
    Internal(String),
}

impl From<sea_orm::DbErr> for RingApiError {
    fn from(error: sea_orm::DbErr) -> Self {
        Self::Internal(error.to_string())
    }
}

impl From<RingApiError> for ErrorObjectOwned {
    fn from(error: RingApiError) -> Self {
        let refusal = match &error {
            RingApiError::OutOfSync(_) => RingRpcError::RegistryOutOfSync,
            RingApiError::RootChanged => RingRpcError::RegistryRootChanged,
            RingApiError::PageGap => RingRpcError::RegistryPageGap,
            RingApiError::InvalidRequest(_) => {
                return Self::owned(
                    ErrorCode::InvalidRequest.code(),
                    error.to_string(),
                    None::<()>,
                )
            }
            RingApiError::Internal(reason) => {
                log::error!("ring lookup failed ({reason})");
                return Self::owned(
                    ErrorCode::InternalError.code(),
                    "internal server error",
                    None::<()>,
                );
            }
        };
        Self::owned(refusal.code(), error.to_string(), None::<()>)
    }
}
