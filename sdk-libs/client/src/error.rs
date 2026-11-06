use custom_ring_interface::stream::StreamError;
use solana_signature::Signature;
use spr_api::BlockingInsideRuntime;
use spr_client::ClientError;
use thiserror::Error;
use zolana_ring_indexer::rpc::RingRpcError;
use zolana_ring_keys::RingKeyError;
use zolana_ring_transaction::RingRailError;

use crate::RingIndexerError;
use spr_hasher::HasherError;
use spr_keypair::KeypairError;
use spr_transaction::TransactionError;
use zolana_ring_policy::MemberError;

use crate::OutputPayloadErrorKind;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("the last message of the transaction is not tagged for the auditor")]
    MissingAuditorMessage,
    #[error("auditor message of {0} bytes does not fit the disclosure layout")]
    AuditorMessageLength(usize),
    #[error("transaction publishes no tx_viewing_pk")]
    MissingTxViewingPk,
    #[error("transaction publishes no salt")]
    MissingSalt,
    #[error("transaction publishes no nullifier")]
    MissingNullifier,
    #[error("transaction names no ring program")]
    MissingRingProgram,
    #[error("recovered transaction viewing key does not match the published tx_viewing_pk")]
    TxViewingKeyMismatch,
    #[error("recovered transaction viewing secret is not the canonical clamped X25519 encoding")]
    NonCanonicalViewingKey,
    #[error("disclosure field lies at or above the field modulus")]
    DisclosureField,
    #[error("disclosure does not fit its layout")]
    DisclosureLayout,
    #[error("{trees} input trees do not match {inputs} published inputs")]
    InputTreeCount { trees: usize, inputs: usize },
    #[error("audited notes answer {got} of {want} requested hashes")]
    AuditedUtxosCount { got: usize, want: usize },
    #[error("audited note does not rebuild UTXO hash {utxo_hash:?}")]
    AuditedUtxoMismatch { utxo_hash: [u8; 32] },
    #[error("the transfer names no ring Transact frame its audit layout is bound to")]
    MissingRingTransact,
    #[error("output slot {slot} does not open, {kind:?}")]
    UnopenedOutput {
        slot: u32,
        kind: OutputPayloadErrorKind,
    },
    #[error("ring transaction event index is unavailable")]
    MissingEventIndex,
    #[error("nullifier ciphertext did not decrypt to a zero-padded secret")]
    NullifierPad,
    #[error("recovered nullifier key does not match the source member identity")]
    NullifierKeyMismatch,
    #[error("recovery progress belongs to another member")]
    RecoveryProgressMismatch,
    #[error("member registry root or paged record opening is invalid")]
    InvalidMemberRegistry,
    #[error("ring history exceeds the scan bound, spent notes cannot be excluded")]
    IncompleteScan,
    #[error("indexer page does not answer its request")]
    InvalidHistoryPage,
    #[error(transparent)]
    HistoryCursor(#[from] crate::history::HistoryCursorError),
    #[error("a verified anonymous merge disclosure does not open its settled output")]
    MergeDisclosureMismatch,
    #[error("merge audit exceeded its key-search work budget")]
    MergeAuditWorkBudget,
    #[error("transaction {signature} is unavailable {message}")]
    Unavailable {
        signature: Signature,
        message: String,
    },
    #[error("inner instruction stack height {0} has no parent")]
    InvalidStackHeight(u32),
    #[error("ring transact instruction data is undecodable {0}")]
    InvalidTransactData(String),
    #[error("ring transact settlement accounts do not match its interface transfers")]
    SettlementAccounts,
    #[error("trusted event index {0} is unavailable")]
    InvalidEventIndex(u16),
    #[error("confirmed SPP event cannot be reconstructed {0}")]
    InvalidConfirmedEvent(String),
    #[error("indexed event does not match the confirmed SPP instruction and event")]
    ConfirmedEventMismatch,
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Indexer(RingRpcError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    RingKeys(#[from] RingKeyError),
    #[error(transparent)]
    RingRail(#[from] RingRailError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error(transparent)]
    Hasher(#[from] HasherError),
    #[error(transparent)]
    Stream(#[from] StreamError),
}

/// What a reader does with a row that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowDisposition {
    /// The read failed or the RPC contradicts the program, the position stays.
    Retry,
    /// The row never opens, the position passes it.
    Invalid,
}

/// Names a failure across the SDKs, `test-vectors/audit/row-dispositions.json` pins each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditFailureKind {
    Transport,
    OriginUnavailable,
    InvalidStackHeight,
    MissingAuditorMessage,
    IndexerResponse,
    OriginDecode,
    TransactData,
    EventMismatch,
    ViewingKeyMismatch,
    NonCanonicalViewingKey,
    KeyMaterial,
    AuditData,
}

impl AuditFailureKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::OriginUnavailable => "originUnavailable",
            Self::InvalidStackHeight => "invalidStackHeight",
            Self::MissingAuditorMessage => "missingAuditorMessage",
            Self::IndexerResponse => "indexerResponse",
            Self::OriginDecode => "originDecode",
            Self::TransactData => "transactData",
            Self::EventMismatch => "eventMismatch",
            Self::ViewingKeyMismatch => "viewingKeyMismatch",
            Self::NonCanonicalViewingKey => "nonCanonicalViewingKey",
            Self::KeyMaterial => "keyMaterial",
            Self::AuditData => "auditData",
        }
    }

    pub const fn disposition(self) -> RowDisposition {
        match self {
            Self::Transport
            | Self::OriginUnavailable
            | Self::InvalidStackHeight
            | Self::MissingAuditorMessage
            | Self::IndexerResponse => RowDisposition::Retry,
            Self::OriginDecode
            | Self::TransactData
            | Self::EventMismatch
            | Self::ViewingKeyMismatch
            | Self::NonCanonicalViewingKey
            | Self::KeyMaterial
            | Self::AuditData => RowDisposition::Invalid,
        }
    }
}

impl AuditError {
    pub fn kind(&self) -> AuditFailureKind {
        match self {
            Self::Client(_) | Self::Indexer(_) => AuditFailureKind::Transport,
            Self::Unavailable { .. } => AuditFailureKind::OriginUnavailable,
            Self::InvalidStackHeight(_) => AuditFailureKind::InvalidStackHeight,
            Self::MissingAuditorMessage => AuditFailureKind::MissingAuditorMessage,
            Self::MissingEventIndex
            | Self::InvalidMemberRegistry
            | Self::IncompleteScan
            | Self::InvalidHistoryPage
            | Self::HistoryCursor(_) => AuditFailureKind::IndexerResponse,
            Self::MissingRingTransact
            | Self::SettlementAccounts
            | Self::InvalidEventIndex(_)
            | Self::InvalidConfirmedEvent(_) => AuditFailureKind::OriginDecode,
            Self::InvalidTransactData(_) => AuditFailureKind::TransactData,
            Self::ConfirmedEventMismatch => AuditFailureKind::EventMismatch,
            Self::TxViewingKeyMismatch => AuditFailureKind::ViewingKeyMismatch,
            Self::NonCanonicalViewingKey => AuditFailureKind::NonCanonicalViewingKey,
            Self::Keypair(_) | Self::RingKeys(_) => AuditFailureKind::KeyMaterial,
            Self::AuditorMessageLength(_)
            | Self::MissingTxViewingPk
            | Self::MissingSalt
            | Self::MissingNullifier
            | Self::MissingRingProgram
            | Self::DisclosureField
            | Self::DisclosureLayout
            | Self::InputTreeCount { .. }
            | Self::AuditedUtxosCount { .. }
            | Self::AuditedUtxoMismatch { .. }
            | Self::UnopenedOutput { .. }
            | Self::NullifierPad
            | Self::NullifierKeyMismatch
            | Self::RecoveryProgressMismatch
            | Self::MergeDisclosureMismatch
            | Self::MergeAuditWorkBudget
            | Self::RingRail(_)
            | Self::Transaction(_)
            | Self::Member(_)
            | Self::Hasher(_)
            | Self::Stream(_) => AuditFailureKind::AuditData,
        }
    }

    pub fn disposition(&self) -> RowDisposition {
        self.kind().disposition()
    }
}

impl From<BlockingInsideRuntime> for AuditError {
    fn from(error: BlockingInsideRuntime) -> Self {
        Self::Client(error.into())
    }
}

impl From<RingIndexerError> for AuditError {
    fn from(error: RingIndexerError) -> Self {
        match error {
            RingIndexerError::Refused(refused) => Self::Indexer(refused),
            RingIndexerError::Client(error) => Self::Client(error),
        }
    }
}

#[derive(Debug, Error)]
pub enum AnonymousError {
    #[error(transparent)]
    CompactAssets(#[from] crate::compact_assets::CompactAssetError),
    #[error("compact recovery requires with_asset_rpc")]
    CompactAssetSourceRequired,
    #[error("recovery budget must be positive")]
    RecoveryBudget,
    #[error("recovery scope or progress changed")]
    RecoveryScopeChanged,
    #[error("wallet recovery is incomplete")]
    SyncIncomplete,

    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Keys(#[from] RingKeyError),
    #[error(transparent)]
    Rail(#[from] RingRailError),
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Hasher(#[from] HasherError),
    #[error("viewing history does not parse because {0}")]
    ViewingHistory(String),
    #[error("a rotated viewing key must be new and created after the current one")]
    RotatedKeyNotNewer,
    #[error("an imported viewing key must be new and created before the current one")]
    ImportedKeyNotOlder,
    #[error("the holder holds a viewing key its history lists no entry for")]
    HeldKeyNotInHistory,
    #[error("no pending reply names that sender")]
    UnknownSenderClaim,
    #[error("a history page is out of order or repeats a row")]
    InvalidHistoryPage,
    #[error("a counter update may not move a stored scan position or watermark")]
    ScanProgressMoved,
    #[error("wallet history changed during the scan")]
    ScanHistoryChanged,
    #[error("the wallet document does not parse because {0}")]
    WalletDocument(String),
    #[error("a view tag counter passed u64")]
    CounterOverflow,
    #[error("the recipient's viewing key agrees on no shared secret")]
    RecipientKeyNotContributory,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde::Deserialize;
    use spr_hasher::HasherError;

    use super::*;

    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        kind: String,
        disposition: String,
    }

    #[test]
    fn every_failure_kind_keeps_its_shared_disposition() {
        let vector: Vector = serde_json::from_str(include_str!(
            "../../../test-vectors/audit/row-dispositions.json"
        ))
        .unwrap();
        let pinned: HashMap<String, String> = vector
            .cases
            .into_iter()
            .map(|case| (case.kind, case.disposition))
            .collect();
        let failures = [
            AuditError::Client(ClientError::Rpc("down".to_owned())),
            AuditError::Unavailable {
                signature: Signature::default(),
                message: "not found".to_owned(),
            },
            AuditError::InvalidStackHeight(4),
            AuditError::MissingAuditorMessage,
            AuditError::InvalidHistoryPage,
            AuditError::InvalidEventIndex(1),
            AuditError::InvalidTransactData("forged".to_owned()),
            AuditError::ConfirmedEventMismatch,
            AuditError::TxViewingKeyMismatch,
            AuditError::NonCanonicalViewingKey,
            AuditError::Keypair(KeypairError::InvalidPublicKey),
            AuditError::Hasher(HasherError::InvalidInputLength(1, 2)),
        ];
        assert_eq!(pinned.len(), failures.len());
        for failure in failures {
            let kind = failure.kind();
            let disposition = match failure.disposition() {
                RowDisposition::Retry => "retry",
                RowDisposition::Invalid => "invalid",
            };
            assert_eq!(pinned[kind.name()], disposition, "{}", kind.name());
        }
    }
}
