//! The custom ring auditor client, free of test utilities so the end-to-end test runs its path.

#[path = "operations/anonymous.rs"]
pub mod anonymous;
#[path = "state/anonymous_wallet.rs"]
mod anonymous_wallet;
#[path = "operations/confidential.rs"]
mod confidential;
#[path = "crypto/decrypt/mod.rs"]
mod decrypt;
#[path = "operations/delivered_utxos.rs"]
pub mod delivered;
#[path = "crypto/disclosure/mod.rs"]
mod disclosure;
#[path = "crypto/encryption/mod.rs"]
mod encryption;
mod error;
#[path = "state/exposed_notes.rs"]
mod exposed_notes;
#[path = "rpc/history.rs"]
pub mod history;
#[path = "rpc/indexer.rs"]
mod indexer;
#[path = "state/known_utxo_index.rs"]
mod known;
#[path = "operations/merge_audit.rs"]
mod merge_audit;
#[path = "state/merge_ledger.rs"]
mod merge_ledger;
#[path = "codec/origin/mod.rs"]
mod origin;
#[path = "codec/program_data.rs"]
mod program_data;
#[path = "security/reader.rs"]
mod reader;
#[path = "operations/records.rs"]
pub mod records;
#[path = "operations/recover.rs"]
mod recover;
#[path = "operations/resolver.rs"]
pub mod resolver;
#[cfg(feature = "rpc")]
#[path = "rpc/mod.rs"]
pub mod rpc;
#[path = "operations/scan.rs"]
mod scan;
#[path = "rpc/tags.rs"]
pub mod tags;
mod types;
#[path = "state/viewing_history.rs"]
pub mod viewing_history;
#[path = "operations/viewing_rotation.rs"]
mod viewing_rotation;

pub(crate) const REDACTED: &str = "<redacted>";

pub use crate::anonymous::{
    AnonymousRingUtxo, AnonymousScan, AnonymousStream, AnonymousSync, AuditorRecovery,
    RecoveryStatus, SenderClaim, SentCheck, SentPayment,
};
pub use crate::anonymous_wallet::{
    AnonymousWallet, LedgerScan, PendingClaim, PendingNote, ScanCommit,
};
#[cfg(feature = "solana-rpc")]
pub use crate::origin::{confirmed_origin, ConfirmedRingOrigins, ORIGIN_TRANSACTION_CONFIG};
pub use crate::tags::{HistoryRows, IndexerReads, TagWindow, TAGS_PER_REQUEST};
pub use crate::viewing_history::{
    AdvancedTag, StreamCounter, ViewingHistory, ViewingKeyEntry, PENDING_RETENTION,
};
pub use crate::{
    confidential::{
        open_ring_confidential, RingConfidentialNotes, RingConfidentialScan, RingFullScan,
    },
    decrypt::{FramedRow, TransactionAudit},
    disclosure::{AuditEnvelope, AuditStreamSeal, OpenedAudit, SealedAuditStream},
    encryption::{
        auditor_view_tag, open_merge_record, open_owned_merge_record, MergeRecordSeal,
        NullifierKeyEnvelope, SealedMergeCiphertexts, SealedMergeOpening, SealedNullifierKey,
    },
    error::{AnonymousError, AuditError, AuditFailureKind, RowDisposition},
    exposed_notes::{
        is_zero_key, mint_balances, note_state, verify_ring_owned, MintBalance, NoteState,
        RingOwnedUtxos,
    },
    indexer::{AsyncRingIndexer, RingIndexer, RingIndexerError},
    known::KnownUtxoIndex,
    merge_audit::{confirmed_merge, MergeAudit, MergeAuditPage},
    merge_ledger::{AuditedMergeOutput, ConfirmedMerge, MergeId, MergeLedger, MergeRecordOutput},
    origin::{
        ring_event_origin_in, ConfirmedEvent, ConfirmedEventKind, ConfirmedMergeDisclosure,
        RingOrigin, RingWithdrawal, TransactionOrigin,
    },
    reader::{Ed25519ReaderKey, P256ReaderKey, ReaderKey, ReaderKeyError},
    records::{
        member_record, owner_record_key, quad_path, storage_apply_proof_inputs, MemberOpeningRead,
        RecordPoolCheck, RecordPoolRead, StorageTip,
    },
    recover::{
        MemberRecovery, RecoveredNotes, RecoveryProgress, RecoveryStep, RingRecovery, SourceMember,
    },
    resolver::{AuthorizationCheck, RecipientResolver, ResolveError, ResolvedRecipient},
    scan::{AuditedPage, RingScan, RingScanPage, ScanPage, SkippedRow},
    types::{
        AuditedEntryInput, AuditedOutput, AuditedTransaction, AuditedUtxo, CreatedUtxo, KnownUtxo,
        OutputOpening, OutputPayloadError, OutputPayloadErrorKind, RingOwnerTag, UtxoOwner,
    },
};
pub use program_data::{program_data, ProgramData, PROGRAM_DATA_METADATA_LEN};
pub use viewing_rotation::{ViewingRotation, ViewingRotationError};
pub use zolana_ring_indexer::rpc::RingRpcError;

/// The answer to a one-item request, a holder that answers more or less is refused.
pub fn exactly_one<T>(answers: Vec<T>) -> Result<T, spr_transaction::TransactionError> {
    let got = answers.len();
    <[T; 1]>::try_from(answers)
        .map(|[answer]| answer)
        .map_err(|_| spr_transaction::TransactionError::IncompleteDerivation { got, want: 1 })
}

/// One answer per request, a holder that answers more or less is refused.
pub(crate) fn exactly_one_each<T>(
    answers: Vec<T>,
    want: usize,
) -> Result<Vec<T>, spr_transaction::TransactionError> {
    match answers.len() {
        got if got == want => Ok(answers),
        got => Err(spr_transaction::TransactionError::IncompleteDerivation { got, want }),
    }
}
