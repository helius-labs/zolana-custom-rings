//! The custom ring auditor client, free of test utilities so the end-to-end test runs its path.

#[path = "operations/anonymous.rs"]
pub mod anonymous;
#[path = "operations/confidential.rs"]
mod confidential;
#[path = "operations/created_utxos.rs"]
mod created;
#[path = "crypto/decrypt/mod.rs"]
mod decrypt;
#[path = "operations/delivered_utxos.rs"]
pub mod delivered;
#[path = "crypto/deposit.rs"]
mod deposit;
#[path = "codec/deposit_payload.rs"]
mod deposit_payload;
#[path = "crypto/disclosure/mod.rs"]
mod disclosure;
#[path = "crypto/encryption/mod.rs"]
mod encryption;
mod error;
#[path = "rpc/indexer.rs"]
mod indexer;
#[path = "state/known_utxo_index.rs"]
mod known;
#[path = "operations/merge_audit.rs"]
mod merge_audit;
#[path = "codec/origin/mod.rs"]
mod origin;
#[path = "rpc/paging.rs"]
mod paging;
#[path = "codec/program_data.rs"]
mod program_data;
#[path = "security/reader.rs"]
mod reader;
#[path = "operations/records.rs"]
pub mod records;
#[path = "operations/recover.rs"]
mod recover;
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

pub(crate) const REDACTED: &str = "<redacted>";

pub use crate::anonymous::{
    AnonymousRingUtxo, AnonymousScan, AnonymousStream, AnonymousSync, SentCheck, SentPayment,
};
#[cfg(feature = "solana-rpc")]
pub use crate::origin::{confirmed_origin, ORIGIN_TRANSACTION_CONFIG};
pub use crate::tags::{IndexerReads, TagWindow, TAGS_PER_REQUEST};
pub use crate::viewing_history::{
    AdvancedTag, FirstContact, PaymentRecipient, PaymentTag, StreamCounter, TagSelection,
    TransferTagging, TransferTags, ViewingHistory, ViewingKeyEntry, PENDING_RETENTION, TAG_GAP,
    VIEWING_HISTORY_VERSION,
};
pub use crate::{
    confidential::{open_ring_confidential, RingConfidentialNotes, RingConfidentialScan},
    created::{CreatedUtxoPage, CreatedUtxoScan, CreatedUtxos, DepositOwner, DepositOwners},
    decrypt::{EscrowedKeys, KnownUtxos, TransactionAudit},
    deposit::{ring_deposits_in, RingDeposit},
    deposit_payload::deposit_payload,
    disclosure::{
        AnonymousDisclosure, AnonymousInputOpening, AnonymousInputs, AnonymousOutputOpening,
        AuditDisclosure, AuditEnvelope, DeliveredOutputOpening, DisclosurePad, PublishedOutputs,
        SealedAuditEnvelope,
    },
    encryption::{
        auditor_view_tag, open_deposit, open_merge_disclosure, seal_deposits, DepositEncryption,
        DepositOpening, MergeDisclosureEncryption, MergeOpening, NullifierKeyEnvelope,
        SealedNullifierKey,
    },
    error::{AnonymousError, AuditError},
    indexer::{AsyncRingIndexer, RingIndexer, RingIndexerError},
    known::KnownUtxoIndex,
    merge_audit::{
        AuditedMerge, MergeAudit, MergeAuditPage, MergeAuditResult, MergeKeys, UnresolvedMerge,
    },
    origin::{
        ring_event_origin_in, ConfirmedDeposit, ConfirmedEvent, ConfirmedEventKind,
        ConfirmedMergeDisclosure, RingOrigin, RingWithdrawal, TransactionOrigin,
    },
    reader::{Ed25519ReaderKey, P256ReaderKey, ReaderKey, ReaderKeyError},
    records::{
        member_record, quad_path, storage_apply_proof_inputs, MemberOpeningRead, RecordPoolCheck,
        RecordPoolRead, StorageTip,
    },
    recover::{MemberRecovery, RecoveredNotes, RingRecovery, SourceMember},
    scan::{AuditedPage, RingScan, RingScanPage, ScanPage},
    types::{
        AuditedInput, AuditedInputOpening, AuditedOutput, AuditedSender, AuditedTransaction,
        AuditedUtxo, CreatedUtxo, InputOpening, InputRing, KnownUtxo, OutputOpening,
        OutputPayloadError, OutputPayloadErrorKind, RingOwnerTag, UtxoOwner,
    },
};
pub use program_data::{program_data, ProgramData, PROGRAM_DATA_METADATA_LEN};
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
