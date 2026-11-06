//! Instruction builders, proofs and submission for the custom ring program, a blocking caller
//! wraps an operation in `zolana.block_on(op.prove(zolana.as_async()))`.

#[path = "state/account.rs"]
mod account;
#[path = "validation/address_ceiling.rs"]
mod address_ceiling;
#[path = "operations/admin.rs"]
mod admin;
#[path = "rpc/client.rs"]
mod client;
#[path = "validation/co_signer.rs"]
mod co_signer;
#[path = "operations/delegate_source.rs"]
mod delegate_source;
#[path = "operations/deposit.rs"]
mod deposit;
#[path = "operations/enrollment.rs"]
pub mod enrollment;
mod error;
#[path = "state/heap.rs"]
mod heap;
#[path = "validation/limits.rs"]
mod limits;
#[path = "operations/merge.rs"]
mod merge;
#[path = "operations/pipeline/mod.rs"]
mod pipeline;
#[path = "rpc/projection.rs"]
mod projection;
#[path = "rpc/prover.rs"]
mod prover;
#[path = "operations/records.rs"]
mod records;
#[path = "rpc/relay.rs"]
mod relay;
#[path = "validation/relay_message.rs"]
mod relay_message;
#[path = "codec/request.rs"]
mod request;
#[path = "operations/utxo_selection.rs"]
mod select;
#[path = "rpc/signature_history.rs"]
mod signature_history;
#[path = "operations/storage.rs"]
mod storage;
#[path = "operations/submission.rs"]
mod submission;
#[cfg(test)]
mod tests;
#[path = "state/trees.rs"]
mod trees;
#[path = "operations/viewing_rotation.rs"]
mod viewing_rotation;

pub(crate) const REDACTED: &str = "<redacted>";

pub use custom_ring_interface::{
    compute_unit_limit, tag, CoSignScope, CustomRingProof, InstructionTag, ListRegistry, RingKind,
    RingMode,
};
pub use spr_program::instruction::{DepositAsset, DepositSplAccounts};

pub use crate::prover::secret_json_body;
pub use crate::{
    account::{
        CustomRing, CustomRingCoSigner, CustomRingConfig, PinnedPolicy, RingRegistration,
        RingStatus,
    },
    address_ceiling::{
        AddressCeiling, AddressCeilingError, CeilingDecision, Fit, FitError, FitSigners,
        MergeCapacity, MergeGroup, SetupEffect, SpentInput, TransactionFit,
    },
    admin::{
        ClearCoSigner, InitialPolicy, Initialize, PolicyTable, PolicyUpdate, SetCoSigner,
        SetDelegate, SourceOwner, UpdateAuthority, UpdatePolicy,
    },
    client::{RingClient, RingIndexerBackend},
    delegate_source::{
        AllowedNullifiers, DelegateSourceError, ResolvedSource, SourceEnrollment,
        TrackingEnrollment,
    },
    deposit::{
        fetch_asset_id_async, DepositOutput, DepositRecipient, PreparedRingDeposit, RingDeposit,
        RingDepositBatch, RingDepositBatchReceipt, RingDepositReceipt,
    },
    enrollment::{
        Enroll, EnrollInstruction, EnrollRelay, EnrollmentAttempt, EnrollmentJournal,
        EnrollmentOutcome, WriteOwnerGrant,
    },
    error::RingError,
    merge::{
        CustomRingMerge, CustomRingMergeInstruction, FittedMerge, MergeProofInput, MergeRelay,
        PreparedCustomRingMerge, ProvenCustomRingMerge, RingMergeOperation, MAX_RING_MERGE_INPUTS,
        MERGE_DEFAULT_INPUT_COUNT,
    },
    pipeline::{
        entry_shape_keyed, shape_keyed, transfer_key, Anonymous, AnonymousMove, AnonymousPayment,
        AnonymousTransfer, ApplicationData, CachedNote, CoOwner, CustomRingTransfer,
        CustomRingTransferInput, DelegateCandidates, DelegateFunding, DelegateMove, DelegateOutput,
        DelegatePayment, DelegateSource, DelegateTransfer, DelegateTransferInput,
        DelegateWithdrawal, Delegated, EntrySpend, NoteData, Owner, OwnerExposure,
        ProvenRingTransfer, PublicOwnerTransfer, PublicOwners, Rail, RailKind, ReadCache, Relayed,
        RelayedTransfer, RelayedTransferInput, RingPayment, RingSender, RingTransfer, SealRow,
        TransferKey, UnsignedRelay,
    },
    records::{
        AuthorityRecordUpdate, MemberRecords, OwnerSaltCheck, RecordUpdateService,
        RecordUpdateTarget, SaltedOwnerCheck, WalletRecordUpdate,
    },
    relay::{
        PendingSignature, PreparedAuthorityTransfer, PreparedRelay, RelaySent,
        RequestedAuthorityTransfer, RingRelay,
    },
    relay_message::{
        ApprovalLimit, ApprovalOpening, CoSignerApproval, CoSignerRule, ExactApproval, FundedLeg,
        FunderApproval, MessageMismatch, OutputTotalsOpening, OwnerApproval, PublicTotalsOpening,
        RelayFunderTerms, RelayTransferTerms, SlotOpening, TokenAccountCreate, VerifiedMessage,
    },
    select::{select_merge_where, select_spend_where},
    signature_history::SignatureHistory,
    storage::{
        tracking_apply_inputs, ApplyEnrollments, EnrollPending, InitializeStorage,
        PrivateStorageWrite, ProvenPrivateWrite, SaltedOwnerWrite, StorageApplyProof,
        UpdateStorage, UpdateStorageAuthority,
    },
    submission::{
        live_registry, RingOperation, RingSubmission, SettledSubmission, SubmissionStatus,
    },
    trees::{tree_id, written_tree_fees},
    viewing_rotation::{RotateViewingKey, RotatedViewingKey},
};
