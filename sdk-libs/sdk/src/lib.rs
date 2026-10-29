//! Instruction builders, proofs and submission for the custom ring program, a blocking caller
//! wraps an operation in `zolana.block_on(op.prove(zolana.as_async()))`.

#[path = "state/account.rs"]
mod account;
#[path = "operations/admin.rs"]
mod admin;
#[path = "rpc/client.rs"]
mod client;
#[path = "validation/co_signer.rs"]
mod co_signer;
#[path = "operations/deposit.rs"]
mod deposit;
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
#[path = "operations/register_key.rs"]
mod register_key;
#[path = "codec/request.rs"]
mod request;
#[path = "operations/utxo_selection.rs"]
mod select;
#[path = "operations/storage.rs"]
mod storage;
#[path = "operations/submission.rs"]
mod submission;
#[cfg(test)]
mod tests;
#[path = "state/trees.rs"]
mod trees;

pub(crate) const REDACTED: &str = "<redacted>";

pub use custom_ring_interface::{
    compute_unit_limit, tag, CoSignScope, CustomRingProof, InstructionTag, ListRegistry, RingKind,
    RingMode,
};
pub use spr_program::instruction::{DepositAsset, DepositSplAccounts};

pub use crate::prover::secret_json_body;
pub use crate::{
    account::{
        CustomRing, CustomRingCoSigner, CustomRingConfig, PinnedPolicy, QueueStatus, RegistryRoot,
        RegistryStatus, RingRegistration, RingStatus,
    },
    admin::{
        ClearCoSigner, CreateConfig, CreateMemberRegistry, GrantReader, InitSppRingConfig,
        PolicyRecords, PolicyRules, RevokeReader, SetAuthority, SetCoSigner, SetDelegate,
        SetSourceOwner, SourceOwner,
    },
    client::{RingClient, RingIndexerBackend},
    deposit::{
        fetch_asset_id_async, DepositRecipient, PreparedRingDeposit, RingDeposit,
        RingDepositReceipt,
    },
    error::RingError,
    merge::{
        CustomRingMerge, CustomRingMergeInstruction, MergeProofInput, PreparedCustomRingMerge,
        ProvenCustomRingMerge, RingMergeOperation, MAX_RING_MERGE_INPUTS,
        MERGE_DEFAULT_INPUT_COUNT,
    },
    pipeline::{
        shape_keyed, Anonymous, AnonymousMove, AnonymousPayment, AnonymousTransfer,
        CustomRingTransfer, CustomRingTransferInput, DelegateMove, DelegateOutput, DelegatePayment,
        DelegateTransfer, DelegateTransferInput, Delegated, EntrySpend, Owner, ProvenRingTransfer,
        Rail, RailKind, RingPayment, RingSender, RingTransfer,
    },
    records::{
        AuthorityListWrite, AuthorityRecordUpdate, MemberListWrite, MemberRecords,
        ProvenRecordWrite, RecordApplication, RecordUpdateService, RecordUpdateTarget,
        WalletRecordUpdate,
    },
    register_key::{
        EscrowedRecipients, KeyEscrowAuthority, KeyRegistration, ProvenKeyRegistration,
        RegisterKey, SealedEscrow,
    },
    select::{select_merge_where, select_spend_where},
    storage::{
        InitializeStorage, StorageApplyProof, SyncRoots, UpdateStorage, UpdateStorageAuthority,
    },
    submission::{RingOperation, RingSubmission, SettledSubmission, SubmissionStatus},
    trees::tree_id,
};
pub use zolana_ring_client::FirstContact;
