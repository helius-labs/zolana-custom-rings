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
    #[error("transaction carries no message tagged for the auditor")]
    MissingAuditorMessage,
    #[error("transaction carries more than one message tagged for the auditor")]
    DuplicateAuditorMessage,
    /// The program accepts the auditor message only as the last message.
    #[error("auditor message is at index {index} of {count} messages, expected the last")]
    AuditorMessageNotLast { index: usize, count: usize },
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
    #[error("the disclosed output seed is not the one the transaction key derives")]
    SeedOutMismatch,
    #[error("disclosure padding is not zero")]
    DisclosurePadding,
    #[error("{trees} input trees do not match {inputs} published inputs")]
    InputTreeCount { trees: usize, inputs: usize },
    #[error("spent UTXO {commitment:?} is in no output the auditor opened")]
    UnseenInput { commitment: [u8; 32] },
    #[error(
        "fewer known notes of the sender carry spent prefix {prefix:#034x} than inputs name it"
    )]
    UnseenInputPrefix { prefix: u128 },
    #[error("audited notes answer {got} of {want} requested hashes")]
    AuditedUtxosCount { got: usize, want: usize },
    #[error("audited note names both or neither of its nullifier key and owner hash")]
    AuditedUtxoOwner,
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
    #[error("deposit count must be between one and eight, got {0}")]
    DepositCount(usize),
    #[error("deposit slot must be below eight, got {0}")]
    DepositSlot(usize),
    #[error("deposit opening does not match the owner commitment")]
    DepositOpeningMismatch,
    #[error("recovered nullifier key does not match the source member identity")]
    NullifierKeyMismatch,
    #[error("member registry root or paged record opening is invalid")]
    InvalidMemberRegistry,
    #[error("ring history exceeds the scan bound, spent notes cannot be excluded")]
    IncompleteScan,
    #[error("indexer page names neither a next cursor nor a scan frontier")]
    ScanFrontierMissing,
    #[error("indexer page holds more rows than its request allowed")]
    PageOverflow,
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
    #[error("confirmed audited deposit data is undecodable {0}")]
    InvalidDepositData(String),
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
    #[error("viewing history version {version} needs a sync from index 0")]
    ViewingHistoryVersion { version: u32 },
    #[error("viewing history does not parse because {0}")]
    ViewingHistory(String),
    #[error("the viewing history's current key is not the wallet's viewing key")]
    ViewingKeyNotCurrent,
    #[error("a rotated viewing key must be new and created after the current one")]
    RotatedKeyNotNewer,
    #[error("a view tag counter passed u64")]
    CounterOverflow,
    #[error("the recipient's viewing key agrees on no shared secret")]
    RecipientKeyNotContributory,
}
