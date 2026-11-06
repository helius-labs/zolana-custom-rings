use custom_ring_interface::{
    key_catalog::RingCircuit, storage::StorageError, stream::StreamError, CustomRingError,
    PublicSlotError, RingRail,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_api::BlockingInsideRuntime;
use spr_client::ClientError;
use spr_hasher::HasherError;
use spr_interface::error::ShieldedPoolError;
use spr_keypair::KeypairError;
use spr_transaction::TransactionError;
use spr_tree::TreeError;
use thiserror::Error;
use zolana_ring_client::{rpc::RecordUpdateError, AnonymousError, RingIndexerError, RingRpcError};
use zolana_ring_keys::RingKeyError;
use zolana_ring_member_registry::RecordTreeError;
use zolana_ring_policy::{
    ListId, MemberError, PolicyTableError, RuleRefusal, RuleTableError, SourceMapError, Writer,
};
use zolana_ring_transaction::RingRailError;

#[derive(Debug, Error)]
pub enum RingError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Indexer(RingRpcError),
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Program(#[from] CustomRingError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Hasher(#[from] HasherError),
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error(transparent)]
    Rules(#[from] RuleTableError),
    #[error(transparent)]
    PolicyTable(#[from] PolicyTableError),
    #[error(transparent)]
    SourceMap(#[from] SourceMapError),
    #[error(transparent)]
    PublicSlots(#[from] PublicSlotError),
    #[error(transparent)]
    Records(#[from] RecordTreeError),
    #[error(transparent)]
    RecordStatement(#[from] zolana_ring_member_registry::RecordStatementError),
    #[error(transparent)]
    Audit(#[from] zolana_ring_client::AuditError),
    #[error(transparent)]
    Encoding(#[from] wincode::WriteError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Tree(#[from] TreeError),
    #[error(transparent)]
    Pool(#[from] ShieldedPoolError),
    #[error(transparent)]
    Blocking(#[from] BlockingInsideRuntime),
    #[error(transparent)]
    Keys(#[from] RingKeyError),
    #[error(transparent)]
    Rail(#[from] RingRailError),
    #[error(transparent)]
    Anonymous(#[from] AnonymousError),
    #[error(transparent)]
    Signer(#[from] solana_signer::SignerError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    RelayProofInputs(#[from] zolana_ring_client::rpc::RelayProofInputsError),
    #[error("custom ring account {address} is invalid")]
    InvalidAccount { address: Address },
    #[error("custom ring config does not exist")]
    MissingRingConfig,
    #[error("the ring has no ring policy")]
    MissingRingPolicy,
    #[error("registry {registry} is not an initialized storage registry")]
    NotStorageRegistry { registry: Address },
    #[error("the ring is not registered with the shielded pool, run Initialize")]
    RingNotRegistered,
    #[error("the shielded pool has not activated the ring, governance runs set_ring_activation")]
    RingNotActivated,
    #[error("the ring is paused")]
    RingPaused,
    #[error("the ring has no delegate")]
    MissingDelegate,
    #[error("asset registry is required")]
    MissingAssetRegistry,
    #[error("the compiled table differs from the stored rows")]
    TableMismatch,
    #[error("the rule table does not reproduce the pinned policy hash")]
    HashMismatch,
    #[error("the table does not reference the list {0:?}")]
    UnreferencedList(ListId),
    #[error("the shared sources name the list {0:?} twice")]
    DuplicateSharedSource(ListId),
    #[error("the write changes no list")]
    EmptyListWrite,
    #[error(transparent)]
    RecordUpdate(#[from] RecordUpdateError),
    #[error("the record update needs the signature of {expected}")]
    RecordUpdateSigner { expected: Address },
    #[error("a wallet update awaits no list or a list outside allow, reader and approval")]
    InvalidAwaitedLists,
    #[error("ring rpc answered another update id")]
    RecordUpdateIdMismatch,
    #[error("the {writer:?} writer may not write the list {list:?}")]
    ListNotWritable { list: ListId, writer: Writer },
    #[error("the indexer's registry differs from the chain's, the projection lags")]
    RecordProjectionStale,
    #[error("the transaction takes {bytes} bytes, a v1 transaction carries {limit}")]
    TransactionTooLarge { bytes: usize, limit: usize },
    #[error("the transaction names {addresses} addresses, a v1 transaction carries {limit}")]
    TooManyAddresses { addresses: usize, limit: usize },
    #[error("the transfer hands SPP {accounts} accounts, one call takes {limit}")]
    TooManySettlementAccounts { accounts: usize, limit: usize },
    #[error(
        "a {inputs}x{outputs} transfer of {bytes} bytes exceeds {limit}, split the payout or merge notes first"
    )]
    TransferTooWide {
        inputs: usize,
        outputs: usize,
        bytes: usize,
        limit: usize,
    },
    #[error(
        "no set of up to {max_trees} input trees holds {amount} of {mint} in {max_inputs} inputs",
        max_trees = spr_interface::MAX_INPUT_TREES
    )]
    Unfunded {
        mint: Address,
        amount: u64,
        max_inputs: usize,
    },
    #[error("{exposed_if_spent} of {mint} sits in zero-key notes, a spend of {amount} needs a public spend naming the wallet")]
    UnfundedPastExposure {
        mint: Address,
        amount: u64,
        exposed_if_spent: u64,
    },
    #[error("input {index} is a zero-key note of the sender and spending it publishes the wallet, call spend_public")]
    ZeroKeyInputUnnamed { index: usize },
    #[error("a public spend named {named} but the sender is {sender}")]
    PublicSpendWalletMismatch { named: Address, sender: Address },
    #[error("a public spend signs the transaction, it cannot prove its owner in the proof")]
    PublicSpendInProofOwner,
    #[error(transparent)]
    AddressCeiling(#[from] crate::AddressCeilingError),
    #[error(transparent)]
    Resolve(#[from] zolana_ring_client::ResolveError),
    #[error(transparent)]
    DelegateSource(#[from] crate::DelegateSourceError),
    #[error("a deposit frame proves once")]
    DepositFrameReused,
    #[error("a deposit frame spends a note")]
    DepositSpendsNote,
    #[error("tree account {address} is missing")]
    MissingTree { address: Address },
    #[error("tree account {address} is not a shielded pool tree")]
    InvalidTree { address: Address },
    #[error("tree {tree} has id {expected}, the transfer was prepared for {found}")]
    TreeIdMismatch {
        tree: Address,
        expected: u16,
        found: u16,
    },
    #[error("indexer returned an incomplete proof set")]
    IncompleteProofSet,
    #[error("the catalog has no {rail} key for the transfer")]
    ShapeUnkeyed { rail: RingRail },
    #[error("a deposit takes one to eight recipients and at most one leg per public slot")]
    DepositUnkeyed,
    #[error("a salted list reads enrolled owner {member:?} and no list salt is known")]
    ListSaltUnknown { member: [u8; 32] },
    #[error("no known list salt of owner {member:?} opens its tracking leaf's list tag")]
    ListSaltMismatch { member: [u8; 32] },
    #[error("the policy refuses the transfer, {0}")]
    PolicyRuleUnsatisfied(#[from] RuleRefusal),
    #[error("transfer references another ring {0}")]
    ForeignRing(Address),
    #[error("a default-ring note carries ring data")]
    RingDataOutsideRing,
    #[error("the input with nullifier {nullifier:?} is spent twice")]
    DuplicateInput { nullifier: [u8; 32] },
    #[error("the transfer spends one owner's notes, input {index} has another owner")]
    MixedOwners { index: usize },
    #[error("a delegate move names one source twice")]
    RepeatedDelegateSource,
    #[error(transparent)]
    TokenAccountSetup(#[from] zolana_ring_client::rpc::TokenAccountSetupError),
    #[error("input {index} spends under a key its owner's tracking row does not hold")]
    InputKeyNotEnrolled { index: usize },
    #[error("output {slot_index} names the literal zero key, a zero-key note commits Poseidon(0)")]
    RecipientLiteralZeroKey { slot_index: usize },
    #[error("the owner at output {slot_index} is enrolled, the zero key does not pay it")]
    EnrolledRecipientAtZeroKey { slot_index: usize },
    #[error("output {slot_index} names a viewing key other than its owner's authorization holds, ask for a new address")]
    RecipientViewingKeyStale { slot_index: usize },
    #[error("the transfer has {owners} owner signers, its accounts leave room for {limit}")]
    TooManyOwnerSigners { owners: usize, limit: usize },
    #[error("an anonymous transfer leads with its hidden owner's note, a frame of only public owners takes the confidential family")]
    HiddenOwnerMissing,
    #[error("the owner {owner} spends an input with no nullifier key in the transfer")]
    MissingCoOwnerKey { owner: Address },
    #[error("output {index} owner marker does not match whether it leaves the ring")]
    RingOutputMarkerMismatch { index: usize },
    #[error("the charged outflow {charged_outflow} of {asset:?} exceeds the cap {cap}")]
    OutflowCapExceeded {
        asset: [u8; 32],
        cap: u64,
        /// A public gross reaches past `u64::MAX` under the policy's 72-bit aggregate bound.
        charged_outflow: u128,
    },
    #[error("the payments' total overflows")]
    PaymentOverflow,
    #[error("the compact transfer expands to external data the SPP proof does not bind")]
    ExternalDataMismatch,
    #[error("a ring merge of {width} slots is no width SPP keys")]
    MergeTooWide { width: usize },
    #[error("a zero-key merge names its owner as a shielded address under the zero key")]
    MergeOwnerKey,
    #[error("the pinned SPP client proves no delegate exit until the exit keys are pinned")]
    ExitProofUnavailable,
    #[error("a deposit to an anonymous ring pays a ring address")]
    AnonymousDepositUntagged,
    #[error("the ring is not anonymous, its owners sign in public")]
    NotAnonymousRing,
    #[error("an anonymous ring spends only through the hidden owner's proof")]
    MissingAnonymousSigner,
    #[error("a deposit leg of a relayed transfer names the relay's fee payer as its funder")]
    RelayFeePayerFundsDeposit,
    #[error("a default-ring spend of {inputs} inputs fits no entry key, split the transfer")]
    DefaultRingSpendTooWide { inputs: usize },
    #[error("input {index} is a ring note beside the hidden owner's default-ring note, use the public-owner rail")]
    EntryRingInput { index: usize },
    #[error("the hidden signer does not match the sender")]
    AnonymousSignerMismatch,
    #[error("the in-proof owner does not match the sender")]
    InProofOwnerMismatch,
    #[error("input {index} is a default-ring note the in-proof owner rail cannot spend")]
    InProofDefaultRingInput { index: usize },
    #[error("the confidential relay carries no owner signature")]
    MissingInProofOwnerSignature,
    #[error("public transaction signers must differ from the hidden owner")]
    AnonymousPublicSignerLinksOwner,
    #[error("withdrawal destination {0} names the hidden owner")]
    AnonymousExitLinksOwner(Address),
    #[error("withdrawal token account {0} has a delegate or a close authority")]
    AnonymousExitTokenAccountShared(Address),
    #[error("withdrawal token account {0} is at a keypair address, SPP takes an ATA or a PDA")]
    AnonymousExitTokenAccountOnCurve(Address),
    #[error("withdrawal destination {0} is not a system account without data")]
    AnonymousExitAccountHasData(Address),
    #[error("withdrawal token account {0} is missing or not an initialized account of its mint")]
    AnonymousExitTokenAccountInvalid(Address),
    #[error(
        "withdrawal token account {token_account} is owned by {owner}, the transfer names {named}"
    )]
    AnonymousExitNamedOwnerMismatch {
        token_account: Address,
        named: Address,
        owner: Address,
    },
    #[error("withdrawal destination {destination} is refused, {refusal}")]
    AnonymousExitRefused {
        destination: Address,
        refusal: CustomRingError,
    },
    #[error("an exit token owner names no SPL withdrawal")]
    AnonymousExitTokenOwnerWithoutSplExit,
    #[error("an anonymous transfer writes no cache and names no compact slot")]
    InvalidAnonymousSlot,
    #[error("the read cache names a note the transfer does not spend")]
    CachedInputUnknown,
    #[error("ring address {address} pays into ring {ring}, the transfer runs in another")]
    ForeignRingAddress { address: Address, ring: Address },
    #[error("merge inputs belong to another tree")]
    InputTreeMismatch,
    #[error("the member's nullifier key does not derive its address")]
    NullifierKeyMismatch,
    #[error("the member record is not included under the requested root")]
    InvalidRecordOpening,
    #[error("the ring key set has no verifying key for {0:?}")]
    MissingVerifyingKey(RingCircuit),
    #[error("no ring key serves {0:?}")]
    UncataloguedCircuit(RingCircuit),
    #[error("no pinned proving key for {0:?}")]
    UnpinnedProvingKey(RingCircuit),
    #[error("the auditor key encryption proof is missing its BSB22 commitment")]
    MissingCommitment,
    #[error("the relayed viewing secret does not derive the external data's viewing key")]
    RelayViewingKeyMismatch,
    #[error("the relayed external data does not close with the ring auditor's message")]
    RelayAuditorMessage,
    #[error("the sealed auditor stream does not open under the {row:?} row the records select, seal under that row and sign again")]
    ResealRequired { row: crate::SealRow },
    #[error("the transfer pays from {payer}, the relay quote names {fee_payer}")]
    RelayPayerMismatch { payer: Address, fee_payer: Address },
    #[error("ring rpc names another relay than the request hashes to")]
    RelayIdMismatch,
    #[error("the relay asks the hidden owner for a public signature")]
    RelayAskedOwnerSignature,
    #[error("the relay message is refused because {0}")]
    RelayMessage(#[from] crate::MessageMismatch),
    #[error("{signature} failed with {error}")]
    Rejected {
        signature: Signature,
        error: solana_transaction_error::TransactionError,
    },
    #[error("{owner} holds a tracking authorization under another nullifier key, the first key is final")]
    AlreadyEnrolled { owner: Address },
    #[error("the journal did not record the enrollment attempt, nothing was sent")]
    AttemptNotRecorded(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("preflight refused the enrollment with {0}")]
    EnrollmentRefused(solana_transaction_error::TransactionError),
    #[error("the recorded enrollment attempt does not decode")]
    AttemptUnreadable,
    #[error("the enrollment attempt reconciles to {0:?}, only an expired attempt goes again")]
    AttemptNotExpired(crate::enrollment::EnrollmentOutcome),
    #[error("ring rpc failed the relay with {reason}")]
    RelayFailed { reason: String },
    #[error("the submission sends only an attempt its charged outflows were read from")]
    SubmissionUnproved,
    #[error("{owner} holds no tracking authorization, enroll before a rotation")]
    RotationUnenrolled { owner: Address },
    #[error("the viewing history's current key differs from the key holder's")]
    ViewingHistoryNotCurrent,
    #[error("the tracking authorization of {owner} names a viewing key the wallet does not hold")]
    ViewingKeyNotHeld { owner: Address },
    #[error("the tracking authorization of {owner} does not hold the rotated viewing key")]
    ViewingKeyNotPublished { owner: Address },
    #[error("the owner of write {write_index} holds no applied tracking row")]
    WriteOwnerNotEnrolled { write_index: u8 },
    #[error("write {write_index} is not the list key of its owner under the salt")]
    ListKeyMismatch { write_index: u8 },
    #[error("the salted owners name other write positions than the private writes")]
    PrivateWritesMismatch,
}

impl From<RingIndexerError> for RingError {
    fn from(error: RingIndexerError) -> Self {
        match error {
            RingIndexerError::Refused(refused) => Self::Indexer(refused),
            RingIndexerError::Client(error) => Self::Client(error),
        }
    }
}

impl RingError {
    /// The ring indexer trails or passed the chain state the read was asked under.
    pub fn is_projection_lag(&self) -> bool {
        matches!(
            self,
            Self::RecordProjectionStale
                | Self::Client(ClientError::IndexerProofDataNotReady)
                | Self::Indexer(
                    RingRpcError::RegistryOutOfSync | RingRpcError::RegistryRootChanged
                )
        )
    }
}
