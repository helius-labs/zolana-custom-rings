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
use spr_program::instruction::DepositBuildError;
use spr_transaction::TransactionError;
use spr_tree::TreeError;
use thiserror::Error;
use zolana_ring_client::{rpc::RecordUpdateError, AnonymousError, RingIndexerError, RingRpcError};
use zolana_ring_keys::RingKeyError;
use zolana_ring_member_registry::RecordTreeError;
use zolana_ring_policy::{
    ListId, Member, MemberError, PolicyTableError, RuleRefusal, RuleTableError, SourceMapError,
    Writer,
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
    Audit(#[from] zolana_ring_client::AuditError),
    #[error(transparent)]
    Encoding(#[from] wincode::WriteError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    DepositBuild(#[from] DepositBuildError),
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
    #[error("the delegate moves notes on escrowed policy rings only")]
    DelegateRequiresEscrow,
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
    #[error("curator registry {address} is not an initialized member registry")]
    InvalidCuratorRegistry { address: Address },
    #[error("the write changes no list")]
    EmptyListWrite,
    #[error(transparent)]
    RecordUpdate(#[from] RecordUpdateError),
    #[error("the record update needs the signature of {expected}")]
    RecordUpdateSigner { expected: Address },
    #[error("the escrow registration names another member")]
    EscrowMemberMismatch,
    #[error("an enrolment awaits no list or a list outside allow, reader and approval")]
    EnrolmentLists,
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
    #[error(
        "a {inputs}x{outputs} transfer of {bytes} bytes exceeds {limit}, split the payout or merge notes first"
    )]
    TransferTooWide {
        inputs: usize,
        outputs: usize,
        bytes: usize,
        limit: usize,
    },
    #[error("no tree holds {amount} of {mint} in {max_inputs} inputs")]
    Unfunded {
        mint: Address,
        amount: u64,
        max_inputs: usize,
    },
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
    #[error("the transfer needs a shape no {rail} key serves")]
    ShapeUnkeyed { rail: RingRail },
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
    #[error("output {index} owner marker does not match whether it leaves the ring")]
    RingOutputMarkerMismatch { index: usize },
    #[error("the outflow {outflow} of {asset:?} exceeds the cap {cap}")]
    OutflowCapExceeded {
        asset: [u8; 32],
        cap: u64,
        outflow: u64,
    },
    #[error("an outflow sum overflows")]
    OutflowOverflow,
    #[error("the payments' total overflows")]
    PaymentOverflow,
    #[error("a public deposit of {asset:?} exceeds what leaves the sender")]
    DepositAboveOutflow { asset: [u8; 32] },
    #[error("the compact transfer expands to external data the SPP proof does not bind")]
    ExternalDataMismatch,
    #[error("a ring merge of {width} slots does not fit a v1 transaction beside its disclosure")]
    MergeTooWide { width: usize },
    #[error("the ring is not anonymous, its owners sign in public")]
    NotAnonymousRing,
    #[error("an anonymous ring spends only through the hidden owner's proof")]
    MissingAnonymousSigner,
    #[error("a default-ring spend of {inputs} inputs fits no entry key, split the transfer")]
    DefaultRingSpendTooWide { inputs: usize },
    #[error("a default-ring spend opens every input in full, input {index} carries data")]
    EntryInputData { index: usize },
    #[error("a default-ring spend takes no ring UTXO, input {index} is one")]
    EntryRingInput { index: usize },
    #[error("the hidden signer does not match the sender")]
    AnonymousSignerMismatch,
    #[error("the in-proof owner does not match the sender")]
    InProofOwnerMismatch,
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
    #[error("anonymous transfers require uncached noncompact Ed25519 notes and no address slot")]
    InvalidAnonymousSlot,
    #[error("an anonymous ring requires an Ed25519 recipient")]
    AnonymousRecipient,
    #[error("ring address {address} pays into ring {ring}, the transfer runs in another")]
    ForeignRingAddress { address: Address, ring: Address },
    #[error("merge inputs belong to another tree")]
    InputTreeMismatch,
    #[error("the member's nullifier key does not derive its address")]
    NullifierKeyMismatch,
    #[error("the member record is not included under the requested root")]
    InvalidRecordOpening,
    #[error("{owner:?} enrolled no matching nullifier key")]
    UnregisteredOutputKey { owner: Member },
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
    #[error("the relayed deposit ciphertext opens with no auditor capsule")]
    RelayDepositCapsule,
    #[error("the relayed audit secret does not derive the capsule's ephemeral key")]
    RelayAuditKeyMismatch,
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
