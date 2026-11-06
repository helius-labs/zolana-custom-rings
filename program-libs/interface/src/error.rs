//! Every refusal of the ring program, one enum for the program and its clients.
//!
//! Read after `program-libs/interface/src/lib.rs`. Read before `program-libs/interface/tests/error_codes.rs`.

use solana_program_error::ProgramError;
use spr_hasher::HasherError;
use thiserror::Error;
use zolana_ring_policy::{AssetLimitsError, PolicyTableError, RuleTableError, SourceMapError};

macro_rules! ring_errors {
    ($($variant:ident = $code:literal => $message:literal,)*) => {
        /// From 8100 clear of SPP, pinned by `error_codes_are_stable`.
        #[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
        #[repr(u32)]
        pub enum CustomRingError {
            $(#[error($message)] $variant = $code,)*
        }
    };
}

ring_errors! {
    InvalidInstructionData = 8100 => "instruction data is invalid",
    ProofVerificationFailed = 8101 => "proof verification failed",
    HashingFailed = 8102 => "hashing failed",
    InvalidShieldedPoolProgram = 8103 => "shielded pool program account is invalid",
    MissingRingAuth = 8104 => "ring auth account is missing from the forwarded account list",
    UnauthorizedAuthority = 8107 => "signer is not the configured ring authority",
    InvalidAuditorPubkey = 8108 => "auditor public key is not allowed",
    InvalidSystemProgram = 8111 => "system program account is invalid",
    UnsupportedCircuit = 8113 => "circuit selector is not supported by the ring",
    UnauthorizedInitializer = 8114 => "authority is not the program upgrade authority",
    TooManyAccounts = 8115 => "forwarded account list exceeds the CPI account limit",
    InvalidListId = 8126 => "list is unknown",
    InvalidSource = 8134 =>
        "policy sources do not match the referenced lists or name a second curator",
    InvalidPolicyRules = 8140 => "policy rules do not decode to a table the circuit enforces",
    PolicyGenerationOverflow = 8141 => "policy generation overflows",
    PolicyOnAuditOnlyRing = 8142 => "an audit-only ring takes no policy",
    MissingCoSigner = 8143 => "the operation needs the co-signer's signature",
    UnauthorizedCoSigner = 8144 => "the signer is not the ring's co-signer",
    InvalidCoSignerScope = 8145 => "co-signer scope must be a nonzero subset of the scope bits",
    InvalidCoSigner = 8146 => "co-signer address is invalid",
    DelegateDisabled = 8150 => "the ring has no delegate",
    UnauthorizedDelegate = 8151 => "the delegate must sign",
    DelegatePublicLeg = 8152 => "a delegate move takes no deposit leg",
    DelegateAlreadySet = 8153 => "the delegate is permanent",
    MissingFundingSigner = 8173 => "forwarded funding account must sign on entry",
    InvalidRingMode = 8174 => "the ring mode is unknown",
    InvalidAnonymousSigner = 8178 => "an anonymous ring transaction takes no signer outside the payer, the owner run, the co-signers and the funders",
    InvalidMergeDisclosure = 8179 =>
        "the merge disclosure's ephemeral key is not tagged",
    MissingOwnerSigner = 8192 => "forwarded owner signer must sign on entry",
    RingTransactLength = 8200 => "the compact transact data length disagrees with its flags and shape",
    RingShapeUnkeyed = 8201 => "no audit key or SPP rail key serves the shape on the rail",
    FlagNotAllowed = 8202 => "a transact flag the ring mode or policy forbids",
    OwnerSignerCount = 8208 => "the owner run is empty on a spend or exceeds the key's signer slots",
    MemberOutOfRange = 8209 => "the member lies outside the record range",
    ListBitNotWritable = 8210 => "the signer may not write a masked list bit",
    ValueOutsideMask = 8211 => "the list value leaves its mask or the mask is zero",
    AuthorityBatchTooLarge = 8214 => "the writes exceed one apply batch",
    PolicyNotSet = 8217 => "the ring has no policy",
    InvalidSppProofPoint = 8218 => "the compressed SPP proof point does not decompress",
    ZeroPublicLegAmount = 8225 => "a public leg moves no amount",
    TooManyPublicAssets = 8226 => "the public legs name more assets than the public slots",
    PublicAmountOverflow = 8227 => "the net public amount of an asset exceeds a u64 magnitude",
    ZeroNetPublicAmount = 8228 => "the public legs of an asset net to zero",
    MissingPolicyProof = 8229 => "a policy ring transfer carries no policy proof",
    UnexpectedPolicyProof = 8230 => "a transfer that reads no policy root carries a policy proof",
    CoSignerIsOwner = 8231 => "dual control needs a co-signer other than the owner",
    MemberWrittenListRule = 8233 => "a policy rule reads a list its members write",
    RingAuthOutOfSlot = 8234 => "the ring authority PDA sits outside its SPP slot",
    InvalidRingProofPoint = 8238 => "a ring proof point does not decompress",
    UnexpectedMemberRegistryRoot = 8240 => "the statement binds no member registry root",
    UnexpectedApproval = 8241 => "a delegate frame carries no approval bit",
    InvalidSettlementAccounts = 8242 => "settlement accounts do not match the public legs",
    TooManyPublicLegs = 8243 => "too many public legs",
    AnonymousExitDestinationsDiffer = 8246 =>
        "all withdrawals of an anonymous spend must name the same destination key",
    AnonymousExitTokenAccountShared = 8247 =>
        "an anonymous SPL withdrawal's token account must have no delegate and no close authority",
    AnonymousExitAccountHasData = 8248 =>
        "an anonymous SOL withdrawal must leave to a system account without data",
    AnonymousExitTokenAccountOnCurve = 8249 =>
        "an anonymous SPL withdrawal's token account address must be off the ed25519 curve",
    AnonymousExitTokenAccountInvalid = 8250 =>
        "an anonymous SPL withdrawal's destination is no initialized token program account",
    OutputBodyLength = 8253 => "a ring output body exceeds its length prefix",
    OutputCountOutOfRange = 8257 => "the published output count is zero or above the key's capacity",
    BodilessExit = 8258 => "a bodiless slot is also an exit",
    TooManyApplicationMessages = 8269 => "application messages exceed what SPP takes beside the auditor message and the sender bundle",
    ReplyLength = 8259 => "reply metadata is shorter than its keys or misses one reply per body-bearing slot",
    RecordsRegistryOtherRing = 8266 => "the records registry serves another ring",
    ListNotPolicyReadable = 8255 => "a policy rule reads a list outside the policy lists",
    MultiListAbsenceRule = 8235 => "a policy rule reads more than one list by absence",
    InvertedListPolarity = 8236 => "a policy rule reads a grant list by absence or a deny list by presence",
    MixedPolarityRule = 8237 => "a policy rule mixes presences and absences",
    InvalidCoSignerRecord = 8260 => "co-signer record account is invalid",
    CoSignerRecordAlreadyExists = 8261 => "co-signer record already exists",
    CoSignerOutOfScope = 8262 => "the co-signer's scope misses a demanded class",
    CoSignerCountOutOfRange = 8263 => "co-signer count of a class leaves the u8 range",
    InvalidRingPolicy = 8300 => "ring policy account is invalid",
    RingPolicyAlreadyExists = 8301 => "ring policy already exists",
    InvalidStorageRegistry = 8302 => "storage registry account is invalid",
    InvalidAssetLimits = 8390 => "a window cap and its window are not set together",
    ZeroRoleKey = 8471 => "a ring role key is zero",
    DuplicateRoleKey = 8472 => "one key holds two ring roles",
    UnboundRegistry = 8480 => "the registry account is not the one the ring binds",
    RootNotServed = 8481 => "the registry serves no root at the revision",
    MissingRegistry = 8482 => "the instruction reads a registry it does not pass",
    InvalidTrackingRegistry = 8502 => "tracking registry account is invalid",
    TrackingRootBelowFloor = 8503 => "the frame names a tracking root below a salted source's floor",
    SaltedSourceOtherTracking = 8504 => "a salted source pins no tracking registry or another one",
    InvalidSignerDataCounts = 8527 => "signer data counts are zero under their bit or pass the encoding",
    TooManyAnonymousParties = 8528 => "the co-signers and deposit funders pass the statement's party cells",
}

impl From<CustomRingError> for ProgramError {
    fn from(error: CustomRingError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

impl From<HasherError> for CustomRingError {
    fn from(_: HasherError) -> Self {
        Self::HashingFailed
    }
}

impl From<RuleTableError> for CustomRingError {
    fn from(error: RuleTableError) -> Self {
        match error {
            RuleTableError::MemberWrittenList => Self::MemberWrittenListRule,
            RuleTableError::ListNotPolicyReadable => Self::ListNotPolicyReadable,
            RuleTableError::MultiListAbsence => Self::MultiListAbsenceRule,
            RuleTableError::InvertedPolarity => Self::InvertedListPolarity,
            RuleTableError::MixedPolarity => Self::MixedPolarityRule,
            _ => Self::InvalidPolicyRules,
        }
    }
}

impl From<AssetLimitsError> for CustomRingError {
    fn from(_: AssetLimitsError) -> Self {
        Self::InvalidAssetLimits
    }
}

impl From<SourceMapError> for CustomRingError {
    fn from(_: SourceMapError) -> Self {
        Self::InvalidSource
    }
}

impl From<crate::PublicSlotError> for CustomRingError {
    fn from(error: crate::PublicSlotError) -> Self {
        match error {
            crate::PublicSlotError::TooManyAssets { .. } => Self::TooManyPublicAssets,
            crate::PublicSlotError::AmountOverflow { .. } => Self::PublicAmountOverflow,
            crate::PublicSlotError::ZeroNet { .. } => Self::ZeroNetPublicAmount,
        }
    }
}

impl From<PolicyTableError> for CustomRingError {
    fn from(error: PolicyTableError) -> Self {
        match error {
            PolicyTableError::Table(error) => error.into(),
            PolicyTableError::MissingSource(_) => Self::InvalidSource,
        }
    }
}
