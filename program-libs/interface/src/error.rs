use solana_program_error::ProgramError;
use spr_hasher::HasherError;
use thiserror::Error;
use zolana_ring_policy::{AssetLimitsError, PolicyTableError, RuleTableError, SourceMapError};

macro_rules! ring_errors {
    ($($variant:ident = $code:literal => $message:literal,)*) => {
        /// From 8100 clear of SPP, pinned by `error_codes_are_stable`, no retired code reused.
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
    ConfigAlreadyInitialized = 8105 => "ring config account is already initialized",
    ConfigNotInitialized = 8106 => "ring config account is not initialized",
    UnauthorizedAuthority = 8107 => "signer is not the configured ring authority",
    InvalidAuditorPubkey = 8108 => "auditor public key is not allowed",
    // 8109 and 8110 retired.
    InvalidSystemProgram = 8111 => "system program account is invalid",
    InvalidConfigPda = 8112 => "config account is not the canonical config PDA",
    UnsupportedCircuit = 8113 => "circuit selector is not supported by the ring",
    UnauthorizedInitializer = 8114 => "authority is not the program upgrade authority",
    TooManyAccounts = 8115 => "forwarded account list exceeds the CPI account limit",
    ReadAccessRecordAlreadyExists = 8116 => "read access record already exists",
    InvalidReadAccessRecord = 8117 => "read access record account is invalid",
    InvalidReaderKey = 8118 => "reader key cannot authorize reads",
    // 8119 retired.
    // 8120 to 8122 retired.
    // 8123 retired.
    // 8124 and 8125 retired.
    InvalidListId = 8126 => "list is unknown",
    // 8127 retired.
    // 8128 retired, an empty policy table is valid.
    // 8129 and 8130 retired.
    // 8131 to 8133 retired.
    InvalidSource = 8134 =>
        "policy sources do not match the referenced lists or name a second curator",
    InvalidCuratorRegistry = 8135 =>
        "curator member registry account is not an initialized member registry",
    // 8136 to 8139 retired.
    InvalidPolicyRules = 8140 => "policy rules do not decode to a table the circuit enforces",
    PolicyGenerationOverflow = 8141 => "policy generation overflows",
    PolicyOnAuditOnlyRing = 8142 => "an audit-only ring takes no policy",
    MissingCoSigner = 8143 => "the operation needs the co-signer's signature",
    UnauthorizedCoSigner = 8144 => "the signer is not the ring's co-signer",
    InvalidCoSignerScope = 8145 => "co-signer scope must be a nonzero subset of the scope bits",
    InvalidCoSigner = 8146 => "co-signer address is invalid",
    InvalidCoSignerThresholds = 8147 => "co-signer thresholds exceed the table or repeat a mint",
    // 8148 and 8149 retired.
    DelegateDisabled = 8150 => "the ring has no delegate",
    UnauthorizedDelegate = 8151 => "the delegate must sign",
    DelegatePublicLeg = 8152 => "a delegate move settles no public leg",
    DelegateAlreadySet = 8153 => "the delegate is permanent",
    // 8154 to 8156 retired.
    ApprovalWithoutCoSigner = 8157 => "dual control needs a configured co-signer",
    // 8158 and 8159 retired.
    InvalidMemberRegistry = 8160 => "member registry account is invalid",
    // 8161 and 8162 retired.
    MemberRegistryAlreadyExists = 8163 => "member registry already exists",
    // 8164 retired.
    DepositAuditRequired = 8165 => "verified deposit disclosure required",
    InvalidDepositDisclosure = 8166 => "invalid deposit disclosure",
    // 8167 retired.
    // 8168 and 8169 retired.
    DelegateRequiresPolicy = 8170 => "a delegate needs a policy ring",
    // 8171 retired.
    // 8172 retired.
    MissingFundingSigner = 8173 => "forwarded funding account must sign on entry",
    InvalidRingMode = 8174 => "the ring mode is unknown",
    AnonymousRingRefused = 8175 => "an anonymous ring refuses this operation",
    // 8176 retired.
    InvalidAnonymousOutput = 8177 => "an anonymous ring output must carry a zero owner tag",
    InvalidAnonymousSigner = 8178 => "an anonymous ring transaction takes no owner signer",
    InvalidMergeDisclosure = 8179 =>
        "the merge disclosure does not match the ring mode or the auditor key",
    InvalidDepositData = 8180 => "forwarded deposit data is invalid",
    // 8181 to 8191 retired.
    MissingOwnerSigner = 8192 => "forwarded owner signer must sign on entry",
    // 8193 to 8198 retired.
    MergeDisclosureWidth = 8199 => "the merge disclosure field count does not match the merge width",
    RingTransactLength = 8200 => "the compact transact data length disagrees with its flags and shape",
    RingShapeUnkeyed = 8201 => "no audit key or SPP rail key serves the shape on the rail",
    FlagNotAllowed = 8202 => "a transact flag the ring mode or policy forbids",
    RootBelowFloor = 8203 => "the member registry root is older than the floor",
    CuratorRootStale = 8204 => "the curator root is outside its floor and grace window",
    RootIndexEmpty = 8205 => "the root history slot holds no root",
    // 8206 and 8207 retired.
    OwnerSignerCount = 8208 => "a policy transfer takes exactly one owner signer",
    MemberOutOfRange = 8209 => "the member lies outside the record range",
    ListBitNotWritable = 8210 => "the signer may not write a masked list bit",
    ValueOutsideMask = 8211 => "the list value leaves its mask or the mask is zero",
    QueueFull = 8212 => "the record queue holds the member limit",
    // 8213 retired.
    AuthorityBatchTooLarge = 8214 => "pending and authority writes exceed one batch",
    ApplyNotDue = 8215 => "the record queue is empty or neither full nor aged",
    FeeRecipient = 8216 => "the insert fee account is not the config authority",
    PolicyNotSet = 8217 => "the policy ring has no policy yet",
    InvalidSppProofPoint = 8218 => "the compressed SPP proof point does not decompress",
    InvalidRecordQueue = 8219 => "record queue account is invalid",
    ZeroDisclosureField = 8220 => "a published disclosure field is zero",
    PolicyAlreadySet = 8221 => "the policy ring already has a policy",
    AuthorityLeafReserve = 8222 => "a member write would enter the leaves reserved for the authority",
    ApplyTooSoon = 8223 => "a permissionless application lands inside the delay of the previous one",
    DataFreeBodyLength = 8224 => "an exit payload is not a data-free scheme 3 body",
    ZeroPublicLegAmount = 8225 => "a public leg moves no amount",
    TooManyPublicAssets = 8226 => "the public legs name more assets than the public slots",
    PublicAmountOverflow = 8227 => "the net public amount of an asset exceeds a u64 magnitude",
    ZeroNetPublicAmount = 8228 => "the public legs of an asset net to zero",
    MissingPolicyProof = 8229 => "a policy ring transfer carries no policy proof",
    UnexpectedPolicyProof = 8230 => "an audit-only ring transfer carries a policy proof",
    CoSignerIsOwner = 8231 => "dual control needs a co-signer other than the owner",
    // 8232 retired.
    MemberWrittenListRule = 8233 => "a policy rule reads a list its members write",
    RingAuthOutOfSlot = 8234 => "the ring authority PDA sits outside its SPP slot",
    InsertFeeAboveMax = 8235 => "the insert fee exceeds the writer's maximum",
    InsertFeeBelowRent = 8236 =>
        "a nonzero insert fee is below the rent-exempt minimum of an empty account",
    CoSignerIsDelegate = 8237 => "dual control needs a co-signer other than the delegate",
    InvalidRingProofPoint = 8238 => "a ring proof point does not decompress",
    ThresholdsWithoutWithdrawals = 8239 => "co-signer thresholds need the withdrawal scope",
    UnexpectedMemberRegistryRoot = 8240 => "the statement binds no member registry root",
    UnexpectedApproval = 8241 => "approval needs a member transfer under outflow limits",
    InvalidSettlementAccounts = 8242 => "settlement accounts do not match the public legs",
    TooManyPublicLegs = 8243 => "too many public legs",
    InvalidAuditedDeposit = 8244 => "audited deposit does not wrap an SPP deposit",
    // 8245 retired.
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
    AnonymousRingDataNotZero = 8251 => "an anonymous ring deposit or merge output carries ring data",
    AnonymousBodyLength = 8252 => "an anonymous ring body is empty or longer than u16::MAX",
    OutputBodyLength = 8253 => "a ring output body exceeds the u32 length prefix",
    InvalidCoSignerRecord = 8260 => "co-signer record account is invalid",
    CoSignerRecordAlreadyExists = 8261 => "co-signer record already exists",
    CoSignerOutOfScope = 8262 => "the co-signer's scope misses a demanded class",
    CoSignerCountOutOfRange = 8263 => "co-signer count of a class leaves the u8 range",
    InvalidRingPolicy = 8300 => "ring policy account is invalid",
    RingPolicyAlreadyExists = 8301 => "ring policy already exists",
    InvalidStorageRegistry = 8302 => "storage registry account is invalid",
    StorageAuthorityMismatch = 8303 =>
        "the records registry answers to neither the config authority nor the named storage authority",
    UnmirroredRegistry = 8304 => "the registry is neither the policy records nor its curator source",
    MirrorNotSynced = 8305 => "the root mirror holds no roots of the registry the policy names",
    MirrorRootExpired = 8306 => "the revision names no unexpired root of the mirror",
    OwnerSignerOnInProofRail = 8350 => "the in-proof owner rail takes no owner signer",
    InvalidAssetLimits = 8390 => "a window cap and its window are not set together",
    DepositMintAccountMissing = 8410 => "an spl deposit group has no mint account",
    DepositAssetIndexUnknown = 8411 => "a deposit entry names no asset group",
    UnexpectedCuratorRevision = 8470 => "the deposit names a curator revision without a curator source",
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
