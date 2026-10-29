use std::collections::BTreeMap;

use custom_ring_interface::CustomRingError::{self, *};

macro_rules! pinned_codes {
    ($($variant:ident = $code:literal,)*) => {
        /// A new variant fails to compile until pinned here.
        fn pinned_code(error: CustomRingError) -> u32 {
            match error {
                $($variant => $code,)*
            }
        }

        const VARIANTS: &[CustomRingError] = &[$($variant,)*];
    };
}

pinned_codes! {
    InvalidInstructionData = 8100,
    ProofVerificationFailed = 8101,
    HashingFailed = 8102,
    InvalidShieldedPoolProgram = 8103,
    MissingRingAuth = 8104,
    ConfigAlreadyInitialized = 8105,
    ConfigNotInitialized = 8106,
    UnauthorizedAuthority = 8107,
    InvalidAuditorPubkey = 8108,
    InvalidSystemProgram = 8111,
    InvalidConfigPda = 8112,
    UnsupportedCircuit = 8113,
    UnauthorizedInitializer = 8114,
    TooManyAccounts = 8115,
    InvalidListId = 8126,
    InvalidSource = 8134,
    InvalidCuratorRegistry = 8135,
    InvalidPolicyRules = 8140,
    PolicyGenerationOverflow = 8141,
    PolicyOnAuditOnlyRing = 8142,
    MissingCoSigner = 8143,
    UnauthorizedCoSigner = 8144,
    InvalidCoSignerScope = 8145,
    InvalidCoSigner = 8146,
    InvalidCoSignerThresholds = 8147,
    DelegateDisabled = 8150,
    UnauthorizedDelegate = 8151,
    DelegatePublicLeg = 8152,
    DelegateAlreadySet = 8153,
    ApprovalWithoutCoSigner = 8157,
    InvalidDepositDisclosure = 8166,
    DelegateRequiresPolicy = 8170,
    MissingFundingSigner = 8173,
    InvalidRingMode = 8174,
    AnonymousRingRefused = 8175,
    InvalidAnonymousOutput = 8177,
    InvalidAnonymousSigner = 8178,
    InvalidMergeDisclosure = 8179,
    InvalidDepositData = 8180,
    MissingOwnerSigner = 8192,
    MergeDisclosureWidth = 8199,
    RingTransactLength = 8200,
    RingShapeUnkeyed = 8201,
    FlagNotAllowed = 8202,
    OwnerSignerCount = 8208,
    MemberOutOfRange = 8209,
    ListBitNotWritable = 8210,
    ValueOutsideMask = 8211,
    AuthorityBatchTooLarge = 8214,
    PolicyNotSet = 8217,
    InvalidSppProofPoint = 8218,
    ZeroDisclosureField = 8220,
    PolicyAlreadySet = 8221,
    DataFreeBodyLength = 8224,
    ZeroPublicLegAmount = 8225,
    TooManyPublicAssets = 8226,
    PublicAmountOverflow = 8227,
    ZeroNetPublicAmount = 8228,
    MissingPolicyProof = 8229,
    UnexpectedPolicyProof = 8230,
    CoSignerIsOwner = 8231,
    MemberWrittenListRule = 8233,
    RingAuthOutOfSlot = 8234,
    CoSignerIsDelegate = 8237,
    InvalidRingProofPoint = 8238,
    ThresholdsWithoutWithdrawals = 8239,
    UnexpectedMemberRegistryRoot = 8240,
    UnexpectedApproval = 8241,
    InvalidSettlementAccounts = 8242,
    TooManyPublicLegs = 8243,
    InvalidAuditedDeposit = 8244,
    AnonymousExitDestinationsDiffer = 8246,
    AnonymousExitTokenAccountShared = 8247,
    AnonymousExitAccountHasData = 8248,
    AnonymousExitTokenAccountOnCurve = 8249,
    AnonymousExitTokenAccountInvalid = 8250,
    AnonymousRingDataNotZero = 8251,
    AnonymousBodyLength = 8252,
    OutputBodyLength = 8253,
    InvalidCoSignerRecord = 8260,
    CoSignerRecordAlreadyExists = 8261,
    CoSignerOutOfScope = 8262,
    CoSignerCountOutOfRange = 8263,
    InvalidRingPolicy = 8300,
    RingPolicyAlreadyExists = 8301,
    InvalidStorageRegistry = 8302,
    StorageAuthorityMismatch = 8303,
    UnmirroredRegistry = 8304,
    MirrorNotSynced = 8305,
    MirrorRootExpired = 8306,
    OwnerSignerOnInProofRail = 8350,
    InvalidAssetLimits = 8390,
    DepositMintAccountMissing = 8410,
    DepositAssetIndexUnknown = 8411,
    UnexpectedCuratorRevision = 8470,
}

#[test]
fn error_codes_are_stable() {
    for &error in VARIANTS {
        assert_eq!(error as u32, pinned_code(error), "{error:?}");
    }
    let fixture: BTreeMap<String, u32> = serde_json::from_str(include_str!(
        "../../../test-vectors/errors/custom-ring-errors.json"
    ))
    .unwrap();
    let actual = VARIANTS
        .iter()
        .map(|&error| (format!("{error:?}"), error as u32))
        .collect();
    assert_eq!(fixture, actual, "shared error code fixture drifted");
}
