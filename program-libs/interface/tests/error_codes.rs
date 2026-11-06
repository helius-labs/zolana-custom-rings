use std::collections::BTreeMap;

use custom_ring_interface::{
    storage::StorageError,
    CustomRingError::{self, *},
};

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
    UnauthorizedAuthority = 8107,
    InvalidAuditorPubkey = 8108,
    InvalidSystemProgram = 8111,
    UnsupportedCircuit = 8113,
    UnauthorizedInitializer = 8114,
    TooManyAccounts = 8115,
    InvalidListId = 8126,
    InvalidSource = 8134,
    InvalidPolicyRules = 8140,
    PolicyGenerationOverflow = 8141,
    PolicyOnAuditOnlyRing = 8142,
    MissingCoSigner = 8143,
    UnauthorizedCoSigner = 8144,
    InvalidCoSignerScope = 8145,
    InvalidCoSigner = 8146,
    DelegateDisabled = 8150,
    UnauthorizedDelegate = 8151,
    DelegatePublicLeg = 8152,
    DelegateAlreadySet = 8153,
    MissingFundingSigner = 8173,
    InvalidRingMode = 8174,
    InvalidMergeDisclosure = 8179,
    MissingOwnerSigner = 8192,
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
    ZeroPublicLegAmount = 8225,
    TooManyPublicAssets = 8226,
    PublicAmountOverflow = 8227,
    ZeroNetPublicAmount = 8228,
    MissingPolicyProof = 8229,
    UnexpectedPolicyProof = 8230,
    CoSignerIsOwner = 8231,
    MemberWrittenListRule = 8233,
    RingAuthOutOfSlot = 8234,
    InvalidRingProofPoint = 8238,
    UnexpectedMemberRegistryRoot = 8240,
    UnexpectedApproval = 8241,
    InvalidSettlementAccounts = 8242,
    TooManyPublicLegs = 8243,
    AnonymousExitTokenAccountShared = 8247,
    AnonymousExitAccountHasData = 8248,
    AnonymousExitTokenAccountOnCurve = 8249,
    AnonymousExitTokenAccountInvalid = 8250,
    OutputBodyLength = 8253,
    OutputCountOutOfRange = 8257,
    TooManyApplicationMessages = 8269,
    ReplyLength = 8259,
    RecordsRegistryOtherRing = 8266,
    ListNotPolicyReadable = 8255,
    MultiListAbsenceRule = 8235,
    InvertedListPolarity = 8236,
    MixedPolarityRule = 8237,
    InvalidCoSignerRecord = 8260,
    CoSignerRecordAlreadyExists = 8261,
    CoSignerOutOfScope = 8262,
    CoSignerCountOutOfRange = 8263,
    InvalidRingPolicy = 8300,
    RingPolicyAlreadyExists = 8301,
    InvalidStorageRegistry = 8302,
    InvalidAssetLimits = 8390,
    ZeroRoleKey = 8471,
    DuplicateRoleKey = 8472,
    UnboundRegistry = 8480,
    RootNotServed = 8481,
    MissingRegistry = 8482,
    InvalidTrackingRegistry = 8502,
    TrackingRootBelowFloor = 8503,
    SaltedSourceOtherTracking = 8504,
    TooManyAnonymousParties = 8528,
}

const ERROR_VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/errors");

fn ring_errors() -> Vec<(String, u32)> {
    VARIANTS
        .iter()
        .map(|&error| (format!("{error:?}"), error as u32))
        .collect()
}

/// Keeps declaration order, the TS tests compare entries in order.
fn error_vector(errors: &[(String, u32)]) -> String {
    let rows: Vec<String> = errors
        .iter()
        .map(|(name, code)| format!("  {}: {code}", serde_json::to_string(name).unwrap()))
        .collect();
    format!("{{\n{}\n}}\n", rows.join(",\n"))
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
    let actual = ring_errors().into_iter().collect();
    assert_eq!(fixture, actual, "shared error code fixture drifted");
}

#[test]
#[ignore = "rewrites test-vectors/errors/custom-ring-errors.json and storage-errors.json"]
fn write_error_vectors() {
    for (file, errors) in [
        ("custom-ring-errors.json", ring_errors()),
        ("storage-errors.json", storage_errors()),
    ] {
        std::fs::write(format!("{ERROR_VECTORS}/{file}"), error_vector(&errors))
            .expect("write vector file");
    }
}

fn storage_pins() -> [(StorageError, u32); 31] {
    use StorageError as Error;
    [
        (Error::InvalidRegistry, 9000),
        (Error::Unauthorized, 9001),
        (Error::RevisionChanged, 9002),
        (Error::RootExpired, 9003),
        (Error::InvalidInstructionData, 9005),
        (Error::BatchTooLarge, 9006),
        (Error::InvalidWrite, 9007),
        (Error::ProofVerificationFailed, 9008),
        (Error::HashingFailed, 9009),
        (Error::MissingAccounts, 9010),
        (Error::MissingSignature, 9011),
        (Error::ReadOnlyRegistry, 9012),
        (Error::InvalidSystemProgram, 9013),
        (Error::AlreadyInitialized, 9014),
        (Error::RevisionOverflow, 9015),
        (Error::UnsupportedBatch, 9016),
        (Error::NonCanonicalViewingKey, 9021),
        (Error::InvalidTrackingRegistry, 9022),
        (Error::InvalidTrackingAuthorization, 9023),
        (Error::EnrollmentAlreadyApplied, 9024),
        (Error::EnrollmentKeyFinal, 9025),
        (Error::ZeroNullifierKey, 9028),
        (Error::EnrollmentProofShape, 9029),
        (Error::NoEnrollmentsNamed, 9030),
        (Error::InvalidOwnerGrant, 9031),
        (Error::InvalidReaderKey, 9032),
        (Error::InvalidAuditorKey, 9033),
        (Error::InvalidAssetWrite, 9034),
        (Error::PrivateWriteWithoutTracking, 9035),
        (Error::TrackingTreeFull, 9036),
        (Error::RootHistoryRetained, 9037),
    ]
}

fn storage_errors() -> Vec<(String, u32)> {
    storage_pins()
        .iter()
        .map(|(error, code)| (format!("{error:?}"), *code))
        .collect()
}

#[test]
fn storage_error_codes_are_stable() {
    for (error, code) in storage_pins() {
        assert_eq!(error as u32, code, "{error:?}");
    }
    let fixture: BTreeMap<String, u32> = serde_json::from_str(include_str!(
        "../../../test-vectors/errors/storage-errors.json"
    ))
    .unwrap();
    let actual = storage_errors().into_iter().collect();
    assert_eq!(fixture, actual, "shared error code fixture drifted");
}
