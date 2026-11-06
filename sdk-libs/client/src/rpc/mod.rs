//! The ring rpc wire, its signed attestations and the auditor key files.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use custom_ring_interface::InputClass;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_signer::{Signer, SignerError};
use spr_client::{AsyncRpc, ClientError};
use spr_indexer_api::{
    Base64String, Context, Hash, Limit, SerializablePubkey, SerializableSignature,
};
use spr_interface::{state::RingConfig, RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID};
use spr_keypair::{KeypairError, X25519Keypair, X25519Pubkey};
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_secret_file::{
    create_new, read_key32, Access, KeyPairFiles, SecretFileError, Visibility,
};

mod authority_transfer;
mod delegate_read;
mod list_salt_read;
mod merge_settings;
mod policy_authority;
mod reader_grant;
mod record_update;
mod relay;
mod relay_enroll;
mod relay_proof;
mod spend_coverage;
mod wallet_activity;
mod wallet_snapshot;
mod wallet_status;

pub use authority_transfer::*;
pub use delegate_read::*;
pub use list_salt_read::*;
pub use merge_settings::*;
pub use policy_authority::*;
pub use reader_grant::*;
pub use record_update::*;
pub use relay::*;
pub use relay_enroll::*;
pub use relay_proof::*;
pub use spend_coverage::*;
pub use wallet_activity::*;
pub use wallet_snapshot::*;
pub use wallet_status::*;

use crate::{
    AuditError, AuditedInput, AuditedMergeOutput, AuditedOutput, AuditedTransaction, AuditedUtxo,
    KnownUtxo, OutputOpening, OutputPayloadErrorKind, ReaderKey, ReaderKeyError, RingOwnerTag,
    RingWithdrawal, UtxoOwner,
};

pub const HEALTH: &str = "health";
pub const CREATE_AUDITOR_KEY: &str = "createAuditorKey";
pub const RING_STATUS: &str = "ringStatus";
pub const GET_DECRYPTED_TRANSACTIONS: &str = "getDecryptedTransactions";
pub const GET_WALLET_ACTIVITY: &str = "getWalletActivity";
pub const GET_AUDITED_MERGES: &str = "getAuditedMerges";
pub const GET_AUDITED_UTXOS: &str = "getAuditedUtxos";
pub const GET_RELAY_QUOTE: &str = "getRelayQuote";
pub const PREPARE_RELAY: &str = "prepareRelay";
pub const SUBMIT_RELAY: &str = "submitRelay";
pub const GET_RELAY_STATUS: &str = "getRelayStatus";
pub const SUBMIT_RECORD_UPDATE: &str = "submitRecordUpdate";
pub const GET_RECORD_UPDATE_STATUS: &str = "getRecordUpdateStatus";
pub const SET_MERGE_SETTINGS: &str = "setMergeSettings";
pub const SET_READER_GRANT: &str = "setReaderGrant";
pub const PREPARE_AUTHORITY_TRANSFER: &str = "prepareAuthorityTransfer";
pub const GET_PENDING_LIST_APPROVALS: &str = "getPendingListApprovals";
pub const REFUSE_LIST_APPROVAL: &str = "refuseListApproval";
pub const CREATE_RECORDS_REGISTRY: &str = "createRecordsRegistry";
/// The most UTXO hashes one `getAuditedUtxos` request names.
pub const AUDITED_UTXOS_LIMIT: usize = 100;
pub const AUDIT_CURSOR_LIMIT: usize = 256;
pub const AUDIT_PAGE_LIMIT: u64 = 100;
pub const PENDING_LIST_APPROVALS_PAGE_LIMIT: usize = 100;
const ATTESTATION_DOMAIN: &[u8] = b"zolana/ring-auditor-key";
const READ_DOMAIN: &str = "zolana/ring-rpc-read";
const AUDITOR_KEY_REQUEST_DOMAIN: &str = "zolana/ring-rpc-auditor-key-request";
const AUDITED_UTXOS_DOMAIN: &str = "zolana/ring-rpc-audited-utxos";

/// One cursor rule for the request builder, the page and the indexer response check.
pub fn cursor_in_bounds(cursor: &[u8]) -> bool {
    !cursor.is_empty() && cursor.len() <= AUDIT_CURSOR_LIMIT
}

pub fn limit_in_bounds(limit: &Limit) -> bool {
    limit.value() <= AUDIT_PAGE_LIMIT
}

/// One count rule for the note request builder and the service.
pub fn utxo_hashes_in_bounds(utxo_hashes: &[Hash]) -> bool {
    (1..=AUDITED_UTXOS_LIMIT).contains(&utxo_hashes.len())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyMode {
    Local,
    Derived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HealthResponse {
    pub mode: KeyMode,
    pub service_pubkey: SerializablePubkey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateAuditorKeyRequest {
    pub ring_program_id: SerializablePubkey,
    pub auth: AuthorityAuth,
}

/// Signed by the ring's Loader v3 upgrade authority or its policy authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorityAuth {
    pub authority: SerializablePubkey,
    /// Diagnostic only, the service signs its own cluster into the attestation.
    pub genesis_hash: Hash,
    pub timestamp: u64,
    pub nonce: Base64String,
    /// Raw Ed25519 over the `AuditorKeyAttestation` message.
    pub signature: Base64String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateAuditorKeyResponse {
    pub ring_program_id: SerializablePubkey,
    pub auditor_pubkey: AuditorPubkey,
    pub auditor_view_tag: Hash,
    pub service_pubkey: SerializablePubkey,
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingStatusRequest {
    pub ring_program_id: SerializablePubkey,
}

/// Unsigned, so it carries only what the chain already publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingStatusResponse {
    pub ring_program_id: SerializablePubkey,
    pub state: RingState,
    /// The key the ring's config names, absent until the config exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_auditor_pubkey: Option<AuditorPubkey>,
    pub service_pubkey: SerializablePubkey,
    /// Absent until SPP holds a config for the ring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<RingActivation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingActivation {
    pub activated: bool,
    pub paused: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RingChainStatus {
    pub activation: Option<RingActivation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RingState {
    /// The config names the service's key, reads work.
    Served,
    /// The config names another auditor for good, the service never opens the ring.
    ForeignAuditor,
    /// No config yet, `init` is free to pin the service's key.
    Uninitialized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Base64String", into = "Base64String")]
pub struct AuditorPubkey(X25519Pubkey);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetDecryptedTransactionsRequest {
    /// Required for derived keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_program_id: Option<SerializablePubkey>,
    /// Opaque indexer cursor.
    #[serde(default)]
    pub cursor: Option<Base64String>,
    #[serde(default)]
    pub limit: Option<Limit>,
    /// Narrows the read to one wallet's rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<SerializablePubkey>,
    pub auth: ReadAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetAuditedMergesResponse {
    pub context: Context,
    pub value: AuditedMergesPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetAuditedUtxosRequest {
    /// Required for derived keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_program_id: Option<SerializablePubkey>,
    /// UTXO hashes with their tree id, `1..=AUDITED_UTXOS_LIMIT` of them.
    pub utxo_hashes: Vec<Hash>,
    /// Narrows the read to one wallet's notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<SerializablePubkey>,
    pub auth: ReadAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetAuditedUtxosResponse {
    /// The backfill's newest page, a later note reads `null` until the backfill passes it.
    pub context: Context,
    pub value: AuditedUtxosPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditedUtxosPage {
    /// In request order, `null` for a note the auditor has not opened.
    pub utxos: Vec<Option<AuditedUtxoView>>,
}

/// A note the auditor opened, with the transaction that created it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditedUtxoView {
    pub utxo_hash: Hash,
    pub utxo: DecryptedKnownUtxo,
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
    pub slot_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditedMergesPage {
    pub opened: Vec<AuditedMergeRecord>,
    pub cursor: Option<Base64String>,
}

/// A resolved merge output, an audit record of inherited fields and no wallet opening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditedMergeRecord {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
    pub output_commitment: Hash,
    pub owner_key: SerializablePubkey,
    pub asset: Hash,
    pub mint: SerializablePubkey,
    pub amount: u64,
    /// With padding left out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub real_nullifiers: Vec<Hash>,
}

impl From<&AuditedMergeOutput> for AuditedMergeRecord {
    fn from(output: &AuditedMergeOutput) -> Self {
        Self {
            slot: output.slot,
            tx_signature: output.tx_signature.into(),
            event_index: output.event_index,
            output_commitment: Hash(output.commitment),
            owner_key: output.owner_key.into(),
            asset: Hash(output.asset),
            mint: output.mint.into(),
            amount: output.amount,
            real_nullifiers: output.real_nullifiers.iter().copied().map(Hash).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReadAuth {
    /// Canonical tagged reader key bytes.
    pub reader: Base64String,
    pub timestamp: u64,
    pub nonce: Base64String,
    /// DER for passkeys and raw Ed25519 otherwise.
    pub signature: Base64String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<WebAuthnAssertion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WebAuthnAssertion {
    pub authenticator_data: Base64String,
    pub client_data_json: Base64String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadSignature {
    Ed25519([u8; 64]),
    WebAuthn {
        signature_der: Vec<u8>,
        assertion: WebAuthnAssertion,
    },
}

pub trait ReadSigner {
    fn reader(&self) -> Result<ReaderKey, ReaderKeyError>;
    fn sign(&self, attestation: &[u8]) -> Result<ReadSignature, ReadBuildError>;
}

#[derive(Debug, Error)]
pub enum RequestBuildError {
    #[error("request signature failed")]
    Signature(#[source] SignerError),
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[derive(Debug, Error)]
pub enum ReadBuildError {
    #[error(transparent)]
    Request(#[from] RequestBuildError),
    #[error(transparent)]
    Reader(#[from] ReaderKeyError),
    #[error("audit cursor is invalid")]
    Cursor,
    #[error("audit page limit is invalid")]
    Limit,
    #[error("a UTXO read names 1 to {AUDITED_UTXOS_LIMIT} UTXO hashes")]
    UtxoHashes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetDecryptedTransactionsResponse {
    pub context: Context,
    pub value: DecryptedTransactionsPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedTransactionsPage {
    pub items: Vec<DecryptedTransaction>,
    pub skipped: Vec<SkippedTransaction>,
    pub cursor: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedTransaction {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    /// The ring event within a Solana transaction, one signature can carry several.
    pub event_index: u16,
    /// Canonical tagged X25519 transaction viewing key.
    pub tx_viewing_pk: Base64String,
    /// Every slot whose rebuilt opening reaches its published commitment, in published order.
    pub outputs: Vec<DecryptedOutput>,
    pub payload_errors: Vec<DecryptedPayloadError>,
    /// `R`, spent notes among the published inputs.
    pub real_inputs: u8,
    /// One per published nullifier.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<DecryptedInput>,
    pub nullifiers: Vec<Hash>,
    /// Owner signers or in-proof owner of a confidential transfer, a data output owner among them may spend no input.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spenders: Vec<SerializablePubkey>,
    /// Required signers, fee payer first.
    pub signers: Vec<SerializablePubkey>,
    /// Public settlement legs, where value left the ring.
    pub withdrawals: Vec<DecryptedWithdrawal>,
}

/// The public legs and nullifiers come from the confirmed transaction.
#[must_use]
pub struct ConfirmedAudit {
    pub audited: AuditedTransaction,
    pub event_index: u16,
    pub nullifiers: Vec<[u8; 32]>,
    pub spenders: Vec<Address>,
    pub signers: Vec<Address>,
    pub withdrawals: Vec<RingWithdrawal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedPayloadError {
    pub slot_index: u32,
    pub kind: OutputPayloadErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedOutputContext {
    pub tree_id: u16,
    pub leaf_index: u64,
    pub hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedOutput {
    pub slot_index: u32,
    pub output_context: DecryptedOutputContext,
    pub kind: DecryptedOutputKind,
    /// Absent for a dummy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utxo: Option<DecryptedUtxo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<Hash>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DecryptedOutputKind {
    Ring,
    Exit,
    Dummy,
}

/// Exact field encodings keep an unknown asset readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedUtxo {
    /// Base58 of it is the owner's Solana address.
    pub owner_key: SerializablePubkey,
    pub nullifier_pk: Hash,
    pub asset: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint: Option<SerializablePubkey>,
    pub amount: u64,
    pub blinding: Hash,
    pub data_hash: Hash,
    pub ring_data_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedKnownUtxo {
    pub owner_key: SerializablePubkey,
    pub nullifier_pk: Hash,
    pub asset: Hash,
    /// Absent while the asset registry does not know the asset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint: Option<SerializablePubkey>,
    pub amount: u64,
    pub blinding: Hash,
    pub data_hash: Hash,
    pub ring_data_hash: Hash,
    pub tree_id: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedInput {
    pub nullifier: Hash,
    pub class: DecryptedInputClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_input: Option<DecryptedDefaultInput>,
}

/// The proven class of one published input, an address spends no note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DecryptedInputClass {
    Note,
    Address,
    Dummy,
}

impl From<InputClass> for DecryptedInputClass {
    fn from(class: InputClass) -> Self {
        match class {
            InputClass::Note => Self::Note,
            InputClass::Address => Self::Address,
            InputClass::Dummy => Self::Dummy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedDefaultInput {
    pub utxo: DecryptedUtxo,
    /// Absent without the input's tree id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecryptedWithdrawal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screened_owner: Option<SerializablePubkey>,
    /// A token account for an SPL leg, a wallet for a SOL leg.
    pub recipient: SerializablePubkey,
    pub asset: SerializablePubkey,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SkippedTransaction {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
    pub reason: SkippedReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SkippedReason {
    MissingAuditorMessage,
    InvalidAuditData,
}

/// What a signed request covers, besides its timestamp and nonce.
pub trait Attestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8>;
}

/// The paged reads a reader signs, each under its method name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagedRead {
    DecryptedTransactions,
    WalletActivity,
    AuditedMerges,
}

/// One ring behind one ring rpc on one cluster, every signed read names all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadTarget {
    /// The genesis hash.
    pub cluster: [u8; 32],
    /// The ring rpc's signing key.
    pub service: Address,
    pub ring: Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadAttestation {
    pub read: PagedRead,
    pub target: ReadTarget,
    pub cursor: Option<Base64String>,
    pub limit: Option<Limit>,
    pub wallet: Option<Address>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditorKeyAttestation {
    pub ring: Address,
    pub genesis_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditedUtxosAttestation {
    pub target: ReadTarget,
    /// sha256 of the requested hashes, concatenated in request order.
    pub utxo_hashes: [u8; 32],
    pub wallet: Option<Address>,
}

/// The service's statement of the auditor key it holds, bound to the request it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditorKeyStatement<'a> {
    pub cluster: &'a [u8; 32],
    pub ring: &'a Address,
    pub auditor_pubkey: &'a X25519Pubkey,
    pub nonce: &'a [u8; 32],
}

#[must_use]
pub struct SignedRequest<A> {
    attestation: A,
    timestamp: Option<u64>,
    nonce: [u8; 32],
}

pub type ReadRequest = SignedRequest<ReadAttestation>;
pub type AuditorKeyRequest = SignedRequest<AuditorKeyAttestation>;

#[must_use]
pub struct AuditedUtxosRequest {
    signed: SignedRequest<AuditedUtxosAttestation>,
    utxo_hashes: Vec<Hash>,
}

#[derive(Debug, Error)]
pub enum KeyFileError {
    #[error(transparent)]
    File(#[from] SecretFileError),
    #[error("public key file is not 66 hex characters")]
    PubkeyEncoding,
    #[error("key path must name a file")]
    InvalidPath,
    #[error("auditor key cannot be zero")]
    ZeroAuditorKey,
    #[error("auditor public key is invalid because {0}")]
    Key(#[from] KeypairError),
}

impl AuditorKeyStatement<'_> {
    pub fn message(&self) -> Vec<u8> {
        [
            ATTESTATION_DOMAIN,
            &self.cluster[..],
            self.ring.as_ref(),
            self.auditor_pubkey.as_bytes(),
            &self.nonce[..],
        ]
        .concat()
    }
}

impl From<ConfirmedAudit> for DecryptedTransaction {
    fn from(confirmed: ConfirmedAudit) -> Self {
        let ConfirmedAudit {
            audited,
            event_index,
            nullifiers,
            spenders,
            signers,
            withdrawals,
        } = confirmed;
        Self {
            slot: audited.slot,
            tx_signature: audited.tx_signature.into(),
            event_index,
            tx_viewing_pk: audited.tx_viewing_pk.as_bytes().to_vec().into(),
            outputs: audited.outputs.into_iter().map(Into::into).collect(),
            payload_errors: audited
                .payload_errors
                .into_iter()
                .map(|error| DecryptedPayloadError {
                    slot_index: error.slot_index,
                    kind: error.kind,
                })
                .collect(),
            real_inputs: audited.real_inputs,
            inputs: audited.inputs.into_iter().map(Into::into).collect(),
            nullifiers: nullifiers.into_iter().map(Into::into).collect(),
            spenders: spenders
                .into_iter()
                .map(|key| key.to_bytes().into())
                .collect(),
            signers: signers
                .into_iter()
                .map(|key| key.to_bytes().into())
                .collect(),
            withdrawals: withdrawals
                .into_iter()
                .map(|withdrawal| DecryptedWithdrawal {
                    screened_owner: withdrawal
                        .screened_owner
                        .map(|owner| owner.to_bytes().into()),
                    recipient: withdrawal.recipient.to_bytes().into(),
                    asset: withdrawal.asset.to_bytes().into(),
                    amount: withdrawal.amount,
                })
                .collect(),
        }
    }
}

impl From<AuditedOutput> for DecryptedOutput {
    fn from(output: AuditedOutput) -> Self {
        let (kind, utxo, tag) = match output.opening {
            OutputOpening::Ring {
                utxo,
                owner_tag: RingOwnerTag(tag),
            } => (DecryptedOutputKind::Ring, Some(utxo), Some(tag.into())),
            OutputOpening::Exit(utxo) => (DecryptedOutputKind::Exit, Some(utxo), None),
            OutputOpening::Dummy => (DecryptedOutputKind::Dummy, None, None),
        };
        Self {
            slot_index: output.slot_index,
            output_context: DecryptedOutputContext {
                tree_id: output.context.tree_id,
                leaf_index: output.context.leaf_index,
                hash: output.context.hash.into(),
            },
            kind,
            utxo: utxo.map(Into::into),
            tag,
        }
    }
}

impl DecryptedOutput {
    /// `None` for a dummy.
    pub fn owner_key(&self) -> Option<SerializablePubkey> {
        self.utxo.as_ref().map(|utxo| utxo.owner_key)
    }
}

impl From<AuditedUtxo> for DecryptedUtxo {
    fn from(utxo: AuditedUtxo) -> Self {
        Self {
            owner_key: utxo.owner_key.into(),
            nullifier_pk: utxo.nullifier_pk.into(),
            asset: utxo.asset.into(),
            mint: utxo.mint.map(Into::into),
            amount: utxo.amount,
            blinding: utxo.blinding.into(),
            data_hash: utxo.data_hash.into(),
            ring_data_hash: utxo.ring_data_hash.into(),
        }
    }
}

impl From<KnownUtxo> for DecryptedKnownUtxo {
    fn from(utxo: KnownUtxo) -> Self {
        let UtxoOwner::Keyed { nullifier_pk } = utxo.owner;
        Self {
            owner_key: utxo.owner_key.into(),
            nullifier_pk: nullifier_pk.into(),
            asset: utxo.asset.into(),
            mint: utxo.mint.map(Into::into),
            amount: utxo.amount,
            blinding: utxo.blinding.into(),
            data_hash: utxo.data_hash.into(),
            ring_data_hash: utxo.ring_data_hash.into(),
            tree_id: utxo.tree_id,
        }
    }
}

impl TryFrom<&DecryptedKnownUtxo> for KnownUtxo {
    type Error = AuditError;

    fn try_from(utxo: &DecryptedKnownUtxo) -> Result<Self, AuditError> {
        Ok(Self {
            owner_key: utxo.owner_key.0.to_bytes(),
            owner: UtxoOwner::Keyed {
                nullifier_pk: utxo.nullifier_pk.0,
            },
            asset: utxo.asset.0,
            mint: utxo.mint.map(|mint| mint.0),
            amount: utxo.amount,
            blinding: utxo.blinding.0,
            data_hash: utxo.data_hash.0,
            ring_data_hash: utxo.ring_data_hash.0,
            tree_id: utxo.tree_id,
        })
    }
}

impl GetAuditedUtxosResponse {
    /// Every opening must rebuild the hash it answers, a note of `ring` or of the default ring.
    pub fn known_utxos(
        &self,
        ring: Address,
        requested: &[Hash],
    ) -> Result<HashMap<[u8; 32], KnownUtxo>, AuditError> {
        let utxos = &self.value.utxos;
        if utxos.len() != requested.len() {
            return Err(AuditError::AuditedUtxosCount {
                got: utxos.len(),
                want: requested.len(),
            });
        }
        let mut known = HashMap::new();
        for (view, requested) in utxos.iter().zip(requested) {
            let Some(view) = view else {
                continue;
            };
            let utxo = KnownUtxo::try_from(&view.utxo)?;
            let rebuilt = [Some(ring), None]
                .into_iter()
                .map(|ring| utxo.commitment(ring))
                .collect::<Result<Vec<_>, _>>()?;
            if view.utxo_hash != *requested || !rebuilt.contains(&requested.0) {
                return Err(AuditError::AuditedUtxoMismatch {
                    utxo_hash: requested.0,
                });
            }
            known.insert(requested.0, utxo);
        }
        Ok(known)
    }
}

impl From<AuditedInput> for DecryptedInput {
    fn from(input: AuditedInput) -> Self {
        Self {
            nullifier: input.nullifier.into(),
            class: input.opening.class().into(),
            default_input: input
                .opening
                .default_input()
                .map(|input| DecryptedDefaultInput {
                    utxo: input.utxo.into(),
                    commitment: input.commitment.map(Into::into),
                }),
        }
    }
}

impl RingChainStatus {
    /// An account of another owner reads as absent, a malformed one of the ring is an error.
    pub async fn read<R: AsyncRpc + ?Sized>(rpc: &R, ring: Address) -> Result<Self, ClientError> {
        let pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let (config, config_bump) = Address::find_program_address(&[RING_AUTH_PDA_SEED], &ring);
        let [config] = <[_; 1]>::try_from(rpc.get_multiple_accounts(vec![config]).await?)
            .map_err(|_| ClientError::Rpc("ring status accounts are missing".to_owned()))?;
        let invalid = |name: &str| ClientError::Rpc(format!("ring {name} account is invalid"));
        let activation = config
            .filter(|account| account.owner == pool)
            .map(|account| {
                bytemuck::try_from_bytes::<RingConfig>(&account.data)
                    .ok()
                    .filter(|config| {
                        config.has_discriminator()
                            && config.program_id == ring
                            && config.bump == config_bump
                    })
                    .map(RingActivation::from)
                    .ok_or_else(|| invalid("SPP config"))
            })
            .transpose()?;
        Ok(Self { activation })
    }
}

impl From<&RingConfig> for RingActivation {
    fn from(config: &RingConfig) -> Self {
        Self {
            activated: config.is_activated(),
            paused: config.is_paused(),
        }
    }
}

impl PagedRead {
    pub const fn method(self) -> &'static str {
        match self {
            Self::DecryptedTransactions => GET_DECRYPTED_TRANSACTIONS,
            Self::WalletActivity => GET_WALLET_ACTIVITY,
            Self::AuditedMerges => GET_AUDITED_MERGES,
        }
    }

    /// A fresh nonce for every request, signing consumes it.
    pub fn request(self, target: ReadTarget) -> ReadRequest {
        SignedRequest::new(ReadAttestation {
            read: self,
            target,
            cursor: None,
            limit: None,
            wallet: None,
        })
    }
}

impl ReadTarget {
    fn lines(&self) -> String {
        format!(
            "cluster: {}\nservice: {}\nring: {}",
            Hash(self.cluster).to_base58(),
            self.service,
            self.ring
        )
    }
}

impl Attestation for ReadAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        let cursor = self.cursor.as_ref().map_or(&[][..], |cursor| &cursor.0);
        format!(
            "{READ_DOMAIN}\nmethod: {}\n{}\ntimestamp: {timestamp}\nnonce: {}\nlimit: {}\ncursor: {}{}",
            self.read.method(),
            self.target.lines(),
            base64(nonce),
            self.limit.as_ref().map_or(0, Limit::value),
            base64(cursor),
            wallet_line(self.wallet),
        )
        .into_bytes()
    }
}

impl Attestation for AuditorKeyAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        format!(
            "{AUDITOR_KEY_REQUEST_DOMAIN}\ngenesis: {}\nring: {}\ntimestamp: {timestamp}\nnonce: {}",
            Hash(self.genesis_hash).to_base58(),
            self.ring,
            base64(nonce),
        )
        .into_bytes()
    }
}

impl AuditedUtxosAttestation {
    pub fn new(target: ReadTarget, utxo_hashes: &[Hash]) -> Self {
        let mut digest = Sha256::new();
        for hash in utxo_hashes {
            digest.update(hash.0);
        }
        Self {
            target,
            utxo_hashes: digest.finalize().into(),
            wallet: None,
        }
    }
}

impl Attestation for AuditedUtxosAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        format!(
            "{AUDITED_UTXOS_DOMAIN}\n{}\ntimestamp: {timestamp}\nnonce: {}\nutxos: {}{}",
            self.target.lines(),
            base64(nonce),
            base64(&self.utxo_hashes),
            wallet_line(self.wallet),
        )
        .into_bytes()
    }
}

impl<A: Attestation> SignedRequest<A> {
    pub fn new(attestation: A) -> Self {
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Self {
            attestation,
            timestamp: None,
            nonce,
        }
    }

    pub fn at(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    fn message(&self) -> Result<(u64, Vec<u8>), RequestBuildError> {
        let timestamp = self.timestamp.map_or_else(unix_now, Ok)?;
        Ok((timestamp, self.attestation.message(timestamp, &self.nonce)))
    }

    /// The reader's signature over the attestation, a passkey's with its assertion.
    fn read_auth<S: ReadSigner + ?Sized>(&self, signer: &S) -> Result<ReadAuth, ReadBuildError> {
        let (timestamp, message) = self.message()?;
        let (signature, webauthn) = match signer.sign(&message)? {
            ReadSignature::Ed25519(raw) => (raw.to_vec(), None),
            ReadSignature::WebAuthn {
                signature_der,
                assertion,
            } => (signature_der, Some(assertion)),
        };
        Ok(ReadAuth {
            reader: signer.reader()?.to_bytes().to_vec().into(),
            timestamp,
            nonce: self.nonce.to_vec().into(),
            signature: signature.into(),
            webauthn,
        })
    }
}

impl ReadRequest {
    pub fn with_cursor(mut self, cursor: Base64String) -> Result<Self, ReadBuildError> {
        if !cursor_in_bounds(&cursor.0) {
            return Err(ReadBuildError::Cursor);
        }
        self.attestation.cursor = Some(cursor);
        Ok(self)
    }

    pub fn with_limit(mut self, limit: Limit) -> Result<Self, ReadBuildError> {
        if !limit_in_bounds(&limit) {
            return Err(ReadBuildError::Limit);
        }
        self.attestation.limit = Some(limit);
        Ok(self)
    }

    pub fn with_wallet(mut self, wallet: Address) -> Self {
        self.attestation.wallet = Some(wallet);
        self
    }

    pub fn sign<S: ReadSigner + ?Sized>(
        self,
        signer: &S,
    ) -> Result<GetDecryptedTransactionsRequest, ReadBuildError> {
        let auth = self.read_auth(signer)?;
        let ReadAttestation {
            target,
            cursor,
            limit,
            wallet,
            ..
        } = self.attestation;
        Ok(GetDecryptedTransactionsRequest {
            ring_program_id: Some(target.ring.to_bytes().into()),
            cursor,
            limit,
            wallet: wallet.map(Into::into),
            auth,
        })
    }
}

impl AuditedUtxosRequest {
    pub fn at(self, timestamp: u64) -> Self {
        Self {
            signed: self.signed.at(timestamp),
            ..self
        }
    }

    pub fn with_wallet(mut self, wallet: Address) -> Self {
        self.signed.attestation.wallet = Some(wallet);
        self
    }

    pub fn sign<S: ReadSigner + ?Sized>(
        self,
        signer: &S,
    ) -> Result<GetAuditedUtxosRequest, ReadBuildError> {
        Ok(GetAuditedUtxosRequest {
            ring_program_id: Some(self.signed.attestation.target.ring.to_bytes().into()),
            wallet: self.signed.attestation.wallet.map(Into::into),
            auth: self.signed.read_auth(signer)?,
            utxo_hashes: self.utxo_hashes,
        })
    }
}

impl AuditorKeyRequest {
    pub fn sign<S: Signer + ?Sized>(
        self,
        authority: &S,
    ) -> Result<CreateAuditorKeyRequest, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        let signature = authority
            .try_sign_message(&message)
            .map_err(RequestBuildError::Signature)?;
        let AuditorKeyAttestation { ring, genesis_hash } = self.attestation;
        Ok(CreateAuditorKeyRequest {
            ring_program_id: ring.to_bytes().into(),
            auth: AuthorityAuth {
                authority: authority.pubkey().to_bytes().into(),
                genesis_hash: Hash(genesis_hash),
                timestamp,
                nonce: self.nonce.to_vec().into(),
                signature: signature.as_ref().to_vec().into(),
            },
        })
    }
}

impl GetDecryptedTransactionsRequest {
    pub fn read(target: ReadTarget) -> ReadRequest {
        PagedRead::DecryptedTransactions.request(target)
    }
}

impl GetAuditedUtxosRequest {
    /// Refuses an empty or oversized read before it is signed.
    pub fn read(
        target: ReadTarget,
        utxo_hashes: Vec<Hash>,
    ) -> Result<AuditedUtxosRequest, ReadBuildError> {
        if !utxo_hashes_in_bounds(&utxo_hashes) {
            return Err(ReadBuildError::UtxoHashes);
        }
        Ok(AuditedUtxosRequest {
            signed: SignedRequest::new(AuditedUtxosAttestation::new(target, &utxo_hashes)),
            utxo_hashes,
        })
    }
}

impl CreateAuditorKeyRequest {
    /// `genesis_hash` names the cluster, a signature never carries over to another one.
    pub fn for_ring(ring: Address, genesis_hash: [u8; 32]) -> AuditorKeyRequest {
        SignedRequest::new(AuditorKeyAttestation { ring, genesis_hash })
    }
}

impl AuditorPubkey {
    pub fn as_key(&self) -> &X25519Pubkey {
        &self.0
    }
}

impl From<X25519Pubkey> for AuditorPubkey {
    fn from(value: X25519Pubkey) -> Self {
        Self(value)
    }
}

impl From<AuditorPubkey> for Base64String {
    fn from(key: AuditorPubkey) -> Self {
        Self(key.0.as_bytes().to_vec())
    }
}

impl TryFrom<Base64String> for AuditorPubkey {
    type Error = &'static str;

    fn try_from(encoded: Base64String) -> Result<Self, Self::Error> {
        let bytes = encoded
            .0
            .try_into()
            .map_err(|_| "auditor public key length is invalid")?;
        X25519Pubkey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| "auditor public key is invalid")
    }
}

impl<T: Signer + ?Sized> ReadSigner for T {
    fn reader(&self) -> Result<ReaderKey, ReaderKeyError> {
        ReaderKey::ed25519(self.pubkey())
    }

    fn sign(&self, attestation: &[u8]) -> Result<ReadSignature, ReadBuildError> {
        self.try_sign_message(attestation)
            .map(|signature| ReadSignature::Ed25519(*signature.as_array()))
            .map_err(|error| RequestBuildError::Signature(error).into())
    }
}

pub fn unix_now() -> Result<u64, RequestBuildError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| RequestBuildError::Clock)
}

/// Lowercase hex, with the public key beside it in `<file>.pub`.
pub fn read_auditor_key(path: &Path, access: Access) -> Result<X25519Keypair, KeyFileError> {
    let secret = read_key32(path, access)?;
    auditor_keypair(&secret)
}

/// Clamping keeps every scalar off the identity, the unset all-zero secret is the only refusal.
pub fn auditor_keypair(secret: &[u8; 32]) -> Result<X25519Keypair, KeyFileError> {
    if secret.iter().all(|byte| *byte == 0) {
        return Err(KeyFileError::ZeroAuditorKey);
    }
    Ok(X25519Keypair::from_bytes(secret))
}

/// Neither new file remains when either cannot be written.
pub fn write_auditor_key(out: &Path) -> Result<X25519Keypair, KeyFileError> {
    let public_path = public_key_path(out)?;
    let key = X25519Keypair::new();
    let secret = Zeroizing::new(hex::encode(*key.secret_bytes()));
    let public = hex::encode(key.pubkey().as_bytes());
    KeyPairFiles {
        secret_path: out,
        secret: secret.as_bytes(),
        public_path: &public_path,
        public: public.as_bytes(),
    }
    .create()?;
    Ok(key)
}

pub fn write_auditor_pubkey(path: &Path, pubkey: &X25519Pubkey) -> Result<(), KeyFileError> {
    let public = hex::encode(pubkey.as_bytes());
    Ok(create_new(path, public.as_bytes(), Visibility::Public)?)
}

pub fn read_auditor_pubkey(path: &Path) -> Result<X25519Pubkey, KeyFileError> {
    let text = std::fs::read_to_string(path).map_err(|source| SecretFileError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let bytes = hex::decode(text.trim())
        .ok()
        .and_then(|bytes| <[u8; 33]>::try_from(bytes).ok())
        .ok_or(KeyFileError::PubkeyEncoding)?;
    Ok(X25519Pubkey::from_bytes(bytes)?)
}

pub fn public_key_path(secret: &Path) -> Result<PathBuf, KeyFileError> {
    let mut name = secret
        .file_name()
        .ok_or(KeyFileError::InvalidPath)?
        .to_os_string();
    name.push(".pub");
    Ok(secret.with_file_name(name))
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Empty for a ring-wide read, its attestation keeps the bytes the TypeScript twin signs.
fn wallet_line(wallet: Option<Address>) -> String {
    wallet.map_or_else(String::new, |wallet| format!("\nwallet: {wallet}"))
}

#[cfg(test)]
mod tests;
