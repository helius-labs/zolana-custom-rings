//! `getWalletStatus`, one owner's notes as of the finalized slot the operator verified.

use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};

use super::{base64, Attestation, ReadAuth, ReadBuildError, ReadSigner, ReadTarget, SignedRequest};

pub const WALLET_SNAPSHOT_EXPIRED: i32 = -32172;
pub const WALLET_SNAPSHOT_CAPACITY: i32 = -32173;
pub const WALLET_SNAPSHOT_CURSOR_LEN: usize = 129;
pub const WALLET_SNAPSHOT_CURSOR_VERSION: u8 = 2;

pub const GET_WALLET_STATUS: &str = "getWalletStatus";
pub const RELEASE_WALLET_SNAPSHOT: &str = "releaseWalletSnapshot";
const WALLET_SNAPSHOT_RELEASE_DOMAIN: &str = "zolana/ring-rpc-wallet-snapshot-release";
const WALLET_STATUS_DOMAIN: &str = "zolana/ring-rpc-wallet-status";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetWalletStatusRequest {
    /// Required for derived keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_program_id: Option<SerializablePubkey>,
    pub wallet: SerializablePubkey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Base64String>,
    pub auth: ReadAuth,
}

/// Holds the wallet's own notes and nothing about any other transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetWalletStatusResponse {
    /// Only an unreadable stream holds it back.
    pub history_through: u64,
    pub enrollment: WalletEnrollment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_expires_at: Option<u64>,
    /// Sums every `Unspent` note from one snapshot, empty past the first page.
    pub balances: Vec<WalletBalance>,
    pub notes: Vec<WalletNote>,
    pub cursor: Option<Base64String>,
}

/// The owner's own public tracking account, a pending enrollment grants nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WalletEnrollment {
    NotEnrolled,
    Pending,
    /// The tree is full, the first enrollment stays pending with its rent spent.
    PendingPastCapacity,
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletBalance {
    pub asset: Hash,
    /// Absent while the asset registry does not know the asset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint: Option<SerializablePubkey>,
    pub amount: u64,
}

/// A full opening, a wallet that got an unusable body rebuilds its note from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletNote {
    pub utxo_hash: Hash,
    pub status: WalletNoteStatus,
    /// Absent on a deposit whose capsule discloses the owner hash alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier_pk: Option<Hash>,
    pub asset: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint: Option<SerializablePubkey>,
    pub amount: u64,
    pub blinding: Hash,
    pub data_hash: Hash,
    pub ring_data_hash: Hash,
    pub tree_id: u16,
    pub leaf_index: u64,
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
    pub slot_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WalletNoteStatus {
    Spent,
    Unspent,
    /// The owner's secret is not readable yet, never counted as unspent.
    Unknown,
    /// A zero key note of an Ed25519 owner, outside the balance and merge selection.
    ExposedIfSpent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletStatusAttestation {
    pub target: ReadTarget,
    pub wallet: Address,
    pub cursor: Option<Base64String>,
}

#[must_use]
pub struct WalletStatusRequest {
    signed: SignedRequest<WalletStatusAttestation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSnapshotReleaseAttestation {
    pub target: ReadTarget,
    pub wallet: Address,
    pub cursor: Base64String,
}

#[must_use]
pub struct WalletSnapshotReleaseRequest {
    signed: SignedRequest<WalletSnapshotReleaseAttestation>,
}

struct WalletStatusMessage<'a> {
    domain: &'a str,
    target: &'a ReadTarget,
    wallet: Address,
    cursor: &'a [u8],
    timestamp: u64,
    nonce: &'a [u8; 32],
}

impl Attestation for WalletStatusAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        WalletStatusMessage {
            domain: WALLET_STATUS_DOMAIN,
            target: &self.target,
            wallet: self.wallet,
            cursor: self.cursor.as_ref().map_or(&[], |cursor| &cursor.0),
            timestamp,
            nonce,
        }
        .encode()
    }
}

impl Attestation for WalletSnapshotReleaseAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        WalletStatusMessage {
            domain: WALLET_SNAPSHOT_RELEASE_DOMAIN,
            target: &self.target,
            wallet: self.wallet,
            cursor: &self.cursor.0,
            timestamp,
            nonce,
        }
        .encode()
    }
}

impl WalletSnapshotReleaseRequest {
    pub fn new(attestation: WalletSnapshotReleaseAttestation) -> Result<Self, ReadBuildError> {
        super::wallet_snapshot::validate_snapshot_cursor(&attestation.cursor)?;
        Ok(Self {
            signed: SignedRequest::new(attestation),
        })
    }

    pub fn at(self, timestamp: u64) -> Self {
        Self {
            signed: self.signed.at(timestamp),
        }
    }

    pub fn sign<S: ReadSigner + ?Sized>(
        self,
        signer: &S,
    ) -> Result<GetWalletStatusRequest, ReadBuildError> {
        let auth = self.signed.read_auth(signer)?;
        let WalletSnapshotReleaseAttestation {
            target,
            wallet,
            cursor,
        } = self.signed.attestation;
        Ok(WalletStatusAttestation {
            target,
            wallet,
            cursor: Some(cursor),
        }
        .request(auth))
    }
}

impl WalletStatusRequest {
    pub fn new(target: ReadTarget, wallet: Address) -> Self {
        Self {
            signed: SignedRequest::new(WalletStatusAttestation {
                target,
                wallet,
                cursor: None,
            }),
        }
    }

    pub fn at(self, timestamp: u64) -> Self {
        Self {
            signed: self.signed.at(timestamp),
        }
    }

    pub fn with_cursor(mut self, cursor: Base64String) -> Result<Self, ReadBuildError> {
        super::wallet_snapshot::validate_snapshot_cursor(&cursor)?;
        self.signed.attestation.cursor = Some(cursor);
        Ok(self)
    }

    pub fn sign<S: ReadSigner + ?Sized>(
        self,
        signer: &S,
    ) -> Result<GetWalletStatusRequest, ReadBuildError> {
        let auth = self.signed.read_auth(signer)?;
        Ok(self.signed.attestation.request(auth))
    }
}

impl WalletStatusMessage<'_> {
    fn encode(self) -> Vec<u8> {
        format!(
            "{}\n{}\ntimestamp: {}\nnonce: {}\nwallet: {}\ncursor: {}",
            self.domain,
            self.target.lines(),
            self.timestamp,
            base64(self.nonce),
            self.wallet,
            base64(self.cursor),
        )
        .into_bytes()
    }
}

impl WalletStatusAttestation {
    fn request(self, auth: ReadAuth) -> GetWalletStatusRequest {
        GetWalletStatusRequest {
            ring_program_id: Some(self.target.ring.into()),
            wallet: self.wallet.into(),
            cursor: self.cursor,
            auth,
        }
    }
}
