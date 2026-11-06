//! `getSpendCoverage`, the one surface that names an unclassified spend, for the ring authority alone.

use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signer::Signer;
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};

use super::{
    base64, cursor_in_bounds, Attestation, ReadBuildError, ReadTarget, RequestBuildError,
    SignedRequest,
};

pub const GET_SPEND_COVERAGE: &str = "getSpendCoverage";
const SPEND_COVERAGE_DOMAIN: &str = "zolana/ring-rpc-spend-coverage";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetSpendCoverageRequest {
    pub ring: SerializablePubkey,
    pub authority: SerializablePubkey,
    pub timestamp: u64,
    pub nonce: Base64String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Base64String>,
    /// Raw Ed25519 over the `SpendCoverageAttestation` message.
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetSpendCoverageResponse {
    /// The slot the next read starts past, absent inside a paged read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position_slot: Option<u64>,
    pub history_through: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<SpendCoverageTotals>,
    /// Transfer nullifiers no opened note owns, unresolved notes among addresses, default-ring
    /// notes and padding.
    pub unclassified: Vec<SpendCoverageRow>,
    /// Frames whose stream is unreadable, the only rows that hold `history_through` back.
    pub unreadable: Vec<SpendCoverageFrame>,
    /// A second event on one nullifier, its first state stays.
    pub integrity_faults: Vec<SpendCoverageRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Base64String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpendCoverageTotals {
    pub observed: u64,
    /// Merge padding alone.
    pub padding: u64,
    pub resolved: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpendCoverageRow {
    pub nullifier: Hash,
    pub frame: SpendCoverageFrame,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpendCoverageFrame {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendCoverageAttestation {
    pub target: ReadTarget,
    pub authority: Address,
    pub cursor: Option<Base64String>,
}

pub type SpendCoverageRequest = SignedRequest<SpendCoverageAttestation>;

impl Attestation for SpendCoverageAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        format!(
            "{SPEND_COVERAGE_DOMAIN}\n{}\nauthority: {}\ntimestamp: {timestamp}\nnonce: {}\ncursor: {}",
            self.target.lines(),
            self.authority,
            base64(nonce),
            base64(self.cursor.as_ref().map_or(&[][..], |cursor| &cursor.0)),
        )
        .into_bytes()
    }
}

impl SpendCoverageRequest {
    pub fn with_cursor(mut self, cursor: Base64String) -> Result<Self, ReadBuildError> {
        if !cursor_in_bounds(&cursor.0) {
            return Err(ReadBuildError::Cursor);
        }
        self.attestation.cursor = Some(cursor);
        Ok(self)
    }

    /// `authority` must be the attestation's authority, the service checks the signature against it.
    pub fn sign<S: Signer + ?Sized>(
        self,
        authority: &S,
    ) -> Result<GetSpendCoverageRequest, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        let signature = authority
            .try_sign_message(&message)
            .map_err(RequestBuildError::Signature)?;
        Ok(GetSpendCoverageRequest {
            ring: self.attestation.target.ring.into(),
            authority: self.attestation.authority.into(),
            timestamp,
            nonce: self.nonce.to_vec().into(),
            cursor: self.attestation.cursor,
            signature: signature.into(),
        })
    }
}
