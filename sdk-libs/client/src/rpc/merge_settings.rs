use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signer::Signer;
use spr_indexer_api::{Base64String, SerializablePubkey, SerializableSignature};

use super::{base64, Attestation, ReadTarget, RequestBuildError, SignedRequest};

const MERGE_SETTINGS_DOMAIN: &str = "zolana/ring-rpc-merge-settings/v1";

/// Ring RPC merges the owner's notes of `mint` toward these settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MergeSettings {
    pub mint: SerializablePubkey,
    pub target_note_count: u32,
    pub min_average_amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SetMergeSettingsRequest {
    pub ring: SerializablePubkey,
    pub owner: SerializablePubkey,
    pub settings: MergeSettings,
    pub timestamp: u64,
    pub nonce: Base64String,
    /// Raw Ed25519 over the `MergeSettingsAttestation` message.
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeSettingsAttestation {
    pub target: ReadTarget,
    pub owner: Address,
    pub settings: MergeSettings,
}

pub type MergeSettingsRequest = SignedRequest<MergeSettingsAttestation>;
/// `setMergeSettings` answers with the stored settings.
pub type SetMergeSettingsResponse = MergeSettings;

impl Attestation for MergeSettingsAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        format!(
            "{MERGE_SETTINGS_DOMAIN}\n{}\nowner: {}\nmint: {}\ntarget notes: {}\nminimum average: {}\ntimestamp: {timestamp}\nnonce: {}",
            self.target.lines(),
            self.owner,
            self.settings.mint.0,
            self.settings.target_note_count,
            self.settings.min_average_amount,
            base64(nonce),
        )
        .into_bytes()
    }
}

impl MergeSettingsRequest {
    /// `owner` must be the attestation's owner, the service checks the signature against it.
    pub fn sign<S: Signer + ?Sized>(
        self,
        owner: &S,
    ) -> Result<SetMergeSettingsRequest, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        let signature = owner
            .try_sign_message(&message)
            .map_err(RequestBuildError::Signature)?;
        Ok(SetMergeSettingsRequest {
            ring: self.attestation.target.ring.into(),
            owner: self.attestation.owner.into(),
            settings: self.attestation.settings,
            timestamp,
            nonce: self.nonce.to_vec().into(),
            signature: signature.into(),
        })
    }
}
