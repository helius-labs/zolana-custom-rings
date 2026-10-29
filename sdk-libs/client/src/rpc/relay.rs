use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};

const RELAY_DOMAIN: &[u8] = b"zolana/ring-rpc-relay/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RelayOperation {
    Anonymous,
    Confidential,
    Delegate,
    Deposit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRelayQuoteRequest {
    pub ring: SerializablePubkey,
    pub operation: RelayOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelayQuote {
    pub fee_payer: SerializablePubkey,
    pub valid_until_slot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrepareRelayRequest {
    pub ring: SerializablePubkey,
    pub quote: RelayQuote,
    pub intent: RelayIntent,
}

/// `proof_inputs` holds the rail's proof inputs without Merkle paths or record openings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    deny_unknown_fields,
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum RelayIntent {
    /// `owner_signature` is raw Ed25519 over `SppProofInputs::message_hash`.
    Anonymous {
        proof_inputs: Base64String,
        owner_signature: SerializableSignature,
    },
    Confidential {
        proof_inputs: Base64String,
        owner_signature: SerializableSignature,
    },
    Delegate {
        proof_inputs: Base64String,
    },
    Deposit {
        proof_inputs: Base64String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelayId(pub Hash);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "step",
    deny_unknown_fields,
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum RelayStep {
    Submitted {
        relay_id: RelayId,
    },
    /// `message` is the v1 message the wallet signs and returns through `submitRelay`.
    SignMessage {
        relay_id: RelayId,
        message: Base64String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubmitRelayRequest {
    pub relay_id: RelayId,
    pub signer: SerializablePubkey,
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRelayStatusRequest {
    pub relay_id: RelayId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    deny_unknown_fields,
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum RelayStatus {
    AwaitingSignature,
    Sent {
        signature: SerializableSignature,
    },
    Confirmed {
        signature: SerializableSignature,
        slot: u64,
    },
    Failed {
        reason: String,
    },
}

impl RelayIntent {
    pub const fn operation(&self) -> RelayOperation {
        match self {
            Self::Anonymous { .. } => RelayOperation::Anonymous,
            Self::Confidential { .. } => RelayOperation::Confidential,
            Self::Delegate { .. } => RelayOperation::Delegate,
            Self::Deposit { .. } => RelayOperation::Deposit,
        }
    }
}

impl PrepareRelayRequest {
    /// SHA-256 over the domain and the request's own serialization, a retry names the same relay.
    pub fn relay_id(&self) -> Result<RelayId, serde_json::Error> {
        let request = serde_json::to_vec(self)?;
        let digest: [u8; 32] = Sha256::new()
            .chain_update(RELAY_DOMAIN)
            .chain_update(request)
            .finalize()
            .into();
        Ok(RelayId(Hash(digest)))
    }
}
