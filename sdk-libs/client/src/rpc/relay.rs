use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};
use zeroize::Zeroizing;

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
        proof_inputs: ProofInputBytes,
        owner_signature: SerializableSignature,
    },
    Confidential {
        proof_inputs: ProofInputBytes,
        owner_signature: SerializableSignature,
    },
    Delegate {
        proof_inputs: ProofInputBytes,
    },
    Deposit {
        proof_inputs: ProofInputBytes,
    },
}

/// Base64 on the wire, zeroized on drop and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct ProofInputBytes(Zeroizing<Vec<u8>>);

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

    pub const fn proof_inputs(&self) -> &ProofInputBytes {
        match self {
            Self::Anonymous { proof_inputs, .. }
            | Self::Confidential { proof_inputs, .. }
            | Self::Delegate { proof_inputs }
            | Self::Deposit { proof_inputs } => proof_inputs,
        }
    }
}

impl PrepareRelayRequest {
    /// SHA-256 over the domain and the request's own serialization, a retry names the same relay.
    pub fn relay_id(&self) -> Result<RelayId, serde_json::Error> {
        let request = Zeroizing::new(serde_json::to_vec(self)?);
        let digest: [u8; 32] = Sha256::new()
            .chain_update(RELAY_DOMAIN)
            .chain_update(&request)
            .finalize()
            .into();
        Ok(RelayId(Hash(digest)))
    }
}

impl ProofInputBytes {
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for ProofInputBytes {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProofInputBytes(..)")
    }
}

impl Serialize for ProofInputBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&Zeroizing::new(STANDARD.encode(&*self.0)))
    }
}

impl<'de> Deserialize<'de> for ProofInputBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        STANDARD
            .decode(encoded.as_bytes())
            .map(|bytes| Self(Zeroizing::new(bytes)))
            .map_err(de::Error::custom)
    }
}
