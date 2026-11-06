//! `getDelegateNotes`, a victim's openings and secret for the ring's configured delegate alone.

use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signer::Signer;
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{constants::BLINDING_LEN, NullifierKey};

use super::{
    base64, Attestation, GetWalletStatusResponse, ReadBuildError, ReadTarget, RequestBuildError,
    SignedRequest, WalletNote,
};

pub const GET_DELEGATE_NOTES: &str = "getDelegateNotes";
pub const RELEASE_DELEGATE_SNAPSHOT: &str = "releaseDelegateSnapshot";
const DELEGATE_SNAPSHOT_RELEASE_DOMAIN: &str = "zolana/ring-rpc-delegate-snapshot-release";
const DELEGATE_NOTES_DOMAIN: &str = "zolana/ring-rpc-delegate-notes";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetDelegateNotesRequest {
    pub ring: SerializablePubkey,
    pub delegate: SerializablePubkey,
    pub owner: SerializablePubkey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Base64String>,
    pub timestamp: u64,
    pub nonce: Base64String,
    /// Raw Ed25519 over the `DelegateNotesAttestation` message.
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetDelegateNotesResponse {
    /// Right aligned, absent while the owner holds no registration or its seal is unread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier_secret: Option<Hash>,
    pub status: GetWalletStatusResponse,
}

impl GetDelegateNotesResponse {
    /// The key whose public half `note` commits, `None` under a key the owner never registered.
    pub fn nullifier_key(&self, note: &WalletNote) -> Option<NullifierKey> {
        let committed = note.nullifier_pk.as_ref()?.0;
        if committed == ZERO_NULLIFIER_PUBKEY {
            return Some(NullifierKey::from_secret([0; BLINDING_LEN]));
        }
        let secret = self.nullifier_secret.as_ref()?.0;
        let (pad, secret) = secret.split_first()?;
        let key = NullifierKey::from_secret(secret.try_into().ok()?);
        (*pad == 0 && key.pubkey().ok()? == committed).then_some(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateNotesAttestation {
    pub target: ReadTarget,
    pub delegate: Address,
    pub owner: Address,
    pub cursor: Option<Base64String>,
}

pub type DelegateNotesRequest = SignedRequest<DelegateNotesAttestation>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateSnapshotReleaseAttestation {
    pub target: ReadTarget,
    pub delegate: Address,
    pub owner: Address,
    pub cursor: Base64String,
}

#[must_use]
pub struct DelegateSnapshotReleaseRequest {
    signed: SignedRequest<DelegateSnapshotReleaseAttestation>,
}

struct DelegateNotesMessage<'a> {
    domain: &'a str,
    target: &'a ReadTarget,
    delegate: Address,
    owner: Address,
    cursor: &'a [u8],
    timestamp: u64,
    nonce: &'a [u8; 32],
}

struct DelegateRequestSigning {
    attestation: DelegateNotesAttestation,
    timestamp: u64,
    nonce: [u8; 32],
    message: Vec<u8>,
}

impl Attestation for DelegateNotesAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        DelegateNotesMessage {
            domain: DELEGATE_NOTES_DOMAIN,
            target: &self.target,
            delegate: self.delegate,
            owner: self.owner,
            cursor: self.cursor.as_ref().map_or(&[], |cursor| &cursor.0),
            timestamp,
            nonce,
        }
        .encode()
    }
}

impl Attestation for DelegateSnapshotReleaseAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        DelegateNotesMessage {
            domain: DELEGATE_SNAPSHOT_RELEASE_DOMAIN,
            target: &self.target,
            delegate: self.delegate,
            owner: self.owner,
            cursor: &self.cursor.0,
            timestamp,
            nonce,
        }
        .encode()
    }
}

impl DelegateSnapshotReleaseRequest {
    pub fn new(attestation: DelegateSnapshotReleaseAttestation) -> Result<Self, ReadBuildError> {
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

    pub fn sign<S: Signer + ?Sized>(
        self,
        delegate: &S,
    ) -> Result<GetDelegateNotesRequest, RequestBuildError> {
        let (timestamp, message) = self.signed.message()?;
        let attestation = self.signed.attestation;
        DelegateRequestSigning {
            attestation: DelegateNotesAttestation {
                target: attestation.target,
                delegate: attestation.delegate,
                owner: attestation.owner,
                cursor: Some(attestation.cursor),
            },
            timestamp,
            nonce: self.signed.nonce,
            message,
        }
        .sign(delegate)
    }
}

impl DelegateNotesRequest {
    /// `delegate` must be the attestation's delegate, the service checks the signature against it.
    pub fn sign<S: Signer + ?Sized>(
        self,
        delegate: &S,
    ) -> Result<GetDelegateNotesRequest, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        DelegateRequestSigning {
            attestation: self.attestation,
            timestamp,
            nonce: self.nonce,
            message,
        }
        .sign(delegate)
    }
}

impl DelegateNotesMessage<'_> {
    fn encode(self) -> Vec<u8> {
        format!(
            "{}\n{}\ndelegate: {}\nowner: {}\ncursor: {}\ntimestamp: {}\nnonce: {}",
            self.domain,
            self.target.lines(),
            self.delegate,
            self.owner,
            base64(self.cursor),
            self.timestamp,
            base64(self.nonce),
        )
        .into_bytes()
    }
}

impl DelegateRequestSigning {
    fn sign<S: Signer + ?Sized>(
        self,
        delegate: &S,
    ) -> Result<GetDelegateNotesRequest, RequestBuildError> {
        let signature = delegate
            .try_sign_message(&self.message)
            .map_err(RequestBuildError::Signature)?;
        Ok(GetDelegateNotesRequest {
            ring: self.attestation.target.ring.into(),
            delegate: self.attestation.delegate.into(),
            owner: self.attestation.owner.into(),
            cursor: self.attestation.cursor,
            timestamp: self.timestamp,
            nonce: self.nonce.to_vec().into(),
            signature: signature.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use solana_signature::Signature;
    use spr_hasher::primitives::right_align;

    use super::*;
    use crate::rpc::{WalletEnrollment, WalletNoteStatus};

    fn note(nullifier_pk: [u8; 32]) -> WalletNote {
        WalletNote {
            utxo_hash: Hash([1; 32]),
            status: WalletNoteStatus::Unspent,
            nullifier_pk: Some(Hash(nullifier_pk)),
            asset: Hash([2; 32]),
            mint: None,
            amount: 5,
            blinding: Hash([3; 32]),
            data_hash: Some(Hash([0; 32])),
            ring_data_hash: Some(Hash([0; 32])),
            tree_id: 0,
            leaf_index: 0,
            slot: 1,
            tx_signature: Signature::default().into(),
            event_index: 0,
            slot_index: 0,
        }
    }

    #[test]
    fn each_note_opens_only_under_the_key_it_commits() {
        let registered = NullifierKey::from_secret([7; BLINDING_LEN]);
        let read = GetDelegateNotesResponse {
            nullifier_secret: Some(Hash(right_align(&registered.secret()))),
            status: GetWalletStatusResponse {
                history_through: 1,
                enrollment: WalletEnrollment::Applied,
                snapshot_expires_at: None,
                balances: Vec::new(),
                notes: Vec::new(),
                cursor: None,
            },
        };
        let keyed = read
            .nullifier_key(&note(registered.pubkey().unwrap()))
            .expect("the registered key opens its note");
        assert_eq!(keyed.secret(), registered.secret());
        let zero = read
            .nullifier_key(&note(ZERO_NULLIFIER_PUBKEY))
            .expect("the zero key opens a zero-key note");
        assert_eq!(zero.pubkey().unwrap(), ZERO_NULLIFIER_PUBKEY);
        let foreign = NullifierKey::from_secret([8; BLINDING_LEN])
            .pubkey()
            .unwrap();
        assert!(read.nullifier_key(&note(foreign)).is_none());
        let unread = GetDelegateNotesResponse {
            nullifier_secret: None,
            ..read
        };
        assert!(unread
            .nullifier_key(&note(registered.pubkey().unwrap()))
            .is_none());
    }
}
