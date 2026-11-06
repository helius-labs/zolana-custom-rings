//! Ring bodies, sender bundles and reply metadata, each under its own label over a CRDS slot secret.
//!
//! A ring body is the slot's proven record and its unproven payload, one stream. The proof binds the
//! record to the slot's opening and its ciphertext to the statement, the payload stays the sender's word.

use custom_ring_interface::{
    domain::{RECIPIENT_BODY_LABEL, REPLY_LABEL, SENDER_BUNDLE_LABEL},
    stream::SlotSecret,
    BundleLayout, OutputRecord, RecipientPayload, RecordKind, SenderBundle, OUTPUT_RECORD_LEN,
};
use solana_address::Address;
use spr_hasher::primitives::is_canonical_x25519_public_key;
use spr_keypair::{ShieldedAddress, X25519Keypair, X25519Pubkey};
use spr_transaction::{
    derive_output_blinding_seed, utxo::derive_transact_output_blinding, Blinding, Data, DataRecord,
    Mint, SppProofOutputUtxo, Utxo,
};
use zeroize::Zeroizing;
use zolana_ring_keys::symmetric_apply_audit;

use crate::{RingAssets, RingRailError};

/// `viewing_u || owner_key || nullifier_pk`.
const REPLY_HEAD_LEN: usize = 3 * 32;

/// Opt in per frame, the statement binds its bytes and proves nothing about its meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplyMetadata {
    pub viewing_key: X25519Pubkey,
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub data: Data,
}

/// A decrypted reply, its sender claim stays unverified until the wallet confirms it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplyClaim(ReplyMetadata);

impl ReplyClaim {
    pub fn claimed(&self) -> &ReplyMetadata {
        &self.0
    }
}

impl ReplyMetadata {
    /// The head and the wincode of the data, no padding.
    pub(crate) fn encoded_len(&self) -> Result<usize, RingRailError> {
        let data = wincode::serialized_size(&self.data)
            .map_err(spr_transaction::TransactionError::from)?;
        usize::try_from(data)
            .map(|data| REPLY_HEAD_LEN + data)
            .map_err(|_| RingRailError::ReplyMetadataLength {
                reply_len: usize::MAX,
            })
    }

    fn encode(&self, reply_len: usize) -> Result<Zeroizing<Vec<u8>>, RingRailError> {
        self.data.validate()?;
        let data = Zeroizing::new(
            wincode::serialize(&self.data).map_err(spr_transaction::TransactionError::from)?,
        );
        if reply_len < REPLY_HEAD_LEN + data.len() {
            return Err(RingRailError::ReplyMetadataLength { reply_len });
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(reply_len));
        bytes.extend_from_slice(&self.viewing_key.u());
        bytes.extend_from_slice(&self.owner_key);
        bytes.extend_from_slice(&self.nullifier_pk);
        bytes.extend_from_slice(&data);
        bytes.resize(reply_len, 0);
        Ok(bytes)
    }

    /// A nonzero padding byte or a zero or non-canonical `viewing_u` opens nothing, as enrollment refuses it.
    fn decode(bytes: &[u8]) -> Option<Self> {
        let (viewing_u, rest) = bytes.split_first_chunk::<32>()?;
        if *viewing_u == [0; 32] || !is_canonical_x25519_public_key(viewing_u) {
            return None;
        }
        let (owner_key, rest) = rest.split_first_chunk::<32>()?;
        let (nullifier_pk, rest) = rest.split_first_chunk::<32>()?;
        let data: Data = wincode::deserialize(rest).ok()?;
        data.validate().ok()?;
        let used = usize::try_from(wincode::serialized_size(&data).ok()?).ok()?;
        if rest.get(used..)?.iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(Self {
            viewing_key: X25519Pubkey::from_u(*viewing_u).ok()?,
            owner_key: *owner_key,
            nullifier_pk: *nullifier_pk,
            data,
        })
    }
}

/// A body its reader decrypted, the record still unchecked against the commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedRecipientBody {
    pub record: OutputRecord,
    pub payload: PayloadRead,
}

/// The unproven bytes past the record, a malformed one leaves the proven record whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadRead {
    /// A frame without data.
    Absent,
    Opened(RecipientPayload),
    Malformed,
}

/// The record then the payload padded to the frame's width, one slot secret keys one body.
pub fn seal_recipient_body(
    record: &OutputRecord,
    payload: Option<(&RecipientPayload, usize)>,
    slot_secret: &SlotSecret,
) -> Result<Vec<u8>, RingRailError> {
    let mut plaintext = Zeroizing::new(record.encode().to_vec());
    if let Some((payload, width)) = payload {
        plaintext.extend_from_slice(&payload.encode_padded(width)?);
    }
    encrypt_recipient_body(plaintext.to_vec(), slot_secret)
}

/// The cipher is unauthenticated, only the commitment a reader rebuilds proves ownership.
pub fn open_recipient_body(
    ciphertext: &[u8],
    slot_secret: &SlotSecret,
) -> Result<OpenedRecipientBody, RingRailError> {
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    symmetric_apply_audit(slot_secret.as_bytes(), RECIPIENT_BODY_LABEL, &mut plaintext)?;
    let (record, payload) = plaintext
        .split_at_checked(OUTPUT_RECORD_LEN)
        .ok_or(custom_ring_interface::CustomRingError::RingTransactLength)?;
    Ok(OpenedRecipientBody {
        record: OutputRecord::decode(record)?,
        payload: match payload.is_empty() {
            true => PayloadRead::Absent,
            false => RecipientPayload::decode(payload)
                .map_or(PayloadRead::Malformed, PayloadRead::Opened),
        },
    })
}

/// The payload `output` commits beside its record, `data` leads with the hash the commitment reads.
pub fn recipient_payload(output: &SppProofOutputUtxo) -> RecipientPayload {
    let data = match output.data_hash.filter(|hash| *hash != [0; 32]) {
        Some(hash) => [&hash[..], output.data.utxo_data().unwrap_or_default()].concat(),
        None => Vec::new(),
    };
    RecipientPayload {
        ring_data_hash: output.ring_data_hash.filter(|hash| *hash != [0; 32]),
        data,
    }
}

/// `slot_secret` sits at index `m`, past every body's index.
pub fn seal_sender_bundle(
    bundle: &SenderBundle,
    slot_secret: &SlotSecret,
) -> Result<Vec<u8>, RingRailError> {
    let mut ciphertext = bundle.encode();
    symmetric_apply_audit(slot_secret.as_bytes(), SENDER_BUNDLE_LABEL, &mut ciphertext)?;
    Ok(ciphertext)
}

/// `layout` holds the frame's published counts, never counts a reader inferred from the ciphertext.
pub fn open_sender_bundle(
    ciphertext: &[u8],
    slot_secret: &SlotSecret,
    layout: BundleLayout,
) -> Result<SenderBundle, RingRailError> {
    if ciphertext.len() != layout.byte_len() {
        return Err(RingRailError::SenderBundleLength {
            len: ciphertext.len(),
        });
    }
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    symmetric_apply_audit(slot_secret.as_bytes(), SENDER_BUNDLE_LABEL, &mut plaintext)?;
    Ok(SenderBundle::decode(&plaintext, layout)?)
}

/// Shares slot `i`'s secret, its own label keeps the body's counter from restarting.
pub fn seal_reply(
    reply: &ReplyMetadata,
    reply_len: usize,
    slot_secret: &SlotSecret,
) -> Result<Vec<u8>, RingRailError> {
    let mut ciphertext = reply.encode(reply_len)?.to_vec();
    symmetric_apply_audit(slot_secret.as_bytes(), REPLY_LABEL, &mut ciphertext)?;
    Ok(ciphertext)
}

/// `None` on a reply that never decodes, a hidden dummy reads as random bytes.
pub fn open_reply(
    ciphertext: &[u8],
    slot_secret: &SlotSecret,
) -> Result<Option<ReplyClaim>, RingRailError> {
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    symmetric_apply_audit(slot_secret.as_bytes(), REPLY_LABEL, &mut plaintext)?;
    Ok(ReplyMetadata::decode(&plaintext).map(ReplyClaim))
}

/// One published anonymous output, rebuilt from a body and the reader's keys.
#[derive(Clone, Copy, Debug)]
pub struct AnonymousOutput<'a> {
    pub owner: &'a ShieldedAddress,
    pub assets: &'a RingAssets,
    pub ring: Address,
    pub tree_id: u16,
    pub utxo_hash: &'a [u8; 32],
}

/// A note its reader rebuilt, a match establishes ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedNote {
    pub utxo: Utxo,
    /// The key the record names, the owner spends the note once that key is its registered one.
    pub nullifier_pk: [u8; 32],
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
}

/// A body whose rebuilt commitment names the reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenedBody {
    Note(OpenedNote),
    /// The commitment rebuilds under a mint the registry does not name, `utxo` holds its asset id at zero.
    UnknownMint(OpenedNote),
}

/// `TXOB(first_nullifier, TXOS(first_nullifier, blinding_seed), position)` per output.
pub struct OutputBlindings {
    first_nullifier: [u8; 32],
    output_seed: Zeroizing<[u8; 32]>,
}

impl AnonymousOutput<'_> {
    /// `None` unless the record names the reader as a ring output's owner and rebuilds the
    /// commitment, its key unchecked.
    pub fn open_body(
        &self,
        body: &OpenedRecipientBody,
    ) -> Result<Option<OpenedBody>, RingRailError> {
        let record = &body.record;
        if record.kind != RecordKind::Ring
            || record.owner_key != self.owner.signing_pubkey.confidential_view_tag()?
        {
            return Ok(None);
        }
        let payload = match &body.payload {
            PayloadRead::Absent => RecipientPayload::default(),
            PayloadRead::Opened(payload) => payload.clone(),
            PayloadRead::Malformed => return Ok(None),
        };
        let mint = Address::new_from_array(record.mint);
        let asset = self.assets.by_mint(&mint);
        let (data_hash, app_data) = match payload.data.split_first_chunk::<32>() {
            // Data under a zero hash binds to no commitment.
            Some((hash, _)) if *hash == [0; 32] => return Ok(None),
            Some((hash, app_data)) => (Some(*hash), app_data),
            None if payload.data.is_empty() => (None, &[][..]),
            None => return Ok(None),
        };
        let note = |asset: Mint| Utxo {
            owner: self.owner.signing_pubkey,
            asset,
            amount: record.amount,
            blinding: record.blinding,
            ring_program_id: Some(self.ring),
            data: match data_hash {
                Some(_) => Data::new(vec![DataRecord::UtxoData(app_data.to_vec())]),
                None => Data::default(),
            },
        };
        // The commitment reads the mint alone, the id only names a registered one.
        let probe = note(asset.unwrap_or(Mint {
            asset: mint,
            asset_id: 0,
        }));
        let rebuilds = probe
            .hash(
                &record.nullifier_pk,
                &data_hash.unwrap_or_default(),
                &payload.ring_data_hash.unwrap_or_default(),
                self.tree_id,
            )
            .is_ok_and(|hash| hash == *self.utxo_hash);
        if !rebuilds {
            return Ok(None);
        }
        let opened = |utxo| OpenedNote {
            utxo,
            nullifier_pk: record.nullifier_pk,
            data_hash,
            ring_data_hash: payload.ring_data_hash,
        };
        Ok(Some(match asset {
            Some(asset) => OpenedBody::Note(opened(note(asset))),
            None => OpenedBody::UnknownMint(opened(probe.clone())),
        }))
    }
}

impl OutputBlindings {
    /// `blinding_seed` is the rail's `CRBS(tx_viewing_sk, salt)`.
    pub fn new(
        first_nullifier: &[u8; 32],
        blinding_seed: &[u8; 32],
    ) -> Result<Self, RingRailError> {
        Ok(Self {
            first_nullifier: *first_nullifier,
            output_seed: Zeroizing::new(derive_output_blinding_seed(
                first_nullifier,
                blinding_seed,
            )?),
        })
    }

    pub fn published(first_nullifier: &[u8; 32], output_seed: &[u8; 32]) -> Self {
        Self {
            first_nullifier: *first_nullifier,
            output_seed: Zeroizing::new(*output_seed),
        }
    }

    pub fn at(&self, position: u32) -> Result<Blinding, RingRailError> {
        Ok(derive_transact_output_blinding(
            &self.first_nullifier,
            &self.output_seed,
            position,
        )?)
    }

    /// The seed the sender bundle publishes, every change blinding derives from it.
    pub fn output_seed(&self) -> &[u8; 32] {
        &self.output_seed
    }
}

/// False for a low-order transaction key, every clamped secret refuses the same keys.
pub fn is_contributory(tx_viewing_pk: &X25519Pubkey) -> bool {
    X25519Keypair::from_bytes(&[0; 32])
        .ecdh(tx_viewing_pk)
        .is_ok()
}

fn encrypt_recipient_body(
    mut plaintext: Vec<u8>,
    slot_secret: &SlotSecret,
) -> Result<Vec<u8>, RingRailError> {
    symmetric_apply_audit(slot_secret.as_bytes(), RECIPIENT_BODY_LABEL, &mut plaintext)?;
    Ok(plaintext)
}
