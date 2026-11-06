//! The auditor stream of a ring transfer, mirrored by Go `prover/circuits/audit`.
//!
//! The stream seals the transaction viewing secret, `R`, any entry records, and every published
//! slot's recipient key. Each record sits in its slot's body under the slot's delivered secret, an
//! auditor holding the viewing secret and the key derives that secret and opens it.

use custom_ring_interface::{
    decode_recipient_keys, domain::AUDIT_STREAM_LABEL, encode_recipient_keys, AuditEvidence,
    AuditStreamLayout, StreamRegion, STREAM_FIRST_COUNTER,
};
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use zeroize::{Zeroize, Zeroizing};
use zolana_ring_keys::RingStream;

use crate::{
    encryption::{opening_salted_stream, sealing_salted_stream},
    AuditError,
};

/// Everything one transfer seals to its auditor under its own viewing key.
pub struct AuditStreamSeal<'a> {
    pub layout: AuditStreamLayout,
    pub tx_viewing_key: &'a ViewingKey,
    pub salt: &'a [u8; 16],
    /// `R`, the spent notes.
    pub real_inputs: u8,
    pub evidence: AuditEvidence,
    /// `V_i` of every published slot.
    pub recipient_keys: Vec<[u8; 32]>,
}

pub struct SealedAuditStream {
    /// The transfer's own viewing key.
    pub eph_u: [u8; 32],
    pub envelope: Vec<u8>,
    /// `32 m` bytes, key `i` at its own counter.
    pub keys: Vec<u8>,
}

impl AuditStreamSeal<'_> {
    /// The salt separates a resend, the viewing key repeats under one first nullifier.
    pub fn seal(self, auditor_pk: &X25519Pubkey) -> Result<SealedAuditStream, AuditError> {
        let Self {
            layout,
            tx_viewing_key,
            salt,
            real_inputs,
            evidence,
            recipient_keys,
        } = self;
        let layout = layout.checked().map_err(|_| AuditError::DisclosureLayout)?;
        if recipient_keys.len() != layout.outputs {
            return Err(AuditError::DisclosureLayout);
        }
        let key = X25519Keypair::from_bytes(&tx_viewing_key.secret_bytes());
        let stream = sealing_salted_stream(&key, auditor_pk, salt, AUDIT_STREAM_LABEL)?;
        let mut plaintext = custom_ring_interface::AuditEnvelope {
            tx_viewing_secret: *tx_viewing_key.secret_bytes(),
            real_inputs,
            evidence,
        };
        let mut envelope = plaintext.encode();
        plaintext.tx_viewing_secret.zeroize();
        // The opener's checks hold on the seal, a seal off its layout never leaves the wallet.
        let checked =
            custom_ring_interface::AuditEnvelope::decode(&envelope, layout).map(|mut opened| {
                opened.tx_viewing_secret.zeroize();
            });
        if checked.is_err() || envelope.len() != layout.envelope().len {
            envelope.zeroize();
            return Err(AuditError::DisclosureLayout);
        }
        stream.apply_at(STREAM_FIRST_COUNTER, &mut envelope);
        let mut keys = encode_recipient_keys(&recipient_keys);
        for (slot, key) in keys.as_chunks_mut::<32>().0.iter_mut().enumerate() {
            stream.apply_at(layout.recipient_key(slot).start_counter, key);
        }
        Ok(SealedAuditStream {
            eph_u: tx_viewing_key.pubkey().u(),
            envelope,
            keys,
        })
    }
}

/// The published envelope, its plaintext reads the rest of the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEnvelope<'a> {
    pub eph_u: [u8; 32],
    pub salt: &'a [u8; 16],
    pub ciphertext: &'a [u8],
}

pub struct OpenedAudit {
    pub tx_viewing_key: ViewingKey,
    /// `R`, the spent notes.
    pub real_inputs: u8,
    pub evidence: AuditEvidence,
    layout: AuditStreamLayout,
    stream: RingStream,
}

impl AuditEnvelope<'_> {
    /// The circuit seals the clamped encoding, an unclamped alias of the same key is refused.
    pub fn open(
        &self,
        auditor: &X25519Keypair,
        layout: AuditStreamLayout,
    ) -> Result<OpenedAudit, AuditError> {
        let stream = opening_salted_stream(
            auditor,
            &X25519Pubkey::from_u(self.eph_u)?,
            self.salt,
            AUDIT_STREAM_LABEL,
        )?;
        self.decode(stream, layout)
    }

    /// The transaction key reads the stream it seals, the wrong `auditor_pk` decrypts noise.
    pub fn open_sealed(
        &self,
        tx_viewing_key: &ViewingKey,
        auditor_pk: &X25519Pubkey,
        layout: AuditStreamLayout,
    ) -> Result<OpenedAudit, AuditError> {
        let key = X25519Keypair::from_bytes(&tx_viewing_key.secret_bytes());
        let stream = sealing_salted_stream(&key, auditor_pk, self.salt, AUDIT_STREAM_LABEL)?;
        self.decode(stream, layout)
    }

    fn decode(
        &self,
        stream: RingStream,
        layout: AuditStreamLayout,
    ) -> Result<OpenedAudit, AuditError> {
        let mut plaintext = Zeroizing::new(self.ciphertext.to_vec());
        stream.apply_at(STREAM_FIRST_COUNTER, &mut plaintext);
        let mut envelope = custom_ring_interface::AuditEnvelope::decode(&plaintext, layout)
            .map_err(|_| AuditError::DisclosureField)?;
        let tx_viewing_key = ViewingKey::from_canonical_bytes(&envelope.tx_viewing_secret)
            .map_err(|_| AuditError::NonCanonicalViewingKey);
        envelope.tx_viewing_secret.zeroize();
        check_evidence(&envelope.evidence)?;
        Ok(OpenedAudit {
            tx_viewing_key: tx_viewing_key?,
            real_inputs: envelope.real_inputs,
            evidence: envelope.evidence,
            layout,
            stream,
        })
    }
}

impl OpenedAudit {
    /// `ciphertext` is the message's key region, key `i` names slot `i`'s recipient.
    pub fn recipient_keys(&self, ciphertext: &[u8]) -> Result<Vec<X25519Pubkey>, AuditError> {
        if ciphertext.len() != self.layout.keys_len() {
            return Err(AuditError::DisclosureLayout);
        }
        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        for (slot, key) in plaintext.as_chunks_mut::<32>().0.iter_mut().enumerate() {
            self.open_region(self.layout.recipient_key(slot), key)?;
        }
        decode_recipient_keys(&plaintext, self.layout)
            .map_err(|_| AuditError::DisclosureField)?
            .into_iter()
            .map(|key| X25519Pubkey::from_u(key).map_err(|_| AuditError::DisclosureField))
            .collect()
    }

    fn open_region(&self, region: StreamRegion, bytes: &mut [u8]) -> Result<(), AuditError> {
        if bytes.len() != region.len {
            return Err(AuditError::DisclosureLayout);
        }
        self.stream.apply_at(region.start_counter, bytes);
        Ok(())
    }
}

/// Refuses an opening the proof cannot have bound.
fn check_evidence(evidence: &AuditEvidence) -> Result<(), AuditError> {
    match evidence {
        AuditEvidence::None => Ok(()),
        AuditEvidence::Entry { inputs, .. } => inputs.iter().try_for_each(|input| {
            canonical(input.nullifier_pk)?;
            canonical(input.input_commitment).map(drop)
        }),
    }
}

pub(crate) fn canonical(field: [u8; 32]) -> Result<[u8; 32], AuditError> {
    match is_canonical_bn254_scalar_be(&field) {
        true => Ok(field),
        false => Err(AuditError::DisclosureField),
    }
}

#[cfg(test)]
mod tests;
