//! Tag 57 record, mirrored by Go `prover/circuits/merge.go`.
//!
//! The record seals to the merged owner's viewing key `V` from a fresh ephemeral key, as a transfer
//! record seals to its slot's key. An envelope seals that ephemeral secret and `V` to the auditor,
//! who then derives the record's secret the owner derives.

use custom_ring_interface::{
    domain::{MERGE_OUTPUT_LABEL, MERGE_RECORD_LABEL},
    stream::{DeliveredSlot, SlotSecret},
    MergeEnvelope, MergeRecord, MERGE_ENVELOPE_LEN, MERGE_RECORD_LEN, STREAM_FIRST_COUNTER,
};
use spr_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use zeroize::{Zeroize, Zeroizing};
use zolana_ring_keys::symmetric_apply_audit;

use super::{opening_ring_stream, sealing_ring_stream, Result};
use crate::AuditError;

pub struct MergeRecordSeal {
    pub record: MergeRecord,
    /// The merged owner's viewing key `V`.
    pub recipient: X25519Pubkey,
    pub first_nullifier: [u8; 32],
}

/// The ephemeral secret is the merge proof's witness.
pub struct SealedMergeOpening {
    pub eph_pk: X25519Pubkey,
    pub envelope: [u8; MERGE_ENVELOPE_LEN],
    pub record: [u8; MERGE_RECORD_LEN],
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
}

impl MergeRecordSeal {
    /// A reused ephemeral key repeats both streams under another record.
    pub fn seal(self, auditor_pk: &X25519Pubkey) -> Result<SealedMergeOpening> {
        self.seal_with(X25519Keypair::new(), auditor_pk)
    }

    /// Vectors only.
    #[doc(hidden)]
    pub fn seal_with(
        self,
        ephemeral: X25519Keypair,
        auditor_pk: &X25519Pubkey,
    ) -> Result<SealedMergeOpening> {
        let mut envelope = MergeEnvelope {
            eph_sk: *ephemeral.secret_bytes(),
            recipient_u: self.recipient.u(),
        }
        .encode();
        sealing_ring_stream(&ephemeral, auditor_pk, MERGE_RECORD_LABEL)?
            .apply_at(STREAM_FIRST_COUNTER, &mut envelope);
        let secret = record_secret(&ephemeral, &self.recipient, &self.first_nullifier)?;
        let mut record = self.record.encode();
        symmetric_apply_audit(secret.as_bytes(), MERGE_OUTPUT_LABEL, &mut record)?;
        Ok(SealedMergeOpening {
            eph_pk: ephemeral.pubkey(),
            envelope,
            record,
            ephemeral_sk: ephemeral.secret_bytes(),
        })
    }
}

/// The auditor's read, unauthenticated, the caller rebuilds the output from the record.
pub fn open_merge_record(
    auditor: &X25519Keypair,
    sealed: &SealedMergeCiphertexts<'_>,
) -> Result<MergeRecord> {
    let mut envelope = Zeroizing::new(*sealed.envelope);
    opening_ring_stream(auditor, sealed.eph_pk, MERGE_RECORD_LABEL)?
        .apply_at(STREAM_FIRST_COUNTER, &mut *envelope);
    let mut opened = MergeEnvelope::decode(&*envelope).map_err(|_| AuditError::DisclosureField)?;
    let ephemeral = X25519Keypair::from_bytes(&opened.eph_sk);
    opened.eph_sk.zeroize();
    // The proof derives the published key from the sealed secret, another secret is no seal of it.
    if ephemeral.pubkey() != *sealed.eph_pk {
        return Err(AuditError::DisclosureField);
    }
    let recipient = X25519Pubkey::from_u(opened.recipient_u)?;
    let secret = record_secret(&ephemeral, &recipient, sealed.first_nullifier)?;
    open_record(&secret, sealed.record)
}

/// The merged owner's read under its viewing key, the auditor reads the same secret.
pub fn open_owned_merge_record(
    viewing_key: &ViewingKey,
    sealed: &SealedMergeCiphertexts<'_>,
) -> Result<MergeRecord> {
    let secret = DeliveredSlot {
        agreement: &viewing_key.ecdh(sealed.eph_pk)?,
        tx_viewing_pk: sealed.eph_pk.as_bytes(),
        recipient_viewing_pk: viewing_key.pubkey().as_bytes(),
        salt: &[0; 16],
        output_index: 0,
        first_nullifier: sealed.first_nullifier,
    }
    .secret()?;
    open_record(&secret, sealed.record)
}

#[derive(Clone, Copy)]
pub struct SealedMergeCiphertexts<'a> {
    pub eph_pk: &'a X25519Pubkey,
    pub envelope: &'a [u8; MERGE_ENVELOPE_LEN],
    pub record: &'a [u8; MERGE_RECORD_LEN],
    pub first_nullifier: &'a [u8; 32],
}

/// `DeliveredSlot` with the ephemeral key as the transaction key, a zero salt and index zero.
fn record_secret(
    ephemeral: &X25519Keypair,
    recipient: &X25519Pubkey,
    first_nullifier: &[u8; 32],
) -> Result<SlotSecret> {
    Ok(DeliveredSlot {
        agreement: &*ephemeral.ecdh(recipient)?,
        tx_viewing_pk: ephemeral.pubkey().as_bytes(),
        recipient_viewing_pk: recipient.as_bytes(),
        salt: &[0; 16],
        output_index: 0,
        first_nullifier,
    }
    .secret()?)
}

fn open_record(secret: &SlotSecret, ciphertext: &[u8; MERGE_RECORD_LEN]) -> Result<MergeRecord> {
    let mut plaintext = Zeroizing::new(*ciphertext);
    symmetric_apply_audit(secret.as_bytes(), MERGE_OUTPUT_LABEL, &mut *plaintext)?;
    MergeRecord::decode(&*plaintext).map_err(|_| AuditError::DisclosureField)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use spr_transaction::instructions::merge::MergeSeed;

    use super::*;

    const VECTOR: &str = include_str!("../../../../../test-vectors/merge/merge.json");

    fn hex_bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }

    fn array<const N: usize>(value: &Value) -> [u8; N] {
        hex_bytes(value).try_into().unwrap()
    }

    fn first_nullifier(case: &Value) -> [u8; 32] {
        array(&case["request"]["firstNullifier"])
    }

    #[test]
    fn both_modes_open_and_seal_to_the_go_vector() {
        let vector: Value = serde_json::from_str(VECTOR).unwrap();
        let auditor = X25519Keypair::from_bytes(&array(&vector["auditor_sk"]));
        let eph_pk = X25519Pubkey::from_bytes(array(&vector["eph_pk"])).unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let envelope = array(&case["envelope_ciphertext"]);
            let record = array(&case["ciphertext"]);
            let first_nullifier = first_nullifier(case);
            let opened = open_merge_record(
                &auditor,
                &SealedMergeCiphertexts {
                    eph_pk: &eph_pk,
                    envelope: &envelope,
                    record: &record,
                    first_nullifier: &first_nullifier,
                },
            )
            .unwrap();
            assert_eq!(opened.encode().to_vec(), hex_bytes(&case["record"]));
            let ephemeral = X25519Keypair::from_bytes(&array(&case["request"]["ephSk"]));
            let recipient = X25519Pubkey::from_u(array(&case["request"]["recipientKey"])).unwrap();
            let sealed = MergeRecordSeal {
                record: opened,
                recipient,
                first_nullifier,
            }
            .seal_with(ephemeral, &auditor.pubkey())
            .unwrap();
            assert_eq!((sealed.envelope, sealed.record), (envelope, record));
            assert_eq!(sealed.eph_pk, eph_pk);
            let blinding = MergeSeed::from_bytes(opened.seed)
                .unwrap()
                .output_blinding(&first_nullifier)
                .unwrap();
            assert_eq!(blinding, array::<32>(&case["output_blinding"]));
        }
    }

    #[test]
    fn another_key_or_a_changed_byte_reads_no_vector_record() {
        let vector: Value = serde_json::from_str(VECTOR).unwrap();
        let auditor = X25519Keypair::from_bytes(&array(&vector["auditor_sk"]));
        let eph_pk = X25519Pubkey::from_bytes(array(&vector["eph_pk"])).unwrap();
        let case = &vector["cases"][0];
        let envelope: [u8; MERGE_ENVELOPE_LEN] = array(&case["envelope_ciphertext"]);
        let mut ciphertext: [u8; MERGE_RECORD_LEN] = array(&case["ciphertext"]);
        let first_nullifier = first_nullifier(case);
        let record = hex_bytes(&case["record"]);
        let read = |auditor: &X25519Keypair, ciphertext: &[u8; MERGE_RECORD_LEN]| {
            open_merge_record(
                auditor,
                &SealedMergeCiphertexts {
                    eph_pk: &eph_pk,
                    envelope: &envelope,
                    record: ciphertext,
                    first_nullifier: &first_nullifier,
                },
            )
            .map(|opened| opened.encode().to_vec())
        };
        assert!(read(&X25519Keypair::new(), &ciphertext).unwrap_or_default() != record);
        ciphertext[100] ^= 1;
        assert!(read(&auditor, &ciphertext).unwrap_or_default() != record);
    }
}
