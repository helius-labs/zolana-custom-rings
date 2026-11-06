//! Tag 57 record, mirrored by Go `prover/circuits/merge.go`.

use custom_ring_interface::{
    domain::MERGE_RECORD_LABEL, OpeningRecord, OPENING_RECORD_LEN, STREAM_FIRST_COUNTER,
};
use spr_keypair::{X25519Keypair, X25519Pubkey};
use zeroize::Zeroizing;

use super::{opening_ring_stream, sealing_ring_stream, Result};
use crate::AuditError;

pub struct MergeRecordSeal {
    pub record: OpeningRecord,
}

/// The ephemeral secret is the merge proof's witness.
pub struct SealedMergeOpening {
    pub eph_pk: X25519Pubkey,
    pub ciphertext: [u8; OPENING_RECORD_LEN],
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
}

impl MergeRecordSeal {
    /// A reused ephemeral key repeats the stream under another record.
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
        let stream = sealing_ring_stream(&ephemeral, auditor_pk, MERGE_RECORD_LABEL)?;
        let mut ciphertext = self.record.encode();
        stream.apply_at(STREAM_FIRST_COUNTER, &mut ciphertext);
        Ok(SealedMergeOpening {
            eph_pk: ephemeral.pubkey(),
            ciphertext,
            ephemeral_sk: ephemeral.secret_bytes(),
        })
    }
}

/// Unauthenticated, the caller rebuilds the output from the record.
pub fn open_merge_record(
    auditor: &X25519Keypair,
    eph_pk: &X25519Pubkey,
    ciphertext: &[u8; OPENING_RECORD_LEN],
) -> Result<OpeningRecord> {
    let stream = opening_ring_stream(auditor, eph_pk, MERGE_RECORD_LABEL)?;
    let mut plaintext = Zeroizing::new(*ciphertext);
    stream.apply_at(STREAM_FIRST_COUNTER, &mut *plaintext);
    OpeningRecord::decode(&*plaintext).map_err(|_| AuditError::DisclosureField)
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

    #[test]
    fn both_modes_open_and_seal_to_the_go_vector() {
        let vector: Value = serde_json::from_str(VECTOR).unwrap();
        let auditor = X25519Keypair::from_bytes(&array(&vector["auditor_sk"]));
        let eph_pk = X25519Pubkey::from_bytes(array(&vector["eph_pk"])).unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let ciphertext = array(&case["ciphertext"]);
            let opened = open_merge_record(&auditor, &eph_pk, &ciphertext).unwrap();
            assert_eq!(opened.encode().to_vec(), hex_bytes(&case["record"]));
            let ephemeral = X25519Keypair::from_bytes(&array(&case["request"]["ephSk"]));
            let sealed = MergeRecordSeal { record: opened }
                .seal_with(ephemeral, &auditor.pubkey())
                .unwrap();
            assert_eq!(sealed.ciphertext, ciphertext);
            assert_eq!(sealed.eph_pk, eph_pk);
            let blinding = MergeSeed::from_bytes(opened.secret)
                .unwrap()
                .output_blinding(&array(&case["request"]["firstNullifier"]))
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
        let mut ciphertext: [u8; OPENING_RECORD_LEN] = array(&case["ciphertext"]);
        let record = hex_bytes(&case["record"]);
        let read = |auditor: &X25519Keypair, ciphertext: &[u8; OPENING_RECORD_LEN]| {
            open_merge_record(auditor, &eph_pk, ciphertext).map(|opened| opened.encode().to_vec())
        };
        assert!(read(&X25519Keypair::new(), &ciphertext).unwrap_or_default() != record);
        ciphertext[100] ^= 1;
        assert!(read(&auditor, &ciphertext).unwrap_or_default() != record);
    }
}
