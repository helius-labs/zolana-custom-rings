//! The ring merge request around its compressed SPP proof point.

mod common;

use std::ops::Range;

use custom_ring_interface::{
    domain::MERGE_RECORD_LABEL, storage::Revision, AuditRecord, CustomRingError,
    CustomRingMergeIxData, CustomRingMergeIxDataRef, CustomRingProof, MergePublicInput,
    OpeningRecord, PlainGroth16Proof, RecordKind, SealedMergeRecord, OPENING_RECORD_LEN,
};
use serde::Deserialize;
use solana_bn254::compression::prelude::alt_bn128_g2_compress_be;
use spr_interface::instruction::{
    instruction_data::{
        merge_ring::{MergeRingAuthority, MergeRingIxData, MergeRingIxDataRef},
        merge_transact::{MergeOutputEncryption, MergeProof, MergeTransactIxData},
    },
    tag::RING_MERGE_TRANSACT,
};

const FRAME_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/merge/merge_frame.hex"
);
const MERGE_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/merge/merge.json"
);

fn merge_body() -> MergeTransactIxData {
    MergeTransactIxData {
        expiry_unix_ts: 42,
        proof: MergeProof {
            a: [0x21; 32],
            b: common::spp_b(),
            c: [0x22; 32],
        },
        output_utxo_hash: [1; 32],
        output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
            salt: [2; 16],
            ciphertext: [[3; 32]; 3],
        },
        private_tx_hash: [4; 32],
        nullifiers: vec![[5; 32]],
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
        cache_slot: None,
    }
}

fn request(authority: MergeRingAuthority) -> CustomRingMergeIxData {
    CustomRingMergeIxData {
        tracking_revision: Revision::from(3),
        output_ring_data_hash: [8; 32],
        authority,
        sealed: SealedMergeRecord {
            proof: CustomRingProof {
                groth16: PlainGroth16Proof {
                    proof_a: [9; 32],
                    proof_b: [10; 64],
                    proof_c: [11; 32],
                },
                commitment: [12; 32],
                commitment_pok: [13; 32],
            },
            eph_pk: [4; 33],
            ciphertext: [14; OPENING_RECORD_LEN],
        },
        merge: merge_body(),
    }
}

#[test]
fn the_frame_is_the_shared_vector() {
    let committed = std::fs::read_to_string(FRAME_VECTOR).expect("vector file");
    assert_eq!(
        committed.trim(),
        hex::encode(request(MergeRingAuthority::Ring).serialize().unwrap())
    );
}

#[test]
#[ignore = "rewrites test-vectors/merge/merge_frame.hex"]
fn write_merge_frame_vector() {
    let line = hex::encode(request(MergeRingAuthority::Ring).serialize().unwrap()) + "\n";
    std::fs::write(FRAME_VECTOR, line).expect("write vector file");
}

#[test]
fn the_view_rebuilds_the_exact_spp_body_from_the_compressed_point() {
    for authority in [MergeRingAuthority::Ring, MergeRingAuthority::OwnerSigned] {
        let request = request(authority);
        let bytes = request.serialize().unwrap();
        let spp_body = request.merge.serialize().unwrap();
        let view = CustomRingMergeIxDataRef::from_bytes(&bytes).unwrap();
        assert_eq!(view.tracking_revision, Revision::from(3));
        assert_eq!(view.output_ring_data_hash, &[8; 32]);
        assert_eq!(view.authority, authority);
        assert_eq!(view.spp_merge_body().unwrap(), spp_body);
        assert_eq!(
            bytes.len() + 64,
            8 + 32 + 1 + CustomRingProof::SIZE + 33 + OPENING_RECORD_LEN + spp_body.len()
        );
        assert_eq!(view.proof, &request.sealed.proof);
        assert_eq!(view.eph_pk, &request.sealed.eph_pk);
        assert_eq!(view.ciphertext, &request.sealed.ciphertext);
    }
}

/// The forwarded bytes are SPP's own `merge_ring` data, a wrong authority tag would move every later field.
#[test]
fn the_forward_parses_as_merge_ring() {
    for authority in [MergeRingAuthority::Ring, MergeRingAuthority::OwnerSigned] {
        let request = request(authority);
        let bytes = request.serialize().unwrap();
        let view = CustomRingMergeIxDataRef::from_bytes(&bytes).unwrap();
        let forwarded = view.forwarded(&view.spp_merge_body().unwrap());
        assert_eq!(forwarded[0], RING_MERGE_TRANSACT);
        assert_eq!(
            MergeRingIxData::deserialize(&forwarded[1..]).unwrap(),
            MergeRingIxData {
                output_ring_data_hash: request.output_ring_data_hash,
                authority,
                merge: request.merge.clone(),
            }
        );
        MergeRingIxDataRef::from_bytes(&forwarded[1..]).unwrap();
    }
}

/// The merge record is a transfer's record followed by the seed, one encoding for both.
#[test]
fn the_merge_record_is_an_opening_record_of_a_ring_note() {
    let opening = OpeningRecord {
        record: AuditRecord {
            kind: RecordKind::Ring,
            amount: 12,
            owner_key: [0xa1; 32],
            mint: [0xa2; 32],
            nullifier_pk: [0xa3; 32],
        },
        secret: [0xa4; 32],
    };
    let encoded = opening.encode();
    assert_eq!(encoded.len(), 144);
    assert_eq!(OpeningRecord::decode(&encoded).unwrap(), opening);
    assert_eq!(MERGE_RECORD_LABEL, b"CRING/mrg");
}

fn compressed_b(bytes: &[u8]) -> Range<usize> {
    let b = alt_bn128_g2_compress_be(&common::spp_b()).unwrap();
    let start = bytes
        .windows(b.len())
        .position(|window| window == b)
        .expect("the request carries b compressed");
    start..start + b.len()
}

#[test]
fn a_compressed_point_off_the_curve_is_refused() {
    let mut bytes = request(MergeRingAuthority::Ring).serialize().unwrap();
    let b = compressed_b(&bytes);
    bytes[b].fill(0xff);
    let view = CustomRingMergeIxDataRef::from_bytes(&bytes).unwrap();
    assert_eq!(
        view.spp_merge_body(),
        Err(CustomRingError::InvalidSppProofPoint)
    );
}

#[test]
fn framing_errors_are_refused_before_or_by_the_spp_parser() {
    let bytes = request(MergeRingAuthority::Ring).serialize().unwrap();
    let truncated = &bytes[..compressed_b(&bytes).end - 1];
    for refused in [truncated, &bytes[..47]] {
        assert_eq!(
            CustomRingMergeIxDataRef::from_bytes(refused).err(),
            Some(CustomRingError::InvalidInstructionData)
        );
    }
}

fn hex_bytes(value: &str) -> Vec<u8> {
    hex::decode(value.trim_start_matches("0x")).unwrap()
}

fn field<const N: usize>(value: &str) -> [u8; N] {
    hex_bytes(value).try_into().unwrap()
}

#[test]
fn merge_statement_matches_the_go_vector() {
    #[derive(Deserialize)]
    struct Request {
        #[serde(rename = "outputUtxoHash")]
        output_utxo_hash: String,
        #[serde(rename = "firstNullifier")]
        first_nullifier: String,
        #[serde(rename = "ringProgramId")]
        ring_id: String,
        payer: String,
        #[serde(rename = "trackingRoot")]
        tracking_root: String,
    }
    #[derive(Deserialize)]
    struct Case {
        name: String,
        record: String,
        ciphertext: String,
        elements: Vec<String>,
        public_input_hash: String,
        request: Request,
    }
    #[derive(Deserialize)]
    struct Vector {
        auditor_pk: String,
        eph_pk: String,
        cases: Vec<Case>,
    }
    let vector: Vector =
        serde_json::from_str(&std::fs::read_to_string(MERGE_VECTOR).unwrap()).unwrap();
    for case in &vector.cases {
        let request = &case.request;
        let record = OpeningRecord::decode(&hex_bytes(&case.record)).unwrap();
        assert_eq!(record.record.kind, RecordKind::Ring);
        // Element 10 is what the program computes from the signer under a zero key.
        let elements = case
            .elements
            .iter()
            .map(|element| field::<32>(element))
            .collect::<Vec<_>>();
        assert_eq!(elements[10] == [0; 32], case.name == "nonzero");
        let statement = MergePublicInput {
            output_utxo_hash: &field(&request.output_utxo_hash),
            first_nullifier: &field(&request.first_nullifier),
            ring_id: &field(&request.ring_id),
            auditor_pk: &field(&vector.auditor_pk),
            eph_pk: &field(&vector.eph_pk),
            ciphertext: &field(&case.ciphertext),
            payer: &field(&request.payer),
            published_owner: &elements[10],
            tracking_root: &field(&request.tracking_root),
        };
        assert_eq!(elements, statement.elements().unwrap());
        assert_eq!(
            field::<32>(&case.public_input_hash),
            statement.hash().unwrap()
        );
    }
}
