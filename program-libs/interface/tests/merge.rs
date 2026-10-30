//! The ring merge request around its compressed SPP proof point.

mod common;

use std::ops::Range;

use custom_ring_interface::{
    merge_disclosure_field_count, storage::Revision, CustomRingError, CustomRingMergeIxData,
    CustomRingMergeIxDataRef, CustomRingProof, MergeDisclosure, PlainGroth16Proof,
};
use solana_bn254::compression::prelude::alt_bn128_g2_compress_be;
use spr_interface::instruction::instruction_data::merge_transact::{
    MergeOutputEncryption, MergeProof, MergeTransactIxData,
};

fn request() -> CustomRingMergeIxData {
    CustomRingMergeIxData {
        own_revision: Revision::from(3),
        output_ring_data_hash: [8; 32],
        disclosure: disclosure(),
        merge: MergeTransactIxData {
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
        },
    }
}

fn disclosure() -> MergeDisclosure {
    MergeDisclosure {
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
        ciphertext: [14; 32],
        fields: vec![[15; 32]; merge_disclosure_field_count(8)],
    }
}

#[test]
fn the_view_rebuilds_the_exact_spp_body_from_the_compressed_point() {
    let request = request();
    let bytes = request.serialize().unwrap();
    let spp_body = request.merge.serialize().unwrap();
    let view = CustomRingMergeIxDataRef::from_bytes(&bytes).unwrap();
    assert_eq!(view.own_revision, Revision::from(3));
    assert_eq!(view.output_ring_data_hash, &[8; 32]);
    assert_eq!(view.spp_merge_body().unwrap(), spp_body);
    assert_eq!(
        bytes.len() + 64,
        8 + 32 + spp_body.len() + disclosure_len(&request)
    );
    let (view, owned) = (&view.disclosure, &request.disclosure);
    assert_eq!(view.proof, &owned.proof);
    assert_eq!(view.eph_pk, &owned.eph_pk);
    assert_eq!(view.ciphertext, &owned.ciphertext);
    assert_eq!(view.fields, owned.fields);
}

/// The proof, the envelope keys and the counted fields ahead of the SPP body.
fn disclosure_len(request: &CustomRingMergeIxData) -> usize {
    CustomRingProof::SIZE + 33 + 32 + 1 + 32 * request.disclosure.fields.len()
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
    let mut bytes = request().serialize().unwrap();
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
    let bytes = request().serialize().unwrap();
    let truncated = &bytes[..compressed_b(&bytes).end - 1];
    for refused in [truncated, &bytes[..47]] {
        assert_eq!(
            CustomRingMergeIxDataRef::from_bytes(refused).err(),
            Some(CustomRingError::InvalidInstructionData)
        );
    }
}
