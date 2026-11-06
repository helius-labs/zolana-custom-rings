//! Reads `test-vectors/audit/anonymous_bodies.json`, the ciphertexts of a witness the anonymous key solves.

use custom_ring_interface::{
    stream::SlotSecret, BundleLayout, OutputRecord, RecordKind, SenderBundle, OUTPUT_RECORD_LEN,
};
use serde::Deserialize;
use spr_keypair::{ViewingKey, X25519Pubkey};
use zolana_ring_transaction::{
    open_recipient_body, open_sender_bundle, seal_recipient_body, seal_sender_bundle,
    AnonymousPlan, AnonymousSlot, PayloadRead, RingDelivery, RingOutputRail,
};

#[derive(Deserialize)]
struct Vector {
    output_count: usize,
    output_seed: String,
    recipient_keys: Vec<String>,
    body_owner_key: String,
    body_nullifier_pk: String,
    body_blinding: String,
    body_amount: u64,
    body_mint: String,
    body_slot_secret: String,
    body: String,
    bundle_slot_secret: String,
    bundle: String,
    tx_viewing_sk: String,
    salt: String,
    first_nullifier: String,
    sender_viewing_key: String,
    body_index: u32,
    body_tag: String,
    bundle_tag: String,
    dummy_tag: String,
    dummy_tag_preimage: String,
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).unwrap().try_into().unwrap()
}

#[test]
fn sealers_and_readers_agree_with_the_proven_ciphertexts() {
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../test-vectors/audit/anonymous_bodies.json"
    ))
    .unwrap();
    let record = OutputRecord {
        kind: RecordKind::Ring,
        amount: vector.body_amount,
        owner_key: array(&vector.body_owner_key),
        mint: array(&vector.body_mint),
        nullifier_pk: array(&vector.body_nullifier_pk),
        blinding: array(&vector.body_blinding),
    };
    let secret = SlotSecret::new(array(&vector.body_slot_secret)).unwrap();
    let sealed = seal_recipient_body(&record, None, &secret).unwrap();
    assert_eq!(hex::encode(sealed), vector.body);
    let ciphertext: [u8; OUTPUT_RECORD_LEN] = array(&vector.body);
    let opened = open_recipient_body(&ciphertext, &secret).unwrap();
    assert_eq!(
        (opened.record, opened.payload),
        (record, PayloadRead::Absent)
    );

    let bundle = SenderBundle {
        output_seed: array(&vector.output_seed),
        recipient_keys: vector
            .recipient_keys
            .iter()
            .map(|key| match key.is_empty() {
                true => [0; 32],
                false => array(key),
            })
            .collect(),
    };
    let secret = SlotSecret::new(array(&vector.bundle_slot_secret)).unwrap();
    assert_eq!(
        hex::encode(seal_sender_bundle(&bundle, &secret).unwrap()),
        vector.bundle
    );
    let opened = open_sender_bundle(
        &hex::decode(&vector.bundle).unwrap(),
        &secret,
        BundleLayout {
            outputs: vector.output_count,
        },
    )
    .unwrap();
    assert_eq!(opened, bundle);
}

#[test]
fn the_rail_publishes_the_vector_tags() {
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../test-vectors/audit/anonymous_bodies.json"
    ))
    .unwrap();
    let tx_key = ViewingKey::from_canonical_bytes(&array(&vector.tx_viewing_sk)).unwrap();
    let auditor = ViewingKey::new().pubkey();
    let rail = RingOutputRail::sealed(
        tx_key,
        array(&vector.salt),
        auditor,
        RingDelivery::Anonymous(Box::new(AnonymousPlan::new())),
    );
    let first_nullifier = array(&vector.first_nullifier);
    let tag_of =
        |slot: AnonymousSlot, index| rail.anonymous_tag(&slot, &first_nullifier, index).unwrap();
    // Key `i` names slot `i`.
    let recipient = X25519Pubkey::from_u(array(
        &vector.recipient_keys[usize::try_from(vector.body_index).unwrap()],
    ))
    .unwrap();
    assert_eq!(
        tag_of(AnonymousSlot::Payment { recipient }, vector.body_index),
        Some(custom_ring_interface::stream::slot_tag(array(
            &vector.body_tag
        )))
    );
    assert_eq!(tag_of(AnonymousSlot::Change, 0), Some([0; 32]));
    assert_eq!(
        tag_of(
            AnonymousSlot::Dummy {
                preimage: array(&vector.dummy_tag_preimage)
            },
            2
        ),
        Some(custom_ring_interface::stream::slot_tag(array(
            &vector.dummy_tag
        )))
    );
    let sender = X25519Pubkey::from_u(array(&vector.sender_viewing_key)).unwrap();
    assert_eq!(
        rail.sender_bundle_tag(
            &sender,
            &first_nullifier,
            u32::try_from(vector.output_count).unwrap()
        )
        .unwrap(),
        array::<32>(&vector.bundle_tag)
    );
}
