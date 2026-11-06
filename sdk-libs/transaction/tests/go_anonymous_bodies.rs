//! Reads `test-vectors/audit/anonymous_bodies.json`, the ciphertexts of a witness the anonymous key solves.

use custom_ring_interface::{
    stream::SlotSecret, BundleLayout, ChangeCell, RecipientBody, SenderBundle, RECIPIENT_BODY_LEN,
};
use serde::Deserialize;
use spr_keypair::{ViewingKey, X25519Pubkey};
use zolana_ring_transaction::{
    open_recipient_body, open_sender_bundle, seal_recipient_body, seal_sender_bundle,
    AnonymousPlan, AnonymousSlot, RingDelivery, RingOutputRail,
};

#[derive(Deserialize)]
struct Vector {
    output_count: usize,
    output_seed: String,
    change_amount: u64,
    change_mint: String,
    recipient_keys: Vec<String>,
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
    let body = RecipientBody {
        blinding: array(&vector.body_blinding),
        amount: vector.body_amount,
        mint: array(&vector.body_mint),
        ..RecipientBody::default()
    };
    let secret = SlotSecret::new(array(&vector.body_slot_secret)).unwrap();
    let sealed = seal_recipient_body(&body, &secret).unwrap();
    assert_eq!(hex::encode(sealed), vector.body);
    let ciphertext: [u8; RECIPIENT_BODY_LEN] = array(&vector.body);
    assert_eq!(open_recipient_body(&ciphertext, &secret).unwrap(), body);

    let bundle = SenderBundle {
        output_seed: array(&vector.output_seed),
        change: vec![ChangeCell {
            mint: array(&vector.change_mint),
            amount: vector.change_amount,
        }],
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
            change: 1,
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
    let rail = RingOutputRail::sealed(
        tx_key,
        array(&vector.salt),
        RingDelivery::Anonymous(Box::new(AnonymousPlan::new())),
    );
    let first_nullifier = array(&vector.first_nullifier);
    let tag_of =
        |slot: AnonymousSlot, index| rail.anonymous_tag(&slot, &first_nullifier, index).unwrap();
    // Slot 0 is the frame's one bodiless slot, the keys name the slots past it.
    let recipient = X25519Pubkey::from_u(array(
        &vector.recipient_keys[usize::try_from(vector.body_index).unwrap() - 1],
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
