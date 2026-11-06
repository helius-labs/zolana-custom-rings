//! The key holder reads the tags the Go witnesses prove.

use custom_ring_interface::stream::slot_tag;
use serde::Deserialize;
use spr_keypair::{viewing_key::ViewTag, ShieldedKeypair, SigningKey, ViewingKey, X25519Pubkey};
use zolana_ring_keys::{RingKeys, RingTagFrame, RingTagKind, RingTagProbe, RotatingRingKeys};

/// The payment's key leads the bundle's keys, slot 0 is the bodiless change.
const RECIPIENT_KEY: usize = 0;

#[derive(Deserialize)]
struct Bodies {
    tx_viewing_sk: String,
    recipient_viewing_sk: String,
    sender_viewing_sk: String,
    sender_viewing_key: String,
    recipient_keys: Vec<String>,
    salt: String,
    first_nullifier: String,
    output_count: u32,
    body_index: u32,
    body_tag: String,
    body_slot_secret: String,
    bundle_tag: String,
    bundle_slot_secret: String,
    dummy_tag: String,
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn bodies() -> Bodies {
    serde_json::from_str(include_str!(
        "../../../test-vectors/audit/anonymous_bodies.json"
    ))
    .unwrap()
}

/// The production holder, the sender's key current and the recipient's retired.
fn holder(vector: &Bodies) -> (RotatingRingKeys, X25519Pubkey, X25519Pubkey) {
    let sender = ViewingKey::from_canonical_bytes(&array(&vector.sender_viewing_sk)).unwrap();
    let recipient = ViewingKey::from_canonical_bytes(&array(&vector.recipient_viewing_sk)).unwrap();
    let sender_key = sender.pubkey();
    let recipient_key = recipient.pubkey();
    assert_eq!(sender_key.u(), array::<32>(&vector.sender_viewing_key));
    assert_eq!(
        recipient_key.u(),
        array::<32>(&vector.recipient_keys[RECIPIENT_KEY])
    );
    let mut identity =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7; 32])).unwrap();
    identity.viewing_key = sender;
    let keys = RotatingRingKeys::new(&identity)
        .unwrap()
        .with_retired(vec![recipient])
        .unwrap();
    (keys, sender_key, recipient_key)
}

fn probe(kind: RingTagKind, output_index: u32, tag: ViewTag) -> RingTagProbe {
    RingTagProbe {
        kind,
        output_index,
        tag,
    }
}

#[test]
fn the_holder_reads_the_body_and_bundle_tags_and_no_dummy_or_change_tag() {
    let vector = bodies();
    let (keys, sender, recipient) = holder(&vector);
    let tx_viewing_pk = ViewingKey::from_canonical_bytes(&array(&vector.tx_viewing_sk))
        .unwrap()
        .pubkey();
    let frame = |viewing_pubkey, probes| RingTagFrame {
        viewing_pubkey,
        tx_viewing_pk,
        salt: array(&vector.salt),
        first_nullifier: array(&vector.first_nullifier),
        probes,
    };
    let recipient_probes = vec![
        probe(
            RingTagKind::Recipient,
            vector.body_index,
            slot_tag(array(&vector.body_tag)),
        ),
        probe(
            RingTagKind::Recipient,
            vector.body_index,
            slot_tag(array(&vector.dummy_tag)),
        ),
        probe(RingTagKind::Recipient, 0, [0; 32]),
    ];
    let sender_probes = vec![
        probe(
            RingTagKind::SenderBundle,
            vector.output_count,
            array(&vector.bundle_tag),
        ),
        probe(RingTagKind::Recipient, 0, [0; 32]),
        probe(
            RingTagKind::Recipient,
            vector.output_count,
            array(&vector.bundle_tag),
        ),
    ];
    let answers = keys
        .ring_tag_matches(&[
            frame(recipient, recipient_probes),
            frame(sender, sender_probes),
        ])
        .unwrap();
    let hits =
        |answers: &[Option<custom_ring_interface::stream::SlotSecret>]| -> Vec<Option<String>> {
            answers
                .iter()
                .map(|answer| answer.as_ref().map(|secret| hex::encode(secret.as_bytes())))
                .collect()
        };
    assert_eq!(
        hits(&answers[0]),
        [Some(vector.body_slot_secret.clone()), None, None],
        "a dummy and a zero change tag open nothing"
    );
    assert_eq!(
        hits(&answers[1]),
        [Some(vector.bundle_slot_secret.clone()), None, None],
        "the bundle answers only under its own domain"
    );
}
