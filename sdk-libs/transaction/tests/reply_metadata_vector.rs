//! Pins `test-vectors/wallet/reply_metadata.json`, the sealed reply and the claims a reader refuses.

use custom_ring_interface::{stream::SlotSecret, MIN_REPLY_LEN};
use serde_json::{json, Value};
use spr_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey};
use spr_transaction::{Data, DataRecord};
use zolana_ring_transaction::{open_reply, seal_reply, ReplyMetadata};

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/wallet/reply_metadata.json"
);
const SLOT_SECRET: [u8; 32] = [3; 32];

fn sender() -> ShieldedAddress {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[1; 32]))
        .expect("keypair")
        .shielded_address()
        .expect("address")
}

fn reply(memo: Option<Vec<u8>>) -> ReplyMetadata {
    let sender = sender();
    ReplyMetadata {
        viewing_key: sender.viewing_pubkey,
        owner_key: sender.signing_pubkey.as_ed25519().expect("ed25519"),
        nullifier_pk: sender.nullifier_pubkey,
        data: memo.map_or_else(Data::default, |memo| {
            Data::new(vec![DataRecord::Memo(memo)])
        }),
    }
}

/// `sealed` with the plaintext head's `viewing_u` replaced, the cipher is a plain stream.
fn with_viewing_u(sealed: &[u8], held: &[u8; 32], claimed: [u8; 32]) -> Vec<u8> {
    let mut forged = sealed.to_vec();
    for (byte, (held, claimed)) in forged.iter_mut().zip(held.iter().zip(claimed)) {
        *byte ^= held ^ claimed;
    }
    forged
}

fn built() -> Value {
    let secret = SlotSecret::new(SLOT_SECRET).expect("secret");
    let opens = |name: &str, reply: &ReplyMetadata, reply_len: usize| {
        json!({
            "name": name,
            "viewingU": hex::encode(reply.viewing_key.u()),
            "ownerKey": hex::encode(reply.owner_key),
            "nullifierPk": hex::encode(reply.nullifier_pk),
            "replyLen": reply_len,
            "ciphertext": hex::encode(seal_reply(reply, reply_len, &secret).expect("sealed")),
        })
    };
    let plain = reply(None);
    let sealed = seal_reply(&plain, MIN_REPLY_LEN, &secret).expect("sealed");
    let held = plain.viewing_key.u();
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    let mut padded = seal_reply(&plain, MIN_REPLY_LEN + 8, &secret).expect("sealed");
    *padded.last_mut().expect("byte") ^= 1;
    json!({
        "slotSecret": hex::encode(SLOT_SECRET),
        "opens": [
            opens("the shortest reply", &plain, MIN_REPLY_LEN),
            opens("zero padding past the record", &plain, MIN_REPLY_LEN + 8),
            opens("a memo", &reply(Some(vec![0xab; 12])), MIN_REPLY_LEN + 32),
        ],
        "refused": [
            {"name": "a zero viewing key", "ciphertext": hex::encode(with_viewing_u(&sealed, &held, [0; 32]))},
            {"name": "the field modulus as a viewing key", "ciphertext": hex::encode(with_viewing_u(&sealed, &held, modulus))},
            {"name": "a nonzero padding byte", "ciphertext": hex::encode(padded)},
        ],
    })
}

/// `UPDATE_RING_VECTORS=1` rewrites the file.
#[test]
fn the_reply_vector_opens_as_pinned() {
    let built = built();
    if std::env::var_os("UPDATE_RING_VECTORS").is_some() {
        let pretty = serde_json::to_string_pretty(&built).expect("json");
        std::fs::write(VECTOR, pretty + "\n").expect("vector");
    }
    let pinned: Value =
        serde_json::from_str(&std::fs::read_to_string(VECTOR).expect("vector")).expect("json");
    assert_eq!(built, pinned);
    let secret = SlotSecret::new(SLOT_SECRET).expect("secret");
    let ciphertext = |case: &Value| hex::decode(case["ciphertext"].as_str().unwrap()).unwrap();
    for case in pinned["opens"].as_array().unwrap() {
        let claim = open_reply(&ciphertext(case), &secret)
            .expect("stream")
            .expect("opens");
        assert_eq!(
            hex::encode(claim.claimed().viewing_key.u()),
            case["viewingU"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(claim.claimed().owner_key),
            case["ownerKey"].as_str().unwrap()
        );
    }
    for case in pinned["refused"].as_array().unwrap() {
        assert!(
            open_reply(&ciphertext(case), &secret)
                .expect("stream")
                .is_none(),
            "{}",
            case["name"]
        );
    }
}
