use custom_ring_interface::domain;
use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_keypair::{NullifierKey, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_ring_keys::{
    ListSaltHolder, MergeSeedHolder, MergeSeedRequest, RingAddress, RingKeyError, RotatingRingKeys,
    LIST_SALT_LABEL,
};

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/registry/list_salt.json"
);
const RING: Address = Address::new_from_array([4; 32]);
const OTHER_RING: Address = Address::new_from_array([5; 32]);

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ListVector {
    description: String,
    signing_secret: String,
    ring_program_id: String,
    list_salt: String,
    list_tag: String,
}

fn wallet(byte: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[byte; 32])).unwrap()
}

fn compute_vector() -> ListVector {
    let list_salt = wallet(7).list_salt(&RING).unwrap();
    ListVector {
        description: "list_salt is the view root's merge seed under ring_program_id and the \
                      non-field label CRING/list_salt, list_tag = Poseidon(CRPT, list_salt). \
                      Produced by sdk-libs/keys/tests/list_salt.rs."
            .to_string(),
        signing_secret: hex::encode([7; 32]),
        ring_program_id: hex::encode(RING.as_array()),
        list_salt: hex::encode(list_salt),
        list_tag: hex::encode(domain::list_tag(&list_salt).unwrap()),
    }
}

#[test]
fn the_wallet_gives_the_pinned_salt_and_tag() {
    let committed: ListVector =
        serde_json::from_str(&std::fs::read_to_string(VECTOR).unwrap()).unwrap();
    assert_eq!(committed, compute_vector());
}

#[test]
#[ignore = "rewrites test-vectors/registry/list_salt.json"]
fn write_list_salt_vector() {
    let json = serde_json::to_string_pretty(&compute_vector()).unwrap();
    std::fs::write(VECTOR, json + "\n").unwrap();
}

#[test]
fn a_salt_is_nonzero_and_canonical() {
    let salt = wallet(7).list_salt(&RING).unwrap();
    assert_eq!(salt[0], 0);
    assert_ne!(salt, [0; 32]);
    assert!(is_canonical_bn254_scalar_be(&salt));
}

#[test]
fn the_nullifier_secret_a_ring_auditor_holds_derives_no_salt() {
    let owner = wallet(7);
    let mut same_secret = wallet(8);
    same_secret.nullifier_key = owner.nullifier_key.clone();
    assert_ne!(
        owner.list_salt(&OTHER_RING).unwrap(),
        same_secret.list_salt(&OTHER_RING).unwrap()
    );
    let mut other_secret = wallet(7);
    other_secret.nullifier_key = NullifierKey::from_secret([3; 31]);
    assert_eq!(
        owner.list_salt(&RING).unwrap(),
        other_secret.list_salt(&RING).unwrap()
    );
}

#[test]
fn a_salt_opens_one_ring() {
    let owner = wallet(7);
    assert_ne!(
        owner.list_salt(&RING).unwrap(),
        owner.list_salt(&OTHER_RING).unwrap()
    );
}

#[test]
fn a_rotation_keeps_the_salt_a_final_tag_holds() {
    let owner = wallet(7);
    let rotated = RotatingRingKeys::new(&owner)
        .unwrap()
        .rotate(ViewingKey::new())
        .unwrap();
    assert_eq!(
        rotated.list_salt(&RING).unwrap(),
        owner.list_salt(&RING).unwrap()
    );
}

#[test]
fn no_merge_seed_request_reaches_the_salt() {
    let owner = wallet(7);
    let refused = owner.merge_seeds(&[MergeSeedRequest {
        viewing_pubkey: owner.viewing_key.pubkey(),
        ring_program_id: RING,
        first_nullifier: LIST_SALT_LABEL,
    }]);
    assert_eq!(refused.err(), Some(RingKeyError::InvalidMergeSeed));
}

#[test]
fn an_enrolled_address_carries_the_wallet_salt_and_a_zero_secret_has_none() {
    let mut owner = wallet(7);
    let address = RingAddress::enrolled(&owner, RING).unwrap();
    assert_eq!(address.recipient, owner.shielded_address().unwrap());
    assert_eq!(address.list_salt, owner.list_salt(&RING).unwrap());
    owner.nullifier_key = NullifierKey::from_secret([0; 31]);
    assert_eq!(
        RingAddress::enrolled(&owner, RING).err(),
        Some(RingKeyError::InvalidRingAddressListSalt)
    );
}
