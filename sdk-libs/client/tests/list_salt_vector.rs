//! The TS codec test checks the same vector.

use serde_json::{json, Value};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_ring_client::rpc::{Attestation, GetListSaltRequest, ListSaltAttestation, ReadTarget};

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/rpc/list_salt_request.json"
);

fn compute_vector() -> Value {
    let writer = Keypair::new_from_array([8; 32]);
    let attestation = ListSaltAttestation {
        target: ReadTarget {
            cluster: [1; 32],
            service: Address::new_from_array([2; 32]),
            ring: Address::new_from_array([7; 32]),
        },
        writer: writer.pubkey(),
        owner: Address::new_from_array([3; 32]),
    };
    let message = attestation.message(1_700_000_000, &[4; 32]);
    let request = GetListSaltRequest {
        ring: attestation.target.ring.into(),
        writer: attestation.writer.into(),
        owner: attestation.owner.into(),
        timestamp: 1_700_000_000,
        nonce: vec![4; 32].into(),
        signature: writer.sign_message(&message).into(),
    };
    json!({
        "description": "One getListSalt request a list writer signs. The target is the ring 0x07 repeated behind the service 0x02 on the cluster 0x01, the writer the Ed25519 keypair of seed 0x08 repeated, the owner 0x03 repeated, timestamp 1700000000 and nonce 0x04 repeated. message is the attestation the writer signs, wire the exact JSON text. Produced by sdk-libs/client/tests/list_salt_vector.rs.",
        "message": String::from_utf8(message).unwrap(),
        "wire": serde_json::to_string(&request).unwrap(),
    })
}

#[test]
fn the_request_is_the_shared_vector() {
    let committed: Value = serde_json::from_str(&std::fs::read_to_string(VECTOR).unwrap()).unwrap();
    assert_eq!(committed, compute_vector());
}

#[test]
#[ignore = "rewrites test-vectors/rpc/list_salt_request.json"]
fn write_list_salt_vector() {
    let json = serde_json::to_string_pretty(&compute_vector()).unwrap() + "\n";
    std::fs::write(VECTOR, json).unwrap();
}
