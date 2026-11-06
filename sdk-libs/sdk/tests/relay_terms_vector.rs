//! The TS terms test checks the same vector.

use custom_ring_sdk::{RelayTransferTerms, SlotOpening, TokenAccountCreate};
use serde_json::{json, Value};
use solana_address::Address;
use spr_indexer_api::{Hash, SerializablePubkey};

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/rpc/relay_transfer_terms.json"
);

fn address(byte: u8) -> SerializablePubkey {
    Address::new_from_array([byte; 32]).into()
}

fn compute_vector() -> Value {
    let terms = RelayTransferTerms {
        ring: address(1),
        fee_payer: address(2),
        signer: address(3),
        slots: vec![SlotOpening {
            slot: 7,
            owner: address(3),
            nullifier_pk: Hash([4; 32]),
            mint: address(5),
            amount: u64::MAX,
            blinding: Hash([6; 32]),
            tree_id: 8,
            data_hash: Hash([9; 32]),
            ring_data_hash: Hash([10; 32]),
        }],
        nullifiers: vec![Hash([11; 32])],
        setup: vec![TokenAccountCreate {
            owner: address(12),
            mint: address(13),
            token_program: address(14),
        }],
    };
    json!({
        "description": "One public owner's RelayTransferTerms, each field repeating one byte value. The amount is u64 max and stays exact. wire is the exact JSON text Rust and TypeScript write and read.",
        "wire": serde_json::to_string(&terms).unwrap(),
    })
}

#[test]
fn the_terms_are_the_shared_vector() {
    let committed: Value = serde_json::from_str(&std::fs::read_to_string(VECTOR).unwrap()).unwrap();
    assert_eq!(committed, compute_vector());
}

#[test]
#[ignore = "rewrites test-vectors/rpc/relay_transfer_terms.json"]
fn write_relay_terms_vector() {
    let json = serde_json::to_string_pretty(&compute_vector()).unwrap() + "\n";
    std::fs::write(VECTOR, json).unwrap();
}
