//! The TS codec test checks the same vector.

use serde_json::{json, Value};
use solana_address::Address;
use solana_signature::Signature;
use zolana_ring_client::rpc::{
    PrepareRelayRequest, ProofInputBytes, RelayEnrollInputs, RelayIntent, RelayQuote,
};

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/rpc/relay_enroll_inputs.json"
);

fn request(intent: RelayIntent) -> String {
    serde_json::to_string(&PrepareRelayRequest {
        ring: Address::new_from_array([1; 32]).into(),
        quote: RelayQuote {
            fee_payer: Address::new_from_array([2; 32]).into(),
            valid_until_slot: 4242,
        },
        intent,
        co_signers: Vec::new(),
    })
    .unwrap()
}

fn proof_inputs() -> ProofInputBytes {
    ProofInputBytes::new(zeroize::Zeroizing::new(vec![3, 4, 5]))
}

fn compute_vector() -> Value {
    let inputs = RelayEnrollInputs {
        ring_program_id: Address::new_from_array([1; 32]),
        owner: Address::new_from_array([2; 32]),
        tracking_registry: Address::new_from_array([3; 32]),
        instruction_data: vec![6, 7, 8],
    };
    json!({
        "description": "One RelayEnrollInputs with its ring program id of bytes 0x01, owner of 0x02, tracking registry of 0x03 and instruction data 06 07 08, encoded in wincode, with the digest its owner signs. enroll_wire, delegate_wire, deposit_wire and merge_wire are prepareRelay requests carrying proofInputs 03 04 05 and a signature of 64 bytes of 0x07, deposit_request_digest and merge_request_digest are what the depositor and the owner sign over those proofInputs. Produced by sdk-libs/client/tests/relay_enroll_vector.rs.",
        "ring_program_id": hex::encode([1; 32]),
        "owner": hex::encode([2; 32]),
        "tracking_registry": hex::encode([3; 32]),
        "instruction_data": hex::encode(&inputs.instruction_data),
        "encoded": hex::encode(inputs.encode().unwrap()),
        "request_digest": hex::encode(inputs.request_digest()),
        "enroll_wire": request(RelayIntent::Enroll {
            proof_inputs: proof_inputs(),
            owner_signature: Signature::from([7; 64]).into(),
        }),
        "delegate_wire": request(RelayIntent::Delegate {
            proof_inputs: proof_inputs(),
            delegate_signature: Signature::from([7; 64]).into(),
            token_account_setup: Vec::new(),
        }),
        "deposit_wire": request(RelayIntent::Deposit {
            proof_inputs: proof_inputs(),
            depositor_signature: Signature::from([7; 64]).into(),
        }),
        "merge_wire": request(RelayIntent::Merge {
            proof_inputs: proof_inputs(),
            owner_signature: Signature::from([7; 64]).into(),
        }),
        "deposit_request_digest": hex::encode(proof_inputs().deposit_request_digest()),
        "merge_request_digest": hex::encode(proof_inputs().merge_request_digest()),
    })
}

#[test]
fn the_wire_is_the_shared_vector() {
    let committed: Value = serde_json::from_str(&std::fs::read_to_string(VECTOR).unwrap()).unwrap();
    assert_eq!(committed, compute_vector());
}

#[test]
#[ignore = "rewrites test-vectors/rpc/relay_enroll_inputs.json"]
fn write_relay_enroll_vector() {
    let json = serde_json::to_string_pretty(&compute_vector()).unwrap() + "\n";
    std::fs::write(VECTOR, json).unwrap();
}
