use custom_ring_interface::{AuditKey, AuditStreamLayout, AuditorMessage};
use serde_json::Value;
use solana_address::Address;
use solana_signature::Signature;
use spr_event::MessageData;
use spr_hasher::primitives::hash_bytes;
use spr_keypair::{ViewingKey, X25519Keypair};
use spr_transaction::{OutputContext, OutputSlot, ShieldedTransaction};
use zolana_ring_client::{OutputOpening, TransactionAudit};

const STREAM: &str = include_str!("../../../test-vectors/audit/audit-stream.json");
const RING: Address = Address::new_from_array([0x90; 32]);
/// The auditor of the Go fixtures.
const AUDITOR_SK: &str = "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c";

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn array<const N: usize>(value: &Value) -> [u8; N] {
    bytes(value).try_into().unwrap()
}

fn list(value: &Value) -> Vec<Vec<u8>> {
    value
        .as_array()
        .map_or_else(Vec::new, |items| items.iter().map(bytes).collect())
}

fn auditor() -> X25519Keypair {
    X25519Keypair::from_bytes(&hex::decode(AUDITOR_SK).unwrap().try_into().unwrap())
}

#[test]
fn every_stream_rebuilds_its_published_hashes_with_no_mint_registry() {
    let vector: Value = serde_json::from_str(STREAM).unwrap();
    assert_eq!(
        hash_bytes(RING.as_array()).unwrap(),
        array::<32>(&vector["ring_id"])
    );
    let tx_key = ViewingKey::from_canonical_bytes(&array(&vector["tx_viewing_sk"])).unwrap();
    let eph = X25519Keypair::from_bytes(&array(&vector["tx_viewing_sk"]));
    let first_nullifier = array::<32>(&vector["first_nullifier"]);
    let tree_id: u16 = vector["output_tree_id"].as_u64().unwrap() as u16;
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let bits = case["layout"].as_u64().unwrap();
        let layout = AuditStreamLayout {
            key: AuditKey {
                format: if bits & 4 != 0 {
                    custom_ring_interface::DisclosureFormat::SingleAssetPayout
                } else {
                    custom_ring_interface::DisclosureFormat::Standard
                },
                class: case["input_class"].as_u64().unwrap() as usize,
                entry: bits & 2 != 0,
            },
            inputs: case["input_count"].as_u64().unwrap() as usize,
            outputs: case["output_count"].as_u64().unwrap() as usize,
            capacity: case["outputs"].as_u64().unwrap() as usize,
            has_data: bits & 1 != 0,
        };
        let hashes = list(&case["output_hashes"]);
        let output_slots: Vec<OutputSlot> = hashes
            .iter()
            .enumerate()
            .map(|(leaf, hash)| OutputSlot {
                view_tag: [0x71 + leaf as u8; 32],
                output_context: OutputContext {
                    hash: hash.clone().try_into().unwrap(),
                    tree_id,
                    leaf_index: leaf as u64,
                },
                payload: Vec::new(),
            })
            .collect();
        let (records, tails) = (
            list(&case["record_ciphertexts"]),
            list(&case["tail_ciphertexts"]),
        );
        let envelope = bytes(&case["envelope_ciphertext"]);
        let parts = core::iter::once(envelope.as_slice())
            .chain(records.iter().map(Vec::as_slice))
            .chain(tails.iter().map(Vec::as_slice));
        let tx = ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::default(),
            event_index: Some(0),
            tx_viewing_pk: Some(tx_key.pubkey()),
            salt: Some(array(&vector["salt"])),
            output_slots,
            messages: vec![MessageData {
                view_tag: auditor().pubkey().u(),
                data: AuditorMessage::data(&eph.pubkey().u(), parts),
            }],
            nullifiers: (0..layout.inputs)
                .map(|input| match input {
                    0 => first_nullifier,
                    later => [later as u8; 32],
                })
                .collect(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        };
        let audited = TransactionAudit::new(&tx, layout).run(&auditor()).unwrap();
        assert!(
            audited.payload_errors.is_empty(),
            "{name}: {:?}",
            audited.payload_errors
        );
        assert_eq!(audited.outputs.len(), hashes.len(), "{name}");
        let plaintext = bytes(&case["envelope_plaintext"]);
        assert_eq!(audited.real_inputs, plaintext[32], "{name}");
        let blindings = list(&case["blindings"]);
        let plain_records = list(&case["records"]);
        for (index, output) in audited.outputs.iter().enumerate() {
            match plain_records[index][0] {
                0 => assert_eq!(output.opening, OutputOpening::Dummy, "{name} slot {index}"),
                1 => assert!(matches!(output.opening, OutputOpening::Ring { .. })),
                _ => assert!(matches!(output.opening, OutputOpening::Exit(_))),
            }
            if let Some(utxo) = output.opening.utxo() {
                assert_eq!(utxo.blinding.to_vec(), blindings[index]);
                assert!(utxo.mint.is_some(), "a record names its mint");
            }
        }
    }
}
