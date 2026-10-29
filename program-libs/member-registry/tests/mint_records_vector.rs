//! Shared nonzero mint settings and asset limits, including full u64 values and records beyond eight.
use custom_ring_interface::QueueEntry;
use spr_hasher::primitives::right_align;
use zolana_ring_member_registry::{MemberRegistryTree, RecordTree};
use zolana_ring_policy::{AssetLimits, MintPolicy};

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/registry/mint-records.json"
);

fn vector() -> serde_json::Value {
    let mut tree = MemberRegistryTree::new().unwrap();
    let mut rows = Vec::new();
    for mint in 1..=12u64 {
        let amount = if mint == 12 { u64::MAX } else { mint * 100 };
        let policy = MintPolicy {
            threshold: amount,
            cap: amount,
            cosign_above: amount,
            withdrawal_threshold: amount,
            limits: AssetLimits {
                sender_cap: amount - 1,
                sender_window_slots: amount - 2,
                volume_cap: amount - 3,
                volume_window_slots: amount - 4,
                deposit_cap: amount - 5,
                deposit_window_slots: amount - 6,
                withdrawal_cap: amount - 7,
                withdrawal_window_slots: amount - 8,
            },
        };
        assert_eq!(MintPolicy::from_bytes(policy.bytes()), policy);
        let member = right_align(&mint.to_be_bytes());
        let entry = QueueEntry {
            member,
            mask: 0,
            value: 0,
            escrow_key: [0; 32],
            mint_policy: Some(policy),
        };
        tree.apply([0; 32], &[entry]).unwrap();
        rows.push(serde_json::json!({"member": hex::encode(member), "amount": amount.to_string(), "field": hex::encode(policy.field()), "wire": hex::encode(policy.bytes()), "limits": policy.limits.fields().map(hex::encode), "entry_hash": hex::encode(entry.hash().unwrap())}));
    }
    serde_json::json!({"rows": rows, "root": hex::encode(tree.root().unwrap())})
}

#[test]
fn twelve_mint_records_match_the_shared_vector() {
    let expected: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(VECTOR).unwrap()).unwrap();
    assert_eq!(vector(), expected);
}

#[test]
#[ignore = "regenerates test-vectors/registry/mint-records.json"]
fn write_mint_records_vector() {
    std::fs::write(
        VECTOR,
        serde_json::to_string_pretty(&vector()).unwrap() + "\n",
    )
    .unwrap();
}
