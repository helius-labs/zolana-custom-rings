//! Pins `test-vectors/registry/empty_root.json` for Go, TS and the indexer.

use custom_ring_interface::{tracking::TRACKING_EMPTY_ROOT, MEMBER_REGISTRY_EMPTY_ROOT};
use serde_json::{json, Value};
use zolana_ring_member_registry::{
    quad_node, MemberRecord, MemberRegistryTree, RecordTree, TrackingRecord, TrackingTree,
    ZERO_SUBTREES,
};

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/registry/empty_root.json"
);

fn vector() -> Value {
    let policy = MemberRecord::SENTINEL;
    let tracking = TrackingRecord::SENTINEL;
    json!({
        "description": "The sentinel leaf and the root of the tree holding only it, for the policy registry and the tracking registry. Produced by program-libs/member-registry/tests/empty_root_vector.rs.",
        "sentinel": {
            "member": hex::encode(policy.member),
            "next": hex::encode(policy.next),
            "lists": policy.lists.to_string(),
            "mint_policy": hex::encode(policy.mint_policy.field()),
            "withdrawal_threshold": policy.mint_policy.withdrawal_threshold.to_string(),
            "limits": policy.mint_policy.limits.fields().map(hex::encode),
            "leaf_hash": hex::encode(policy.hash().unwrap()),
        },
        "empty_root": hex::encode(MEMBER_REGISTRY_EMPTY_ROOT),
        "tracking_sentinel": {
            "member": hex::encode(tracking.member),
            "next": hex::encode(tracking.next),
            "leaf_hash": hex::encode(tracking.hash().unwrap()),
        },
        "tracking_empty_root": hex::encode(TRACKING_EMPTY_ROOT),
        "zero_subtrees": ZERO_SUBTREES.iter().map(hex::encode).collect::<Vec<_>>(),
    })
}

#[test]
fn zero_subtrees_chain_and_the_trees_start_at_their_roots() {
    for level in 0..ZERO_SUBTREES.len() - 1 {
        let zero = ZERO_SUBTREES[level];
        assert_eq!(quad_node(&[zero; 4]).unwrap(), ZERO_SUBTREES[level + 1]);
    }
    assert_eq!(
        MemberRegistryTree::new().unwrap().root().unwrap(),
        MEMBER_REGISTRY_EMPTY_ROOT
    );
    assert_eq!(
        TrackingTree::new().unwrap().root().unwrap(),
        TRACKING_EMPTY_ROOT
    );
}

#[test]
fn the_empty_roots_are_the_shared_vector() {
    let committed: Value = serde_json::from_str(&std::fs::read_to_string(VECTOR).unwrap()).unwrap();
    assert_eq!(committed, vector());
}

#[test]
#[ignore = "rewrites test-vectors/registry/empty_root.json"]
fn write_empty_root_vector() {
    std::fs::write(
        VECTOR,
        serde_json::to_string_pretty(&vector()).unwrap() + "\n",
    )
    .unwrap();
}
