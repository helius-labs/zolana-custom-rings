//! Pins `test-vectors/registry/tracking-records.json` for the Go circuits.

use custom_ring_interface::tracking::{TrackingEntry, TRACKING_EMPTY_ROOT};
use serde::{Deserialize, Serialize};
use spr_hasher::primitives::right_align;
use zolana_ring_member_registry::{
    AppliedTree, RecordTree, TrackingPath, TrackingRecord, TrackingTree, TrackingWriteProofInput,
};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/registry/tracking-records.json"
);

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct TrackingVectors {
    description: String,
    empty_root: String,
    applications: Vec<Application>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Application {
    name: String,
    old_root: String,
    new_root: String,
    old_next_index: u64,
    new_next_index: u64,
    chain_start: String,
    chain_end: String,
    count: u64,
    statement_hash: String,
    writes: Vec<Write>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Entry {
    member: String,
    nullifier_pk: String,
    ct_hash: String,
    list_tag: String,
    entry_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Record {
    member: String,
    next: String,
    nullifier_pk: String,
    ct_hash: String,
    list_tag: String,
    leaf_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Path {
    index: u64,
    siblings: Vec<Vec<String>>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Write {
    entry: Entry,
    slot: Path,
    low: Record,
    low_path: Path,
}

fn field(byte: u8) -> [u8; 32] {
    right_align(&[byte])
}

/// Every field differs, a reordered hash input cannot match.
fn entry(owner: u8) -> TrackingEntry {
    TrackingEntry {
        member: field(owner),
        nullifier_pk: field(owner ^ 0x40),
        ct_hash: field(owner ^ 0x50),
        list_tag: field(owner ^ 0x70),
    }
}

fn record_vector(record: &TrackingRecord) -> Record {
    Record {
        member: hex::encode(record.member),
        next: hex::encode(record.next),
        nullifier_pk: hex::encode(record.nullifier_pk),
        ct_hash: hex::encode(record.ct_hash),
        list_tag: hex::encode(record.list_tag),
        leaf_hash: hex::encode(record.hash().unwrap()),
    }
}

fn path_vector(path: &TrackingPath) -> Path {
    Path {
        index: path.index,
        siblings: path
            .siblings
            .iter()
            .map(|level| level.iter().map(hex::encode).collect())
            .collect(),
    }
}

fn write_vector(write: &TrackingWriteProofInput) -> Write {
    Write {
        entry: Entry {
            member: hex::encode(write.entry.member),
            nullifier_pk: hex::encode(write.entry.nullifier_pk),
            ct_hash: hex::encode(write.entry.ct_hash),
            list_tag: hex::encode(write.entry.list_tag),
            entry_hash: hex::encode(write.entry.hash().unwrap()),
        },
        slot: path_vector(&write.slot),
        low: record_vector(&write.low),
        low_path: path_vector(&write.low_path),
    }
}

fn apply(
    tree: &mut TrackingTree,
    name: &str,
    chain_start: [u8; 32],
    entries: &[TrackingEntry],
) -> Application {
    let AppliedTree {
        tree: next,
        proof: inputs,
    } = tree.clone().apply(chain_start, entries).unwrap();
    *tree = next;
    let statement = inputs.statement();
    Application {
        name: name.to_string(),
        old_root: hex::encode(inputs.old_root),
        new_root: hex::encode(inputs.new_root),
        old_next_index: inputs.old_next_index,
        new_next_index: inputs.new_next_index,
        chain_start: hex::encode(inputs.chain_start),
        chain_end: hex::encode(inputs.chain_end),
        count: statement.count,
        statement_hash: hex::encode(statement.hash().unwrap()),
        writes: inputs.writes.iter().map(write_vector).collect(),
    }
}

fn compute_vectors() -> TrackingVectors {
    let mut tree = TrackingTree::new().unwrap();
    let inserts = apply(
        &mut tree,
        "inserts_in_named_order",
        [0x11; 32],
        &[entry(0x20), entry(0x10), entry(0x30)],
    );
    let one = apply(&mut tree, "one_insert", [0x12; 32], &[entry(0x18)]);
    let bounds = apply(
        &mut tree,
        "inserts_at_both_ends",
        [0x13; 32],
        &[entry(0x48), entry(0x08)],
    );
    TrackingVectors {
        description: "Tracking tree applications with every proof input. Produced by program-libs/member-registry/tests/tracking_records_vector.rs.".to_string(),
        empty_root: hex::encode(TRACKING_EMPTY_ROOT),
        applications: vec![inserts, one, bounds],
    }
}

#[test]
fn tracking_records_vector() {
    let committed: TrackingVectors =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, compute_vectors());
}

#[test]
#[ignore = "rewrites test-vectors/registry/tracking-records.json"]
fn write_tracking_records_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}
