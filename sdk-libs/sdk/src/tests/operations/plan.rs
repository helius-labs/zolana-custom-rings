//! A seal carries to the key a later read selects only where both streams open alike.
//!
//! `tests/fixtures/transfer-plan-rekey.json` pins each case for the TS test.

use custom_ring_interface::{
    key_catalog::{FrameKey, RecordPools, RingCircuit, TransferSpend},
    AuditStreamLayout, RingRail,
};
use serde_json::{json, Value};

use super::*;
use crate::{RingError, TransferKey};

struct Case {
    name: &'static str,
    rail: RingRail,
    inputs: usize,
    outputs: usize,
    spends_default_ring: bool,
    has_data: bool,
    approval: bool,
}

const CASES: [Case; 5] = [
    Case {
        name: "one stream at eight outputs",
        rail: RingRail::Confidential,
        inputs: 16,
        outputs: 8,
        spends_default_ring: false,
        has_data: true,
        approval: false,
    },
    Case {
        name: "data tails at another capacity",
        rail: RingRail::Confidential,
        inputs: 24,
        outputs: 2,
        spends_default_ring: false,
        has_data: true,
        approval: false,
    },
    Case {
        name: "records alone at another capacity",
        rail: RingRail::Confidential,
        inputs: 24,
        outputs: 2,
        spends_default_ring: false,
        has_data: false,
        approval: false,
    },
    Case {
        name: "an approval opening at another capacity",
        rail: RingRail::Confidential,
        inputs: 24,
        outputs: 2,
        spends_default_ring: false,
        has_data: false,
        approval: true,
    },
    Case {
        name: "an entry envelope of one class",
        rail: RingRail::Anonymous,
        inputs: 2,
        outputs: 2,
        spends_default_ring: true,
        has_data: false,
        approval: false,
    },
];

impl Case {
    fn subjects(&self) -> TransferSpend {
        TransferSpend {
            format: custom_ring_interface::DisclosureFormat::Standard,
            rail: self.rail,
            inputs: self.inputs,
            outputs: self.outputs,
            spends_default_ring: self.spends_default_ring,
            legs: 0,
            owners: 1,
            pools: RecordPools::default(),
            wide: false,
        }
    }

    /// One tracking record past the narrow row, a salted read the wallet cannot make.
    fn read_pools(&self) -> RecordPools {
        let narrow = RingCircuit::transfer(self.subjects())
            .and_then(RingCircuit::record_pools)
            .expect("a narrow row");
        RecordPools {
            tracking: narrow.tracking + 1,
            ..RecordPools::default()
        }
    }

    /// The layout `stream_under` derives from the frame, built from the catalog row alone.
    fn plan(&self, spend: TransferSpend) -> PlannedTransfer {
        let shape = FrameKey {
            format: custom_ring_interface::DisclosureFormat::Standard,
            rail: spend.rail,
            inputs: spend.inputs,
            outputs: spend.outputs,
            spends_default_ring: spend.spends_default_ring,
            wide: spend.wide,
        }
        .shape()
        .expect("a catalog row");
        PlannedTransfer {
            key: TransferKey {
                circuit: RingCircuit::transfer(spend).expect("a key"),
                wide: spend.wide,
            },
            stream: AuditStreamLayout {
                key: shape.audit_key(),
                inputs: spend.inputs,
                outputs: spend.outputs,
                capacity: usize::from(shape.outputs),
                has_data: self.has_data,
            },
            spans_capacity: self.has_data || self.approval,
        }
    }
}

fn circuit_json(circuit: RingCircuit) -> Value {
    let RingCircuit::Transfer {
        outputs,
        inputs,
        withdrawals,
        owners,
        entry,
        wide,
        ..
    } = circuit
    else {
        panic!("a transfer key");
    };
    json!({
        "outputs": outputs,
        "inputs": inputs,
        "withdrawals": withdrawals,
        "owners": owners,
        "entry": entry,
        "wide": wide,
    })
}

#[test]
fn a_read_keeps_a_seal_of_one_stream_and_refuses_another() {
    let mut pinned = Vec::new();
    for case in &CASES {
        let unread = case.plan(case.subjects().fitted());
        let pools = case.read_pools();
        let read = case.plan(
            TransferSpend {
                pools,
                ..case.subjects()
            }
            .fitted(),
        );
        assert!(!unread.key.wide && read.key.wide, "{}", case.name);
        let outcome = match unread.rekeyed(read) {
            Ok(kept) => {
                assert_eq!(kept, read, "{}", case.name);
                "reuse"
            }
            Err(RingError::ResealRequired { row }) => {
                assert_eq!(row, SealRow::Wide, "{}", case.name);
                let resealed = case.plan(TransferSpend {
                    wide: row.wide(),
                    ..case.subjects()
                });
                assert_eq!(resealed.rekeyed(read).unwrap(), read, "{}", case.name);
                "reseal"
            }
            Err(error) => panic!("{}: {error}", case.name),
        };
        pinned.push(json!({
            "name": case.name,
            "rail": case.rail.to_string(),
            "inputs": case.inputs,
            "outputs": case.outputs,
            "spendsDefaultRing": case.spends_default_ring,
            "hasData": case.has_data,
            "approval": case.approval,
            "readPools": { "own": pools.own, "curator": pools.curator, "tracking": pools.tracking },
            "sealed": circuit_json(unread.key.circuit),
            "read": circuit_json(read.key.circuit),
            "outcome": outcome,
        }));
    }
    let outcomes: Vec<_> = pinned.iter().map(|case| case["outcome"].clone()).collect();
    assert_eq!(
        outcomes,
        ["reuse", "reseal", "reuse", "reseal", "reuse"].map(Value::from)
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/transfer-plan-rekey.json");
    let body = serde_json::to_string_pretty(&Value::from(pinned)).unwrap() + "\n";
    if std::env::var_os("UPDATE_PROVER_JSON").is_some() {
        std::fs::write(&path, &body).unwrap();
    }
    assert_eq!(std::fs::read_to_string(&path).unwrap(), body);
}
