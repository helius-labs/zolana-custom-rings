//! Pins ring verifying keys to `proving-keys.lock` and the key catalog to the program's circuits.
#![cfg(feature = "verifying-keys")]

use std::collections::BTreeSet;

use custom_ring_interface::{
    key_catalog::{RingCircuit, RING_KEYS},
    verifying_key, AnonymousLayout, AnonymousSpend, DisclosureLayout, RingRail, APPLY_BATCH,
    DELIVERED_AUDIT_CAPACITIES, MERGE_WIDTHS, PROVING_KEY_SHA256S,
};
use spr_interface::shape::SPP_SUPPORTED_SHAPES;

const LOCK: &str = include_str!("../../../prover/ring/proving-keys.lock");

fn locked_ring_keys() -> Vec<(String, String)> {
    let lock: serde_json::Value = serde_json::from_str(LOCK).unwrap();
    lock["keys"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(name, _)| name.starts_with("custom_ring_"))
        .map(|(name, entry)| (name.clone(), entry["sha256"].as_str().unwrap().to_owned()))
        .collect()
}

#[test]
fn ring_verifying_keys_pin_the_locked_proving_keys() {
    let locked = locked_ring_keys();
    for (name, sha256) in PROVING_KEY_SHA256S {
        let pinned = locked.iter().find(|(locked, _)| locked == name);
        assert_eq!(
            pinned.map(|(_, sha256)| sha256.as_str()),
            Some(hex::encode(sha256).as_str()),
            "{name}"
        );
    }
}

#[test]
fn every_catalog_key_is_locked_with_its_verifying_key() {
    let catalog: BTreeSet<String> = RING_KEYS.iter().map(|key| key.file_name()).collect();
    let locked: BTreeSet<String> = locked_ring_keys()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let verified: BTreeSet<String> = PROVING_KEY_SHA256S
        .iter()
        .map(|(name, _)| name.to_string())
        .collect();
    assert_eq!(locked, catalog);
    assert_eq!(verified, catalog);
}

/// Every circuit the program selects for a supported shape, as the generated catalog spells it.
fn selectable_circuits() -> BTreeSet<String> {
    let mut circuits = vec![RingCircuit::RegisterKey, RingCircuit::WithdrawalExemption];
    circuits.extend((1..=8).map(RingCircuit::deposit));
    for shape in SPP_SUPPORTED_SHAPES {
        let (n_in, n_out) = (shape.n_inputs(), shape.n_outputs());
        let outputs = n_out as u8;
        if DELIVERED_AUDIT_CAPACITIES.contains(&n_out) {
            circuits.push(RingCircuit::DeliveredAudit { outputs });
        }
        for inputs in 1..=n_in {
            for spends_default_ring in [false, true] {
                let spend = AnonymousSpend {
                    inputs,
                    outputs: n_out,
                    spends_default_ring,
                };
                if let Some(key) = spend.audit_key() {
                    let layout = AnonymousLayout {
                        key,
                        inputs,
                        outputs: n_out,
                        exits: false,
                    };
                    circuits.push(RingCircuit::audit(
                        DisclosureLayout::Anonymous(layout),
                        outputs,
                    ));
                }
            }
        }
        for own_only in [false, true] {
            for withdrawals in 0..=32 {
                circuits.push(RingCircuit::policy(
                    RingRail::Confidential,
                    n_in as u8,
                    outputs,
                    withdrawals,
                    own_only,
                ));
            }
            if shape.is_ring_authority() {
                circuits.push(RingCircuit::policy(
                    RingRail::Delegate,
                    n_in as u8,
                    outputs,
                    0,
                    own_only,
                ));
            }
        }
    }
    circuits.extend((1..=APPLY_BATCH as u64).map(RingCircuit::apply_records));
    circuits.extend(MERGE_WIDTHS.map(|width| RingCircuit::Merge { width: width as u8 }));
    circuits
        .iter()
        .map(|circuit| format!("{circuit:?}"))
        .collect()
}

#[test]
fn key_catalog_matches_circuits() {
    let catalog: BTreeSet<String> = RING_KEYS
        .iter()
        .map(|key| format!("{:?}", key.circuit))
        .collect();
    assert_eq!(catalog.len(), RING_KEYS.len(), "a circuit keyed twice");
    assert_eq!(catalog, selectable_circuits());
    let names: BTreeSet<String> = RING_KEYS.iter().map(|key| key.file_name()).collect();
    assert_eq!(names.len(), RING_KEYS.len(), "a key file named twice");
    for key in RING_KEYS {
        let pinned = PROVING_KEY_SHA256S
            .iter()
            .any(|(name, _)| *name == key.file_name());
        assert_eq!(verifying_key(key.circuit).is_some(), pinned, "{}", key.name);
    }
}
