use super::*;
use crate::tests::support::redacts;

#[test]
fn an_opening_or_a_merge_slot_prints_no_blinding() {
    let opening = Opening {
        blinding: [0xab; 32],
        ..Opening::default()
    };
    let slot = MergeSlot {
        domain: [1; 32],
        tree_id: [2; 32],
        amount: [3; 32],
        blinding: [0xab; 32],
        ring_data_hash: [4; 32],
    };
    for printed in [format!("{opening:?}"), format!("{slot:?}")] {
        assert!(redacts(&printed, &["blinding"]));
        assert!(!printed.contains("171, 171"));
    }
}
