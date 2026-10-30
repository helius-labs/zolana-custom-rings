use serde::Deserialize;

use super::*;
use crate::types::UtxoOwner;

#[derive(Deserialize)]
struct AssignmentCase {
    name: String,
    inputs: usize,
    notes: Vec<String>,
    expected: Expected,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Expected {
    Opened,
    Ambiguous,
    Unseen,
}

fn note(commitment: &str) -> ([u8; 32], KnownUtxo) {
    let commitment: [u8; 32] = hex::decode(commitment).unwrap().try_into().unwrap();
    let byte = commitment[31];
    let utxo = KnownUtxo {
        owner_key: [0xa1; 32],
        owner: UtxoOwner::Keyed {
            nullifier_pk: [byte; 32],
        },
        asset: [byte; 32],
        mint: None,
        amount: u64::from(byte),
        blinding: [byte; 32],
        data_hash: [0; 32],
        ring_data_hash: [0; 32],
        tree_id: 1,
    };
    (commitment, utxo)
}

#[test]
fn the_inputs_under_one_prefix_open_only_when_one_note_fills_one_position() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../test-vectors/audit/prefix-assignment.json"
    ))
    .unwrap();
    let cases: Vec<AssignmentCase> = serde_json::from_value(vector["cases"].clone()).unwrap();
    for case in cases {
        let notes: Vec<_> = case.notes.iter().map(String::as_str).map(note).collect();
        let prefix = InputPrefix::of(&notes[0].0).unwrap();
        let assigned = PrefixNotes {
            prefix,
            notes: notes.clone(),
        }
        .assign(case.inputs);
        let candidates = notes.iter().map(|(commitment, _)| *commitment).collect();
        match case.expected {
            Expected::Opened => assert_eq!(
                assigned.unwrap(),
                [InputOpening::Opened(ring_input(notes[0].0, notes[0].1))],
                "{}",
                case.name
            ),
            Expected::Ambiguous => assert_eq!(
                assigned.unwrap(),
                vec![InputOpening::Ambiguous { candidates }; case.inputs],
                "{}",
                case.name
            ),
            Expected::Unseen => assert!(
                matches!(assigned, Err(AuditError::UnseenInputPrefix { prefix: unseen }) if unseen == prefix.get()),
                "{}",
                case.name
            ),
        }
    }
}
