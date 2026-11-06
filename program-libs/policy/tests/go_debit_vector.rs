//! Reads `test-vectors/policy/debit.json`, the table the transfer circuit settles at and refuses one below.

use serde::Deserialize;
use zolana_ring_policy::{owner_debits, DebitInput, DebitOutput, DebitTransfer};

#[derive(Deserialize)]
struct Note {
    owner: u64,
    asset: u64,
    amount: u64,
    ring: bool,
}

#[derive(Deserialize)]
struct Row {
    owner: u64,
    asset: u64,
    debit: u128,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    inputs: Vec<Note>,
    outputs: Vec<Note>,
    debits: Vec<Row>,
}

#[derive(Deserialize)]
struct Vector {
    cases: Vec<Case>,
}

fn identity(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

#[test]
fn owner_debits_match_the_circuit_table() {
    let vector: Vector =
        serde_json::from_str(include_str!("../../../test-vectors/policy/debit.json")).unwrap();
    for case in vector.cases {
        let inputs: Vec<DebitInput> = case
            .inputs
            .iter()
            .map(|note| DebitInput {
                owner: identity(note.owner),
                asset: identity(note.asset),
                amount: note.amount,
            })
            .collect();
        let outputs: Vec<DebitOutput> = case
            .outputs
            .iter()
            .map(|note| DebitOutput {
                ring: note.ring,
                owner: identity(note.owner),
                asset: identity(note.asset),
                amount: note.amount,
            })
            .collect();
        let senders: Vec<[u8; 32]> = inputs.iter().map(|input| input.owner).collect();
        let assets: Vec<[u8; 32]> = outputs.iter().map(|output| output.asset).collect();
        let rows = owner_debits(&DebitTransfer {
            senders: &senders,
            assets: &assets,
            inputs: &inputs,
            outputs: &outputs,
            public_gross: &[],
        });
        let want: Vec<([u8; 32], [u8; 32], u128)> = case
            .debits
            .iter()
            .filter(|row| row.debit != 0)
            .map(|row| (identity(row.owner), identity(row.asset), row.debit))
            .collect();
        let got: Vec<([u8; 32], [u8; 32], u128)> = rows
            .iter()
            .map(|row| (row.owner, row.asset, row.debit))
            .collect();
        assert_eq!(got, want, "{}", case.name);
    }
}
