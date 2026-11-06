use serde::Deserialize;
use solana_address::Address;
use spr_transaction::{Mint, TransactionError, WalletUtxo};

use super::Funding;
use crate::tests::support::{keypair, ring_utxo, wallet};
use crate::RingError;

fn notes(held: impl IntoIterator<Item = (u16, u64)>) -> Vec<WalletUtxo> {
    let owner = keypair(7);
    held.into_iter()
        .zip(0..)
        .map(|((tree, amount), leaf)| {
            wallet(
                ring_utxo(&owner, Mint::SOL, amount, leaf).utxo,
                &owner.nullifier_key,
                tree,
                leaf,
            )
        })
        .collect()
}

fn funding(utxos: &[WalletUtxo], amount: u64, max_inputs: usize) -> Funding<'_> {
    Funding {
        utxos,
        asset: Mint::SOL.asset,
        amount,
        max_inputs,
    }
}

fn first_choice(utxos: &[WalletUtxo], amount: u64, max_inputs: usize) -> Vec<(u16, u64)> {
    let mut picked: Vec<_> = funding(utxos, amount, max_inputs)
        .select(|_| true)
        .unwrap()
        .utxos
        .iter()
        .map(|utxo| (utxo.tree_id, utxo.utxo.amount))
        .collect();
    picked.sort_unstable();
    picked
}

#[test]
fn rejects_three_selected_trees_without_searching_for_an_alternative() {
    let utxos = notes([(0, 60), (0, 20), (1, 55), (2, 50)]);
    assert!(matches!(
        funding(&utxos, 130, 4).select(|_| true),
        Err(RingError::Transaction(
            TransactionError::TooManyInputTrees { got: 3, max: 2 }
        ))
    ));
}

#[test]
fn a_large_fragmented_wallet_returns_the_tree_refusal() {
    let note = notes([(0, 1)]).pop().unwrap();
    let utxos: Vec<_> = (0..10_000)
        .map(|tree_id| WalletUtxo {
            tree_id,
            ..note.clone()
        })
        .collect();
    assert!(matches!(
        funding(&utxos, 3, 5).select(|_| true),
        Err(RingError::Transaction(
            TransactionError::TooManyInputTrees { got: 3, max: 2 }
        ))
    ));
}

#[test]
fn input_fragmentation_requires_an_explicit_merge() {
    let utxos = notes([(0, 4), (0, 4), (0, 4)]);
    assert!(matches!(
        funding(&utxos, 10, 2).select(|_| true),
        Err(RingError::Transaction(TransactionError::SpendNeedsMerge {
            max_inputs: 2,
            ..
        }))
    ));
}

#[test]
fn pays_ten_from_six_on_each_of_two_trees() {
    let utxos = notes([(0, 6), (1, 6), (2, 1)]);
    assert_eq!(first_choice(&utxos, 10, 5), [(0, 6), (1, 6)]);
}

#[test]
fn a_tree_of_another_asset_stays_out_of_the_search() {
    let mut utxos = notes([(0, 6), (1, 6)]);
    utxos[1].utxo.asset = Mint::new(Address::new_from_array([9; 32]), 2);
    assert!(matches!(
        funding(&utxos, 10, 5).select(|_| true),
        Err(RingError::Unfunded { .. })
    ));
}

#[test]
fn largest_notes_fit_the_input_budget() {
    let utxos = notes(
        (0..8)
            .flat_map(|tree| [(tree, 40), (tree, 40)])
            .chain([(8, 60)]),
    );
    let picked = first_choice(&utxos, 100, 2);
    assert_eq!(picked.len(), 2);
    assert_eq!(picked.iter().map(|(_, amount)| amount).sum::<u64>(), 100);
    assert!(picked.iter().any(|(tree, _)| *tree == 8));
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    amount: u64,
    max_inputs: usize,
    notes: Vec<Note>,
    selected: Vec<Note>,
}

#[derive(Deserialize)]
struct Note {
    tree: u16,
    amount: u64,
}

#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}

#[test]
fn matches_the_shared_tree_selection_vector() {
    let vectors: Vectors = serde_json::from_str(include_str!(
        "../../../../../test-vectors/wallet/tree-selection.json"
    ))
    .unwrap();
    for case in vectors.cases {
        let utxos = notes(case.notes.iter().map(|note| (note.tree, note.amount)));
        let expected: Vec<_> = case
            .selected
            .iter()
            .map(|note| (note.tree, note.amount))
            .collect();
        assert_eq!(
            first_choice(&utxos, case.amount, case.max_inputs),
            expected,
            "{}",
            case.name
        );
    }
}
