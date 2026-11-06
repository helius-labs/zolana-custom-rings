//! UTXO selection over the UTXOs a caller's predicate admits.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, HashSet},
};

use solana_address::Address;
use spr_interface::{MAX_INPUT_TREES, ZERO_NULLIFIER_PUBKEY};
use spr_transaction::{instructions::merge::MAX_MERGE_INPUTS, TransactionError, WalletUtxo};

pub(crate) struct BoundedSpendCandidates {
    notes: Vec<WalletUtxo>,
    available: Option<u64>,
    capacity: usize,
}

pub(crate) struct SpendRequest {
    pub asset: Address,
    pub amount: u64,
    pub max_inputs: usize,
}

struct SpendDecision<'a> {
    notes: Vec<&'a WalletUtxo>,
    available: Option<u64>,
    request: SpendRequest,
}

impl BoundedSpendCandidates {
    pub fn new(capacity: usize) -> Self {
        Self {
            notes: Vec::with_capacity(capacity),
            available: Some(0),
            capacity,
        }
    }

    pub fn observe(&mut self, note: &WalletUtxo) {
        if note.utxo.amount == 0 {
            return;
        }
        self.available = self
            .available
            .and_then(|available| available.checked_add(note.utxo.amount));
        let position = self
            .notes
            .partition_point(|held| held.utxo.amount >= note.utxo.amount);
        if position < self.capacity {
            self.notes.insert(position, note.clone());
            self.notes.truncate(self.capacity);
        }
    }

    pub fn select(self, request: SpendRequest) -> Result<Vec<WalletUtxo>, TransactionError> {
        SpendDecision {
            notes: self.notes.iter().collect(),
            available: self.available,
            request,
        }
        .select()
    }
}

/// The largest keyed UTXOs `keep` admits until they cover `amount`, at most `max_inputs`.
pub fn select_spend_where<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    amount: u64,
    max_inputs: usize,
    keep: impl Fn(&WalletUtxo) -> bool,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    let admitted = candidates(utxos, asset, keep);
    SpendRequest {
        asset,
        amount,
        max_inputs,
    }
    .select(admitted)
}

/// The smallest keyed UTXOs `keep` admits on the tree holding most of them, at most `max_inputs` up to [`MAX_MERGE_INPUTS`].
pub fn select_merge_where<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    max_inputs: usize,
    excluded: &HashSet<[u8; 32]>,
    keep: impl Fn(&WalletUtxo) -> bool,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    let mut trees: BTreeMap<u16, Vec<&WalletUtxo>> = BTreeMap::new();
    let admitted = candidates(utxos, asset, keep);
    for utxo in admitted
        .into_iter()
        .filter(|utxo| !excluded.contains(&utxo.nullifier))
    {
        trees.entry(utxo.tree_id()).or_default().push(utxo);
    }
    // The lowest tree id wins a tie, so the choice does not depend on order.
    let mut selected = trees
        .into_values()
        .rev()
        .max_by_key(Vec::len)
        .unwrap_or_default();
    selected.sort_by_key(|utxo| utxo.utxo.amount);
    selected.truncate(max_inputs.min(MAX_MERGE_INPUTS));
    if selected.len() < 2 {
        return Err(TransactionError::NothingToMerge { asset });
    }
    Ok(selected.into_iter().cloned().collect())
}

/// The nonzero UTXOs of `asset` the key class and `keep` admit.
fn candidates<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    keep: impl Fn(&WalletUtxo) -> bool,
) -> Vec<&'a WalletUtxo> {
    utxos
        .into_iter()
        .filter(|utxo| {
            utxo.utxo.asset.asset == asset
                && utxo.utxo.amount > 0
                && utxo.nullifier_pubkey != ZERO_NULLIFIER_PUBKEY
                && keep(utxo)
        })
        .collect()
}

impl SpendRequest {
    fn select(self, notes: Vec<&WalletUtxo>) -> Result<Vec<WalletUtxo>, TransactionError> {
        let available = notes
            .iter()
            .try_fold(0u64, |total, note| total.checked_add(note.utxo.amount));
        SpendDecision {
            notes,
            available,
            request: self,
        }
        .select()
    }
}

impl SpendDecision<'_> {
    fn select(mut self) -> Result<Vec<WalletUtxo>, TransactionError> {
        let SpendRequest {
            asset,
            amount,
            max_inputs,
        } = self.request;
        if amount == 0 {
            return Err(TransactionError::ZeroSpendAmount);
        }
        let available = self
            .available
            .ok_or(TransactionError::SelectedBalanceOverflow)?;
        if available == 0 {
            return Err(TransactionError::NoSpendableBalance { asset });
        }
        if available < amount {
            return Err(TransactionError::InsufficientBalance {
                requested: amount,
                available,
            });
        }
        self.notes.sort_by_key(|utxo| Reverse(utxo.utxo.amount));
        let mut selected = Vec::new();
        let mut covered = 0u64;
        for note in self.notes.into_iter().take(max_inputs) {
            covered += note.utxo.amount;
            selected.push(note.clone());
            if covered >= amount {
                let mut trees: Vec<u16> = selected.iter().map(WalletUtxo::tree_id).collect();
                trees.sort_unstable();
                trees.dedup();
                if trees.len() > MAX_INPUT_TREES {
                    return Err(TransactionError::TooManyInputTrees {
                        got: trees.len(),
                        max: MAX_INPUT_TREES,
                    });
                }
                return Ok(selected);
            }
        }
        Err(TransactionError::SpendNeedsMerge { amount, max_inputs })
    }
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use crate::tests::support::{keypair, ring_utxo};
    use spr_transaction::Mint;

    fn request(amount: u64, max_inputs: usize) -> SpendRequest {
        SpendRequest {
            asset: Mint::SOL.asset,
            amount,
            max_inputs,
        }
    }

    #[test]
    fn retained_openings_follow_capacity_and_stable_ties() {
        let mut note = ring_utxo(&keypair(7), Mint::SOL, 10, 0);
        let mut candidates = BoundedSpendCandidates::new(4);
        for rank in 0..100 {
            note.leaf_index = rank;
            candidates.observe(&note);
            assert!(candidates.notes.len() <= 4);
        }
        let selected = candidates.select(request(30, 4)).unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|note| note.leaf_index)
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
    }

    #[test]
    fn full_totals_preserve_merge_and_balance_refusals() {
        let note = ring_utxo(&keypair(7), Mint::SOL, 1, 0);
        for target in [6, 8] {
            let mut candidates = BoundedSpendCandidates::new(4);
            for _ in 0..7 {
                candidates.observe(&note);
            }
            let refusal = candidates.select(request(target, 4)).unwrap_err();
            match target {
                6 => assert!(matches!(
                    refusal,
                    TransactionError::SpendNeedsMerge {
                        amount: 6,
                        max_inputs: 4
                    }
                )),
                _ => assert!(matches!(
                    refusal,
                    TransactionError::InsufficientBalance {
                        requested: 8,
                        available: 7
                    }
                )),
            }
        }
        let mut candidates = BoundedSpendCandidates::new(4);
        let mut overflow = note.clone();
        overflow.utxo.amount = u64::MAX;
        candidates.observe(&overflow);
        candidates.observe(&note);
        assert!(matches!(
            candidates.select(request(1, 4)),
            Err(TransactionError::SelectedBalanceOverflow)
        ));
    }

    #[test]
    fn bounded_selection_keeps_the_greedy_tree_refusal() {
        let mut note = ring_utxo(&keypair(7), Mint::SOL, 1, 0);
        let mut candidates = BoundedSpendCandidates::new(4);
        for (tree, amount) in [(0, 100), (1, 99), (2, 98), (3, 97), (0, 80), (1, 79)] {
            note.tree_id = tree;
            note.utxo.amount = amount;
            candidates.observe(&note);
        }
        assert!(matches!(
            candidates.select(request(350, 4)),
            Err(TransactionError::TooManyInputTrees { got: 4, max: 2 })
        ));
    }
}
