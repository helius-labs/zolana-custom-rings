//! UTXO selection over the UTXOs a caller's predicate admits.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, HashSet},
};

use solana_address::Address;
use spr_interface::MAX_INPUT_TREES;
use spr_transaction::{
    instructions::{merge::MAX_MERGE_INPUTS, transact::MAX_SPEND_INPUTS},
    TransactionError, WalletUtxo,
};

/// The largest UTXOs `keep` admits until they cover `amount`, at most `max_inputs` up to [`MAX_SPEND_INPUTS`].
pub fn select_spend_where<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    amount: u64,
    max_inputs: usize,
    keep: impl Fn(&WalletUtxo) -> bool,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    select(candidates(utxos, asset, keep), asset, amount, max_inputs)
}

/// The smallest UTXOs `keep` admits on the tree holding most of them, at most `max_inputs` up to [`MAX_MERGE_INPUTS`].
pub fn select_merge_where<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    max_inputs: usize,
    excluded: &HashSet<[u8; 32]>,
    keep: impl Fn(&WalletUtxo) -> bool,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    let mut trees: BTreeMap<u16, Vec<&WalletUtxo>> = BTreeMap::new();
    for utxo in candidates(utxos, asset, keep)
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

fn candidates<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    keep: impl Fn(&WalletUtxo) -> bool,
) -> Vec<&'a WalletUtxo> {
    utxos
        .into_iter()
        .filter(|utxo| utxo.utxo.asset.asset == asset && utxo.utxo.amount > 0 && keep(utxo))
        .collect()
}

fn select(
    mut utxos: Vec<&WalletUtxo>,
    asset: Address,
    amount: u64,
    max_inputs: usize,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    let max_inputs = max_inputs.min(MAX_SPEND_INPUTS);
    if amount == 0 {
        return Err(TransactionError::ZeroSpendAmount);
    }
    if utxos.is_empty() {
        return Err(TransactionError::NoSpendableBalance { asset });
    }
    let available = utxos
        .iter()
        .try_fold(0u64, |total, utxo| total.checked_add(utxo.utxo.amount))
        .ok_or(TransactionError::SelectedBalanceOverflow)?;
    if available < amount {
        return Err(TransactionError::InsufficientBalance {
            requested: amount,
            available,
        });
    }
    utxos.sort_by_key(|utxo| Reverse(utxo.utxo.amount));
    let mut selected = Vec::new();
    let mut covered = 0u64;
    for utxo in utxos.into_iter().take(max_inputs) {
        // At most `available`, which did not overflow.
        covered += utxo.utxo.amount;
        selected.push(utxo.clone());
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
