//! Zero-key notes stay readable and recorded, and no automatic path ever spends one.

use std::collections::{BTreeMap, HashSet};

use solana_address::Address;
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::NullifierKey;
use spr_transaction::{
    verify_owned, DecryptionResult, OwnedUtxos, ShieldedKeys, TransactionError, WalletUtxo,
};

/// Where a note stands for its wallet, read from its key and its nullifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteState {
    PendingSpendCheck,
    Spendable,
    /// Its sender and the auditor compute its nullifier, spending publishes its owner.
    ExposedIfSpent,
    Spent,
}

/// One mint's unspent funds, the exposed ones never counted as spendable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MintBalance {
    pub spendable: u64,
    pub exposed_if_spent: u64,
}

/// What a wallet owns on a ring, `owned` is the part any automatic path reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RingOwnedUtxos {
    pub owned: OwnedUtxos,
    /// Unspent zero-key notes in publication order.
    pub exposed_if_spent: Vec<WalletUtxo>,
    /// The nullifiers of the spent zero-key notes.
    pub spent_exposed: HashSet<[u8; 32]>,
}

pub fn is_zero_key(note: &WalletUtxo) -> bool {
    note.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY
}

/// `spent` holds a note's nullifier once any transaction published it.
pub fn note_state(note: &WalletUtxo, spent: impl Fn(&[u8; 32]) -> bool) -> NoteState {
    match (spent(&note.nullifier), is_zero_key(note)) {
        (true, _) => NoteState::Spent,
        (false, true) => NoteState::ExposedIfSpent,
        (false, false) => NoteState::Spendable,
    }
}

/// The per-mint sum of `notes`, a saturated sum never reads as more than a u64.
pub fn mint_balances<'a>(
    notes: impl IntoIterator<Item = &'a WalletUtxo>,
    spent: impl Fn(&[u8; 32]) -> bool,
) -> BTreeMap<Address, MintBalance> {
    let mut balances: BTreeMap<Address, MintBalance> = BTreeMap::new();
    for note in notes {
        let amount = note.utxo.amount;
        let slot = balances.entry(note.utxo.asset.asset).or_default();
        match note_state(note, &spent) {
            NoteState::Spendable => slot.spendable = slot.spendable.saturating_add(amount),
            NoteState::ExposedIfSpent => {
                slot.exposed_if_spent = slot.exposed_if_spent.saturating_add(amount);
            }
            NoteState::Spent | NoteState::PendingSpendCheck => {}
        }
    }
    balances
}

/// [`verify_owned`] drops a zero-key note, the same checks run here under the zero key.
pub fn verify_ring_owned<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    decrypted: &DecryptionResult,
) -> Result<RingOwnedUtxos, TransactionError> {
    let (zero_key, keyed): (Vec<_>, Vec<_>) =
        decrypted.utxos.iter().cloned().partition(is_zero_key);
    let owned = verify_owned(
        shielded_keys,
        &DecryptionResult {
            utxos: keyed,
            ..decrypted.clone()
        },
    )?;
    let signing_pubkey = shielded_keys.address()?.signing_pubkey;
    let zero_secret = NullifierKey::from_secret([0; 31]);
    let mut claimed = HashSet::new();
    let mut exposed_if_spent = Vec::new();
    let mut spent_exposed = HashSet::new();
    for note in zero_key {
        if note.utxo.owner != signing_pubkey
            || (note.utxo.data.utxo_data().is_some() && note.data_hash.is_none())
            || (note.utxo.data.ring_data().is_some() && note.ring_data_hash.is_none())
        {
            continue;
        }
        let hash = note.utxo.hash(
            &ZERO_NULLIFIER_PUBKEY,
            &note.data_hash.unwrap_or_default(),
            &note.ring_data_hash.unwrap_or_default(),
            note.tree_id,
        )?;
        if hash != note.utxo_hash || !claimed.insert(hash) {
            continue;
        }
        let nullifier = zero_secret.nullifier(&hash, &note.utxo.blinding)?;
        match decrypted.spent_nullifiers.contains(&nullifier) {
            true => {
                spent_exposed.insert(nullifier);
            }
            false => exposed_if_spent.push(WalletUtxo { nullifier, ..note }),
        }
    }
    Ok(RingOwnedUtxos {
        owned,
        exposed_if_spent,
        spent_exposed,
    })
}
