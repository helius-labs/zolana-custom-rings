//! The UTXOs a ring's auditor opened and the nullifier keys its registry escrows.

use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    sync::{PoisonError, RwLock, RwLockReadGuard},
    time::Duration,
};

use solana_address::Address;
use solana_signature::Signature;
use spr_indexer_api::{Context, Hash};
use spr_keypair::{NullifierKey, PublicKey};
use spr_transaction::{Data, Mint, Utxo, WalletUtxo};
use tokio::sync::Mutex as AsyncMutex;
use zolana_ring_client::{
    rpc::AuditedUtxoView, CreatedUtxo, DepositNote, DepositOwner, DepositOwners, EscrowedKeys,
    KnownUtxo, KnownUtxoIndex, SealedNullifierKey, UtxoOwner,
};

use crate::error::RingRpcError;

pub const UTXO_BACKFILL_INTERVAL: Duration = Duration::from_secs(30);

/// Pages one backfill run reads, the next run resumes from its cursor.
pub(crate) const MAX_BACKFILL_PAGES: usize = 64;

/// The guards are never held across an await, the audit reads them synchronously.
#[derive(Default)]
pub(crate) struct AuditStore {
    utxos: RwLock<KnownUtxoIndex<StoredUtxo>>,
    escrow: RwLock<EscrowMap>,
    /// Confidential deposits by commitment, each opens once the escrow names its owner.
    unowned: RwLock<HashMap<[u8; 32], (CreatedIn, DepositNote)>>,
    /// Every nullifier the ring history published.
    spent: RwLock<HashSet<[u8; 32]>>,
    /// The indexer context when the backfill last reached the scan frontier.
    context: RwLock<Context>,
    /// The ring history position the next backfill resumes from, one backfill and escrow
    /// refresh at a time.
    pub(crate) backfill: AsyncMutex<Option<Vec<u8>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CreatedIn {
    pub slot: u64,
    pub tx_signature: Signature,
    pub event_index: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EscrowRoot {
    pub root: [u8; 32],
    pub revision: u64,
}

/// Verified under the registry root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EscrowedOwner {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub owner_hash: [u8; 32],
    pub sealed: SealedNullifierKey,
}

#[must_use]
pub(crate) struct SpendableNotes<'a> {
    pub ring: Address,
    pub owner_key: [u8; 32],
    pub mint: Mint,
    pub nullifier_key: &'a NullifierKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredUtxo {
    utxo: KnownUtxo,
    created_in: CreatedIn,
    slot_index: u32,
    leaf_index: u64,
}

#[derive(Default)]
struct EscrowMap {
    root: Option<EscrowRoot>,
    keys: HashMap<[u8; 32], EscrowedOwner>,
    /// Owner hash to owner key, over the owners of `keys`.
    owner_keys: HashMap<[u8; 32], [u8; 32]>,
}

impl AuditStore {
    pub(crate) fn record(
        &self,
        created_in: CreatedIn,
        utxos: impl IntoIterator<Item = CreatedUtxo>,
    ) {
        let mut stored = self.utxos.write().unwrap_or_else(PoisonError::into_inner);
        for created in utxos {
            stored.insert(
                created.commitment,
                StoredUtxo {
                    utxo: created.utxo,
                    created_in,
                    slot_index: created.slot_index,
                    leaf_index: created.leaf_index,
                },
            );
        }
    }

    pub(crate) fn hold(&self, created_in: CreatedIn, notes: impl IntoIterator<Item = DepositNote>) {
        let mut unowned = self.unowned.write().unwrap_or_else(PoisonError::into_inner);
        for note in notes {
            unowned.insert(note.commitment, (created_in, note));
        }
    }

    /// A Photon nullifier enters unbound, a false one only holds a note back from a merge.
    pub(crate) fn spend(&self, nullifiers: impl IntoIterator<Item = [u8; 32]>) {
        self.spent
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(nullifiers);
    }

    pub(crate) fn spendable(
        &self,
        notes: SpendableNotes<'_>,
    ) -> Result<Vec<WalletUtxo>, RingRpcError> {
        let owner = UtxoOwner::Keyed {
            nullifier_pk: notes.nullifier_key.pubkey()?,
        };
        let spent = self.spent.read().unwrap_or_else(PoisonError::into_inner);
        let known = self.known();
        known
            .iter()
            .filter(|(_, stored)| {
                let utxo = &stored.utxo;
                utxo.owner_key == notes.owner_key
                    && utxo.owner == owner
                    && utxo.mint == Some(notes.mint.asset)
                    && utxo.data_hash == [0; 32]
            })
            .map(|(commitment, stored)| stored.wallet_utxo(commitment, &notes))
            .filter(|note| !matches!(note, Ok(note) if spent.contains(&note.nullifier)))
            .collect()
    }

    pub(crate) fn escrowed(&self, owner_key: &[u8; 32]) -> Option<EscrowedOwner> {
        self.escrow
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys
            .get(owner_key)
            .copied()
    }

    pub(crate) fn absorbed(&self, context: Context) {
        let mut newest = self.context.write().unwrap_or_else(PoisonError::into_inner);
        if context.slot >= newest.slot {
            *newest = context;
        }
    }

    pub(crate) fn context(&self) -> Context {
        self.context
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn view(&self, utxo_hash: &Hash) -> Option<AuditedUtxoView> {
        let stored = self.stored(&utxo_hash.0)?;
        Some(AuditedUtxoView {
            utxo_hash: Hash(utxo_hash.0),
            utxo: stored.utxo.into(),
            slot: stored.created_in.slot,
            tx_signature: stored.created_in.tx_signature.into(),
            event_index: stored.created_in.event_index,
            slot_index: stored.slot_index,
        })
    }

    pub(crate) fn escrow_root(&self) -> Option<EscrowRoot> {
        self.escrow
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .root
    }

    /// Every key the registry escrows under `root`, the map read under an older root goes.
    pub(crate) fn replace_escrow(
        &self,
        root: EscrowRoot,
        owners: HashMap<[u8; 32], EscrowedOwner>,
    ) {
        {
            let mut escrow = self.escrow.write().unwrap_or_else(PoisonError::into_inner);
            escrow.owner_keys = owners
                .values()
                .map(|owner| (owner.owner_hash, owner.owner_key))
                .collect();
            escrow.keys = owners
                .into_values()
                .map(|owner| (owner.owner_key, owner))
                .collect();
            escrow.root = Some(root);
        }
        self.open_held();
    }

    /// An audit holds the guard for its full run, no UTXO enters between two of its lookups.
    pub(crate) fn known(&self) -> RwLockReadGuard<'_, KnownUtxoIndex<StoredUtxo>> {
        self.utxos.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn open_held(&self) {
        let mut opened = Vec::new();
        self.unowned
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (created_in, note)| match note.created(self) {
                Some(utxo) => {
                    opened.push((*created_in, utxo));
                    false
                }
                None => true,
            });
        for (created_in, utxo) in opened {
            self.record(created_in, [utxo]);
        }
    }

    fn stored(&self, utxo_hash: &[u8; 32]) -> Option<StoredUtxo> {
        self.known().get(utxo_hash).copied()
    }
}

impl StoredUtxo {
    fn wallet_utxo(
        &self,
        commitment: &[u8; 32],
        notes: &SpendableNotes<'_>,
    ) -> Result<WalletUtxo, RingRpcError> {
        let utxo = &self.utxo;
        Ok(WalletUtxo {
            utxo: Utxo {
                owner: PublicKey::from_ed25519(&utxo.owner_key),
                asset: notes.mint,
                amount: utxo.amount,
                blinding: utxo.blinding,
                ring_program_id: Some(notes.ring),
                data: Data::default(),
            },
            nullifier_pubkey: notes.nullifier_key.pubkey()?,
            utxo_hash: *commitment,
            nullifier: notes.nullifier_key.nullifier(commitment, &utxo.blinding)?,
            tx_viewing_key: None,
            data_hash: None,
            ring_data_hash: (utxo.ring_data_hash != [0; 32]).then_some(utxo.ring_data_hash),
            tree_id: utxo.tree_id,
            leaf_index: self.leaf_index,
            latest_tree_id: None,
            slot: self.created_in.slot,
            tx_signature: self.created_in.tx_signature,
            slot_index: self.slot_index,
        })
    }
}

impl Borrow<KnownUtxo> for StoredUtxo {
    fn borrow(&self) -> &KnownUtxo {
        &self.utxo
    }
}

impl EscrowedKeys for AuditStore {
    fn nullifier_pk(&self, owner_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.escrow
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys
            .get(owner_key)
            .map(|owner| owner.nullifier_pk)
    }
}

impl DepositOwners for AuditStore {
    fn deposit_owner(&self, owner_hash: &[u8; 32]) -> Option<DepositOwner> {
        let escrow = self.escrow.read().unwrap_or_else(PoisonError::into_inner);
        let owner = escrow.keys.get(escrow.owner_keys.get(owner_hash)?)?;
        Some(DepositOwner {
            owner_key: owner.owner_key,
            nullifier_pk: owner.nullifier_pk,
        })
    }
}

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use spr_keypair::X25519Keypair;
    use zolana_ring_client::{NullifierKeyEnvelope, UtxoOwner};

    use super::*;

    fn created(mint: Option<Address>) -> CreatedUtxo {
        CreatedUtxo {
            commitment: [1; 32],
            slot_index: 0,
            leaf_index: 0,
            utxo: KnownUtxo {
                owner_key: [2; 32],
                owner: UtxoOwner::Keyed {
                    nullifier_pk: [3; 32],
                },
                asset: [4; 32],
                mint,
                amount: 10,
                blinding: [5; 32],
                data_hash: [0; 32],
                ring_data_hash: [0; 32],
                tree_id: 1,
            },
        }
    }

    #[test]
    fn a_stored_utxo_changes_only_to_gain_its_mint() {
        let store = AuditStore::default();
        let created_in = CreatedIn {
            slot: 1,
            tx_signature: Signature::from([7; 64]),
            event_index: 0,
        };
        let mint = Some(Address::new_from_array([6; 32]));
        let stored_mint = || store.stored(&[1; 32]).map(|stored| stored.utxo.mint);
        store.record(created_in, [created(None)]);
        store.record(created_in, [created(mint)]);
        assert_eq!(stored_mint(), Some(mint));
        store.record(created_in, [created(None)]);
        assert_eq!(stored_mint(), Some(mint));
    }

    #[test]
    fn an_escrowed_owner_opens_the_deposits_audited_before_its_key() {
        let store = AuditStore::default();
        let created_in = CreatedIn {
            slot: 1,
            tx_signature: Signature::from([7; 64]),
            event_index: 0,
        };
        let note = DepositNote {
            commitment: [1; 32],
            slot_index: 0,
            leaf_index: 0,
            owner_hash: [8; 32],
            owner_key: None,
            asset: [4; 32],
            mint: Address::new_from_array([6; 32]),
            amount: 10,
            blinding: [5; 32],
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
            tree_id: 1,
        };
        let owner = EscrowedOwner {
            owner_key: [2; 32],
            nullifier_pk: [3; 32],
            owner_hash: note.owner_hash,
            sealed: NullifierKeyEnvelope::new(
                &NullifierKey::from_secret([9; 31]),
                &X25519Keypair::new().pubkey(),
            )
            .expect("envelope")
            .sealed,
        };
        store.hold(created_in, [note]);
        assert!(store.stored(&note.commitment).is_none());
        store.replace_escrow(
            EscrowRoot {
                root: [1; 32],
                revision: 1,
            },
            HashMap::from([(owner.owner_key, owner)]),
        );
        let opened = store.stored(&note.commitment).expect("reopened deposit");
        assert_eq!(opened.created_in, created_in);
        assert_eq!(opened.utxo.owner_key, owner.owner_key);
        assert_eq!(
            opened.utxo.owner,
            UtxoOwner::Keyed {
                nullifier_pk: owner.nullifier_pk
            }
        );
    }
}
