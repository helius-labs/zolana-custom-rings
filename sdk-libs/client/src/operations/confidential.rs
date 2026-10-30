//! Confidential ring notes of scheme 10 and ring deposits opened into a wallet, the pinned zolana scan skips them.

use std::collections::HashSet;

use spr_client::{AsyncRpc, IndexerRpcConfig};
use spr_keypair::KeypairError;
use spr_transaction::{
    verify_owned, DecryptionResult, OwnedUtxos, ShieldedKeys, ShieldedTransaction, TransactionError,
};
use zolana_ring_keys::RingKeys;
use zolana_ring_transaction::RingAssets;

use crate::{
    delivered::{confidential_delivered, open_delivered, PendingUtxo},
    deposit::{DepositOpener, OpenedDeposit},
    deposit_payload,
    tags::IndexerReads,
    AnonymousError,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RingConfidentialNotes {
    pub owned: OwnedUtxos,
    /// Scheme 10 notes whose commitment no held mint rebuilds.
    pub pending: Vec<PendingUtxo>,
}

/// Reads the spends of the notes it opens and the ring merges among them, the scanned transactions alone miss a spend without change.
#[must_use]
pub struct RingConfidentialScan<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a RingAssets,
    config: Option<IndexerRpcConfig>,
}

impl<'a, K: ShieldedKeys + RingKeys + ?Sized> RingConfidentialScan<'a, K> {
    pub fn new(keys: &'a K, assets: &'a RingAssets) -> Self {
        Self {
            keys,
            assets,
            config: None,
        }
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub async fn fetch<I: AsyncRpc + ?Sized>(
        &self,
        indexer: &I,
        transactions: &[ShieldedTransaction],
    ) -> Result<RingConfidentialNotes, AnonymousError> {
        let mut notes = self.open(transactions)?;
        let mut reads = IndexerReads::configured(indexer, self.config);
        let mut queried = HashSet::new();
        loop {
            let unread: Vec<[u8; 32]> = notes
                .owned
                .utxos
                .iter()
                .map(|utxo| utxo.nullifier)
                .filter(|nullifier| !notes.owned.spent.contains(nullifier))
                .filter(|nullifier| queried.insert(*nullifier))
                .collect();
            if unread.is_empty() {
                return Ok(notes);
            }
            let spends = reads.spends(&unread).await?;
            let read: HashSet<[u8; 32]> = spends
                .iter()
                .flat_map(|tx| tx.nullifiers.iter().copied())
                .collect();
            notes.owned.spent.extend(
                unread
                    .into_iter()
                    .filter(|nullifier| read.contains(nullifier)),
            );
            let merged = verify_owned(
                self.keys,
                &RingMerges::among(spends).open(self.keys, self.assets)?,
            )?;
            for utxo in merged.utxos {
                if !notes
                    .owned
                    .utxos
                    .iter()
                    .any(|held| held.utxo_hash == utxo.utxo_hash)
                {
                    notes.owned.utxos.push(utxo);
                }
            }
            notes
                .owned
                .unknown_asset_ids
                .extend(merged.unknown_asset_ids);
            notes.owned.unknown_mints.extend(merged.unknown_mints);
        }
    }

    /// Spent state covers `transactions` alone, a malformed audit capsule skips its deposit.
    pub fn open(
        &self,
        transactions: &[ShieldedTransaction],
    ) -> Result<RingConfidentialNotes, AnonymousError> {
        let address = self.keys.address()?;
        let delivered = open_delivered(
            &address,
            self.assets,
            &confidential_delivered(self.keys, transactions)?,
        )?;
        let mut decrypted = DecryptionResult {
            utxos: delivered.found,
            spent_nullifiers: transactions
                .iter()
                .flat_map(|tx| tx.nullifiers.iter().copied())
                .collect(),
            ..DecryptionResult::default()
        };
        let opener = DepositOpener {
            keys: self.keys,
            address: &address,
            assets: self.assets.registry(),
            deposit_payload,
        };
        for opened in opener.open_held(transactions)? {
            match opened {
                OpenedDeposit::Note(utxo) => decrypted.utxos.push(*utxo),
                OpenedDeposit::UnknownMint(mint) => {
                    decrypted.unknown_mints.insert(mint);
                }
            }
        }
        Ok(RingConfidentialNotes {
            owned: verify_owned(self.keys, &decrypted)?,
            pending: delivered.pending,
        })
    }
}

/// Spent state covers `transactions` alone.
pub fn open_ring_confidential<K: ShieldedKeys + RingKeys + ?Sized>(
    keys: &K,
    assets: &RingAssets,
    transactions: &[ShieldedTransaction],
) -> Result<RingConfidentialNotes, AnonymousError> {
    RingConfidentialScan::new(keys, assets).open(transactions)
}

pub(crate) struct RingMerges(pub Vec<ShieldedTransaction>);

impl RingMerges {
    pub(crate) fn among(spends: Vec<ShieldedTransaction>) -> Self {
        Self(
            spends
                .into_iter()
                .filter(|tx| tx.ring_program_id.is_some() && tx.may_be_merge())
                .collect(),
        )
    }

    pub(crate) fn open<K: ShieldedKeys + ?Sized>(
        &self,
        keys: &K,
        assets: &RingAssets,
    ) -> Result<DecryptionResult, AnonymousError> {
        let mut opened = DecryptionResult::default();
        for merge in &self.0 {
            match opened.extend(keys, core::slice::from_ref(merge), assets.registry()) {
                Ok(()) => {}
                // A merge output outside the field opens to nothing.
                Err(TransactionError::Keypair(KeypairError::Poseidon(_))) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(opened)
    }
}
