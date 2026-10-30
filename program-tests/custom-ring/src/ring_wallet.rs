//! A wallet on one anonymous ring, the default-ring scan and the anonymous streams kept in memory.

use anyhow::Result;
use solana_address::Address;
use spr_client::{IndexerRpcConfig, Rpc, UtxoScan};
use spr_keypair::ShieldedKeypair;
use spr_transaction::{verify_owned, SpendableDecryptionResult, WalletUtxo};
use zolana_ring_client::{AnonymousSync, RingConfidentialScan, ViewingHistory};
use zolana_ring_transaction::RingAssets;

use crate::shared::TestEnv;

pub struct RingWallet<'a> {
    keys: &'a ShieldedKeypair,
    assets: RingAssets,
    ring: Address,
    pub history: ViewingHistory,
    kept: Vec<WalletUtxo>,
    spendable: SpendableDecryptionResult,
}

impl<'a> RingWallet<'a> {
    /// A wallet that never paid or was paid, its history from the keypair's viewing key.
    pub fn new(keys: &'a ShieldedKeypair, assets: RingAssets, ring: Address) -> Self {
        Self {
            keys,
            ring,
            assets,
            history: ViewingHistory::new(keys.viewing_pubkey(), 0),
            kept: Vec::new(),
            spendable: SpendableDecryptionResult::default(),
        }
    }

    /// Reads the default ring and every anonymous stream from index 0 at the indexer's tip.
    pub fn sync(&mut self, env: &TestEnv) -> Result<()> {
        let config = IndexerRpcConfig::at_slot(env.client.rpc().get_slot()?);
        let owned = UtxoScan::new(self.keys, self.assets.registry())
            .with_indexer_config(config)
            .fetch(env.client.indexer())?;
        let synced = env.client.block_on(async {
            AnonymousSync::new(self.keys, &self.assets)
                .with_full_rescan()
                .with_indexer_config(config)
                .with_deposit_payload(zolana_ring_client::deposit_payload)
                .fetch(env.client.as_async().indexer(), &self.history)
                .await
                .map_err(anyhow::Error::from)
        })?;
        // A sync reads every stream from index 0, its notes replace the kept ones.
        let spent: Vec<[u8; 32]> = owned
            .history
            .transactions
            .iter()
            .flat_map(|tx| tx.nullifiers.iter().copied())
            .collect();
        self.kept = verify_owned(self.keys, &synced.decrypted)?
            .spendable()
            .utxos()
            .filter(|utxo| {
                utxo.utxo.ring_program_id == Some(self.ring) && !spent.contains(&utxo.nullifier)
            })
            .cloned()
            .collect();
        self.history = synced.history;
        let notes = env
            .client
            .block_on(async {
                RingConfidentialScan::new(self.keys, &self.assets)
                    .with_indexer_config(config)
                    .fetch(env.client.as_async().indexer(), &owned.history.transactions)
                    .await
                    .map_err(anyhow::Error::from)
            })?
            .owned
            .spendable();
        let mut spendable = owned.spendable;
        for utxo in self.kept.iter().chain(notes.utxos()) {
            if !spendable
                .utxos()
                .any(|held| held.utxo_hash == utxo.utxo_hash)
            {
                spendable.utxos_with_data.push(utxo.clone());
            }
        }
        self.spendable = spendable;
        Ok(())
    }

    pub fn unspent(&self) -> impl Iterator<Item = &WalletUtxo> {
        self.spendable.utxos()
    }

    pub fn is_spent(&self, utxo: &WalletUtxo) -> bool {
        !self.unspent().any(|held| held.utxo_hash == utxo.utxo_hash)
    }
}
