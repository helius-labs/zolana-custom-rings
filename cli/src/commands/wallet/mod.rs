//! A member's anonymous viewing history between runs and the scans that read its notes.

use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{ensure, Context as _, Result};
use custom_ring_interface::RingMode;
use custom_ring_sdk::CustomRingConfig;
use spr_client::{BlockingIndexer, BlockingRpc, IndexerRpcConfig, Rpc, UtxoScan};
use spr_keypair::{ShieldedKeypair, X25519Pubkey};
use spr_transaction::{verify_owned, SpendableDecryptionResult};
use zolana_ring_client::{AnonymousSync, RingConfidentialScan, ViewingHistory};
use zolana_ring_transaction::RingAssets;
use zolana_secret_file::{create_new, Visibility};

use crate::{file, Context, Zolana};

/// Under the `keys/` that `new` writes into `.gitignore`.
pub const ANONYMOUS_RING_DIR: &str = "keys/anonymous-ring";

/// One wallet's viewing history, shared by every anonymous ring it holds notes in.
pub struct AnonymousWalletStore {
    path: PathBuf,
    viewing_pubkey: X25519Pubkey,
}

#[must_use]
pub struct StoreLocation<'a> {
    pub dir: &'a Path,
    pub keys: &'a ShieldedKeypair,
}

#[must_use]
pub struct WalletScan<'a> {
    pub keys: &'a ShieldedKeypair,
    pub assets: &'a RingAssets,
    pub config: &'a CustomRingConfig,
}

#[must_use]
struct ScanAt<'a> {
    keys: &'a ShieldedKeypair,
    assets: &'a RingAssets,
    /// Read only when a found note's mint is missing from `assets`.
    chain_assets: &'a dyn Fn() -> Result<RingAssets>,
    /// The indexer answers only after it holds the slot.
    slot: u64,
    /// Present on an anonymous ring.
    store: Option<&'a AnonymousWalletStore>,
}

/// Held while a store's file changes, any part file found under it is a crashed run's.
#[must_use]
struct StoreLock {
    _file: fs::File,
}

impl StoreLocation<'_> {
    pub fn open(self) -> AnonymousWalletStore {
        let viewing_pubkey = self.keys.viewing_pubkey();
        AnonymousWalletStore {
            path: self
                .dir
                .join(format!("{}.json", hex::encode(viewing_pubkey.as_bytes()))),
            viewing_pubkey,
        }
    }
}

impl AnonymousWalletStore {
    /// A wallet that never stored a history starts one at its current key.
    pub fn load(&self) -> Result<ViewingHistory> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ViewingHistory::new(self.viewing_pubkey, unix_now()?))
            }
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", self.path.display()))
            }
        };
        let history = ViewingHistory::from_json(&text)
            .with_context(|| format!("cannot parse {}", self.path.display()))?;
        ensure!(
            history.entry(&self.viewing_pubkey).is_some(),
            "{} holds no entry of the wallet's viewing key",
            self.path.display()
        );
        Ok(history)
    }

    /// Applies `change` to the stored history under the store's lock.
    pub fn update<T>(&self, change: impl FnOnce(&mut ViewingHistory) -> Result<T>) -> Result<T> {
        let lock = self.lock()?;
        let stored = self.load()?;
        let mut history = stored.clone();
        let outcome = change(&mut history)?;
        if history != stored || !self.path.exists() {
            lock.replace(&self.path, history.to_json())?;
        }
        Ok(outcome)
    }

    /// Stores `advanced` in place of `from`, refused once another run moved the history.
    pub fn commit(&self, from: &ViewingHistory, advanced: ViewingHistory) -> Result<()> {
        self.update(|stored| {
            ensure!(
                stored == from,
                "the viewing history moved while the transfer was built, run it again"
            );
            *stored = advanced;
            Ok(())
        })
    }

    fn lock(&self) -> Result<StoreLock> {
        let path = self.path.with_extension("lock");
        if let Some(dir) = path.parent() {
            file::create_dir_all(dir)?;
        }
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("cannot open {}", path.display()))?;
        lock.lock()
            .with_context(|| format!("cannot lock {}", path.display()))?;
        Ok(StoreLock { _file: lock })
    }
}

impl WalletScan<'_> {
    pub fn fetch(self, ctx: &Context) -> Result<SpendableDecryptionResult> {
        let store = (self.config.mode == RingMode::Anonymous)
            .then(|| ctx.anonymous_wallet_store(self.keys));
        ScanAt {
            keys: self.keys,
            assets: self.assets,
            chain_assets: &|| crate::assets::ring_assets(ctx.rpc()),
            slot: ctx.rpc().get_slot()?,
            store: store.as_ref(),
        }
        .fetch(&ctx.zolana)
    }
}

impl ScanAt<'_> {
    /// The CLI keeps no notes, its anonymous sync reads every stream from index 0 under the store's lock.
    fn fetch<R: BlockingRpc, I: BlockingIndexer>(
        self,
        zolana: &Zolana<R, I>,
    ) -> Result<SpendableDecryptionResult> {
        let (keys, assets) = (self.keys, self.assets);
        let config = IndexerRpcConfig::at_slot(self.slot);
        let owned = UtxoScan::new(keys, assets.registry())
            .with_indexer_config(config)
            .fetch(zolana.indexer())?;
        let mut spendable = owned.spendable;
        let ring_notes = |assets: &RingAssets| {
            zolana.block_on(async {
                RingConfidentialScan::new(keys, assets)
                    .with_indexer_config(config)
                    .fetch(zolana.as_async().indexer(), &owned.history.transactions)
                    .await
                    .map_err(anyhow::Error::from)
            })
        };
        let mut notes = ring_notes(assets)?;
        if !notes.pending.is_empty() {
            notes = ring_notes(&(self.chain_assets)()?)?;
        }
        let notes = notes.owned.spendable();
        for utxo in notes.utxos() {
            if !spendable
                .utxos()
                .any(|held| held.utxo_hash == utxo.utxo_hash)
            {
                spendable.utxos_with_data.push(utxo.clone());
            }
        }
        spendable.unknown_asset_ids.extend(notes.unknown_asset_ids);
        spendable.unknown_mints.extend(notes.unknown_mints);
        let Some(store) = self.store else {
            return Ok(spendable);
        };
        let sync = |assets: &RingAssets, history: &ViewingHistory| {
            zolana.block_on(async {
                AnonymousSync::new(keys, assets)
                    .with_full_rescan()
                    .with_indexer_config(config)
                    .with_deposit_payload(zolana_ring_client::deposit_payload)
                    .fetch(zolana.as_async().indexer(), history)
                    .await
                    .map_err(anyhow::Error::from)
            })
        };
        let scan = store.update(|history| {
            let mut scan = sync(assets, history)?;
            // A note in a mint registered after the registry read opens under the chain's assets.
            if !scan.unmatched.is_empty()
                || !scan.decrypted.unknown_asset_ids.is_empty()
                || !scan.decrypted.unknown_mints.is_empty()
            {
                scan = sync(&(self.chain_assets)()?, history)?;
            }
            *history = scan.history.clone();
            Ok(scan)
        })?;
        let found = verify_owned(keys, &scan.decrypted)?
            .spendable()
            .with_transaction_keys(keys)?;
        let spent = &scan.decrypted.spent_nullifiers;
        for balance in &mut spendable.balances.assets {
            balance
                .utxos
                .retain(|held| !spent.contains(&held.nullifier));
            balance.amount = balance
                .utxos
                .iter()
                .fold(0, |sum, held| sum.saturating_add(held.utxo.amount));
        }
        spendable
            .utxos_with_data
            .retain(|held| !spent.contains(&held.nullifier));
        for utxo in found.utxos() {
            if !spendable
                .utxos()
                .any(|held| held.utxo_hash == utxo.utxo_hash)
            {
                spendable.utxos_with_data.push(utxo.clone());
            }
        }
        spendable.unknown_asset_ids.extend(found.unknown_asset_ids);
        spendable.unknown_mints.extend(found.unknown_mints);
        Ok(spendable)
    }
}

impl StoreLock {
    /// Owner-only, a crash leaves the previous contents whole.
    fn replace(&self, path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
        let part = path.with_added_extension("part");
        let _ = fs::remove_file(&part);
        create_new(&part, contents.as_ref(), Visibility::Secret)
            .with_context(|| format!("cannot write {}", part.display()))?;
        fs::rename(&part, path)
            .inspect_err(|_| {
                let _ = fs::remove_file(&part);
            })
            .with_context(|| format!("cannot write {}", path.display()))
    }
}

impl Context {
    pub fn anonymous_wallet_store(&self, keys: &ShieldedKeypair) -> AnonymousWalletStore {
        StoreLocation {
            dir: &self.path(Path::new(ANONYMOUS_RING_DIR)),
            keys,
        }
        .open()
    }
}

fn unix_now() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the system clock is before the Unix epoch")?
        .as_secs();
    Ok(i64::try_from(seconds)?)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use solana_address::Address;
    use spr_keypair::SigningKey;

    use super::*;

    pub(crate) const RING: Address = Address::new_from_array([4; 32]);

    pub(crate) fn keypair(seed: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
    }

    /// A keypair with a store no other test shares.
    pub(crate) struct Member {
        pub(crate) keys: ShieldedKeypair,
        pub(crate) store: AnonymousWalletStore,
        dir: PathBuf,
    }

    impl Member {
        pub(crate) fn new(seed: u8, test: &str) -> Self {
            let keys = keypair(seed);
            let dir =
                std::env::temp_dir().join(format!("ring-wallet-{test}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let store = StoreLocation {
                dir: &dir,
                keys: &keys,
            }
            .open();
            Self { keys, store, dir }
        }

        pub(crate) fn state_file(&self) -> PathBuf {
            self.store.path.clone()
        }
    }

    impl Drop for Member {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use zolana_ring_client::AnonymousError;

    use super::{
        fixtures::{keypair, Member},
        *,
    };

    #[test]
    fn a_new_store_starts_a_history_at_the_wallets_viewing_key() {
        let member = Member::new(1, "fresh");
        let fresh = member.store.load().unwrap();
        assert_eq!(fresh.entries().len(), 1);
        assert_eq!(
            fresh.current().viewing_pubkey(),
            member.keys.viewing_pubkey()
        );
        assert_eq!(fresh.current().tx_count(), 0);
        assert!(!member.state_file().exists(), "a load writes nothing");
    }

    #[test]
    fn a_foreign_or_older_store_is_refused() {
        let member = Member::new(1, "foreign");
        let path = member.state_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let other = ViewingHistory::new(keypair(2).viewing_pubkey(), 1);
        fs::write(&path, other.to_json()).unwrap();
        assert!(member.store.load().is_err(), "another viewing key");
        fs::write(&path, r#"{"version":4,"ring":"x"}"#).unwrap();
        let refused = member.store.load().unwrap_err();
        assert!(matches!(
            refused.downcast_ref::<AnonymousError>(),
            Some(AnonymousError::ViewingHistoryVersion { version: 4 })
        ));
    }

    #[test]
    fn a_commit_lands_only_on_the_history_it_was_built_from() {
        let member = Member::new(1, "commit");
        let keys = &member.keys;
        let loaded = member.store.load().unwrap();
        let first = loaded.sender_tag(keys).unwrap().history;
        member.store.commit(&loaded, first.clone()).unwrap();
        assert_eq!(member.store.load().unwrap(), first);
        let stale = loaded.sender_tag(keys).unwrap().history;
        let refused = member.store.commit(&loaded, stale).unwrap_err();
        assert!(refused.to_string().contains("moved"), "{refused}");
        assert_eq!(member.store.load().unwrap().current().tx_count(), 1);
    }

    #[test]
    fn concurrent_updates_keep_every_counter_step() {
        let member = Member::new(1, "concurrent");
        let (store, keys) = (&member.store, &member.keys);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(move || {
                    store
                        .update(|history| {
                            *history = history.request_tag(keys)?.history;
                            Ok(())
                        })
                        .unwrap()
                });
            }
        });
        assert_eq!(store.load().unwrap().current().request_count(), 16);
    }

    #[test]
    fn a_part_left_by_a_crashed_run_does_not_block_the_next_write() {
        let member = Member::new(1, "crashed-part");
        let path = member.state_file();
        let part = path.with_added_extension("part");
        let lock = member.store.lock().unwrap();
        fs::write(&part, b"torn").unwrap();
        lock.replace(&path, b"whole").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"whole");
        assert!(!part.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}

#[cfg(test)]
mod scan_tests;
