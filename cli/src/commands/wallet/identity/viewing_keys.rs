//! `key rotate`, a new viewing key in the member's tracking authorization, and the key holder every
//! wallet command loads.
//!
//! Read before `wallet`. Read after `custom_ring_sdk::RotateViewingKey`.
//!
//! Each rotated key is an owner-only `<n>.key` file, never overwritten, the newest current and every
//! earlier one retained. The anonymous wallet store stays keyed by the identity key.

use std::path::{Path, PathBuf};

use anyhow::{ensure, Context as _, Result};
use custom_ring_sdk::RotateViewingKey;
use solana_signer::Signer;
use spr_keypair::{ShieldedKeypair, ViewingKey};
use spr_transaction::ShieldedKeys;
use zolana_ring_client::ViewingRotation;
use zolana_ring_keys::RotatingRingKeys;
use zolana_secret_file::{create_key32, read_key32, Access};

use crate::{line, member::authorization, wallet::unix_now, Context};

/// Under the `keys/` that `new` writes into `.gitignore`, one directory per owner.
pub const ROTATED_VIEWING_KEY_DIR: &str = "keys/viewing-keys";

struct RotatedKeys {
    dir: PathBuf,
}

impl Context {
    /// The identity key and every rotated key of `identity`, the newest current.
    pub fn ring_keys(&self, identity: &ShieldedKeypair) -> Result<RotatingRingKeys> {
        RotatedKeys::of(self, identity).holder(identity)
    }
}

pub fn rotate(ctx: &Context) -> Result<()> {
    let config = ctx.ring_config()?;
    let owner = ctx.sender()?;
    let identity = ShieldedKeypair::from_keypair(&owner)?;
    let rotated = RotatedKeys::of(ctx, &identity);
    let keys = rotated.holder(&identity)?;
    let published = authorization(ctx.ring, &ctx.zolana, &identity)?
        .context("the sender has no tracking authorization, enroll before a rotation")?
        .viewing_u;
    // 1. An authorization key the wallet never held is another copy's, publishing over it strands its payments.
    ensure!(
        keys.viewing_public_keys()
            .iter()
            .any(|key| key.u() == published),
        "the tracking authorization names a viewing key the wallet does not hold"
    );
    let store = ctx.anonymous_wallet_store(identity.viewing_pubkey());
    let rotation = if published == keys.address()?.viewing_pubkey.u() {
        // 2. The secret file lands before the history and the authorization name its key, a
        //    stopped run still holds it.
        let next = ViewingKey::new();
        rotated.store(&next)?;
        store.update(|wallet| {
            let rotation = ViewingRotation {
                keys,
                history: wallet.history().clone(),
            }
            .rotate(next, unix_now()?)?;
            wallet.update_history(rotation.history.clone())?;
            Ok(rotation)
        })?
    } else {
        // 3. An older held key in the authorization marks a stopped run, whose newest file joins
        //    the history and publishes before any new key.
        store.update(|wallet| {
            let current = keys.address()?.viewing_pubkey;
            if wallet.history().entry(&current).is_none() {
                let caught_up = wallet
                    .history()
                    .clone()
                    .with_rotated_key(current, unix_now()?)?;
                wallet.update_history(caught_up)?;
            }
            Ok(ViewingRotation {
                keys,
                history: wallet.history().clone(),
            })
        })?
    };
    let sent = ctx.block(
        RotateViewingKey {
            ring: ctx.ring,
            owner: &owner,
            payer: ctx.member_payer(config.mode, owner.pubkey())?,
            keys: &rotation.keys,
            history: &rotation.history,
        }
        .send(ctx.ring_client()),
    )?;
    line("viewing key", hex::encode(sent.viewing_pubkey.as_bytes()));
    match sent.signature {
        Some(signature) => line("tracking rotation", signature),
        None => line("tracking authorization", "already current"),
    }
    Ok(())
}

impl RotatedKeys {
    fn of(ctx: &Context, identity: &ShieldedKeypair) -> Self {
        Self {
            dir: ctx
                .path(Path::new(ROTATED_VIEWING_KEY_DIR))
                .join(identity.pubkey().to_string()),
        }
    }

    fn holder(&self, identity: &ShieldedKeypair) -> Result<RotatingRingKeys> {
        let mut keys = RotatingRingKeys::new(identity)?;
        for path in self.stored() {
            let secret = read_key32(&path, Access::OwnerOnly)?;
            let next = ViewingKey::from_canonical_bytes(&secret)
                .with_context(|| format!("{} holds no viewing key", path.display()))?;
            keys = keys.rotate(next)?;
        }
        Ok(keys)
    }

    fn store(&self, next: &ViewingKey) -> Result<()> {
        let path = self.path(self.stored().count() + 1);
        Ok(create_key32(&path, &next.secret_bytes())?)
    }

    /// Oldest first, a gap ends the rotations.
    fn stored(&self) -> impl Iterator<Item = PathBuf> + '_ {
        (1..)
            .map(|rotation| self.path(rotation))
            .take_while(|path| path.exists())
    }

    fn path(&self, rotation: usize) -> PathBuf {
        self.dir.join(format!("{rotation}.key"))
    }
}

#[cfg(test)]
mod tests {
    use spr_transaction::{DecryptLabel, DecryptRequest};

    use super::*;
    use crate::wallet::fixtures::keypair;

    struct Dir(PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn rotated(test: &str) -> (RotatedKeys, Dir) {
        let dir = std::env::temp_dir().join(format!("ring-viewing-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (RotatedKeys { dir: dir.clone() }, Dir(dir))
    }

    #[test]
    fn the_holder_takes_the_newest_file_as_current_and_opens_a_note_to_the_identity_key() {
        let (rotated, _dir) = rotated("holder");
        let identity = keypair(1);
        let (first, second) = (ViewingKey::new(), ViewingKey::new());
        rotated.store(&first).unwrap();
        rotated.store(&second).unwrap();
        let keys = rotated.holder(&identity).unwrap();
        assert_eq!(keys.address().unwrap().viewing_pubkey, second.pubkey());
        assert_eq!(keys.identity_viewing_pubkey(), identity.viewing_pubkey());
        let (tx, old) = (ViewingKey::new(), identity.viewing_pubkey());
        let ciphertext = tx.encrypt_slot(&old, b"old note", [5; 16], 0).unwrap();
        let opened = keys.decrypt(&[DecryptRequest {
            ciphertext: &ciphertext,
            viewing_pubkey: old,
            tx_viewing_pubkey: tx.pubkey(),
            salt: [5; 16],
            slot_index: 0,
            label: DecryptLabel::Utxo,
        }]);
        assert_eq!(opened.unwrap(), [b"old note".to_vec()]);
    }

    #[test]
    fn a_secret_no_viewing_key_derives_is_refused() {
        let (rotated, _dir) = rotated("refused");
        let identity = keypair(2);
        rotated.store(&ViewingKey::new()).unwrap();
        let mut unclamped = [0x41; 32];
        unclamped[31] = 0xff;
        create_key32(&rotated.path(2), &unclamped).unwrap();
        assert!(rotated.holder(&identity).is_err());
    }
}
