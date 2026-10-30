//! The anonymous rail's output blindings and the rebuild of a published output from its plaintext.

use solana_address::Address;
use spr_keypair::{
    constants::PUBLIC_KEY_LEN, x25519::X25519_PUBKEY_LEN, ShieldedAddress, X25519Pubkey,
};
use spr_transaction::{
    derive_output_blinding_seed, utxo::derive_transact_output_blinding, Blinding, Utxo,
};
use zeroize::Zeroizing;

use crate::{
    AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext, RingAssets,
    RingRailError,
};

/// The sender bundle's entry for an output no anonymous recipient reads.
pub const DUMMY_RECIPIENT_VIEWING_PK: [u8; X25519_PUBKEY_LEN] = {
    let mut key = [0u8; X25519_PUBKEY_LEN];
    key[0] = 0x04;
    key
};

/// A recipient plaintext with empty data, the length of every dummy body.
pub const RECIPIENT_BODY_LEN: usize = PUBLIC_KEY_LEN + 32 + 8 + X25519_PUBKEY_LEN + 32 + 1;

/// One published anonymous output, rebuilt from a plaintext and the reader's keys.
#[derive(Clone, Copy, Debug)]
pub struct AnonymousOutput<'a> {
    pub owner: &'a ShieldedAddress,
    pub assets: &'a RingAssets,
    pub ring: Address,
    pub tree_id: u16,
    pub utxo_hash: &'a [u8; 32],
}

/// `TXOB(first_nullifier, TXOS(first_nullifier, blinding_seed), position)` per output.
pub struct OutputBlindings {
    first_nullifier: [u8; 32],
    output_seed: Zeroizing<[u8; 32]>,
}

impl AnonymousOutput<'_> {
    /// `None` unless the plaintext names the reader as owner and rebuilds the hash.
    pub fn open_recipient(
        &self,
        plaintext: AnonymousTransferRecipientPlaintext,
    ) -> Result<Option<Utxo>, RingRailError> {
        if plaintext.verified.owner_pubkey != self.owner.signing_pubkey {
            return Ok(None);
        }
        let utxo = self.in_ring(plaintext.into_utxo(self.assets.registry())?);
        Ok(self.rebuilds(&utxo).then_some(utxo))
    }

    /// The bundle's change in output order, the change leading at output 0.
    pub fn sender_change(
        &self,
        plaintext: AnonymousTransferSenderPlaintext,
        first_nullifier: &[u8; 32],
    ) -> Result<Vec<Utxo>, RingRailError> {
        let change = plaintext.into_utxos(first_nullifier, self.assets.registry())?;
        Ok(change.into_iter().map(|utxo| self.in_ring(utxo)).collect())
    }

    /// Every anonymous output is the ring's, its plaintext names no ring.
    fn in_ring(&self, utxo: Utxo) -> Utxo {
        Utxo {
            ring_program_id: Some(self.ring),
            ..utxo
        }
    }

    /// Ring outputs commit to no data, a hashed record rebuilds nothing.
    pub fn rebuilds(&self, utxo: &Utxo) -> bool {
        utxo.data.ring_data().is_none()
            && utxo.data.utxo_data().is_none()
            && utxo
                .hash(
                    &self.owner.nullifier_pubkey,
                    &[0; 32],
                    &[0; 32],
                    self.tree_id,
                )
                .is_ok_and(|hash| hash == *self.utxo_hash)
    }
}

impl OutputBlindings {
    /// `blinding_seed` is the rail's `CRBS(tx_viewing_sk, salt)`.
    pub fn new(
        first_nullifier: &[u8; 32],
        blinding_seed: &[u8; 32],
    ) -> Result<Self, RingRailError> {
        Ok(Self {
            first_nullifier: *first_nullifier,
            output_seed: Zeroizing::new(derive_output_blinding_seed(
                first_nullifier,
                blinding_seed,
            )?),
        })
    }

    pub fn at(&self, position: u32) -> Result<Blinding, RingRailError> {
        Ok(derive_transact_output_blinding(
            &self.first_nullifier,
            &self.output_seed,
            position,
        )?)
    }

    /// The seed the sender bundle publishes, every change blinding derives from it.
    pub fn output_seed(&self) -> &[u8; 32] {
        &self.output_seed
    }
}

/// Dummy entries left out.
pub fn listed_recipients(
    plaintext: &AnonymousTransferSenderPlaintext,
) -> impl Iterator<Item = &X25519Pubkey> {
    plaintext
        .verified
        .recipient_viewing_pks
        .iter()
        .filter(|key| !is_dummy_recipient(key))
}

pub fn is_dummy_recipient(key: &X25519Pubkey) -> bool {
    *key.as_bytes() == DUMMY_RECIPIENT_VIEWING_PK
}
