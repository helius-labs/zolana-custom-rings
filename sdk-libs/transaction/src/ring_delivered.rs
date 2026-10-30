//! Delivered ring output bodies of scheme 10, `be32(blinding) ‖ u64be(amount)` under the
//! audit stream of a CRDS slot secret, mirrored by Go `prover/circuits/audit`.

use custom_ring_interface::{stream::SlotSecret, AUDIT_STREAM_INFO, RING_DELIVERED_BODY_LEN};
use solana_address::Address;
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_keypair::{PublicKey, X25519Keypair, X25519Pubkey};
use spr_transaction::{Blinding, Data, Mint, Utxo};
use zolana_ring_keys::symmetric_apply_audit;

use crate::{RingAssets, RingRailError};

/// The opening a delivered body carries, the commitment picks its asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDeliveredBody {
    pub blinding: Blinding,
    pub amount: u64,
}

impl RingDeliveredBody {
    /// One slot secret keys one body, the secret binds the slot and the first nullifier.
    pub fn seal(
        &self,
        slot_secret: &SlotSecret,
    ) -> Result<[u8; RING_DELIVERED_BODY_LEN], RingRailError> {
        let mut body = [0u8; RING_DELIVERED_BODY_LEN];
        let (blinding, amount) = body.split_at_mut(32);
        blinding.copy_from_slice(&self.blinding);
        amount.copy_from_slice(&self.amount.to_be_bytes());
        symmetric_apply_audit(slot_secret.as_bytes(), AUDIT_STREAM_INFO, &mut body)?;
        Ok(body)
    }

    /// The cipher is unauthenticated, only the rebuilt commitment tells a body of another key.
    pub fn open(
        body: &[u8; RING_DELIVERED_BODY_LEN],
        slot_secret: &SlotSecret,
    ) -> Result<Self, RingRailError> {
        let mut plaintext = *body;
        symmetric_apply_audit(slot_secret.as_bytes(), AUDIT_STREAM_INFO, &mut plaintext)?;
        let (blinding, amount) = plaintext.split_at(32);
        Ok(Self {
            blinding: core::array::from_fn(|i| blinding[i]),
            amount: u64::from_be_bytes(core::array::from_fn(|i| amount[i])),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingUtxoOwner<'a> {
    pub signing_pubkey: &'a PublicKey,
    pub nullifier_pubkey: &'a [u8; 32],
}

/// One published delivered body and the secret its recipient agreed for it.
#[derive(Clone, Copy)]
pub struct RingDeliveryOpening<'a> {
    pub ring: Address,
    pub body: &'a [u8; RING_DELIVERED_BODY_LEN],
    pub slot_secret: &'a SlotSecret,
    pub owner: RingUtxoOwner<'a>,
    /// The published commitment and the tree it was appended to.
    pub commitment: &'a [u8; 32],
    pub tree_id: u16,
}

/// A delivered note opened to everything its commitment binds but the asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingDeliveredNote {
    pub owner: PublicKey,
    pub nullifier_pubkey: [u8; 32],
    pub ring: Address,
    pub body: RingDeliveredBody,
    pub utxo_hash: [u8; 32],
    pub tree_id: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingDelivered {
    pub note: RingDeliveredNote,
    /// `None` while no held asset rebuilds the commitment.
    pub mint: Option<Mint>,
}

impl RingDeliveryOpening<'_> {
    /// `None` for a blinding outside the field or a zero amount in no held asset.
    pub fn open(self, assets: &RingAssets) -> Result<Option<RingDelivered>, RingRailError> {
        let body = RingDeliveredBody::open(self.body, self.slot_secret)?;
        if !is_canonical_bn254_scalar_be(&body.blinding) {
            return Ok(None);
        }
        let note = RingDeliveredNote {
            owner: *self.owner.signing_pubkey,
            nullifier_pubkey: *self.owner.nullifier_pubkey,
            ring: self.ring,
            body,
            utxo_hash: *self.commitment,
            tree_id: self.tree_id,
        };
        let mint = note.resolve(assets)?;
        Ok((mint.is_some() || note.body.amount != 0).then_some(RingDelivered { note, mint }))
    }
}

impl RingDeliveredNote {
    pub fn resolve(&self, assets: &RingAssets) -> Result<Option<Mint>, RingRailError> {
        for mint in assets.mints() {
            let utxo = self.utxo(*mint);
            let hash = utxo.hash(&self.nullifier_pubkey, &[0; 32], &[0; 32], self.tree_id)?;
            if hash == self.utxo_hash {
                return Ok(Some(*mint));
            }
        }
        Ok(None)
    }

    pub fn utxo(&self, asset: Mint) -> Utxo {
        Utxo {
            owner: self.owner,
            asset,
            amount: self.body.amount,
            blinding: self.body.blinding,
            ring_program_id: Some(self.ring),
            data: Data::default(),
        }
    }
}

/// False for a low-order transaction key, every clamped secret refuses the same keys.
pub fn is_contributory(tx_viewing_pk: &X25519Pubkey) -> bool {
    X25519Keypair::from_bytes(&[0; 32])
        .ecdh(tx_viewing_pk)
        .is_ok()
}
