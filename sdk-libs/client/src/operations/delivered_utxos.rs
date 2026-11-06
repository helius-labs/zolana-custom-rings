//! Slot secrets of the ring outputs under a wallet's viewing keys.

use custom_ring_interface::{
    ring_body_output,
    stream::{confidential_slot_tag, SlotSecret},
};
use solana_address::Address;
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_keypair::{NullifierKey, X25519Pubkey};
use spr_transaction::{
    DeriveRequest, ShieldedKeys, ShieldedTransaction, TransactionError, WalletUtxo,
};
use zolana_ring_keys::{RingKeys, RingTagFrame, RingTagKind, RingTagProbe};
use zolana_ring_transaction::is_contributory;

use crate::{exactly_one_each, is_zero_key, AnonymousError};

/// One delivered ring output and the slot secret its recipient agreed for it.
#[derive(Clone)]
pub struct RingDeliveredCandidate<'a> {
    pub tx: &'a ShieldedTransaction,
    pub slot_index: u32,
    pub slot_secret: SlotSecret,
}

/// What every delivered slot secret of one ring transaction binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDeliveryContext {
    pub ring: Address,
    pub tx_viewing_pk: X25519Pubkey,
    pub salt: [u8; 16],
    pub first_nullifier: [u8; 32],
}

impl RingDeliveryContext {
    /// `None` without a ring, a contributory key, a salt or a canonical first nullifier.
    #[must_use]
    pub fn of(tx: &ShieldedTransaction) -> Option<Self> {
        let context = Self {
            ring: tx.ring_program_id?,
            tx_viewing_pk: tx.tx_viewing_pk?,
            salt: tx.salt?,
            first_nullifier: *tx.nullifiers.first()?,
        };
        (is_contributory(&context.tx_viewing_pk)
            && is_canonical_bn254_scalar_be(&context.first_nullifier))
        .then_some(context)
    }
}

/// Ring body slots under the wallet's viewing keys.
pub fn confidential_delivered<'a, K: ShieldedKeys + RingKeys + ?Sized>(
    shielded_keys: &K,
    transactions: &'a [ShieldedTransaction],
) -> Result<Vec<RingDeliveredCandidate<'a>>, AnonymousError> {
    let held = shielded_keys.viewing_public_keys();
    let mut framed = Vec::new();
    let mut frames = Vec::new();
    for tx in transactions {
        let Some(context) = RingDeliveryContext::of(tx) else {
            continue;
        };
        for viewing_pubkey in &held {
            // 1. The tag is public, a frame names only a key whose tag a ring body publishes.
            let tag = confidential_slot_tag(viewing_pubkey.u());
            let probes = tx
                .output_slots
                .iter()
                .enumerate()
                .filter(|(_, slot)| {
                    slot.view_tag == tag && ring_body_output(&slot.payload).is_some()
                })
                .map(|(position, _)| {
                    Ok(RingTagProbe {
                        kind: RingTagKind::Confidential,
                        output_index: u32::try_from(position)
                            .map_err(|_| TransactionError::TooManyOutputs)?,
                        tag,
                    })
                })
                .collect::<Result<Vec<_>, AnonymousError>>()?;
            if probes.is_empty() {
                continue;
            }
            framed.push(tx);
            frames.push(RingTagFrame {
                viewing_pubkey: *viewing_pubkey,
                tx_viewing_pk: context.tx_viewing_pk,
                salt: context.salt,
                first_nullifier: context.first_nullifier,
                probes,
            });
        }
    }
    if frames.is_empty() {
        return Ok(Vec::new());
    }
    // 2. The holder answers each probe with its slot secret, one agreement per frame.
    let answers = exactly_one_each(shielded_keys.ring_tag_matches(&frames)?, frames.len())?;
    let mut candidates = Vec::new();
    for ((tx, frame), answers) in framed.into_iter().zip(&frames).zip(answers) {
        let answers = exactly_one_each(answers, frame.probes.len())?;
        candidates.extend(
            frame
                .probes
                .iter()
                .zip(answers)
                .filter_map(|(probe, secret)| {
                    secret.map(|slot_secret| RingDeliveredCandidate {
                        tx,
                        slot_index: probe.output_index,
                        slot_secret,
                    })
                }),
        );
    }
    Ok(candidates)
}

pub(crate) fn assign_nullifiers<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    utxos: &mut [WalletUtxo],
) -> Result<(), AnonymousError> {
    if utxos.is_empty() {
        return Ok(());
    }
    let requests: Vec<_> = utxos
        .iter()
        .map(|input| DeriveRequest::Nullifier {
            utxo_hash: input.utxo_hash,
            blinding: input.utxo.blinding,
        })
        .collect();
    let nullifiers = exactly_one_each(shielded_keys.derive(&requests)?, utxos.len())?;
    let zero_secret = NullifierKey::from_secret([0; 31]);
    for (input, nullifier) in utxos.iter_mut().zip(nullifiers) {
        // A zero-key note spends under secret zero, never the wallet's.
        input.nullifier = match is_zero_key(input) {
            true => zero_secret.nullifier(&input.utxo_hash, &input.utxo.blinding)?,
            false => nullifier,
        };
    }
    Ok(())
}

/// Mirrors spr-transaction's private publication order.
pub(crate) fn sort_by_publication(utxos: &mut [WalletUtxo]) {
    utxos.sort_by_key(|utxo| {
        (
            utxo.slot,
            utxo.tx_signature.as_ref().to_vec(),
            utxo.slot_index,
        )
    });
}
