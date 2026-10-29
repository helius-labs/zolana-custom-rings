//! Delivered ring outputs opened into a wallet's decryption result, the pinned zolana scan skips scheme 10.

use std::collections::HashMap;

use custom_ring_interface::{
    ring_confidential_delivered_output_body, ring_owner_delivered_output, stream::SlotSecret,
    RING_DELIVERED_BODY_LEN,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_keypair::{shielded::ShieldedAddress, X25519Pubkey};
use spr_transaction::{
    DecryptionResult, DeriveRequest, Mint, OutputSlot, ShieldedKeys, ShieldedTransaction,
    TransactionError, WalletUtxo,
};
use zolana_ring_keys::{RingDeliveryRequest, RingKeys};
use zolana_ring_transaction::{
    is_contributory, RingAssets, RingDelivered, RingDeliveredNote, RingDeliveryOpening,
    RingUtxoOwner,
};

use crate::{exactly_one_each, AnonymousError};

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

/// A candidate whose rebuilt note matched its published commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDeliveredFind {
    /// Index into the candidates.
    pub candidate: usize,
    pub utxo_hash: [u8; 32],
    /// `None` while the note is held in the pending notes.
    pub mint: Option<Mint>,
    pub amount: u64,
}

/// A delivered note whose commitment no registered mint rebuilds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingUtxo {
    pub note: RingDeliveredNote,
    pub publication: Publication,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Publication {
    pub leaf_index: u64,
    pub slot: u64,
    pub tx_signature: Signature,
    pub slot_index: u32,
}

/// A pending note admitted by [`resolve_pending`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedUtxo {
    pub utxo: WalletUtxo,
    /// Its nullifier was among the spent ones before it was admitted.
    pub spent: bool,
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

impl PendingUtxo {
    /// `None` while no held asset rebuilds the commitment.
    pub fn resolve(&self, assets: &RingAssets) -> Result<Option<WalletUtxo>, AnonymousError> {
        Ok(self
            .note
            .resolve(assets)?
            .map(|mint| wallet_utxo(&self.note, mint, self.publication)))
    }
}

/// Scheme 11 leads its payload with the recipient key, scheme 10 tags the slot with it.
fn delivered_body(slot: &OutputSlot) -> Option<(&[u8; 32], &[u8; RING_DELIVERED_BODY_LEN])> {
    ring_owner_delivered_output(&slot.payload).or_else(|| {
        ring_confidential_delivered_output_body(&slot.payload).map(|body| (&slot.view_tag, body))
    })
}

/// Keeps every candidate whose body rebuilds its published commitment, both results unchanged on error.
pub fn extend_ring_delivered<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    decrypted: &mut DecryptionResult,
    pending: &mut Vec<PendingUtxo>,
    assets: &RingAssets,
    transactions: &[ShieldedTransaction],
    candidates: &[RingDeliveredCandidate<'_>],
) -> Result<Vec<RingDeliveredFind>, AnonymousError> {
    let address = shielded_keys.address()?;
    let mut opened = open_delivered(&address, assets, candidates)?;
    assign_nullifiers(shielded_keys, &mut opened.found)?;
    decrypted.utxos.extend(opened.found);
    sort_by_publication(&mut decrypted.utxos);
    decrypted.spent_nullifiers.extend(
        transactions
            .iter()
            .flat_map(|tx| tx.nullifiers.iter().copied()),
    );
    for waiting in opened.pending {
        if !pending
            .iter()
            .any(|held| held.note.utxo_hash == waiting.note.utxo_hash)
        {
            pending.push(waiting);
        }
    }
    Ok(opened.finds)
}

/// Admits every pending note the registry resolves, its spent state read before it joins the utxos.
pub fn resolve_pending<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    decrypted: &mut DecryptionResult,
    pending: &mut Vec<PendingUtxo>,
    assets: &RingAssets,
) -> Result<Vec<ResolvedUtxo>, AnonymousError> {
    let resolutions = pending
        .iter()
        .map(|waiting| waiting.resolve(assets))
        .collect::<Result<Vec<_>, _>>()?;
    let mut keep = resolutions
        .iter()
        .map(Option::is_none)
        .collect::<Vec<_>>()
        .into_iter();
    let mut admitted: Vec<WalletUtxo> = resolutions.into_iter().flatten().collect();
    // A failed step returns before any note leaves the pending notes.
    assign_nullifiers(shielded_keys, &mut admitted)?;
    pending.retain(|_| keep.next().unwrap_or(true));
    let resolved: Vec<ResolvedUtxo> = admitted
        .into_iter()
        .map(|utxo| ResolvedUtxo {
            spent: decrypted.spent_nullifiers.contains(&utxo.nullifier),
            utxo,
        })
        .collect();
    decrypted
        .utxos
        .extend(resolved.iter().map(|admitted| admitted.utxo.clone()));
    sort_by_publication(&mut decrypted.utxos);
    Ok(resolved)
}

/// Every scheme 10 or 11 slot delivered to one of the wallet's viewing keys.
pub fn confidential_delivered<'a, K: ShieldedKeys + RingKeys + ?Sized>(
    shielded_keys: &K,
    transactions: &'a [ShieldedTransaction],
) -> Result<Vec<RingDeliveredCandidate<'a>>, AnonymousError> {
    let held: HashMap<[u8; 32], X25519Pubkey> = shielded_keys
        .viewing_public_keys()
        .into_iter()
        .map(|pubkey| (pubkey.u(), pubkey))
        .collect();
    let mut sites = Vec::new();
    let mut requests = Vec::new();
    for tx in transactions {
        let Some(RingDeliveryContext {
            tx_viewing_pk,
            salt,
            first_nullifier,
            ..
        }) = RingDeliveryContext::of(tx)
        else {
            continue;
        };
        for (position, slot) in tx.output_slots.iter().enumerate() {
            let Some(&viewing_pubkey) = delivered_body(slot).and_then(|(u, _)| held.get(u)) else {
                continue;
            };
            let output_index =
                u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?;
            sites.push((tx, output_index));
            requests.push(RingDeliveryRequest {
                viewing_pubkey,
                tx_viewing_pk,
                salt,
                output_index,
                first_nullifier,
            });
        }
    }
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    let secrets = exactly_one_each(
        shielded_keys.ring_delivery_secrets(&requests)?,
        requests.len(),
    )?;
    sites
        .into_iter()
        .zip(secrets)
        .map(|((tx, slot_index), secret)| {
            Ok(RingDeliveredCandidate {
                tx,
                slot_index,
                slot_secret: SlotSecret::new(secret)?,
            })
        })
        .collect()
}

/// What [`open_delivered`] kept, the notes in a registered mint and the ones held back.
pub(crate) struct OpenedDelivered {
    pub(crate) found: Vec<WalletUtxo>,
    pub(crate) pending: Vec<PendingUtxo>,
    finds: Vec<RingDeliveredFind>,
}

/// Opens every candidate under its own slot secret, nothing is absorbed here.
pub(crate) fn open_delivered(
    address: &ShieldedAddress,
    assets: &RingAssets,
    candidates: &[RingDeliveredCandidate<'_>],
) -> Result<OpenedDelivered, AnonymousError> {
    let owner = RingUtxoOwner {
        signing_pubkey: &address.signing_pubkey,
        nullifier_pubkey: &address.nullifier_pubkey,
    };
    let mut opened = OpenedDelivered {
        found: Vec::new(),
        pending: Vec::new(),
        finds: Vec::new(),
    };
    for (index, candidate) in candidates.iter().enumerate() {
        let tx = candidate.tx;
        let Some(RingDeliveryContext { ring, .. }) = RingDeliveryContext::of(tx) else {
            continue;
        };
        let Some(slot) = tx.output_slots.get(candidate.slot_index as usize) else {
            continue;
        };
        let Some((_, body)) = delivered_body(slot) else {
            continue;
        };
        let context = &slot.output_context;
        let delivered = RingDeliveryOpening {
            ring,
            body,
            slot_secret: &candidate.slot_secret,
            owner,
            commitment: &context.hash,
            tree_id: context.tree_id,
        }
        .open(assets)?;
        let Some(RingDelivered { note, mint }) = delivered else {
            continue;
        };
        opened.finds.push(RingDeliveredFind {
            candidate: index,
            utxo_hash: note.utxo_hash,
            mint,
            amount: note.body.amount,
        });
        let publication = Publication {
            leaf_index: context.leaf_index,
            slot: tx.slot,
            tx_signature: tx.tx_signature,
            slot_index: candidate.slot_index,
        };
        match mint {
            Some(mint) => opened.found.push(wallet_utxo(&note, mint, publication)),
            None => opened.pending.push(PendingUtxo { note, publication }),
        }
    }
    Ok(opened)
}

fn wallet_utxo(note: &RingDeliveredNote, mint: Mint, publication: Publication) -> WalletUtxo {
    WalletUtxo {
        utxo: note.utxo(mint),
        nullifier_pubkey: note.nullifier_pubkey,
        utxo_hash: note.utxo_hash,
        nullifier: [0; 32],
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id: note.tree_id,
        leaf_index: publication.leaf_index,
        latest_tree_id: None,
        slot: publication.slot,
        tx_signature: publication.tx_signature,
        slot_index: publication.slot_index,
    }
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
    for (input, nullifier) in utxos.iter_mut().zip(nullifiers) {
        input.nullifier = nullifier;
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
