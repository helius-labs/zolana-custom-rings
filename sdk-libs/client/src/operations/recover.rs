//! Rebuilds a source member's unspent ring notes from what the auditor sees, one history page at a time.

use std::{
    collections::{BTreeSet, HashSet},
    num::{NonZeroU32, NonZeroUsize},
};

use custom_ring_interface::RingMode;
use solana_address::Address;
use spr_client::{AsyncRpc, IndexerRpcConfig};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{hash::owner_hash, NullifierKey, ShieldedAddress, X25519Keypair};
use spr_transaction::{
    instructions::merge::{
        merge_circuit_width, merge_output_blinding, merge_output_key, MergeOutputPlaintext,
    },
    Data, OutputContext, ShieldedTransaction, TransactionError, Utxo, WalletUtxo,
};
use zolana_ring_transaction::RingAssets;

use crate::{
    confirmed_merge,
    decrypt::TransactionAudit,
    history::HistoryCursor,
    merge_audit::RingMergeBody,
    origin::{ConfirmedEventKind, RingOrigin, TransactionOrigin},
    scan::{RingHistory, SkippedRow, RING_HISTORY_MAX_PAGES, RING_HISTORY_PAGE_SIZE},
    types::{OutputOpening, OutputPayloadErrorKind},
    AuditError, MergeLedger,
};

pub const RECOVERY_INPUT_SAMPLE_LIMIT: usize = 64;

type HistoryRow = (ShieldedTransaction, RingOrigin);

#[must_use = "run the recovery explicitly"]
pub struct RingRecovery<'a> {
    ring_program_id: Address,
    auditor: &'a X25519Keypair,
    mode: RingMode,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

pub struct SourceMember<'a> {
    pub address: &'a ShieldedAddress,
    pub nullifier_key: &'a NullifierKey,
}

#[must_use = "run the recovery explicitly"]
pub struct MemberRecovery<'a> {
    recovery: RingRecovery<'a>,
    source: SourceMember<'a>,
    progress: Option<RecoveryProgress>,
}

#[must_use = "resume a paused recovery or read its notes"]
pub enum RecoveryStep {
    Complete(RecoveredNotes),
    Paused(RecoveryProgress),
}

/// The recovery state of every page read, resumed after `cursor` and never before it.
#[derive(Clone)]
pub struct RecoveryProgress {
    cursor: HistoryCursor,
    /// The source's owner hash, the ring stays bound through `cursor`.
    member: [u8; 32],
    state: Box<RecoveryState>,
}

/// Application commitments supplied by the note's protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct UtxoDataHashes {
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
}

/// Verified unspent notes with the coverage left unresolved.
pub struct RecoveredNotes {
    pub utxos: Vec<WalletUtxo>,
    /// Commitments that cannot yet become spendable notes, including unknown mints.
    pub unopened: Vec<[u8; 32]>,
    /// Verified merge mints the asset registry lacks, their notes stay unresolved.
    pub unknown_mints: BTreeSet<Address>,
    /// Up to `RECOVERY_INPUT_SAMPLE_LIMIT` unmatched nullifiers of frames that spent an unopened
    /// note, addresses and padding among them.
    pub unseen_inputs: Vec<[u8; 32]>,
    /// Spent notes no batch opened, each frame's `R` less its matched nullifiers.
    pub unseen_input_count: u64,
}

impl<'a> RingRecovery<'a> {
    pub fn new(ring_program_id: Address, auditor: &'a X25519Keypair) -> Self {
        Self {
            ring_program_id,
            auditor,
            mode: RingMode::Confidential,
            page_size: RING_HISTORY_PAGE_SIZE,
            max_pages: RING_HISTORY_MAX_PAGES,
            indexer_config: None,
        }
    }

    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    /// The rail a ring `Transact` frame parses under.
    pub fn with_mode(mut self, mode: RingMode) -> Self {
        self.mode = mode;
        self
    }

    /// Pages one call reads before it pauses.
    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    /// An indexer behind `config.require_slot` would report a spent note as unspent.
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    pub fn for_member(self, source: SourceMember<'a>) -> MemberRecovery<'a> {
        MemberRecovery {
            recovery: self,
            source,
            progress: None,
        }
    }
}

impl RecoveryProgress {
    /// Prints as the TS `RingRecoveryProgress.cursor`.
    pub fn cursor(&self) -> HistoryCursor {
        self.cursor
    }
}

impl SourceMember<'_> {
    /// The key a note of `owner` sits under, `None` for another owner.
    fn nullifier_pk_of(&self, owner: [u8; 32]) -> Result<Option<[u8; 32]>, AuditError> {
        // A zero-key note of the member's signing key is still the member's note.
        for nullifier_pk in [self.address.nullifier_pubkey, ZERO_NULLIFIER_PUBKEY] {
            if owner_hash(&self.address.signing_pubkey, &nullifier_pk)? == owner {
                return Ok(Some(nullifier_pk));
            }
        }
        Ok(None)
    }

    /// A zero-key note's nullifier needs no secret, anyone with the opening derives it.
    fn nullifier(
        &self,
        nullifier_pk: &[u8; 32],
        commitment: &[u8; 32],
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], AuditError> {
        let zero_key;
        let key = if *nullifier_pk == ZERO_NULLIFIER_PUBKEY {
            zero_key = NullifierKey::from_secret([0; 31]);
            &zero_key
        } else {
            self.nullifier_key
        };
        Ok(key.nullifier(commitment, blinding)?)
    }

    /// The UTXO at `context` under `nullifier_pk` and whether it reproduces the leaf there.
    fn wallet_utxo(
        &self,
        utxo: Utxo,
        nullifier_pk: [u8; 32],
        context: &OutputContext,
        hashes: UtxoDataHashes,
        tx: &ShieldedTransaction,
        slot_index: u32,
    ) -> Result<(WalletUtxo, bool), AuditError> {
        let commitment = utxo.hash(
            &nullifier_pk,
            &hashes.data_hash.unwrap_or_default(),
            &hashes.ring_data_hash.unwrap_or_default(),
            context.tree_id,
        )?;
        let held = WalletUtxo {
            nullifier: self.nullifier(&nullifier_pk, &context.hash, &utxo.blinding)?,
            utxo,
            nullifier_pubkey: nullifier_pk,
            utxo_hash: context.hash,
            tx_viewing_key: None,
            data_hash: hashes.data_hash,
            ring_data_hash: hashes.ring_data_hash,
            tree_id: context.tree_id,
            leaf_index: context.leaf_index,
            latest_tree_id: None,
            slot: tx.slot,
            tx_signature: tx.tx_signature,
            slot_index,
        };
        Ok((held, commitment == context.hash))
    }

    fn utxo(&self, asset: spr_transaction::Mint, amount: u64, blinding: [u8; 32]) -> Utxo {
        Utxo {
            owner: self.address.signing_pubkey,
            asset,
            amount,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        }
    }
}

/// One frame's `R` and every nullifier it published, the proof names no note position.
#[derive(Clone)]
struct FrameSpends {
    real_inputs: u8,
    nullifiers: Vec<[u8; 32]>,
}

/// Notes found so far, by the commitments already claimed.
#[derive(Clone, Default)]
struct Found {
    candidates: Vec<WalletUtxo>,
    /// Commitments without a verified opening, with their nullifiers.
    unresolved: Vec<([u8; 32], [u8; 32])>,
    seen: HashSet<[u8; 32]>,
    unknown_mints: BTreeSet<Address>,
    /// The batch's spends in history order.
    spends: Vec<FrameSpends>,
}

#[derive(Clone, Default)]
struct RecoveryState {
    found: Found,
    unseen_inputs: Vec<[u8; 32]>,
    unseen_input_count: u64,
    unopened_merges: Vec<[u8; 32]>,
    /// The indexer orders one slot by signature, a later row of the slot can create the note an earlier row spends.
    open_slot: Vec<HistoryRow>,
}

impl RecoveryState {
    /// Rows of every slot below the last one read.
    fn close_slots(&mut self) -> Vec<HistoryRow> {
        let Some(last) = self.open_slot.iter().map(|(row, _)| row.slot).max() else {
            return Vec::new();
        };
        let (closed, open) = std::mem::take(&mut self.open_slot)
            .into_iter()
            .partition(|(row, _)| row.slot < last);
        self.open_slot = open;
        closed
    }

    fn finish(self) -> RecoveredNotes {
        let Self {
            found,
            unseen_inputs,
            unseen_input_count,
            unopened_merges,
            ..
        } = self;
        RecoveredNotes {
            utxos: found.candidates,
            unopened: found
                .unresolved
                .into_iter()
                .map(|(commitment, _)| commitment)
                .chain(unopened_merges)
                .collect(),
            unknown_mints: found.unknown_mints,
            unseen_inputs,
            unseen_input_count,
        }
    }
}

impl Found {
    fn nullifiers(&self) -> HashSet<[u8; 32]> {
        self.candidates
            .iter()
            .map(|note| note.nullifier)
            .chain(self.unresolved.iter().map(|(_, nullifier)| *nullifier))
            .collect()
    }
}

impl<'a> MemberRecovery<'a> {
    /// Continues after the last page `progress` covers.
    pub fn with_progress(mut self, progress: RecoveryProgress) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Applies each closed slot as its page lands and pauses at the page cap.
    pub async fn run<I: AsyncRpc, O: TransactionOrigin>(
        mut self,
        indexer: &I,
        origin: &O,
        assets: &RingAssets,
    ) -> Result<RecoveryStep, AuditError> {
        // The nullifier key must derive the requested address.
        if self.source.nullifier_key.pubkey()? != self.source.address.nullifier_pubkey {
            return Err(AuditError::NullifierKeyMismatch);
        }
        let RingRecovery {
            ring_program_id,
            page_size,
            max_pages,
            indexer_config,
            ..
        } = self.recovery;
        let member = owner_hash(
            &self.source.address.signing_pubkey,
            &self.source.address.nullifier_pubkey,
        )?;
        let (mut cursor, mut state) = match self.progress.take() {
            Some(progress) if progress.member != member => {
                return Err(AuditError::RecoveryProgressMismatch)
            }
            Some(RecoveryProgress { cursor, state, .. }) => (Some(cursor), state),
            None => (None, Box::default()),
        };
        let mut pages_read = 0;
        loop {
            // 1. One page at a time, the cursor names the last row read and the next call starts after it.
            let page = RingHistory {
                ring: ring_program_id,
                kinds: &[ConfirmedEventKind::Merge, ConfirmedEventKind::Transfer],
                cursor,
                page_size,
                max_pages: NonZeroUsize::MIN,
                indexer_config,
            }
            .bound(indexer, origin)
            .await?;
            refuse_skipped(page.skipped)?;
            state.open_slot.extend(page.transactions);
            let rows = state.close_slots();
            self.apply(&rows, assets, &mut state)?;
            // 2. The terminal page closes the last slot, a page with more holds it back.
            let Some(next) = page.next_cursor else {
                let rows = std::mem::take(&mut state.open_slot);
                self.apply(&rows, assets, &mut state)?;
                return Ok(RecoveryStep::Complete(state.finish()));
            };
            pages_read += 1;
            if pages_read == max_pages.get() {
                return Ok(RecoveryStep::Paused(RecoveryProgress {
                    cursor: next,
                    member,
                    state,
                }));
            }
            cursor = Some(next);
        }
    }

    /// Rows of closed slots, every note one of them spends opens in them or in an earlier batch.
    fn apply(
        &self,
        rows: &[HistoryRow],
        assets: &RingAssets,
        state: &mut RecoveryState,
    ) -> Result<(), AuditError> {
        let recovery = &self.recovery;
        let RecoveryState {
            found,
            unseen_inputs,
            unseen_input_count,
            unopened_merges,
            ..
        } = state;
        // 1. A merge record opens its own row's output alone, a batch ledger loses no opening.
        let mut ledger = MergeLedger::default();
        for (transaction, confirmed) in rows {
            if confirmed.event.kind() == ConfirmedEventKind::Merge {
                let event_index = transaction
                    .event_index
                    .ok_or(AuditError::MissingEventIndex)?;
                if let Some(merge) =
                    confirmed_merge(transaction, event_index, confirmed, recovery.auditor)?
                {
                    ledger.apply(merge);
                }
            }
        }
        // 2. Outputs before spends, the batch's merges and inputs need the notes they consume.
        for row in rows {
            if row.1.requires_audit() {
                self.audited_utxos(row, assets, found)?;
            }
        }
        let merges = MergeRecovery {
            ring: recovery.ring_program_id,
            history: rows,
            ledger: &ledger,
            assets,
            found,
        }
        .recover(&self.source)?;
        let opened_nullifiers = found.nullifiers();
        for spends in std::mem::take(&mut found.spends) {
            let (matched, unmatched): (Vec<_>, Vec<_>) = spends
                .nullifiers
                .into_iter()
                .partition(|nullifier| opened_nullifiers.contains(nullifier));
            let unseen = usize::from(spends.real_inputs).saturating_sub(matched.len());
            if unseen == 0 {
                continue;
            }
            *unseen_input_count = unseen_input_count.saturating_add(unseen as u64);
            let room = RECOVERY_INPUT_SAMPLE_LIMIT.saturating_sub(unseen_inputs.len());
            unseen_inputs.extend(unmatched.into_iter().take(room));
        }
        unopened_merges.extend(
            merges
                .iter()
                .map(|merge| merge.output_slots[0].output_context.hash)
                .filter(|commitment| !found.seen.contains(commitment)),
        );
        // 3. No later batch creates a note these rows spend, the spent notes leave the state.
        let spent = rows
            .iter()
            .flat_map(|(transaction, _)| transaction.nullifiers.iter().copied())
            .collect::<HashSet<_>>();
        found
            .candidates
            .retain(|candidate| !spent.contains(&candidate.nullifier));
        found
            .unresolved
            .retain(|(_, nullifier)| !spent.contains(nullifier));
        Ok(())
    }

    /// The source's ring outputs in one audited transaction, every opening already proof-bound.
    fn audited_utxos(
        &self,
        (transaction, origin): &HistoryRow,
        assets: &RingAssets,
        found: &mut Found,
    ) -> Result<(), AuditError> {
        let frame = origin.audit_frame(self.recovery.mode)?;
        let audited = TransactionAudit::new(transaction, frame).run(self.recovery.auditor)?;
        found.spends.push(FrameSpends {
            real_inputs: audited.real_inputs,
            nullifiers: audited.nullifiers.clone(),
        });
        // An unopened record could hide a source UTXO, a payload error keeps its record.
        if let Some(error) = audited
            .payload_errors
            .iter()
            .find(|error| error.kind != OutputPayloadErrorKind::Payload)
        {
            return Err(AuditError::UnopenedOutput {
                slot: error.slot_index,
                kind: error.kind,
            });
        }
        for output in &audited.outputs {
            let OutputOpening::Ring { utxo: opened, .. } = &output.opening else {
                continue;
            };
            let context = &output.context;
            let Some(nullifier_pk) = self.source.nullifier_pk_of(opened.owner_hash()?)? else {
                continue;
            };
            if !found.seen.insert(context.hash) {
                continue;
            }
            let mint = match opened
                .mint
                .map(|mint| assets.registry().mint(&mint))
                .transpose()
            {
                Ok(mint) => mint,
                Err(TransactionError::UnknownMint(mint)) => {
                    found.unknown_mints.insert(mint);
                    None
                }
                Err(error) => return Err(error.into()),
            };
            let data = opened.data_hash.zip(opened.ring_data_hash);
            let Some((mint, (data_hash, ring_data_hash))) = mint.zip(data) else {
                // Ownership and spentness remain known even without the asset or data preimage.
                found.unresolved.push((
                    context.hash,
                    self.source
                        .nullifier(&nullifier_pk, &context.hash, &opened.blinding)?,
                ));
                continue;
            };
            let hashes = UtxoDataHashes {
                data_hash: Some(data_hash).filter(|hash| *hash != [0; 32]),
                ring_data_hash: Some(ring_data_hash).filter(|hash| *hash != [0; 32]),
            };
            let utxo = Utxo {
                ring_program_id: Some(self.recovery.ring_program_id),
                ..self.source.utxo(mint, opened.amount, opened.blinding)
            };
            match self.source.wallet_utxo(
                utxo,
                nullifier_pk,
                context,
                hashes,
                transaction,
                output.slot_index,
            )? {
                (held, true) => found.candidates.push(held),
                (held, false) => found.unresolved.push((context.hash, held.nullifier)),
            }
        }
        Ok(())
    }
}

struct MergeRecovery<'a, 'h> {
    ring: Address,
    history: &'h [HistoryRow],
    ledger: &'a MergeLedger,
    assets: &'a RingAssets,
    found: &'a mut Found,
}

impl<'h> MergeRecovery<'_, 'h> {
    fn recover(
        self,
        source: &SourceMember<'_>,
    ) -> Result<Vec<&'h ShieldedTransaction>, AuditError> {
        let Self {
            ring,
            history,
            ledger,
            assets,
            found,
        } = self;
        let merges: Vec<_> = history
            .iter()
            .filter(|(transaction, origin)| {
                origin.event.kind() == ConfirmedEventKind::Merge
                    && transaction.output_slots.len() == 1
                    && merge_circuit_width(transaction.nullifiers.len()).is_some()
            })
            .map(|(transaction, _)| transaction)
            .collect();
        loop {
            let previous = found.seen.len();
            let source_nullifiers = found.nullifiers();
            for transaction in &merges {
                let output = &transaction.output_slots[0].output_context;
                if found.seen.contains(&output.hash) {
                    continue;
                }
                let successor = match ledger.output(&output.hash) {
                    // 1. A sealed record opens its output without input history, the only path to a zero-key merge.
                    Some(merged) => {
                        let owner =
                            source.nullifier_pk_of(merged.owner.hash(&merged.owner_key)?)?;
                        match owner {
                            Some(nullifier_pk) => {
                                let opening = merged.opening()?;
                                // The record rebuild checked the commitment, the leaf check adds nothing.
                                let (note, _) = source.wallet_utxo(
                                    Utxo {
                                        ring_program_id: Some(ring),
                                        ..source.utxo(
                                            spr_transaction::Mint::new(merged.mint, 0),
                                            opening.amount,
                                            opening.blinding,
                                        )
                                    },
                                    nullifier_pk,
                                    output,
                                    UtxoDataHashes {
                                        data_hash: None,
                                        ring_data_hash: opening.ring_data_hash,
                                    },
                                    transaction,
                                    0,
                                )?;
                                Some(note)
                            }
                            // 2. Another owner's record, the member's spends alone never claim its output.
                            None => None,
                        }
                    }
                    // 3. With no record, only a merge spending a source note opens under the nullifier key.
                    None if transaction
                        .nullifiers
                        .iter()
                        .any(|nullifier| source_nullifiers.contains(nullifier)) =>
                    {
                        merge_successor(source, transaction, ring)?
                    }
                    None => None,
                };
                let Some(mut note) = successor else {
                    continue;
                };
                found.seen.insert(output.hash);
                match assets.registry().mint(&note.utxo.asset.asset) {
                    Ok(mint) => {
                        note.utxo.asset = mint;
                        found.candidates.push(note);
                    }
                    Err(TransactionError::UnknownMint(mint)) => {
                        found.unknown_mints.insert(mint);
                        found.unresolved.push((note.utxo_hash, note.nullifier));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if found.seen.len() == previous {
                break;
            }
        }
        let source_nullifiers = found.nullifiers();
        Ok(merges
            .into_iter()
            .filter(|transaction| {
                found
                    .seen
                    .contains(&transaction.output_slots[0].output_context.hash)
                    || transaction
                        .nullifiers
                        .iter()
                        .any(|nullifier| source_nullifiers.contains(nullifier))
            })
            .collect())
    }
}

/// A row left unread can hold a source note or its spend, the result would not be complete.
fn refuse_skipped(skipped: Vec<SkippedRow>) -> Result<(), AuditError> {
    match skipped.into_iter().next() {
        Some(row) => Err(row.error),
        None => Ok(()),
    }
}

/// A temporary asset id verifies the commitment before the registry lookup.
fn merge_successor(
    source: &SourceMember<'_>,
    transaction: &ShieldedTransaction,
    ring: Address,
) -> Result<Option<WalletUtxo>, AuditError> {
    let Some(first_nullifier) = transaction.nullifiers.first() else {
        return Ok(None);
    };
    let Some(slot) = transaction.output_slots.first() else {
        return Ok(None);
    };
    let Some(RingMergeBody {
        ring_data_hash,
        encrypted,
    }) = RingMergeBody::of(slot)
    else {
        return Ok(None);
    };
    let key = merge_output_key(source.nullifier_key, first_nullifier)?;
    let Ok(plaintext) = MergeOutputPlaintext::decrypt(&encrypted, &key) else {
        return Ok(None);
    };
    let utxo = plaintext.into_utxo(
        source.address.signing_pubkey,
        spr_transaction::Mint::new(plaintext.mint, 0),
        merge_output_blinding(source.nullifier_key, first_nullifier)?,
        Some(ring),
    );
    let hashes = UtxoDataHashes {
        data_hash: None,
        ring_data_hash: Some(ring_data_hash),
    };
    let (successor, opens) = source.wallet_utxo(
        utxo,
        source.address.nullifier_pubkey,
        &slot.output_context,
        hashes,
        transaction,
        0,
    )?;
    Ok(opens.then_some(successor))
}
