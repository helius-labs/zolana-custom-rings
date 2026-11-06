//! Confidential ring notes opened into a wallet, the pinned zolana scan skips them.
//!
//! Only [`AnonymousWallet::absorb`] stores a sync's [`ScanCommit`], a crash before the absorb repeats the read.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use custom_ring_interface::{ring_body_output, stream::confidential_slot_tag};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{AsyncRpc, IndexerRpcConfig};
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_keypair::ShieldedAddress;
use spr_transaction::{
    verify_owned, DecryptionResult, OwnedUtxos, ShieldedKeys, ShieldedTransaction, WalletUtxo,
};
use zolana_ring_keys::{MergeSeedHolder, RingKeys};
use zolana_ring_transaction::{open_recipient_body, AnonymousOutput, OpenedBody, RingAssets};

use crate::{
    anonymous::{published_note, AnonymousSync, AuditorRecovery, OwnerMergeOpener},
    anonymous_wallet::{AnonymousWallet, PendingNote, ScanCommit},
    delivered::{
        assign_nullifiers, confidential_delivered, RingDeliveredCandidate, RingDeliveryContext,
    },
    exposed_notes::{verify_ring_owned, RingOwnedUtxos},
    history::HistoryPosition,
    merge_audit::RingMergeBody,
    tags::IndexerReads,
    viewing_history::ViewingHistory,
    AnonymousError,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RingConfidentialNotes {
    pub owned: OwnedUtxos,
    /// Unspent zero-key notes, outside `owned` and every automatic path.
    pub exposed_if_spent: Vec<WalletUtxo>,
}

/// What a read of the whole ring opened with no tag read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingFullScan {
    pub owned: RingOwnedUtxos,
    pub pending: Vec<PendingNote>,
    pub auditor_recovery: AuditorRecovery,
}

/// Reads the spends of the notes it opens and the ring merges among them, the scanned transactions alone miss a spend without change.
#[must_use]
pub struct RingConfidentialScan<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a RingAssets,
    config: Option<IndexerRpcConfig>,
}

/// Every commitment rebuilt under the owner.
struct OpenedRows {
    notes: RingConfidentialNotes,
    /// Rebuilt under a mint `assets` does not name, nullifiers assigned.
    pending: Vec<WalletUtxo>,
}

#[derive(Default)]
struct Found {
    notes: Vec<WalletUtxo>,
    pending: Vec<WalletUtxo>,
    /// Every nullifier a read row published, the commit keeps the wallet's own.
    published: HashSet<[u8; 32]>,
    unknown_mints: BTreeSet<Address>,
    unresolved: BTreeSet<[u8; 32]>,
}

impl<'a, K: ShieldedKeys + RingKeys + MergeSeedHolder + ?Sized> RingConfidentialScan<'a, K> {
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

    /// A sync from no stored state, for a caller that keeps no ledger between reads.
    pub async fn fetch<I: AsyncRpc + ?Sized>(
        &self,
        indexer: &I,
        transactions: &[ShieldedTransaction],
    ) -> Result<RingConfidentialNotes, AnonymousError> {
        let mut wallet = AnonymousWallet::new(self.unread_history()?);
        let scan = self.sync(indexer, &wallet, transactions).await?;
        let unknown_mints = scan.decrypted().unknown_mints.clone();
        wallet.absorb(scan)?;
        let RingOwnedUtxos {
            mut owned,
            exposed_if_spent,
            ..
        } = verify_ring_owned(self.keys, &wallet.decrypted())?;
        owned.unknown_mints = unknown_mints;
        Ok(RingConfidentialNotes {
            owned,
            exposed_if_spent,
        })
    }

    /// Reads from `wallet`'s committed tag positions, `transactions` open again on every call.
    pub async fn sync<I: AsyncRpc + ?Sized>(
        &self,
        indexer: &I,
        wallet: &AnonymousWallet,
        transactions: &[ShieldedTransaction],
    ) -> Result<ScanCommit, AnonymousError> {
        let mut reads = IndexerReads::configured(indexer, self.config);
        let mut history = wallet.history().clone();
        // 1. Only rows above the committed positions come back, the ledger holds what earlier rows opened.
        let tagged = self.read_tags(&mut reads, &mut history).await?;
        // 2. Every event read so far opens once, later rounds follow only spends.
        let rows = union_events(transactions, tagged);
        let opened = self.open_rows(&rows)?;
        let mut found = Found {
            notes: opened
                .notes
                .owned
                .utxos
                .into_iter()
                .chain(opened.notes.exposed_if_spent)
                .collect(),
            unknown_mints: opened.notes.owned.unknown_mints,
            pending: opened.pending,
            published: rows
                .iter()
                .flat_map(|tx| tx.nullifiers.iter().copied())
                .collect(),
            ..Found::default()
        };
        // 3. A spend without change publishes no tag of the wallet, only a nullifier read finds it.
        self.read_spends(&mut reads, wallet, &mut found).await?;
        // 4. The commit keeps the wallet's own spent nullifiers, a foreign input of a read row stays out.
        let own: HashSet<[u8; 32]> = wallet
            .notes()
            .iter()
            .chain(&found.notes)
            .chain(&found.pending)
            .map(|note| note.nullifier)
            .chain(wallet.pending_notes().iter().map(PendingNote::nullifier))
            .collect();
        Ok(ScanCommit {
            recovery: crate::anonymous::RecoveryUpdate::Keep,
            starting_history: wallet.history().clone(),
            history,
            decrypted: DecryptionResult {
                utxos: found.notes,
                spent_nullifiers: found.published.intersection(&own).copied().collect(),
                unknown_mints: found.unknown_mints,
                ..DecryptionResult::default()
            },
            pending: found.pending.into_iter().map(PendingNote::new).collect(),
            claims: Vec::new(),
            retried: wallet
                .merge_retries()
                .iter()
                .filter(|nullifier| found.published.contains(*nullifier))
                .copied()
                .collect(),
            unresolved: found.unresolved,
        })
    }

    /// Reads each held key's slot tag above its position, every read key moves to the lowest terminal slot.
    async fn read_tags<I: AsyncRpc + ?Sized>(
        &self,
        reads: &mut IndexerReads<'_, I>,
        history: &mut ViewingHistory,
    ) -> Result<Vec<ShieldedTransaction>, AnonymousError> {
        let held = self.keys.viewing_public_keys();
        // A held key with no entry would read nothing and report nothing missed.
        if held.iter().any(|key| history.entry(key).is_none()) {
            return Err(AnonymousError::HeldKeyNotInHistory);
        }
        // 1. Keys at one position share a read, a new key reads from the first indexed block.
        let mut groups: BTreeMap<Option<u64>, Vec<usize>> = BTreeMap::new();
        for (index, entry) in history.entries().iter().enumerate() {
            if held.contains(&entry.viewing_pubkey()) {
                groups.entry(entry.tag_position()).or_default().push(index);
            }
        }
        // 2. Only the owner tag finds a zero-key merge, it rides the lowest group and step 3 keeps its next read gapless.
        let owner_tag = self
            .keys
            .address()?
            .signing_pubkey
            .owner_proof_input_hash()?;
        let mut rows = Vec::new();
        let mut covered: Option<u64> = None;
        for (group, (position, entries)) in groups.iter().enumerate() {
            let tags: Vec<[u8; 32]> = entries
                .iter()
                .map(|index| confidential_slot_tag(history.entries()[*index].viewing_pubkey().u()))
                .chain((group == 0).then_some(owner_tag))
                .collect();
            let from = position.map_or_else(HistoryPosition::default, HistoryPosition::after_slot);
            let read = reads.tagged(&tags, from).await?;
            rows.extend(read.rows);
            if let Some(slot) = read.next.checkpoint() {
                covered = Some(covered.map_or(slot, |lowest| lowest.min(slot)));
            }
        }
        // 3. One shared position keeps the next sync at one read.
        if let Some(slot) = covered {
            for index in groups.into_values().flatten() {
                history.entries_mut()[index].set_tag_position(slot);
            }
        }
        Ok(rows)
    }

    /// Rounds of nullifier reads until no unread nullifier of an unspent note remains.
    async fn read_spends<I: AsyncRpc + ?Sized>(
        &self,
        reads: &mut IndexerReads<'_, I>,
        wallet: &AnonymousWallet,
        found: &mut Found,
    ) -> Result<(), AnonymousError> {
        // 1. A stored retry is spent, its merge output opens only on a read of that spend.
        let mut queried: HashSet<[u8; 32]> = HashSet::new();
        let mut retries: Vec<[u8; 32]> = wallet.merge_retries().iter().copied().collect();
        loop {
            let unread: Vec<[u8; 32]> = wallet
                .notes()
                .iter()
                .chain(&found.notes)
                .map(|note| note.nullifier)
                .filter(|nullifier| {
                    !wallet.is_spent(nullifier) && !found.published.contains(nullifier)
                })
                .chain(std::mem::take(&mut retries))
                .filter(|nullifier| queried.insert(*nullifier))
                .collect();
            if unread.is_empty() {
                return Ok(());
            }
            let spends = reads.spends(&unread).await?;
            found
                .published
                .extend(spends.iter().flat_map(|tx| tx.nullifiers.iter().copied()));
            // 2. Each merge opens alone, an unregistered mint keeps only its own spends for the next sync.
            for merge in RingMerges::among(spends).0 {
                let spent: Vec<[u8; 32]> = merge
                    .nullifiers
                    .iter()
                    .filter(|nullifier| unread.contains(nullifier))
                    .copied()
                    .collect();
                let opened = RingMerges(vec![merge]).open(self.keys, self.assets)?;
                if !opened.unknown_mints.is_empty() {
                    found.unresolved.extend(spent);
                    found
                        .unknown_mints
                        .extend(opened.unknown_mints.iter().copied());
                }
                for utxo in verify_owned(self.keys, &opened)?.utxos {
                    let mut held = wallet.notes().iter().chain(&found.notes);
                    if !held.any(|note| note.utxo_hash == utxo.utxo_hash) {
                        found.notes.push(utxo);
                    }
                }
            }
        }
    }

    /// Spent state covers `transactions` alone.
    pub fn open(
        &self,
        transactions: &[ShieldedTransaction],
    ) -> Result<RingConfidentialNotes, AnonymousError> {
        Ok(self.open_rows(transactions)?.notes)
    }

    fn open_rows(
        &self,
        transactions: &[ShieldedTransaction],
    ) -> Result<OpenedRows, AnonymousError> {
        // 1. Every opening below is a candidate until step 3, rows from the caller or the indexer earn no trust here.
        let address = self.keys.address()?;
        let candidates = confidential_delivered(self.keys, transactions)?;
        let mut decrypted = DecryptionResult {
            spent_nullifiers: transactions
                .iter()
                .flat_map(|tx| tx.nullifiers.iter().copied())
                .collect(),
            ..DecryptionResult::default()
        };
        let mut pending = Vec::new();
        for candidate in &candidates {
            if let Some(opened) = open_recipient_candidate(&address, self.assets, candidate)? {
                keep_opened(
                    &mut decrypted,
                    &mut pending,
                    candidate.tx,
                    candidate.slot_index as usize,
                    opened,
                )?;
            }
        }
        // 2. A seeded merge opens from its row alone, the spent input may be absent from `transactions`.
        self.open_owner_merges(transactions, &mut decrypted, &mut pending)?;
        assign_nullifiers(self.keys, &mut decrypted.utxos)?;
        // 3. Only a commitment rebuilt under the owner proves a note, a pending note rebuilt its own in the opener.
        assign_nullifiers(self.keys, &mut pending)?;
        let RingOwnedUtxos {
            owned,
            exposed_if_spent,
            ..
        } = verify_ring_owned(self.keys, &decrypted)?;
        Ok(OpenedRows {
            notes: RingConfidentialNotes {
                owned,
                exposed_if_spent,
            },
            pending,
        })
    }

    /// A rotated wallet's merge sits under the seed of the key it held then, every held key tries each row.
    fn open_owner_merges(
        &self,
        transactions: &[ShieldedTransaction],
        decrypted: &mut DecryptionResult,
        pending: &mut Vec<WalletUtxo>,
    ) -> Result<(), AnonymousError> {
        let owner = self.keys.address()?.signing_pubkey;
        let opener = OwnerMergeOpener::new(self.keys, owner, self.assets)?;
        let held = self.keys.viewing_public_keys();
        for merge in transactions.iter().filter_map(|tx| opener.candidate(tx)) {
            for viewing_pubkey in &held {
                if let Some(opened) = opener.open(&merge, *viewing_pubkey)? {
                    keep_opened(decrypted, pending, merge.tx, 0, opened)?;
                    break;
                }
            }
        }
        Ok(())
    }

    /// A wrong tag hides nothing here, every held key tries every site of `ring`.
    pub async fn full_scan<I: AsyncRpc + ?Sized>(
        &self,
        indexer: &I,
        ring: Address,
    ) -> Result<RingFullScan, AnonymousError> {
        let history = self.unread_history()?.with_ring(ring, None);
        let sync = AnonymousSync::new(self.keys, self.assets);
        let sync = match self.config {
            Some(config) => sync.with_indexer_config(config),
            None => sync,
        };
        let scan = sync.full_scan(indexer, &history, ring).await?;
        Ok(RingFullScan {
            owned: verify_ring_owned(self.keys, scan.decrypted())?,
            pending: scan.pending_notes().to_vec(),
            auditor_recovery: scan.auditor_recovery,
        })
    }

    /// Every held key with nothing read, the creation order invented.
    fn unread_history(&self) -> Result<ViewingHistory, AnonymousError> {
        let mut held = self.keys.viewing_public_keys().into_iter().rev();
        let current = held.next().ok_or(AnonymousError::HeldKeyNotInHistory)?;
        held.zip(1..).try_fold(
            ViewingHistory::new(current, 0),
            |history, (key, created_at)| history.with_rotated_key(key, created_at),
        )
    }
}

/// Spent state covers `transactions` alone.
pub fn open_ring_confidential<K: ShieldedKeys + RingKeys + MergeSeedHolder + ?Sized>(
    keys: &K,
    assets: &RingAssets,
    transactions: &[ShieldedTransaction],
) -> Result<RingConfidentialNotes, AnonymousError> {
    RingConfidentialScan::new(keys, assets).open(transactions)
}

/// One transaction can emit several relevant events, only its signature and event index name one.
fn union_events(
    known: &[ShieldedTransaction],
    tagged: Vec<ShieldedTransaction>,
) -> Vec<ShieldedTransaction> {
    let identity = |tx: &ShieldedTransaction| -> (Signature, Option<u16>) {
        (tx.tx_signature, tx.event_index)
    };
    let mut seen: HashSet<_> = known.iter().map(identity).collect();
    known
        .iter()
        .cloned()
        .chain(tagged.into_iter().filter(|tx| seen.insert(identity(tx))))
        .collect()
}

/// A note under an unregistered mint stays out of `utxos`, waits in `pending` and names its mint.
fn keep_opened(
    decrypted: &mut DecryptionResult,
    pending: &mut Vec<WalletUtxo>,
    tx: &ShieldedTransaction,
    position: usize,
    opened: OpenedBody,
) -> Result<(), AnonymousError> {
    match opened {
        OpenedBody::Note(note) => decrypted.utxos.push(published_note(tx, position, note)?),
        OpenedBody::UnknownMint(note) => {
            decrypted.unknown_mints.insert(note.utxo.asset.asset);
            pending.push(published_note(tx, position, note)?);
        }
    }
    Ok(())
}

/// `None` off a ring body output or on a body that rebuilds nothing.
fn open_recipient_candidate(
    address: &ShieldedAddress,
    assets: &RingAssets,
    candidate: &RingDeliveredCandidate<'_>,
) -> Result<Option<OpenedBody>, AnonymousError> {
    let tx = candidate.tx;
    let Some(slot) = tx.output_slots.get(candidate.slot_index as usize) else {
        return Ok(None);
    };
    let (Some((ciphertext, _)), Some(context)) =
        (ring_body_output(&slot.payload), RingDeliveryContext::of(tx))
    else {
        return Ok(None);
    };
    let Ok(body) = open_recipient_body(ciphertext, &candidate.slot_secret) else {
        return Ok(None);
    };
    Ok(AnonymousOutput {
        ring: context.ring,
        owner: address,
        utxo_hash: &slot.output_context.hash,
        tree_id: slot.output_context.tree_id,
        assets,
    }
    .open_body(&body)
    .unwrap_or(None))
}

/// Refuses a first nullifier or ring data hash off the field, a Poseidon error past here fails the read.
pub(crate) fn is_ring_merge(tx: &ShieldedTransaction) -> bool {
    tx.ring_program_id.is_some()
        && tx.may_be_merge()
        && tx
            .nullifiers
            .first()
            .is_none_or(is_canonical_bn254_scalar_be)
        && tx
            .output_slots
            .iter()
            .filter_map(RingMergeBody::of)
            .all(|body| is_canonical_bn254_scalar_be(&body.ring_data_hash))
}

pub(crate) struct RingMerges(pub Vec<ShieldedTransaction>);

impl RingMerges {
    pub(crate) fn among(spends: Vec<ShieldedTransaction>) -> Self {
        Self(spends.into_iter().filter(is_ring_merge).collect())
    }

    pub(crate) fn open<K: ShieldedKeys + ?Sized>(
        &self,
        keys: &K,
        assets: &RingAssets,
    ) -> Result<DecryptionResult, AnonymousError> {
        let mut opened = DecryptionResult::default();
        opened.extend(keys, &self.0, assets.registry())?;
        Ok(opened)
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use custom_ring_interface::{
        encode_ring_body_output,
        stream::{DeliveredSlot, SlotSecret},
        RecipientBody,
    };
    use spr_client::{
        rpc::{Context, GetShieldedTransactionsByNullifiersResponse, HistoryFilters, Page},
        ClientError, GetShieldedTransactionsByTagsResponse, OutputContext, OutputSlot,
        PaginationToken, RingHistoryOptions, TransactionEvents,
    };
    use spr_event::{encode_merge_output_data, MergeOutputDataRef};
    use spr_interface::ZERO_NULLIFIER_PUBKEY;
    use spr_keypair::{
        viewing_key::ViewTag, KeypairError, NullifierKey, ShieldedKeypair, SigningKey, ViewingKey,
        X25519Pubkey,
    };
    use spr_transaction::{
        instructions::merge::{
            merge_output_blinding, merge_output_key, MergeOutputPlaintext, MergeSeed,
        },
        DecryptRequest, DeriveRequest, Mint, TransactionError, TransactionKeyRequest,
    };
    use zolana_ring_keys::{
        MergeSeedRequest, RingDeliveryRequest, RingKeyError, RingTagFrame, ViewTagRequest,
    };
    use zolana_ring_transaction::seal_recipient_body;

    use std::sync::Mutex;

    use spr_transaction::Utxo;

    use super::*;
    use crate::NoteState;

    const NOT_IN_FIELD: [u8; 32] = [0xff; 32];
    const RING: Address = Address::new_from_array([0x90; 32]);
    const TREE: u16 = 9;
    const AMOUNT: u64 = 25;

    fn wallet(seed: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
    }

    fn ring_note(owner: &ShieldedAddress, blinding: [u8; 32]) -> Utxo {
        Utxo {
            owner: owner.signing_pubkey,
            asset: Mint::SOL,
            amount: AMOUNT,
            blinding,
            ring_program_id: Some(RING),
            data: Default::default(),
        }
    }

    /// Rows each read served since the last take.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct Served {
        tagged: usize,
        spent: usize,
    }

    /// Answers each read from one list, in the position order Photon pages.
    #[derive(Default)]
    struct Rows {
        rows: Vec<ShieldedTransaction>,
        served: Mutex<Served>,
    }

    impl Rows {
        fn of(rows: Vec<ShieldedTransaction>) -> Self {
            Self {
                rows,
                ..Self::default()
            }
        }

        fn take_served(&self) -> Served {
            std::mem::take(&mut *self.served.lock().unwrap())
        }

        fn page(
            &self,
            filters: &HistoryFilters,
            matches: impl Fn(&ShieldedTransaction) -> bool,
        ) -> GetShieldedTransactionsByTagsResponse {
            let mut rows: Vec<ShieldedTransaction> = self
                .rows
                .iter()
                .filter(|tx| filters.slot.contains(tx.slot) && matches(tx))
                .cloned()
                .collect();
            rows.sort_by_key(|row| {
                (
                    PaginationToken::new(row.slot, row.tx_signature),
                    row.event_index,
                )
            });
            let mut data: Vec<TransactionEvents<ShieldedTransaction, Signature>> = Vec::new();
            for row in rows {
                match data.last_mut() {
                    Some(last) if last.signature == row.tx_signature && last.slot == row.slot => {
                        last.events.push(row)
                    }
                    _ => data.push(TransactionEvents {
                        slot: row.slot,
                        signature: row.tx_signature,
                        events: vec![row],
                    }),
                }
            }
            terminal(self.tip(), data)
        }

        fn tip(&self) -> u64 {
            self.rows.iter().map(|tx| tx.slot).max().unwrap_or_default()
        }
    }

    fn terminal<T>(slot: u64, data: Vec<T>) -> Page<T> {
        Page {
            context: Context {
                block_time: 0,
                slot,
            },
            output_tree_id: Some(TREE),
            data,
            pagination_token: None,
        }
    }

    #[async_trait]
    impl AsyncRpc for Rows {
        async fn get_shielded_transactions_by_tags(
            &self,
            tags: Vec<[u8; 32]>,
            _pagination_token: Option<PaginationToken>,
            _limit: Option<u32>,
            filters: HistoryFilters,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            let page = self.page(&filters, |tx| {
                tx.output_slots
                    .iter()
                    .any(|slot| tags.contains(&slot.view_tag))
            });
            self.served.lock().unwrap().tagged += served(&page);
            Ok(page)
        }

        async fn get_shielded_transactions_by_ring(
            &self,
            options: RingHistoryOptions,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            Ok(self.page(&options.filters, |tx| {
                tx.ring_program_id == Some(options.ring_program_id)
            }))
        }

        async fn get_shielded_transactions_by_nullifiers(
            &self,
            nullifiers: Vec<[u8; 32]>,
            _pagination_token: Option<PaginationToken>,
            _limit: Option<u32>,
            filters: HistoryFilters,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            let page = self.page(&filters, |tx| {
                tx.nullifiers.iter().any(|spent| nullifiers.contains(spent))
            });
            self.served.lock().unwrap().spent += served(&page);
            Ok(page)
        }
    }

    fn served(page: &GetShieldedTransactionsByTagsResponse) -> usize {
        page.data.iter().map(|item| item.events.len()).sum()
    }

    #[derive(PartialEq)]
    enum HolderFailure {
        /// The error a bad published value raises.
        MergeOutputKey,
        MergeSeed,
    }

    /// Answers as its keypair does, except the call it fails.
    struct FailingHolder(ShieldedKeypair, HolderFailure);

    impl ShieldedKeys for FailingHolder {
        fn address(&self) -> Result<ShieldedAddress, TransactionError> {
            self.0.address()
        }

        fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
            self.0.viewing_public_keys()
        }

        fn decrypt(
            &self,
            requests: &[DecryptRequest<'_>],
        ) -> Result<Vec<Vec<u8>>, TransactionError> {
            self.0.decrypt(requests)
        }

        fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
            if self.1 == HolderFailure::MergeOutputKey
                && requests
                    .iter()
                    .any(|request| matches!(request, DeriveRequest::MergeOutputKey { .. }))
            {
                return Err(TransactionError::Keypair(KeypairError::Poseidon(1)));
            }
            self.0.derive(requests)
        }

        fn transaction_keys(
            &self,
            requests: &[TransactionKeyRequest],
        ) -> Result<Vec<ViewingKey>, TransactionError> {
            self.0.transaction_keys(requests)
        }
    }

    impl MergeSeedHolder for FailingHolder {
        fn merge_seeds(
            &self,
            requests: &[MergeSeedRequest],
        ) -> Result<Vec<MergeSeed>, RingKeyError> {
            if self.1 == HolderFailure::MergeSeed {
                return Err(RingKeyError::UnknownViewingKey);
            }
            self.0.merge_seeds(requests)
        }
    }

    impl RingKeys for FailingHolder {
        fn ring_delivery_secrets(
            &self,
            requests: &[RingDeliveryRequest],
        ) -> Result<Vec<[u8; 32]>, RingKeyError> {
            self.0.ring_delivery_secrets(requests)
        }

        fn ring_tag_matches(
            &self,
            frames: &[RingTagFrame],
        ) -> Result<Vec<Vec<Option<SlotSecret>>>, RingKeyError> {
            self.0.ring_tag_matches(frames)
        }

        fn view_tags(&self, requests: &[ViewTagRequest]) -> Result<Vec<ViewTag>, RingKeyError> {
            self.0.view_tags(requests)
        }
    }

    fn assets() -> RingAssets {
        RingAssets::new([]).unwrap()
    }

    fn hashes(notes: &[WalletUtxo]) -> Vec<[u8; 32]> {
        notes.iter().map(|note| note.utxo_hash).collect()
    }

    /// A row with no transaction key or salt, spending `first`.
    fn merge_row(slot: OutputSlot, first: [u8; 32]) -> ShieldedTransaction {
        ShieldedTransaction {
            tx_signature: Signature::from([first[0]; 64]),
            slot: 2,
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![slot],
            messages: Vec::new(),
            nullifiers: vec![first],
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        }
    }

    fn output_context(hash: [u8; 32]) -> OutputContext {
        OutputContext {
            hash,
            tree_id: TREE,
            leaf_index: 0,
        }
    }

    fn merge_payload(key: &[u8; 32], published: [u8; 32], mint: Mint) -> Vec<u8> {
        let salt = [8; 16];
        let ciphertext = MergeOutputPlaintext {
            amount: AMOUNT,
            mint: mint.asset,
        }
        .encrypt(key, &salt)
        .unwrap();
        encode_merge_output_data(MergeOutputDataRef {
            salt: &salt,
            ciphertext: &ciphertext,
            prefix: &[published],
        })
    }

    struct ProvenMerge {
        /// Enters the commitment, the proof holds the published value to it.
        committed: [u8; 32],
        published: [u8; 32],
    }

    impl ProvenMerge {
        /// The row of `merge_ring` under `owner`'s nonzero key and the utxo hash it commits.
        fn row(self, owner: &ShieldedKeypair, first: [u8; 32]) -> ([u8; 32], ShieldedTransaction) {
            self.row_under(owner, first, Mint::SOL)
        }

        fn row_under(
            self,
            owner: &ShieldedKeypair,
            first: [u8; 32],
            mint: Mint,
        ) -> ([u8; 32], ShieldedTransaction) {
            let address = owner.shielded_address().unwrap();
            let blinding = merge_output_blinding(&owner.nullifier_key, &first).unwrap();
            let hash = Utxo {
                asset: mint,
                ..ring_note(&address, blinding)
            }
            .hash(&address.nullifier_pubkey, &[0; 32], &self.committed, TREE)
            .unwrap();
            let key = merge_output_key(&owner.nullifier_key, &first).unwrap();
            let slot = OutputSlot {
                view_tag: first,
                output_context: output_context(hash),
                payload: merge_payload(&key, self.published, mint),
            };
            (hash, merge_row(slot, first))
        }

        /// The utxo hash the row commits and what its owner opens from the row.
        fn opened(self) -> ([u8; 32], Vec<[u8; 32]>) {
            let owner = wallet(7);
            let (hash, row) = self.row(&owner, [0x11; 32]);
            let opened = RingMerges::among(vec![row])
                .open(&owner, &assets())
                .unwrap();
            (hash, hashes(&opened.utxos))
        }
    }

    /// A zero-key merge under `owner`'s tag, encrypted to `seed`, its commitment and row.
    fn seeded_merge(
        owner: &ShieldedAddress,
        seed: &MergeSeed,
        first: [u8; 32],
    ) -> ([u8; 32], ShieldedTransaction) {
        let hash = ring_note(owner, seed.output_blinding(&first).unwrap())
            .hash(&ZERO_NULLIFIER_PUBKEY, &[0; 32], &[0; 32], TREE)
            .unwrap();
        let slot = OutputSlot {
            view_tag: owner.signing_pubkey.owner_proof_input_hash().unwrap(),
            output_context: output_context(hash),
            payload: merge_payload(&seed.output_key(&first).unwrap(), [0; 32], Mint::SOL),
        };
        (hash, merge_row(slot, first))
    }

    fn own_seed(keys: &ShieldedKeypair, first: [u8; 32]) -> MergeSeed {
        keys.merge_seeds(&[MergeSeedRequest {
            viewing_pubkey: keys.viewing_pubkey(),
            ring_program_id: RING,
            first_nullifier: first,
        }])
        .unwrap()
        .remove(0)
    }

    /// The blinding of `payment_event(_, 0)`.
    const PAYMENT_BLINDING: [u8; 32] = [0x13; 32];

    /// One delivered payment, every event shares one signature.
    fn payment_event(recipient: &ShieldedKeypair, event_index: u16) -> ShieldedTransaction {
        Payment {
            slot: 3,
            event_index,
            mint: Mint::SOL,
        }
        .row(recipient)
    }

    /// Events at one slot share its signature and first nullifier.
    struct Payment {
        slot: u64,
        event_index: u16,
        mint: Mint,
    }

    impl Payment {
        fn row(self, recipient: &ShieldedKeypair) -> ShieldedTransaction {
            let address = recipient.shielded_address().unwrap();
            let tx_key = ViewingKey::new();
            let salt = [9; 16];
            let first_nullifier = [0x1e + self.slot as u8; 32];
            let view = recipient.viewing_pubkey();
            let secret = DeliveredSlot {
                agreement: &tx_key.ecdh(&view).unwrap(),
                tx_viewing_pk: tx_key.pubkey().as_bytes(),
                recipient_viewing_pk: view.as_bytes(),
                salt: &salt,
                output_index: 0,
                first_nullifier: &first_nullifier,
            }
            .secret()
            .unwrap();
            let blinding = [0x10 + self.slot as u8 + self.event_index as u8; 32];
            let hash = Utxo {
                asset: self.mint,
                ..ring_note(&address, blinding)
            }
            .hash(&address.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
            .unwrap();
            let body = seal_recipient_body(
                &RecipientBody {
                    blinding,
                    amount: AMOUNT,
                    mint: self.mint.asset.to_bytes(),
                    ..RecipientBody::default()
                },
                &secret,
            )
            .unwrap();
            ShieldedTransaction {
                slot: self.slot,
                tx_signature: Signature::from([self.slot as u8; 64]),
                event_index: Some(self.event_index),
                tx_viewing_pk: Some(tx_key.pubkey()),
                salt: Some(salt),
                output_slots: vec![OutputSlot {
                    view_tag: confidential_slot_tag(view.u()),
                    output_context: output_context(hash),
                    payload: encode_ring_body_output(&body, &[]).unwrap(),
                }],
                messages: Vec::new(),
                nullifiers: vec![first_nullifier],
                proofless: false,
                ring_config: None,
                ring_program_id: Some(RING),
            }
        }
    }

    /// Spends `nullifier` at `slot` and publishes no output, no tag of the wallet finds it.
    fn spend_row(nullifier: [u8; 32], slot: u64) -> ShieldedTransaction {
        ShieldedTransaction {
            tx_signature: Signature::from([0x50 + slot as u8; 64]),
            slot,
            output_slots: Vec::new(),
            ..merge_row(
                OutputSlot {
                    view_tag: [0; 32],
                    output_context: output_context([0; 32]),
                    payload: Vec::new(),
                },
                nullifier,
            )
        }
    }

    /// Registered after the first payment under it.
    const LATE: Mint = Mint {
        asset: Address::new_from_array([0x44; 32]),
        asset_id: 5,
    };

    fn ledger(owner: &ShieldedKeypair) -> AnonymousWallet {
        AnonymousWallet::new(ViewingHistory::new(owner.viewing_pubkey(), 0))
    }

    /// Stores one sync and returns the unregistered mints it met.
    async fn absorb_sync(
        scan: &RingConfidentialScan<'_, ShieldedKeypair>,
        indexer: &Rows,
        ledger: &mut AnonymousWallet,
    ) -> BTreeSet<Address> {
        let commit = scan.sync(indexer, ledger, &[]).await.unwrap();
        let unknown = commit.decrypted().unknown_mints.clone();
        ledger.absorb(commit).unwrap();
        unknown
    }

    #[tokio::test]
    async fn a_restarted_sync_reads_no_committed_row_and_a_new_payment_and_spend_once() {
        let owner = wallet(7);
        let assets = assets();
        let scan = RingConfidentialScan::new(&owner, &assets);
        let first = payment_event(&owner, 0);
        let mut indexer = Rows::of(vec![first.clone()]);
        let mut stored = ledger(&owner);
        absorb_sync(&scan, &indexer, &mut stored).await;
        let held = stored.notes()[0].clone();
        assert_eq!(held.utxo_hash, first.output_slots[0].output_context.hash);
        assert_eq!(stored.history().current().tag_position(), Some(3));
        assert_eq!(
            indexer.take_served(),
            Served {
                tagged: 1,
                spent: 0
            }
        );

        let mut restarted = AnonymousWallet::from_json(&stored.to_json()).unwrap();
        absorb_sync(&scan, &indexer, &mut restarted).await;
        assert_eq!(indexer.take_served(), Served::default());
        assert_eq!(restarted, stored);

        let second = Payment {
            slot: 5,
            event_index: 0,
            mint: Mint::SOL,
        }
        .row(&owner);
        indexer
            .rows
            .extend([second.clone(), spend_row(held.nullifier, 5)]);
        absorb_sync(&scan, &indexer, &mut restarted).await;
        assert_eq!(
            indexer.take_served(),
            Served {
                tagged: 1,
                spent: 1
            }
        );
        assert_eq!(restarted.history().current().tag_position(), Some(5));
        let states: Vec<_> = restarted
            .notes()
            .iter()
            .map(|note| (note.utxo_hash, restarted.note_state(note)))
            .collect();
        assert_eq!(
            states,
            [
                (held.utxo_hash, NoteState::Spent),
                (
                    second.output_slots[0].output_context.hash,
                    NoteState::Spendable
                ),
            ]
        );

        absorb_sync(&scan, &indexer, &mut restarted).await;
        assert_eq!(indexer.take_served(), Served::default());
    }

    #[tokio::test]
    async fn a_pending_mint_waits_in_the_ledger_and_registers_with_no_history_read() {
        let owner = wallet(7);
        let row = Payment {
            slot: 3,
            event_index: 0,
            mint: LATE,
        }
        .row(&owner);
        let hash = row.output_slots[0].output_context.hash;
        let indexer = Rows::of(vec![row]);
        let (unregistered, registered) = (assets(), RingAssets::new([LATE]).unwrap());
        let mut stored = ledger(&owner);
        let unknown = absorb_sync(
            &RingConfidentialScan::new(&owner, &unregistered),
            &indexer,
            &mut stored,
        )
        .await;
        assert_eq!(unknown, BTreeSet::from([LATE.asset]));
        assert!(stored.notes().is_empty());
        assert_eq!(stored.pending_notes()[0].utxo_hash(), hash);

        indexer.take_served();
        absorb_sync(
            &RingConfidentialScan::new(&owner, &registered),
            &indexer,
            &mut stored,
        )
        .await;
        assert_eq!(indexer.take_served(), Served::default());
        assert!(stored.notes().is_empty());

        stored.resolve_pending(&registered);
        assert!(stored.pending_notes().is_empty());
        let owned = verify_ring_owned(&owner, &stored.decrypted())
            .unwrap()
            .owned;
        assert_eq!(hashes(&owned.utxos), [hash]);
        assert_eq!(owned.utxos[0].utxo.asset, LATE);
    }

    #[tokio::test]
    async fn a_merge_under_an_unregistered_mint_reads_its_spend_again_until_the_mint_registers() {
        let owner = wallet(7);
        let (unregistered, registered) = (assets(), RingAssets::new([LATE]).unwrap());
        let mut indexer = Rows::of(vec![Payment {
            slot: 3,
            event_index: 0,
            mint: LATE,
        }
        .row(&owner)]);
        let mut stored = ledger(&owner);
        let late_scan = RingConfidentialScan::new(&owner, &registered);
        absorb_sync(&late_scan, &indexer, &mut stored).await;
        let held = stored.notes()[0].clone();
        let (merged, merge) = ProvenMerge {
            committed: [0; 32],
            published: [0; 32],
        }
        .row_under(&owner, held.nullifier, LATE);
        indexer.rows.push(merge);
        indexer.take_served();

        let stale_scan = RingConfidentialScan::new(&owner, &unregistered);
        for _ in 0..2 {
            let unknown = absorb_sync(&stale_scan, &indexer, &mut stored).await;
            assert_eq!(unknown, BTreeSet::from([LATE.asset]));
            assert_eq!(
                indexer.take_served(),
                Served {
                    tagged: 0,
                    spent: 1
                }
            );
            assert_eq!(stored.note_state(&held), NoteState::Spent);
            assert_eq!(hashes(stored.notes()), [held.utxo_hash]);
        }

        let lagging = Rows::of(vec![indexer.rows[0].clone()]);
        absorb_sync(&late_scan, &lagging, &mut stored).await;
        assert_eq!(lagging.take_served(), Served::default());
        assert!(stored.merge_retries().contains(&held.nullifier));

        absorb_sync(&late_scan, &indexer, &mut stored).await;
        assert_eq!(
            indexer.take_served(),
            Served {
                tagged: 0,
                spent: 1
            }
        );
        assert_eq!(hashes(stored.notes()), [held.utxo_hash, merged]);
        assert!(stored.merge_retries().is_empty());

        absorb_sync(&late_scan, &indexer, &mut stored).await;
        assert_eq!(indexer.take_served(), Served::default());
    }

    #[tokio::test]
    async fn a_sync_read_before_another_commit_is_refused_whole() {
        let owner = wallet(7);
        let assets = assets();
        let scan = RingConfidentialScan::new(&owner, &assets);
        let indexer = Rows::of(vec![payment_event(&owner, 0)]);
        let mut stored = ledger(&owner);
        let (first, stale) = (
            scan.sync(&indexer, &stored, &[]).await.unwrap(),
            scan.sync(&indexer, &stored, &[]).await.unwrap(),
        );
        stored.absorb(first).unwrap();
        let committed = stored.clone();
        assert!(matches!(
            stored.absorb(stale),
            Err(AnonymousError::ScanHistoryChanged)
        ));
        assert_eq!(stored, committed);
    }

    #[tokio::test]
    async fn a_held_key_absent_from_the_ledger_refuses_the_sync() {
        let (owner, other) = (wallet(7), wallet(8));
        let assets = assets();
        let refused = RingConfidentialScan::new(&owner, &assets)
            .sync(&Rows::default(), &ledger(&other), &[])
            .await;
        assert!(matches!(refused, Err(AnonymousError::HeldKeyNotInHistory)));
    }

    /// `merge_ring` under a nonzero key, the proven encoding and its first nullifier tag.
    #[test]
    fn a_proven_ring_merge_opens_under_the_nullifier_secret() {
        let (hash, opened) = ProvenMerge {
            committed: [0; 32],
            published: [0; 32],
        }
        .opened();
        assert_eq!(opened, [hash]);
    }

    /// `merge.go` leaves the value free, the commitment holds it and the owner rebuilds from the row.
    #[test]
    fn a_relay_chosen_ring_data_hash_binds_the_commitment_and_stays_the_owners_note() {
        let chosen = [3; 32];
        let (hash, opened) = ProvenMerge {
            committed: chosen,
            published: chosen,
        }
        .opened();
        assert_eq!(opened, [hash]);
        let (_, unbound) = ProvenMerge {
            committed: chosen,
            published: [4; 32],
        }
        .opened();
        assert!(unbound.is_empty());
    }

    #[tokio::test]
    async fn fetch_finds_a_zero_key_merge_with_no_input_history_and_reads_it_exposed() {
        let owner = wallet(7);
        let address = owner.shielded_address().unwrap();
        let first = [0x14; 32];
        let (hash, row) = seeded_merge(&address, &own_seed(&owner, first), first);
        let assets = assets();
        let notes = RingConfidentialScan::new(&owner, &assets)
            .fetch(&Rows::of(vec![row]), &[])
            .await
            .unwrap();
        assert_eq!(hashes(&notes.exposed_if_spent), [hash]);
        assert!(notes.owned.utxos.is_empty());
    }

    #[tokio::test]
    async fn fetch_moves_the_exposure_from_a_spent_zero_key_note_to_its_merge_output() {
        let owner = wallet(7);
        let address = owner.shielded_address().unwrap();
        let mut payment = payment_event(&owner, 0);
        let note = &mut payment.output_slots[0].output_context;
        note.hash = ring_note(&address, PAYMENT_BLINDING)
            .hash(&ZERO_NULLIFIER_PUBKEY, &[0; 32], &[0; 32], TREE)
            .unwrap();
        let input = NullifierKey::from_secret([0; 31])
            .nullifier(&note.hash, &PAYMENT_BLINDING)
            .unwrap();
        let (hash, merge) = seeded_merge(&address, &own_seed(&owner, input), input);
        let assets = assets();
        let notes = RingConfidentialScan::new(&owner, &assets)
            .fetch(
                &Rows::of(vec![payment.clone(), merge]),
                core::slice::from_ref(&payment),
            )
            .await
            .unwrap();
        assert_eq!(hashes(&notes.exposed_if_spent), [hash]);
    }

    #[tokio::test]
    async fn fetch_opens_no_zero_key_merge_under_another_wallets_seed() {
        let (owner, other) = (wallet(7), wallet(8));
        let first = [0x14; 32];
        let (_, row) = seeded_merge(
            &owner.shielded_address().unwrap(),
            &own_seed(&other, first),
            first,
        );
        let assets = assets();
        let notes = RingConfidentialScan::new(&owner, &assets)
            .fetch(&Rows::of(vec![row]), &[])
            .await
            .unwrap();
        assert!(notes.exposed_if_spent.is_empty() && notes.owned.utxos.is_empty());
    }

    #[tokio::test]
    async fn a_poseidon_error_from_the_holder_fails_fetch_and_full_scan() {
        let holder = FailingHolder(wallet(7), HolderFailure::MergeOutputKey);
        let payment = payment_event(&holder.0, 0);
        let input = holder
            .0
            .nullifier(
                &payment.output_slots[0].output_context.hash,
                &PAYMENT_BLINDING,
            )
            .unwrap();
        let (_, merge) = ProvenMerge {
            committed: [0; 32],
            published: [0; 32],
        }
        .row(&holder.0, input);
        let indexer = Rows::of(vec![payment.clone(), merge]);
        let assets = assets();
        let scan = RingConfidentialScan::new(&holder, &assets);
        let refused = |error: AnonymousError| {
            matches!(
                error,
                AnonymousError::Transaction(TransactionError::Keypair(KeypairError::Poseidon(_)))
            )
        };
        assert!(refused(
            scan.fetch(&indexer, core::slice::from_ref(&payment))
                .await
                .err()
                .unwrap()
        ));
        assert!(refused(scan.full_scan(&indexer, RING).await.err().unwrap()));
    }

    #[tokio::test]
    async fn a_merge_seed_failure_from_the_holder_fails_fetch_and_full_scan() {
        let holder = FailingHolder(wallet(7), HolderFailure::MergeSeed);
        let address = holder.address().unwrap();
        let first = [0x14; 32];
        let (_, row) = seeded_merge(&address, &own_seed(&holder.0, first), first);
        let indexer = Rows::of(vec![row]);
        let assets = assets();
        let scan = RingConfidentialScan::new(&holder, &assets);
        assert!(scan.fetch(&indexer, &[]).await.is_err());
        assert!(scan.full_scan(&indexer, RING).await.is_err());
    }

    #[test]
    fn a_published_value_outside_the_field_skips_only_its_merge() {
        let owner = wallet(7);
        let (hash, good) = ProvenMerge {
            committed: [0; 32],
            published: [0; 32],
        }
        .row(&owner, [0x11; 32]);
        let (_, bad_ring_data) = ProvenMerge {
            committed: [0; 32],
            published: NOT_IN_FIELD,
        }
        .row(&owner, [0x12; 32]);
        let (_, mut bad_first) = ProvenMerge {
            committed: [0; 32],
            published: [0; 32],
        }
        .row(&owner, [0x13; 32]);
        bad_first.nullifiers[0] = NOT_IN_FIELD;
        let opened = RingMerges::among(vec![bad_ring_data, good, bad_first])
            .open(&owner, &assets())
            .unwrap();
        assert_eq!(hashes(&opened.utxos), [hash]);
    }

    #[tokio::test]
    async fn a_seeded_merge_with_a_first_nullifier_outside_the_field_fails_no_read() {
        let owner = wallet(7);
        let address = owner.shielded_address().unwrap();
        let first = [0x14; 32];
        let (hash, good) = seeded_merge(&address, &own_seed(&owner, first), first);
        let other = [0x15; 32];
        let (_, mut bad) = seeded_merge(&address, &own_seed(&owner, other), other);
        bad.nullifiers[0] = NOT_IN_FIELD;
        let assets = assets();
        let notes = RingConfidentialScan::new(&owner, &assets)
            .fetch(&Rows::of(vec![good, bad]), &[])
            .await
            .unwrap();
        assert_eq!(hashes(&notes.exposed_if_spent), [hash]);
    }

    #[tokio::test]
    async fn two_events_of_one_transaction_both_open_on_fetch() {
        let owner = wallet(7);
        let (first, second) = (payment_event(&owner, 0), payment_event(&owner, 1));
        let both = [
            first.output_slots[0].output_context.hash,
            second.output_slots[0].output_context.hash,
        ];
        let assets = assets();
        let notes = RingConfidentialScan::new(&owner, &assets)
            .fetch(
                &Rows::of(vec![first.clone(), second]),
                core::slice::from_ref(&first),
            )
            .await
            .unwrap();
        assert_eq!(hashes(&notes.owned.utxos), both);
    }

    #[test]
    fn an_event_read_twice_stays_one_row() {
        let owner = wallet(7);
        let (first, second) = (payment_event(&owner, 0), payment_event(&owner, 1));
        let read = union_events(
            core::slice::from_ref(&first),
            vec![first.clone(), first.clone(), second.clone()],
        );
        let events: Vec<_> = read.iter().map(|tx| tx.event_index).collect();
        assert_eq!(events, [first.event_index, second.event_index]);
    }
}
