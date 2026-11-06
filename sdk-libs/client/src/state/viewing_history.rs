//! The anonymous rail's wallet state, spec `ViewingKeyEntry` per retained viewing key.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_keypair::{viewing_key::ViewTag, x25519::X25519_PUBKEY_LEN, X25519Pubkey};
use zolana_ring_keys::{RingKeys, ViewTagRequest, ViewTagStream};
use zolana_ring_transaction::is_contributory;

use crate::{exactly_one, AnonymousError, REDACTED};

/// How far below its watermark a sync still reads an unobserved index.
pub const PENDING_RETENTION: u64 = 256;

/// `scanned` never passes `next`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamCounter {
    next: u64,
    scanned: u64,
    /// Unobserved, below `scanned` by at most [`PENDING_RETENTION`].
    pending: BTreeSet<u64>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ViewingKeyEntry {
    viewing_pubkey: X25519Pubkey,
    created_at: i64,
    tx: StreamCounter,
    /// Viewing keys whose reply claim the wallet confirmed.
    known_senders: HashSet<X25519Pubkey>,
    /// `after_slot` per ring, `None` reads from the first indexed block.
    ring_positions: BTreeMap<Address, Option<u64>>,
    /// `after_slot` of the confidential slot tag read, `None` reads from the first indexed block.
    tag_position: Option<u64>,
}

/// Every retained viewing key, oldest first, the last one current.
#[derive(Clone, PartialEq, Eq)]
pub struct ViewingHistory {
    entries: Vec<ViewingKeyEntry>,
}

/// `history` is advanced past `tag`.
#[must_use]
#[derive(Clone, Debug)]
pub struct AdvancedTag<T> {
    pub tag: T,
    pub history: ViewingHistory,
}

impl StreamCounter {
    pub fn next(&self) -> u64 {
        self.next
    }

    pub fn scanned(&self) -> u64 {
        self.scanned
    }

    /// Reserved indices below the watermark no sync has observed yet.
    pub fn pending(&self) -> impl Iterator<Item = u64> + '_ {
        self.pending.iter().copied()
    }

    fn same_progress(&self, stored: &Self) -> bool {
        self.scanned == stored.scanned && self.pending == stored.pending
    }

    fn take_next(&mut self) -> Result<u64, AnonymousError> {
        let next = self.next;
        self.next = next.checked_add(1).ok_or(AnonymousError::CounterOverflow)?;
        Ok(next)
    }
}

impl ViewingKeyEntry {
    pub fn new(viewing_pubkey: X25519Pubkey, created_at: i64) -> Self {
        Self {
            viewing_pubkey,
            created_at,
            tx: StreamCounter::default(),
            known_senders: HashSet::new(),
            ring_positions: BTreeMap::new(),
            tag_position: None,
        }
    }

    pub fn viewing_pubkey(&self) -> X25519Pubkey {
        self.viewing_pubkey
    }

    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    pub fn tx_count(&self) -> u64 {
        self.tx.next
    }

    pub fn known_senders(&self) -> &HashSet<X25519Pubkey> {
        &self.known_senders
    }

    pub fn ring_positions(&self) -> &BTreeMap<Address, Option<u64>> {
        &self.ring_positions
    }

    pub fn tag_position(&self) -> Option<u64> {
        self.tag_position
    }

    /// Only a terminal page's `context.slot` reaches here.
    pub(crate) fn set_ring_position(&mut self, ring: Address, after_slot: u64) {
        self.ring_positions.insert(ring, Some(after_slot));
    }

    /// Only a terminal page's `context.slot` reaches here.
    pub(crate) fn set_tag_position(&mut self, after_slot: u64) {
        self.tag_position = Some(after_slot);
    }

    /// A reply is a claim, the wallet confirms a sender here and nothing else does.
    pub fn confirm_sender(&mut self, sender: X25519Pubkey) -> Result<(), AnonymousError> {
        if !is_contributory(&sender) {
            return Err(AnonymousError::RecipientKeyNotContributory);
        }
        self.known_senders.insert(sender);
        Ok(())
    }

    fn progress_matches(&self, stored: &Self) -> bool {
        self.tx.same_progress(&stored.tx)
            && self.tag_position == stored.tag_position
            && stored
                .ring_positions
                .iter()
                .all(|(ring, after_slot)| self.ring_positions.get(ring) == Some(after_slot))
            && self.ring_positions.iter().all(|(ring, after_slot)| {
                stored.ring_positions.contains_key(ring) || after_slot.is_none()
            })
    }
}

impl fmt::Debug for ViewingKeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewingKeyEntry")
            .field("created_at", &self.created_at)
            .field("tx", &self.tx)
            .field("known_senders", &REDACTED)
            .finish_non_exhaustive()
    }
}

impl ViewingHistory {
    /// A wallet whose one viewing key never paid or was paid.
    pub fn new(viewing_pubkey: X25519Pubkey, created_at: i64) -> Self {
        Self {
            entries: vec![ViewingKeyEntry::new(viewing_pubkey, created_at)],
        }
    }

    /// The rotated key becomes current, the earlier keys keep reading what was sent to them.
    pub fn with_rotated_key(
        mut self,
        viewing_pubkey: X25519Pubkey,
        created_at: i64,
    ) -> Result<Self, AnonymousError> {
        let current = self.current();
        if created_at <= current.created_at || self.entry(&viewing_pubkey).is_some() {
            return Err(AnonymousError::RotatedKeyNotNewer);
        }
        let entry = self.unread_entry(viewing_pubkey, created_at);
        self.entries.push(entry);
        Ok(self)
    }

    /// A key the wallet held before its current one, the current key stays last.
    pub fn with_imported_key(
        mut self,
        viewing_pubkey: X25519Pubkey,
        created_at: i64,
    ) -> Result<Self, AnonymousError> {
        let taken = self
            .entries
            .iter()
            .any(|entry| entry.created_at == created_at);
        if created_at >= self.current().created_at || taken || self.entry(&viewing_pubkey).is_some()
        {
            return Err(AnonymousError::ImportedKeyNotOlder);
        }
        let entry = self.unread_entry(viewing_pubkey, created_at);
        let at = self
            .entries
            .partition_point(|entry| entry.created_at < created_at);
        self.entries.insert(at, entry);
        Ok(self)
    }

    /// Existing ring positions remain unchanged.
    pub fn with_ring(mut self, ring: Address, after_slot: Option<u64>) -> Self {
        for entry in &mut self.entries {
            entry.ring_positions.entry(ring).or_insert(after_slot);
        }
        self
    }

    /// Every ring the wallet reads is unread under an added key, its next sync reads their history.
    fn unread_entry(&self, viewing_pubkey: X25519Pubkey, created_at: i64) -> ViewingKeyEntry {
        ViewingKeyEntry {
            ring_positions: self
                .entries
                .iter()
                .flat_map(|entry| entry.ring_positions.keys())
                .map(|ring| (*ring, None))
                .collect(),
            ..ViewingKeyEntry::new(viewing_pubkey, created_at)
        }
    }

    pub fn entries(&self) -> &[ViewingKeyEntry] {
        &self.entries
    }

    /// Reads `sender`'s shared tags under the current key once the wallet trusts its claim.
    pub fn confirm_sender(&mut self, sender: X25519Pubkey) -> Result<(), AnonymousError> {
        self.current_mut().confirm_sender(sender)
    }

    pub fn current(&self) -> &ViewingKeyEntry {
        // Every constructor and `from_json` holds at least one entry.
        &self.entries[self.entries.len() - 1]
    }

    pub fn entry(&self, viewing_pubkey: &X25519Pubkey) -> Option<&ViewingKeyEntry> {
        self.entries
            .iter()
            .find(|entry| entry.viewing_pubkey == *viewing_pubkey)
    }

    pub(crate) fn entries_mut(&mut self) -> &mut [ViewingKeyEntry] {
        &mut self.entries
    }

    /// The next sender tag of the current key, the tag of a deposit to the wallet's own note.
    pub fn sender_tag<K: RingKeys + ?Sized>(
        &self,
        keys: &K,
    ) -> Result<AdvancedTag<ViewTag>, AnonymousError> {
        self.own_tag(keys, |entry| {
            Ok(ViewTagStream::Sender {
                tx_count: entry.tx.take_next()?,
            })
        })
    }

    fn own_tag<K: RingKeys + ?Sized>(
        &self,
        keys: &K,
        advance: impl FnOnce(&mut ViewingKeyEntry) -> Result<ViewTagStream, AnonymousError>,
    ) -> Result<AdvancedTag<ViewTag>, AnonymousError> {
        let mut history = self.clone();
        let current = history.current_mut();
        let stream = advance(current)?;
        let tag = exactly_one(keys.view_tags(&[ViewTagRequest {
            viewing_pubkey: current.viewing_pubkey,
            stream,
        }])?)?;
        Ok(AdvancedTag { tag, history })
    }

    fn current_mut(&mut self) -> &mut ViewingKeyEntry {
        let last = self.entries.len() - 1;
        &mut self.entries[last]
    }

    /// Whether every stored key's progress is unmoved, an added key starts with none.
    pub(crate) fn progress_matches(&self, stored: &Self) -> bool {
        stored.entries.iter().all(|stored| {
            self.entry(&stored.viewing_pubkey)
                .is_some_and(|entry| entry.progress_matches(stored))
        }) && self.entries.iter().all(|entry| {
            stored.entry(&entry.viewing_pubkey).is_some()
                || (entry.tx.scanned == 0
                    && entry.tag_position.is_none()
                    && entry.ring_positions.values().all(Option::is_none))
        })
    }
}

impl fmt::Debug for ViewingHistory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewingHistory")
            .field("entries", &self.entries)
            .finish()
    }
}

/// The persisted form, keys in hex.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HistoryJson {
    viewing_history: Vec<EntryJson>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EntryJson {
    viewing_pubkey: String,
    created_at: i64,
    tx: CounterJson,
    known_senders: Vec<String>,
    ring_positions: Vec<RingPositionJson>,
    tag_position: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RingPositionJson {
    ring: String,
    after_slot: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CounterJson {
    next: u64,
    scanned: u64,
    pending: Vec<u64>,
}

impl From<&StreamCounter> for CounterJson {
    fn from(counter: &StreamCounter) -> Self {
        Self {
            next: counter.next,
            scanned: counter.scanned,
            pending: counter.pending().collect(),
        }
    }
}

impl TryFrom<CounterJson> for StreamCounter {
    type Error = AnonymousError;

    fn try_from(stored: CounterJson) -> Result<Self, AnonymousError> {
        if stored.scanned > stored.next {
            return Err(invalid("a scan watermark passes its next index"));
        }
        let floor = stored.scanned.saturating_sub(PENDING_RETENTION);
        let ascending = stored.pending.windows(2).all(|pair| pair[0] < pair[1]);
        let retained = stored
            .pending
            .iter()
            .all(|index| (floor..stored.scanned).contains(index));
        match ascending && retained {
            true => Ok(Self {
                next: stored.next,
                scanned: stored.scanned,
                pending: stored.pending.into_iter().collect(),
            }),
            false => Err(invalid(
                "a pending index repeats or lies outside its retention window",
            )),
        }
    }
}

impl ViewingHistory {
    /// Stored only inside `AnonymousWallet`, its positions and watermarks cover the wallet's notes.
    pub(crate) fn to_json_value(&self) -> serde_json::Value {
        let history = HistoryJson {
            viewing_history: self
                .entries
                .iter()
                .map(|entry| {
                    let mut known_senders: Vec<String> = entry
                        .known_senders
                        .iter()
                        .map(|sender| hex::encode(sender.as_bytes()))
                        .collect();
                    known_senders.sort();
                    EntryJson {
                        viewing_pubkey: hex::encode(entry.viewing_pubkey.as_bytes()),
                        created_at: entry.created_at,
                        tx: (&entry.tx).into(),
                        known_senders,
                        ring_positions: entry
                            .ring_positions
                            .iter()
                            .map(|(ring, after_slot)| RingPositionJson {
                                ring: ring.to_string(),
                                after_slot: *after_slot,
                            })
                            .collect(),
                        tag_position: entry.tag_position,
                    }
                })
                .collect(),
        };
        serde_json::to_value(&history)
            .expect("a struct of strings, integers and vectors serializes")
    }

    pub(crate) fn from_json_value(value: serde_json::Value) -> Result<Self, AnonymousError> {
        let entries = HistoryJson::deserialize(&value)
            .map_err(unparsed)?
            .viewing_history
            .into_iter()
            .map(entry_of)
            .collect::<Result<Vec<_>, _>>()?;
        for (at, entry) in entries.iter().enumerate() {
            if at > 0 && entries[at - 1].created_at >= entry.created_at
                || entries[..at]
                    .iter()
                    .any(|earlier| earlier.viewing_pubkey == entry.viewing_pubkey)
            {
                return Err(invalid("viewing keys repeat or are not oldest first"));
            }
        }
        if entries.is_empty() {
            return Err(invalid("holds no viewing key"));
        }
        Ok(Self { entries })
    }
}

fn entry_of(stored: EntryJson) -> Result<ViewingKeyEntry, AnonymousError> {
    let mut ring_positions = BTreeMap::new();
    for position in stored.ring_positions {
        let ring: Address = position
            .ring
            .parse()
            .map_err(|_| invalid("ringPositions holds a ring that is not an address"))?;
        if ring_positions.insert(ring, position.after_slot).is_some() {
            return Err(invalid("ringPositions repeats a ring"));
        }
    }
    Ok(ViewingKeyEntry {
        viewing_pubkey: pubkey("viewingPubkey", &stored.viewing_pubkey)?,
        created_at: stored.created_at,
        tx: stored.tx.try_into()?,
        known_senders: senders(&stored.known_senders)?,
        ring_positions,
        tag_position: stored.tag_position,
    })
}

fn senders(keys: &[String]) -> Result<HashSet<X25519Pubkey>, AnonymousError> {
    let mut known = HashSet::new();
    for text in keys {
        let key = pubkey("knownSenders", text)?;
        if !is_contributory(&key) {
            return Err(invalid("knownSenders holds a small-order key"));
        }
        if !known.insert(key) {
            return Err(invalid("knownSenders repeats a key"));
        }
    }
    Ok(known)
}

/// An error names the field alone.
fn pubkey(name: &str, text: &str) -> Result<X25519Pubkey, AnonymousError> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| <[u8; X25519_PUBKEY_LEN]>::try_from(bytes).ok())
        .and_then(|bytes| X25519Pubkey::from_bytes(bytes).ok())
        .ok_or_else(|| {
            invalid(&format!(
                "{name} holds a key that is not a tagged X25519 key"
            ))
        })
}

fn invalid(reason: &str) -> AnonymousError {
    AnonymousError::ViewingHistory(reason.to_owned())
}

/// A serde message can quote the value it refused, the position alone names the fault.
fn unparsed(error: serde_json::Error) -> AnonymousError {
    AnonymousError::ViewingHistory(format!(
        "{:?} at line {} column {}",
        error.classify(),
        error.line(),
        error.column()
    ))
}

#[cfg(test)]
mod tests {
    use spr_keypair::ViewingKey;

    use super::*;

    #[test]
    fn a_stored_pending_index_outside_its_window_or_repeated_is_refused() {
        let counter = StreamCounter {
            next: PENDING_RETENTION + 2,
            scanned: PENDING_RETENTION + 2,
            pending: (2..=PENDING_RETENTION).collect(),
        };
        let mut history = ViewingHistory::new(ViewingKey::new().pubkey(), 0);
        history.entries_mut()[0].tx = counter;
        let stored = history.to_json_value();
        assert_eq!(
            ViewingHistory::from_json_value(stored.clone()).unwrap(),
            history
        );
        for pending in [vec![0], vec![2, 2], vec![3, 2], vec![PENDING_RETENTION + 2]] {
            let mut refused = stored.clone();
            refused["viewingHistory"][0]["tx"]["pending"] = pending.clone().into();
            assert!(
                matches!(
                    ViewingHistory::from_json_value(refused),
                    Err(AnonymousError::ViewingHistory(_))
                ),
                "{pending:?}"
            );
        }
    }

    #[test]
    fn a_stored_watermark_past_its_next_index_is_refused() {
        let history = ViewingHistory::new(ViewingKey::new().pubkey(), 0);
        let mut stored = history.to_json_value();
        stored["viewingHistory"][0]["tx"]["scanned"] = 1.into();
        assert!(matches!(
            ViewingHistory::from_json_value(stored),
            Err(AnonymousError::ViewingHistory(_))
        ));
    }

    #[test]
    fn an_added_key_reads_every_watched_ring_from_its_start() {
        let ring = Address::new_from_array([7; 32]);
        let synced = ViewingHistory::new(ViewingKey::new().pubkey(), 10).with_ring(ring, Some(40));
        let imported = ViewingKey::new().pubkey();
        let rotated = ViewingKey::new().pubkey();
        let added = synced
            .with_imported_key(imported, 5)
            .unwrap()
            .with_rotated_key(rotated, 20)
            .unwrap();
        assert_eq!(
            added.entry(&imported).unwrap().ring_positions()[&ring],
            None
        );
        assert_eq!(added.current().viewing_pubkey(), rotated);
        assert_eq!(added.current().ring_positions()[&ring], None);
        assert_eq!(added.entries()[1].ring_positions()[&ring], Some(40));
    }

    #[test]
    fn watching_a_ring_fills_absent_positions_and_preserves_existing_ones() {
        let existing = Address::new_from_array([7; 32]);
        let added = Address::new_from_array([8; 32]);
        let history = ViewingHistory::new(ViewingKey::new().pubkey(), 10)
            .with_ring(existing, Some(40))
            .with_rotated_key(ViewingKey::new().pubkey(), 20)
            .unwrap()
            .with_ring(existing, Some(90))
            .with_ring(added, Some(60));
        assert_eq!(history.entries()[0].ring_positions()[&existing], Some(40));
        assert_eq!(history.entries()[1].ring_positions()[&existing], None);
        assert!(history
            .entries()
            .iter()
            .all(|entry| entry.ring_positions()[&added] == Some(60)));
    }

    #[test]
    fn an_import_newer_than_the_current_key_or_repeated_is_refused() {
        let current = ViewingKey::new().pubkey();
        let history = ViewingHistory::new(current, 10);
        for (key, created_at) in [
            (ViewingKey::new().pubkey(), 11),
            (ViewingKey::new().pubkey(), 10),
            (current, 5),
        ] {
            assert!(matches!(
                history.clone().with_imported_key(key, created_at),
                Err(AnonymousError::ImportedKeyNotOlder)
            ));
        }
    }
}
