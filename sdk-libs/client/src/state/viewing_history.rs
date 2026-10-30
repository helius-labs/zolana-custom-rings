//! The anonymous rail's wallet state, spec `ViewingKeyEntry` per retained viewing key, and the
//! spec view tag selection over it.

use std::{
    collections::{BTreeSet, HashMap},
    fmt,
};

use serde::{Deserialize, Serialize};
use spr_keypair::{viewing_key::ViewTag, x25519::X25519_PUBKEY_LEN, X25519Pubkey};
use spr_transaction::ShieldedKeys;
use zolana_ring_keys::{RingKeys, SharedTagPair, SharedTagsRequest, ViewTagRequest, ViewTagStream};
use zolana_ring_transaction::{is_contributory, AnonymousPlan, TaggedPayment};

use crate::{exactly_one, AnonymousError, REDACTED, TAGS_PER_REQUEST};

pub const VIEWING_HISTORY_VERSION: u32 = 7;

/// How far below its watermark a sync still reads an unobserved index.
pub const PENDING_RETENTION: u64 = 256;

/// Indices a stream's first round reads past its next index, doubled up to [`TAGS_PER_REQUEST`] after every round that finds one.
pub const TAG_GAP: u64 = 20;

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
    request: StreamCounter,
    /// Keyed by the viewing key a sender's recipient bodies name.
    known_senders: HashMap<X25519Pubkey, StreamCounter>,
    known_recipients: HashMap<X25519Pubkey, StreamCounter>,
}

/// Every retained viewing key, oldest first, the last one current.
#[derive(Clone, PartialEq, Eq)]
pub struct ViewingHistory {
    entries: Vec<ViewingKeyEntry>,
}

/// The tag a first payment to a recipient takes, chosen by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstContact {
    Request(ViewTag),
    /// The recipient's `recipient_bootstrap_view_tag`, readable by anyone who knows its address.
    Bootstrap,
}

/// A first contact pairs only when its body names the sender.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FirstContactPairing {
    Pairs,
    Unpaired,
}

/// Paid under `first_contact` until the pair is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentRecipient {
    pub viewing_pubkey: X25519Pubkey,
    pub first_contact: FirstContact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagSelection {
    Shared { index: u64 },
    Request,
    Bootstrap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentTag {
    pub payment: TaggedPayment,
    pub selection: TagSelection,
}

/// `history` is advanced past the tags and stored before the transfer is sent.
#[must_use]
#[derive(Clone, Debug)]
pub struct TransferTags {
    pub sender_tag: ViewTag,
    pub payments: Vec<PaymentTag>,
    pub history: ViewingHistory,
}

/// `history` is advanced past `tag`.
#[must_use]
#[derive(Clone, Debug)]
pub struct AdvancedTag<T> {
    pub tag: T,
    pub history: ViewingHistory,
}

/// The tags of a transfer from the current viewing key, payments in declared order.
#[must_use]
pub struct TransferTagging<'a, K: ?Sized> {
    pub keys: &'a K,
    pub history: &'a ViewingHistory,
    pub recipients: &'a [PaymentRecipient],
}

#[derive(Clone, Debug)]
pub(crate) struct GapScan {
    from: u64,
    start: u64,
    end: u64,
    gap: u64,
    late: Vec<u64>,
    observed: BTreeSet<u64>,
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

    /// A scan from `from` saw `observed`, an index it passed unseen stays pending.
    pub(crate) fn observe(&mut self, from: u64, observed: &BTreeSet<u64>) {
        let reached = observed
            .range(from..)
            .next_back()
            .map_or(from, |highest| highest.saturating_add(1));
        self.scanned = self.scanned.max(reached);
        self.next = self.next.max(self.scanned);
        let floor = self.scanned.saturating_sub(PENDING_RETENTION);
        self.pending.extend(from.max(floor)..reached);
        self.pending
            .retain(|index| *index >= floor && !observed.contains(index));
    }

    fn take_next(&mut self) -> Result<u64, AnonymousError> {
        let next = self.next;
        self.next = next.checked_add(1).ok_or(AnonymousError::CounterOverflow)?;
        Ok(next)
    }
}

impl GapScan {
    pub(crate) fn new(from: u64, counter: &StreamCounter) -> Self {
        Self {
            from,
            start: from,
            end: counter.next.max(from).saturating_add(TAG_GAP),
            gap: TAG_GAP,
            late: counter.pending().collect(),
            observed: BTreeSet::new(),
        }
    }

    pub(crate) fn round(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.late)
            .into_iter()
            .chain(self.start..self.end)
            .collect()
    }

    /// `false` once a round finds nothing in its range.
    pub(crate) fn advance(&mut self, seen: impl IntoIterator<Item = u64>) -> bool {
        self.observed.extend(seen);
        if self.observed.range(self.start..self.end).next().is_none() {
            return false;
        }
        self.gap = self.gap.saturating_mul(2).min(TAGS_PER_REQUEST as u64);
        self.start = self.end;
        self.end = self.start.saturating_add(self.gap);
        true
    }

    pub(crate) fn finish(&self, counter: &mut StreamCounter) {
        counter.observe(self.from, &self.observed);
    }
}

impl ViewingKeyEntry {
    pub fn new(viewing_pubkey: X25519Pubkey, created_at: i64) -> Self {
        Self {
            viewing_pubkey,
            created_at,
            tx: StreamCounter::default(),
            request: StreamCounter::default(),
            known_senders: HashMap::new(),
            known_recipients: HashMap::new(),
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

    pub fn request_count(&self) -> u64 {
        self.request.next
    }

    pub fn tx_stream(&self) -> &StreamCounter {
        &self.tx
    }

    pub fn request_stream(&self) -> &StreamCounter {
        &self.request
    }

    pub fn known_senders(&self) -> &HashMap<X25519Pubkey, StreamCounter> {
        &self.known_senders
    }

    pub fn known_recipients(&self) -> &HashMap<X25519Pubkey, StreamCounter> {
        &self.known_recipients
    }

    pub(crate) fn tx_stream_mut(&mut self) -> &mut StreamCounter {
        &mut self.tx
    }

    pub(crate) fn request_stream_mut(&mut self) -> &mut StreamCounter {
        &mut self.request
    }

    pub(crate) fn pair_mut(&mut self, pair: &SharedTagPair) -> Option<&mut StreamCounter> {
        match pair {
            SharedTagPair::FromSender(sender) => self.known_senders.get_mut(sender),
            SharedTagPair::ToRecipient(recipient) => self.known_recipients.get_mut(recipient),
        }
    }

    pub(crate) fn learn(&mut self, pair: SharedTagPair) {
        let (known, key) = match pair {
            SharedTagPair::FromSender(sender) => (&mut self.known_senders, sender),
            SharedTagPair::ToRecipient(recipient) => (&mut self.known_recipients, recipient),
        };
        known.entry(key).or_default();
    }

    /// Shared once known, else the caller's first contact tag.
    fn select<K: RingKeys + ?Sized>(
        &mut self,
        keys: &K,
        recipient: &PaymentRecipient,
        pairing: FirstContactPairing,
    ) -> Result<PaymentTag, AnonymousError> {
        let viewing_pubkey = self.viewing_pubkey;
        let (tag, selection) = match self.known_recipients.get_mut(&recipient.viewing_pubkey) {
            Some(counter) => {
                let index = counter.take_next()?;
                let shared = exactly_one(keys.shared_view_tags(&[SharedTagsRequest {
                    viewing_pubkey,
                    pair: SharedTagPair::ToRecipient(recipient.viewing_pubkey),
                }])?)?;
                (shared.tag(index)?, TagSelection::Shared { index })
            }
            None => {
                if !is_contributory(&recipient.viewing_pubkey) {
                    return Err(AnonymousError::RecipientKeyNotContributory);
                }
                if pairing == FirstContactPairing::Pairs {
                    self.learn(SharedTagPair::ToRecipient(recipient.viewing_pubkey));
                }
                match recipient.first_contact {
                    FirstContact::Request(tag) => (tag, TagSelection::Request),
                    FirstContact::Bootstrap => {
                        (recipient.viewing_pubkey.u(), TagSelection::Bootstrap)
                    }
                }
            }
        };
        Ok(PaymentTag {
            payment: TaggedPayment {
                recipient: recipient.viewing_pubkey,
                tag,
            },
            selection,
        })
    }
}

impl fmt::Debug for ViewingKeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewingKeyEntry")
            .field("created_at", &self.created_at)
            .field("tx", &self.tx)
            .field("request", &self.request)
            .field("known_senders", &REDACTED)
            .field("known_recipients", &REDACTED)
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
        self.entries
            .push(ViewingKeyEntry::new(viewing_pubkey, created_at));
        Ok(self)
    }

    pub fn entries(&self) -> &[ViewingKeyEntry] {
        &self.entries
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

    /// A deposit's tag, a first contact pairs nothing since a deposit names no sender.
    pub fn deposit_tag<K: RingKeys + ?Sized>(
        &self,
        keys: &K,
        recipient: &PaymentRecipient,
    ) -> Result<AdvancedTag<PaymentTag>, AnonymousError> {
        let mut history = self.clone();
        let tag = history
            .current_mut()
            .select(keys, recipient, FirstContactPairing::Unpaired)?;
        Ok(AdvancedTag { tag, history })
    }

    /// A fresh `recipient_request_view_tag` for a payment request.
    pub fn request_tag<K: RingKeys + ?Sized>(
        &self,
        keys: &K,
    ) -> Result<AdvancedTag<ViewTag>, AnonymousError> {
        self.own_tag(keys, |entry| {
            Ok(ViewTagStream::Request {
                request_count: entry.request.take_next()?,
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
}

impl fmt::Debug for ViewingHistory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewingHistory")
            .field("entries", &self.entries)
            .finish()
    }
}

impl TransferTags {
    pub fn anonymous_plan(&self) -> AnonymousPlan {
        self.payments
            .iter()
            .fold(AnonymousPlan::new(self.sender_tag), |plan, tag| {
                plan.with_payment(tag.payment)
            })
    }
}

impl<K: ShieldedKeys + RingKeys + ?Sized> TransferTagging<'_, K> {
    /// Refused unless the history's current key is the wallet's viewing key.
    pub fn plan(self) -> Result<TransferTags, AnonymousError> {
        if self.history.current().viewing_pubkey != self.keys.address()?.viewing_pubkey {
            return Err(AnonymousError::ViewingKeyNotCurrent);
        }
        let AdvancedTag {
            tag: sender_tag,
            mut history,
        } = self.history.sender_tag(self.keys)?;
        let current = history.current_mut();
        let payments = self
            .recipients
            .iter()
            .map(|recipient| current.select(self.keys, recipient, FirstContactPairing::Pairs))
            .collect::<Result<_, _>>()?;
        Ok(TransferTags {
            sender_tag,
            payments,
            history,
        })
    }
}

/// The persisted form, keys in hex.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HistoryJson {
    version: u32,
    viewing_history: Vec<EntryJson>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EntryJson {
    viewing_pubkey: String,
    created_at: i64,
    tx: CounterJson,
    request: CounterJson,
    known_senders: Vec<CounterpartyJson>,
    known_recipients: Vec<CounterpartyJson>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CounterJson {
    next: u64,
    scanned: u64,
    pending: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CounterpartyJson {
    pubkey: String,
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
    /// Its counterparties link the wallet's payments, store it as key material.
    pub fn to_json(&self) -> String {
        let counterparties = |known: &HashMap<X25519Pubkey, StreamCounter>| {
            let mut rows: Vec<CounterpartyJson> = known
                .iter()
                .map(|(pubkey, counter)| {
                    let CounterJson {
                        next,
                        scanned,
                        pending,
                    } = counter.into();
                    CounterpartyJson {
                        pubkey: hex::encode(pubkey.as_bytes()),
                        next,
                        scanned,
                        pending,
                    }
                })
                .collect();
            rows.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
            rows
        };
        let history = HistoryJson {
            version: VIEWING_HISTORY_VERSION,
            viewing_history: self
                .entries
                .iter()
                .map(|entry| EntryJson {
                    viewing_pubkey: hex::encode(entry.viewing_pubkey.as_bytes()),
                    created_at: entry.created_at,
                    tx: (&entry.tx).into(),
                    request: (&entry.request).into(),
                    known_senders: counterparties(&entry.known_senders),
                    known_recipients: counterparties(&entry.known_recipients),
                })
                .collect(),
        };
        serde_json::to_string(&history)
            .expect("a struct of strings, integers and vectors serializes")
    }

    /// Another version fails with [`AnonymousError::ViewingHistoryVersion`], a sync rebuilds it.
    pub fn from_json(text: &str) -> Result<Self, AnonymousError> {
        #[derive(Deserialize)]
        struct Versioned {
            version: u32,
        }
        let Versioned { version } = serde_json::from_str(text).map_err(unparsed)?;
        if version != VIEWING_HISTORY_VERSION {
            return Err(AnonymousError::ViewingHistoryVersion { version });
        }
        let history: HistoryJson = serde_json::from_str(text).map_err(unparsed)?;
        let mut entries: Vec<ViewingKeyEntry> = Vec::with_capacity(history.viewing_history.len());
        for stored in history.viewing_history {
            let entry = ViewingKeyEntry {
                viewing_pubkey: pubkey("viewingPubkey", &stored.viewing_pubkey)?,
                created_at: stored.created_at,
                tx: stored.tx.try_into()?,
                request: stored.request.try_into()?,
                known_senders: counterparties("knownSenders", stored.known_senders)?,
                known_recipients: counterparties("knownRecipients", stored.known_recipients)?,
            };
            if entries
                .last()
                .is_some_and(|last| last.created_at >= entry.created_at)
                || entries
                    .iter()
                    .any(|earlier| earlier.viewing_pubkey == entry.viewing_pubkey)
            {
                return Err(invalid("viewing keys repeat or are not oldest first"));
            }
            entries.push(entry);
        }
        if entries.is_empty() {
            return Err(invalid("holds no viewing key"));
        }
        Ok(Self { entries })
    }
}

fn counterparties(
    name: &str,
    rows: Vec<CounterpartyJson>,
) -> Result<HashMap<X25519Pubkey, StreamCounter>, AnonymousError> {
    let mut known = HashMap::with_capacity(rows.len());
    for row in rows {
        let key = pubkey(name, &row.pubkey)?;
        if !is_contributory(&key) {
            return Err(invalid(&format!("{name} holds a small-order key")));
        }
        if known
            .insert(
                key,
                CounterJson {
                    next: row.next,
                    scanned: row.scanned,
                    pending: row.pending,
                }
                .try_into()?,
            )
            .is_some()
        {
            return Err(invalid(&format!("{name} repeats a key")));
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
    fn an_unseen_index_stays_pending_until_it_trails_past_the_retention() {
        let mut counter = StreamCounter::default();
        counter.observe(0, &BTreeSet::from([1, 3]));
        assert_eq!((counter.scanned(), counter.next()), (4, 4));
        assert_eq!(counter.pending().collect::<Vec<_>>(), [0, 2]);
        counter.observe(4, &BTreeSet::from([2]));
        assert_eq!(counter.pending().collect::<Vec<_>>(), [0]);
        counter.observe(4, &BTreeSet::from([PENDING_RETENTION]));
        assert_eq!(counter.scanned(), PENDING_RETENTION + 1);
        assert_eq!(
            counter.pending().collect::<Vec<_>>(),
            (4..PENDING_RETENTION).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_round_finding_its_last_index_reads_at_most_one_request_next() {
        let mut scan = GapScan::new(0, &StreamCounter::default());
        for _ in 0..64 {
            let round = scan.round();
            assert!(round.len() <= TAGS_PER_REQUEST);
            assert!(scan.advance(round.last().copied()));
        }
    }

    #[test]
    fn a_full_rescan_keeps_the_watermark_and_the_pending_index_it_passes_unseen() {
        let mut counter = StreamCounter::default();
        counter.observe(0, &BTreeSet::from([1, 3]));
        counter.observe(0, &BTreeSet::from([0, 1]));
        assert_eq!(counter.scanned(), 4);
        assert_eq!(counter.pending().collect::<Vec<_>>(), [2]);
    }

    #[test]
    fn a_stored_pending_index_outside_its_window_or_repeated_is_refused() {
        let mut counter = StreamCounter::default();
        counter.observe(0, &BTreeSet::from([PENDING_RETENTION + 1]));
        let mut history = ViewingHistory::new(ViewingKey::new().pubkey(), 0);
        history.entries_mut()[0].tx = counter;
        assert_eq!(
            ViewingHistory::from_json(&history.to_json()).unwrap(),
            history
        );
        let stored: serde_json::Value = serde_json::from_str(&history.to_json()).unwrap();
        for pending in [vec![0], vec![2, 2], vec![3, 2], vec![PENDING_RETENTION + 2]] {
            let mut refused = stored.clone();
            refused["viewingHistory"][0]["tx"]["pending"] = pending.clone().into();
            assert!(
                matches!(
                    ViewingHistory::from_json(&refused.to_string()),
                    Err(AnonymousError::ViewingHistory(_))
                ),
                "{pending:?}"
            );
        }
    }

    #[test]
    fn a_stored_watermark_past_its_next_index_is_refused() {
        let history = ViewingHistory::new(ViewingKey::new().pubkey(), 0);
        let mut stored: serde_json::Value = serde_json::from_str(&history.to_json()).unwrap();
        stored["viewingHistory"][0]["tx"]["scanned"] = 1.into();
        assert!(matches!(
            ViewingHistory::from_json(&stored.to_string()),
            Err(AnonymousError::ViewingHistory(_))
        ));
    }
}
