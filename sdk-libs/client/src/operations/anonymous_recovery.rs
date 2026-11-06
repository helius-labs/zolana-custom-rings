use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::*;
use crate::history::RecoveryWindow;
use crate::tags::TAGS_PER_REQUEST;

const SESSION_VERSION: u8 = 1;
const DIAGNOSTIC_SAMPLES: usize = 64;
const PAGE_LIMIT: u32 = spr_indexer_api::PAGE_LIMIT as u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStatus {
    Paused,
    Complete,
}

#[derive(Default)]
pub(crate) enum RecoveryUpdate {
    #[default]
    Keep,
    Paused(Box<RecoverySession>),
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RecoverySession {
    version: u8,
    scope: RecoveryScope,
    pub(crate) target_slot: Option<u64>,
    working_history: Value,
    tasks: VecDeque<DiscoveryTask>,
    queue: VecDeque<[u8; 32]>,
    known: BTreeSet<[u8; 32]>,
    pub(crate) checked: BTreeSet<[u8; 32]>,
    active: Option<SpendBatch>,
    diagnostics: AuditorRecovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RecoveryScope {
    owner: String,
    keys: Vec<String>,
    full_scan: Option<Address>,
    from_start: bool,
    sender_fast_path: bool,
    starting_history: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "camelCase")]
enum DiscoveryTask {
    Ring {
        ring: Address,
        entries: Vec<usize>,
        window: RecoveryWindow,
        offset: PageOffset,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PageOffset {
    row: usize,
    entry: usize,
    site: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SpendBatch {
    nullifiers: Vec<[u8; 32]>,
    window: RecoveryWindow,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PageProgress {
    More,
    Done,
    Paused,
}

struct DiscoveryStep<'s> {
    task: &'s mut DiscoveryTask,
    session: &'s mut RecoverySession,
}

struct BodyWork<'a, 't> {
    entry: usize,
    body: &'a Body<'t>,
    secret: &'a SlotSecret,
}

impl RecoverySession {
    pub(crate) fn validate(&self) -> Result<(), AnonymousError> {
        let starting = ViewingHistory::from_json_value(self.scope.starting_history.clone())?;
        let working = ViewingHistory::from_json_value(self.working_history.clone())?;
        if self.target_slot.is_none()
            || starting.entries().len() != working.entries().len()
            || starting
                .entries()
                .iter()
                .zip(working.entries())
                .any(|(before, after)| {
                    before.viewing_pubkey() != after.viewing_pubkey()
                        || before.created_at() != after.created_at()
                        || before.known_senders() != after.known_senders()
                })
        {
            return Err(AnonymousError::RecoveryScopeChanged);
        }
        if self.version != SESSION_VERSION
            || self.diagnostics.unopened.len() > DIAGNOSTIC_SAMPLES
            || self.diagnostics.unopened_count < self.diagnostics.unopened.len() as u64
            || !self.checked.is_subset(&self.known)
            || self
                .queue
                .iter()
                .any(|key| !self.known.contains(key) || self.checked.contains(key))
            || self.queue.iter().copied().collect::<BTreeSet<_>>().len() != self.queue.len()
        {
            return Err(AnonymousError::RecoveryScopeChanged);
        }
        if let Some(active) = &self.active {
            if active.nullifiers.is_empty()
                || active.nullifiers.len() > TAGS_PER_REQUEST
                || active.window.target_slot != self.target_slot
                || active
                    .nullifiers
                    .iter()
                    .any(|key| !self.known.contains(key) || self.checked.contains(key))
            {
                return Err(AnonymousError::RecoveryScopeChanged);
            }
        }
        let mut scheduled = self.checked.clone();
        for nullifier in self
            .queue
            .iter()
            .chain(self.active.iter().flat_map(|batch| &batch.nullifiers))
        {
            if !scheduled.insert(*nullifier) {
                return Err(AnonymousError::RecoveryScopeChanged);
            }
        }
        if scheduled != self.known {
            return Err(AnonymousError::RecoveryScopeChanged);
        }
        for task in &self.tasks {
            let valid_entry = |entry: usize| {
                working.entries().get(entry).is_some_and(|entry| {
                    self.scope
                        .keys
                        .contains(&hex::encode(entry.viewing_pubkey().as_bytes()))
                })
            };
            let DiscoveryTask::Ring {
                entries, window, ..
            } = task;
            if entries.iter().any(|entry| !valid_entry(*entry))
                || window
                    .page_limit
                    .is_some_and(|limit| limit == 0 || limit > PAGE_LIMIT)
                || window.target_slot != self.target_slot
            {
                return Err(AnonymousError::RecoveryScopeChanged);
            }
        }
        Ok(())
    }

    fn enqueue(&mut self, nullifier: [u8; 32]) {
        if self.known.insert(nullifier) {
            self.queue.push_back(nullifier);
        }
    }

    fn set_target(&mut self, target: u64) {
        self.target_slot = Some(target);
        for DiscoveryTask::Ring { window, .. } in &mut self.tasks {
            window.target_slot = Some(target);
        }
    }

    fn complete(&self) -> bool {
        self.tasks.is_empty() && self.queue.is_empty() && self.active.is_none()
    }
}

impl<'a, K: ShieldedKeys + RingKeys + MergeSeedHolder + ?Sized> AnonymousSync<'a, K> {
    pub fn with_page_budget(mut self, pages: usize) -> Result<Self, AnonymousError> {
        if pages == 0 {
            return Err(AnonymousError::RecoveryBudget);
        }
        self.page_budget = pages;
        Ok(self)
    }

    pub fn with_full_scan(mut self, ring: Address) -> Self {
        self.full_ring = Some(ring);
        self
    }

    pub(super) async fn recover_wallet<I: AsyncRpc + ?Sized>(
        &self,
        indexer: &I,
        wallet: &AnonymousWallet,
    ) -> Result<AnonymousScan, AnonymousError> {
        let full_scan = self.full_ring;
        let mut scan = self.scan(indexer, wallet.history())?;
        let held = scan.held_entries();
        let mut keys: Vec<_> = self
            .keys
            .viewing_public_keys()
            .iter()
            .map(|key| hex::encode(key.as_bytes()))
            .collect();
        keys.sort();
        let scope = RecoveryScope {
            owner: self.keys.address()?.to_string(),
            keys,
            full_scan,
            from_start: self.from == ScanFrom::Start,
            sender_fast_path: self.sender_fast_path,
            starting_history: wallet.history().to_json_value(),
        };
        let mut session = if let Some(session) = wallet.recovery_session() {
            session.validate()?;
            if session.scope != scope {
                return Err(AnonymousError::RecoveryScopeChanged);
            }
            scan.history = ViewingHistory::from_json_value(session.working_history.clone())?;
            session.clone()
        } else {
            let mut tasks = VecDeque::new();
            if let Some(ring) = full_scan {
                tasks.push_back(DiscoveryTask::Ring {
                    ring,
                    entries: held.clone(),
                    window: RecoveryWindow::default(),
                    offset: PageOffset::default(),
                });
            } else {
                for read in scan.ring_reads(&held) {
                    tasks.push_back(DiscoveryTask::Ring {
                        ring: read.ring,
                        entries: read.entries,
                        window: RecoveryWindow {
                            after_slot: read.position.checkpoint(),
                            ..RecoveryWindow::default()
                        },
                        offset: PageOffset::default(),
                    });
                }
            }
            RecoverySession {
                version: SESSION_VERSION,
                scope,
                target_slot: None,
                working_history: wallet.history().to_json_value(),
                tasks,
                queue: VecDeque::new(),
                known: BTreeSet::new(),
                checked: BTreeSet::new(),
                active: None,
                diagnostics: AuditorRecovery::default(),
            }
        };
        scan.minimum_slot = wallet
            .notes()
            .iter()
            .chain(wallet.pending_notes().iter().map(PendingNote::opening))
            .map(|note| note.slot)
            .max();
        if session
            .target_slot
            .is_some_and(|target| scan.minimum_slot.is_some_and(|slot| slot > target))
        {
            return Err(AnonymousError::RecoveryScopeChanged);
        }
        scan.resolved_assets.extend(
            wallet
                .notes()
                .iter()
                .filter(|note| note.utxo.asset.asset_id != 0)
                .map(|note| (note.utxo.asset.asset_id, note.utxo.asset)),
        );
        scan.owned_nullifiers
            .extend(wallet.notes().iter().map(|note| note.nullifier));
        scan.owned_nullifiers
            .extend(wallet.pending_notes().iter().map(PendingNote::nullifier));
        scan.found_hashes
            .extend(wallet.notes().iter().map(|note| note.utxo_hash));
        scan.found_hashes
            .extend(wallet.pending_notes().iter().map(PendingNote::utxo_hash));
        for note in wallet
            .notes()
            .iter()
            .chain(wallet.pending_notes().iter().map(PendingNote::opening))
        {
            if !wallet.is_spent(&note.nullifier) {
                session.enqueue(note.nullifier);
            }
        }
        for &nullifier in wallet.merge_retries() {
            session.enqueue(nullifier);
        }
        let mut pages = 0;
        if session.target_slot.is_none() && !session.complete() {
            let target = scan.probe_target(&session).await?;
            session.set_target(target);
            pages += 1;
        }
        while pages < self.page_budget && !session.complete() {
            if session.active.is_some() || !session.queue.is_empty() {
                scan.recovery_spends(&mut session).await?;
            } else if let Some(mut task) = session.tasks.pop_front() {
                let progress = scan
                    .recovery_discovery(DiscoveryStep {
                        task: &mut task,
                        session: &mut session,
                    })
                    .await?;
                if progress != PageProgress::Done {
                    session.tasks.push_front(task);
                }
                if progress == PageProgress::Paused {
                    scan.queue_found(&mut session)?;
                    break;
                }
            }
            scan.queue_found(&mut session)?;
            pages += 1;
        }
        session.working_history = scan.history.to_json_value();
        let complete = session.complete();
        if !complete {
            scan.history = wallet.history().clone();
        }
        let diagnostics = session.diagnostics.clone();
        let target_slot = session.target_slot;
        let mut result = scan.finish(self.keys)?;
        result.expected_revision = Some(wallet.revision());
        result.retried = wallet
            .merge_retries()
            .iter()
            .filter(|nullifier| result.decrypted.spent_nullifiers.contains(*nullifier))
            .copied()
            .collect();
        result.recovery = if complete {
            RecoveryUpdate::Complete
        } else {
            RecoveryUpdate::Paused(Box::new(session))
        };
        result.target_slot = target_slot;
        result.auditor_recovery = diagnostics;
        Ok(result)
    }
}

impl<'s, 'a, 'r, I: AsyncRpc + ?Sized, K: ShieldedKeys + RingKeys + MergeSeedHolder + ?Sized>
    Scan<'s, 'a, 'r, I, K>
{
    async fn probe_target(&mut self, session: &RecoverySession) -> Result<u64, AnonymousError> {
        let floor = self
            .history
            .entries()
            .iter()
            .flat_map(|entry| {
                entry
                    .ring_positions()
                    .values()
                    .copied()
                    .chain(std::iter::once(entry.tag_position()))
                    .flatten()
            })
            .max()
            .max(self.minimum_slot)
            .max(self.sync.config.and_then(|config| config.require_slot));
        let mut window = RecoveryWindow {
            after_slot: floor,
            ..RecoveryWindow::default()
        };
        if let Some(DiscoveryTask::Ring { ring, .. }) = session.tasks.front() {
            let (page, limit) = self.reads.recovery_ring_page(*ring, window).await?;
            window
                .advance(&page, limit)
                .map_err(|_| AnonymousError::InvalidHistoryPage)?;
            return Ok(page.context.slot);
        }
        let page = self
            .reads
            .recovery_spend_page(
                session
                    .queue
                    .iter()
                    .take(TAGS_PER_REQUEST)
                    .copied()
                    .collect(),
                window,
            )
            .await?;
        window
            .advance(&page, PAGE_LIMIT)
            .map_err(|_| AnonymousError::InvalidHistoryPage)?;
        Ok(page.context.slot)
    }

    fn queue_found(&mut self, session: &mut RecoverySession) -> Result<(), AnonymousError> {
        let mut found = std::mem::take(&mut self.found);
        delivered::assign_nullifiers(self.sync.keys, &mut found)?;
        for note in &found {
            session.enqueue(note.nullifier);
        }
        self.decrypted.utxos.extend(found);
        let mut pending = std::mem::take(&mut self.held_back);
        delivered::assign_nullifiers(self.sync.keys, &mut pending)?;
        for note in &pending {
            session.enqueue(note.nullifier);
            self.decrypted.unknown_mints.insert(note.utxo.asset.asset);
        }
        self.pending_assigned.extend(pending);
        Ok(())
    }

    async fn recovery_spends(
        &mut self,
        session: &mut RecoverySession,
    ) -> Result<(), AnonymousError> {
        let mut active = session.active.take().unwrap_or_else(|| SpendBatch {
            nullifiers: session
                .queue
                .drain(..session.queue.len().min(TAGS_PER_REQUEST))
                .collect(),
            window: RecoveryWindow {
                target_slot: session.target_slot,
                ..RecoveryWindow::default()
            },
        });
        let page = self
            .reads
            .recovery_spend_page(active.nullifiers.clone(), active.window)
            .await?;
        let done = active
            .window
            .advance(&page, PAGE_LIMIT)
            .map_err(|_| AnonymousError::InvalidHistoryPage)?;
        if page.data.iter().any(|row| {
            row.validate_events(|tx| (tx.slot, tx.tx_signature, tx.event_index))
                .is_err()
        }) {
            return Err(AnonymousError::InvalidHistoryPage);
        }
        let queried: HashSet<_> = active.nullifiers.iter().copied().collect();
        if page.data.iter().any(|transaction| {
            !transaction
                .events
                .iter()
                .flat_map(|row| &row.nullifiers)
                .any(|nullifier| queried.contains(nullifier))
        }) {
            return Err(AnonymousError::InvalidHistoryPage);
        }
        let rows: Vec<_> = page.data.into_iter().flat_map(|item| item.events).collect();
        self.decrypted.spent_nullifiers.extend(
            rows.iter()
                .flat_map(|tx| tx.nullifiers.iter())
                .filter(|nf| session.known.contains(*nf))
                .copied(),
        );
        for entry in self.held_entries() {
            self.open_owner_merges(entry, &rows)?;
        }
        self.open_ring_merges(rows)?;
        if done {
            session.checked.extend(active.nullifiers);
        } else {
            session.active = Some(active);
        }
        Ok(())
    }

    async fn recovery_discovery(
        &mut self,
        step: DiscoveryStep<'_>,
    ) -> Result<PageProgress, AnonymousError> {
        let DiscoveryStep { task, session } = step;
        match task {
            DiscoveryTask::Ring {
                ring,
                entries,
                window,
                offset,
            } => {
                let (page, limit) = self.reads.recovery_ring_page(*ring, *window).await?;
                let mut next = *window;
                let done = next
                    .advance(&page, limit)
                    .map_err(|_| AnonymousError::InvalidHistoryPage)?;
                if page.data.iter().any(|row| {
                    row.validate_events(|tx| (tx.slot, tx.tx_signature, tx.event_index))
                        .is_err()
                }) {
                    return Err(AnonymousError::InvalidHistoryPage);
                }
                let rows: Vec<_> = page.data.into_iter().flat_map(|item| item.events).collect();
                if rows
                    .iter()
                    .any(|row| row.ring_program_id.is_some_and(|id| id != *ring))
                    || offset.row > rows.len()
                {
                    return Err(AnonymousError::RecoveryScopeChanged);
                }
                window.page_limit = Some(limit);
                for (row_index, row) in rows.iter().enumerate().skip(offset.row) {
                    if offset.entry > entries.len()
                        || entries
                            .iter()
                            .any(|entry| *entry >= self.history.entries().len())
                    {
                        return Err(AnonymousError::RecoveryScopeChanged);
                    }
                    let slice = std::slice::from_ref(row);
                    for (entry_offset, &entry) in entries.iter().enumerate().skip(offset.entry) {
                        let key = self.history.entries()[entry].viewing_pubkey();
                        let candidates = if session.scope.full_scan.is_some() {
                            let bodies = sites_of(row)
                                .filter_map(|site| Body::of(row, site, AnonymousStream::FullScan))
                                .collect();
                            self.body_secrets(key, bodies)?
                        } else {
                            self.tag_bodies(entry, slice)?
                        };
                        if offset.site > candidates.len() {
                            return Err(AnonymousError::RecoveryScopeChanged);
                        }
                        for (site, (body, secret)) in
                            candidates.iter().enumerate().skip(offset.site)
                        {
                            let work = BodyWork {
                                entry,
                                body,
                                secret,
                            };
                            if self.recovery_body(work)? == PageProgress::Paused {
                                return Ok(PageProgress::Paused);
                            }
                            offset.site = site + 1;
                        }
                        self.open_owner_merges(entry, slice)?;
                        offset.entry = entry_offset + 1;
                        offset.site = 0;
                    }
                    if session.scope.full_scan.is_some() {
                        self.open_ring_merges(vec![row.clone()])?;
                        for slot in &row.output_slots {
                            let hash = slot.output_context.hash;
                            if ring_body_output(&slot.payload).is_some()
                                && !self.found_hashes.contains(&hash)
                            {
                                session.diagnostics.unopened_count =
                                    session.diagnostics.unopened_count.saturating_add(1);
                                if session.diagnostics.unopened.len() < DIAGNOSTIC_SAMPLES {
                                    session.diagnostics.unopened.push(hash);
                                }
                            }
                        }
                    }
                    offset.row = row_index + 1;
                    offset.entry = 0;
                    offset.site = 0;
                }
                next.page_limit = None;
                *window = next;
                *offset = PageOffset::default();
                if done {
                    let target = session
                        .target_slot
                        .ok_or(AnonymousError::RecoveryScopeChanged)?;
                    for &entry in entries.iter() {
                        self.entry_mut(entry).set_ring_position(*ring, target);
                    }
                }
                Ok(if done {
                    PageProgress::Done
                } else {
                    PageProgress::More
                })
            }
        }
    }

    fn recovery_body(&mut self, work: BodyWork<'_, '_>) -> Result<PageProgress, AnonymousError> {
        let BodyWork {
            entry,
            body,
            secret,
        } = work;
        let position = match body.site {
            Site::Message(message) => {
                let viewing_key = self.history.entries()[entry].viewing_pubkey();
                let own = self.own_transactions(viewing_key, &[body])?;
                self.open_bundle(
                    entry,
                    body,
                    message,
                    secret,
                    own.get(&body.context.first_nullifier),
                )?;
                return Ok(PageProgress::Done);
            }
            Site::Output(position) => position,
        };
        self.open_recipient(entry, body, position, secret)?;
        Ok(PageProgress::Done)
    }
}
