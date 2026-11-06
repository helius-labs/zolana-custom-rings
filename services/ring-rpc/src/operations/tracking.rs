//! Enrollments of one ring, read from its pinned tracking tree and opened with the auditor key.
//!
//! Storage `Enroll` writes one authorization per owner and `ApplyEnrollments` moves it into the
//! tracking tree. A row's nullifier key, list tag and seal never change after the first enrollment,
//! a rotation moves only its viewing key. Leaves are appended in order, so every enrolled owner sits
//! below the root's next index and a scan by leaf index under one root finds each of them once.
//!
//! A scan reads only the root the registry names at finalized commitment. A confirmed root can leave
//! the chain with its fork, and a cursor moved past a forked leaf would never read the canonical row
//! that replaces it, so nothing a fork wrote ever enters the store or derives a note's key.
//!
//! The ring indexer serves the rows unverified. Each row's path must rebuild the root the tracking
//! registry account names, and its seal must hash to the row's `ct_hash` and open to the row's key
//! and list tag. A page holds consecutive leaves from the cursor, only the last page may be short.
//! The cursor moves only past a page whose every row verified and opened, and on the lease holder the
//! page commits with the cursor before the move. A held enrollment is never replaced, a page naming a
//! held member with other key fields refuses whole. A missing owner reads as unknown until a scan
//! reaches the root's next index.
//!
//! Read after `services/ring-indexer/src/rpc/tracking.rs` and
//! `program-libs/interface/src/accounts/tracking.rs`.
//! Read before `operations/audit.rs`, the caller holding the backfill lock.

use std::{collections::HashMap, future::Future};

use custom_ring_interface::{domain, tracking::TRACKING_QUAD_HEIGHT, REGISTER_KEY_CIPHERTEXT_LEN};
use solana_address::Address;
use spr_client::ClientError;
use spr_hasher::primitives::hash_bytes;
use spr_keypair::{hash::owner_hash, NullifierKey, PublicKey, X25519Keypair, X25519Pubkey};
use thiserror::Error;
use zolana_ring_client::{
    records::path_of, resolver::tracking_record, RingIndexerError, SealedNullifierKey,
};
use zolana_ring_indexer::tracking::{
    GetTrackingRecordsRequest, GetTrackingRecordsResponse, RingIndexedTrackingRecordView,
    FIRST_TRACKING_LEAF,
};
use zolana_ring_member_registry::{OpeningCheck, TrackingOpening, TrackingRecord};
use zolana_ring_policy::{Member, MemberError};

use crate::{
    bounded_map::{BoundedMap, Cached},
    error::RingRpcError,
    spent_index::ProjectionWriter,
    upstream::{Finality, TrackingRoot, TransactionSource},
    utxos::AuditStore,
};

const TRACKING_PAGE_ROWS: u64 = 100;
/// The next refresh resumes from the cursor the cap leaves.
pub(crate) const MAX_TRACKING_PAGES: usize = 64;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TrackingRefusal {
    #[error("a tracking page is truncated, out of order or under another root")]
    PageShape,
    #[error("a tracking row does not open under the registry root")]
    Opening,
    #[error("a tracking seal does not hash to its row or names another member")]
    SealMismatch,
    #[error("a tracking seal does not open to its nullifier key and list tag")]
    Sealed,
    #[error("a held enrollment member names other key fields")]
    Conflict,
    #[error("tracking discovery has not reached the root's next index")]
    Incomplete,
}

/// Opened once at admission, the secrets never stay in the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldEnrollment {
    pub(crate) owner_key: [u8; 32],
    pub(crate) owner_hash: [u8; 32],
    pub(crate) member: [u8; 32],
    pub(crate) nullifier_pk: [u8; 32],
    pub(crate) list_tag: [u8; 32],
    pub(crate) eph_u: [u8; 32],
    pub(crate) ciphertext: [u8; REGISTER_KEY_CIPHERTEXT_LEN],
    /// `Member::salted(member, list_salt)`, the key a salted list writes for the owner.
    pub(crate) list_key: [u8; 32],
}

/// The seal's two secrets, each checked against the public value its row binds.
pub(crate) struct EnrollmentSecrets {
    pub nullifier_key: NullifierKey,
    pub list_salt: [u8; 32],
}

/// `Unknown` only while the scan has not reached the root's next index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OwnerEnrollment {
    Held(Box<HeldEnrollment>),
    Absent,
    Unknown,
}

/// Every enrollment without a database, a bounded cache of the stored rows beside one.
///
/// On the lease holder a scan caches rows only after its page commits, so each is a stored row.
#[derive(Default)]
pub(crate) struct HeldEnrollments {
    by_member: BoundedMap<[u8; 32], HeldEnrollment>,
    /// List key to member, a salted write names the owner by its list key.
    list_keys: BoundedMap<[u8; 32], [u8; 32]>,
}

/// The rows of one page no held enrollment contradicts, admitted once the page commits.
#[must_use]
#[derive(Debug, Default)]
pub(crate) struct EnrollmentAdmission {
    fresh: Vec<HeldEnrollment>,
}

/// The leaf a scan reads next, never the sentinel, so every request meets the indexer's start rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TrackingCursor(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScanEnd {
    /// The scan reached the root's next index, every enrollment under the root is held.
    Complete,
    /// The page cap stopped the scan, an owner not held reads as unknown.
    Partial,
}

/// The registry root and unverified pages, `TrackingScan` checks every page against the root.
pub trait TrackingSource: Sync {
    fn root(
        &self,
        ring: Address,
        finality: Finality,
    ) -> impl Future<Output = Result<Option<TrackingRoot>, ClientError>> + Send;

    fn records(
        &self,
        request: GetTrackingRecordsRequest,
    ) -> impl Future<Output = Result<GetTrackingRecordsResponse, RingIndexerError>> + Send;
}

#[must_use]
pub(crate) struct TrackingScan<'a, S> {
    pub ring: Address,
    pub auditor: &'a X25519Keypair,
    pub source: &'a S,
    pub store: &'a AuditStore,
    /// The lease holder persists each page, `None` scans into memory without a database.
    pub durable: Option<&'a ProjectionWriter<'a>>,
}

impl<S: TransactionSource> TrackingSource for S {
    fn root(
        &self,
        ring: Address,
        finality: Finality,
    ) -> impl Future<Output = Result<Option<TrackingRoot>, ClientError>> + Send {
        self.tracking_root(ring, finality)
    }

    fn records(
        &self,
        request: GetTrackingRecordsRequest,
    ) -> impl Future<Output = Result<GetTrackingRecordsResponse, RingIndexerError>> + Send {
        self.tracking_records(request)
    }
}

impl HeldEnrollment {
    pub fn member(&self) -> [u8; 32] {
        self.member
    }

    /// The fields the first enrollment fixed, a rotation moves none of them.
    fn key_fields(&self) -> impl PartialEq + '_ {
        (
            self.owner_key,
            self.nullifier_pk,
            self.list_tag,
            self.eph_u,
            self.ciphertext,
        )
    }

    /// Opened per use, the secrets never stay in the store.
    pub(crate) fn secrets(
        &self,
        auditor: &X25519Keypair,
    ) -> Result<EnrollmentSecrets, TrackingRefusal> {
        open_seal(
            &self.eph_u,
            &self.ciphertext,
            &self.nullifier_pk,
            &self.list_tag,
            auditor,
        )
    }
}

#[cfg(test)]
impl HeldEnrollment {
    /// An owner's row whose seal no auditor opens, for tests that hand out keys directly.
    pub(crate) fn unsealed(owner_key: [u8; 32], key: &NullifierKey) -> Self {
        let nullifier_pk = key.pubkey().expect("nullifier pk");
        Self {
            owner_key,
            owner_hash: owner_hash(&PublicKey::from_ed25519(&owner_key), &nullifier_pk)
                .expect("owner hash"),
            member: *Member::owner_tag(&owner_key).expect("member").as_bytes(),
            nullifier_pk,
            list_tag: [0; 32],
            eph_u: [0; 32],
            ciphertext: [0; REGISTER_KEY_CIPHERTEXT_LEN],
            list_key: owner_key,
        }
    }
}

impl Default for TrackingCursor {
    fn default() -> Self {
        Self(FIRST_TRACKING_LEAF)
    }
}

impl TrackingCursor {
    /// `None` below the first enrolled leaf, no commit writes such a cursor.
    pub(crate) fn stored(next_leaf: u64) -> Option<Self> {
        (next_leaf >= FIRST_TRACKING_LEAF).then_some(Self(next_leaf))
    }

    pub(crate) const fn next_leaf(self) -> u64 {
        self.0
    }
}

impl OwnerEnrollment {
    /// Refuses an unknown owner, an unscanned enrollment never reads as absent.
    pub fn known(self) -> Result<Option<HeldEnrollment>, TrackingRefusal> {
        match self {
            Self::Held(held) => Ok(Some(*held)),
            Self::Absent => Ok(None),
            Self::Unknown => Err(TrackingRefusal::Incomplete),
        }
    }

    pub fn held(&self) -> Option<&HeldEnrollment> {
        match self {
            Self::Held(held) => Some(held),
            Self::Absent | Self::Unknown => None,
        }
    }
}

impl HeldEnrollments {
    pub fn bounded(capacity: usize) -> Self {
        Self {
            by_member: BoundedMap::bounded(capacity),
            list_keys: BoundedMap::bounded(capacity),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.by_member.clear();
        self.list_keys.clear();
    }

    pub fn by_member(&self, member: &[u8; 32]) -> Cached<HeldEnrollment> {
        self.by_member.cached(member)
    }

    pub fn by_list_key(&self, list_key: &[u8; 32]) -> Cached<HeldEnrollment> {
        self.through(self.list_keys.cached(list_key))
    }

    /// An index entry whose row the cache evicted reads as unknown, never as absent.
    fn through(&self, member: Cached<[u8; 32]>) -> Cached<HeldEnrollment> {
        match member {
            Cached::Hit(member) => match self.by_member.cached(&member) {
                Cached::Hit(held) => Cached::Hit(held),
                Cached::Absent | Cached::Unknown => Cached::Unknown,
            },
            Cached::Absent => Cached::Absent,
            Cached::Unknown => Cached::Unknown,
        }
    }

    /// All or nothing against `held`, the stored row of every member the page names.
    pub fn admission(
        found: Vec<HeldEnrollment>,
        held: &HashMap<[u8; 32], HeldEnrollment>,
    ) -> Result<EnrollmentAdmission, TrackingRefusal> {
        // The program never changes a row's key fields, a differing one refuses the page.
        let mut fresh: HashMap<[u8; 32], HeldEnrollment> = HashMap::new();
        for row in found {
            match held.get(&row.member).or_else(|| fresh.get(&row.member)) {
                Some(known) if known.key_fields() != row.key_fields() => {
                    return Err(TrackingRefusal::Conflict)
                }
                Some(_) => {}
                None => {
                    fresh.insert(row.member, row);
                }
            }
        }
        Ok(EnrollmentAdmission {
            fresh: fresh.into_values().collect(),
        })
    }

    /// Stored rows only, returns the owner keys held for the first time.
    pub fn insert(&mut self, rows: impl IntoIterator<Item = HeldEnrollment>) -> Vec<[u8; 32]> {
        rows.into_iter()
            .map(|held| {
                self.list_keys.insert(held.list_key, held.member);
                self.by_member.insert(held.member, held);
                held.owner_key
            })
            .collect()
    }
}

#[cfg(test)]
impl HeldEnrollments {
    /// Entries the cache holds by member and list key.
    pub(crate) fn len(&self) -> [usize; 2] {
        [self.by_member.len(), self.list_keys.len()]
    }
}

impl EnrollmentAdmission {
    pub fn rows(&self) -> &[HeldEnrollment] {
        &self.fresh
    }
}

impl<S: TrackingSource> TrackingScan<'_, S> {
    /// Reads from leaf `cursor` under the registry's newest root until its next index or the cap.
    pub async fn run(self, cursor: &mut TrackingCursor) -> Result<ScanEnd, RingRpcError> {
        // 1. One finalized root for the whole pass, a later apply appends leaves the next pass reads.
        let Some(root) = self.source.root(self.ring, Finality::Finalized).await? else {
            return Ok(ScanEnd::Complete);
        };
        for _ in 0..MAX_TRACKING_PAGES {
            if cursor.0 >= root.next_index {
                return Ok(ScanEnd::Complete);
            }
            let response = self
                .source
                .records(GetTrackingRecordsRequest {
                    registry: root.registry.into(),
                    expected_root: root.root.into(),
                    start_index: cursor.0,
                    limit: TRACKING_PAGE_ROWS,
                })
                .await?;
            // 2. The page binds the root, holds consecutive leaves from the cursor and stops short
            //    only at the root's next index.
            if response.root.root.0 != root.root || response.root.next_index != root.next_index {
                return Err(TrackingRefusal::PageShape.into());
            }
            let next = checked_page(&response.records, *cursor, &root)?;
            if response.next_leaf_index != (next.0 < root.next_index).then_some(next.0) {
                return Err(TrackingRefusal::PageShape.into());
            }
            // 3. Every row opens under the root and its seal opens before any row is held.
            let found = response
                .records
                .iter()
                .map(|view| self.held(view, &root))
                .collect::<Result<Vec<_>, _>>()?;
            // 4. The page commits whole with the cursor past it, an evicted member still conflicts.
            let admission = self.store.enrollment_admission(found.clone()).await?;
            if let Some(writer) = self.durable {
                writer.commit_enrollments(&found, next).await?;
            }
            match self.store.admit_enrollments(admission) {
                Ok(()) => {}
                Err(TrackingRefusal::Incomplete) => return Ok(ScanEnd::Partial),
                Err(error) => return Err(error.into()),
            }
            *cursor = next;
        }
        Ok(match cursor.0 >= root.next_index {
            true => ScanEnd::Complete,
            false => ScanEnd::Partial,
        })
    }

    fn held(
        &self,
        view: &RingIndexedTrackingRecordView,
        root: &TrackingRoot,
    ) -> Result<HeldEnrollment, TrackingRefusal> {
        let record = tracking_record(&view.record);
        let path =
            path_of::<TRACKING_QUAD_HEIGHT>(&view.path).map_err(|_| TrackingRefusal::Opening)?;
        // 1. The path rebuilds the registry's root, the indexer cannot add or alter a row.
        OpeningCheck {
            opening: &TrackingOpening::Present { record, path },
            root: &root.root,
            member: &record.member,
        }
        .verify()
        .map_err(|_| TrackingRefusal::Opening)?;
        // 2. The seal hashes to `ct_hash` and its owner hashes to the member, so the row names them.
        let seal = view
            .record
            .seal
            .as_ref()
            .ok_or(TrackingRefusal::SealMismatch)?;
        let owner = seal.owner.0;
        let ciphertext: [u8; REGISTER_KEY_CIPHERTEXT_LEN] = seal
            .ciphertext
            .0
            .as_slice()
            .try_into()
            .map_err(|_| TrackingRefusal::SealMismatch)?;
        let eph_pk: [u8; 33] = seal
            .eph_pk
            .0
            .as_slice()
            .try_into()
            .map_err(|_| TrackingRefusal::SealMismatch)?;
        let eph_u = X25519Pubkey::from_bytes(eph_pk)
            .map_err(|_| TrackingRefusal::SealMismatch)?
            .u();
        let member_of_owner =
            Member::owner_tag(owner.as_array()).map_err(|_| TrackingRefusal::SealMismatch)?;
        if hash_bytes(&ciphertext).ok() != Some(record.ct_hash)
            || *member_of_owner.as_bytes() != record.member
        {
            return Err(TrackingRefusal::SealMismatch);
        }
        // 3. The auditor opens the seal once here, its list key derives from the opened salt.
        let secrets = open_seal(
            &eph_u,
            &ciphertext,
            &record.nullifier_pk,
            &record.list_tag,
            self.auditor,
        )?;
        Ok(HeldEnrollment {
            owner_key: owner.to_bytes(),
            owner_hash: owner_hash(
                &PublicKey::from_ed25519(owner.as_array()),
                &record.nullifier_pk,
            )
            .map_err(|_| TrackingRefusal::SealMismatch)?,
            member: record.member,
            nullifier_pk: record.nullifier_pk,
            list_tag: record.list_tag,
            eph_u,
            ciphertext,
            list_key: list_key(&record, &secrets.list_salt).map_err(|_| TrackingRefusal::Sealed)?,
        })
    }
}

/// The cursor past the page, refusing a gap, a repeat or a short continued page.
///
/// The page starts at the cursor and the cursor never names the sentinel, so no row is leaf 0.
fn checked_page(
    records: &[RingIndexedTrackingRecordView],
    cursor: TrackingCursor,
    root: &TrackingRoot,
) -> Result<TrackingCursor, TrackingRefusal> {
    let consecutive = records
        .iter()
        .zip(cursor.0..)
        .all(|(view, index)| view.path.index == index);
    let len = u64::try_from(records.len()).map_err(|_| TrackingRefusal::PageShape)?;
    let next = cursor
        .0
        .checked_add(len)
        .ok_or(TrackingRefusal::PageShape)?;
    let short = len < TRACKING_PAGE_ROWS && next != root.next_index;
    if !consecutive || len == 0 || len > TRACKING_PAGE_ROWS || short || next > root.next_index {
        return Err(TrackingRefusal::PageShape);
    }
    Ok(TrackingCursor(next))
}

fn open_seal(
    eph_u: &[u8; 32],
    ciphertext: &[u8; REGISTER_KEY_CIPHERTEXT_LEN],
    nullifier_pk: &[u8; 32],
    list_tag: &[u8; 32],
    auditor: &X25519Keypair,
) -> Result<EnrollmentSecrets, TrackingRefusal> {
    let sealed = SealedNullifierKey {
        eph_pk: X25519Pubkey::from_u(*eph_u).map_err(|_| TrackingRefusal::Sealed)?,
        ciphertext: *ciphertext,
    };
    // The seal's pad alone binds neither value, each must match the row's public hash of it.
    let nullifier_key = sealed.open(auditor).map_err(|_| TrackingRefusal::Sealed)?;
    let list_salt = sealed
        .open_list_salt(auditor)
        .map_err(|_| TrackingRefusal::Sealed)?;
    if nullifier_key.pubkey().ok().as_ref() != Some(nullifier_pk)
        || domain::list_tag(&list_salt).ok().as_ref() != Some(list_tag)
    {
        return Err(TrackingRefusal::Sealed);
    }
    Ok(EnrollmentSecrets {
        nullifier_key,
        list_salt,
    })
}

fn list_key(record: &TrackingRecord, list_salt: &[u8; 32]) -> Result<[u8; 32], MemberError> {
    let key = Member::salted(&Member::from_bytes(record.member)?, list_salt)?;
    Ok(*key.as_bytes())
}

/// A ring's tracking tree served the way the ring indexer serves it, for tests outside the crate.
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixture {
    use std::sync::{Arc, Mutex};

    use custom_ring_interface::tracking::TrackingEntry;
    use spr_indexer_api::{Base64String, Context, Hash};
    use zolana_ring_client::{rpc::WalletEnrollment, NullifierKeyEnvelope};
    use zolana_ring_indexer::{
        rpc::{RingRecordPathView, StorageRootView},
        tracking::{RingTrackingRecordView, RingTrackingSealView},
    };
    use zolana_ring_member_registry::{RecordTree, TrackingTree};

    use super::*;
    use crate::projection_reads::EnrollmentKey;

    pub const TRACKING: Address = Address::new_from_array([0x7a; 32]);

    /// A fresh auditor's scan of `source` to its root's next index, the row it holds per owner.
    pub async fn fresh_scan(
        ring: Address,
        auditor: &X25519Keypair,
        source: &impl TrackingSource,
        owners: &[Address],
    ) -> Result<Vec<Option<HeldEnrollment>>, RingRpcError> {
        let store = AuditStore::default();
        let mut cursor = TrackingCursor::default();
        let end = TrackingScan {
            ring,
            auditor,
            source,
            store: &store,
            durable: None,
        }
        .run(&mut cursor)
        .await?;
        if end != ScanEnd::Complete {
            return Err(TrackingRefusal::Incomplete.into());
        }
        let mut held = Vec::with_capacity(owners.len());
        for owner in owners {
            let member = Member::owner_tag(owner.as_array())?;
            held.push(
                store
                    .enrollment(EnrollmentKey::Member, member.as_bytes())
                    .await?,
            );
        }
        Ok(held)
    }

    /// Empty until the first enrollment applies.
    #[derive(Clone, Default)]
    pub struct TrackingLedger(Arc<Mutex<Option<Ledger>>>);

    struct Ledger {
        tree: TrackingTree,
        seals: HashMap<[u8; 32], RingTrackingSealView>,
        revision: u64,
    }

    #[must_use]
    pub struct Enrollment<'a> {
        pub owner: Address,
        pub key: &'a NullifierKey,
        pub list_salt: [u8; 32],
        pub auditor: &'a X25519Pubkey,
    }

    impl TrackingLedger {
        /// Applies the owner's row in a new root and returns what a scan of it holds.
        pub fn enroll(&self, enrollment: Enrollment<'_>) -> HeldEnrollment {
            let Enrollment {
                owner,
                key,
                list_salt,
                auditor,
            } = enrollment;
            let member = *Member::owner_tag(owner.as_array())
                .expect("member")
                .as_bytes();
            let sealed = NullifierKeyEnvelope::new(key, &list_salt, auditor)
                .expect("envelope")
                .sealed;
            let nullifier_pk = key.pubkey().expect("nullifier pk");
            let list_tag = domain::list_tag(&list_salt).expect("list tag");
            let mut guard = self.0.lock().expect("ledger");
            let ledger = guard.get_or_insert_with(|| Ledger {
                tree: TrackingTree::new().expect("tree"),
                seals: HashMap::new(),
                revision: 0,
            });
            let applied = ledger
                .tree
                .clone()
                .apply(
                    [0; 32],
                    &[TrackingEntry {
                        member,
                        nullifier_pk,
                        ct_hash: hash_bytes(&sealed.ciphertext).expect("ct hash"),
                        list_tag,
                    }],
                )
                .expect("apply");
            ledger.tree = applied.tree;
            ledger.revision += 1;
            ledger.seals.insert(
                member,
                RingTrackingSealView {
                    owner: owner.into(),
                    eph_pk: Base64String(sealed.eph_pk.as_bytes().to_vec()),
                    ciphertext: Base64String(sealed.ciphertext.to_vec()),
                },
            );
            HeldEnrollment {
                owner_key: owner.to_bytes(),
                owner_hash: owner_hash(&PublicKey::from_ed25519(owner.as_array()), &nullifier_pk)
                    .expect("owner hash"),
                member,
                nullifier_pk,
                list_tag,
                eph_u: sealed.eph_pk.u(),
                ciphertext: sealed.ciphertext,
                list_key: *Member::salted(&Member::from_bytes(member).expect("member"), &list_salt)
                    .expect("list key")
                    .as_bytes(),
            }
        }

        /// What the owner's own authorization reads, every fixture enrollment is applied.
        pub fn enrollment(&self, owner: &Address) -> WalletEnrollment {
            let member = *Member::owner_tag(owner.as_array())
                .expect("member")
                .as_bytes();
            let guard = self.0.lock().expect("ledger");
            match guard
                .as_ref()
                .is_some_and(|ledger| ledger.seals.contains_key(&member))
            {
                true => WalletEnrollment::Applied,
                false => WalletEnrollment::NotEnrolled,
            }
        }

        pub fn root(&self) -> Option<TrackingRoot> {
            let guard = self.0.lock().expect("ledger");
            guard.as_ref().map(|ledger| TrackingRoot {
                registry: TRACKING,
                root: ledger.tree.root().expect("root"),
                revision: ledger.revision,
                next_index: ledger.tree.records().len() as u64,
            })
        }

        /// The leaves from `start_index`, at most `limit`, under the newest root.
        pub fn page(&self, request: &GetTrackingRecordsRequest) -> GetTrackingRecordsResponse {
            let guard = self.0.lock().expect("ledger");
            let ledger = guard.as_ref().expect("a tracking tree");
            let next_index = ledger.tree.records().len() as u64;
            assert!(
                request.starts_within(next_index),
                "the ring indexer refuses this start"
            );
            let end = request
                .start_index
                .saturating_add(request.limit)
                .min(next_index);
            let records = (request.start_index..end)
                .map(|index| {
                    let record = ledger.tree.records()[index as usize];
                    RingIndexedTrackingRecordView {
                        record: RingTrackingRecordView {
                            member: Hash(record.member),
                            next: Hash(record.next),
                            nullifier_pk: Hash(record.nullifier_pk),
                            ct_hash: Hash(record.ct_hash),
                            list_tag: Hash(record.list_tag),
                            seal: ledger.seals.get(&record.member).cloned(),
                        },
                        path: RingRecordPathView {
                            index,
                            siblings: ledger
                                .tree
                                .path(index)
                                .expect("path")
                                .siblings
                                .iter()
                                .map(|level| level.map(Hash))
                                .collect(),
                        },
                    }
                })
                .collect();
            GetTrackingRecordsResponse {
                context: Context {
                    block_time: 0,
                    slot: 99,
                },
                root: StorageRootView {
                    root: Hash(ledger.tree.root().expect("root")),
                    revision: ledger.revision,
                    next_index,
                },
                records,
                next_leaf_index: (end < next_index).then_some(end),
            }
        }
    }
}

#[cfg(test)]
#[path = "tracking_tests.rs"]
mod tracking_tests;
