use std::sync::Mutex;

use spr_keypair::NullifierKey;

use super::{
    fixture::{Enrollment, TrackingLedger},
    *,
};
use crate::{
    database::Store,
    hub::Clock,
    projection_lease::LeaseClaim,
    projection_reads::EnrollmentKey,
    spent_index::{HistoryScope, LoadSpends, NoteSeal, ProjectionWriter},
    utxos::{Backing, PageWork, MAX_CACHED_ENTRIES, MAX_LATE_OWNERS},
};

const RING: Address = Address::new_from_array([8; 32]);

/// Serves the ledger, `tamper` edits each page before the scan reads it.
struct Served {
    ledger: TrackingLedger,
    tamper: Mutex<Option<fn(&mut GetTrackingRecordsResponse)>>,
}

impl TrackingSource for Served {
    async fn root(
        &self,
        _ring: Address,
        _finality: Finality,
    ) -> Result<Option<TrackingRoot>, ClientError> {
        Ok(self.ledger.root())
    }

    async fn records(
        &self,
        request: GetTrackingRecordsRequest,
    ) -> Result<GetTrackingRecordsResponse, RingIndexerError> {
        let mut page = self.ledger.page(&request);
        if let Some(tamper) = *self.tamper.lock().expect("tamper") {
            tamper(&mut page);
        }
        Ok(page)
    }
}

fn owner(seed: u8) -> Address {
    Address::new_from_array([seed; 32])
}

/// Byte 0 is the seal's pad, a canonical salt leaves it zero.
fn list_salt(seed: u8) -> [u8; 32] {
    let mut salt = [seed; 32];
    salt[0] = 0;
    salt
}

fn served(auditor: &X25519Keypair, owners: &[u8]) -> (Served, Vec<HeldEnrollment>) {
    let ledger = TrackingLedger::default();
    let held = owners
        .iter()
        .map(|seed| {
            ledger.enroll(Enrollment {
                owner: owner(*seed),
                key: &NullifierKey::from_secret([*seed; 31]),
                list_salt: list_salt(*seed),
                auditor: &auditor.pubkey(),
            })
        })
        .collect();
    let served = Served {
        ledger,
        tamper: Mutex::new(None),
    };
    (served, held)
}

async fn scan(
    served: &Served,
    auditor: &X25519Keypair,
    store: &AuditStore,
    cursor: &mut TrackingCursor,
) -> Result<ScanEnd, RingRpcError> {
    TrackingScan {
        ring: RING,
        auditor,
        source: served,
        store,
        durable: None,
    }
    .run(cursor)
    .await
}

async fn enrollment(store: &AuditStore, member: &[u8; 32]) -> Option<HeldEnrollment> {
    store
        .enrollment(EnrollmentKey::Member, member)
        .await
        .expect("lookup")
}

#[tokio::test]
async fn a_scan_holds_every_enrolled_owner_and_completes_at_the_next_index() {
    let auditor = X25519Keypair::new();
    let (served, held) = served(&auditor, &[1, 2, 3]);
    let store = AuditStore::default();
    let mut cursor = TrackingCursor::default();
    let end = scan(&served, &auditor, &store, &mut cursor)
        .await
        .expect("scan");
    assert_eq!(end, ScanEnd::Complete);
    assert_eq!(cursor.next_leaf(), 4, "past the sentinel and three rows");
    for held in held {
        assert_eq!(enrollment(&store, &held.member).await, Some(held));
        let secrets = held.secrets(&auditor).expect("opens");
        assert_eq!(
            secrets.nullifier_key.pubkey().expect("pk"),
            held.nullifier_pk
        );
    }
}

#[tokio::test]
async fn a_full_memory_pending_set_keeps_the_page_until_derivation_frees_capacity() {
    let auditor = X25519Keypair::new();
    let (source, held) = served(&auditor, &[1, 2]);
    let store = AuditStore::default();
    store.queue_late_owners((0..MAX_CACHED_ENTRIES).map(|index| {
        let mut owner = [0xa5; 32];
        owner[..8].copy_from_slice(&(index as u64).to_le_bytes());
        owner
    }));
    let mut cursor = TrackingCursor::default();
    assert_eq!(
        scan(&source, &auditor, &store, &mut cursor)
            .await
            .expect("full scan"),
        ScanEnd::Partial
    );
    assert_eq!(cursor, TrackingCursor::default());
    for row in &held {
        assert_eq!(enrollment(&store, &row.member).await, None);
    }

    let opener = |_: &HeldEnrollment| None;
    let mut work = PageWork::new(&store, &opener);
    work.late_keys();
    let delta = work.finish().await.expect("derive");
    assert_eq!(delta.derived_owners().len(), MAX_LATE_OWNERS);
    store.commit(delta);
    assert_eq!(
        scan(&source, &auditor, &store, &mut cursor)
            .await
            .expect("resumed scan"),
        ScanEnd::Complete
    );
    assert_eq!(cursor.next_leaf(), 3);
    for row in held {
        assert_eq!(enrollment(&store, &row.member).await, Some(row));
    }
}

#[tokio::test]
async fn a_page_skipping_a_leaf_holds_nothing_and_keeps_the_cursor() {
    let auditor = X25519Keypair::new();
    let (served, held) = served(&auditor, &[1, 2]);
    *served.tamper.lock().expect("tamper") = Some(|page| {
        page.records.remove(1);
    });
    let store = AuditStore::default();
    let mut cursor = TrackingCursor::default();
    let refused = scan(&served, &auditor, &store, &mut cursor).await;
    assert!(matches!(
        refused,
        Err(RingRpcError::Tracking(TrackingRefusal::PageShape))
    ));
    assert_eq!(cursor, TrackingCursor::default());
    assert_eq!(enrollment(&store, &held[1].member).await, None);
}

#[tokio::test]
async fn a_row_sealed_to_another_auditor_is_refused() {
    let auditor = X25519Keypair::new();
    let (served, _) = served(&X25519Keypair::new(), &[1]);
    let store = AuditStore::default();
    let mut cursor = TrackingCursor::default();
    let refused = scan(&served, &auditor, &store, &mut cursor).await;
    assert!(matches!(
        refused,
        Err(RingRpcError::Tracking(TrackingRefusal::Sealed))
    ));
    assert_eq!(cursor, TrackingCursor::default());
}

/// A bounded mirror over `database`, as a ring served with a store holds one.
fn cached_store(database: &Store, auditor: &X25519Keypair, capacity: usize) -> AuditStore {
    AuditStore::new(Backing::Database {
        store: database.clone(),
        ring: RING,
        seal: Box::new(NoteSeal::derive(auditor, RING).expect("seal")),
        capacity,
    })
}

async fn writer<'a>(database: &'a Store, seal: &'a NoteSeal) -> ProjectionWriter<'a> {
    const NOW: u64 = 1_000;
    ProjectionWriter {
        db: database.connection(),
        ring: RING,
        seal,
        lease: LeaseClaim {
            db: database.connection(),
            ring: RING,
            holder: database.lease_holder(),
            now: NOW,
        }
        .claim()
        .await
        .expect("claim")
        .expect("held"),
        clock: Clock::Fixed(NOW),
    }
}

#[tokio::test]
async fn a_bounded_enrollment_cache_holds_its_bound_and_storage_answers_an_evicted_row() {
    let auditor = X25519Keypair::new();
    let database = Store::open("sqlite::memory:", 1).await.expect("store");
    let store = cached_store(&database, &auditor, 2);
    let writer_seal = NoteSeal::derive(&auditor, RING).expect("seal");
    let writer = writer(&database, &writer_seal).await;
    let rows: Vec<HeldEnrollment> = (1..=5)
        .map(|seed| {
            HeldEnrollment::unsealed(
                owner(seed).to_bytes(),
                &NullifierKey::from_secret([seed; 31]),
            )
        })
        .collect();
    // One page per row, as a scan admits them, each committed before the cache takes it.
    for row in &rows {
        let admission = store
            .enrollment_admission(vec![*row])
            .await
            .expect("admission");
        writer
            .commit_enrollments(admission.rows(), TrackingCursor::default())
            .await
            .expect("commit");
        store.admit_enrollments(admission).expect("admitted");
    }
    assert!(store
        .cached_enrollments()
        .iter()
        .all(|entries| *entries <= 2));

    // 1. The evicted first row answers by each key it is read by, from storage.
    let first = rows[0];
    for (key, value) in [
        (EnrollmentKey::Member, first.member),
        (EnrollmentKey::ListKey, first.list_key),
    ] {
        assert_eq!(
            store.enrollment(key, &value).await.expect("lookup"),
            Some(first)
        );
    }
    // 2. A page naming the evicted member with other key fields still refuses.
    let conflicting = HeldEnrollment {
        nullifier_pk: [9; 32],
        ..first
    };
    assert!(matches!(
        store.enrollment_admission(vec![conflicting]).await,
        Err(RingRpcError::Tracking(TrackingRefusal::Conflict))
    ));
}

#[tokio::test]
async fn cached_scan_rows_are_persisted_before_the_durable_cursor() {
    let auditor = X25519Keypair::new();
    let (source, held) = served(&auditor, &[1, 2, 3]);
    let database = Store::open("sqlite::memory:", 1).await.expect("store");
    let seal = NoteSeal::derive(&auditor, RING).expect("seal");
    let store = AuditStore::new(Backing::Database {
        store: database.clone(),
        ring: RING,
        seal: Box::new(NoteSeal::derive(&auditor, RING).expect("seal")),
        capacity: 4,
    });
    scan(&source, &auditor, &store, &mut TrackingCursor::default())
        .await
        .expect("temporary scan");
    let writer = ProjectionWriter {
        db: database.connection(),
        ring: RING,
        seal: &seal,
        lease: LeaseClaim {
            db: database.connection(),
            ring: RING,
            holder: database.lease_holder(),
            now: 1000,
        }
        .claim()
        .await
        .expect("claim")
        .expect("lease"),
        clock: Clock::Fixed(1000),
    };
    let mut cursor = TrackingCursor::default();
    TrackingScan {
        ring: RING,
        auditor: &auditor,
        source: &source,
        store: &store,
        durable: Some(&writer),
    }
    .run(&mut cursor)
    .await
    .expect("durable scan");
    drop(store);
    let restarted = AuditStore::new(Backing::Database {
        store: database.clone(),
        ring: RING,
        seal: Box::new(NoteSeal::derive(&auditor, RING).expect("seal")),
        capacity: 1,
    });
    for row in held {
        assert_eq!(enrollment(&restarted, &row.member).await, Some(row));
    }
    let loaded = crate::spent_index::LoadSpends {
        db: database.connection(),
        ring: RING,
        seal: &seal,
        scope: crate::spent_index::HistoryScope::Cold,
    }
    .load()
    .await
    .expect("reload");
    assert_eq!(loaded.tracking_cursor, cursor);
    assert!(loaded.enrollments.is_empty());
    let pending = writer
        .pending_owners()
        .await
        .expect("pending after restart");
    assert_eq!(pending.len(), 3);
    restarted.replace_late_owners(pending);
    let opener = |_: &HeldEnrollment| None;
    let mut work = crate::utxos::PageWork::new(&restarted, &opener);
    work.late_keys();
    let delta = work.finish().await.expect("derive");
    assert_eq!(
        writer
            .pending_owners()
            .await
            .expect("pending before commit")
            .len(),
        3
    );
    writer.commit_page(&delta).await.expect("commit derivation");
    assert!(writer.pending_owners().await.expect("completed").is_empty());
}

#[tokio::test]
async fn durable_admission_keeps_the_backlog_outside_the_active_derivation_set() {
    let auditor = X25519Keypair::new();
    let count = MAX_LATE_OWNERS * 2 + 1;
    let owners: Vec<u8> = (1..=count)
        .map(|owner| u8::try_from(owner).expect("owner seed"))
        .collect();
    let (source, _) = served(&auditor, &owners);
    let database = Store::open("sqlite::memory:", 1).await.expect("store");
    let seal = NoteSeal::derive(&auditor, RING).expect("seal");
    let store = cached_store(&database, &auditor, 2);
    let writer = writer(&database, &seal).await;
    let mut cursor = TrackingCursor::default();
    assert_eq!(
        TrackingScan {
            ring: RING,
            auditor: &auditor,
            source: &source,
            store: &store,
            durable: Some(&writer),
        }
        .run(&mut cursor)
        .await
        .expect("scan"),
        ScanEnd::Complete
    );
    let opener = |_: &HeldEnrollment| None;
    let mut work = PageWork::new(&store, &opener);
    work.late_keys();
    assert!(work
        .finish()
        .await
        .expect("no active owners")
        .derived_owners()
        .is_empty());

    for expected in [MAX_LATE_OWNERS, MAX_LATE_OWNERS, 1] {
        let pending = writer.pending_owners().await.expect("pending");
        assert_eq!(pending.len(), expected);
        store.replace_late_owners(pending.clone());
        let mut work = PageWork::new(&store, &opener);
        work.late_keys();
        let delta = work.finish().await.expect("derive");
        assert_eq!(delta.derived_owners().len(), expected);
        assert_eq!(writer.pending_owners().await.expect("uncommitted"), pending);
        let revision = writer.commit_page(&delta).await.expect("commit");
        store.commit(delta.at_commit(revision));
    }
    assert!(writer.pending_owners().await.expect("drained").is_empty());
    store.replace_late_owners(Vec::new());
    let mut work = PageWork::new(&store, &opener);
    work.late_keys();
    assert!(work
        .finish()
        .await
        .expect("empty active set")
        .derived_owners()
        .is_empty());
}

/// Confirmed reads the fork while it lives, finalized reads the canonical chain.
struct Forked {
    fork: Mutex<Option<TrackingLedger>>,
    canonical: TrackingLedger,
}

impl Forked {
    fn ledger(&self, root: &[u8; 32]) -> TrackingLedger {
        let fork = self.fork.lock().expect("fork").clone();
        fork.filter(|fork| fork.root().is_some_and(|held| held.root == *root))
            .unwrap_or_else(|| self.canonical.clone())
    }
}

impl TrackingSource for Forked {
    async fn root(
        &self,
        _ring: Address,
        finality: Finality,
    ) -> Result<Option<TrackingRoot>, ClientError> {
        let fork = self.fork.lock().expect("fork").clone();
        Ok(match (finality, fork) {
            (Finality::Confirmed, Some(fork)) => fork.root(),
            (Finality::Confirmed, None) | (Finality::Finalized, _) => self.canonical.root(),
        })
    }

    async fn records(
        &self,
        request: GetTrackingRecordsRequest,
    ) -> Result<GetTrackingRecordsResponse, RingIndexerError> {
        Ok(self.ledger(&request.expected_root.0).page(&request))
    }
}

/// The audit's fork, A at leaf 1 on a fork and B at leaf 1 on the canonical chain.
#[tokio::test]
async fn a_forked_enrollment_never_enters_the_store_and_the_canonical_one_survives_a_restart() {
    let auditor = X25519Keypair::new();
    let enroll = |ledger: &TrackingLedger, seed: u8| {
        ledger.enroll(Enrollment {
            owner: owner(seed),
            key: &NullifierKey::from_secret([seed; 31]),
            list_salt: list_salt(seed),
            auditor: &auditor.pubkey(),
        })
    };
    let fork = TrackingLedger::default();
    let forked = enroll(&fork, 1);
    let source = Forked {
        fork: Mutex::new(Some(fork)),
        canonical: TrackingLedger::default(),
    };
    let database = Store::open("sqlite::memory:", 1).await.expect("store");
    let seal = NoteSeal::derive(&auditor, RING).expect("seal");
    let writer = writer(&database, &seal).await;
    let scan = |store| TrackingScan {
        ring: RING,
        auditor: &auditor,
        source: &source,
        store,
        durable: Some(&writer),
    };

    // 1. A confirmed only on the fork, the pass reads the finalized root and holds nothing.
    let store = cached_store(&database, &auditor, MAX_CACHED_ENTRIES);
    let mut cursor = TrackingCursor::default();
    scan(&store).run(&mut cursor).await.expect("fork pass");
    assert_eq!(enrollment(&store, &forked.member).await, None);
    assert_eq!(cursor, TrackingCursor::default());

    // 2. The fork drops, B finalizes at the same leaf and the next pass holds it.
    *source.fork.lock().expect("fork") = None;
    let canonical = enroll(&source.canonical, 2);
    scan(&store).run(&mut cursor).await.expect("canonical pass");
    assert_eq!(cursor.next_leaf(), 2);

    // 3. A restart reads the committed cursor and resolves B from storage, A never was stored.
    let restarted = cached_store(&database, &auditor, MAX_CACHED_ENTRIES);
    let mut cursor = LoadSpends {
        db: database.connection(),
        ring: RING,
        seal: &seal,
        scope: HistoryScope::Cold,
    }
    .load()
    .await
    .expect("load")
    .tracking_cursor;
    let end = scan(&restarted)
        .run(&mut cursor)
        .await
        .expect("restarted pass");
    assert_eq!(end, ScanEnd::Complete);
    assert_eq!(
        enrollment(&restarted, &canonical.member).await,
        Some(canonical)
    );
    assert_eq!(enrollment(&restarted, &forked.member).await, None);
}
