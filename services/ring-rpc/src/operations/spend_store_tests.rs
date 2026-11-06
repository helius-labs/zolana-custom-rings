use std::{collections::HashMap, sync::Mutex};

use sea_orm::ConnectionTrait;
use spr_hasher::primitives::solana_owner_identity;
use spr_keypair::NullifierKey;
use zolana_ring_client::{rpc::WalletNoteStatus, CreatedUtxo, KnownUtxo, UtxoOwner};

use super::{page_work::MAX_LATE_NOTES, *};
use crate::{
    database::Store,
    hub::Clock,
    owner_notes::{OwnerNotesPage, OPENED_ROWS},
    projection_lease::LeaseClaim,
    spend_machine::{InputRead, Observation},
    spent_index::{HistoryScope, LoadSpends, NoteSeal, ProjectionWriter},
    tracking::TrackingCursor,
};

const RING: Address = Address::new_from_array([8; 32]);
const ASSET: [u8; 32] = [4; 32];
const NOW: u64 = 1_000;

/// A real Ed25519 point, `Address::is_on_curve` holds.
fn wallet(seed: u8) -> Address {
    use solana_signer::Signer;
    solana_keypair::Keypair::new_from_array([seed; 32]).pubkey()
}

fn secret(seed: u8) -> NullifierKey {
    NullifierKey::from_secret([seed; 31])
}

fn frame(slot: u64) -> CreatedIn {
    CreatedIn {
        slot,
        tx_signature: Signature::from([slot as u8; 64]),
        event_index: 0,
    }
}

fn note(owner: Address, key: &NullifierKey, commitment: u8, amount: u64) -> CreatedUtxo {
    CreatedUtxo {
        commitment: [commitment; 32],
        slot_index: 0,
        leaf_index: u64::from(commitment),
        utxo: KnownUtxo {
            owner_key: owner.to_bytes(),
            owner: UtxoOwner::Keyed {
                nullifier_pk: key.pubkey().expect("key"),
            },
            asset: ASSET,
            mint: None,
            amount,
            blinding: [commitment.wrapping_add(1); 32],
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
            tree_id: 1,
        },
        ring_note: true,
    }
}

fn nullifier_of(created: &CreatedUtxo, key: &NullifierKey) -> [u8; 32] {
    key.nullifier(&created.commitment, &created.utxo.blinding)
        .expect("nullifier")
}

struct Keys(Mutex<HashMap<[u8; 32], [u8; 31]>>);

impl Keys {
    fn none() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    fn with(owner: Address, seed: u8) -> Self {
        let keys = Self::none();
        keys.grant(owner, seed);
        keys
    }

    fn grant(&self, owner: Address, seed: u8) {
        self.0
            .lock()
            .expect("keys")
            .insert(owner.to_bytes(), [seed; 31]);
    }

    fn open(&self, held: &HeldEnrollment) -> Option<NullifierKey> {
        self.0
            .lock()
            .expect("keys")
            .get(&held.owner_key)
            .map(|secret| NullifierKey::from_secret(*secret))
    }

    /// Every granted owner's row, committed beside a database so an evicted row still reads.
    async fn enroll(&self, store: &AuditStore, writer: Option<&ProjectionWriter<'_>>) {
        let rows: Vec<HeldEnrollment> = self
            .0
            .lock()
            .expect("keys")
            .iter()
            .map(|(owner, secret)| {
                HeldEnrollment::unsealed(*owner, &NullifierKey::from_secret(*secret))
            })
            .collect();
        let admission = store.enrollment_admission(rows).await.expect("admission");
        if let Some(writer) = writer {
            writer
                .commit_enrollments(admission.rows(), TrackingCursor::default())
                .await
                .expect("enrollments");
        }
        store.admit_enrollments(admission).expect("admitted");
    }
}

fn apply(store: &AuditStore, keys: &Keys, page: impl FnOnce(&mut PageWork<'_>)) {
    block_on(keys.enroll(store, None));
    let opener = |held: &HeldEnrollment| keys.open(held);
    let mut work = PageWork::new(store, &opener);
    page(&mut work);
    store.commit(block_on(work.finish()).expect("page"));
}

fn real(nullifier: [u8; 32], at: CreatedIn, position: u16) -> Observation {
    Observation {
        nullifier,
        frame: at,
        position,
        read: InputRead::Real,
        hit: None,
    }
}

fn through(store: &AuditStore, keys: &Keys, slot: u64) {
    apply(store, keys, |work| {
        work.checkpoint(
            HistoryPosition::after_slot(slot),
            Some(Context {
                slot,
                block_time: 1,
            }),
        );
    });
}

fn query(owner: Address) -> WalletStatusQuery {
    WalletStatusQuery {
        principal: *spr_keypair::PublicKey::from_ed25519(owner.as_array()).as_bytes(),
        now: NOW,
        enrollment: WalletEnrollment::NotEnrolled,
        wallet: owner,
        ring: RING,
        after: None,
        limit: 100,
    }
}

fn status_of(store: &AuditStore, owner: Address) -> GetWalletStatusResponse {
    block_on(store.wallet_status(query(owner))).expect("status")
}

fn balance(response: &GetWalletStatusResponse) -> u64 {
    response.balances.iter().map(|entry| entry.amount).sum()
}

fn statuses(response: &GetWalletStatusResponse) -> Vec<WalletNoteStatus> {
    response.notes.iter().map(|note| note.status).collect()
}

#[test]
fn a_note_reads_unspent_then_leaves_the_wallet_once_spent() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let created = note(owner, &secret(7), 0x10, 50);
    apply(&store, &keys, |work| work.open(frame(5), [created]));
    through(&store, &keys, 10);
    let read = status_of(&store, owner);
    assert_eq!(statuses(&read), [WalletNoteStatus::Unspent]);
    assert_eq!(balance(&read), 50);
    apply(&store, &keys, |work| {
        work.observe(real(nullifier_of(&created, &secret(7)), frame(11), 0));
    });
    through(&store, &keys, 12);
    let read = status_of(&store, owner);
    assert!(read.notes.is_empty());
    assert_eq!(balance(&read), 0);
}

#[test]
fn a_note_with_no_readable_secret_is_unknown_and_never_counts() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::none();
    let created = note(owner, &secret(7), 0x10, 50);
    apply(&store, &keys, |work| work.open(frame(5), [created]));
    through(&store, &keys, 10);
    let read = status_of(&store, owner);
    assert_eq!(statuses(&read), [WalletNoteStatus::Unknown]);
    assert_eq!(balance(&read), 0);
}

#[test]
fn a_late_key_recomputes_the_owners_notes_and_resolves_their_rows() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::none();
    let created = note(owner, &secret(7), 0x10, 50);
    let nullifier = nullifier_of(&created, &secret(7));
    apply(&store, &keys, |work| {
        work.open(frame(5), [created]);
        work.observe(real(nullifier, frame(6), 0));
    });
    assert!(matches!(
        store.row_state(&nullifier),
        Some(SpendState::UnresolvedReal)
    ));
    keys.grant(owner, 7);
    store.queue_late_owners([owner.to_bytes()]);
    apply(&store, &keys, |work| work.late_keys());
    assert_eq!(
        store.row_state(&nullifier),
        Some(SpendState::Resolved {
            note: created.commitment
        })
    );
    assert!(store.late_owners.read().expect("late").is_empty());
    through(&store, &keys, 10);
    assert!(status_of(&store, owner).notes.is_empty());
}

#[test]
fn a_spend_of_an_unknown_note_stays_unresolved_then_resolves_when_it_opens() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let created = note(owner, &secret(7), 0x10, 50);
    let nullifier = nullifier_of(&created, &secret(7));
    apply(&store, &keys, |work| {
        work.observe(real(nullifier, frame(6), 0));
    });
    let coverage = block_on(store.spend_coverage(CoverageCursor::new(RING))).expect("coverage");
    assert_eq!(coverage.unresolved_real.len(), 1);
    assert_eq!(coverage.totals.expect("first page totals").padding, 0);
    apply(&store, &keys, |work| work.open(frame(5), [created]));
    assert_eq!(
        store.row_state(&nullifier),
        Some(SpendState::Resolved {
            note: created.commitment
        })
    );
    let coverage = block_on(store.spend_coverage(CoverageCursor::new(RING))).expect("coverage");
    assert!(coverage.unresolved_real.is_empty());
    assert_eq!(coverage.totals.expect("first page totals").resolved, 1);
}

/// Replays give the same state, and no step lists the spent inputs beside their merge.
#[test]
fn notes_merged_with_a_late_read_never_count_twice() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let first = note(owner, &secret(7), 0x10, 50);
    let second = note(owner, &secret(7), 0x11, 50);
    let merged = note(owner, &secret(7), 0x12, 100);
    apply(&store, &keys, |work| work.open(frame(2), [first, second]));
    through(&store, &keys, 3);
    assert_eq!(balance(&status_of(&store, owner)), 100);
    // The merge at slot 4 is unreadable, its output has not opened.
    let merge_frame = frame(4);
    let spends = [
        nullifier_of(&first, &secret(7)),
        nullifier_of(&second, &secret(7)),
    ];
    let unreadable = |work: &mut PageWork<'_>| {
        for (position, nullifier) in spends.iter().enumerate() {
            work.observe(Observation {
                read: InputRead::Unreadable,
                ..real(*nullifier, merge_frame, position as u16)
            });
        }
        work.mark_unread(merge_frame);
    };
    apply(&store, &keys, unreadable);
    through(&store, &keys, 9);
    let held = status_of(&store, owner);
    assert_eq!(held.history_through, 3);
    assert_eq!(balance(&held), 100, "as of the slot before the gap");
    let late_read = |work: &mut PageWork<'_>| {
        work.open(merge_frame, [merged]);
        for (position, nullifier) in spends.iter().enumerate() {
            work.observe(real(*nullifier, merge_frame, position as u16));
        }
        work.mark_read(merge_frame);
    };
    apply(&store, &keys, late_read);
    let read = status_of(&store, owner);
    assert_eq!(read.history_through, 9);
    assert_eq!(balance(&read), 100);
    let dump = store.dump();
    apply(&store, &keys, late_read);
    assert_eq!(store.dump(), dump, "a replay changes nothing");
}

#[test]
fn another_wallets_unresolved_spend_leaves_a_wallet_read_byte_equal() {
    let read_with = |stranger_row: bool| {
        let store = AuditStore::default();
        let owner = wallet(1);
        let keys = Keys::with(owner, 7);
        let created = note(owner, &secret(7), 0x10, 50);
        apply(&store, &keys, |work| work.open(frame(5), [created]));
        if stranger_row {
            apply(&store, &keys, |work| {
                work.observe(real([0xee; 32], frame(6), 0));
            });
        }
        through(&store, &keys, 10);
        serde_json::to_vec(&status_of(&store, owner)).expect("json")
    };
    assert_eq!(read_with(true), read_with(false));
}

#[test]
fn only_an_unreadable_frame_holds_the_history_slot() {
    let store = AuditStore::default();
    let keys = Keys::none();
    through(&store, &keys, 100);
    apply(&store, &keys, |work| {
        work.observe(real([1; 32], frame(50), 0));
    });
    assert_eq!(
        block_on(store.spend_coverage(CoverageCursor::new(RING)))
            .expect("coverage")
            .history_through,
        100
    );
    apply(&store, &keys, |work| work.mark_unread(frame(60)));
    let coverage = block_on(store.spend_coverage(CoverageCursor::new(RING))).expect("coverage");
    assert_eq!(coverage.history_through, 59);
    assert_eq!(coverage.unreadable.len(), 1);
    apply(&store, &keys, |work| work.mark_read(frame(60)));
    assert_eq!(
        block_on(store.spend_coverage(CoverageCursor::new(RING)))
            .expect("coverage")
            .history_through,
        100
    );
}

#[test]
fn a_note_past_the_history_slot_stays_out_so_input_and_change_never_both_count() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let input = note(owner, &secret(7), 0x10, 50);
    let change = note(owner, &secret(7), 0x11, 50);
    apply(&store, &keys, |work| work.open(frame(2), [input]));
    through(&store, &keys, 3);
    apply(&store, &keys, |work| {
        work.open(frame(5), [change]);
        work.observe(real(nullifier_of(&input, &secret(7)), frame(5), 0));
    });
    let read = status_of(&store, owner);
    assert_eq!(read.history_through, 3);
    assert_eq!(statuses(&read), [WalletNoteStatus::Unspent]);
    assert_eq!(balance(&read), 50);
}

#[test]
fn padding_and_external_add_no_unresolved_state() {
    let store = AuditStore::default();
    let keys = Keys::none();
    apply(&store, &keys, |work| {
        work.observe(Observation {
            read: InputRead::Padding,
            ..real([1; 32], frame(5), 1)
        });
        work.observe(Observation {
            read: InputRead::External,
            ..real([2; 32], frame(5), 0)
        });
    });
    let coverage = block_on(store.spend_coverage(CoverageCursor::new(RING))).expect("coverage");
    assert!(coverage.unresolved_real.is_empty());
    assert_eq!(
        (
            coverage.totals.expect("first page totals").padding,
            coverage.totals.expect("first page totals").external
        ),
        (1, 1)
    );
}

#[test]
fn a_duplicate_nullifier_is_surfaced_and_the_first_state_stays() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let created = note(owner, &secret(7), 0x10, 50);
    let nullifier = nullifier_of(&created, &secret(7));
    apply(&store, &keys, |work| {
        work.open(frame(2), [created]);
        work.observe(real(nullifier, frame(3), 0));
    });
    let before = store.row_state(&nullifier);
    apply(&store, &keys, |work| {
        work.observe(real(nullifier, frame(4), 0));
    });
    assert_eq!(store.row_state(&nullifier), before);
    let faults = block_on(store.spend_coverage(CoverageCursor::new(RING)))
        .expect("coverage")
        .integrity_faults;
    assert_eq!(faults.len(), 1);
    assert_eq!(faults[0].frame.slot, 4);
}

#[test]
fn a_zero_key_note_of_a_wallet_is_exposed_and_a_pda_note_is_not() {
    let store = AuditStore::default();
    let keys = Keys::none();
    let zero = NullifierKey::from_secret([0; 31]);
    assert_eq!(zero.pubkey().expect("zero"), ZERO_NULLIFIER_PUBKEY);
    let owner = wallet(1);
    let exposed = note(owner, &zero, 0x10, 50);
    let (program, _) = Address::find_program_address(&[b"vault"], &RING);
    assert!(!program.is_on_curve());
    let vault = note(program, &zero, 0x11, 70);
    apply(&store, &keys, |work| {
        work.open(frame(2), [exposed, vault]);
    });
    through(&store, &keys, 3);
    let read = status_of(&store, owner);
    assert_eq!(statuses(&read), [WalletNoteStatus::ExposedIfSpent]);
    assert_eq!(balance(&read), 0, "outside the balance");
    let read = status_of(&store, program);
    assert_eq!(statuses(&read), [WalletNoteStatus::Unspent]);
    assert_eq!(balance(&read), 70);
    // Spent takes precedence, the zero secret needs no credential.
    apply(&store, &keys, |work| {
        work.observe(real(nullifier_of(&exposed, &zero), frame(4), 0));
    });
    through(&store, &keys, 5);
    assert!(status_of(&store, owner).notes.is_empty());
}

#[test]
fn spendable_scan_skips_a_published_nullifier_and_ignores_an_unrelated_row() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let mint = Address::new_from_array([6; 32]);
    let named = |commitment, amount| {
        let mut created = note(owner, &secret(7), commitment, amount);
        created.utxo.mint = Some(mint);
        created
    };
    let (spent, kept) = (named(0x10, 50), named(0x11, 20));
    apply(&store, &keys, |work| {
        work.open(frame(2), [spent, kept]);
        work.observe(real(nullifier_of(&spent, &secret(7)), frame(3), 0));
        work.observe(real([0xee; 32], frame(3), 1));
    });
    let key = secret(7);
    let mut hashes = Vec::new();
    block_on(store.visit_spendable_notes(
        SpendableNotes {
            ring: RING,
            owner_key: owner.to_bytes(),
            nullifier_key: &key,
            mints: &[Mint::new(mint, 6)],
            held: &HashSet::new(),
        },
        |note| hashes.push(note.utxo_hash),
    ))
    .expect("selection");
    assert_eq!(hashes, [kept.commitment]);
}

type PageScript<'a> = Box<dyn Fn(&mut PageWork<'_>) + 'a>;

/// One scripted run, each page a closure over the overlay.
fn script<'a>(created: &'a [CreatedUtxo; 2], key: &'a NullifierKey) -> Vec<PageScript<'a>> {
    vec![
        Box::new(move |work| {
            work.open(frame(2), [created[0]]);
            work.observe(Observation {
                read: InputRead::Padding,
                ..real([3; 32], frame(2), 1)
            });
            work.mark_unread(frame(2));
            work.checkpoint(
                HistoryPosition::after_slot(2),
                Some(Context {
                    slot: 2,
                    block_time: 7,
                }),
            );
        }),
        Box::new(move |work| {
            work.open(frame(3), [created[1]]);
            work.observe(real(nullifier_of(&created[0], key), frame(3), 0));
            work.observe(real([9; 32], frame(3), 1));
            work.observe(real([9; 32], frame(4), 0));
            work.mark_read(frame(2));
            work.checkpoint(
                HistoryPosition::after_slot(5),
                Some(Context {
                    slot: 5,
                    block_time: 8,
                }),
            );
        }),
    ]
}

async fn commit_page(
    store: &Store,
    book: &AuditStore,
    seal: &NoteSeal,
    keys: &Keys,
    page: &dyn Fn(&mut PageWork<'_>),
) -> Result<(), sea_orm::DbErr> {
    let lease = LeaseClaim {
        db: store.connection(),
        ring: RING,
        holder: store.lease_holder(),
        now: NOW,
    }
    .claim()
    .await?
    .expect("one replica holds the lease");
    let writer = ProjectionWriter {
        db: store.connection(),
        ring: RING,
        seal,
        lease,
        clock: Clock::Fixed(NOW),
    };
    keys.enroll(book, Some(&writer)).await;
    let opener = |held: &HeldEnrollment| keys.open(held);
    let mut work = PageWork::new(book, &opener);
    page(&mut work);
    let delta = work.finish().await.expect("page");
    let revision = writer.commit_page(&delta).await?;
    book.commit(delta.at_commit(revision));
    Ok(())
}

async fn restart(store: &Store, seal: &NoteSeal) -> AuditStore {
    let book = AuditStore::default();
    let loaded = LoadSpends {
        db: store.connection(),
        ring: RING,
        seal,
        scope: HistoryScope::Everything,
    }
    .load()
    .await
    .expect("load");
    book.refresh(loaded.spends, loaded.revision);
    book
}

fn seal() -> NoteSeal {
    NoteSeal::derive(&spr_keypair::X25519Keypair::from_bytes(&[0x41; 32]), RING).expect("seal")
}

#[tokio::test]
async fn a_kill_at_any_checkpoint_step_replays_to_the_uninterrupted_state() {
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let key = secret(7);
    let created = [note(owner, &key, 0x10, 50), note(owner, &key, 0x11, 20)];
    let pages = script(&created, &key);
    let seal = seal();

    let clean = Store::open("sqlite::memory:", 1).await.expect("store");
    let uninterrupted = AuditStore::default();
    for page in &pages {
        commit_page(&clean, &uninterrupted, &seal, &keys, page)
            .await
            .expect("page");
    }
    let expected = uninterrupted.dump();
    assert_eq!(restart(&clean, &seal).await.dump(), expected);

    for table in [
        "finalized_notes",
        "finalized_spent_nullifiers",
        "spend_integrity_faults",
        "spend_unread_frames",
        "spend_checkpoints",
    ] {
        for failing in 0..pages.len() {
            let store = Store::open("sqlite::memory:", 1).await.expect("store");
            let mut book = AuditStore::default();
            for page in &pages[..failing] {
                commit_page(&store, &book, &seal, &keys, page)
                    .await
                    .expect("page");
            }
            let before = book.dump();
            let rename = |from: &str, to: &str| format!("ALTER TABLE {from} RENAME TO {to}");
            store
                .connection()
                .execute_unprepared(&rename(table, "parked"))
                .await
                .expect("park");
            let refused = commit_page(&store, &book, &seal, &keys, pages[failing].as_ref()).await;
            store
                .connection()
                .execute_unprepared(&rename("parked", table))
                .await
                .expect("restore");
            // A table the page leaves alone does not fail the page.
            if refused.is_err() {
                assert_eq!(book.dump(), before, "the mirror follows the commit");
                assert_eq!(
                    restart(&store, &seal).await.dump(),
                    before,
                    "a failed page writes nothing"
                );
            }
            book = restart(&store, &seal).await;
            // A restart replays the failed page and every later one.
            let start = if refused.is_err() {
                failing
            } else {
                failing + 1
            };
            for page in &pages[start..] {
                commit_page(&store, &book, &seal, &keys, page)
                    .await
                    .expect("replay");
            }
            assert_eq!(book.dump(), expected);
            assert_eq!(restart(&store, &seal).await.dump(), expected);
        }
    }
}

#[tokio::test]
async fn a_replayed_page_changes_no_row() {
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let key = secret(7);
    let created = [note(owner, &key, 0x10, 50), note(owner, &key, 0x11, 20)];
    let pages = script(&created, &key);
    let seal = seal();
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let book = AuditStore::default();
    for page in &pages {
        commit_page(&store, &book, &seal, &keys, page)
            .await
            .expect("page");
    }
    let expected = book.dump();
    let replayed = restart(&store, &seal).await;
    for page in &pages {
        commit_page(&store, &replayed, &seal, &keys, page)
            .await
            .expect("replay");
    }
    let mut dump = replayed.dump();
    dump.position_slot = expected.position_slot;
    dump.context = expected.context;
    assert_eq!(dump, expected);
}

#[tokio::test]
async fn a_note_row_opens_only_under_the_auditor_key_and_holds_no_plaintext() {
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let key = secret(7);
    let created = [note(owner, &key, 0x10, 50), note(owner, &key, 0x11, 20)];
    let pages = script(&created, &key);
    let seal = seal();
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let book = AuditStore::default();
    commit_page(&store, &book, &seal, &keys, pages[0].as_ref())
        .await
        .expect("page");
    let other =
        NoteSeal::derive(&spr_keypair::X25519Keypair::from_bytes(&[0x42; 32]), RING).expect("seal");
    assert!(LoadSpends {
        db: store.connection(),
        ring: RING,
        seal: &other,
        scope: HistoryScope::Everything,
    }
    .load()
    .await
    .is_err());
    let row = store
        .connection()
        .query_one(sea_orm::Statement::from_string(
            store.connection().get_database_backend(),
            "SELECT sealed FROM finalized_notes LIMIT 1",
        ))
        .await
        .expect("query")
        .expect("row");
    let sealed: Vec<u8> = row.try_get("", "sealed").expect("sealed");
    let identity = solana_owner_identity(owner.as_array()).expect("identity");
    for secret_field in [owner.to_bytes(), identity, created[0].utxo.blinding] {
        assert!(!sealed.windows(32).any(|window| window == secret_field));
    }
}

fn indexed_store(store: &Store) -> AuditStore {
    AuditStore::new(Backing::Database {
        store: store.clone(),
        ring: RING,
        seal: Box::new(seal()),
        capacity: MAX_CACHED_ENTRIES,
    })
}

fn terminal(work: &mut PageWork<'_>, slot: u64) {
    work.checkpoint(
        HistoryPosition::after_slot(slot),
        Some(Context {
            slot,
            block_time: 1,
        }),
    );
}

async fn count(store: &Store, sql: &str) -> i64 {
    store
        .connection()
        .query_one(sea_orm::Statement::from_string(
            store.connection().get_database_backend(),
            sql,
        ))
        .await
        .expect("query")
        .expect("row")
        .try_get_by_index(0)
        .expect("count")
}

#[tokio::test]
async fn a_wallet_page_and_balance_read_only_the_owners_active_rows() {
    let (first, second) = (wallet(1), wallet(2));
    let keys = Keys::with(first, 7);
    keys.grant(second, 8);
    let spent = [
        note(first, &secret(7), 0x10, 50),
        note(first, &secret(7), 0x11, 20),
    ];
    let live = note(first, &secret(7), 0x12, 5);
    let others = [
        note(second, &secret(8), 0x20, 9),
        note(second, &secret(8), 0x21, 4),
    ];
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let book = indexed_store(&store);
    let seal = seal();
    let pages: [PageScript<'_>; 3] = [
        Box::new(|work| {
            work.open(frame(2), [spent[0], spent[1], live, others[0], others[1]]);
            terminal(work, 3);
        }),
        Box::new(|work| {
            for (position, created) in spent.iter().enumerate() {
                let nullifier = nullifier_of(created, &secret(7));
                work.observe(real(nullifier, frame(4), position as u16));
            }
            terminal(work, 5);
        }),
        Box::new(|work| terminal(work, 6)),
    ];
    for page in &pages {
        commit_page(&store, &book, &seal, &keys, page.as_ref())
            .await
            .expect("page");
    }
    let member = |owner: Address| {
        *Member::owner_tag(owner.as_array())
            .expect("member")
            .as_bytes()
    };
    let read = |owner| OwnerNotesPage {
        ring: RING,
        seal: &seal,
        range: OwnerRange {
            member: member(owner),
            after: None,
            limit: 100,
        },
    };
    let rows = read(first).read(store.connection()).await.expect("rows");
    assert_eq!(rows.notes.len(), 1, "the spent notes left the index");
    assert_eq!(rows.notes[0].commitment, live.commitment);
    let others = read(second).read(store.connection()).await.expect("rows");
    assert_eq!(others.notes.len(), 2);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM owner_notes").await, 3);
    let status = book.wallet_status(query(first)).await.expect("status");
    assert_eq!((status.notes.len(), balance(&status)), (1, 5));
    let first_page = book
        .wallet_status(WalletStatusQuery {
            limit: 1,
            ..query(second)
        })
        .await
        .expect("page");
    let cursor =
        WalletCursor::decode(&first_page.cursor.clone().expect("cursor").0).expect("cursor");
    let next = book
        .wallet_status(WalletStatusQuery {
            after: Some(cursor),
            limit: 1,
            ..query(second)
        })
        .await
        .expect("page");
    assert_eq!((balance(&first_page), next.balances.len()), (13, 0));
    assert_ne!(first_page.notes[0].utxo_hash, next.notes[0].utxo_hash);
    assert!(next.cursor.is_none());
}

#[tokio::test]
async fn a_spend_leaves_the_owner_index_in_the_transaction_of_its_row() {
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let created = note(owner, &secret(7), 0x10, 50);
    let nullifier = nullifier_of(&created, &secret(7));
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let book = indexed_store(&store);
    let seal = seal();
    let open: PageScript<'_> = Box::new(|work| {
        work.open(frame(2), [created]);
        terminal(work, 3);
    });
    let spend: PageScript<'_> = Box::new(|work| {
        work.observe(real(nullifier, frame(4), 0));
        terminal(work, 5);
    });
    commit_page(&store, &book, &seal, &keys, open.as_ref())
        .await
        .expect("open");
    let active = "SELECT COUNT(*) FROM owner_notes WHERE spent_slot IS NULL";
    let rows = "SELECT COUNT(*) FROM finalized_spent_nullifiers";
    let park = |from: &str, to: &str| format!("ALTER TABLE {from} RENAME TO {to}");
    let connection = store.connection();
    // The checkpoint write fails after the index write, the transaction drops both.
    connection
        .execute_unprepared(&park("spend_checkpoints", "parked"))
        .await
        .expect("park");
    let refused = commit_page(&store, &book, &seal, &keys, spend.as_ref()).await;
    connection
        .execute_unprepared(&park("parked", "spend_checkpoints"))
        .await
        .expect("restore");
    assert!(refused.is_err());
    assert_eq!(
        (count(&store, active).await, count(&store, rows).await),
        (1, 0)
    );
    assert_eq!(
        balance(&book.wallet_status(query(owner)).await.expect("status")),
        50
    );
    commit_page(&store, &book, &seal, &keys, spend.as_ref())
        .await
        .expect("spend");
    assert_eq!(
        (count(&store, active).await, count(&store, rows).await),
        (0, 1)
    );
    assert!(book
        .wallet_status(query(owner))
        .await
        .expect("status")
        .notes
        .is_empty());
}

fn cached_store(store: &Store, capacity: usize) -> AuditStore {
    AuditStore::new(Backing::Database {
        store: store.clone(),
        ring: RING,
        seal: Box::new(seal()),
        capacity,
    })
}

#[tokio::test]
async fn a_bounded_cache_holds_its_bound_and_storage_answers_every_evicted_row() {
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let book = cached_store(&store, 4);
    let seal = seal();
    let created: Vec<CreatedUtxo> = (0..12)
        .map(|index| note(owner, &secret(7), 0x10 + index, 10))
        .collect();
    for (index, utxo) in created.iter().enumerate() {
        let open: PageScript<'_> = Box::new(move |work| {
            work.open(frame(2 + index as u64), [*utxo]);
            terminal(work, 2 + index as u64);
        });
        commit_page(&store, &book, &seal, &keys, open.as_ref())
            .await
            .expect("open");
    }
    let first = nullifier_of(&created[0], &secret(7));
    let spend: PageScript<'_> = Box::new(|work| {
        work.observe(real(first, frame(20), 0));
        terminal(work, 21);
    });
    commit_page(&store, &book, &seal, &keys, spend.as_ref())
        .await
        .expect("spend");
    assert!(book.cached_entries().iter().all(|entries| *entries <= 4));

    // 1. The evicted note and its spend still answer, from storage.
    let commitment = created[0].commitment;
    assert!(book
        .notes(&[commitment])
        .await
        .expect("note")
        .contains_key(&commitment));
    let rows = book.spend_rows(&[first]).await.expect("row");
    assert_eq!(
        rows[&first].state,
        SpendState::Resolved { note: commitment }
    );
    // 2. A second spend of the evicted nullifier reads its stored row and faults.
    let repeat: PageScript<'_> = Box::new(|work| work.observe(real(first, frame(30), 0)));
    commit_page(&store, &book, &seal, &keys, repeat.as_ref())
        .await
        .expect("repeat");
    let coverage = book
        .spend_coverage(CoverageCursor::new(RING))
        .await
        .expect("coverage");
    assert_eq!(coverage.integrity_faults.len(), 1);
    assert_eq!(coverage.totals.expect("first page totals").resolved, 1);
    assert_eq!(
        balance(&book.wallet_status(query(owner)).await.expect("status")),
        110
    );
}

#[tokio::test]
async fn a_follower_invalidates_changed_caches_without_loading_history() {
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let writer = cached_store(&store, MAX_CACHED_ENTRIES);
    let follower = cached_store(&store, MAX_CACHED_ENTRIES);
    let seal = seal();
    let reload = |follower: &AuditStore| {
        let scope = follower.history_scope();
        let seal = &seal;
        let store = &store;
        async move {
            LoadSpends {
                db: store.connection(),
                ring: RING,
                seal,
                scope,
            }
            .load()
            .await
            .expect("load")
        }
    };
    let created: Vec<CreatedUtxo> = (0..5)
        .map(|index| note(owner, &secret(7), 0x10 + index, 10))
        .collect();
    let history: PageScript<'_> = Box::new(|work| {
        work.open(frame(2), created.iter().copied());
        terminal(work, 3);
    });
    commit_page(&store, &writer, &seal, &keys, history.as_ref())
        .await
        .expect("history");
    let cold = reload(&follower).await;
    assert_eq!((cold.spends.notes.len(), cold.spends.rows.len()), (0, 0));
    follower.refresh(cold.spends, cold.revision);
    let retained = PageDelta {
        notes: [(
            created[0].commitment,
            StoredUtxo {
                utxo: created[0].utxo,
                created_in: frame(2),
                slot_index: 0,
                leaf_index: 0,
                ring_note: true,
                nullifier: Some(nullifier_of(&created[0], &secret(7))),
            },
        )]
        .into(),
        revision: Some(cold.revision),
        ..PageDelta::default()
    };
    follower.commit(retained);
    keys.enroll(&follower, None).await;
    let before = follower.cached_entries();
    let before_enrollments = follower.cached_enrollments();
    let idle = reload(&follower).await;
    follower.refresh(idle.spends, idle.revision);
    assert_eq!(follower.cached_entries(), before);
    assert_eq!(follower.cached_enrollments(), before_enrollments);

    let fresh = [
        note(owner, &secret(7), 0x30, 4),
        note(owner, &secret(7), 0x31, 6),
    ];
    let spent = nullifier_of(&created[0], &secret(7));
    let next: PageScript<'_> = Box::new(|work| {
        work.open(frame(5), fresh);
        work.observe(real(spent, frame(5), 0));
        terminal(work, 6);
    });
    commit_page(&store, &writer, &seal, &keys, next.as_ref())
        .await
        .expect("next");
    let changed = reload(&follower).await;
    assert_eq!(
        (changed.spends.notes.len(), changed.spends.rows.len()),
        (0, 0)
    );
    follower.refresh(changed.spends, changed.revision);
    assert_eq!(follower.cached_entries(), [0; 3]);
    assert_eq!(follower.cached_enrollments(), [0; 2]);
    assert!(follower
        .spend_rows(&[spent])
        .await
        .expect("row")
        .contains_key(&spent));
    assert_eq!(follower.context().slot, 6);
    let idle = reload(&follower).await;
    assert_eq!((idle.spends.notes.len(), idle.spends.rows.len()), (0, 0));
}

#[tokio::test]
async fn a_restart_after_enrollment_resumes_old_note_derivation() {
    let database = Store::open("sqlite::memory:", 1).await.expect("store");
    let seal = seal();
    let owner = wallet(1);
    let key = secret(7);
    let created = note(owner, &key, 0x10, 50);
    let nullifier = nullifier_of(&created, &key);
    let before = indexed_store(&database);
    commit_page(&database, &before, &seal, &Keys::none(), &|work| {
        work.open(frame(5), [created]);
        work.observe(real(nullifier, frame(6), 0));
        terminal(work, 6);
    })
    .await
    .expect("history without enrollment");
    let writer = ProjectionWriter {
        db: database.connection(),
        ring: RING,
        seal: &seal,
        lease: LeaseClaim {
            db: database.connection(),
            ring: RING,
            holder: database.lease_holder(),
            now: NOW,
        }
        .claim()
        .await
        .expect("claim")
        .expect("lease"),
        clock: Clock::Fixed(NOW),
    };
    writer
        .commit_enrollments(
            &[HeldEnrollment::unsealed(owner.to_bytes(), &key)],
            TrackingCursor::default(),
        )
        .await
        .expect("enrollment");
    drop(before);
    let after = indexed_store(&database);
    after.replace_late_owners(writer.pending_owners().await.expect("pending"));
    let keys = Keys::with(owner, 7);
    let opener = |held: &HeldEnrollment| keys.open(held);
    let mut work = PageWork::new(&after, &opener);
    work.late_keys();
    let delta = work.finish().await.expect("derive");
    writer.commit_page(&delta).await.expect("derived page");
    let loaded = LoadSpends {
        db: database.connection(),
        ring: RING,
        seal: &seal,
        scope: HistoryScope::Everything,
    }
    .load()
    .await
    .expect("durable result");
    assert_eq!(loaded.spends.notes[0].1.nullifier, Some(nullifier));
    assert_eq!(
        loaded.spends.rows[0].state,
        SpendState::Resolved {
            note: created.commitment
        }
    );
    assert!(writer.pending_owners().await.expect("completed").is_empty());
}

/// The read's value and the owner rows it opened.
async fn opened_by<T>(read: impl std::future::Future<Output = T>) -> (T, usize) {
    OPENED_ROWS.with(|opened| opened.set(0));
    let value = read.await;
    (value, OPENED_ROWS.with(std::cell::Cell::get))
}

/// Commitment and blinding end in a 16 bit index, leading bytes below the field modulus.
fn indexed_note(owner: Address, key: &NullifierKey, index: u16, amount: u64) -> CreatedUtxo {
    let mut created = note(owner, key, 0, amount);
    created.commitment[29] = 0xc0;
    created.commitment[30..].copy_from_slice(&index.to_be_bytes());
    created.utxo.blinding[30..].copy_from_slice(&index.to_be_bytes());
    created.leaf_index = u64::from(index);
    created
}

#[tokio::test]
async fn a_wallet_read_page_by_page_opens_each_listed_row_once() {
    paged_wallet_read(Store::open("sqlite::memory:", 1).await.expect("store")).await;
}

#[tokio::test]
async fn a_stale_follower_reads_newer_rows_at_their_own_history_slot() {
    stale_follower_read(Store::open("sqlite::memory:", 1).await.expect("store")).await;
}

/// Both reads over the repeatable read snapshot, two owners of one ring in one database.
#[tokio::test]
#[ignore = "needs RING_RPC_TEST_POSTGRES_URL"]
async fn wallet_pages_read_one_snapshot_on_postgres() {
    let url = std::env::var("RING_RPC_TEST_POSTGRES_URL").expect("postgres url");
    let store = Store::open(&url, 2).await.expect("store");
    paged_wallet_read(store.clone()).await;
    stale_follower_read(store).await;
}

#[tokio::test]
async fn wallet_snapshot_survives_a_same_slot_spend_and_change() {
    for persistent in [false, true] {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let book = if persistent {
            indexed_store(&store)
        } else {
            AuditStore::default()
        };
        let owner = wallet(1);
        let keys = Keys::with(owner, 7);
        let key = secret(7);
        let seal = seal();
        let initial = [
            indexed_note(owner, &key, 30, 10),
            indexed_note(owner, &key, 40, 10),
            indexed_note(owner, &key, 50, 10),
        ];
        let open = |work: &mut PageWork<'_>| {
            work.open(frame(2), initial);
            terminal(work, 5);
        };
        commit_page(&store, &book, &seal, &keys, &open)
            .await
            .expect("open");
        let first_query = WalletStatusQuery {
            limit: 2,
            ..query(owner)
        };
        let first = book.wallet_status(first_query).await.expect("first page");
        let cursor = WalletCursor::decode(&first.cursor.expect("cursor").0).expect("cursor");
        assert!(zolana_ring_client::rpc::cursor_in_bounds(
            bytemuck::bytes_of(&cursor)
        ));
        let continuation = WalletStatusQuery {
            after: Some(cursor),
            ..first_query
        };
        let next = book
            .wallet_status(continuation)
            .await
            .expect("same snapshot");
        assert_eq!(next.notes.len(), 1);
        assert!(next.cursor.is_none());
        assert!(next.balances.is_empty());
        for foreign in [
            WalletStatusQuery {
                wallet: wallet(2),
                ..continuation
            },
            WalletStatusQuery {
                ring: Address::new_from_array([9; 32]),
                ..continuation
            },
            WalletStatusQuery {
                principal: [9; 34],
                ..continuation
            },
        ] {
            assert!(matches!(
                book.wallet_status(foreign).await,
                Err(RingRpcError::InvalidCursor)
            ));
        }
        let spent = initial
            .iter()
            .find(|note| note.commitment == next.notes[0].utxo_hash.0)
            .expect("input");
        let change = indexed_note(owner, &key, 0, 9);
        if !persistent {
            assert!(change.commitment < cursor.after);
        }
        let spend = |work: &mut PageWork<'_>| {
            work.open(frame(4), [change]);
            work.observe(real(nullifier_of(spent, &key), frame(4), 0));
            terminal(work, 5);
        };
        commit_page(&store, &book, &seal, &keys, &spend)
            .await
            .expect("spend");
        let retained = book
            .wallet_status(continuation)
            .await
            .expect("retained page");
        assert_eq!(retained, next);
        assert_eq!(
            book.wallet_status(WalletStatusQuery {
                enrollment: WalletEnrollment::Applied,
                ..continuation
            })
            .await
            .expect("captured enrollment"),
            next
        );
        assert_eq!(retained.snapshot_expires_at, Some(NOW + 300));
        assert!(matches!(
            book.wallet_status(WalletStatusQuery {
                now: NOW + 300,
                ..continuation
            })
            .await,
            Err(RingRpcError::WalletSnapshotExpired)
        ));
        let restarted = book.wallet_status(query(owner)).await.expect("restart");
        assert_eq!(restarted.history_through, first.history_through);
        assert_eq!(balance(&restarted), 29);
        assert!(restarted
            .notes
            .iter()
            .any(|note| note.utxo_hash.0 == change.commitment));
        assert!(restarted
            .notes
            .iter()
            .all(|note| note.utxo_hash.0 != spent.commitment
                || note.status == WalletNoteStatus::Spent));
    }
}

#[test]
fn wallet_cursor_refuses_unknown_versions_and_old_positions() {
    assert_eq!(
        std::mem::size_of::<WalletCursor>(),
        zolana_ring_client::rpc::WALLET_SNAPSHOT_CURSOR_LEN
    );
    assert!(matches!(
        WalletCursor::decode(&[0; 32]),
        Err(RingRpcError::InvalidCursor)
    ));
    let cursor = WalletCursor {
        version: 1,
        ring: [0; 32],
        wallet: [0; 32],
        snapshot: [0; 32],
        after: [0; 32],
    };
    assert!(matches!(
        WalletCursor::decode(bytemuck::bytes_of(&cursor)),
        Err(RingRpcError::InvalidCursor)
    ));
    let error = jsonrpsee::types::ErrorObjectOwned::from(RingRpcError::WalletSnapshotExpired);
    assert_eq!(
        error.code(),
        zolana_ring_client::rpc::WALLET_SNAPSHOT_EXPIRED
    );
    assert!(error.message().contains("restart without a cursor"));
}

async fn paged_wallet_read(store: Store) {
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let book = indexed_store(&store);
    let seal = seal();
    let created: Vec<CreatedUtxo> = (0..10)
        .map(|index| indexed_note(owner, &secret(7), index, 10))
        .collect();
    let history: PageScript<'_> = Box::new(|work| {
        work.open(frame(2), created.iter().copied());
        terminal(work, 3);
    });
    commit_page(&store, &book, &seal, &keys, history.as_ref())
        .await
        .expect("history");
    let limit = 3;
    let page = |after| WalletStatusQuery {
        after,
        limit,
        ..query(owner)
    };
    let (first, opened) = opened_by(book.wallet_status(page(None))).await;
    let first = first.expect("first page");
    assert!(opened <= 10 + 2 * limit);
    assert_eq!((first.notes.len(), balance(&first)), (3, 100));
    // 2. Every later page opens its own rows alone and carries no balance.
    let mut listed: BTreeSet<[u8; 32]> = first.notes.iter().map(|note| note.utxo_hash.0).collect();
    let mut cursor = first.cursor.clone();
    let mut later_opens = 0;
    while let Some(next) = cursor {
        let after = WalletCursor::decode(&next.0).expect("cursor");
        let (read, opened) = opened_by(book.wallet_status(page(Some(after)))).await;
        let read = read.expect("page");
        assert!(opened <= limit && read.balances.is_empty());
        later_opens += opened;
        for note in &read.notes {
            assert!(listed.insert(note.utxo_hash.0), "a row lists once");
        }
        cursor = read.cursor;
    }
    assert_eq!((later_opens, listed.len()), (7, 10));
}

#[tokio::test]
async fn a_wallet_read_never_pairs_rows_with_a_mirror_that_moved_past_them() {
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let created = note(owner, &secret(7), 0x10, 50);
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let book = indexed_store(&store);
    let seal = seal();
    let open: PageScript<'_> = Box::new(|work| {
        work.open(frame(2), [created]);
        terminal(work, 3);
    });
    commit_page(&store, &book, &seal, &keys, open.as_ref())
        .await
        .expect("open");
    // The writer's mirror takes the spend page its transaction has not yet committed, the state a
    // read sees when the commit lands between its row read and its coverage read.
    let opener = |held: &HeldEnrollment| keys.open(held);
    let mut work = PageWork::new(&book, &opener);
    work.observe(real(nullifier_of(&created, &secret(7)), frame(4), 0));
    terminal(&mut work, 5);
    book.commit(work.finish().await.expect("spend page"));
    assert_eq!(book.read_book().history_through(), 5);
    let read = book.wallet_status(query(owner)).await.expect("status");
    assert_eq!(
        read.history_through, 3,
        "the slot comes from the rows' snapshot"
    );
    assert_eq!(statuses(&read), [WalletNoteStatus::Unspent]);
}

async fn stale_follower_read(store: Store) {
    let owner = wallet(2);
    let keys = Keys::with(owner, 8);
    let input = note(owner, &secret(8), 0x10, 50);
    let change = note(owner, &secret(8), 0x11, 30);
    let writer = indexed_store(&store);
    let follower = indexed_store(&store);
    let seal = seal();
    let pages: [PageScript<'_>; 3] = [
        Box::new(|work| {
            work.open(frame(2), [input]);
            terminal(work, 3);
        }),
        Box::new(|work| {
            work.open(frame(4), [change]);
            work.observe(real(nullifier_of(&input, &secret(8)), frame(4), 0));
            terminal(work, 5);
        }),
        Box::new(|work| terminal(work, 6)),
    ];
    for page in &pages {
        commit_page(&store, &writer, &seal, &keys, page.as_ref())
            .await
            .expect("page");
    }
    // The follower never reloaded, its mirror still holds slot zero.
    assert_eq!(follower.read_book().history_through(), 0);
    let read = follower.wallet_status(query(owner)).await.expect("status");
    assert_eq!((read.history_through, balance(&read)), (6, 30));
    assert_eq!(read.notes[0].utxo_hash.0, change.commitment);
}

#[tokio::test]
async fn a_late_owner_derives_in_bounded_steps_and_resumes_after_each_restart() {
    let database = Store::open("sqlite::memory:", 1).await.expect("store");
    let seal = seal();
    let owner = wallet(1);
    let count_notes = MAX_LATE_NOTES * 2 + 1;
    let created: Vec<CreatedUtxo> = (0..count_notes)
        .map(|index| indexed_note(owner, &secret(7), index as u16, 1))
        .collect();
    let before = indexed_store(&database);
    commit_page(&database, &before, &seal, &Keys::none(), &|work| {
        work.open(frame(5), created.iter().copied());
        terminal(work, 6);
    })
    .await
    .expect("history without enrollment");
    drop(before);
    let writer = ProjectionWriter {
        db: database.connection(),
        ring: RING,
        seal: &seal,
        lease: LeaseClaim {
            db: database.connection(),
            ring: RING,
            holder: database.lease_holder(),
            now: NOW,
        }
        .claim()
        .await
        .expect("claim")
        .expect("lease"),
        clock: Clock::Fixed(NOW),
    };
    writer
        .commit_enrollments(
            &[HeldEnrollment::unsealed(owner.to_bytes(), &secret(7))],
            TrackingCursor::default(),
        )
        .await
        .expect("enrollment");
    let keys = Keys::with(owner, 7);
    let derived = "SELECT COUNT(*) FROM finalized_notes WHERE nullifier_tag IS NOT NULL";
    // Each step is a fresh replica, it knows only the resume tag the last commit stored.
    for expected in [MAX_LATE_NOTES, MAX_LATE_NOTES * 2, count_notes] {
        let restarted = indexed_store(&database);
        let pending = writer.pending_owners().await.expect("pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].resume.is_some(), expected != MAX_LATE_NOTES);
        restarted.replace_late_owners(pending);
        let opener = |held: &HeldEnrollment| keys.open(held);
        let mut work = PageWork::new(&restarted, &opener);
        work.late_keys();
        let delta = work.finish().await.expect("derive");
        writer.commit_page(&delta).await.expect("derived page");
        assert_eq!(count(&database, derived).await, expected as i64);
    }
    assert!(writer.pending_owners().await.expect("completed").is_empty());
}

#[tokio::test]
async fn wallet_snapshot_capacity_release_and_restart_preserve_sessions() {
    for persistent in [false, true] {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let book = if persistent {
            indexed_store(&store)
        } else {
            AuditStore::default()
        }
        .with_wallet_snapshots(
            SharedWalletSnapshots::default(),
            WalletSnapshotLimits {
                store: std::num::NonZeroUsize::MIN,
                principal_wallet: std::num::NonZeroUsize::MIN,
            },
        );
        let owner = wallet(1);
        let key = secret(7);
        let keys = Keys::with(owner, 7);
        let seal = seal();
        commit_page(&store, &book, &seal, &keys, &|work| {
            work.open(
                frame(2),
                [
                    indexed_note(owner, &key, 30, 10),
                    indexed_note(owner, &key, 40, 10),
                    indexed_note(owner, &key, 50, 10),
                ],
            );
            terminal(work, 5);
        })
        .await
        .expect("open");
        let first_query = WalletStatusQuery {
            limit: 1,
            ..query(owner)
        };
        let first = book.wallet_status(first_query).await.expect("snapshot");
        let cursor = WalletCursor::decode(&first.cursor.expect("cursor").0).expect("cursor");
        assert_eq!(first.snapshot_expires_at, Some(NOW + 300));
        assert!(matches!(
            book.wallet_status(first_query).await,
            Err(RingRpcError::WalletSnapshotCapacity)
        ));
        let single = book.wallet_status(query(owner)).await.expect("single page");
        assert!(single.snapshot_expires_at.is_none());
        assert_eq!(single.notes.len(), 3);
        let continuation = WalletStatusQuery {
            after: Some(cursor),
            ..first_query
        };
        let next = book
            .wallet_status(continuation)
            .await
            .expect("retained page");
        if persistent {
            let reopened = indexed_store(&store);
            assert_eq!(
                reopened
                    .wallet_status(continuation)
                    .await
                    .expect("restart page"),
                next
            );
        }
        let release = || WalletSnapshotRelease {
            ring: RING,
            wallet: owner,
            principal: first_query.principal,
            cursor,
            now: NOW,
        };
        assert!(matches!(
            book.release_wallet_snapshot(WalletSnapshotRelease {
                principal: [9; 34],
                ..release()
            })
            .await,
            Err(RingRpcError::InvalidCursor)
        ));
        assert_eq!(
            book.wallet_status(continuation).await.expect("still live"),
            next
        );
        book.release_wallet_snapshot(release())
            .await
            .expect("release");
        book.release_wallet_snapshot(release())
            .await
            .expect("idempotent release");
        assert!(matches!(
            book.wallet_status(continuation).await,
            Err(RingRpcError::WalletSnapshotExpired)
        ));
        book.wallet_status(first_query)
            .await
            .expect("released capacity");
        assert!(matches!(
            book.wallet_status(WalletStatusQuery {
                now: NOW + 301,
                ..first_query
            })
            .await,
            Err(RingRpcError::WalletSnapshotCapacity)
        ));
        if persistent {
            crate::wallet_snapshots::WalletSnapshotCleanup {
                db: store.connection(),
                now: NOW + 301,
            }
            .run()
            .await
            .expect("cleanup");
        } else {
            book.wallet_snapshots
                .lock()
                .expect("snapshots")
                .cleanup(NOW + 301);
        }
        book.wallet_status(WalletStatusQuery {
            now: NOW + 301,
            ..first_query
        })
        .await
        .expect("expired capacity");
    }
}

#[tokio::test]
async fn wallet_snapshot_cleanup_keeps_capacity_until_all_rows_are_removed() {
    for persistent in [false, true] {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let book = if persistent {
            indexed_store(&store)
        } else {
            AuditStore::default()
        }
        .with_wallet_snapshots(
            SharedWalletSnapshots::default(),
            WalletSnapshotLimits {
                store: std::num::NonZeroUsize::MIN,
                principal_wallet: std::num::NonZeroUsize::MIN,
            },
        );
        let owner = wallet(1);
        let key = secret(7);
        let keys = Keys::with(owner, 7);
        let seal = seal();
        let created: Vec<_> = (0..=OWNER_ROW_BATCH)
            .map(|index| indexed_note(owner, &key, index.try_into().expect("note index"), 10))
            .collect();
        commit_page(&store, &book, &seal, &keys, &|work| {
            work.open(frame(2), created.iter().copied());
            terminal(work, 5);
        })
        .await
        .expect("open");
        let read = query(owner);
        let first = book.wallet_status(read).await.expect("snapshot");
        let cursor = WalletCursor::decode(&first.cursor.expect("cursor").0).expect("cursor");
        book.release_wallet_snapshot(WalletSnapshotRelease {
            ring: RING,
            wallet: owner,
            principal: read.principal,
            cursor,
            now: NOW,
        })
        .await
        .expect("release");
        assert!(matches!(
            book.wallet_status(read).await,
            Err(RingRpcError::WalletSnapshotCapacity)
        ));
        let remaining = if persistent {
            crate::wallet_snapshots::WalletSnapshotCleanup {
                db: store.connection(),
                now: NOW,
            }
            .run()
            .await
            .expect("cleanup")
        } else {
            book.wallet_snapshots
                .lock()
                .expect("snapshots")
                .cleanup(NOW)
        };
        assert_eq!(remaining, 1);
        book.wallet_status(read).await.expect("capacity reclaimed");
    }
}

#[tokio::test]
#[ignore = "needs RING_RPC_TEST_POSTGRES_URL"]
async fn overlapping_wallet_snapshots_preserve_both_quotas_on_postgres() {
    use sea_orm::{DatabaseBackend, Statement, TransactionTrait};
    use sea_orm_migration::MigratorTrait;
    use std::{num::NonZeroUsize, sync::Arc, time::Duration};

    let url = std::env::var("RING_RPC_TEST_POSTGRES_URL").expect("postgres url");
    let coordinator = Store::open(&url, 2).await.expect("coordinator");
    crate::Migrator::fresh(coordinator.connection())
        .await
        .expect("empty test store");
    let stores = [
        Store::open(&url, 1).await.expect("first capture pool"),
        Store::open(&url, 1).await.expect("second capture pool"),
    ];
    let mut pids = Vec::new();
    for store in &stores {
        let row = store
            .connection()
            .query_one(Statement::from_string(
                DatabaseBackend::Postgres,
                "SELECT pg_backend_pid() AS pid",
            ))
            .await
            .expect("backend")
            .expect("backend row");
        pids.push(row.try_get::<i32>("", "pid").expect("backend pid"));
    }
    let owner = wallet(97);
    let key = secret(7);
    let keys = Keys::with(owner, 7);
    let book = indexed_store(&coordinator);
    commit_page(&coordinator, &book, &seal(), &keys, &|work| {
        work.open(
            frame(2),
            [
                indexed_note(owner, &key, 30_000, 10),
                indexed_note(owner, &key, 30_001, 10),
            ],
        );
        terminal(work, 5);
    })
    .await
    .expect("wallet notes");
    let baseline = count(&coordinator, "SELECT COUNT(*) FROM wallet_snapshots").await;

    for same_principal in [false, true] {
        let limits = WalletSnapshotLimits {
            store: NonZeroUsize::new(baseline as usize + if same_principal { 2 } else { 1 })
                .expect("store limit"),
            principal_wallet: NonZeroUsize::new(if same_principal { 1 } else { 2 })
                .expect("scope limit"),
        };
        let first = WalletStatusQuery {
            principal: query(wallet(98)).principal,
            limit: 1,
            ..query(owner)
        };
        let second = WalletStatusQuery {
            principal: if same_principal {
                first.principal
            } else {
                query(wallet(99)).principal
            },
            ..first
        };
        let lock = coordinator
            .connection()
            .begin()
            .await
            .expect("admission lock");
        lock.query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT id FROM wallet_snapshot_admission WHERE id=1 FOR UPDATE",
        ))
        .await
        .expect("lock admission")
        .expect("admission row");
        let start = Arc::new(tokio::sync::Barrier::new(2));
        let mut attempts = Vec::new();
        for (store, query) in stores.iter().cloned().zip([first, second]) {
            let start = start.clone();
            attempts.push(tokio::spawn(async move {
                let book = indexed_store(&store)
                    .with_wallet_snapshots(SharedWalletSnapshots::default(), limits);
                start.wait().await;
                (query, book.wallet_status(query).await)
            }));
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let row = coordinator.connection().query_one(Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    "SELECT COUNT(*) AS blocked FROM pg_stat_activity WHERE pid IN ($1,$2) AND wait_event_type='Lock' AND query LIKE 'LOCK TABLE wallet_snapshot_admission%'",
                    vec![pids[0].into(), pids[1].into()],
                )).await.expect("capture lock waits").expect("lock count");
                if row.try_get::<i64>("", "blocked").expect("blocked captures") == 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both captures must reach admission before release");
        lock.rollback().await.expect("release admission");
        let mut admitted = Vec::new();
        let mut refused = Vec::new();
        for attempt in attempts {
            let (query, result) = tokio::time::timeout(Duration::from_secs(10), attempt)
                .await
                .expect("capture completes")
                .expect("capture task");
            match result {
                Ok(page) => admitted.push((query, page)),
                Err(error) => refused.push((query, error)),
            }
        }
        assert_eq!(admitted.len(), 1);
        assert_eq!(refused.len(), 1);
        assert!(
            matches!(refused[0].1, RingRpcError::WalletSnapshotCapacity),
            "{:?}",
            refused[0].1
        );
        assert_eq!(
            count(&coordinator, "SELECT COUNT(*) FROM wallet_snapshots").await,
            baseline + 1
        );
        let book = indexed_store(&coordinator)
            .with_wallet_snapshots(SharedWalletSnapshots::default(), limits);
        assert!(matches!(
            book.wallet_status(refused[0].0).await,
            Err(RingRpcError::WalletSnapshotCapacity)
        ));
        let (query, page) = admitted.pop().expect("admitted snapshot");
        book.release_wallet_snapshot(WalletSnapshotRelease {
            ring: query.ring,
            wallet: query.wallet,
            principal: query.principal,
            cursor: WalletCursor::decode(&page.cursor.expect("cursor").0).expect("cursor"),
            now: query.now,
        })
        .await
        .expect("release snapshot");
        assert_eq!(
            count(&coordinator, "SELECT COUNT(*) FROM wallet_snapshots").await,
            baseline
        );
    }
    crate::Migrator::fresh(coordinator.connection())
        .await
        .expect("restore empty test store");
}

#[tokio::test]
async fn coverage_pages_visit_all_faults_without_retaining_database_history() {
    let database = Store::open("sqlite::memory:", 1).await.expect("store");
    let seal = seal();
    let keys = Keys::none();
    let memory = AuditStore::default();
    let bounded = cached_store(&database, 4);
    let history = |work: &mut PageWork<'_>| {
        for index in 1..=205u64 {
            let nullifier = [index as u8; 32];
            work.observe(real(nullifier, frame(index), 0));
            work.observe(real(nullifier, frame(index + 300), 0));
            work.mark_unread(frame(index));
        }
        terminal(work, 600);
    };
    let opener = |held: &HeldEnrollment| keys.open(held);
    let mut work = PageWork::new(&memory, &opener);
    history(&mut work);
    memory.commit(work.finish().await.expect("memory history"));
    commit_page(&database, &bounded, &seal, &keys, &history)
        .await
        .expect("history");
    assert_eq!(bounded.read_book().unread.len(), 1);
    assert!(bounded.read_book().faults.is_empty());
    let loaded = LoadSpends {
        db: database.connection(),
        ring: RING,
        seal: &seal,
        scope: bounded.history_scope(),
    }
    .load()
    .await
    .expect("load");
    assert_eq!(loaded.spends.unread.len(), 1);
    assert!(loaded.spends.faults.is_empty());
    assert!(loaded.repairs.is_empty());
    for store in [&memory, &bounded] {
        let mut cursor = CoverageCursor::new(RING);
        let mut totals = [0; 3];
        let mut seen = [BTreeSet::new(), BTreeSet::new(), BTreeSet::new()];
        let mut pages = 0;
        loop {
            let response = store.spend_coverage(cursor).await.expect("coverage");
            assert_eq!(response.totals.is_some(), pages == 0);
            let wire = serde_json::to_value(&response).expect("coverage wire");
            assert_eq!(wire.get("totals").is_some(), pages == 0);
            assert_eq!(response.history_through, 0);
            let sizes = [
                response.unresolved_real.len(),
                response.unreadable.len(),
                response.integrity_faults.len(),
            ];
            for (total, size) in totals.iter_mut().zip(sizes) {
                assert!(size <= zolana_ring_client::rpc::AUDIT_PAGE_LIMIT as usize);
                *total += size;
            }
            seen[0].extend(response.unresolved_real.iter().map(|row| row.nullifier.0));
            seen[1].extend(response.unreadable.iter().map(|row| [row.slot as u8; 32]));
            seen[2].extend(response.integrity_faults.iter().map(|row| row.nullifier.0));
            pages += 1;
            match response.cursor {
                Some(token) => {
                    assert!(zolana_ring_client::rpc::cursor_in_bounds(&token.0));
                    assert!(
                        CoverageCursor::decode(&token.0, Address::new_from_array([9; 32])).is_err()
                    );
                    cursor = CoverageCursor::decode(&token.0, RING).expect("cursor");
                }
                None => break,
            }
        }
        assert_eq!(pages, 3);
        assert_eq!(totals, [205; 3]);
        assert_eq!(seen.map(|rows| rows.len()), [205; 3]);
    }
}

#[tokio::test]
async fn durable_repairs_select_due_frames_and_keep_only_one_batch() {
    use crate::frame_repairs::MAX_REPAIRED_FRAMES;
    let database = Store::open("sqlite::memory:", 1).await.expect("store");
    let book = cached_store(&database, 4);
    let seal = seal();
    commit_page(&database, &book, &seal, &Keys::none(), &|work| {
        for slot in 1..=40 {
            work.mark_unread(frame(slot));
        }
        terminal(work, 50);
    })
    .await
    .expect("history");
    let mut repairs = RepairBook::default();
    let first = book.due_repairs(&mut repairs, NOW).await.expect("due");
    assert_eq!(first.len(), MAX_REPAIRED_FRAMES);
    assert_eq!(first[0], frame(1));
    database
        .connection()
        .execute_unprepared(
            "UPDATE spend_unread_frames SET attempts=1,retry_after=2000 WHERE slot<=16",
        )
        .await
        .expect("backoff");
    let second = book.due_repairs(&mut repairs, NOW).await.expect("due");
    assert_eq!(second.len(), MAX_REPAIRED_FRAMES);
    assert_eq!(second[0], frame(17));
    assert_eq!(repairs.failed(first[0], NOW).attempts, 1);
    commit_page(&database, &book, &seal, &Keys::none(), &|work| {
        work.mark_read(frame(1))
    })
    .await
    .expect("repair");
    assert_eq!(book.read_book().history_through(), 1);
}

#[tokio::test]
async fn coverage_continuation_does_not_read_lifetime_totals() {
    let database = Store::open("sqlite::memory:", 1).await.expect("store");
    let book = cached_store(&database, 4);
    let seal = seal();
    commit_page(&database, &book, &seal, &Keys::none(), &|work| {
        for slot in 1..=101 {
            work.mark_unread(frame(slot));
        }
        terminal(work, 102);
    })
    .await
    .expect("history");
    let first = book
        .spend_coverage(CoverageCursor::new(RING))
        .await
        .expect("first page");
    assert_eq!(first.totals, Some(SpendCoverageTotals::default()));
    assert_eq!(first.unreadable.len(), 100);
    let cursor =
        CoverageCursor::decode(&first.cursor.expect("continuation").0, RING).expect("cursor");
    database
        .connection()
        .execute_unprepared(
            "ALTER TABLE finalized_spent_nullifiers RENAME TO parked_spent_nullifiers",
        )
        .await
        .expect("park totals source");
    let continuation = book.spend_coverage(cursor).await;
    database
        .connection()
        .execute_unprepared(
            "ALTER TABLE parked_spent_nullifiers RENAME TO finalized_spent_nullifiers",
        )
        .await
        .expect("restore totals source");
    let continuation = continuation.expect("continuation does not count spends");
    assert_eq!(continuation.totals, None);
    assert_eq!(continuation.unreadable.len(), 1);
    assert!(continuation.cursor.is_none());
}
