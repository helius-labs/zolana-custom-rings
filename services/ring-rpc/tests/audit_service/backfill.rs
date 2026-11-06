use super::*;
use sea_orm::{ConnectionTrait, Statement, TransactionTrait};
use std::{future::poll_fn, pin::pin, task::Poll};
use zolana_ring_client::rpc::{WalletEnrollment, WalletNoteStatus};

#[tokio::test]
async fn audited_utxos_answer_in_request_order_with_null_for_an_unseen_hash() {
    let fixture = Fixture::new();
    let mut source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone()]);
    source.next_cursor = None;
    let hub = Arc::new(fixture.hub(source));
    let service = hub.service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let outputs: Vec<[u8; 32]> = fixture
        .audited
        .output_slots
        .iter()
        .map(|slot| slot.output_context.hash)
        .collect();
    let unseen = Hash([0x77; 32]);
    let request = utxos_request(vec![outputs[1].into(), unseen, outputs[0].into()]);
    let module = rpc_module(hub).expect("module");
    let response: GetAuditedUtxosResponse = module
        .call(GET_AUDITED_UTXOS, as_object(&request))
        .await
        .expect("UTXO read");
    let amounts: Vec<Option<u64>> = response
        .value
        .utxos
        .iter()
        .map(|view| view.as_ref().map(|view| view.utxo.amount))
        .collect();
    assert_eq!(amounts, [Some(7), None, Some(500)]);
    // Only the backfill's terminal page vouches for the history before its context.
    assert_eq!(response.context.slot, 99);
    let wire = as_object(response.value.utxos[0].as_ref().expect("opened UTXO"));
    let keys: HashSet<&str> = wire.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        HashSet::from([
            "utxoHash",
            "utxo",
            "slot",
            "txSignature",
            "eventIndex",
            "slotIndex",
        ])
    );
    assert_eq!(
        wire["utxoHash"],
        serde_json::json!(Hash(outputs[1]).to_base58())
    );
    assert_eq!(wire["slotIndex"], serde_json::json!(1));
}

#[tokio::test]
async fn audited_utxos_refuse_an_ungranted_reader_a_bad_count_a_changed_hash_and_a_replay() {
    let fixture = Fixture::new();
    let service = fixture
        .hub(fixture.source())
        .service(None)
        .expect("service");
    let hashes = vec![Hash([0x77; 32])];
    let stranger_request = GetAuditedUtxosRequest::read(target(RING), hashes.clone())
        .expect("UTXO read")
        .sign(&stranger())
        .expect("signed UTXO read");
    assert!(matches!(
        service.audited_utxos(&stranger_request).await,
        Err(RingRpcError::Unauthorized(Unauthorized::NotGranted))
    ));
    for count in [0, AUDITED_UTXOS_LIMIT + 1] {
        let hashes = vec![Hash([0x77; 32]); count];
        assert!(matches!(
            GetAuditedUtxosRequest::read(target(RING), hashes.clone()),
            Err(ReadBuildError::UtxoHashes)
        ));
        let request = GetAuditedUtxosRequest {
            utxo_hashes: hashes,
            ..utxos_request(vec![Hash([0x77; 32])])
        };
        assert!(matches!(
            service.audited_utxos(&request).await,
            Err(RingRpcError::InvalidUtxoRequest)
        ));
    }
    let mut changed = utxos_request(hashes.clone());
    changed.utxo_hashes = vec![Hash([0x78; 32])];
    assert!(matches!(
        service.audited_utxos(&changed).await,
        Err(RingRpcError::Unauthorized(Unauthorized::BadSignature))
    ));
    let request = utxos_request(hashes);
    assert!(service.audited_utxos(&request).await.is_ok());
    assert!(matches!(
        service.audited_utxos(&request).await,
        Err(RingRpcError::Unauthorized(Unauthorized::Replay))
    ));
}

#[tokio::test]
async fn a_confirmed_merge_tag_collision_does_not_poison_an_audit_page() {
    let fixture = Fixture::new();
    let mut merge = fixture.missing_message.clone();
    merge.tx_signature = Signature::from([12; 64]);
    merge.tx_viewing_pk = None;
    let source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone(), merge]);
    let service = fixture.hub(source).service(None).unwrap();
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &auth(&delegate()),
            page: &page(),
            wallet: None,
        })
        .await
        .unwrap();
    assert_eq!(response.value.items.len(), 1);
    assert_eq!(
        response.value.items[0].tx_signature,
        fixture.audited.tx_signature.into()
    );
    assert!(response.value.skipped.is_empty());
}

#[tokio::test]
async fn a_backfill_stops_at_its_page_budget() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = long_history(&fixture, None, 1);
    let reads = source.history_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("bounded backfill");
    assert!(reads.load(Ordering::Relaxed) < HISTORY_READ_CAP);
}

#[tokio::test]
async fn the_utxo_context_moves_only_at_the_scan_frontier() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = HashMap::from([
        (None, paged(vec![fixture.audited.clone()], Some(1), None)),
        (
            Some(vec![1]),
            paged(vec![outside_row(&fixture)], Some(1), None),
        ),
    ]);
    let service = fixture.hub(source).service(None).expect("service");
    assert!(matches!(
        service.backfill_utxos().await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));
    let hash = Hash(fixture.audited.output_slots[0].output_context.hash);
    let found = service
        .audited_utxos(&utxos_request(vec![hash]))
        .await
        .expect("UTXO read");
    assert!(found.value.utxos[0].is_some());
    assert_eq!(found.context.slot, 0);
}

#[tokio::test]
async fn an_unconfigured_ring_backfills_nothing() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.configs.clear();
    let reads = source.history_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("unconfigured ring");
    assert_eq!(reads.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_row_whose_origin_does_not_decode_is_skipped_and_the_backfill_goes_past_it() {
    let fixture = Fixture::new();
    let utxos = SpentUtxo::new(&fixture);
    let rows = vec![utxos.entry.clone(), utxos.paid.clone()];
    let source = utxos.source(
        &fixture,
        [
            (None, paged(rows, Some(1), None)),
            (Some(vec![1]), paged(Vec::new(), None, Some(2))),
        ],
    );
    source
        .undecodable
        .lock()
        .unwrap()
        .insert(utxos.entry.tx_signature);
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let found = service
        .audited_utxos(&utxos_request(vec![utxos.commitment.into()]))
        .await
        .expect("UTXO read");
    assert!(found.value.utxos[0].is_some(), "the row after the bad one");
    let page = read_at(&service, None).await;
    let [skipped] = page.value.skipped.as_slice() else {
        panic!("one bad row, {:?}", page.value.skipped);
    };
    assert_eq!(skipped.tx_signature.0, utxos.entry.tx_signature);
    assert_eq!(skipped.reason, SkippedReason::InvalidAuditData);
    assert_eq!(page.value.items.len(), 1);
}

#[tokio::test]
async fn a_failed_origin_read_stops_the_backfill_at_its_position() {
    let fixture = Fixture::new();
    let utxos = SpentUtxo::new(&fixture);
    let mut source = utxos.source(
        &fixture,
        [
            (None, paged(vec![utxos.paid.clone()], None, Some(1))),
            (Some(vec![1]), paged(Vec::new(), None, Some(1))),
        ],
    );
    source.origins.clear();
    let service = fixture.hub(source).service(None).expect("service");
    assert!(service.backfill_utxos().await.is_err());
    assert!(read_at_result(&service, None).await.is_err());
}

async fn stored_amount(service: &AuditService<StaticSource>, hash: &Hash) -> Option<u64> {
    let found = service
        .audited_utxos(&utxos_request(vec![hash.clone()]))
        .await
        .expect("UTXO read");
    found.value.utxos[0].as_ref().map(|view| view.utxo.amount)
}

fn cursors(source: &StaticSource) -> Vec<Option<Vec<u8>>> {
    source.history_cursors.lock().unwrap().clone()
}

#[tokio::test]
async fn a_permanently_invalid_row_passes_the_cursor() {
    let fixture = Fixture::new();
    let rows = vec![fixture.foreign_key.clone(), fixture.audited.clone()];
    let hash = Hash(fixture.audited.output_slots[0].output_context.hash);
    let mut source = fixture.source().with_transactions(rows.clone());
    source.pages = HashMap::from([
        (None, paged(rows, None, Some(1))),
        (Some(vec![1]), paged(Vec::new(), None, Some(1))),
    ]);
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(stored_amount(&service, &hash).await, Some(500));
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(cursors(&probe), [None, Some(vec![1])]);
    assert_eq!(
        *probe.frame_reads.lock().unwrap(),
        [fixture.foreign_key.tx_signature],
        "the row retries by its signature"
    );
}

#[tokio::test]
async fn a_lost_auditor_message_holds_the_backfill_and_lists_on_a_read() {
    let fixture = Fixture::new();
    let rows = vec![fixture.missing_message.clone(), fixture.audited.clone()];
    let mut source = fixture.source().with_transactions(rows.clone());
    source.pages = HashMap::from([(None, paged(rows, None, Some(1)))]);
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    assert!(service.backfill_utxos().await.is_err());
    assert!(service.backfill_utxos().await.is_err());
    assert_eq!(cursors(&probe), [None, None]);
    let page = read_at(&service, None).await;
    let [skipped] = page.value.skipped.as_slice() else {
        panic!("one lost message, {:?}", page.value.skipped);
    };
    assert_eq!(skipped.reason, SkippedReason::MissingAuditorMessage);
    assert_eq!(page.value.items.len(), 1);
}

#[tokio::test]
async fn a_faulty_call_stack_stops_the_backfill_and_the_read() {
    let fixture = Fixture::new();
    let rows = vec![fixture.audited.clone()];
    let mut source = fixture.source().with_transactions(rows.clone());
    source.pages = HashMap::from([(None, paged(rows, None, Some(1)))]);
    source.stack_faults.insert(fixture.audited.tx_signature);
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    assert!(service.backfill_utxos().await.is_err());
    assert!(service.backfill_utxos().await.is_err());
    assert_eq!(cursors(&probe), [None, None]);
    assert!(read_at_result(&service, None).await.is_err());
}

/// A row of no served ring, each pass reads it and applies nothing.
fn outside_row(fixture: &Fixture) -> ShieldedTransaction {
    let mut row = fixture.audited.clone();
    row.ring_program_id = None;
    row
}

/// More non terminal pages than one pass reads, from `start`, keyed from `first`.
fn long_history(
    fixture: &Fixture,
    start: Option<Vec<u8>>,
    first: u8,
) -> HashMap<Option<Vec<u8>>, Paged> {
    let mut pages = HashMap::new();
    let mut key = start;
    for index in first..first + 70 {
        pages.insert(
            key.clone(),
            paged(vec![outside_row(fixture)], Some(index), None),
        );
        key = Some(vec![index]);
    }
    pages.insert(key, paged(Vec::new(), None, Some(200)));
    pages
}

async fn history_through(service: &AuditService<StaticSource>) -> u64 {
    let request = WalletStatusRequest::new(target(RING), Address::new_from_array([1; 32]))
        .sign(&delegate())
        .expect("signed status read");
    service
        .wallet_status(&request)
        .await
        .expect("status read")
        .history_through
}

#[tokio::test]
async fn an_empty_history_claims_only_its_terminal_slot() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = HashMap::from([(None, paged(Vec::new(), None, Some(1)))]);
    let service = fixture.hub(source).service(None).expect("service");
    assert_eq!(history_through(&service).await, 0, "no pass reached a page");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(history_through(&service).await, 99);
}

#[tokio::test]
async fn a_capped_pass_keeps_the_history_slot_until_a_later_terminal_page() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = long_history(&fixture, Some(vec![1]), 2);
    source.pages.insert(None, paged(Vec::new(), None, Some(1)));
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("first pass");
    let first = history_through(&service).await;
    service.backfill_utxos().await.expect("capped pass");
    assert_eq!(
        history_through(&service).await,
        first,
        "the cap stopped the pass"
    );
    service.backfill_utxos().await.expect("last pass");
    assert!(history_through(&service).await > first);
}

#[tokio::test]
async fn a_failed_pass_keeps_the_history_slot_and_the_position() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = HashMap::from([(None, paged(Vec::new(), None, Some(1)))]);
    let down = source.history_down.clone();
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("first pass");
    let through = history_through(&service).await;

    down.store(true, Ordering::Relaxed);
    assert!(service.backfill_utxos().await.is_err());
    assert_eq!(history_through(&service).await, through);

    down.store(false, Ordering::Relaxed);
    service.backfill_utxos().await.expect("retry");
    assert_eq!(cursors(&probe), [None, Some(vec![1]), Some(vec![1])]);
}

#[tokio::test]
async fn a_snapshot_behind_the_floor_refuses_the_page_and_keeps_the_position() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = HashMap::from([(None, paged(Vec::new(), None, Some(1)))]);
    let context = source.forced_context.clone();
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("first pass");
    let through = history_through(&service).await;

    *context.lock().unwrap() = Some(through - 1);
    assert!(matches!(
        service.backfill_utxos().await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));
    assert_eq!(history_through(&service).await, through);

    *context.lock().unwrap() = None;
    service.backfill_utxos().await.expect("caught up");
    assert_eq!(cursors(&probe), [None, Some(vec![1]), Some(vec![1])]);
}

#[tokio::test]
async fn a_retryable_row_keeps_the_position_and_claims_nothing() {
    let fixture = Fixture::new();
    let rows = vec![fixture.missing_message.clone(), fixture.audited.clone()];
    let mut source = fixture.source().with_transactions(rows.clone());
    source.pages = HashMap::from([(None, paged(rows, None, Some(1)))]);
    let probe = source.clone();
    let service = fixture.hub(source).service(None).expect("service");
    assert!(service.backfill_utxos().await.is_err());
    assert!(service.backfill_utxos().await.is_err());
    assert_eq!(cursors(&probe), [None, None]);
    assert_eq!(history_through(&service).await, 0);
}

#[tokio::test]
async fn a_restart_without_a_store_replays_from_the_start() {
    let fixture = Fixture::new();
    let rows = vec![fixture.audited.clone()];
    let hash = Hash(fixture.audited.output_slots[0].output_context.hash);
    let mut source = fixture.source().with_transactions(rows.clone());
    source.pages = HashMap::from([(None, paged(rows, None, Some(1)))]);
    let probe = source.clone();
    let before = fixture.hub(source.clone()).service(None).expect("service");
    before.backfill_utxos().await.expect("first run");
    assert!(history_through(&before).await > 0);

    let restarted = fixture.hub(source).service(None).expect("service");
    assert_eq!(
        history_through(&restarted).await,
        0,
        "the replay has not run"
    );
    restarted.backfill_utxos().await.expect("replay");
    assert!(history_through(&restarted).await > 0);
    assert_eq!(
        stored_amount(&restarted, &hash).await,
        stored_amount(&before, &hash).await
    );
    assert_eq!(cursors(&probe), [None, None]);
}

#[tokio::test]
async fn a_restart_over_a_store_resumes_at_the_durable_position_with_its_notes() {
    let fixture = Fixture::new();
    let rows = vec![fixture.audited.clone()];
    let hash = Hash(fixture.audited.output_slots[0].output_context.hash);
    let mut source = fixture.source().with_transactions(rows.clone());
    source.pages = HashMap::from([
        (None, paged(rows, None, Some(1))),
        (Some(vec![1]), paged(Vec::new(), None, Some(1))),
    ]);
    let probe = source.clone();
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let before = stored_hub(&fixture, source.clone(), store.clone())
        .service(None)
        .expect("service");
    before.backfill_utxos().await.expect("first run");
    let through = history_through(&before).await;
    assert_eq!(stored_amount(&before, &hash).await, Some(500));

    let restarted = stored_hub(&fixture, source, store)
        .service(None)
        .expect("service");
    restarted.backfill_utxos().await.expect("resume");
    assert_eq!(stored_amount(&restarted, &hash).await, Some(500));
    assert!(history_through(&restarted).await >= through);
    assert_ne!(
        cursors(&probe).last(),
        Some(&None),
        "the first page is not read again"
    );
}

fn stored_hub(fixture: &Fixture, source: StaticSource, store: Store) -> Hub<StaticSource> {
    Hub::builder(source, identity(GENESIS))
        .with_origins(origins())
        .with_store(store)
        .local(RING, fixture.auditor.clone())
        .expect("hub")
}

/// The audited note on the first of more pages than one pass reads.
fn durable_history(fixture: &Fixture) -> StaticSource {
    let mut source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone()]);
    source.pages = long_history(fixture, None, 1);
    source
        .pages
        .insert(None, paged(vec![fixture.audited.clone()], Some(1), None));
    source
}

#[derive(Debug, PartialEq)]
struct DurableCheckpoint {
    after_slot: Option<i64>,
    token: Option<String>,
    through_slot: i64,
}

async fn durable_checkpoint(store: &Store) -> DurableCheckpoint {
    let db = store.connection();
    let row = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            "SELECT after_slot,token,through_slot FROM spend_checkpoints",
        ))
        .await
        .expect("checkpoint read")
        .expect("checkpoint row");
    DurableCheckpoint {
        after_slot: row.try_get("", "after_slot").expect("after slot"),
        token: row.try_get("", "token").expect("token"),
        through_slot: row.try_get("", "through_slot").expect("through slot"),
    }
}

/// Two passes reach the terminal page, the restarted service reads the store next.
async fn restart_after_the_terminal_page(
    fixture: &Fixture,
    source: &StaticSource,
    store: &Store,
) -> AuditService<StaticSource> {
    let before = stored_hub(fixture, source.clone(), store.clone())
        .service(None)
        .expect("service");
    before.backfill_utxos().await.expect("capped pass");
    before.backfill_utxos().await.expect("terminal pass");
    stored_hub(fixture, source.clone(), store.clone())
        .service(None)
        .expect("service")
}

/// The retry loads the notes with history down, then resumes at the durable checkpoint.
async fn assert_the_retry_loads_the_tables(
    restarted: &AuditService<StaticSource>,
    source: &StaticSource,
    store: &Store,
) {
    let hash = Hash(source.transactions[0].output_slots[0].output_context.hash);
    let durable = durable_checkpoint(store).await;
    let reads = cursors(source).len();
    source.history_down.store(true, Ordering::Relaxed);
    assert!(restarted.backfill_utxos().await.is_err());
    assert_eq!(stored_amount(restarted, &hash).await, Some(500));

    source.history_down.store(false, Ordering::Relaxed);
    restarted.backfill_utxos().await.expect("resume");
    assert_eq!(durable_checkpoint(store).await, durable);
    assert!(
        !cursors(source)[reads..].contains(&None),
        "no read starts from the empty position"
    );
}

#[tokio::test]
async fn a_failed_table_read_loads_on_the_retry_and_keeps_the_checkpoint() {
    let fixture = Fixture::new();
    let source = durable_history(&fixture);
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let restarted = restart_after_the_terminal_page(&fixture, &source, &store).await;
    let rename = |from: &str, to: &str| format!("ALTER TABLE {from} RENAME TO {to}");
    let db = store.connection();
    db.execute_unprepared(&rename("spend_checkpoints", "parked_checkpoints"))
        .await
        .expect("park");
    assert!(restarted.backfill_utxos().await.is_err());
    db.execute_unprepared(&rename("parked_checkpoints", "spend_checkpoints"))
        .await
        .expect("restore");

    assert_the_retry_loads_the_tables(&restarted, &source, &store).await;
}

#[tokio::test]
async fn a_cancelled_table_read_loads_on_the_retry_and_keeps_the_checkpoint() {
    let fixture = Fixture::new();
    let source = durable_history(&fixture);
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let restarted = restart_after_the_terminal_page(&fixture, &source, &store).await;
    // The pool's one connection is the gate, the table read cannot pass it while held.
    let held = store.connection().begin().await.expect("hold");
    {
        let mut backfill = pin!(restarted.backfill_utxos());
        let first = poll_fn(|cx| Poll::Ready(backfill.as_mut().poll(cx))).await;
        assert!(first.is_pending(), "the table read waits at the gate");
    }
    held.rollback().await.expect("release");

    assert_the_retry_loads_the_tables(&restarted, &source, &store).await;
}

#[tokio::test]
async fn a_backfill_fills_the_store_before_any_page_read() {
    let fixture = Fixture::new();
    let utxos = SpentUtxo::new(&fixture);
    let mut source = utxos.source(
        &fixture,
        [
            (None, paged(vec![utxos.paid.clone()], Some(1), None)),
            (Some(vec![1]), paged(Vec::new(), None, Some(2))),
        ],
    );
    source.pages.insert(
        Some(vec![9]),
        paged(vec![utxos.spent.clone()], None, Some(10)),
    );
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let found = service
        .audited_utxos(&utxos_request(vec![utxos.commitment.into()]))
        .await
        .expect("UTXO read");
    let [Some(view)] = found.value.utxos.as_slice() else {
        panic!("the backfill opened the paid UTXO, {:?}", found.value.utxos);
    };
    assert_eq!(found.context.slot, 99);
    assert_eq!(
        (view.utxo.amount, view.utxo.owner_key.0.to_bytes()),
        (utxos.member.amount, utxos.member.owner_key)
    );
    assert_eq!(view.tx_signature.0, utxos.paid.tx_signature);
}

#[tokio::test]
async fn an_enrolled_key_names_a_note_and_another_key_names_none() {
    let fixture = Fixture::new();
    let owner = [0xb0; 32];
    let key = NullifierKey::from_secret([7; 31]);
    let (row, _) = KeyedNote {
        fixture: &fixture,
        seed: 91,
        note: sol(0xb0, 500),
        key: &key,
    }
    .delivered();
    let status = |source: StaticSource| {
        let fixture = &fixture;
        async move {
            let service = fixture.hub(source).service(None).expect("service");
            service.backfill_utxos().await.expect("backfill");
            let request = WalletStatusRequest::new(target(RING), Address::new_from_array(owner))
                .sign(&delegate())
                .expect("signed");
            service.wallet_status(&request).await.expect("status")
        }
    };
    let source = |row: &ShieldedTransaction| {
        let mut source = fixture.source().with_transactions(vec![row.clone()]);
        source.next_cursor = None;
        source
    };

    let unenrolled = status(source(&row)).await;
    assert_eq!(unenrolled.enrollment, WalletEnrollment::NotEnrolled);
    assert_eq!(unenrolled.notes[0].status, WalletNoteStatus::Unknown);
    assert!(unenrolled.balances.is_empty());

    let enrolled = source(&row);
    enrolled
        .tracking
        .enroll(&owner, &key, &fixture.auditor.pubkey());
    let read = status(enrolled).await;
    assert_eq!(read.enrollment, WalletEnrollment::Applied);
    assert_eq!(read.notes[0].status, WalletNoteStatus::Unspent);
    assert_eq!(read.balances[0].amount, 500);

    // An enrollment under another key derives no nullifier of the note, the note stays unknown.
    let forged = source(&row);
    forged.tracking.enroll(
        &owner,
        &NullifierKey::from_secret([8; 31]),
        &fixture.auditor.pubkey(),
    );
    let read = status(forged).await;
    assert_eq!(read.notes[0].status, WalletNoteStatus::Unknown);
}
