use sea_orm::{ConnectionTrait, Statement};

use super::{coverage_failures::coverage_request, *};

/// Signatures of the frames the coverage read still names unread.
async fn unread(service: &AuditService<StaticSource>) -> Vec<Signature> {
    service
        .spend_coverage(&coverage_request(&authority()))
        .await
        .expect("operator read")
        .unreadable
        .iter()
        .map(|frame| frame.tx_signature.0)
        .collect()
}

#[tokio::test]
async fn sixteen_failing_frames_do_not_hold_back_a_seventeenth() {
    let fixture = Fixture::new();
    // 1. Sixteen frames that never decode sit in slots below the one frame a later pass can read.
    let mut rows: Vec<ShieldedTransaction> = (0x60..0x70)
        .map(|seed| ShieldedTransaction {
            tx_signature: Signature::from([seed; 64]),
            ..fixture.audited.clone()
        })
        .collect();
    rows.push(fixture.audited.clone());
    let mut source = fixture.source().with_transactions(rows.clone());
    source.next_cursor = None;
    let undecodable = source.undecodable.clone();
    undecodable
        .lock()
        .unwrap()
        .extend(rows.iter().map(|row| row.tx_signature));
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let service = Hub::builder(source, identity(GENESIS))
        .with_origins(origins())
        .with_store(store.clone())
        .local(RING, fixture.auditor.clone())
        .expect("hub")
        .service(None)
        .expect("service");
    service.backfill_utxos().await.expect("forward pass");
    assert_eq!(unread(&service).await.len(), 17);

    // 2. The last frame becomes readable, the first repair pass spends its cap on the sixteen.
    undecodable
        .lock()
        .unwrap()
        .remove(&fixture.audited.tx_signature);
    service
        .backfill_utxos()
        .await
        .expect("a failed repair leaves the forward read running");
    assert!(unread(&service)
        .await
        .contains(&fixture.audited.tx_signature));

    // 3. Each failure backed off, the next pass reaches the seventeenth.
    service.backfill_utxos().await.expect("next pass");
    let left = unread(&service).await;
    assert_eq!(left.len(), 16);
    assert!(!left.contains(&fixture.audited.tx_signature));
    let attempts = store
        .connection()
        .query_one(Statement::from_string(
            store.connection().get_database_backend(),
            "SELECT COUNT(*) AS failed FROM spend_unread_frames WHERE attempts = 1",
        ))
        .await
        .expect("query")
        .expect("row");
    assert_eq!(attempts.try_get::<i64>("", "failed").expect("count"), 16);
}

#[tokio::test]
async fn a_repair_reads_its_frame_by_signature_while_the_history_is_down() {
    let fixture = Fixture::new();
    let mut source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone()]);
    source.next_cursor = None;
    let undecodable = source.undecodable.clone();
    undecodable
        .lock()
        .unwrap()
        .insert(fixture.audited.tx_signature);
    let (history_down, history_reads) = (source.history_down.clone(), source.history_reads.clone());
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("forward pass");
    assert_eq!(unread(&service).await, [fixture.audited.tx_signature]);

    undecodable.lock().unwrap().clear();
    history_down.store(true, Ordering::Relaxed);
    let reads = history_reads.load(Ordering::Relaxed);
    assert!(
        service.backfill_utxos().await.is_err(),
        "the forward read fails"
    );
    assert!(
        unread(&service).await.is_empty(),
        "the repair read the frame"
    );
    assert_eq!(
        history_reads.load(Ordering::Relaxed),
        reads + 1,
        "only the forward read asked for a page"
    );
}
