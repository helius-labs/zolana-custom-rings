use super::*;
use zolana_ring_client::rpc::{
    GetWalletStatusResponse, SpendCoverageAttestation, SpendCoverageRequest,
};

async fn status(service: &AuditService<StaticSource>, wallet: [u8; 32]) -> GetWalletStatusResponse {
    let request = WalletStatusRequest::new(target(RING), Address::new_from_array(wallet))
        .sign(&delegate())
        .expect("signed read");
    service.wallet_status(&request).await.expect("status read")
}

pub(super) fn coverage_request(
    signer: &Keypair,
) -> zolana_ring_client::rpc::GetSpendCoverageRequest {
    SpendCoverageRequest::new(SpendCoverageAttestation {
        target: target(RING),
        authority: signer.pubkey(),
        cursor: None,
    })
    .at(unix_now().expect("clock"))
    .sign(signer)
    .expect("signed coverage")
}

#[tokio::test]
async fn a_failed_config_read_moves_no_history_slot() {
    let fixture = Fixture::new();
    let mut source = fixture.source().with_transactions(Vec::new());
    source.next_cursor = None;
    let config_down = source.config_down.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("first pass");
    let first = status(&service, [0xb0; 32]).await.history_through;
    assert!(first > 0);

    config_down.store(true, Ordering::Relaxed);
    assert!(service.backfill_utxos().await.is_err());
    config_down.store(false, Ordering::Relaxed);
    assert_eq!(status(&service, [0xb0; 32]).await.history_through, first);
    service.backfill_utxos().await.expect("retry");
}

/// The gap lowers the slot for every wallet and names no transaction to any of them.
#[tokio::test]
async fn an_unreadable_frame_holds_the_history_slot_for_everyone_and_shows_only_on_the_operator_read(
) {
    let fixture = Fixture::new();
    let mut merge = fixture.audited.clone();
    merge.tx_signature = Signature::from([0x77; 64]);
    merge.tx_viewing_pk = None;
    merge.salt = None;
    merge.messages.clear();
    merge.output_slots.truncate(1);
    merge.output_slots[0].output_context.hash = field(0x77);
    merge.output_slots[0].payload.clear();
    merge.nullifiers = vec![field(0x78)];
    let confirmed = origin_fixture::event(&merge);
    merge.nullifiers[0] = field(0x79);
    let merge_signature = merge.tx_signature;
    let mut source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone(), merge]);
    source.next_cursor = None;
    source
        .confirmed_events
        .insert((merge_signature, 0), confirmed);
    let hub = Arc::new(fixture.hub(source));
    let service = hub.service(None).expect("service");
    service.backfill_utxos().await.expect("terminal pass");

    let coverage = service
        .spend_coverage(&coverage_request(&authority()))
        .await
        .expect("operator read");
    let [frame] = coverage.unreadable.as_slice() else {
        panic!("one unreadable frame, {:?}", coverage.unreadable);
    };
    assert_eq!(frame.tx_signature.0, merge_signature);
    let held = frame.slot - 1;
    assert_eq!(coverage.history_through, held);

    let read = status(&service, [0xb0; 32]).await;
    assert_eq!(read.history_through, held);
    let wire = serde_json::to_string(&read).expect("json");
    assert!(!wire.contains(&merge_signature.to_string()));
}

#[tokio::test]
async fn an_unauthorized_caller_is_refused_the_operator_read() {
    let fixture = Fixture::new();
    let source = fixture.source().with_transactions(Vec::new());
    let module = rpc_module(Arc::new(fixture.hub(source))).expect("module");
    let call = |request| {
        let module = module.clone();
        async move {
            module
                .call::<_, zolana_ring_client::rpc::GetSpendCoverageResponse>(
                    zolana_ring_client::rpc::GET_SPEND_COVERAGE,
                    as_object(request),
                )
                .await
        }
    };
    // A ring-wide reader holds no operator read.
    for signer in [delegate(), stranger()] {
        assert!(call(coverage_request(&signer)).await.is_err());
    }
    let mut changed = coverage_request(&authority());
    changed.cursor = Some(vec![1; 240].into());
    assert!(call(changed).await.is_err());
    call(coverage_request(&authority()))
        .await
        .expect("the authority reads it");
}
