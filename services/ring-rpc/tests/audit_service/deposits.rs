use super::*;

/// The limit counts signatures examined, so a page can hold fewer deposits
/// than the limit and still carry a cursor over older history.
#[tokio::test]
async fn deposit_pages_walk_the_whole_ring_history() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.history = vec![
        examined(21, 30, vec![deposit(21, 30, 500)]),
        examined(22, 20, Vec::new()),
        examined(23, 10, vec![deposit(23, 10, 7)]),
    ];
    let module = rpc_module(Arc::new(fixture.hub(source))).expect("module");

    let first: RingDepositsResponse = module
        .call(RING_DEPOSITS, as_object(deposits_request(Some(2), None)))
        .await
        .expect("first page");
    let wire = as_object(&first);
    assert!(wire.contains_key("oldestSlot"));
    assert!(wire.contains_key("cursor"));
    assert_eq!(first.deposits.len(), 1);
    assert_eq!(first.deposits[0].amount, 500);
    assert_eq!(first.oldest_slot, Some(20));
    let cursor = first.cursor.clone().expect("older history");
    assert_eq!(
        cursor,
        Base64String(Signature::from([22; 64]).as_ref().to_vec())
    );

    let second: RingDepositsResponse = module
        .call(
            RING_DEPOSITS,
            as_object(deposits_request(Some(2), Some(cursor))),
        )
        .await
        .expect("second page");
    assert_eq!(second.deposits.len(), 1);
    assert_eq!(second.deposits[0].amount, 7);
    assert_eq!(second.oldest_slot, Some(10));
    assert_eq!(second.cursor, None);
    assert!(!as_object(&second).contains_key("cursor"));
}

/// A page over signatures that made no deposit reports how far back it
/// reached, which the cursor alone does not say.
#[tokio::test]
async fn a_deposit_page_without_deposits_reports_its_frontier() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.history = vec![examined(24, 40, Vec::new()), examined(25, 30, Vec::new())];
    let module = rpc_module(Arc::new(fixture.hub(source))).expect("module");

    let page: RingDepositsResponse = module
        .call(RING_DEPOSITS, as_object(deposits_request(Some(1), None)))
        .await
        .expect("page");
    assert!(page.deposits.is_empty());
    assert_eq!(page.oldest_slot, Some(40));
    assert_eq!(
        page.cursor,
        Some(Base64String(Signature::from([24; 64]).as_ref().to_vec()))
    );
}

#[tokio::test]
async fn deposit_pages_clamp_the_examined_limit_and_reject_bad_cursors() {
    let fixture = Fixture::new();

    for (limit, expected) in [(None, 50), (Some(7), 7), (Some(500), 200)] {
        let source = fixture.source();
        let examined_limit = source.examined_limit.clone();
        let module = rpc_module(Arc::new(fixture.hub(source))).expect("module");
        let page: RingDepositsResponse = module
            .call(RING_DEPOSITS, as_object(deposits_request(limit, None)))
            .await
            .expect("page");
        assert_eq!(examined_limit.load(Ordering::Relaxed), expected);
        assert!(page.deposits.is_empty());
        assert_eq!(page.cursor, None);
        assert_eq!(page.oldest_slot, None);
    }

    let module = rpc_module(Arc::new(fixture.hub(fixture.source()))).expect("module");
    let result: Result<RingDepositsResponse, _> = module
        .call(
            RING_DEPOSITS,
            as_object(deposits_request(None, Some(Base64String(vec![1, 2, 3])))),
        )
        .await;
    assert!(result.is_err());
}

/// The state a ring is in decides whether `init` may pin a key, so it travels
/// over the wire for every ring the caller names.
#[tokio::test]
async fn ring_status_reports_the_state_of_each_ring() {
    let fixture = Fixture::new();
    let served = Address::new_from_array([1; 32]);
    let foreign = Address::new_from_array([3; 32]);
    let uninitialized = Address::new_from_array([4; 32]);
    let mut source = fixture.source();
    source.configs = HashMap::from([(
        foreign,
        RingConfiguration {
            auditor_pubkey: fixture.auditor.pubkey(),
            authority: authority().pubkey(),
            mode: RingMode::Confidential,
            delegate: None,
        },
    )]);
    let hub = Arc::new(
        Hub::builder(source, GENESIS)
            .with_origins(origins())
            .derived(RootSecret::from_bytes([7; 32]).expect("root"))
            .expect("hub"),
    );
    let derived = hub.service(Some(served)).expect("service").auditor_pubkey();
    let chain = RingChainStatus {
        activation: Some(RingActivation {
            activated: true,
            paused: false,
        }),
        registry: Some(RegistryStatus {
            history: vec![
                Some(RegistryRoot {
                    root: Hash([1; 32]),
                    applied: 3,
                    slot: 40,
                }),
                None,
            ],
            history_cursor: 0,
            next_index: 3,
            floor: 3,
            prior_floor: 0,
            floor_slot: 40,
            queue_head: 3,
            queue_tail: 5,
        }),
    };
    let mut source = fixture.source();
    source.chain = HashMap::from([(served, chain.clone())]);
    source.configs = HashMap::from([
        (
            served,
            RingConfiguration {
                auditor_pubkey: derived,
                authority: authority().pubkey(),
                mode: RingMode::Confidential,
                delegate: None,
            },
        ),
        (
            foreign,
            RingConfiguration {
                auditor_pubkey: fixture.auditor.pubkey(),
                authority: authority().pubkey(),
                mode: RingMode::Confidential,
                delegate: None,
            },
        ),
    ]);
    let module = rpc_module(Arc::new(
        Hub::builder(source, GENESIS)
            .with_origins(origins())
            .derived(RootSecret::from_bytes([7; 32]).expect("root"))
            .expect("hub"),
    ))
    .expect("module");

    for (ring, state) in [
        (served, RingState::Served),
        (foreign, RingState::ForeignAuditor),
        (uninitialized, RingState::Uninitialized),
    ] {
        let status: RingStatusResponse = module
            .call(
                RING_STATUS,
                as_object(RingStatusRequest {
                    ring_program_id: ring.to_bytes().into(),
                }),
            )
            .await
            .expect("status");
        assert_eq!(status.state, state);
        assert_eq!(status.ring_program_id.0, ring);
        assert_eq!(status.service_pubkey.0, hub.service_pubkey());
        let expected = match ring == served {
            true => chain.clone(),
            false => RingChainStatus::default(),
        };
        assert_eq!(
            (status.activation, status.registry),
            (expected.activation, expected.registry)
        );
    }

    let object = as_object(RingStatusRequest {
        ring_program_id: served.to_bytes().into(),
    });
    assert!(object.contains_key("ringProgramId"));
    let raw: serde_json::Value = module.call(RING_STATUS, object).await.expect("status");
    assert_eq!(raw.get("state"), Some(&serde_json::json!("served")));
    assert!(raw.get("auditorPubkey").is_none());
    assert!(raw.get("auditorViewTag").is_none());
    assert!(raw.get("configAuditorPubkey").is_some());
    assert_eq!(
        raw.get("activation"),
        Some(&serde_json::json!({ "activated": true, "paused": false }))
    );
    let raw: serde_json::Value = module
        .call(
            RING_STATUS,
            as_object(RingStatusRequest {
                ring_program_id: uninitialized.to_bytes().into(),
            }),
        )
        .await
        .expect("status");
    assert!(raw.get("activation").is_none());
    assert!(raw.get("registry").is_none());
}
