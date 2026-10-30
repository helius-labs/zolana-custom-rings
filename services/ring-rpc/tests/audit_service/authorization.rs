use super::*;

#[tokio::test]
async fn only_granted_readers_with_the_configured_auditor_key_can_read() {
    let fixture = Fixture::new();
    let page = page();
    let service = fixture
        .hub(fixture.source())
        .service(None)
        .expect("service");
    for signer in [&delegate() as &dyn ReadSigner, &Passkey::new(46)] {
        let request = auth(signer);
        assert!(service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page,
                wallet: None,
            })
            .await
            .is_ok());
    }

    for signer in [&authority() as &dyn ReadSigner, &stranger()] {
        let request = auth(signer);
        assert!(matches!(
            service
                .read(AuditRead {
                    read: PagedRead::DecryptedTransactions,
                    auth: &request,
                    page: &page,
                    wallet: None,
                })
                .await,
            Err(RingRpcError::Unauthorized(Unauthorized::NotGranted))
        ));
    }

    let mut source = fixture.source();
    source.configs.insert(
        RING,
        RingConfiguration {
            auditor_pubkey: X25519Keypair::new().pubkey(),
            roles: custom_ring_interface::RingRoles {
                policy: authority().pubkey(),
                ..bytemuck::Zeroable::zeroed()
            },
            mode: RingMode::Confidential,
            delegate: None,
        },
    );
    let service = fixture.hub(source).service(None).expect("service");
    let request = auth(&delegate());
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page,
                wallet: None,
            })
            .await,
        Err(RingRpcError::Unauthorized(Unauthorized::AuditorKeyMismatch))
    ));
}

#[tokio::test]
async fn auditor_keys_are_released_to_the_ring_authorities_only() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.configs.clear();
    let hub = Arc::new(fixture.hub(source));
    let module = rpc_module(hub.clone()).expect("module");
    let request = signed_by(&deployer());
    let created: CreateAuditorKeyResponse = module
        .call(CREATE_AUDITOR_KEY, as_object(&request))
        .await
        .expect("deployer before config");
    assert_eq!(created.auditor_pubkey.as_key(), &fixture.auditor.pubkey());
    assert!(released(&created, &request));
    let replayed = signed_by(&deployer());
    assert!(!released(&created, &replayed));
    assert!(refused(
        authorize(&hub, &signed_by(&authority())).await,
        Unauthorized::NotRingAuthority
    ));

    let hub = fixture.hub(fixture.source());
    authorize(&hub, &signed_by(&authority()))
        .await
        .expect("config authority");
    for signer in [deployer(), stranger(), delegate()] {
        assert!(refused(
            authorize(&hub, &signed_by(&signer)).await,
            Unauthorized::NotRingAuthority
        ));
    }

    let mut immutable = fixture.source();
    immutable.configs.clear();
    immutable.upgrade_authorities.clear();
    let hub = fixture.hub(immutable);
    assert!(refused(
        authorize(&hub, &signed_by(&deployer())).await,
        Unauthorized::NotRingAuthority
    ));
}

#[tokio::test]
async fn an_unsigned_auditor_key_request_is_refused() {
    let fixture = Fixture::new();
    let hub = fixture.hub(fixture.source());
    let mut blank = signed_by(&authority());
    blank.auth.signature = vec![0; 64].into();
    assert!(refused(
        authorize(&hub, &blank).await,
        Unauthorized::BadSignature
    ));
}

#[tokio::test]
async fn auditor_key_requests_bind_cluster_ring_time_and_nonce() {
    let fixture = Fixture::new();
    let hub = fixture.hub(fixture.source());

    let other_cluster = CreateAuditorKeyRequest::for_ring(RING, [10; 32])
        .sign(&authority())
        .expect("signed request");
    assert!(refused(
        authorize(&hub, &other_cluster).await,
        Unauthorized::ClusterMismatch
    ));

    let mut relabelled = other_cluster;
    relabelled.auth.genesis_hash = Hash(GENESIS);
    assert!(refused(
        authorize(&hub, &relabelled).await,
        Unauthorized::BadSignature
    ));

    let other_ring = CreateAuditorKeyRequest::for_ring(OTHER_RING, GENESIS)
        .sign(&authority())
        .expect("signed request");
    assert!(refused(
        authorize(&hub, &other_ring).await,
        Unauthorized::BadSignature
    ));

    let mut forged = signed_by(&stranger());
    forged.auth.authority = authority().pubkey().to_bytes().into();
    assert!(refused(
        authorize(&hub, &forged).await,
        Unauthorized::BadSignature
    ));

    let mut shifted = signed_by(&authority());
    shifted.auth.timestamp += 1;
    assert!(refused(
        authorize(&hub, &shifted).await,
        Unauthorized::BadSignature
    ));

    let request = signed_by(&authority());
    authorize(&hub, &request).await.expect("first use");
    assert!(refused(
        authorize(&hub, &request).await,
        Unauthorized::Replay
    ));
}

#[tokio::test]
async fn auditor_key_requests_are_accepted_exactly_within_the_skew_window() {
    let fixture = Fixture::new();
    let now = 1_000_000_000;
    let hub = fixture.hub_at(fixture.source(), now);

    for timestamp in [now - AUTH_SKEW.as_secs() - 1, now + AUTH_SKEW.as_secs() + 1] {
        let outside = CreateAuditorKeyRequest::for_ring(RING, GENESIS)
            .at(timestamp)
            .sign(&authority())
            .expect("signed request");
        assert!(refused(
            authorize(&hub, &outside).await,
            Unauthorized::StaleTimestamp
        ));
    }

    for timestamp in [now - AUTH_SKEW.as_secs(), now + AUTH_SKEW.as_secs()] {
        let boundary = CreateAuditorKeyRequest::for_ring(RING, GENESIS)
            .at(timestamp)
            .sign(&authority())
            .expect("signed request");
        authorize(&hub, &boundary).await.expect("boundary request");
    }
}

#[tokio::test]
async fn invalid_audit_requests_do_not_consume_valid_capacity() {
    let fixture = Fixture::new();
    let module = rpc_module(Arc::new(fixture.hub(fixture.source()))).expect("module");

    let mut request = signed_request(&delegate(), target(RING), unix_now().expect("clock"));
    request.auth.timestamp += 1;
    let result: Result<GetDecryptedTransactionsResponse, _> = module
        .call(GET_DECRYPTED_TRANSACTIONS, as_object(request))
        .await;
    assert!(result.is_err());

    let response: GetDecryptedTransactionsResponse = module
        .call(
            GET_DECRYPTED_TRANSACTIONS,
            as_object(signed_request(
                &delegate(),
                target(RING),
                unix_now().expect("clock"),
            )),
        )
        .await
        .expect("valid request");
    assert_eq!(response.value.items.len(), 1);
}

/// A ring registered with a key this instance did not derive stays closed, and
/// says so before anything is decrypted.
#[tokio::test]
async fn a_ring_registered_with_another_auditor_stays_closed() {
    let fixture = Fixture::new();
    let ring = Address::new_from_array([3; 32]);
    let uninitialized = Address::new_from_array([4; 32]);
    let mut source = fixture.source();
    source.configs = HashMap::from([(
        ring,
        RingConfiguration {
            auditor_pubkey: fixture.auditor.pubkey(),
            roles: custom_ring_interface::RingRoles {
                policy: authority().pubkey(),
                ..bytemuck::Zeroable::zeroed()
            },
            mode: RingMode::Confidential,
            delegate: None,
        },
    )]);
    let hub = Hub::builder(source, GENESIS)
        .with_origins(origins())
        .derived(RootSecret::from_bytes([7; 32]).expect("root"))
        .expect("hub");
    let service = hub.service(Some(ring)).expect("service");
    assert_ne!(service.auditor_pubkey(), fixture.auditor.pubkey());

    assert_eq!(
        service.configured_auditor().await.expect("status"),
        Some(fixture.auditor.pubkey())
    );
    assert_eq!(
        hub.service(Some(uninitialized))
            .expect("service")
            .configured_auditor()
            .await
            .expect("status"),
        None
    );

    let request = signed_request(&delegate(), served(&hub, ring), unix_now().expect("clock")).auth;
    let page = page();
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page,
                wallet: None,
            })
            .await,
        Err(RingRpcError::Unauthorized(Unauthorized::AuditorKeyMismatch))
    ));
}

#[tokio::test]
async fn derived_keys_are_ring_and_cluster_specific() {
    let fixture = Fixture::new();
    let root_bytes = [7; 32];
    let root = RootSecret::from_bytes(root_bytes).expect("root");
    let derivation_root = RootSecret::from_bytes(root_bytes).expect("root");
    let genesis_hash = [9; 32];
    let ring_a = Address::new_from_array([1; 32]);
    let ring_b = Address::new_from_array([2; 32]);
    let mut source = fixture.source();
    source
        .upgrade_authorities
        .insert(ring_a, deployer().pubkey());
    let hub = Hub::builder(source, genesis_hash)
        .derived(root)
        .expect("hub");
    let key_a = hub.service(Some(ring_a)).expect("ring a").auditor_pubkey();
    let key_b = hub.service(Some(ring_b)).expect("ring b").auditor_pubkey();
    let other_genesis = Hub::builder(fixture.source(), [10; 32])
        .derived(RootSecret::from_bytes(root_bytes).expect("root"))
        .expect("hub");
    assert_ne!(
        other_genesis
            .service(Some(ring_a))
            .expect("ring a")
            .auditor_pubkey(),
        key_a
    );
    assert_eq!(
        hub.service_pubkey().to_string(),
        "FQ7ZZ4DEkoubT5Ca9BzzbgXDTmjKdRh6a3snGfPjpEZT"
    );
    assert_eq!(
        hex::encode(key_a.as_bytes()),
        "046ac65f6fa828249939ac012a53b665c474fadedc018f71010fb7fcf4b5585248"
    );
    assert_ne!(key_a, key_b);
    let second = Hub::builder(fixture.source(), genesis_hash)
        .derived(derivation_root)
        .expect("hub");
    assert_eq!(
        second
            .service(Some(ring_a))
            .expect("ring a")
            .auditor_pubkey(),
        key_a
    );
    assert!(matches!(hub.service(None), Err(RingRpcError::RingRequired)));

    let module = rpc_module(Arc::new(hub)).expect("module");
    let health: HealthResponse = module.call(HEALTH, [(); 0]).await.expect("health");
    assert_eq!(health.mode, KeyMode::Derived);
    let request = CreateAuditorKeyRequest::for_ring(ring_a, genesis_hash)
        .sign(&deployer())
        .expect("signed request");
    let created: CreateAuditorKeyResponse = module
        .call(CREATE_AUDITOR_KEY, as_object(&request))
        .await
        .expect("auditor key");
    assert_eq!(created.auditor_pubkey.as_key(), &key_a);
    assert!(released(&created, &request));
    let mut other_cluster = request;
    other_cluster.auth.genesis_hash = Hash([10; 32]);
    assert!(!released(&created, &other_cluster));
}

#[tokio::test]
async fn a_read_signed_for_another_method_cluster_or_service_is_refused() {
    let fixture = Fixture::new();
    let service = fixture
        .hub(fixture.source())
        .service(None)
        .expect("service");
    let page = page();
    let signed = |read: PagedRead, target: ReadTarget| {
        read.request(target)
            .sign(&delegate())
            .expect("request")
            .auth
    };
    let refused = [
        signed(PagedRead::AuditedMerges, target(RING)),
        signed(
            PagedRead::DecryptedTransactions,
            ReadTarget {
                cluster: [8; 32],
                ..target(RING)
            },
        ),
        signed(
            PagedRead::DecryptedTransactions,
            ReadTarget {
                service: Address::new_from_array([3; 32]),
                ..target(RING)
            },
        ),
    ];
    for auth in &refused {
        assert!(matches!(
            service
                .read(AuditRead {
                    read: PagedRead::DecryptedTransactions,
                    auth,
                    page: &page,
                    wallet: None,
                })
                .await,
            Err(RingRpcError::Unauthorized(Unauthorized::BadSignature))
        ));
    }
    let valid = signed(PagedRead::DecryptedTransactions, target(RING));
    service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &valid,
            page: &page,
            wallet: None,
        })
        .await
        .expect("read");
}
