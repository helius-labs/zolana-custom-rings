use super::*;

#[tokio::test]
async fn granted_reader_opens_audited_transfers_and_reports_the_rest() {
    let fixture = Fixture::new();
    let service = fixture
        .hub(fixture.source())
        .service(None)
        .expect("service");
    let page = page();
    let request = auth(&delegate());
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request,
            page: &page,
            wallet: None,
        })
        .await
        .expect("read");

    assert_eq!(response.context.slot, 99);
    assert_eq!(response.value.cursor, Some(Base64String(vec![7, 7])));
    let [item] = response.value.items.as_slice() else {
        panic!("expected one audited transaction");
    };
    assert_eq!(amounts(item), [500, 7]);
    for output in &item.outputs {
        let mint = output.utxo.as_ref().and_then(|utxo| utxo.mint.as_ref());
        assert_eq!(mint.map(|mint| mint.0), Some(SOL_MINT));
        // The published owner tag, nothing recovered from the recipient's ciphertext.
        assert_eq!(output.recipient_u, Some(Hash(fixture.recipient_u)));
    }
    assert_eq!(item.signers, vec![SENDER.to_bytes().into()]);
    assert_eq!(
        item.withdrawals,
        vec![
            DecryptedWithdrawal {
                screened_owner: None,
                recipient: RECIPIENT.to_bytes().into(),
                asset: SOL_MINT.to_bytes().into(),
                amount: WITHDRAWN,
            },
            DecryptedWithdrawal {
                screened_owner: None,
                recipient: TOKEN_ACCOUNT.to_bytes().into(),
                asset: MINT.to_bytes().into(),
                amount: SPL_WITHDRAWN,
            }
        ]
    );
    assert_eq!(item.nullifiers.len(), 1);
    let reasons: Vec<(Signature, SkippedReason)> = response
        .value
        .skipped
        .iter()
        .map(|skipped| (skipped.tx_signature.0, skipped.reason))
        .collect();
    assert_eq!(
        reasons,
        vec![
            (
                fixture.foreign_key.tx_signature,
                SkippedReason::InvalidAuditData
            ),
            (
                fixture.missing_message.tx_signature,
                SkippedReason::MissingAuditorMessage
            ),
        ]
    );
}

#[tokio::test]
async fn a_terminal_indexer_page_has_no_next_audit_cursor() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.scanned_through = Some(vec![9, 9]);
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let request = auth(&delegate());
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request,
            page: &page,
            wallet: None,
        })
        .await
        .expect("read");

    assert_eq!(response.value.items.len(), 1);
    assert_eq!(response.value.cursor, None);
}

#[tokio::test]
async fn events_in_one_signature_keep_distinct_ordinals() {
    let fixture = Fixture::new();
    let mut second = fixture.audited.clone();
    second.event_index = Some(1);
    let source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone(), second]);
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let request = auth(&delegate());
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request,
            page: &page,
            wallet: None,
        })
        .await
        .expect("read");

    assert_eq!(response.value.items.len(), 2);
    assert_eq!(
        response.value.items[0].tx_signature,
        response.value.items[1].tx_signature
    );
    assert_eq!(response.value.items[0].event_index, 0);
    assert_eq!(response.value.items[1].event_index, 1);
}

#[tokio::test]
async fn passkey_reader_opens_anonymous_spend_trace() {
    let fixture = Fixture::new();
    let mut transfer = ring_transfer(70);
    transfer.nullifiers.push(field(0x71));
    let sender = Spend {
        utxo: sol(0xa1, 900),
        blinding: field(0x60),
    };
    let tag = field(0x53);
    let outputs = [
        Output::Ring {
            utxo: sol(0xb5, 500),
            recipient_u: x25519_u(0x50),
            tag: Some(field(0x51)),
        },
        Output::Ring {
            utxo: sol(0xb6, 501),
            recipient_u: x25519_u(0x52),
            tag: Some(tag),
        },
    ];
    let tx = Indexed {
        transfer: &transfer,
        outputs: &outputs,
        auditor: &fixture.auditor.pubkey(),
        signature: 70,
        frames: &fixture.frames,
    }
    .anonymous(&[Some(sender), None]);
    let mut source = fixture.source().with_transactions(vec![tx]);
    source.configs.get_mut(&RING).expect("config").mode = RingMode::Anonymous;
    let module = rpc_module(Arc::new(fixture.hub(source))).expect("module");
    let response: GetDecryptedTransactionsResponse = module
        .call(
            GET_DECRYPTED_TRANSACTIONS,
            as_object(signed_request(
                &Passkey::new(46),
                target(RING),
                unix_now().expect("clock"),
            )),
        )
        .await
        .expect("passkey read");
    let [item] = response.value.items.as_slice() else {
        panic!("anonymous transaction must be readable")
    };
    assert_eq!(
        item.sender,
        Some(DecryptedSender {
            owner_key: sender.utxo.owner_key.into(),
            nullifier_pk: Some(sender.utxo.nullifier_pk.into()),
        })
    );
    let [spent, dummy] = item.inputs.as_slice() else {
        panic!("one input per published nullifier")
    };
    assert_eq!(
        spent.opening.as_ref().map(|opening| opening.amount),
        Some(900)
    );
    assert_eq!(dummy.opening, None);
    assert_eq!(amounts(item), [500, 501]);
    assert_eq!(item.outputs[1].tag, Some(Hash(tag)));
    assert!(item.payload_errors.is_empty());
    assert!(response.value.skipped.is_empty());
}

#[tokio::test]
async fn an_input_spending_a_utxo_the_page_opened_resolves_its_ring() {
    let fixture = Fixture::new();
    let utxos = SpentUtxo::new(&fixture);
    let opened = Some(DecryptedInputRing::Ring {
        commitment: utxos.commitment.into(),
    });
    let page = fixture
        .read_anonymous(vec![utxos.paid.clone(), utxos.spent.clone()])
        .await;
    assert_eq!(input_ring(&page), opened);
    // A ring output carries no ring data, the entry opening rebuilds the commitment the page opened.
    assert_eq!(
        input_ring(
            &fixture
                .read_anonymous(vec![utxos.paid.clone(), utxos.entry.clone()])
                .await
        ),
        opened
    );
    // The entry key opens the input itself, only its ring stays open.
    assert!(matches!(
        input_ring(&fixture.read_anonymous(vec![utxos.entry.clone()]).await),
        Some(DecryptedInputRing::Unresolved { .. })
    ));
    let alone = fixture.read_anonymous(vec![utxos.spent.clone()]).await;
    assert!(alone.value.items.is_empty());
    let reasons: Vec<SkippedReason> = alone
        .value
        .skipped
        .iter()
        .map(|skipped| skipped.reason)
        .collect();
    assert_eq!(reasons, [SkippedReason::UnseenInput]);
}

#[tokio::test]
async fn an_input_whose_utxo_an_earlier_page_opened_resolves_through_the_store() {
    let fixture = Fixture::new();
    let utxos = SpentUtxo::new(&fixture);
    let source = utxos.source(
        &fixture,
        [
            (None, paged(vec![utxos.paid.clone()], Some(1), None)),
            (
                Some(vec![1]),
                paged(vec![utxos.spent.clone()], None, Some(2)),
            ),
        ],
    );
    let service = fixture.hub(source).service(None).expect("service");
    read_at(&service, None).await;
    assert_eq!(
        input_ring(&read_at(&service, Some(1)).await),
        Some(DecryptedInputRing::Ring {
            commitment: utxos.commitment.into(),
        })
    );
}

#[tokio::test]
async fn rows_outside_the_ring_are_dropped() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source
        .origins
        .insert((fixture.audited.tx_signature, 0), false);
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let request = auth(&delegate());
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request,
            page: &page,
            wallet: None,
        })
        .await
        .expect("read");
    assert!(response.value.items.is_empty());
    assert_eq!(response.value.skipped.len(), 2);
    assert_eq!(response.value.cursor, Some(Base64String(vec![7, 7])));
}

#[tokio::test]
async fn origin_cache_separates_event_ordinals_in_one_transaction() {
    let fixture = Fixture::new();
    let first = fixture.audited.clone();
    let mut second = first.clone();
    second.event_index = Some(1);
    let signature = first.tx_signature;
    let mut source = fixture.source();
    source.transactions = vec![first, second];
    source.origins = HashMap::from([((signature, 0), true), ((signature, 1), false)]);
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let request = auth(&delegate());
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request,
            page: &page,
            wallet: None,
        })
        .await
        .expect("read");

    assert_eq!(response.value.items.len(), 1);
}

#[tokio::test]
async fn missing_event_index_fails_closed() {
    let fixture = Fixture::new();
    let mut transaction = fixture.audited.clone();
    transaction.event_index = None;
    let mut source = fixture.source();
    source.transactions = vec![transaction];
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
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
        Err(RingRpcError::InvalidIndexerResponse)
    ));
}

#[tokio::test]
async fn unknown_origins_fail_the_page() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.origins.remove(&(fixture.audited.tx_signature, 0));
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
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
        Err(RingRpcError::Origin(AuditError::Unavailable { .. }))
    ));
}

#[tokio::test]
async fn accepted_nonces_are_single_use() {
    let fixture = Fixture::new();
    let service = fixture
        .hub(fixture.source())
        .service(None)
        .expect("service");
    let page = page();
    let request = auth(&delegate());
    assert!(service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request,
            page: &page,
            wallet: None,
        })
        .await
        .is_ok());
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page,
                wallet: None,
            })
            .await,
        Err(RingRpcError::Unauthorized(Unauthorized::Replay))
    ));
    let distinct = auth(&delegate());
    assert!(service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &distinct,
            page: &page,
            wallet: None,
        })
        .await
        .is_ok());
}

#[tokio::test]
async fn indexer_pages_must_match_the_attested_bounds() {
    let fixture = Fixture::new();
    let signer = delegate();

    let source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone(); 101]);
    let service = fixture.hub(source).service(None).expect("service");
    let request = auth(&signer);
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page(),
                wallet: None,
            })
            .await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));

    for cursor in [Vec::new(), vec![1; 257]] {
        let mut source = fixture.source();
        source.next_cursor = Some(cursor);
        let service = fixture.hub(source).service(None).expect("service");
        let request = auth(&signer);
        assert!(matches!(
            service
                .read(AuditRead {
                    read: PagedRead::DecryptedTransactions,
                    auth: &request,
                    page: &page(),
                    wallet: None,
                })
                .await,
            Err(RingRpcError::InvalidIndexerResponse)
        ));
    }

    for (transactions, scanned_through) in [
        (vec![fixture.audited.clone()], Vec::new()),
        (vec![fixture.audited.clone(); 100], vec![9]),
    ] {
        let mut source = fixture.source().with_transactions(transactions);
        source.scanned_through = Some(scanned_through);
        let service = fixture.hub(source).service(None).expect("service");
        let request = auth(&signer);
        assert!(matches!(
            service
                .read(AuditRead {
                    read: PagedRead::DecryptedTransactions,
                    auth: &request,
                    page: &page(),
                    wallet: None,
                })
                .await,
            Err(RingRpcError::InvalidIndexerResponse)
        ));
    }

    let mut source = fixture.source();
    source.next_cursor = None;
    let service = fixture.hub(source).service(None).expect("service");
    let request = auth(&signer);
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page(),
                wallet: None,
            })
            .await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));

    let mut source = fixture.source();
    source.next_cursor = Some(vec![8]);
    let service = fixture.hub(source).service(None).expect("service");
    let repeated_page = Page::new(Some(vec![8].into()), None).expect("page");
    let request = GetDecryptedTransactionsRequest::read(target(RING))
        .with_cursor(vec![8].into())
        .expect("cursor")
        .sign(&signer)
        .expect("request")
        .auth;
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &repeated_page,
                wallet: None,
            })
            .await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));

    let mut source = fixture.source();
    source.transactions[0].nullifiers.push([2; 32]);
    source.transactions[0].output_slots = vec![source.transactions[0].output_slots[0].clone(); 17];
    let service = fixture.hub(source).service(None).expect("service");
    let request = auth(&signer);
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page(),
                wallet: None,
            })
            .await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));
}

#[tokio::test]
async fn rpc_wire_uses_camel_case_and_rejects_another_local_ring() {
    let fixture = Fixture::new();
    let module = rpc_module(Arc::new(fixture.hub(fixture.source()))).expect("module");
    let health: HealthResponse = module.call(HEALTH, [(); 0]).await.expect("health");
    assert_eq!(health.mode, KeyMode::Local);

    let request = GetDecryptedTransactionsRequest::read(target(RING))
        .sign(&delegate())
        .expect("request");
    let object = as_object(request);
    assert!(object.contains_key("ringProgramId"));
    let page: GetDecryptedTransactionsResponse = module
        .call(GET_DECRYPTED_TRANSACTIONS, object)
        .await
        .expect("read");
    assert_eq!(page.value.items.len(), 1);
    let merges: GetAuditedMergesResponse = module
        .call(
            GET_AUDITED_MERGES,
            as_object(
                PagedRead::AuditedMerges
                    .request(target(RING))
                    .sign(&delegate())
                    .expect("merge read request"),
            ),
        )
        .await
        .expect("merge read");
    assert!(merges.value.opened.is_empty());
    assert!(merges.value.unresolved.is_empty());
    let item = as_object(&page.value.items[0]);
    assert_eq!(
        item.get("withdrawals"),
        Some(&serde_json::json!([
            {
                "recipient": RECIPIENT.to_string(),
                "asset": SOL_MINT.to_string(),
                "amount": WITHDRAWN,
            },
            {
                "recipient": TOKEN_ACCOUNT.to_string(),
                "asset": MINT.to_string(),
                "amount": SPL_WITHDRAWN,
            }
        ]))
    );

    let other_ring = CreateAuditorKeyRequest::for_ring(OTHER_RING, GENESIS)
        .sign(&authority())
        .expect("signed request");
    let result: Result<CreateAuditorKeyResponse, _> =
        module.call(CREATE_AUDITOR_KEY, as_object(other_ring)).await;
    assert!(result.is_err());
}

/// One instance, two rings: each read must use its own derived key, its own
/// view tag and its own config.
#[tokio::test]
async fn two_rings_read_only_their_own_transactions() {
    let fixture = Fixture::new();
    let hub_of = |source: StaticSource| {
        Hub::builder(source, GENESIS)
            .with_origins(origins())
            .derived(RootSecret::from_bytes([7; 32]).expect("root"))
            .expect("hub")
    };
    let probe = hub_of(fixture.source());
    let ring_a = Address::new_from_array([1; 32]);
    let ring_b = Address::new_from_array([2; 32]);
    let key_a = probe
        .service(Some(ring_a))
        .expect("ring a")
        .auditor_pubkey();
    let key_b = probe
        .service(Some(ring_b))
        .expect("ring b")
        .auditor_pubkey();
    assert_ne!(key_a, key_b);

    let audited_a = Indexed {
        transfer: &Transfer {
            ring: ring_a,
            ..ring_transfer(11)
        },
        outputs: &[paid(sol(0xb0, 500), fixture.recipient_u)],
        auditor: &key_a,
        signature: 11,
        frames: &fixture.frames,
    }
    .delivered();
    let audited_b = Indexed {
        transfer: &Transfer {
            ring: ring_b,
            ..ring_transfer(12)
        },
        outputs: &[paid(sol(0xb0, 7), fixture.recipient_u)],
        auditor: &key_b,
        signature: 12,
        frames: &fixture.frames,
    }
    .delivered();
    let mut source = fixture.source();
    source.origins = HashMap::from([
        ((audited_a.tx_signature, 0), true),
        ((audited_b.tx_signature, 0), true),
    ]);
    source.transactions = Vec::new();
    source.by_tag = HashMap::from([
        (auditor_view_tag(&key_a), vec![audited_a.clone()]),
        (auditor_view_tag(&key_b), vec![audited_b.clone()]),
    ]);
    source.configs = HashMap::from([
        (
            ring_a,
            RingConfiguration {
                auditor_pubkey: key_a,
                roles: custom_ring_interface::RingRoles {
                    policy: authority().pubkey(),
                    ..bytemuck::Zeroable::zeroed()
                },
                mode: RingMode::Confidential,
                delegate: None,
            },
        ),
        (
            ring_b,
            RingConfiguration {
                auditor_pubkey: key_b,
                roles: custom_ring_interface::RingRoles {
                    policy: authority().pubkey(),
                    ..bytemuck::Zeroable::zeroed()
                },
                mode: RingMode::Confidential,
                delegate: None,
            },
        ),
    ]);
    let hub = hub_of(source);
    let page = page();

    for (ring, expected, amount) in [
        (ring_a, audited_a.tx_signature, 500),
        (ring_b, audited_b.tx_signature, 7),
    ] {
        let request =
            signed_request(&delegate(), served(&hub, ring), unix_now().expect("clock")).auth;
        let response = hub
            .service(Some(ring))
            .expect("service")
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page,
                wallet: None,
            })
            .await
            .expect("read");
        let [item] = response.value.items.as_slice() else {
            panic!("expected one audited transaction for {ring}");
        };
        assert_eq!(item.tx_signature.0, expected);
        assert_eq!(amounts(item), [amount]);
    }
}

#[tokio::test]
async fn an_indexer_forgery_is_reported_without_hiding_other_verified_outputs() {
    let fixture = Fixture::new();
    let confirmed = fixture.audited.clone();
    let mut forged = confirmed.clone();
    forged.output_slots[0].output_context.leaf_index += 1;
    let mut valid = confirmed.clone();
    valid.tx_signature = Signature::from([44; 64]);
    let frame = fixture.frames.lock().unwrap()[&confirmed.tx_signature].clone();
    fixture
        .frames
        .lock()
        .unwrap()
        .insert(valid.tx_signature, frame);
    let mut source = fixture.source().with_transactions(vec![forged, valid]);
    source.confirmed_events.insert(
        (confirmed.tx_signature, confirmed.event_index.unwrap()),
        origin_fixture::event(&confirmed),
    );
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
    assert_eq!(response.value.skipped.len(), 1);
    assert_eq!(
        response.value.skipped[0].reason,
        zolana_ring_client::rpc::SkippedReason::InvalidAuditData
    );
}

#[tokio::test]
async fn an_outsider_row_never_reaches_the_origin_read() {
    let fixture = Fixture::new();
    let mut outsider = fixture.foreign_key.clone();
    outsider.tx_signature = Signature::from([0xee; 64]);
    outsider.ring_program_id = None;
    let rows = vec![outsider.clone(), fixture.audited.clone()];
    let mut source = fixture.source().with_transactions(rows.clone());
    source.origins.remove(&(
        outsider.tx_signature,
        outsider.event_index.expect("event index"),
    ));
    source.pages = HashMap::from([(None, paged(rows, None, Some(1)))]);
    let service = fixture.hub(source).service(None).expect("service");
    let page = read_at(&service, None).await;
    let [item] = page.value.items.as_slice() else {
        panic!("one ring transfer, {:?}", page.value.skipped);
    };
    assert_eq!(item.tx_signature.0, fixture.audited.tx_signature);
    service.backfill_utxos().await.expect("backfill");
}
