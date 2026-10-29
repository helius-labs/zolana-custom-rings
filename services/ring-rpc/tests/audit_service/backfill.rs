use super::*;

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
    assert_eq!(
        input_ring(&read_at(&service, Some(9)).await),
        Some(DecryptedInputRing::Ring {
            commitment: utxos.commitment.into(),
        })
    );
}

#[tokio::test]
async fn a_backfill_opens_a_deposited_utxo_a_later_spend_names() {
    let fixture = Fixture::new();
    let member = sol(0xa6, 64);
    let blinding = field(0x66);
    let (deposit, bindings) = audited_deposit(&fixture.auditor.pubkey(), &member, blinding);
    let commitment = deposit.output_slots[0].output_context.hash;
    let exit = [Output::Exit(sol(0xe9, 64)), Output::Dummy];
    let spent = Indexed {
        transfer: &ring_transfer(83),
        outputs: &exit,
        auditor: &fixture.auditor.pubkey(),
        signature: 83,
        frames: &fixture.frames,
    }
    .anonymous_commitments(&[Some(commitment)]);
    let mut source = fixture
        .source()
        .with_transactions(vec![deposit.clone(), spent.clone()]);
    source.configs.get_mut(&RING).expect("config").mode = RingMode::Anonymous;
    source.deposits.insert(deposit.tx_signature, bindings);
    source.pages = HashMap::from([
        (None, paged(vec![deposit, spent.clone()], Some(1), None)),
        (Some(vec![1]), paged(Vec::new(), None, Some(2))),
        (Some(vec![9]), paged(vec![spent], None, Some(10))),
    ]);
    let service = fixture.hub(source).service(None).expect("service");
    let before = read_at(&service, Some(9)).await;
    assert_eq!(
        before
            .value
            .skipped
            .iter()
            .map(|row| row.reason)
            .collect::<Vec<_>>(),
        [SkippedReason::UnseenInput]
    );
    service.backfill_utxos().await.expect("backfill");
    let found = service
        .audited_utxos(&utxos_request(vec![commitment.into()]))
        .await
        .expect("UTXO read");
    let [Some(view)] = found.value.utxos.as_slice() else {
        panic!("the backfill opened the deposit, {:?}", found.value.utxos);
    };
    assert_eq!(
        (view.utxo.amount, view.utxo.nullifier_pk.clone()),
        (64, None)
    );
    let after = read_at(&service, Some(9)).await;
    assert_eq!(
        input_ring(&after),
        Some(DecryptedInputRing::Ring {
            commitment: commitment.into(),
        })
    );
    assert_eq!(
        after.value.items[0].sender.as_ref().unwrap().nullifier_pk,
        None
    );
}

#[tokio::test]
async fn audited_utxos_answer_in_request_order_with_null_for_an_unseen_hash() {
    let fixture = Fixture::new();
    let hub = Arc::new(fixture.hub(fixture.source()));
    let service = hub.service(None).expect("service");
    read_at(&service, None).await;
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
    // A page read opens UTXOs, only the backfill vouches for the history before its context.
    assert_eq!(response.context.slot, 0);
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
async fn an_escrowed_ring_opens_its_outputs_with_the_keys_its_registry_holds() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let page = read_at(&service, None).await;
    let [item] = page.value.items.as_slice() else {
        panic!("one escrowed transfer, {:?}", page.value.skipped);
    };
    assert!(item.payload_errors.is_empty(), "{:?}", item.payload_errors);
    assert_eq!(amounts(item), [30, 12]);
    let keys: Vec<Hash> = item
        .outputs
        .iter()
        .map(|output| output.utxo.as_ref().expect("utxo").nullifier_pk.clone())
        .collect();
    assert_eq!(keys, owners.map(|utxo| Hash(utxo.nullifier_pk)));
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_read_never_reads_the_registry() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let page = read_at(&service, None).await;
    assert_eq!(
        escrow_errors(&page),
        [OutputPayloadErrorKind::EscrowUnknown; 2]
    );
    assert_eq!(record_reads.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn concurrent_backfills_read_the_registry_once() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30)];
    let source = escrowed_source(&fixture, &owners, &owners);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let (first, second) = tokio::join!(service.backfill_utxos(), service.backfill_utxos());
    first.expect("first backfill");
    second.expect("second backfill");
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_applied_write_rereads_only_the_members_it_names() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners);
    let registry = source.registry.clone();
    *registry.lock().unwrap() = Some(EscrowRegistry::new(&owners[..1]).with_pending(&owners[1..]));
    let record_reads = source.record_reads.clone();
    let opening_reads = source.opening_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(
        escrow_errors(&read_at(&service, None).await),
        [OutputPayloadErrorKind::EscrowUnknown]
    );

    *registry.lock().unwrap() = Some(EscrowRegistry::new(&owners).applied(1));
    service.backfill_utxos().await.expect("backfill");
    assert!(escrow_errors(&read_at(&service, None).await).is_empty());
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
    assert_eq!(opening_reads.load(Ordering::Relaxed), 1);

    // Writes no refresh saw pending leave only the full scan.
    let late = [owners[0], owners[1], sol(0xc2, 5)];
    *registry.lock().unwrap() = Some(EscrowRegistry::new(&late).applied(3));
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(record_reads.load(Ordering::Relaxed), 2);
    assert_eq!(opening_reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_owner_the_registry_never_escrowed_reports_its_slot() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners[..1]);
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let page = read_at(&service, None).await;
    let [item] = page.value.items.as_slice() else {
        panic!("one escrowed transfer, {:?}", page.value.skipped);
    };
    assert_eq!(amounts(item), [30]);
    assert_eq!(
        item.payload_errors,
        [DecryptedPayloadError {
            slot_index: 1,
            kind: OutputPayloadErrorKind::EscrowUnknown,
        }]
    );
}

/// A page short of a record keeps no partial key map, the next backfill reads again.
#[tokio::test]
async fn a_registry_page_short_of_a_record_escrows_no_key() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners);
    source
        .registry
        .lock()
        .unwrap()
        .as_mut()
        .expect("registry")
        .records
        .remove(0);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(
        escrow_errors(&read_at(&service, None).await),
        [OutputPayloadErrorKind::EscrowUnknown; 2]
    );
    let refreshed = record_reads.load(Ordering::Relaxed);
    service.backfill_utxos().await.expect("backfill");
    assert!(record_reads.load(Ordering::Relaxed) > refreshed);
}

#[tokio::test]
async fn the_backfill_reads_the_escrowed_keys_before_its_first_page() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30)];
    let mut source = escrowed_source(&fixture, &owners, &owners);
    let audited = source.transactions.clone();
    source.pages = HashMap::from([(None, paged(audited, None, Some(1)))]);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
    let hash = fixture_output_hash(&service, &owners[0]).await;
    let found = service
        .audited_utxos(&utxos_request(vec![hash]))
        .await
        .expect("UTXO read");
    assert_eq!(
        found.value.utxos[0].as_ref().map(|view| view.utxo.amount),
        Some(30)
    );
}

#[tokio::test]
async fn confirmed_deposit_and_merge_tag_collisions_do_not_poison_an_audit_page() {
    let fixture = Fixture::new();
    let mut deposit = fixture.missing_message.clone();
    deposit.tx_signature = Signature::from([11; 64]);
    deposit.proofless = true;
    deposit.tx_viewing_pk = None;
    deposit.nullifiers.clear();
    let mut merge = fixture.missing_message.clone();
    merge.tx_signature = Signature::from([12; 64]);
    merge.tx_viewing_pk = None;
    let source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone(), deposit, merge]);
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
async fn recipient_bodies_cannot_poison_an_audit_page_or_trigger_registry_refresh() {
    let fixture = Fixture::new();
    let auditor = fixture.auditor.pubkey();
    let outputs: Vec<Output> = (0u8..6)
        .map(|k| paid(sol(0xb0 + k, 10 + u64::from(k)), x25519_u(0x40 + k)))
        .chain([Output::Dummy, Output::Dummy])
        .collect();
    let delivered = |seed: u8| {
        Indexed {
            transfer: &ring_transfer(seed),
            outputs: &outputs,
            auditor: &auditor,
            signature: seed,
            frames: &fixture.frames,
        }
        .delivered()
    };
    // The body is a stream cipher, a flipped bit changes the amount the commitment binds.
    let mut corrupted = delivered(8);
    *corrupted.output_slots[1]
        .payload
        .last_mut()
        .expect("delivered body") ^= 1;
    // A body that opens under its slot secret yet rebuilds no asset's commitment.
    let mut unmatched = delivered(9);
    let transfer = ring_transfer(9);
    let secret = transfer.delivered_secret(&x25519_u(0x42), 2);
    let body = RingDeliveredBody {
        blinding: transfer.blinding(2),
        amount: 13,
    }
    .seal(&secret)
    .expect("delivered body");
    unmatched.output_slots[2].payload = encode_ring_confidential_delivered_output(&body).unwrap();
    let mut invalid_disclosure = delivered(10);
    // The first disclosure field, past the tagged ephemeral key and the sealed key.
    invalid_disclosure.messages[0].data[65] = 0xff;
    let mut source =
        fixture
            .source()
            .with_transactions(vec![corrupted, unmatched, invalid_disclosure]);
    source.assets = None;
    let reads = source.asset_reads.clone();
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
    assert_eq!(response.value.items.len(), 2);
    for (item, slot_index) in response.value.items.iter().zip([1, 2]) {
        assert_eq!(item.outputs.len(), outputs.len() - 1);
        assert_eq!(
            item.payload_errors,
            [DecryptedPayloadError {
                slot_index,
                kind: OutputPayloadErrorKind::Commitment,
            }]
        );
    }
    assert_eq!(response.value.skipped.len(), 1);
    assert_eq!(
        response.value.skipped[0].reason,
        SkippedReason::InvalidAuditData
    );
    // One timed read at the page start.
    assert_eq!(reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn unknown_assets_share_refresh_and_back_off_after_failure() {
    const ASSET_ID: u64 = 2;
    let asset = Address::new_from_array([8; 32]);
    let fixture = Fixture::new();
    let mut source = fixture.source().with_transactions(vec![Indexed {
        transfer: &ring_transfer(8),
        outputs: &[Output::Exit(utxo(0xb8, asset, 13))],
        auditor: &fixture.auditor.pubkey(),
        signature: 8,
        frames: &fixture.frames,
    }
    .delivered()]);
    source.assets = Some(RingAssets::new([Mint::new(asset, ASSET_ID)]).expect("ring assets"));
    let unknown_transactions = source.transactions.clone();
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let ed25519 = auth(&delegate());
    let p256 = auth(&Passkey::new(46));
    let (first, second) = tokio::join!(
        service.read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &ed25519,
            page: &page,
            wallet: None,
        }),
        service.read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &p256,
            page: &page,
            wallet: None,
        })
    );
    let mint = |response: &GetDecryptedTransactionsResponse| {
        let utxo = response.value.items[0].outputs[0].utxo.as_ref();
        utxo.and_then(|utxo| utxo.mint.as_ref()).map(|mint| mint.0)
    };
    for result in [first, second] {
        assert_eq!(mint(&result.expect("refreshed read")), Some(asset));
    }
    assert_eq!(reads.load(Ordering::Relaxed), 1);

    let mut source = fixture
        .source()
        .with_transactions(unknown_transactions.clone());
    source.assets = None;
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    for signer in [&delegate() as &dyn ReadSigner, &Passkey::new(46)] {
        let response = service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &auth(signer),
                page: &page,
                wallet: None,
            })
            .await
            .unwrap();
        assert_eq!(response.value.items[0].outputs.len(), 2);
        assert_eq!(mint(&response), None);
        assert!(response.value.skipped.is_empty());
    }
    assert_eq!(reads.load(Ordering::Relaxed), 1);

    let mut source = fixture.source().with_transactions(unknown_transactions);
    source.asset_delay = Some(Duration::from_secs(1));
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let first = auth(&delegate());
    assert!(tokio::time::timeout(
        Duration::from_millis(1),
        service.read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &first,
            page: &page,
            wallet: None,
        })
    )
    .await
    .is_err());
    let second = auth(&Passkey::new(46));
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &second,
            page: &page,
            wallet: None,
        })
        .await
        .unwrap();
    assert_eq!(mint(&response), None);
    assert!(response.value.skipped.is_empty());
    assert_eq!(reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_backfill_stops_at_its_page_budget() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = HashMap::from([
        (None, paged(Vec::new(), Some(1), None)),
        (Some(vec![1]), paged(Vec::new(), Some(2), None)),
        (Some(vec![2]), paged(Vec::new(), Some(1), None)),
    ]);
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
        (Some(vec![1]), paged(Vec::new(), Some(1), None)),
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
