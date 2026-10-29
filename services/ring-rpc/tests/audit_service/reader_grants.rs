//! Refuses a wallet reader outside its wallet and a reader whose only grant is revoked, in the tree or the database.

use super::*;

async fn wallet_read(
    service: &AuditService<StaticSource>,
    reader: &Keypair,
    wallet: Address,
) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
    let request = GetDecryptedTransactionsRequest::read(target(RING))
        .with_wallet(wallet)
        .sign(reader)
        .expect("request");
    service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request.auth,
            page: &page(),
            wallet: Some(wallet),
        })
        .await
}

async fn ring_read(
    service: &AuditService<StaticSource>,
    reader: &Keypair,
) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
    service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &auth(reader),
            page: &page(),
            wallet: None,
        })
        .await
}

async fn database_hub(fixture: &Fixture, source: StaticSource) -> Arc<Hub<StaticSource>> {
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    Arc::new(
        Hub::builder(source, GENESIS)
            .with_origins(origins())
            .with_store(store)
            .with_reader_grants(ReaderGrantStore::Database)
            .local(RING, fixture.auditor.clone())
            .expect("hub"),
    )
}

fn set_grant(
    signer: &Keypair,
    wallet: Option<Address>,
    reader: &Keypair,
    action: ReaderGrantAction,
) -> serde_json::Map<String, serde_json::Value> {
    as_object(
        ReaderGrantRequest::new(ReaderGrantAttestation {
            target: target(RING),
            wallet,
            reader: ReaderKey::ed25519(reader.pubkey()).expect("reader"),
            action,
        })
        .sign(signer)
        .expect("signed grant"),
    )
}

fn granted(result: Result<GetDecryptedTransactionsResponse, RingRpcError>) -> Vec<Signature> {
    let page = result.expect("granted read").value;
    assert!(page.skipped.is_empty());
    page.items.iter().map(|item| item.tx_signature.0).collect()
}

fn not_granted(result: Result<GetDecryptedTransactionsResponse, RingRpcError>) -> bool {
    matches!(
        result,
        Err(RingRpcError::Unauthorized(Unauthorized::NotGranted))
    )
}

#[tokio::test]
async fn a_wallet_scoped_reader_sees_only_its_wallet_rows() {
    let fixture = Fixture::new();
    let wallet = Address::new_from_array([0xb0; 32]);
    let elsewhere = Indexed {
        transfer: &ring_transfer(4),
        outputs: &[paid(sol(0xc0, 13), fixture.recipient_u)],
        auditor: &fixture.auditor.pubkey(),
        signature: 4,
        frames: &fixture.frames,
    }
    .delivered();
    let source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone(), elsewhere.clone()]);
    let reader = stranger();
    let grant = Member::wallet_grant(
        &Member::owner_tag(wallet.as_array()).expect("wallet member"),
        &reader_member(ReaderKey::ed25519(reader.pubkey()).expect("reader")),
    )
    .expect("grant member");
    source.records.list_reader(grant, true);
    let service = fixture.hub(source).service(None).expect("service");

    assert_eq!(
        granted(wallet_read(&service, &reader, wallet).await),
        [fixture.audited.tx_signature]
    );
    // The grant names one wallet, another wallet's rows stay closed.
    let other = Address::new_from_array([0xc0; 32]);
    assert!(not_granted(wallet_read(&service, &reader, other).await));
    assert_eq!(
        granted(wallet_read(&service, &delegate(), other).await),
        [elsewhere.tx_signature]
    );
}

#[tokio::test]
async fn a_revoked_grant_stops_reads() {
    let fixture = Fixture::new();
    let wallet = Keypair::new_from_array([47; 32]);
    let owned = Indexed {
        transfer: &ring_transfer(5),
        outputs: &[paid(
            UtxoFields {
                owner_key: wallet.pubkey().to_bytes(),
                ..sol(0, 21)
            },
            fixture.recipient_u,
        )],
        auditor: &fixture.auditor.pubkey(),
        signature: 5,
        frames: &fixture.frames,
    }
    .delivered();
    let source = fixture.source().with_transactions(vec![owned.clone()]);
    let records = source.records.clone();
    let tree = fixture.hub(source).service(None).expect("service");
    assert_eq!(
        granted(ring_read(&tree, &delegate()).await),
        [owned.tx_signature]
    );
    records.list_reader(
        reader_member(ReaderKey::ed25519(delegate().pubkey()).expect("reader")),
        false,
    );
    assert!(not_granted(ring_read(&tree, &delegate()).await));

    let hub = database_hub(
        &fixture,
        fixture.source().with_transactions(vec![owned.clone()]),
    )
    .await;
    let module = rpc_module(hub.clone()).expect("module");
    let service = hub.service(None).expect("service");
    let reader = stranger();
    for (action, readable) in [
        (ReaderGrantAction::Grant, true),
        (ReaderGrantAction::Revoke, false),
    ] {
        let held: ReaderGrantAction = module
            .call(
                SET_READER_GRANT,
                set_grant(&wallet, Some(wallet.pubkey()), &reader, action),
            )
            .await
            .expect("stored grant");
        assert_eq!(held, action);
        let read = wallet_read(&service, &reader, wallet.pubkey()).await;
        match readable {
            true => assert_eq!(granted(read), [owned.tx_signature]),
            false => assert!(not_granted(read)),
        }
    }
}

#[tokio::test]
async fn a_database_ring_grant_serves_a_ring_whose_policy_mirrors_no_root() {
    let fixture = Fixture::new();
    let mut source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone()]);
    source.records_synced = false;
    let hub = database_hub(&fixture, source).await;
    let module = rpc_module(hub.clone()).expect("module");
    let service = hub.service(None).expect("service");
    let reader = stranger();

    for (action, readable) in [
        (ReaderGrantAction::Grant, true),
        (ReaderGrantAction::Revoke, false),
    ] {
        let held: ReaderGrantAction = module
            .call(
                SET_READER_GRANT,
                set_grant(&authority(), None, &reader, action),
            )
            .await
            .expect("stored grant");
        assert_eq!(held, action);
        let read = ring_read(&service, &reader).await;
        match readable {
            true => assert_eq!(granted(read), [fixture.audited.tx_signature]),
            false => assert!(not_granted(read)),
        }
    }
}
