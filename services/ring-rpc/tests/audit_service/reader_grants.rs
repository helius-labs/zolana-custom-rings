//! Refuses a wallet reader outside its wallet and a reader whose only grant is revoked, in the tree or the row store.

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
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let hub = Arc::new(
        Hub::builder(source, GENESIS)
            .with_origins(origins())
            .with_store(store)
            .with_encrypted_grants()
            .local(RING, fixture.auditor.clone())
            .expect("hub"),
    );
    let module = rpc_module(hub.clone()).expect("module");
    let service = hub.service(None).expect("service");
    let reader = stranger();
    let set = |action| {
        ReaderGrantRequest::new(ReaderGrantAttestation {
            target: target(RING),
            wallet: wallet.pubkey(),
            reader: ReaderKey::ed25519(reader.pubkey()).expect("reader"),
            action,
        })
        .sign(&wallet)
        .expect("signed grant")
    };

    for (action, readable) in [
        (ReaderGrantAction::Grant, true),
        (ReaderGrantAction::Revoke, false),
    ] {
        let held: ReaderGrantAction = module
            .call(SET_READER_GRANT, as_object(set(action)))
            .await
            .expect("stored grant");
        assert_eq!(held, action);
        let read = wallet_read(&service, &reader, wallet.pubkey()).await;
        match readable {
            true => assert_eq!(granted(read), [owned.tx_signature]),
            false => assert!(not_granted(read)),
        }
    }

    let ring_wide = |signer: &Keypair| {
        let auth = auth(signer);
        let service = &service;
        async move {
            service
                .read(AuditRead {
                    read: PagedRead::DecryptedTransactions,
                    auth: &auth,
                    page: &page(),
                    wallet: None,
                })
                .await
        }
    };
    assert_eq!(granted(ring_wide(&delegate()).await), [owned.tx_signature]);
    records.list_reader(
        reader_member(ReaderKey::ed25519(delegate().pubkey()).expect("reader")),
        false,
    );
    assert!(not_granted(ring_wide(&delegate()).await));
}
