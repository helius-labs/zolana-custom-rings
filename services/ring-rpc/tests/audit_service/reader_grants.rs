//! Serves a wallet reader its own part of each transaction, refuses it outside its wallet and refuses a reader whose only grant is revoked, in the tree or the database.

use super::*;
use custom_ring_interface::{InProofOwner, RingOutput, RingRail, RingTransactData};

async fn wallet_read(
    service: &AuditService<StaticSource>,
    reader: &Keypair,
    wallet: Address,
) -> Result<GetWalletActivityResponse, RingRpcError> {
    let request = WalletActivity::read(target(RING), wallet)
        .sign(reader)
        .expect("request");
    service
        .wallet_activity(AuditRead {
            read: PagedRead::WalletActivity,
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
        Hub::builder(source, identity(GENESIS))
            .with_origins(origins())
            .with_store(store)
            .with_reader_grants(ReaderGrantStore::Database)
            .with_grant_rows_key(grant_rows_key())
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

fn activity(result: Result<GetWalletActivityResponse, RingRpcError>) -> Vec<WalletActivity> {
    result.expect("granted read").value.items
}

fn not_granted<T>(result: Result<T, RingRpcError>) -> bool {
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
        signatures(&activity(wallet_read(&service, &reader, wallet).await)),
        [fixture.audited.tx_signature]
    );
    // The grant names one wallet, another wallet's rows stay closed.
    let other = Address::new_from_array([0xc0; 32]);
    assert!(not_granted(wallet_read(&service, &reader, other).await));
    assert_eq!(
        signatures(&activity(wallet_read(&service, &delegate(), other).await)),
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
            true => assert_eq!(signatures(&activity(read)), [owned.tx_signature]),
            false => assert!(not_granted(read)),
        }
    }
}

#[tokio::test]
async fn a_database_ring_grant_serves_a_ring_without_a_records_registry() {
    let fixture = Fixture::new();
    let mut source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone()]);
    source.records_registered = false;
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

fn wallet_reader(source: &StaticSource, wallet: Address) -> Keypair {
    let reader = stranger();
    let grant = Member::wallet_grant(
        &Member::owner_tag(wallet.as_array()).expect("wallet member"),
        &reader_member(ReaderKey::ed25519(reader.pubkey()).expect("reader")),
    )
    .expect("grant member");
    source.records.list_reader(grant, true);
    reader
}

fn signatures(items: &[WalletActivity]) -> Vec<Signature> {
    items.iter().map(|item| item.tx_signature.0).collect()
}

#[tokio::test]
async fn a_signer_wallet_scope_sees_nothing() {
    let fixture = Fixture::new();
    let source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone()]);
    let reader = wallet_reader(&source, SENDER);
    let service = fixture.hub(source).service(None).expect("service");
    // The fixture lists SENDER as the transaction's only signer.
    assert!(activity(wallet_read(&service, &reader, SENDER).await).is_empty());
}

fn anonymous_transfer(fixture: &Fixture) -> StaticSource {
    let mut transfer = ring_transfer(70);
    transfer.nullifiers.push(field(0x71));
    let sender = Spend {
        utxo: sol(0xa1, 900),
        blinding: field(0x60),
    };
    let outputs = [
        Output::Ring {
            utxo: sol(0xb5, 500),
            recipient_u: x25519_u(0x50),
            tag: Some(field(0x51)),
        },
        Output::Ring {
            utxo: sol(0xb6, 501),
            recipient_u: x25519_u(0x52),
            tag: Some(field(0x53)),
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
    source
}

#[tokio::test]
async fn a_recipient_sees_only_its_own_output_of_an_anonymous_transfer() {
    let fixture = Fixture::new();
    let source = anonymous_transfer(&fixture);
    let wallet = Address::new_from_array([0xb5; 32]);
    let reader = wallet_reader(&source, wallet);
    let service = fixture.hub(source).service(None).expect("service");
    let [item] = activity(wallet_read(&service, &reader, wallet).await)
        .try_into()
        .expect("the recipient's transfer");
    let WalletView::Recipient {
        outputs,
        withdrawals,
    } = item.view
    else {
        panic!("a recipient view")
    };
    let amounts: Vec<u64> = outputs
        .iter()
        .flat_map(|output| &output.utxo)
        .map(|utxo| utxo.amount)
        .collect();
    assert_eq!(amounts, [500]);
    assert!(withdrawals.is_empty());
}

#[tokio::test]
async fn a_sender_sees_its_own_anonymous_transfer() {
    let fixture = Fixture::new();
    let source = anonymous_transfer(&fixture);
    let wallet = Address::new_from_array([0xa1; 32]);
    let reader = wallet_reader(&source, wallet);
    let service = fixture.hub(source).service(None).expect("service");
    let [item] = activity(wallet_read(&service, &reader, wallet).await)
        .try_into()
        .expect("the sender's transfer");
    let WalletView::Sender {
        inputs,
        outputs,
        withdrawals,
        ..
    } = item.view
    else {
        panic!("a sender view")
    };
    assert_eq!(outputs.len(), 2);
    assert_eq!(inputs.len(), 2);
    assert_eq!(withdrawals.len(), 2);
}

const OWNER: Address = Address::new_from_array([0xd0; 32]);
const CO_OWNER: Address = Address::new_from_array([0xd1; 32]);

/// The fixture's confidential transfer, `owners` its owner signer run.
fn owner_signed(fixture: &Fixture, owners: &[Address]) -> StaticSource {
    let mut source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone()]);
    source
        .owner_signers
        .insert(fixture.audited.tx_signature, owners.to_vec());
    source
}

/// The fixture's confidential transfer, `owner` verified in the SPP proof.
fn owned_in_proof(fixture: &Fixture, owner: Address) -> StaticSource {
    let mut frames = fixture.frames.lock().unwrap();
    let frame = frames
        .get_mut(&fixture.audited.tx_signature)
        .expect("frame");
    let zero = [0; 32];
    let mut data = RingTransactData::parse(&frame[1..], RingRail::Confidential)
        .expect("frame")
        .into_data();
    // The in-proof rail frames each ring slot under its owner.
    for output in &mut data.outputs {
        if let RingOutput::Delivered { hash, u, body } = *output {
            *output = RingOutput::Owned {
                hash,
                owner: u,
                u,
                body,
            };
        }
    }
    data.in_proof_owner = Some(InProofOwner {
        owner: owner.as_array(),
        commitment: &zero,
        commitment_pok: &zero,
    });
    let encoded = [vec![frame[0]], data.encode().expect("frame")].concat();
    *frame = encoded;
    drop(frames);
    owner_signed(fixture, &[])
}

async fn wallet_activity(
    source: StaticSource,
    fixture: &Fixture,
    wallet: Address,
) -> Vec<WalletActivity> {
    let reader = wallet_reader(&source, wallet);
    let service = fixture.hub(source).service(None).expect("service");
    activity(wallet_read(&service, &reader, wallet).await)
}

/// A spender sees every output and no input opening.
fn assert_spent_in_full(items: Vec<WalletActivity>) {
    let [item] = items.try_into().expect("the spender's transfer");
    let WalletView::Sender {
        inputs, outputs, ..
    } = item.view
    else {
        panic!("a sender view")
    };
    let amounts: Vec<u64> = outputs
        .iter()
        .flat_map(|output| &output.utxo)
        .map(|utxo| utxo.amount)
        .collect();
    assert_eq!(amounts, [500, 7]);
    assert!(inputs.is_empty());
}

#[tokio::test]
async fn a_confidential_owner_signer_sees_its_full_transfer() {
    let fixture = Fixture::new();
    let source = owner_signed(&fixture, &[OWNER]);
    assert_spent_in_full(wallet_activity(source, &fixture, OWNER).await);
}

#[tokio::test]
async fn a_confidential_in_proof_owner_sees_its_full_transfer() {
    let fixture = Fixture::new();
    let source = owned_in_proof(&fixture, OWNER);
    assert_spent_in_full(wallet_activity(source, &fixture, OWNER).await);
}

#[tokio::test]
async fn a_fee_payer_that_owns_no_input_sees_nothing_on_either_rail() {
    let fixture = Fixture::new();
    // SENDER pays and signs, OWNER spends.
    let source = owner_signed(&fixture, &[OWNER]);
    assert!(wallet_activity(source, &fixture, SENDER).await.is_empty());
    let source = owned_in_proof(&fixture, OWNER);
    assert!(wallet_activity(source, &fixture, SENDER).await.is_empty());
}

#[tokio::test]
async fn each_co_spender_of_an_audit_only_ring_sees_no_input_opening() {
    let fixture = Fixture::new();
    for owner in [OWNER, CO_OWNER] {
        let source = owner_signed(&fixture, &[OWNER, CO_OWNER]);
        assert_spent_in_full(wallet_activity(source, &fixture, owner).await);
    }
}
