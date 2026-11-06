//! Serves a wallet reader its own part of each transaction, refuses it outside its wallet and refuses a reader whose only grant is revoked, in the tree or the database.

use super::*;
use custom_ring_interface::{InProofOwner, RingRail, RingTransactData};
use zolana_ring_client::rpc::{GetWalletStatusResponse, GET_WALLET_STATUS};

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
        outputs: &[paid(sol(0xc0, 13), fixture.recipient_u), Output::Dummy],
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
        outputs: &[
            paid(
                UtxoFields {
                    owner_key: wallet.pubkey().to_bytes(),
                    ..sol(0, 21)
                },
                fixture.recipient_u,
            ),
            Output::Dummy,
        ],
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
    .anonymous(&[true, false]);
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

/// A note the index cannot name reads as another party's, the view fails closed.
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

/// The fixture's confidential transfer sealed for the in-proof rail, `owner` verified in the SPP proof.
fn owned_in_proof(fixture: &Fixture, owner: Address) -> StaticSource {
    let transfer = ring_transfer(1);
    let outputs = [
        paid(sol(0xb0, 500), fixture.recipient_u),
        paid(sol(0xb1, 7), fixture.recipient_u),
    ];
    let mut disclosure = transfer.disclosure(Rail::Delivered, &outputs);
    disclosure.in_proof = true;
    disclosure.real_inputs = 1;
    let audited = Indexed {
        transfer: &transfer,
        outputs: &outputs,
        auditor: &fixture.auditor.pubkey(),
        signature: 1,
        frames: &fixture.frames,
    }
    .publish(Rail::Delivered, &outputs, &disclosure);
    let mut frames = fixture.frames.lock().unwrap();
    let frame = frames.get_mut(&audited.tx_signature).expect("frame");
    let zero = [0; 32];
    let mut data = RingTransactData::parse(&frame[1..], RingRail::Confidential)
        .expect("frame")
        .into_data();
    data.in_proof_owner = Some(InProofOwner {
        owner: owner.as_array(),
        commitment: &zero,
        commitment_pok: &zero,
    });
    let encoded = [vec![frame[0]], data.encode().expect("frame")].concat();
    *frame = encoded;
    drop(frames);
    let mut source = fixture.source().with_transactions(vec![audited.clone()]);
    source
        .owner_signers
        .insert(audited.tx_signature, Vec::new());
    source
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

/// A spender of unnamed inputs reads no input opening and only its own notes.
fn assert_reads_own_notes_alone(items: Vec<WalletActivity>) {
    let [item] = items.try_into().expect("the spender's transfer");
    let WalletView::Sender {
        inputs, outputs, ..
    } = item.view
    else {
        panic!("a sender view")
    };
    assert!(outputs.is_empty());
    assert!(inputs.is_empty());
}

#[tokio::test]
async fn a_confidential_owner_signer_of_an_unnamed_input_reads_its_own_notes_alone() {
    let fixture = Fixture::new();
    let source = owner_signed(&fixture, &[OWNER]);
    assert_reads_own_notes_alone(wallet_activity(source, &fixture, OWNER).await);
}

fn owned_note(amount: u64) -> UtxoFields {
    UtxoFields {
        owner_key: OWNER.to_bytes(),
        ..sol(0, amount)
    }
}

/// `OWNER`'s enrolled note spent beside `co_spent`, paying a stranger and `OWNER`.
fn enrolled_spend(fixture: &Fixture, co_spent: &[[u8; 32]]) -> StaticSource {
    let key = NullifierKey::from_secret([7; 31]);
    let (note, nullifier) = KeyedNote {
        fixture,
        seed: 0x60,
        note: owned_note(900),
        key: &key,
    }
    .delivered();
    let nullifiers = [&[nullifier], co_spent].concat();
    let spend = Indexed {
        transfer: &spending(0x61, &nullifiers),
        outputs: &[
            paid(sol(0xb0, 500), fixture.recipient_u),
            paid(owned_note(7), fixture.recipient_u),
        ],
        auditor: &fixture.auditor.pubkey(),
        signature: 0x61,
        frames: &fixture.frames,
    }
    .delivered();
    let mut source = fixture.source().with_transactions(vec![note, spend]);
    source.next_cursor = None;
    source
        .tracking
        .enroll(OWNER.as_array(), &key, &fixture.auditor.pubkey());
    source
}

/// The output amounts of the wallet's spend, one input of its own, after the note it received.
fn sender_amounts(items: Vec<WalletActivity>) -> Vec<u64> {
    let Some(WalletActivity {
        view: WalletView::Sender {
            inputs, outputs, ..
        },
        ..
    }) = items.into_iter().last()
    else {
        panic!("a sender view")
    };
    assert_eq!(inputs.len(), 1);
    outputs
        .iter()
        .flat_map(|output| &output.utxo)
        .map(|utxo| utxo.amount)
        .collect()
}

/// The amounts of the wallet's spend, after the note it received.
async fn spent_amounts(source: StaticSource, fixture: &Fixture) -> Vec<u64> {
    let reader = wallet_reader(&source, OWNER);
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    sender_amounts(activity(wallet_read(&service, &reader, OWNER).await))
}

#[tokio::test]
async fn a_sole_owner_keeps_every_output_and_a_co_owner_its_own() {
    let fixture = Fixture::new();
    let sole = enrolled_spend(&fixture, &[]);
    assert_eq!(spent_amounts(sole, &fixture).await, [500, 7]);
    let co_owned = enrolled_spend(&fixture, &[field(0x71)]);
    assert_eq!(spent_amounts(co_owned, &fixture).await, [7]);
}

#[tokio::test]
async fn a_confidential_in_proof_owner_with_an_unopened_input_reads_its_own_notes_alone() {
    let fixture = Fixture::new();
    let source = owned_in_proof(&fixture, OWNER);
    let [item] = wallet_activity(source, &fixture, OWNER)
        .await
        .try_into()
        .expect("the spender's transfer");
    let WalletView::Sender {
        inputs, outputs, ..
    } = item.view
    else {
        panic!("a sender view")
    };
    assert!(
        outputs.is_empty() && inputs.is_empty(),
        "an input the service never opened names no sole owner"
    );
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

/// A deposit-funded confidential transfer of dummy inputs, `OWNER` signing for its own output beside a stranger's.
fn deposit_funded(fixture: &Fixture) -> StaticSource {
    let transfer = ring_transfer(0x64);
    let outputs = [
        paid(sol(0xb0, 500), fixture.recipient_u),
        paid(owned_note(7), fixture.recipient_u),
    ];
    let mut disclosure = transfer.disclosure(Rail::Delivered, &outputs);
    disclosure.real_inputs = 0;
    let funded = Indexed {
        transfer: &transfer,
        outputs: &outputs,
        auditor: &fixture.auditor.pubkey(),
        signature: 0x64,
        frames: &fixture.frames,
    }
    .publish(Rail::Delivered, &outputs, &disclosure);
    let deposit = spr_interface::instruction::InterfaceTransfer::SolDeposit { amount: 507 };
    let mut frames = fixture.frames.lock().unwrap();
    let frame = frames.get_mut(&funded.tx_signature).expect("frame");
    let mut data = RingTransactData::parse(&frame[1..], RingRail::Confidential)
        .expect("frame")
        .into_data();
    data.interface_transfers = vec![deposit];
    *frame = [vec![frame[0]], data.encode().expect("frame")].concat();
    drop(frames);
    let mut source = fixture.source().with_transactions(vec![funded.clone()]);
    // The settlement group of the deposit ends the account list after the owner signer run.
    let settlement = vec![Address::default(); deposit.settlement_account_count()];
    source
        .owner_signers
        .insert(funded.tx_signature, [vec![OWNER], settlement].concat());
    source
}

#[tokio::test]
async fn a_data_output_signer_of_dummy_inputs_reads_only_its_own_output() {
    let fixture = Fixture::new();
    let [item] = wallet_activity(deposit_funded(&fixture), &fixture, OWNER)
        .await
        .try_into()
        .expect("the signer's transfer");
    let WalletView::Sender {
        inputs, outputs, ..
    } = item.view
    else {
        panic!("a sender view")
    };
    assert!(inputs.is_empty());
    let amounts: Vec<u64> = outputs
        .iter()
        .flat_map(|output| &output.utxo)
        .map(|utxo| utxo.amount)
        .collect();
    assert_eq!(amounts, [7], "the stranger's output stays closed");
}

#[tokio::test]
async fn each_co_spender_of_an_audit_only_ring_sees_no_input_opening() {
    let fixture = Fixture::new();
    for owner in [OWNER, CO_OWNER] {
        let source = owner_signed(&fixture, &[OWNER, CO_OWNER]);
        assert_reads_own_notes_alone(wallet_activity(source, &fixture, owner).await);
    }
}

/// One spend of an unseen note, paying `paid` beside a stranger.
fn unseen_spend(fixture: &Fixture, signature: u8, paid: u8) -> ShieldedTransaction {
    let mut transfer = ring_transfer(signature);
    transfer.nullifiers.push(field(0x71));
    let outputs = [
        Output::Ring {
            utxo: sol(paid, 500),
            recipient_u: x25519_u(0x50),
            tag: Some(field(0x51)),
        },
        Output::Ring {
            utxo: sol(0xb6, 501),
            recipient_u: x25519_u(0x52),
            tag: Some(field(0x53)),
        },
    ];
    Indexed {
        transfer: &transfer,
        outputs: &outputs,
        auditor: &fixture.auditor.pubkey(),
        signature,
        frames: &fixture.frames,
    }
    .anonymous(&[true, false])
}

#[tokio::test]
async fn a_wallet_read_is_byte_equal_with_another_owners_unresolved_spend_present() {
    let fixture = Fixture::new();
    let (others, own) = (0x70, 0x73);
    let wallet = Address::new_from_array([0xb5; 32]);
    let read_with = |rows: Vec<ShieldedTransaction>| {
        let fixture = &fixture;
        async move {
            let mut source = fixture.source().with_transactions(rows);
            source.configs.get_mut(&RING).expect("config").mode = RingMode::Anonymous;
            // The history ends at these rows, the default cursor names its own page.
            source.next_cursor = None;
            let reader = wallet_reader(&source, wallet);
            let hub = Arc::new(fixture.hub(source));
            let service = hub.service(None).expect("service");
            service.backfill_utxos().await.expect("backfill");
            let request = WalletStatusRequest::new(target(RING), wallet)
                .sign(&reader)
                .expect("signed");
            let read: GetWalletStatusResponse = rpc_module(hub.clone())
                .expect("module")
                .call(GET_WALLET_STATUS, as_object(request))
                .await
                .expect("wallet read");
            let refused = rpc_module(hub.clone())
                .expect("module")
                .call::<_, GetWalletStatusResponse>(
                    GET_WALLET_STATUS,
                    as_object(
                        WalletStatusRequest::new(target(RING), Address::new_from_array([0xb6; 32]))
                            .sign(&reader)
                            .expect("signed"),
                    ),
                )
                .await;
            assert!(refused.is_err(), "a wallet grant reads no other wallet");
            read
        }
    };
    // The stranger's row comes last, the fixture numbers slots by position.
    let with_row = read_with(vec![
        unseen_spend(&fixture, own, 0xb5),
        unseen_spend(&fixture, others, 0xb7),
    ])
    .await;
    let without_row = read_with(vec![unseen_spend(&fixture, own, 0xb5)]).await;
    assert_eq!(
        serde_json::to_vec(&with_row).expect("json"),
        serde_json::to_vec(&without_row).expect("json")
    );
    let [paid] = with_row.notes.as_slice() else {
        panic!("the wallet's own note stays listed, {:?}", with_row.notes);
    };
    assert_eq!(paid.amount, 500);
    let wire = serde_json::to_string(&with_row).expect("json");
    assert!(!wire.contains(&Hash(field(others)).to_base58()));
    assert!(!wire.contains(&Hash(field(own)).to_base58()));
    for key in ["unresolved", "coverage", "complete"] {
        assert!(!wire.contains(key), "no {key} marker reaches a wallet");
    }
}

/// A wallet signs for itself, no list holds its key.
#[tokio::test]
async fn a_wallet_reads_its_own_notes_with_its_own_signature() {
    let fixture = Fixture::new();
    let source = fixture.source().with_transactions(Vec::new());
    let service = fixture.hub(source).service(None).expect("service");
    let owner = Keypair::new_from_array([0x61; 32]);
    let own = WalletStatusRequest::new(target(RING), owner.pubkey())
        .sign(&owner)
        .expect("signed");
    service.wallet_status(&own).await.expect("its own read");
    let other = WalletStatusRequest::new(target(RING), Address::new_from_array([0xb6; 32]))
        .sign(&owner)
        .expect("signed");
    assert!(service.wallet_status(&other).await.is_err());
}

/// `OWNER`'s enrolled note spent on the anonymous rail, `real` flags each input after it.
fn anonymous_spend(fixture: &Fixture, others: &[([u8; 32], bool)]) -> StaticSource {
    let key = NullifierKey::from_secret([7; 31]);
    let (note, nullifier) = KeyedNote {
        fixture,
        seed: 0x62,
        note: owned_note(900),
        key: &key,
    }
    .anonymous();
    let nullifiers: Vec<_> = core::iter::once(nullifier)
        .chain(others.iter().map(|(other, _)| *other))
        .collect();
    let real: Vec<_> = core::iter::once(true)
        .chain(others.iter().map(|(_, real)| *real))
        .collect();
    let spend = Indexed {
        transfer: &spending(0x63, &nullifiers),
        outputs: &[
            Output::Ring {
                utxo: sol(0xb0, 500),
                recipient_u: x25519_u(0x50),
                tag: Some(field(0x51)),
            },
            Output::Ring {
                utxo: owned_note(7),
                recipient_u: x25519_u(0x52),
                tag: Some(field(0x53)),
            },
        ],
        auditor: &fixture.auditor.pubkey(),
        signature: 0x63,
        frames: &fixture.frames,
    }
    .anonymous(&real);
    let mut source = fixture.source().with_transactions(vec![note, spend]);
    source.configs.get_mut(&RING).expect("config").mode = RingMode::Anonymous;
    source.next_cursor = None;
    source
        .tracking
        .enroll(OWNER.as_array(), &key, &fixture.auditor.pubkey());
    source
}

#[tokio::test]
async fn an_anonymous_spend_reads_a_resolved_input_an_unresolved_one_and_padding_apart() {
    let fixture = Fixture::new();
    let source = anonymous_spend(&fixture, &[(field(0x71), true), (field(0x72), false)]);
    let reader = wallet_reader(&source, OWNER);
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");

    let coverage = service
        .spend_coverage(&coverage_failures::coverage_request(&authority()))
        .await
        .expect("coverage");
    assert_eq!(coverage.totals.expect("first page totals").resolved, 1);
    assert_eq!(coverage.totals.expect("first page totals").padding, 1);
    // The paying transfer's own input stays unresolved beside the spend's.
    assert_eq!(
        coverage
            .unresolved_real
            .iter()
            .map(|row| row.nullifier.0)
            .collect::<Vec<_>>(),
        [field(0x62), field(0x71)]
    );
    assert!(coverage.unreadable.is_empty());
    assert!(coverage.integrity_faults.is_empty());

    let status = service
        .wallet_status(
            &WalletStatusRequest::new(target(RING), OWNER)
                .sign(&delegate())
                .expect("signed read"),
        )
        .await
        .expect("status");
    // The resolved spend took its note out of the wallet.
    assert!(status.notes.iter().all(|note| note.amount != 900));

    // The unresolved input makes the wallet a co-owner, it reads its own notes alone.
    let items = activity(wallet_read(&service, &reader, OWNER).await);
    assert_eq!(sender_amounts(items), [7]);
}

#[tokio::test]
async fn padding_beside_a_resolved_anonymous_input_leaves_a_sole_owner() {
    let fixture = Fixture::new();
    let source = anonymous_spend(&fixture, &[(field(0x72), false)]);
    let reader = wallet_reader(&source, OWNER);
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let items = activity(wallet_read(&service, &reader, OWNER).await);
    assert_eq!(sender_amounts(items), [500, 7]);
}
