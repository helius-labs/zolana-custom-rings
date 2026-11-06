use solana_keypair::Keypair;
use solana_signature::Signature;
use spr_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey};
use spr_transaction::OutputContext;

use super::*;
use crate::{
    AuditedEntryInput, InputOpening, OutputPayloadError,
    OutputPayloadErrorKind::{self, Commitment, Disclosure},
};

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ring-rpc-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

#[test]
fn auditor_key_request_attestation_is_stable() {
    let attestation = AuditorKeyAttestation {
        genesis_hash: [9; 32],
        ring: Address::new_from_array([5; 32]),
    }
    .message(1_700_000_000, &[7; 32]);
    assert_eq!(
        String::from_utf8(attestation).expect("utf8"),
        "zolana/ring-rpc-auditor-key-request\n\
         genesis: cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN\n\
         ring: LbUiWL3xVV8hTFYBVdbTNrpDo41NKS6o3LHHuDzjfcY\n\
         timestamp: 1700000000\n\
         nonce: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
    );
}

/// The ring at `[7; 32]` behind the service `[2; 32]` on the cluster `[1; 32]`.
fn target() -> ReadTarget {
    ReadTarget {
        cluster: [1; 32],
        service: Address::new_from_array([2; 32]),
        ring: Address::new_from_array([7; 32]),
    }
}

#[test]
fn read_attestation_is_stable() {
    let message = ReadAttestation {
        read: PagedRead::DecryptedTransactions,
        target: target(),
        cursor: Some(vec![1, 2, 3].into()),
        limit: Some(Limit::new(5).expect("in range")),
        wallet: None,
    }
    .message(1_700_000_000, &[4; 32]);
    assert_eq!(
        String::from_utf8(message).expect("text"),
        "zolana/ring-rpc-read\nmethod: getDecryptedTransactions\ncluster: 4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\nservice: 8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nlimit: 5\ncursor: AQID"
    );
}

/// A reader's signature names its method, cluster, service and ring, each request a fresh nonce.
#[test]
fn a_signed_read_names_its_method_and_target_and_draws_its_own_nonce() {
    let reader = Keypair::new();
    let sign = |read: PagedRead| {
        read.request(target())
            .at(1_700_000_000)
            .sign(&reader)
            .unwrap()
    };
    let transfers = sign(PagedRead::DecryptedTransactions);
    let nonce: [u8; 32] = transfers.auth.nonce.0.clone().try_into().unwrap();
    let signature = Signature::try_from(transfers.auth.signature.0.as_slice()).unwrap();
    let attested = |read, target| {
        ReadAttestation {
            read,
            target,
            cursor: None,
            limit: None,
            wallet: None,
        }
        .message(1_700_000_000, &nonce)
    };
    assert!(signature.verify(
        reader.pubkey().as_ref(),
        &attested(PagedRead::DecryptedTransactions, target())
    ));
    let elsewhere = [
        ReadTarget {
            cluster: [9; 32],
            ..target()
        },
        ReadTarget {
            service: Address::new_from_array([9; 32]),
            ..target()
        },
    ];
    for other in elsewhere {
        assert!(!signature.verify(
            reader.pubkey().as_ref(),
            &attested(PagedRead::DecryptedTransactions, other)
        ));
    }
    assert!(!signature.verify(
        reader.pubkey().as_ref(),
        &attested(PagedRead::AuditedMerges, target())
    ));
    assert_ne!(
        sign(PagedRead::DecryptedTransactions).auth.nonce,
        transfers.auth.nonce
    );
}

#[test]
fn audited_utxos_attestation_is_stable() {
    let message = AuditedUtxosAttestation::new(target(), &[Hash([1; 32]), Hash([2; 32])])
        .message(1_700_000_000, &[4; 32]);
    assert_eq!(
        String::from_utf8(message).expect("text"),
        "zolana/ring-rpc-audited-utxos\ncluster: 4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\nservice: 8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nutxos: +Biv03ptw7yS+0RzEBEncAbbTvpukCPNdGjAIzXSKk0="
    );
}

#[test]
fn a_signed_utxo_read_carries_the_hashes_it_signed() {
    let reader = Keypair::new();
    let ring = target().ring;
    let hashes = vec![Hash([1; 32]), Hash([2; 32])];
    let request = GetAuditedUtxosRequest::read(target(), hashes.clone())
        .expect("utxo read")
        .at(1_700_000_000)
        .sign(&reader)
        .expect("signed");
    assert_eq!(request.utxo_hashes, hashes);
    assert_eq!(request.ring_program_id, Some(ring.to_bytes().into()));
    let nonce = request.auth.nonce.0.clone().try_into().expect("nonce");
    let signature = Signature::try_from(request.auth.signature.0.as_slice()).expect("signature");
    let signed = |hashes: &[Hash]| {
        AuditedUtxosAttestation::new(target(), hashes).message(1_700_000_000, &nonce)
    };
    assert!(signature.verify(reader.pubkey().as_ref(), &signed(&hashes)));
    assert!(!signature.verify(
        reader.pubkey().as_ref(),
        &signed(&[Hash([2; 32]), Hash([1; 32])])
    ));
    for count in [0, AUDITED_UTXOS_LIMIT + 1] {
        assert!(matches!(
            GetAuditedUtxosRequest::read(target(), vec![Hash([1; 32]); count]),
            Err(ReadBuildError::UtxoHashes)
        ));
    }
}

/// `Limit` cannot hold zero, so the smallest audit page the wire carries is one.
#[test]
fn an_audit_page_holds_at_its_cursor_and_limit_bounds() {
    assert!(!cursor_in_bounds(&[]));
    assert!(cursor_in_bounds(&vec![1; AUDIT_CURSOR_LIMIT]));
    assert!(!cursor_in_bounds(&vec![1; AUDIT_CURSOR_LIMIT + 1]));
    assert!(limit_in_bounds(&Limit::new(1).expect("indexer limit")));
    assert!(limit_in_bounds(
        &Limit::new(AUDIT_PAGE_LIMIT).expect("indexer limit")
    ));
    assert!(!limit_in_bounds(
        &Limit::new(AUDIT_PAGE_LIMIT + 1).expect("indexer limit")
    ));
}

fn utxo(seed: u8, mint: Option<Address>) -> AuditedUtxo {
    AuditedUtxo {
        owner_key: [seed; 32],
        nullifier_pk: [seed + 1; 32],
        asset: [seed + 2; 32],
        mint,
        amount: u64::from(seed),
        blinding: [seed + 3; 32],
        data_hash: [seed + 4; 32],
        ring_data_hash: [seed + 5; 32],
    }
}

fn entry_input(seed: u8) -> AuditedEntryInput {
    AuditedEntryInput {
        owner_key: [seed; 32],
        nullifier_pk: [seed + 1; 32],
        asset: [seed + 2; 32],
        mint: Address::new_from_array([4; 32]),
        amount: u64::from(seed),
        commitment: [seed + 3; 32],
    }
}

fn output(slot_index: u32, opening: OutputOpening) -> AuditedOutput {
    AuditedOutput {
        slot_index,
        context: OutputContext {
            hash: [0x40 + slot_index as u8; 32],
            tree_id: 4,
            leaf_index: u64::from(slot_index) + 1,
        },
        opening,
    }
}

fn page(
    audited: AuditedTransaction,
    nullifiers: Vec<[u8; 32]>,
) -> GetDecryptedTransactionsResponse {
    let withdrawal = RingWithdrawal {
        screened_owner: None,
        recipient: Address::new_from_array([10; 32]),
        asset: Address::new_from_array([4; 32]),
        amount: 5,
    };
    GetDecryptedTransactionsResponse {
        context: Context {
            block_time: 1,
            slot: 43,
        },
        value: DecryptedTransactionsPage {
            items: vec![ConfirmedAudit {
                audited,
                event_index: 7,
                nullifiers,
                spenders: Vec::new(),
                signers: vec![Address::new_from_array([13; 32])],
                withdrawals: vec![withdrawal],
            }
            .into()],
            skipped: vec![SkippedTransaction {
                slot: 40,
                tx_signature: Signature::from([14; 64]).into(),
                event_index: 8,
                reason: SkippedReason::MissingAuditorMessage,
            }],
            cursor: Some(vec![15].into()),
        },
    }
}

fn delivered_audited() -> AuditedTransaction {
    AuditedTransaction {
        tx_signature: Signature::from([1; 64]),
        slot: 42,
        tx_viewing_pk: ViewingKey::from_bytes(&[3; 32]).pubkey(),
        outputs: vec![
            output(
                0,
                OutputOpening::Ring {
                    utxo: utxo(0x10, Some(Address::new_from_array([4; 32]))),
                    owner_tag: RingOwnerTag([6; 32]),
                },
            ),
            output(1, OutputOpening::Exit(utxo(0x20, None))),
            output(2, OutputOpening::Dummy),
        ],
        payload_errors: vec![OutputPayloadError {
            slot_index: 3,
            kind: Commitment,
        }],
        real_inputs: 0,
        inputs: Vec::new(),
    }
}

/// The JSON clients parse, pinned byte for byte.
#[test]
fn a_decrypted_page_keeps_its_wire_json() {
    let mut page = page(delivered_audited(), vec![[12; 32]]);
    page.value.items[0].spenders = vec![[13; 32].into()];
    let json = serde_json::to_string(&page).expect("json");
    assert_eq!(json, include_str!("decrypted_page.json").trim_end());
    assert_eq!(
        serde_json::from_str::<GetDecryptedTransactionsResponse>(&json).expect("parses"),
        page
    );
}

/// The TypeScript decoder reads the same page.
#[test]
fn a_real_input_reads_apart_from_a_dummy() {
    let real = AuditedInput {
        nullifier: [12; 32],
        opening: InputOpening::Real,
    };
    let dummy = AuditedInput {
        nullifier: [11; 32],
        opening: InputOpening::Dummy,
    };
    let page = in_proof_page(real.clone(), dummy);
    let json = serde_json::to_string(&page).expect("json");
    assert_eq!(
        json,
        include_str!("decrypted_in_proof_page.json").trim_end()
    );
    let parsed: GetDecryptedTransactionsResponse = serde_json::from_str(&json).expect("parses");
    assert_eq!(parsed, page);
    let [read_real, read_dummy] = parsed.value.items[0].inputs.as_slice() else {
        panic!("two inputs")
    };
    assert_eq!(read_real.class, DecryptedInputClass::Note);
    assert_eq!(read_real.default_input, None);
    assert_eq!(read_dummy.class, DecryptedInputClass::Dummy);
    assert_eq!(
        DecryptedInput::from(AuditedInput {
            opening: InputOpening::Address,
            ..real.clone()
        })
        .class,
        DecryptedInputClass::Address
    );
    assert_ne!(
        DecryptedInput::from(real.clone()),
        DecryptedInput::from(AuditedInput {
            opening: InputOpening::Dummy,
            ..real
        })
    );
    let [transaction] = page.value.items.as_slice() else {
        panic!("one transaction")
    };
    let activity = WalletActivity::of(
        Address::new_from_array([13; 32]),
        transaction.clone(),
        |input| match input.class {
            DecryptedInputClass::Note => InputParty::Own,
            DecryptedInputClass::Address | DecryptedInputClass::Dummy => InputParty::Padding,
        },
    )
    .expect("a spender");
    let read: WalletActivity =
        serde_json::from_str(&serde_json::to_string(&activity).expect("json")).expect("parses");
    assert_eq!(read, activity);
    let WalletView::Sender { inputs, .. } = read.view else {
        panic!("the spender's view")
    };
    assert_eq!(inputs.len(), 1, "padding never reaches a wallet");
}

fn in_proof_page(real: AuditedInput, dummy: AuditedInput) -> GetDecryptedTransactionsResponse {
    let mut page = page(
        AuditedTransaction {
            real_inputs: 1,
            inputs: vec![real, dummy],
            ..delivered_audited()
        },
        vec![[12; 32], [11; 32]],
    );
    page.value.items[0].spenders = vec![[13; 32].into()];
    page
}

fn two_owner_transaction(wallet: Address) -> DecryptedTransaction {
    let mint = Some(Address::new_from_array([4; 32]));
    let mut transaction = page(
        AuditedTransaction {
            outputs: vec![
                output(
                    0,
                    OutputOpening::Ring {
                        utxo: utxo(0x10, mint),
                        owner_tag: RingOwnerTag([9; 32]),
                    },
                ),
                output(
                    1,
                    OutputOpening::Ring {
                        utxo: utxo(0x50, mint),
                        owner_tag: RingOwnerTag([8; 32]),
                    },
                ),
            ],
            payload_errors: vec![OutputPayloadError {
                slot_index: 2,
                kind: OutputPayloadErrorKind::Commitment,
            }],
            inputs: Vec::new(),
            ..delivered_audited()
        },
        Vec::new(),
    )
    .value
    .items
    .remove(0);
    transaction.spenders = vec![wallet.to_bytes().into()];
    let input = |seed: u8| {
        DecryptedInput::from(AuditedInput {
            nullifier: [seed; 32],
            opening: InputOpening::Real,
        })
    };
    transaction.inputs = vec![input(1), input(2), input(3)];
    transaction
}

fn sender_slots(view: WalletView) -> (Vec<Hash>, Vec<u32>) {
    let WalletView::Sender {
        inputs, outputs, ..
    } = view
    else {
        panic!("the spender's view")
    };
    (
        inputs.into_iter().map(|input| input.nullifier).collect(),
        outputs.iter().map(|output| output.slot_index).collect(),
    )
}

/// A public co-owner beside another owner reads its own notes and no marker.
#[test]
fn a_co_owner_reads_its_own_notes_alone() {
    let co_owner = Address::new_from_array([0x10; 32]);
    let activity =
        WalletActivity::of(co_owner, two_owner_transaction(co_owner), |input| {
            match input.nullifier == Hash::from([1; 32]) {
                true => InputParty::Own,
                false => InputParty::Other,
            }
        })
        .expect("a spender");
    assert_eq!(
        sender_slots(activity.view),
        (vec![Hash::from([1; 32])], vec![0])
    );
}

/// Every output of a sole owner is its own payment, padding counts as no other owner.
#[test]
fn a_wallet_owning_every_input_keeps_all_outputs_without_a_marker() {
    let owner = Address::new_from_array([0x10; 32]);
    let activity = WalletActivity::of(owner, two_owner_transaction(owner), |input| {
        match input.nullifier == Hash::from([3; 32]) {
            true => InputParty::Padding,
            false => InputParty::Own,
        }
    })
    .expect("a spender");
    assert_eq!(
        sender_slots(activity.view),
        (vec![Hash::from([1; 32]), Hash::from([2; 32])], vec![0, 1])
    );
}

#[test]
fn a_wallet_with_no_spent_input_reads_only_its_own_outputs() {
    let transaction = two_owner_transaction(Address::new_from_array([0x77; 32]));
    let read = |wallet: u8| {
        WalletActivity::of(
            Address::new_from_array([wallet; 32]),
            transaction.clone(),
            |_| InputParty::Other,
        )
    };
    assert!(matches!(
        read(0x10).expect("the output's owner").view,
        WalletView::Recipient { .. }
    ));
    assert_eq!(read(0x60), None);
}

fn anonymous_audited() -> AuditedTransaction {
    AuditedTransaction {
        tx_signature: Signature::from([1; 64]),
        slot: 42,
        tx_viewing_pk: ViewingKey::from_bytes(&[2; 32]).pubkey(),
        outputs: vec![
            output(
                0,
                OutputOpening::Ring {
                    utxo: AuditedUtxo {
                        data_hash: [0; 32],
                        ring_data_hash: [0; 32],
                        ..utxo(0x10, Some(Address::new_from_array([4; 32])))
                    },
                    owner_tag: RingOwnerTag([0x31; 32]),
                },
            ),
            output(1, OutputOpening::Exit(utxo(0x20, None))),
            output(2, OutputOpening::Dummy),
        ],
        payload_errors: Vec::new(),
        real_inputs: 3,
        inputs: vec![
            AuditedInput {
                nullifier: [12; 32],
                opening: InputOpening::Real,
            },
            AuditedInput {
                nullifier: [11; 32],
                opening: InputOpening::External(Box::new(entry_input(0x60))),
            },
            AuditedInput {
                nullifier: [10; 32],
                opening: InputOpening::External(Box::new(entry_input(0x70))),
            },
            AuditedInput {
                nullifier: [9; 32],
                opening: InputOpening::Dummy,
            },
        ],
    }
}

fn anonymous_page() -> GetDecryptedTransactionsResponse {
    page(
        anonymous_audited(),
        vec![[12; 32], [11; 32], [10; 32], [9; 32]],
    )
}

/// The TypeScript decoder reads the same page.
#[test]
fn an_anonymous_decrypted_page_keeps_its_wire_json() {
    let page = anonymous_page();
    let json = serde_json::to_string(&page).expect("json");
    assert_eq!(
        json,
        include_str!("decrypted_anonymous_page.json").trim_end()
    );
    assert_eq!(
        serde_json::from_str::<GetDecryptedTransactionsResponse>(&json).expect("parses"),
        page
    );
}

/// The TypeScript decoder reads both views of the anonymous page.
#[test]
fn a_wallet_activity_page_keeps_its_wire_json() {
    let page = anonymous_page();
    let [transaction] = page.value.items.as_slice() else {
        panic!("one transaction")
    };
    let view = |wallet: u8| {
        WalletActivity::of(
            Address::new_from_array([wallet; 32]),
            transaction.clone(),
            |_| InputParty::Own,
        )
        .expect("a party")
    };
    let recipient = WalletActivity::of(
        Address::new_from_array([0x10; 32]),
        transaction.clone(),
        |_| InputParty::Other,
    )
    .expect("the output's owner");
    let activity = GetWalletActivityResponse {
        context: page.context,
        value: WalletActivityPage {
            items: vec![view(0x50), recipient],
            cursor: page.value.cursor.clone(),
        },
    };
    let json = serde_json::to_string(&activity).expect("json");
    assert_eq!(json, include_str!("wallet_activity_page.json").trim_end());
    assert_eq!(
        serde_json::from_str::<GetWalletActivityResponse>(&json).expect("parses"),
        activity
    );
}

/// The TypeScript decoder reads the same vector, `UPDATE_RING_VECTORS=1` rewrites it.
#[test]
fn payload_errors_keep_the_encoding_of_the_shared_vector() {
    // A new kind fails to compile here, `kinds` and the vector must then name it.
    let named = |kind: OutputPayloadErrorKind| match kind {
        Disclosure | Commitment => kind,
    };
    let kinds = [Disclosure, Commitment].map(named);
    let slots = [(2, Commitment), (5, Disclosure)]
        .map(|(slot_index, kind)| DecryptedPayloadError { slot_index, kind });
    let written = serde_json::json!({
        "description": "Payload errors of a DecryptedTransaction as the ring rpc serializes them. kinds names every OutputPayloadErrorKind. commitment_and_disclosure holds the errors of one transfer whose slot 2 record opens to another commitment and whose slot 5 record holds a value outside the field. Written by the sdk-libs/client rpc tests and decoded by the TypeScript RingRpc tests.",
        "kinds": kinds,
        "commitment_and_disclosure": slots,
    });
    if std::env::var_os("UPDATE_RING_VECTORS").is_some() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/rpc/ring_rpc_payload_errors.json"
        );
        let pretty = serde_json::to_string_pretty(&written).expect("json");
        std::fs::write(path, pretty + "\n").expect("vector");
        return;
    }
    let stored: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/ring_rpc_payload_errors.json"
    ))
    .expect("vector");
    assert_eq!(written, stored);
}

#[test]
fn a_signed_read_carries_the_reader_and_the_bounds_it_signed() {
    let reader = Keypair::new();
    let request = GetDecryptedTransactionsRequest::read(target())
        .with_cursor(vec![1].into())
        .expect("cursor")
        .with_limit(Limit::new(5).expect("limit"))
        .expect("limit")
        .at(1_700_000_000)
        .sign(&reader)
        .expect("signed");
    assert_eq!(
        request.auth.reader.0,
        ReaderKey::ed25519(reader.pubkey())
            .expect("reader")
            .to_bytes()
            .to_vec()
    );
    let message = ReadAttestation {
        read: PagedRead::DecryptedTransactions,
        target: target(),
        cursor: request.cursor.clone(),
        limit: request.limit.clone(),
        wallet: None,
    }
    .message(
        1_700_000_000,
        &request.auth.nonce.0.clone().try_into().expect("nonce"),
    );
    let signature = Signature::try_from(request.auth.signature.0.as_slice()).expect("signature");
    assert!(signature.verify(reader.pubkey().as_ref(), &message));
    assert!(matches!(
        GetDecryptedTransactionsRequest::read(target()).with_cursor(Vec::new().into()),
        Err(ReadBuildError::Cursor)
    ));
}

#[test]
fn keygen_writes_a_secret_the_loader_reads_and_a_matching_public_key() {
    let dir = temp_dir("keygen");
    let secret = dir.join("auditor.key");
    let key = write_auditor_key(&secret).expect("keygen");
    assert_eq!(
        read_auditor_key(&secret, Access::OwnerOnly)
            .expect("load")
            .pubkey(),
        key.pubkey()
    );
    let public_path = public_key_path(&secret).expect("public path");
    assert_eq!(
        std::fs::read_to_string(&public_path).expect("pub file"),
        hex::encode(key.pubkey().as_bytes())
    );
    assert_eq!(
        read_auditor_pubkey(&public_path).expect("pubkey"),
        key.pubkey()
    );
    assert!(matches!(
        write_auditor_key(&secret),
        Err(KeyFileError::File(SecretFileError::Write { .. }))
    ));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn public_key_files_round_trip_and_reject_other_lengths() {
    let dir = temp_dir("pubkey");
    let path = dir.join("nested").join("auditor.key.pub");
    let key = X25519Keypair::new();
    write_auditor_pubkey(&path, &key.pubkey()).expect("write");
    assert_eq!(read_auditor_pubkey(&path).expect("read"), key.pubkey());
    let short = dir.join("short.pub");
    std::fs::write(&short, "02ab").expect("short");
    assert!(matches!(
        read_auditor_pubkey(&short),
        Err(KeyFileError::PubkeyEncoding)
    ));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn malformed_and_zero_auditor_secrets_are_refused() {
    let dir = temp_dir("zero");
    let zero = dir.join("zero.key");
    create_new(&zero, "00".repeat(32).as_bytes(), Visibility::Secret).expect("zero");
    assert!(matches!(
        read_auditor_key(&zero, Access::OwnerOnly),
        Err(KeyFileError::ZeroAuditorKey)
    ));
    let upper = dir.join("upper.key");
    create_new(&upper, "AA".repeat(32).as_bytes(), Visibility::Secret).expect("upper");
    assert!(matches!(
        read_auditor_key(&upper, Access::OwnerOnly),
        Err(KeyFileError::File(SecretFileError::Hex))
    ));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

fn small_field(value: u8) -> [u8; 32] {
    let mut field = [0; 32];
    field[31] = value;
    field
}

/// An audited notes answer is used only where each opening rebuilds the hash it answers.
#[test]
fn audited_utxos_are_used_only_when_they_rebuild_their_hashes() {
    let ring = Address::new_from_array([7; 32]);
    let mint = Address::new_from_array([3; 32]);
    let keyed = KnownUtxo {
        owner_key: [0xa1; 32],
        owner: UtxoOwner::Keyed {
            nullifier_pk: small_field(5),
        },
        asset: spr_hasher::primitives::hash_bytes(mint.as_array()).unwrap(),
        mint: Some(mint),
        amount: 40,
        blinding: small_field(6),
        data_hash: [0; 32],
        ring_data_hash: [0; 32],
        tree_id: 3,
    };
    let second = KnownUtxo {
        owner: UtxoOwner::Keyed {
            nullifier_pk: small_field(9),
        },
        amount: 12,
        ..keyed
    };
    let hashes = [keyed, second].map(|utxo| utxo.commitment(Some(ring)).unwrap());
    let hash = |index: usize| Hash(hashes[index]);
    let view = |utxo: KnownUtxo, utxo_hash: Hash| AuditedUtxoView {
        utxo_hash,
        utxo: utxo.into(),
        slot: 1,
        tx_signature: Signature::default().into(),
        event_index: 0,
        slot_index: 0,
    };
    let answer = |utxos: Vec<Option<AuditedUtxoView>>| GetAuditedUtxosResponse {
        context: Context {
            slot: 1,
            block_time: 0,
        },
        value: AuditedUtxosPage { utxos },
    };
    let full = answer(vec![
        Some(view(keyed, hash(0))),
        Some(view(second, hash(1))),
        None,
    ]);
    let known = full
        .known_utxos(ring, &[hash(0), hash(1), Hash([4; 32])])
        .unwrap();
    assert_eq!(
        known,
        HashMap::from([(hashes[0], keyed), (hashes[1], second)])
    );
    let tampered = answer(vec![Some(view(
        KnownUtxo {
            amount: 41,
            ..keyed
        },
        hash(0),
    ))]);
    assert!(matches!(
        tampered.known_utxos(ring, &[hash(0)]),
        Err(AuditError::AuditedUtxoMismatch { .. })
    ));
    let pair = answer(vec![
        Some(view(keyed, hash(0))),
        Some(view(second, hash(1))),
    ]);
    assert!(matches!(
        pair.known_utxos(ring, &[hash(1), hash(0)]),
        Err(AuditError::AuditedUtxoMismatch { .. })
    ));
    assert!(matches!(
        full.known_utxos(ring, &[hash(0), hash(1)]),
        Err(AuditError::AuditedUtxosCount { got: 3, want: 2 })
    ));
}

/// The TypeScript encoder writes the same bytes.
#[test]
fn a_relay_request_serializes_to_the_shared_vector() {
    #[derive(Deserialize)]
    struct Vector {
        wire: String,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/relay_request.json"
    ))
    .expect("vector");
    let request = PrepareRelayRequest {
        ring: Address::new_from_array([1; 32]).into(),
        quote: RelayQuote {
            fee_payer: Address::new_from_array([2; 32]).into(),
            valid_until_slot: 4242,
        },
        intent: RelayIntent::Anonymous {
            proof_inputs: ProofInputBytes::new(zeroize::Zeroizing::new(vec![3, 4, 5])),
            owner_signature: Signature::from([7; 64]).into(),
            token_account_setup: Vec::new(),
        },
        co_signers: Vec::new(),
    };
    assert_eq!(serde_json::to_string(&request).expect("json"), vector.wire);
    let read: PrepareRelayRequest = serde_json::from_str(&vector.wire).expect("read");
    assert_eq!(read.intent.operation(), RelayOperation::Anonymous);
}

fn signed_wallet_update() -> SubmitRecordUpdateRequest {
    let wallet = Keypair::new_from_array([7; 32]);
    let identity = Hash(
        *zolana_ring_policy::Member::owner_tag(wallet.pubkey().as_array())
            .expect("wallet")
            .as_bytes(),
    );
    let reader = Hash(*passkey_reader().member().expect("reader").as_bytes());
    let bit = zolana_ring_policy::ListId::RingViewing.record_bit();
    RecordUpdate {
        genesis_hash: Hash([3; 32]),
        ring: Address::new_from_array([1; 32]).into(),
        entries: vec![
            RecordUpdateEntry::Write(zolana_ring_indexer::rpc::RingListWriteView {
                mint_policy: None,
                member: identity.clone(),
                mask: bit,
                value: bit,
            }),
            RecordUpdateEntry::WalletGrant(WalletGrant {
                wallet: identity,
                reader,
                access: ReaderAccess::Granted,
            }),
        ],
        valid_until_slot: 4242,
        awaited_lists: 0,
    }
    .sign(Address::new_from_array([2; 32]), &wallet)
    .expect("sign")
}

/// The TypeScript signer writes the same wire bytes.
#[test]
fn a_signed_wallet_update_verifies_from_the_shared_vector() {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        wire: String,
        update_id: RecordUpdateId,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/record_update.json"
    ))
    .expect("vector");
    let signed = signed_wallet_update();
    assert_eq!(serde_json::to_string(&signed).expect("json"), vector.wire);
    let read: SubmitRecordUpdateRequest = serde_json::from_str(&vector.wire).expect("read");
    assert_eq!(read.verify(), Ok(vector.update_id));
    // The signature covers the slot bound, a later one names another statement.
    let mut extended = read;
    extended.update.valid_until_slot += 1;
    assert_eq!(extended.verify(), Err(RecordUpdateError::Signature));
}

/// Keeps each description, regenerates what the signer writes.
#[test]
#[ignore]
fn write_record_update_vectors() {
    for (name, signed) in [
        ("record_update.json", signed_wallet_update()),
        (
            "list_approval_update.json",
            signed_update_pending_approval(),
        ),
    ] {
        let path = format!(
            "{}/../../test-vectors/rpc/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut vector: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("vector");
        vector["wire"] = serde_json::to_string(&signed).expect("json").into();
        vector["updateId"] = serde_json::to_value(signed.verify().expect("verify")).expect("id");
        let json = serde_json::to_string_pretty(&vector).expect("json") + "\n";
        std::fs::write(&path, json).expect("write");
    }
}

/// A spend of `owner`, its hash and nullifier under its own key.
fn relay_spend(
    owner: &ShieldedKeypair,
    ring: Address,
    blinding: [u8; 32],
) -> spr_transaction::utxo::SppProofInputUtxo {
    let address = owner.shielded_address().expect("address");
    let utxo = spr_transaction::Utxo {
        owner: address.signing_pubkey,
        asset: spr_transaction::Mint::SOL,
        amount: 900,
        blinding,
        ring_program_id: Some(ring),
        data: spr_transaction::Data::default(),
    };
    let utxo_hash = utxo
        .hash(&address.nullifier_pubkey, &[0; 32], &[0; 32], 4)
        .expect("hash");
    spr_transaction::utxo::SppProofInputUtxo {
        address: false,
        nullifier: owner
            .nullifier_key
            .nullifier(&utxo_hash, &utxo.blinding)
            .expect("nullifier"),
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash,
        data_hash: None,
        ring_data_hash: None,
        tree_id: 4,
        leaf_index: 17,
        cache_slot: None,
        compact: false,
    }
}

fn relay_proof_inputs() -> RelayProofInputs {
    use spr_event::MessageData;
    use spr_instruction::instruction::{
        TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    };
    use spr_interface::{
        instruction::instruction_data::transact::{OwnerTag, TransactOutput},
        MAX_OUTPUTS,
    };
    use spr_keypair::{NullifierKey, ShieldedKeypair, SigningKey, X25519Keypair};
    use spr_transaction::{
        instructions::transact::{ExternalData, SettlementTransfer},
        utxo::SppProofInputUtxo,
        Mint, SppProofOutputUtxo,
    };
    use zolana_ring_transaction::AnonymousPlan;
    let owner =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[5; 32])).expect("owner");
    let sender = owner.shielded_address().expect("address");
    let ring = Address::new_from_array([6; 32]);
    let spend = relay_spend(&owner, ring, [11; 32]);
    let change = SppProofOutputUtxo {
        asset: Mint::SOL,
        amount: 800,
        blinding: [12; 32],
        ring_program_id: Some(ring),
        owner_address: Some(sender),
        ..SppProofOutputUtxo::default()
    };
    let tx_viewing_key = ViewingKey::from_secret_key(X25519Keypair::from_bytes(&[13; 32]));
    let recipient = Address::new_from_array([14; 32]);
    let external_data = ExternalData {
        interface_transfers: vec![SettlementTransfer::Sol {
            is_deposit: false,
            amount: 100,
            user_sol_account: recipient,
        }],
        ..ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            [15; 16],
            vec![TransactOutput {
                utxo_hash: [16; 32],
                owner_tag: OwnerTag::Inline([17; 32]),
                data: Some(vec![18, 19]),
            }],
            vec![[20; 32]],
            vec![MessageData {
                view_tag: [21; 32],
                data: vec![22],
            }],
        )
    };
    RelayProofInputs {
        rail: RelayRail::Anonymous {
            plan: Box::new(AnonymousPlan::from_parts(
                vec![owner.viewing_pubkey()],
                [[25; 32]; MAX_OUTPUTS],
            )),
            exit_token_owner: None,
        },
        ring_program_id: ring,
        nullifier_key: NullifierKey::from_secret(*owner.nullifier_key.secret()),
        sender,
        tx_viewing_key,
        inputs: vec![
            spend,
            SppProofInputUtxo::dummy_with_blinding([27; 32], 4).expect("dummy"),
        ],
        outputs: vec![change],
        external_data,
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient },
        )],
        blinding_seed: [28; 32],
        output_tree_id: 4,
        list_salts: Vec::new(),
        co_owners: Vec::new(),
        approval_blinder: None,
        wide_owners: false,
    }
}

fn pinned(file: &str, pointer: &str, actual: &str, expected: &str) {
    if std::env::var_os("UPDATE_RING_VECTORS").is_none() {
        assert_eq!(actual, expected, "{pointer}");
        return;
    }
    let path = format!(
        "{}/../../test-vectors/rpc/{file}",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("vector")).expect("json");
    *stored.pointer_mut(pointer).expect("field") = actual.into();
    let pretty = serde_json::to_string_pretty(&stored).expect("json");
    std::fs::write(path, pretty + "\n").expect("vector");
}

/// `UPDATE_RING_VECTORS=1` rewrites the payload.
#[test]
fn relay_proof_inputs_encode_to_the_shared_vector() {
    let inputs = relay_proof_inputs();
    if std::env::var_os("UPDATE_RING_VECTORS").is_some() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/rpc/relay_proof_inputs.json"
        );
        let mut stored: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("vector")).expect("json");
        let encoded = Base64String::from(inputs.encode().expect("encode").to_vec());
        stored["proofInputs"] = serde_json::to_value(encoded).expect("base64");
        std::fs::write(
            path,
            serde_json::to_string_pretty(&stored).expect("json") + "\n",
        )
        .expect("vector");
    }
    let vector: PayloadVector = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/rpc/relay_proof_inputs.json"
        ))
        .expect("vector"),
    )
    .expect("vector");
    assert_eq!(*inputs.encode().expect("encode"), vector.proof_inputs.0);
    let read = RelayProofInputs::decode(&vector.proof_inputs.0).expect("decode");
    assert_eq!(read.inputs, inputs.inputs);
    assert_eq!(read.outputs, inputs.outputs);
    assert_eq!(read.external_data, inputs.external_data);
    assert_eq!(read.rail.operation(), RelayOperation::Anonymous);
}

fn co_owner_keys() -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[40; 32])).expect("co-owner")
}

fn relay_co_owner(keys: &ShieldedKeypair) -> RelayCoOwner {
    let signing = keys.shielded_address().expect("address").signing_pubkey;
    RelayCoOwner {
        owner: Address::new_from_array(signing.as_ed25519().expect("ed25519")),
        nullifier_key: nullifier_key_of(keys),
    }
}

fn nullifier_key_of(keys: &ShieldedKeypair) -> spr_keypair::NullifierKey {
    spr_keypair::NullifierKey::from_secret(*keys.nullifier_key.secret())
}

/// `relay_proof_inputs` with a co-owner's note at input 1 and every term the owner sealed.
fn co_owned_relay_proof_inputs() -> RelayProofInputs {
    let keys = co_owner_keys();
    let mut inputs = relay_proof_inputs();
    inputs.inputs[1] = relay_spend(&keys, inputs.ring_program_id, [41; 32]);
    inputs.co_owners = vec![relay_co_owner(&keys)];
    inputs.approval_blinder = Some([42; 32]);
    inputs.list_salts = vec![SubjectListSalt {
        member: [43; 32],
        list_salt: [44; 32],
    }];
    inputs.wide_owners = true;
    inputs
}

#[test]
fn relay_proof_inputs_rederive_a_co_owners_spend_and_carry_the_sealed_terms() {
    let inputs = co_owned_relay_proof_inputs();
    let read = RelayProofInputs::decode(&inputs.encode().expect("encode")).expect("decode");
    assert_eq!(read.inputs, inputs.inputs);
    assert_eq!(read.approval_blinder, Some([42; 32]));
    assert!(read.wide_owners);
    assert!(read.list_salts == inputs.list_salts);
    let [co_owner] = read.co_owners.as_slice() else {
        panic!("one co-owner");
    };
    assert_eq!(co_owner.owner, inputs.co_owners[0].owner);
    assert_eq!(
        co_owner.nullifier_key.secret(),
        co_owner_keys().nullifier_key.secret()
    );
}

#[test]
fn relay_proof_inputs_refuse_to_encode_what_the_service_cannot_prove() {
    let refused = |change: fn(&mut RelayProofInputs)| {
        let mut inputs = co_owned_relay_proof_inputs();
        change(&mut inputs);
        inputs.encode().expect_err("refused")
    };
    assert!(matches!(
        refused(|inputs| inputs.nullifier_key = nullifier_key_of(&co_owner_keys())),
        RelayProofInputsError::NullifierKey
    ));
    assert!(matches!(
        refused(|inputs| inputs.co_owners.clear()),
        RelayProofInputsError::Input { index: 1 }
    ));
    assert!(matches!(
        refused(|inputs| inputs.co_owners[0].nullifier_key = inputs.nullifier_key.clone()),
        RelayProofInputsError::Input { index: 1 }
    ));
    assert!(matches!(
        refused(|inputs| inputs.inputs[0].cache_slot = Some(0)),
        RelayProofInputsError::Input { index: 0 }
    ));
    assert!(matches!(
        refused(|inputs| inputs.outputs[0].cache_slot = Some(0)),
        RelayProofInputsError::CachedOutput { index: 0 }
    ));
    assert!(matches!(
        refused(|inputs| inputs.interface_transfer_accounts.clear()),
        RelayProofInputsError::Settlement { index: 0 }
    ));
    assert!(matches!(
        refused(|inputs| {
            inputs.external_data.interface_transfers = vec![
                spr_transaction::instructions::transact::SettlementTransfer::Sol {
                    is_deposit: true,
                    amount: 100,
                    user_sol_account: Address::new_from_array([15; 32]),
                },
            ];
        }),
        RelayProofInputsError::Settlement { index: 0 }
    ));
}

/// A relay decodes bytes from outside, so each check holds without the encoder.
#[test]
fn relay_proof_inputs_refuse_forged_bytes() {
    let inputs = co_owned_relay_proof_inputs();
    let encoded = inputs.encode().expect("encode");
    // The owner's last site is the co-owner list, its first is the spend naming it.
    let swapped = |from: &[u8], to: &[u8]| {
        let site = encoded
            .windows(from.len())
            .rposition(|window| window == from)
            .expect("site");
        let mut forged = encoded.to_vec();
        forged[site..site + from.len()].copy_from_slice(to);
        forged
    };
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(matches!(
        RelayProofInputs::decode(&trailing).err().expect("refused"),
        RelayProofInputsError::Decode(_)
    ));
    assert!(matches!(
        RelayProofInputs::decode(&encoded[..encoded.len() - 1])
            .err()
            .expect("refused"),
        RelayProofInputsError::Decode(_)
    ));
    let other_key = swapped(
        &inputs.nullifier_key.secret()[..],
        &co_owner_keys().nullifier_key.secret()[..],
    );
    assert!(matches!(
        RelayProofInputs::decode(&other_key).err().expect("refused"),
        RelayProofInputsError::NullifierKey
    ));
    let unnamed = swapped(inputs.co_owners[0].owner.as_array(), &[45; 32]);
    assert!(matches!(
        RelayProofInputs::decode(&unnamed).err().expect("refused"),
        RelayProofInputsError::NullifierKey
    ));
}

#[test]
fn relay_merge_inputs_refuse_a_note_the_sender_does_not_own() {
    let spends = relay_proof_inputs();
    let foreign = relay_spend(&co_owner_keys(), spends.ring_program_id, [41; 32]);
    let refused = RelayMergeInputs {
        ring_program_id: spends.ring_program_id,
        sender: spends.sender,
        nullifier_key: spends.nullifier_key.clone(),
        inputs: vec![spr_transaction::WalletUtxo {
            utxo: foreign.utxo,
            nullifier_pubkey: foreign.nullifier_pubkey,
            utxo_hash: foreign.utxo_hash,
            nullifier: foreign.nullifier,
            tx_viewing_key: None,
            data_hash: None,
            ring_data_hash: None,
            tree_id: foreign.tree_id,
            leaf_index: foreign.leaf_index,
            latest_tree_id: None,
            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        }],
    }
    .encode()
    .expect_err("refused");
    assert!(matches!(
        refused,
        RelayProofInputsError::MergeInput { index: 0 }
    ));
}

#[test]
fn token_account_setup_names_only_a_withdrawals_associated_account_once() {
    use spr_instruction::instruction::{
        CreateAssociatedTokenAccount, TransactInterfaceTransferAccounts,
        TransactSplWithdrawalAccounts,
    };
    let payer = Address::new_from_array([50; 32]);
    let owner = Address::new_from_array([51; 32]);
    let mint = Address::new_from_array([52; 32]);
    let token_program = Address::new_from_array([54; 32]);
    let mut inputs = relay_proof_inputs();
    inputs.interface_transfer_accounts = vec![TransactInterfaceTransferAccounts::SplWithdrawal(
        TransactSplWithdrawalAccounts {
            mint,
            spl_interface: Address::new_from_array([53; 32]),
            user_token_account: CreateAssociatedTokenAccount {
                payer,
                owner,
                mint,
                token_program,
            }
            .address(),
            token_program,
        },
    )];
    let setup = |owner: Address, mint: Address| TokenAccountSetup {
        owner: owner.into(),
        mint: mint.into(),
    };
    let created = inputs
        .token_account_setup(payer, &[setup(owner, mint)])
        .expect("setup");
    assert_eq!(created.len(), 1);
    let refused = |entries: &[TokenAccountSetup]| inputs.token_account_setup(payer, entries).err();
    let no_withdrawal = Some(TokenAccountSetupError::NoWithdrawal { index: 0 });
    assert_eq!(refused(&[setup(payer, mint)]), no_withdrawal);
    assert_eq!(refused(&[setup(owner, payer)]), no_withdrawal);
    assert_eq!(
        refused(&[setup(owner, mint), setup(owner, mint)]),
        Some(TokenAccountSetupError::Repeated { index: 1 })
    );
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PayloadVector {
    proof_inputs: Base64String,
}

fn shielded_address(seed: u8) -> ShieldedAddress {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
        .expect("keypair")
        .shielded_address()
        .expect("address")
}

/// `relay_proof_inputs` on the deposit rail, every input a dummy. `UPDATE_RING_VECTORS=1` rewrites the payload.
#[test]
fn relay_deposit_inputs_encode_to_the_shared_vector() {
    let mut inputs = relay_proof_inputs();
    inputs.rail = RelayRail::Deposit {
        plan: Some(Box::new(
            zolana_ring_transaction::AnonymousPlan::from_parts(
                Vec::new(),
                [[25; 32]; spr_interface::MAX_OUTPUTS],
            ),
        )),
    };
    inputs.inputs = vec![
        spr_transaction::utxo::SppProofInputUtxo::dummy_with_blinding([29; 32], 4).expect("dummy"),
        spr_transaction::utxo::SppProofInputUtxo::dummy_with_blinding([27; 32], 4).expect("dummy"),
    ];
    let encoded = Base64String::from(inputs.encode().expect("encode").to_vec());
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/rpc/relay_deposit_proof_inputs.json"
    );
    if std::env::var_os("UPDATE_RING_VECTORS").is_some() {
        let stored = serde_json::json!({
            "description": "relay_proof_inputs.json on the deposit rail (RailWire tag 3) with an anonymous plan of no payment, its inputs two dummies of blindings 0x1d and 0x1b in tree 4. Pinned by the sdk-libs/client rpc tests.",
            "proofInputs": encoded,
        });
        std::fs::write(
            path,
            serde_json::to_string_pretty(&stored).expect("json") + "\n",
        )
        .expect("vector");
    }
    let vector: PayloadVector =
        serde_json::from_str(&std::fs::read_to_string(path).expect("vector")).expect("vector");
    assert_eq!(*inputs.encode().expect("encode"), vector.proof_inputs.0);
    let read = RelayProofInputs::decode(&vector.proof_inputs.0).expect("decode");
    assert_eq!(read.inputs, inputs.inputs);
    assert_eq!(read.rail.operation(), RelayOperation::Deposit);
}

/// The TypeScript encoder writes the same merge payload.
#[test]
fn relay_merge_inputs_encode_to_the_shared_vector() {
    let vector: PayloadVector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/relay_merge_inputs.json"
    ))
    .expect("vector");
    let spends = relay_proof_inputs();
    let spend = &spends.inputs[0];
    let inputs = RelayMergeInputs {
        ring_program_id: spends.ring_program_id,
        sender: spends.sender,
        nullifier_key: spends.nullifier_key.clone(),
        inputs: vec![spr_transaction::WalletUtxo {
            utxo: spend.utxo.clone(),
            nullifier_pubkey: spend.nullifier_pubkey,
            utxo_hash: spend.utxo_hash,
            nullifier: spend.nullifier,
            tx_viewing_key: None,
            data_hash: None,
            ring_data_hash: None,
            tree_id: spend.tree_id,
            leaf_index: spend.leaf_index,
            latest_tree_id: None,
            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        }],
    };
    let encoded = inputs.encode().expect("encode");
    let text = |bytes: &[u8]| {
        serde_json::to_value(Base64String::from(bytes.to_vec()))
            .expect("base64")
            .as_str()
            .expect("text")
            .to_owned()
    };
    pinned(
        "relay_merge_inputs.json",
        "/proofInputs",
        &text(&encoded),
        &text(&vector.proof_inputs.0),
    );
    let read = RelayMergeInputs::decode(&encoded).expect("decode");
    assert_eq!(read.inputs[0].nullifier, spend.nullifier);
}

/// The TypeScript signer writes the same message and wire bytes.
#[test]
fn a_signed_authority_transfer_matches_the_shared_vector() {
    #[derive(Deserialize)]
    struct Vector {
        message: String,
        wire: String,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/authority_transfer.json"
    ))
    .expect("vector");
    let delegate = Keypair::new_from_array([8; 32]);
    let attestation = AuthorityTransferAttestation {
        target: target(),
        delegate: delegate.pubkey(),
        transfer: AuthorityTransfer {
            exits: vec![AuthorityPayment {
                recipient: shielded_address(10).into(),
                mint: Address::new_from_array([3; 32]).into(),
                amount: 20,
            }],
            withdrawals: vec![
                super::AuthorityWithdrawal {
                    recipient: Address::new_from_array([11; 32]).into(),
                    mint: Address::new_from_array([3; 32]).into(),
                    amount: 30,
                    token_program: Some(
                        Address::new_from_array(spr_interface::SPL_TOKEN_PROGRAM_ID).into(),
                    ),
                },
                super::AuthorityWithdrawal {
                    recipient: Address::new_from_array([12; 32]).into(),
                    mint: spr_transaction::SOL_MINT.into(),
                    amount: 40,
                    token_program: None,
                },
            ],
            sources: vec![shielded_address(5).into()],
            payments: vec![AuthorityPayment {
                recipient: shielded_address(9).into(),
                mint: Address::new_from_array([3; 32]).into(),
                amount: 250,
            }],
        },
    };
    let message = attestation.message(1_700_000_000, &[4; 32]);
    let file = "authority_transfer.json";
    pinned(
        file,
        "/message",
        &String::from_utf8(message).expect("utf8"),
        &vector.message,
    );
    let signed = SignedRequest {
        attestation,
        timestamp: Some(1_700_000_000),
        nonce: [4; 32],
    }
    .sign(&delegate, &spr_keypair::ViewingKey::from_bytes(&[6; 32]))
    .expect("sign");
    let wire = serde_json::to_string(&signed).expect("json");
    pinned(file, "/wire", &wire, &vector.wire);
}

fn signed_update_pending_approval() -> SubmitRecordUpdateRequest {
    let wallet = Keypair::new_from_array([7; 32]);
    let identity = Hash(
        *zolana_ring_policy::Member::owner_tag(wallet.pubkey().as_array())
            .expect("wallet")
            .as_bytes(),
    );
    let bit = zolana_ring_policy::ListId::RingViewing.record_bit();
    RecordUpdate {
        genesis_hash: Hash([3; 32]),
        ring: Address::new_from_array([1; 32]).into(),
        entries: vec![RecordUpdateEntry::Write(
            zolana_ring_indexer::rpc::RingListWriteView {
                mint_policy: None,
                member: identity,
                mask: bit,
                value: bit,
            },
        )],
        valid_until_slot: 4242,
        awaited_lists: zolana_ring_policy::ListId::Allow.record_bit(),
    }
    .sign(Address::new_from_array([2; 32]), &wallet)
    .expect("sign")
}

/// The TypeScript signer writes the same wire bytes.
#[test]
fn a_signed_update_pending_approval_verifies_from_the_shared_vector() {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        wire: String,
        update_id: RecordUpdateId,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/list_approval_update.json"
    ))
    .expect("vector");
    let signed = signed_update_pending_approval();
    assert_eq!(serde_json::to_string(&signed).expect("json"), vector.wire);
    let read: SubmitRecordUpdateRequest = serde_json::from_str(&vector.wire).expect("read");
    assert_eq!(read.verify(), Ok(vector.update_id));
    // A signature pending list approval never verifies as a plain update.
    let mut plain = read;
    plain.update.awaited_lists = 0;
    assert_eq!(plain.verify(), Err(RecordUpdateError::Signature));
}

/// The TypeScript signers write the same messages and wire bytes.
#[test]
fn the_policy_authority_requests_match_the_shared_vector() {
    #[derive(Deserialize)]
    struct Signed {
        message: String,
        wire: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Refuse {
        update_id: RecordUpdateId,
        message: String,
        wire: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        list: Signed,
        list_after: Signed,
        refuse: Refuse,
        create_records: Signed,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/policy_authority_attestation.json"
    ))
    .expect("vector");
    let authority = Keypair::new_from_array([8; 32]);
    let list = PolicyAuthorityAttestation {
        target: target(),
        authority: authority.pubkey(),
        action: ListPendingApprovals {
            registry: Address::new_from_array([2; 32]),
            cursor: None,
        },
    };
    let refuse = PolicyAuthorityAttestation {
        target: target(),
        authority: authority.pubkey(),
        action: RefuseListApproval {
            registry: Address::new_from_array([2; 32]),
            update_id: vector.refuse.update_id.clone(),
        },
    };
    let list_after = GetPendingListApprovalsRequest::read(ListApprovalScope {
        target: target(),
        authority: authority.pubkey(),
        registry: Address::new_from_array([2; 32]),
    })
    .with_cursor(vector.refuse.update_id.clone());
    let message = |bytes: Vec<u8>| String::from_utf8(bytes).expect("utf8");
    let file = "policy_authority_attestation.json";
    pinned(
        file,
        "/listAfter/message",
        &message(list_after.attestation.message(1_700_000_000, &[4; 32])),
        &vector.list_after.message,
    );
    let list_after = SignedRequest {
        timestamp: Some(1_700_000_000),
        nonce: [4; 32],
        ..list_after
    }
    .sign(&authority)
    .expect("sign the second page");
    pinned(
        file,
        "/listAfter/wire",
        &serde_json::to_string(&list_after).expect("json"),
        &vector.list_after.wire,
    );
    pinned(
        file,
        "/list/message",
        &message(list.message(1_700_000_000, &[4; 32])),
        &vector.list.message,
    );
    pinned(
        file,
        "/refuse/message",
        &message(refuse.message(1_700_000_000, &[4; 32])),
        &vector.refuse.message,
    );
    let list = SignedRequest {
        attestation: list,
        timestamp: Some(1_700_000_000),
        nonce: [4; 32],
    }
    .sign(&authority)
    .expect("sign list");
    let refuse = SignedRequest {
        attestation: refuse,
        timestamp: Some(1_700_000_000),
        nonce: [4; 32],
    }
    .sign(&authority)
    .expect("sign refusal");
    pinned(
        file,
        "/list/wire",
        &serde_json::to_string(&list).expect("json"),
        &vector.list.wire,
    );
    pinned(
        file,
        "/refuse/wire",
        &serde_json::to_string(&refuse).expect("json"),
        &vector.refuse.wire,
    );
    let create_records = CreateRecordsRegistryRequest::create(target(), authority.pubkey());
    pinned(
        file,
        "/createRecords/message",
        &message(create_records.attestation.message(1_700_000_000, &[4; 32])),
        &vector.create_records.message,
    );
    let create_records = SignedRequest {
        timestamp: Some(1_700_000_000),
        nonce: [4; 32],
        ..create_records
    }
    .sign(&authority)
    .expect("sign the records request");
    pinned(
        file,
        "/createRecords/wire",
        &serde_json::to_string(&create_records).expect("json"),
        &vector.create_records.wire,
    );
}

/// The P-256 generator, a passkey reader the shared vectors name.
fn passkey_reader() -> ReaderKey {
    let key = hex::decode("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
        .expect("hex");
    ReaderKey::p256(
        crate::P256ReaderKey::from_bytes(key.try_into().expect("33 bytes")).expect("on curve"),
    )
    .expect("passkey")
}

/// The TypeScript signers write the same messages and wire bytes.
#[test]
fn the_reader_grants_and_wallet_reads_match_the_shared_vector() {
    #[derive(Deserialize)]
    struct Signed {
        message: String,
        wire: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        ring_wide: Signed,
        wallet: Signed,
        wallet_read: String,
        wallet_utxos: String,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/reader_grant.json"
    ))
    .expect("vector");
    let authority = Keypair::new_from_array([8; 32]);
    let wallet = Keypair::new_from_array([7; 32]);
    let reader = ReaderKey::ed25519(Keypair::new_from_array([9; 32]).pubkey()).expect("reader");
    let file = "reader_grant.json";
    let grants = [
        (
            &authority,
            None,
            reader,
            ReaderGrantAction::Grant,
            &vector.ring_wide,
            "/ringWide",
        ),
        (
            &wallet,
            Some(wallet.pubkey()),
            passkey_reader(),
            ReaderGrantAction::Revoke,
            &vector.wallet,
            "/wallet",
        ),
    ];
    let text = |bytes: Vec<u8>| String::from_utf8(bytes).expect("utf8");
    for (signer, wallet, reader, action, expected, at) in grants {
        let attestation = ReaderGrantAttestation {
            target: target(),
            wallet,
            reader,
            action,
        };
        let message = attestation.message(1_700_000_000, &[4; 32]);
        pinned(
            file,
            &format!("{at}/message"),
            &text(message.clone()),
            &expected.message,
        );
        let signed = SignedRequest {
            attestation,
            timestamp: Some(1_700_000_000),
            nonce: [4; 32],
        }
        .sign(signer)
        .expect("sign");
        let wire = serde_json::to_string(&signed).expect("json");
        pinned(file, &format!("{at}/wire"), &wire, &expected.wire);
        let read: SetReaderGrantRequest = serde_json::from_str(&wire).expect("read");
        assert!(read.signature.0.verify(signer.pubkey().as_ref(), &message));
    }
    let read = ReadAttestation {
        read: PagedRead::DecryptedTransactions,
        target: target(),
        cursor: None,
        limit: None,
        wallet: Some(wallet.pubkey()),
    };
    pinned(
        file,
        "/walletRead",
        &text(read.message(1_700_000_000, &[4; 32])),
        &vector.wallet_read,
    );
    let utxos = AuditedUtxosAttestation {
        wallet: Some(wallet.pubkey()),
        ..AuditedUtxosAttestation::new(target(), &[Hash([5; 32])])
    };
    pinned(
        file,
        "/walletUtxos",
        &text(utxos.message(1_700_000_000, &[4; 32])),
        &vector.wallet_utxos,
    );
}

fn wallet_update_writes() -> Vec<custom_ring_interface::RecordWriteData> {
    use zolana_ring_policy::{AssetLimits, ListId, Member, MintPolicy};
    let wallet = Keypair::new_from_array([7; 32]);
    let identity = Member::owner_tag(wallet.pubkey().as_array()).expect("wallet");
    let bit = ListId::RingViewing.record_bit();
    [
        RecordUpdateEntry::Write(zolana_ring_indexer::rpc::RingListWriteView {
            mint_policy: Some(MintPolicy {
                threshold: 1,
                cap: 2,
                cosign_above: 3,
                withdrawal_threshold: 4,
                limits: AssetLimits {
                    sender_cap: 5,
                    sender_window_slots: 6,
                    volume_cap: 7,
                    volume_window_slots: 8,
                    deposit_cap: 9,
                    deposit_window_slots: 10,
                    withdrawal_cap: 11,
                    withdrawal_window_slots: 12,
                },
            }),
            member: Hash(*identity.as_bytes()),
            mask: bit,
            value: bit,
        }),
        RecordUpdateEntry::WalletGrant(WalletGrant {
            wallet: Hash(*identity.as_bytes()),
            reader: Hash(*passkey_reader().member().expect("member").as_bytes()),
            access: ReaderAccess::Granted,
        }),
    ]
    .iter()
    .map(|entry| entry.write().expect("write"))
    .collect()
}

/// The TypeScript codec writes and reads the same bytes.
#[test]
fn the_storage_writes_of_a_wallet_update_match_the_shared_vector() {
    use custom_ring_interface::{CustomRingError, RecordWriteData};
    #[derive(Deserialize)]
    struct Vector {
        writes: String,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/registry/storage_writes.json"
    ))
    .expect("vector");
    let writes = wallet_update_writes();
    let bytes: &[u8] = bytemuck::cast_slice(&writes);
    assert_eq!(hex::encode(bytes), vector.writes);
    let decoded = hex::decode(&vector.writes).expect("hex");
    assert_eq!(
        bytemuck::try_cast_slice::<u8, RecordWriteData>(&decoded).expect("whole writes"),
        writes
    );
    assert!(writes.iter().all(|write| write.storage_entry().is_ok()));
    let tag = core::mem::offset_of!(RecordWriteData, mint_policy);
    for refused in [2, 7] {
        let mut tampered = decoded.clone();
        tampered[tag] = refused;
        let write: &RecordWriteData = bytemuck::from_bytes(&tampered[..RecordWriteData::SIZE]);
        assert_eq!(
            write.storage_entry(),
            Err(CustomRingError::InvalidInstructionData)
        );
    }
}

#[test]
#[ignore = "rewrites test-vectors/registry/storage_writes.json"]
fn write_storage_writes_vector() {
    let writes = wallet_update_writes();
    let vector = serde_json::json!({
        "description": "The RecordWriteData bytes of two record update entries of the wallet of seed 0x07, each member || mask || value || mint_policy_write in little endian. The first sets the ring-viewing list on the wallet's own record and replaces its mint settings with the amounts 1 to 12 in field order. The second grants the passkey reader on the wallet grant record and keeps the mint settings. A mint_policy_write leading byte off 0 and 1 is refused.",
        "writes": hex::encode(bytemuck::cast_slice::<_, u8>(&writes)),
    });
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/registry/storage_writes.json"
    );
    std::fs::write(
        path,
        serde_json::to_string_pretty(&vector).expect("json") + "\n",
    )
    .expect("vector");
}

#[test]
#[ignore = "rewrites the decrypted page fixtures"]
fn write_decrypted_page_vectors() {
    let mut delivered = page(delivered_audited(), vec![[12; 32]]);
    delivered.value.items[0].spenders = vec![[13; 32].into()];
    let in_proof = in_proof_page(
        AuditedInput {
            nullifier: [12; 32],
            opening: InputOpening::Real,
        },
        AuditedInput {
            nullifier: [11; 32],
            opening: InputOpening::Dummy,
        },
    );
    let anonymous = anonymous_page();
    let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/src/rpc/");
    for (name, page) in [
        ("decrypted_page.json", &delivered),
        ("decrypted_in_proof_page.json", &in_proof),
        ("decrypted_anonymous_page.json", &anonymous),
    ] {
        let json = serde_json::to_string(page).expect("json") + "\n";
        std::fs::write(format!("{directory}{name}"), json).expect("vector");
    }
    let [transaction] = anonymous.value.items.as_slice() else {
        panic!("one transaction")
    };
    let of = |wallet: u8, party: InputParty| {
        WalletActivity::of(
            Address::new_from_array([wallet; 32]),
            transaction.clone(),
            |_| party,
        )
        .expect("a party")
    };
    let activity = GetWalletActivityResponse {
        context: anonymous.context,
        value: WalletActivityPage {
            items: vec![of(0x50, InputParty::Own), of(0x10, InputParty::Other)],
            cursor: anonymous.value.cursor.clone(),
        },
    };
    std::fs::write(
        format!("{directory}wallet_activity_page.json"),
        serde_json::to_string(&activity).expect("json") + "\n",
    )
    .expect("vector");
}
