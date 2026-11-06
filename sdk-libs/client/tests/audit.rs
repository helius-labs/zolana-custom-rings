//! Audits of synthetic ring transfers built as the ring program publishes them.

#[path = "common/history_page.rs"]
pub mod history_page;
#[path = "common/origin.rs"]
mod origin_fixture;
#[path = "common/transfer.rs"]
pub mod transfer;

use std::{
    collections::HashMap,
    num::{NonZeroU32, NonZeroUsize},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

use custom_ring_interface::{AuditStreamLayout, MergeRecord, OutputRecord, RecordKind, RingMode};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    AsyncRpc, Context, GetShieldedTransactionsByTagsResponse, HistoryFilters, IndexerRpcConfig,
    PaginationToken, ShieldedTransaction,
};
use spr_event::{encode_merge_output_data, MergeOutputDataRef, MessageData};
use spr_hasher::primitives::hash_bytes;
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use spr_transaction::instructions::merge::MergeSeed;
use spr_transaction::{OutputContext, OutputSlot};
use zolana_ring_client::{
    auditor_view_tag, confirmed_merge,
    history::{HistoryCursor, HistoryQuery, HistoryStream},
    AuditError, AuditStreamSeal, AuditedEntryInput, AuditedTransaction, ConfirmedMerge,
    ConfirmedMergeDisclosure, MergeAudit, MergeLedger, MergeRecordSeal, OutputOpening,
    OutputPayloadError, OutputPayloadErrorKind, RingOrigin, RingOwnerTag, RingScan,
    TransactionAudit, TransactionOrigin,
};

use history_page::{position, EventsPage};
use transfer::{
    audited_opening, auditor, entry_record, field, known_utxo, x25519_u, Disclosure, Frame, Output,
    Placement, Publish, Rail, Slot, Transfer, UtxoFields,
};

const SOL: Address = Address::new_from_array([0; 32]);
const MINT: Address = Address::new_from_array([0x0a; 32]);

/// A record frame reads no mint.
fn utxo(owner: u8, asset_address: Address, amount: u64) -> UtxoFields {
    UtxoFields {
        owner_key: [owner; 32],
        nullifier_pk: field(owner - 0x80),
        asset_address,
        amount,
        ..UtxoFields::default()
    }
}

fn transfer(seed: u8) -> Transfer {
    let first_nullifier = field(seed);
    Transfer {
        tx_key: ViewingKey::from_bytes(&[seed; 32]),
        first_nullifier,
        salt: [seed; 16],
        nullifiers: vec![first_nullifier],
        ..Transfer::fixture()
    }
}

struct Built {
    transaction: ShieldedTransaction,
    outputs: Vec<Output>,
    slots: Vec<Slot>,
    layout: AuditStreamLayout,
    frame: Vec<u8>,
    disclosure: Disclosure,
    rail: Rail,
}

fn build(transfer: &Transfer, rail: Rail, outputs: Vec<Output>) -> Built {
    let disclosure = transfer.disclosure(rail, &outputs);
    publish(transfer, rail, outputs, disclosure)
}

fn publish(transfer: &Transfer, rail: Rail, outputs: Vec<Output>, disclosure: Disclosure) -> Built {
    let slots = transfer.slots(&outputs);
    let transaction = transfer.publish(Publish {
        slots: slots.iter().map(|slot| slot.output.clone()).collect(),
        disclosure: &disclosure,
        auditor: &auditor().pubkey(),
        rail,
    });
    Built {
        frame: transfer.frame(Frame {
            tx: &transaction,
            disclosure: &disclosure,
            rail,
        }),
        layout: disclosure.layout,
        transaction,
        outputs,
        slots,
        disclosure,
        rail,
    }
}

fn delivered_outputs() -> Vec<Output> {
    let mut outputs: Vec<Output> = (0u8..5)
        .map(|k| Output::Ring {
            utxo: utxo(0xb0 + k, [SOL, MINT][usize::from(k % 2)], 10 + u64::from(k)),
            recipient_u: x25519_u(0x40 + k),
            tag: None,
        })
        .collect();
    outputs.extend([
        Output::Exit(utxo(0xe5, SOL, 40)),
        Output::Dummy,
        Output::Dummy,
    ]);
    outputs
}

fn audit(
    transaction: &ShieldedTransaction,
    layout: AuditStreamLayout,
) -> Result<AuditedTransaction, AuditError> {
    TransactionAudit::new(transaction, layout).run(&auditor())
}

fn slot_error(slot_index: u32, kind: OutputPayloadErrorKind) -> OutputPayloadError {
    OutputPayloadError { slot_index, kind }
}

fn opened_slots(audited: &AuditedTransaction) -> Vec<u32> {
    audited
        .outputs
        .iter()
        .map(|output| output.slot_index)
        .collect()
}

fn expect_every_slot(built: &Built, audited: &AuditedTransaction) {
    assert!(audited.payload_errors.is_empty());
    assert_eq!(audited.outputs.len(), built.outputs.len());
    for ((opened, output), slot) in audited.outputs.iter().zip(&built.outputs).zip(&built.slots) {
        assert_eq!(opened.opening, audited_opening(output, slot));
        assert_eq!(opened.context, slot.output.output_context);
    }
}

#[test]
fn every_slot_opens_to_its_published_commitment_with_an_empty_mint_registry() {
    for rail in [Rail::Delivered, Rail::Anonymous] {
        let outputs = match rail {
            Rail::Delivered => delivered_outputs(),
            Rail::Anonymous => delivered_outputs()[..4].to_vec(),
        };
        let built = build(&Transfer::fixture(), rail, outputs);
        let audited = audit(&built.transaction, built.layout).unwrap();
        expect_every_slot(&built, &audited);
    }
}

/// A reader tries no candidate key.
#[test]
fn zero_key_and_enrolled_outputs_in_one_frame_are_each_identified() {
    let enrolled = utxo(0xb1, MINT, 11);
    let exposed = UtxoFields {
        nullifier_pk: ZERO_NULLIFIER_PUBKEY,
        ..utxo(0xb2, MINT, 12)
    };
    let ring = |utxo, recipient| Output::Ring {
        utxo,
        recipient_u: x25519_u(recipient),
        tag: None,
    };
    let built = build(
        &Transfer::fixture(),
        Rail::Delivered,
        vec![ring(enrolled, 0x41), ring(exposed, 0x42)],
    );
    let audited = audit(&built.transaction, built.layout).unwrap();
    expect_every_slot(&built, &audited);
    let keys: Vec<_> = audited
        .outputs
        .iter()
        .map(|output| output.opening.utxo().unwrap().nullifier_pk)
        .collect();
    assert_eq!(keys, [enrolled.nullifier_pk, ZERO_NULLIFIER_PUBKEY]);
}

#[test]
fn a_data_bearing_note_rebuilds_from_its_payload() {
    let note = UtxoFields {
        data_hash: field(0x71),
        ring_data_hash: field(0x72),
        ..utxo(0xb3, MINT, 30)
    };
    let outputs = vec![
        Output::Ring {
            utxo: note,
            recipient_u: x25519_u(0x43),
            tag: None,
        },
        Output::Dummy,
    ];
    let transfer = Transfer::fixture();
    let disclosure = Transfer::with_data(transfer.disclosure(Rail::Delivered, &outputs), &outputs);
    let built = publish(&transfer, Rail::Delivered, outputs, disclosure);
    let body_lengths: Vec<_> = built
        .transaction
        .output_slots
        .iter()
        .map(|slot| {
            custom_ring_interface::ring_body_output(&slot.payload)
                .unwrap()
                .0
                .len()
        })
        .collect();
    assert_eq!(body_lengths[0], body_lengths[1]);
    assert!(body_lengths[0] > custom_ring_interface::OUTPUT_RECORD_LEN);
    let audited = audit(&built.transaction, built.layout).unwrap();
    expect_every_slot(&built, &audited);
    let opened = audited.outputs[0].opening.utxo().unwrap();
    assert_eq!(opened.data_hash, Some(field(0x71)));
    assert_eq!(opened.ring_data_hash, Some(field(0x72)));
    // The commitment holds both hashes.
    let mut cleared = built.disclosure.clone();
    cleared.payloads.as_mut().unwrap()[0] = Default::default();
    let forged = transfer.publish(Publish {
        slots: built.transaction.output_slots.clone(),
        disclosure: &cleared,
        auditor: &auditor().pubkey(),
        rail: built.rail,
    });
    let audited = audit(&forged, built.layout).unwrap();
    assert_eq!(
        audited.payload_errors,
        [slot_error(0, OutputPayloadErrorKind::Payload)]
    );
    // The proven record stands under the published commitment, its data hashes stay unknown.
    let kept = audited.outputs[0].opening.utxo().unwrap();
    assert_eq!((kept.amount, kept.owner_key), (note.amount, note.owner_key));
    assert_eq!((kept.data_hash, kept.ring_data_hash), (None, None));
}

#[test]
fn each_record_field_changed_fails_the_rebuild() {
    let transfer = Transfer::fixture();
    let built = build(&transfer, Rail::Delivered, delivered_outputs());
    type Spoil = fn(&mut OutputRecord);
    let spoils: [(&str, Spoil); 4] = [
        ("amount", |record| record.amount += 1),
        ("owner_key", |record| record.owner_key[0] ^= 1),
        ("mint", |record| record.mint[0] ^= 1),
        ("nullifier_pk", |record| record.nullifier_pk[31] ^= 1),
    ];
    for slot in [0usize, 5] {
        for (name, spoil) in spoils {
            let mut spoiled = built.disclosure.clone();
            spoil(&mut spoiled.records[slot]);
            let forged = transfer.publish(Publish {
                slots: built.transaction.output_slots.clone(),
                disclosure: &spoiled,
                auditor: &auditor().pubkey(),
                rail: built.rail,
            });
            let audited = audit(&forged, built.layout).unwrap();
            assert_eq!(
                audited.payload_errors,
                [slot_error(slot as u32, OutputPayloadErrorKind::Payload)],
                "{name} of slot {slot}"
            );
            // The reader keeps the record, only the ring proof refuses a forged one.
            assert_eq!(audited.outputs.len(), built.outputs.len());
        }
    }
}

#[test]
fn a_noncanonical_nullifier_key_or_blinding_refuses_the_transaction() {
    let transfer = Transfer::fixture();
    let built = build(&transfer, Rail::Delivered, delivered_outputs());
    type Spoil = fn(&mut OutputRecord);
    let spoils: [(&str, Spoil); 2] = [
        ("nullifier_pk", |record| record.nullifier_pk = [0xff; 32]),
        ("blinding", |record| record.blinding = [0xff; 32]),
    ];
    for (name, spoil) in spoils {
        let mut spoiled = built.disclosure.clone();
        spoil(&mut spoiled.records[0]);
        let forged = transfer.publish(Publish {
            slots: built.transaction.output_slots.clone(),
            disclosure: &spoiled,
            auditor: &auditor().pubkey(),
            rail: built.rail,
        });
        assert!(
            matches!(
                audit(&forged, built.layout),
                Err(AuditError::DisclosureField)
            ),
            "{name}"
        );
    }
}

#[test]
fn a_record_of_one_slot_at_another_drops_its_data_hashes() {
    let transfer = Transfer::fixture();
    let built = build(&transfer, Rail::Delivered, delivered_outputs());
    let mut swapped = built.disclosure.clone();
    swapped.records.swap(0, 1);
    let forged = transfer.publish(Publish {
        slots: built.transaction.output_slots.clone(),
        disclosure: &swapped,
        auditor: &auditor().pubkey(),
        rail: built.rail,
    });
    let audited = audit(&forged, built.layout).unwrap();
    assert_eq!(
        audited.payload_errors,
        [
            slot_error(0, OutputPayloadErrorKind::Payload),
            slot_error(1, OutputPayloadErrorKind::Payload),
        ]
    );
    assert_eq!(opened_slots(&audited), [0, 1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn a_live_slot_under_a_dummy_record_is_rejected_on_the_commitment() {
    let transfer = Transfer::fixture();
    let built = build(&transfer, Rail::Delivered, delivered_outputs());
    let mut hidden = built.disclosure.clone();
    hidden.records[0] = OutputRecord::default();
    let forged = transfer.publish(Publish {
        slots: built.transaction.output_slots.clone(),
        disclosure: &hidden,
        auditor: &auditor().pubkey(),
        rail: built.rail,
    });
    assert_eq!(
        audit(&forged, built.layout).unwrap().payload_errors,
        [slot_error(0, OutputPayloadErrorKind::Commitment)]
    );
}

/// The proof names `R` and no note position, the reader keeps every published nullifier for the index.
#[test]
fn the_reader_keeps_the_proven_count_and_every_published_nullifier() {
    let mut transfer = Transfer::fixture();
    transfer.nullifiers = vec![transfer.first_nullifier, field(0x61), field(0x62)];
    let outputs = delivered_outputs()[..2].to_vec();
    let mut disclosure = transfer.disclosure(Rail::Delivered, &outputs);
    disclosure.real_inputs = 2;
    let built = publish(&transfer, Rail::Delivered, outputs, disclosure);
    let audited = audit(&built.transaction, built.layout).unwrap();
    assert_eq!(audited.real_inputs, 2);
    assert_eq!(audited.nullifiers, transfer.nullifiers);
    assert!(audited.entries.is_empty());
}

/// The entry bit names absolute note position 1.
#[test]
fn an_entry_input_opens_under_its_default_bit_with_its_proven_commitment() {
    let mut transfer = Transfer::fixture();
    transfer.nullifiers = vec![transfer.first_nullifier, field(0x61)];
    let outputs = delivered_outputs()[..2].to_vec();
    let spent = utxo(0xc1, MINT, 70);
    let commitment = spent.commitment(Placement {
        blinding: field(0x63),
        ring: None,
        tree_id: transfer.tree_id,
    });
    let disclosure = transfer.entry_disclosure(
        &outputs,
        0b10,
        vec![Default::default(), entry_record(&spent, commitment)],
    );
    let built = publish(&transfer, Rail::Anonymous, outputs, disclosure);
    let audited = audit(&built.transaction, built.layout).unwrap();
    assert_eq!(
        audited.entries,
        [AuditedEntryInput {
            owner_key: spent.owner_key,
            nullifier_pk: spent.nullifier_pk,
            asset: spent.asset(),
            mint: MINT,
            amount: 70,
            commitment,
        }]
    );
}

#[test]
fn an_exit_opens_with_its_published_owner_tag() {
    let exit = utxo(0xe5, SOL, 40);
    let built = build(
        &Transfer::fixture(),
        Rail::Delivered,
        vec![Output::Exit(exit), Output::Dummy],
    );
    let audited = audit(&built.transaction, built.layout).unwrap();
    let OutputOpening::Exit(opened) = audited.outputs[0].opening else {
        panic!("an exit")
    };
    assert_eq!(opened.owner_key, exit.owner_key);
    // A ring id off the record's kind hashes to another note.
    let mut swapped = built.disclosure.clone();
    swapped.records[0].kind = RecordKind::Ring;
    let transfer = Transfer::fixture();
    let forged = transfer.publish(Publish {
        slots: built.transaction.output_slots.clone(),
        disclosure: &swapped,
        auditor: &auditor().pubkey(),
        rail: built.rail,
    });
    assert_eq!(
        audit(&forged, built.layout).unwrap().payload_errors,
        [slot_error(0, OutputPayloadErrorKind::Payload)]
    );
}

/// An exit's data sits in its scheme 3 body, the auditor opens its record without the data hashes.
#[test]
fn an_honest_data_bearing_exit_opens() {
    let exit = UtxoFields {
        data_hash: field(0x75),
        ..utxo(0xe5, SOL, 40)
    };
    let built = build(
        &Transfer::fixture(),
        Rail::Delivered,
        vec![Output::Exit(exit), Output::Dummy],
    );
    let audited = audit(&built.transaction, built.layout).unwrap();
    let OutputOpening::Exit(opened) = audited.outputs[0].opening else {
        panic!("an exit")
    };
    assert_eq!(
        (opened.owner_key, opened.amount, opened.nullifier_pk),
        (exit.owner_key, exit.amount, exit.nullifier_pk)
    );
    assert_eq!(
        audited.payload_errors,
        [slot_error(0, OutputPayloadErrorKind::Payload)]
    );
}

#[test]
fn an_opened_note_reads_as_its_known_form() {
    let note = utxo(0xb4, MINT, 21);
    let transfer = Transfer::fixture();
    let built = build(
        &transfer,
        Rail::Delivered,
        vec![
            Output::Ring {
                utxo: note,
                recipient_u: x25519_u(0x44),
                tag: None,
            },
            Output::Dummy,
        ],
    );
    let audited = audit(&built.transaction, built.layout).unwrap();
    let created: Vec<_> = audited.utxos().collect();
    assert_eq!(
        created[0].utxo,
        known_utxo(
            &note,
            Placement {
                blinding: built.slots[0].blinding,
                ring: Some(transfer.ring),
                tree_id: transfer.tree_id,
            }
        )
    );
    assert!(created[0].ring_note);
    assert_eq!(created.len(), 1);
    assert_eq!(
        audited.outputs[0].opening,
        OutputOpening::Ring {
            utxo: *audited.outputs[0].opening.utxo().unwrap(),
            owner_tag: RingOwnerTag(custom_ring_interface::stream::slot_tag(x25519_u(0x44))),
        }
    );
}

#[derive(Clone, Copy)]
struct Spend {
    utxo: UtxoFields,
}

fn anonymous_spend() -> (Transfer, Built, [Spend; 2]) {
    let mut transfer = transfer(0x1a);
    transfer.nullifiers = vec![transfer.first_nullifier, field(0x69)];
    let outputs = vec![
        Output::Ring {
            utxo: utxo(0xb5, SOL, 50),
            recipient_u: x25519_u(0x50),
            tag: Some(field(0x51)),
        },
        Output::Dummy,
    ];
    let built = build(&transfer, Rail::Anonymous, outputs);
    let spent = [
        Spend {
            utxo: utxo(0xb6, MINT, 60),
        },
        Spend {
            utxo: utxo(0xb7, MINT, 61),
        },
    ];
    (transfer, built, spent)
}

const MERGE_SEED: [u8; 32] = {
    let mut seed = [0x31; 32];
    seed[0] = 0;
    seed
};

fn merged(transfer: &Transfer, spend: &Spend) -> Confirmed {
    let first_nullifier = field(0x74);
    let blinding = MergeSeed::from_bytes(MERGE_SEED)
        .unwrap()
        .output_blinding(&first_nullifier)
        .unwrap();
    let hash = spend.utxo.commitment(Placement {
        blinding,
        ring: Some(transfer.ring),
        tree_id: transfer.tree_id,
    });
    let sealed = MergeRecordSeal {
        record: MergeRecord {
            record: OutputRecord {
                kind: RecordKind::Ring,
                amount: spend.utxo.amount,
                owner_key: spend.utxo.owner_key,
                mint: spend.utxo.asset_address.to_bytes(),
                nullifier_pk: spend.utxo.nullifier_pk,
                blinding,
            },
            seed: MERGE_SEED,
        },
        recipient: X25519Pubkey::from_u(x25519_u(0x4e)).unwrap(),
        first_nullifier,
    }
    .seal(&auditor().pubkey())
    .unwrap();
    let payload = encode_merge_output_data(MergeOutputDataRef {
        salt: &[0x4d; 16],
        ciphertext: &[field(0x73); 3],
        prefix: &[[0; 32]],
    });
    let transaction = created_transaction(transfer, hash, payload, vec![first_nullifier]);
    Confirmed {
        origin: RingOrigin {
            merge_disclosure: Some(ConfirmedMergeDisclosure {
                eph_pk: *sealed.eph_pk.as_bytes(),
                envelope: sealed.envelope,
                record: sealed.record,
            }),
            ..confirmed(&transaction)
        },
        transaction,
    }
}

struct Confirmed {
    transaction: ShieldedTransaction,
    origin: RingOrigin,
}

impl Confirmed {
    fn merge(&self) -> Result<Option<ConfirmedMerge>, AuditError> {
        confirmed_merge(
            &self.transaction,
            self.transaction.event_index.unwrap(),
            &self.origin,
            &auditor(),
        )
    }
}

fn created_transaction(
    transfer: &Transfer,
    hash: [u8; 32],
    payload: Vec<u8>,
    nullifiers: Vec<[u8; 32]>,
) -> ShieldedTransaction {
    ShieldedTransaction {
        slot: 1,
        tx_signature: Signature::from([0xd0; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: field(0x72),
            output_context: OutputContext {
                hash,
                tree_id: transfer.tree_id,
                leaf_index: 0,
            },
            payload,
        }],
        messages: Vec::new(),
        proofless: nullifiers.is_empty(),
        nullifiers,
        ring_config: None,
        ring_program_id: Some(transfer.ring),
    }
}

fn confirmed(transaction: &ShieldedTransaction) -> RingOrigin {
    RingOrigin {
        ring_invoked: true,
        event: origin_fixture::event(transaction),
        signers: Vec::new(),
        pool_accounts: Vec::new(),
        withdrawals: Vec::new(),
        merge_disclosure: None,
        transact: None,
    }
}

#[test]
fn a_merge_record_resolves_alone_in_the_ledger() {
    let (transfer, _, spent) = anonymous_spend();
    let merge = merged(&transfer, &spent[1]);
    let confirmed_merge = merge.merge().unwrap().expect("a record merge");
    let record = confirmed_merge.disclosed();
    assert_eq!(record.amount, spent[1].utxo.amount);
    assert_eq!(record.real_nullifiers, [field(0x74)]);
    assert_eq!(record.seed, MERGE_SEED);
    let mut ledger = MergeLedger::default();
    let hash = confirmed_merge.output_commitment();
    assert!(ledger.apply(confirmed_merge).is_some());
    let opened = ledger
        .output(&hash)
        .expect("resolved with no input")
        .opening()
        .unwrap();
    assert_eq!(
        opened.asset,
        hash_bytes(spent[1].utxo.asset_address.as_array()).unwrap()
    );
    assert_eq!(opened.commitment(Some(transfer.ring)).unwrap(), Some(hash));
    assert_eq!(opened.amount, spent[1].utxo.amount);
}

fn page_after(pages: &[Vec<ShieldedTransaction>], token: Option<PaginationToken>) -> usize {
    token.map_or(0, |token| {
        pages
            .iter()
            .rposition(|page| page.iter().map(position).max() == Some(token))
            .map_or(pages.len(), |index| index + 1)
    })
}

/// Ring history pages in order, a token closes every page but the last.
struct RingHistory(Vec<Vec<ShieldedTransaction>>);

#[async_trait::async_trait]
impl AsyncRpc for RingHistory {
    async fn get_shielded_transactions_by_ring(
        &self,
        options: spr_client::RingHistoryOptions,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, spr_client::ClientError> {
        let index = page_after(&self.0, options.pagination_token);
        Ok(EventsPage {
            context: Context {
                block_time: 0,
                slot: 1,
            },
            output_tree_id: None,
            rows: self.0.get(index).cloned().unwrap_or_default(),
            more: index + 1 < self.0.len(),
        }
        .response())
    }
}

struct ConfirmedOrigins(HashMap<Signature, RingOrigin>);

impl TransactionOrigin for ConfirmedOrigins {
    async fn origin(
        &self,
        signature: Signature,
        _event_index: u16,
        _ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        self.0
            .get(&signature)
            .cloned()
            .ok_or_else(|| AuditError::Unavailable {
                signature,
                message: "not found".to_owned(),
            })
    }
}

#[tokio::test]
async fn the_merge_audit_reads_every_merge() {
    let (transfer, built, spent) = anonymous_spend();
    let mut merge = merged(&transfer, &spent[1]);
    merge.transaction.tx_signature = Signature::from([0xd1; 64]);
    let origins: HashMap<Signature, RingOrigin> = [
        (merge.transaction.tx_signature, merge.origin.clone()),
        (
            built.transaction.tx_signature,
            confirmed(&built.transaction),
        ),
    ]
    .into_iter()
    .collect();
    let history = RingHistory(vec![
        vec![built.transaction.clone()],
        vec![merge.transaction.clone()],
    ]);
    let auditor = auditor();
    let merges = MergeAudit::new(transfer.ring, &auditor)
        .run(&history, &ConfirmedOrigins(origins))
        .await
        .unwrap();
    assert_eq!(
        merges
            .iter()
            .map(|merge| merge.output_commitment())
            .collect::<Vec<_>>(),
        [merge.transaction.output_slots[0].output_context.hash]
    );
}

#[test]
fn the_envelope_must_seal_the_published_transaction_key() {
    let built = build(&Transfer::fixture(), Rail::Delivered, delivered_outputs());
    let mut forged = built.transaction.clone();
    let other_key = ViewingKey::new();
    let sealed = AuditStreamSeal {
        layout: built.layout,
        tx_viewing_key: &other_key,
        salt: &built.transaction.salt.unwrap(),
        real_inputs: built.disclosure.real_inputs,
        evidence: built.disclosure.evidence.clone(),
        recipient_keys: built.disclosure.recipient_keys.clone(),
    }
    .seal(&auditor().pubkey())
    .unwrap();
    let stream = [&sealed.eph_u[..], &sealed.envelope].concat();
    forged.messages[0].data[1..=stream.len()].copy_from_slice(&stream);
    assert!(matches!(
        audit(&forged, built.layout),
        Err(AuditError::TxViewingKeyMismatch)
    ));
}

#[test]
fn the_auditor_message_is_unique_and_last() {
    let built = build(&Transfer::fixture(), Rail::Delivered, delivered_outputs());
    let free_form = MessageData {
        view_tag: [0x77; 32],
        data: vec![1, 2, 3],
    };
    let mut missing = built.transaction.clone();
    missing.messages = vec![free_form.clone()];
    assert!(matches!(
        audit(&missing, built.layout),
        Err(AuditError::MissingAuditorMessage)
    ));
    let mut misplaced = built.transaction.clone();
    misplaced.messages.push(free_form);
    assert!(matches!(
        audit(&misplaced, built.layout),
        Err(AuditError::MissingAuditorMessage)
    ));
    assert!(matches!(
        TransactionAudit::new(&built.transaction, built.layout).run(&X25519Keypair::new()),
        Err(AuditError::MissingAuditorMessage)
    ));
}

#[test]
fn a_message_off_the_layout_is_refused() {
    let built = build(&Transfer::fixture(), Rail::Delivered, delivered_outputs());
    let length = built.transaction.messages[0].data.len();
    for mutated in [length - 32, length + 32] {
        let mut transaction = built.transaction.clone();
        transaction.messages[0].data.resize(mutated, 0);
        assert!(matches!(
            audit(&transaction, built.layout),
            Err(AuditError::AuditorMessageLength(len)) if len == mutated
        ));
    }
    let mut widened = built.transaction.clone();
    widened.output_slots.truncate(5);
    assert!(matches!(
        audit(&widened, built.layout),
        Err(AuditError::DisclosureLayout)
    ));
}

#[test]
fn the_layout_comes_from_the_ring_frame() {
    let built = build(&Transfer::fixture(), Rail::Delivered, delivered_outputs());
    let origin = |transact| RingOrigin {
        transact,
        ..confirmed(&built.transaction)
    };
    assert_eq!(
        origin(Some(built.frame.clone()))
            .audit_frame(RingMode::Confidential)
            .unwrap(),
        built.layout
    );
    assert!(matches!(
        origin(None).audit_frame(RingMode::Confidential),
        Err(AuditError::MissingRingTransact)
    ));
    // An anonymous ring parses a `Transfer` frame under its own rail.
    assert!(matches!(
        origin(Some(built.frame.clone())).audit_frame(RingMode::Anonymous),
        Err(AuditError::InvalidTransactData(_))
    ));
}

/// Token paging plus the message-tag filter. Photon's tag filter is an OR over
/// output tags and message tags, so a transaction can arrive because an output
/// tag matched; the scan drops those.
struct PagedIndexer {
    expected_tag: [u8; 32],
    pages: Vec<Vec<ShieldedTransaction>>,
    /// Page size asked for on each round trip, in call order.
    requested: Mutex<Vec<Option<u32>>>,
}

#[async_trait::async_trait]
impl AsyncRpc for PagedIndexer {
    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        pagination_token: Option<PaginationToken>,
        limit: Option<u32>,
        _filters: HistoryFilters,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, spr_client::ClientError> {
        assert_eq!(tags, vec![self.expected_tag]);
        self.requested.lock().unwrap().push(limit);
        let index = page_after(&self.pages, pagination_token);
        Ok(EventsPage {
            context: Context {
                block_time: 0,
                slot: 1,
            },
            output_tree_id: None,
            rows: self.pages.get(index).cloned().unwrap_or_default(),
            more: index + 1 < self.pages.len(),
        }
        .response())
    }
}

struct KnownOrigins {
    ring: Address,
    origins: HashMap<Signature, bool>,
    confirmed: HashMap<Signature, zolana_ring_client::ConfirmedEvent>,
    frames: HashMap<Signature, Vec<u8>>,
    lookups: AtomicUsize,
}

impl TransactionOrigin for KnownOrigins {
    async fn origin(
        &self,
        signature: Signature,
        _event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        assert_eq!(ring, self.ring);
        self.lookups.fetch_add(1, Ordering::Relaxed);
        self.origins
            .get(&signature)
            .copied()
            .map(|ring_invoked| RingOrigin {
                event: self
                    .confirmed
                    .get(&signature)
                    .expect("confirmed event")
                    .clone(),
                ring_invoked,
                signers: Vec::new(),
                pool_accounts: Vec::new(),
                withdrawals: Vec::new(),
                merge_disclosure: None,
                transact: self.frames.get(&signature).cloned(),
            })
            .ok_or_else(|| AuditError::Unavailable {
                signature,
                message: "not found".to_owned(),
            })
    }
}

fn with_signature(mut tx: ShieldedTransaction, byte: u8) -> ShieldedTransaction {
    tx.tx_signature = Signature::from([byte; 64]);
    tx
}

fn ring() -> Address {
    Transfer::fixture().ring
}

fn delivered_transfer(seed: u8) -> Built {
    let outputs = vec![
        Output::Ring {
            utxo: utxo(
                0xb0 + seed % 0x10,
                [SOL, MINT][usize::from(seed % 2)],
                u64::from(seed),
            ),
            recipient_u: x25519_u(seed),
            tag: None,
        },
        Output::Dummy,
    ];
    build(&transfer(seed), Rail::Delivered, outputs)
}

#[tokio::test]
async fn scan_walks_every_page_and_keeps_only_ring_transactions_tagged_for_the_auditor() {
    let auditor_pk = auditor().pubkey();
    let first_built = delivered_transfer(1);
    let second_built = delivered_transfer(2);
    let first = with_signature(first_built.transaction.clone(), 1);
    let second = with_signature(second_built.transaction.clone(), 5);
    // An output tag match must still be attributed before it can be excluded.
    let mut output_tag_match = with_signature(delivered_transfer(3).transaction, 3);
    output_tag_match.messages.clear();
    output_tag_match.output_slots[0].view_tag = auditor_view_tag(&auditor_pk);
    let foreign_ring = with_signature(first.clone(), 4);
    let indexer = PagedIndexer {
        expected_tag: auditor_view_tag(&auditor_pk),
        pages: vec![
            vec![first.clone(), output_tag_match, foreign_ring.clone()],
            vec![second.clone()],
        ],
        requested: Mutex::new(Vec::new()),
    };
    let origin = KnownOrigins {
        ring: ring(),
        origins: HashMap::from([
            (first.tx_signature, true),
            (second.tx_signature, true),
            (foreign_ring.tx_signature, false),
            (Signature::from([3; 64]), false),
        ]),
        confirmed: indexer
            .pages
            .iter()
            .flatten()
            .map(|tx| (tx.tx_signature, origin_fixture::event(tx)))
            .collect(),
        frames: HashMap::from([
            (first.tx_signature, first_built.frame.clone()),
            (second.tx_signature, second_built.frame.clone()),
        ]),
        lookups: AtomicUsize::new(0),
    };
    assert_eq!(
        RingScan::new(ring(), auditor_pk)
            .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
            .run(&indexer, &origin)
            .await
            .expect("scan")
            .transactions,
        vec![first, second]
    );
    assert_eq!(
        origin.lookups.load(Ordering::Relaxed),
        4,
        "one lookup per signature"
    );
    let audited = RingScan::new(ring(), auditor_pk)
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .audit(&auditor(), &indexer, &origin)
        .await
        .expect("audit all")
        .transactions;
    assert_eq!(audited.len(), 2);
    for (audited, built) in audited.iter().zip([&first_built, &second_built]) {
        assert_eq!(
            audited.outputs[0].opening,
            audited_opening(&built.outputs[0], &built.slots[0])
        );
    }
    assert_eq!(audited[0].tx_viewing_pk, transfer(1).tx_key.pubkey());
}

fn paid_and_spent() -> (Built, Built) {
    let payee = utxo(0xb8, MINT, 80);
    let paid_transfer = transfer(0x2a);
    let paid = build(
        &paid_transfer,
        Rail::Anonymous,
        vec![
            Output::Ring {
                utxo: payee,
                recipient_u: x25519_u(0x52),
                tag: Some(field(0x53)),
            },
            Output::Dummy,
        ],
    );
    let spending_transfer = transfer(0x2b);
    let spent = build(
        &spending_transfer,
        Rail::Anonymous,
        vec![
            Output::Ring {
                utxo: utxo(0xb9, MINT, 80),
                recipient_u: x25519_u(0x54),
                tag: Some(field(0x55)),
            },
            Output::Dummy,
        ],
    );
    (paid, spent)
}

/// One page of `built` under signatures from 5, every frame known.
fn anonymous_page(built: &[&Built]) -> (PagedIndexer, KnownOrigins) {
    let page: Vec<ShieldedTransaction> = (5..)
        .zip(built)
        .map(|(byte, built)| with_signature(built.transaction.clone(), byte))
        .collect();
    let mut origin = ring_origins(ring(), std::slice::from_ref(&page));
    origin.frames = page
        .iter()
        .zip(built)
        .map(|(tx, built)| (tx.tx_signature, built.frame.clone()))
        .collect();
    (indexer(&auditor().pubkey(), vec![page]), origin)
}

struct FailingOrigin {
    known: KnownOrigins,
    failing: Signature,
    error: fn(Signature) -> AuditError,
}

impl TransactionOrigin for FailingOrigin {
    async fn origin(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        if signature == self.failing {
            return Err((self.error)(signature));
        }
        self.known.origin(signature, event_index, ring).await
    }
}

#[tokio::test]
async fn a_confirmed_ring_match_without_mandatory_disclosure_is_incomplete() {
    let mut tx = delivered_transfer(1).transaction;
    tx.messages.clear();
    let origin = KnownOrigins {
        ring: ring(),
        origins: HashMap::from([(tx.tx_signature, true)]),
        confirmed: HashMap::from([(tx.tx_signature, origin_fixture::event(&tx))]),
        frames: HashMap::new(),
        lookups: AtomicUsize::new(0),
    };
    let indexer = indexer(&auditor().pubkey(), vec![vec![tx]]);
    assert!(matches!(
        RingScan::new(ring(), auditor().pubkey())
            .audit(&auditor(), &indexer, &origin)
            .await,
        Err(AuditError::MissingAuditorMessage)
    ));
}

#[tokio::test]
async fn scan_fails_when_an_origin_is_unavailable() {
    let auditor_pk = auditor().pubkey();
    let indexer = indexer(&auditor_pk, vec![vec![delivered_transfer(1).transaction]]);
    let origin = KnownOrigins {
        ring: ring(),
        origins: HashMap::new(),
        confirmed: HashMap::new(),
        frames: HashMap::new(),
        lookups: AtomicUsize::new(0),
    };
    assert!(matches!(
        RingScan::new(ring(), auditor_pk)
            .with_max_pages(NonZeroUsize::new(1).expect("page limit"))
            .run(&indexer, &origin)
            .await,
        Err(AuditError::Unavailable { .. })
    ));
}

/// One auditor-tagged transaction per page, so the paging rules are what the
/// scan is measured on.
fn paged_history(pages: u8) -> Vec<Vec<ShieldedTransaction>> {
    (0..pages)
        .map(|index| {
            vec![with_signature(
                delivered_transfer(index + 1).transaction,
                index + 1,
            )]
        })
        .collect()
}

fn indexer(auditor_pk: &X25519Pubkey, pages: Vec<Vec<ShieldedTransaction>>) -> PagedIndexer {
    PagedIndexer {
        expected_tag: auditor_view_tag(auditor_pk),
        pages,
        requested: Mutex::new(Vec::new()),
    }
}

fn ring_origins(ring: Address, pages: &[Vec<ShieldedTransaction>]) -> KnownOrigins {
    KnownOrigins {
        ring,
        confirmed: pages
            .iter()
            .flatten()
            .map(|tx| (tx.tx_signature, origin_fixture::event(tx)))
            .collect(),
        origins: pages
            .iter()
            .flatten()
            .map(|tx| (tx.tx_signature, true))
            .collect(),
        frames: HashMap::new(),
        lookups: AtomicUsize::new(0),
    }
}

fn signatures(transactions: &[ShieldedTransaction]) -> Vec<Signature> {
    transactions.iter().map(|tx| tx.tx_signature).collect()
}

#[tokio::test]
async fn the_page_size_is_asked_for_on_every_round_trip() {
    let auditor_pk = auditor().pubkey();
    let pages = paged_history(3);
    let origin = ring_origins(ring(), &pages);
    let indexer = indexer(&auditor_pk, pages.clone());
    let page = RingScan::new(ring(), auditor_pk)
        .with_page_size(NonZeroU32::new(1).expect("page size"))
        .with_max_pages(NonZeroUsize::new(3).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("scan");
    assert_eq!(*indexer.requested.lock().unwrap(), vec![Some(1); 3]);
    assert_eq!(signatures(&page.transactions), signatures(&pages.concat()));
}

/// A scan cut short by `max_pages` hands back the cursor of the page it did
/// not read, and resuming there repeats nothing and skips nothing.
#[tokio::test]
async fn a_scan_stopped_by_max_pages_resumes_where_it_stopped() {
    let auditor_pk = auditor().pubkey();
    let pages = paged_history(3);
    let origin = ring_origins(ring(), &pages);
    let indexer = indexer(&auditor_pk, pages.clone());
    let stopped = RingScan::new(ring(), auditor_pk)
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("first scan");
    let cursor = stopped.next_cursor.expect("unread history");
    assert_eq!(
        signatures(&stopped.transactions),
        signatures(&pages[..2].concat())
    );
    let resumed = RingScan::new(ring(), auditor_pk)
        .with_cursor(cursor)
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("resumed scan");
    assert_eq!(resumed.next_cursor, None);
    assert_eq!(signatures(&resumed.transactions), signatures(&pages[2]));
}

/// A token names the last transaction returned, so an empty page never carries one.
struct TokenOnAnEmptyPage;

#[async_trait::async_trait]
impl AsyncRpc for TokenOnAnEmptyPage {
    async fn get_shielded_transactions_by_tags(
        &self,
        _tags: Vec<[u8; 32]>,
        _pagination_token: Option<PaginationToken>,
        _limit: Option<u32>,
        _filters: HistoryFilters,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, spr_client::ClientError> {
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 1,
            },
            output_tree_id: None,
            data: Vec::new(),
            pagination_token: Some(PaginationToken::new(1, Signature::from([1; 64]))),
        })
    }
}

#[tokio::test]
async fn an_empty_page_with_a_token_is_refused_and_an_empty_terminal_page_ends_the_scan() {
    let auditor_pk = auditor().pubkey();
    let origin = ring_origins(ring(), &[]);
    let scan = || {
        RingScan::new(ring(), auditor_pk).with_max_pages(NonZeroUsize::new(2).expect("page limit"))
    };
    assert!(matches!(
        scan().run(&TokenOnAnEmptyPage, &origin).await,
        Err(AuditError::InvalidHistoryPage)
    ));
    let page = scan()
        .run(&indexer(&auditor_pk, vec![Vec::new()]), &origin)
        .await
        .expect("scan");
    assert!(page.transactions.is_empty());
    assert_eq!(page.next_cursor, None);
}

#[tokio::test]
async fn a_cursor_at_the_end_of_history_returns_an_empty_page() {
    let auditor_pk = auditor().pubkey();
    let pages = paged_history(2);
    let origin = ring_origins(ring(), &pages);
    let token = position(pages[1].last().expect("a row"));
    let indexer = indexer(&auditor_pk, pages);
    let page = RingScan::new(ring(), auditor_pk)
        .with_cursor(HistoryCursor {
            query: HistoryQuery {
                ring: ring(),
                stream: HistoryStream::Tags,
            },
            token,
        })
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("scan");
    assert!(page.transactions.is_empty());
    assert_eq!(page.next_cursor, None);
    assert_eq!(origin.lookups.load(Ordering::Relaxed), 0);
}

#[test]
fn a_sender_bundle_under_the_auditor_tag_leaves_the_transfer_open() {
    let (_, built, _) = anonymous_spend();
    let expected = audit(&built.transaction, built.layout).unwrap();
    let mut transaction = built.transaction.clone();
    assert_eq!(transaction.messages.len(), 2);
    transaction.messages[0].view_tag = auditor_view_tag(&auditor().pubkey());
    assert_eq!(audit(&transaction, built.layout).unwrap(), expected);
}

fn anonymous_scan() -> RingScan {
    RingScan::new(ring(), auditor().pubkey()).with_mode(RingMode::Anonymous)
}

#[tokio::test]
async fn a_scan_goes_past_a_row_that_does_not_decode_and_stops_at_a_failed_read() {
    let (paid, spent) = paid_and_spent();
    let (indexer, known) = anonymous_page(&[&paid, &spent]);
    let mut origin = FailingOrigin {
        known,
        failing: Signature::from([5; 64]),
        error: |_| AuditError::InvalidTransactData("forged".to_owned()),
    };
    let page = anonymous_scan()
        .audit(&auditor(), &indexer, &origin)
        .await
        .expect("audit");
    assert_eq!(page.transactions.len(), 1);
    let [row] = page.skipped.as_slice() else {
        panic!("one bad row");
    };
    assert_eq!(row.tx_signature, origin.failing);
    assert!(matches!(row.error, AuditError::InvalidTransactData(_)));
    origin.error = |signature| AuditError::Unavailable {
        signature,
        message: "unreachable".to_owned(),
    };
    assert!(matches!(
        anonymous_scan().audit(&auditor(), &indexer, &origin).await,
        Err(AuditError::Unavailable { .. })
    ));
    origin.error = |_| AuditError::InvalidStackHeight(4);
    assert!(matches!(
        anonymous_scan().audit(&auditor(), &indexer, &origin).await,
        Err(AuditError::InvalidStackHeight(4))
    ));
}

#[tokio::test]
async fn a_scan_lists_a_row_its_audit_refuses_and_opens_the_next() {
    let (mut paid, spent) = paid_and_spent();
    // The envelope's first byte, past the tagged ephemeral key.
    let refused = paid
        .transaction
        .messages
        .last_mut()
        .expect("auditor message");
    refused.data[33] ^= 1;
    let (indexer, origin) = anonymous_page(&[&paid, &spent]);
    let page = anonymous_scan()
        .audit(&auditor(), &indexer, &origin)
        .await
        .expect("audit");
    let [row] = page.skipped.as_slice() else {
        panic!("one refused row");
    };
    assert_eq!(row.tx_signature, Signature::from([5; 64]));
    let [opened] = page.transactions.as_slice() else {
        panic!("the row after the refused one");
    };
    assert_eq!(opened.tx_signature, Signature::from([6; 64]));
}

#[tokio::test]
async fn a_lost_auditor_message_stays_fatal_in_a_local_scan() {
    let (_, mut built, _) = anonymous_spend();
    let tag = auditor_view_tag(&auditor().pubkey());
    // A free tag keeps the row on the auditor's page, the last message names no auditor.
    built.transaction.messages[0].view_tag = tag;
    built.transaction.messages[1].view_tag = field(0x7c);
    let (indexer, origin) = anonymous_page(&[&built]);
    assert!(matches!(
        anonymous_scan().audit(&auditor(), &indexer, &origin).await,
        Err(AuditError::MissingAuditorMessage)
    ));
}

/// A tampered disclosure stops the merge audit, a spend it would name stays unread and never unspent.
#[tokio::test]
async fn the_merge_audit_refuses_a_disclosure_it_cannot_open() {
    let (transfer, _, spent) = anonymous_spend();
    let mut merge = merged(&transfer, &spent[1]);
    merge.transaction.tx_signature = Signature::from([0xd1; 64]);
    let Some(ConfirmedMergeDisclosure { record, .. }) = merge.origin.merge_disclosure.as_mut()
    else {
        panic!("the record")
    };
    record[16] ^= 1;
    let origins: HashMap<Signature, RingOrigin> =
        [(merge.transaction.tx_signature, merge.origin.clone())]
            .into_iter()
            .collect();
    let history = RingHistory(vec![vec![merge.transaction.clone()]]);
    let auditor = auditor();
    assert!(MergeAudit::new(transfer.ring, &auditor)
        .run(&history, &ConfirmedOrigins(origins))
        .await
        .is_err());
}
