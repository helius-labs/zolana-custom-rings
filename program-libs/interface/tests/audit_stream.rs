//! Pins the audit vectors the Go circuits read.

use custom_ring_interface::{
    ciphertext_digest, key_catalog::TRANSFER_SHAPES, AuditEnvelope, AuditEvidence, AuditKey,
    AuditRecord, AuditStreamLayout, AuditorMessage, BundleLayout, ChangeCell, CustomRingError,
    DataTail, EntryInput, OpeningRecord, RecipientBody, RecordKind, SenderBundle, AUDIT_RECORD_LEN,
    DATA_TAIL_LEN, ENTRY_INPUT_LEN, OPENING_RECORD_LEN, RECIPIENT_BODY_LEN, RECORD_STRIDE,
    STREAM_BLOCK_LEN,
};
use serde::Deserialize;
use serde_json::{json, Value};
use spr_hasher::{hash_chain::create_hash_chain_4_from_slice, primitives::hash_bytes};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/audit/ring-disclosure-ranges.json"
);

struct KeyCase {
    key: AuditKey,
    outputs: usize,
    has_data: bool,
}

fn key_cases() -> Vec<KeyCase> {
    TRANSFER_SHAPES
        .iter()
        .flat_map(|shape| {
            [false, true].into_iter().filter_map(|has_data| {
                (shape.format == custom_ring_interface::DisclosureFormat::Standard || !has_data)
                    .then_some(KeyCase {
                        key: shape.audit_key(),
                        outputs: usize::from(shape.outputs),
                        has_data,
                    })
            })
        })
        .collect()
}

impl KeyCase {
    fn layout(&self, inputs: usize) -> AuditStreamLayout {
        AuditStreamLayout {
            key: self.key,
            inputs,
            outputs: self.outputs,
            capacity: self.outputs,
            has_data: self.has_data,
        }
    }

    fn inputs(&self) -> impl Iterator<Item = usize> {
        1..=self.key.class()
    }

    fn vector(&self) -> Value {
        let bare = self.layout(1);
        json!({
            "class": self.key.class(),
            "outputs": self.outputs,
            "entry": self.key.entry,
            "single_asset_payout": self.key.format == custom_ring_interface::DisclosureFormat::SingleAssetPayout,
            "has_data": self.has_data,
            "envelope_blocks": self.key.envelope_blocks(),
            "first_record_counter": self.key.first_record_counter(),
            "first_tail_counter": bare.first_tail_counter(),
            "capacity_blocks": bare.capacity_blocks(),
            "record_len": self.key.format.record_len(),
            "tail_len": bare.tail_len(0),
            "record_start_counters": (0..self.outputs)
                .map(|slot| bare.record(slot).start_counter)
                .collect::<Vec<_>>(),
            "tail_start_counters": (0..self.outputs)
                .map(|slot| bare.tail(slot).start_counter)
                .collect::<Vec<_>>(),
            "envelope_len_by_input_count": self.inputs()
                .map(|inputs| self.layout(inputs).envelope().len)
                .collect::<Vec<_>>(),
            "message_len_by_input_count": self.inputs()
                .map(|inputs| self.layout(inputs).message_len())
                .collect::<Vec<_>>(),
        })
    }
}

fn compute_vector() -> Value {
    json!({
        "description": "Auditor stream ranges for each transfer key at full output capacity.",
        "keys": key_cases().iter().map(KeyCase::vector).collect::<Vec<_>>(),
    })
}

#[test]
fn the_ranges_are_the_shared_vector() {
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, compute_vector());
}

#[test]
#[ignore = "rewrites test-vectors/audit/ring-disclosure-ranges.json"]
fn write_ring_disclosure_ranges_vector() {
    let json = serde_json::to_string_pretty(&compute_vector()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}

const fn block_bytes(blocks: usize) -> usize {
    blocks * STREAM_BLOCK_LEN
}

#[test]
fn the_contract_counts_each_key() {
    let key = |class, entry| AuditKey {
        format: custom_ring_interface::DisclosureFormat::Standard,
        class,
        entry,
    };
    for (key, envelope_blocks) in [
        (key(5, false), 3),
        (key(24, false), 3),
        (key(2, true), 29),
        (key(8, true), 104),
    ] {
        assert_eq!(key.envelope_blocks(), envelope_blocks, "{key:?}");
        assert_eq!(
            key.first_record_counter() as usize,
            2 + envelope_blocks,
            "{key:?}"
        );
        assert_eq!(key.signer_slots(), key.class(), "{key:?}");
    }
    assert_eq!(AUDIT_RECORD_LEN, 105);
    assert_eq!(RECORD_STRIDE, 112);
    assert_eq!(DATA_TAIL_LEN, 64);
    assert_eq!(ENTRY_INPUT_LEN, 200);
    assert_eq!(OPENING_RECORD_LEN, 144);
    assert_eq!(RECIPIENT_BODY_LEN, 72);
}

/// Every region of every key at every `n`, in counter order with no shared counter.
#[test]
fn no_counter_serves_two_regions_and_every_region_holds_its_bytes() {
    for case in key_cases() {
        for inputs in case.inputs() {
            let layout = case.layout(inputs);
            assert_eq!(layout.checked(), Ok(layout));
            let envelope = layout.envelope();
            assert_eq!(envelope.start_counter, 2);
            assert_eq!(envelope.keystream_offset(), 0);
            assert!(envelope.len <= block_bytes(envelope.max_blocks));
            let mut next = envelope.start_counter as usize + envelope.max_blocks;
            for slot in 0..case.outputs {
                let record = layout.record(slot);
                assert_eq!(record.start_counter as usize, next);
                assert_eq!(record.len, case.key.format.record_len());
                assert!(record.len <= block_bytes(record.max_blocks));
                assert_eq!(record.keystream_offset(), block_bytes(next - 2));
                next += record.max_blocks;
            }
            for slot in 0..case.outputs {
                let tail = layout.tail(slot);
                assert_eq!(tail.start_counter as usize, next);
                assert_eq!(tail.len, layout.tail_len(slot));
                assert!(tail.len <= block_bytes(tail.max_blocks));
                next += tail.max_blocks;
            }
            if case.has_data {
                assert_eq!(next - 2, layout.capacity_blocks());
            }
        }
    }
}

/// A key's widest evidence fills its reserved blocks up to the last, one more input crosses into the records.
#[test]
fn the_input_past_the_class_is_refused() {
    for case in key_cases() {
        let class = case.key.class();
        let widest = case.layout(class).envelope();
        assert!(widest.len > block_bytes(widest.max_blocks - 1));
        assert_eq!(
            case.layout(class + 1).checked(),
            Err(CustomRingError::RingTransactLength)
        );
        assert_eq!(
            case.layout(0).checked(),
            Err(CustomRingError::RingTransactLength)
        );
        if case.key.entry {
            assert!(
                case.layout(class + 1).envelope().len > block_bytes(widest.max_blocks),
                "{:?}",
                case.key
            );
        }
    }
}

/// An omitted suffix leaves the frame, the stream still spans `N` so no slot's counter moves.
#[test]
fn a_compact_frame_keeps_every_counter_and_drops_the_suffix() {
    let layout = |outputs, has_data| AuditStreamLayout {
        key: AuditKey {
            format: custom_ring_interface::DisclosureFormat::Standard,
            class: 16,
            entry: false,
        },
        inputs: 1,
        outputs,
        capacity: 4,
        has_data,
    };
    let (compact, full) = (layout(2, true), layout(4, true));
    assert_eq!(compact.capacity_blocks(), full.capacity_blocks());
    assert_eq!(compact.record(1), full.record(1));
    assert_eq!(compact.tail(1), full.tail(1));
    assert_eq!(compact.record_len(2), 0);
    assert_eq!(compact.tail_len(2), 0);
    assert_eq!(compact.records_len(), 2 * AUDIT_RECORD_LEN);
    assert_eq!(compact.tails_len(), 2 * DATA_TAIL_LEN);
    assert_eq!(
        compact.message_len(),
        33 + 41 + 2 * AUDIT_RECORD_LEN + 2 * DATA_TAIL_LEN
    );
    for refused in [layout(0, false), layout(5, false)] {
        assert_eq!(refused.checked(), Err(CustomRingError::RingTransactLength));
    }
}

#[test]
fn a_clear_has_data_transmits_no_tail() {
    let plain = AuditStreamLayout {
        key: AuditKey {
            format: custom_ring_interface::DisclosureFormat::Standard,
            class: 24,
            entry: false,
        },
        inputs: 2,
        outputs: 2,
        capacity: 2,
        has_data: false,
    };
    assert_eq!(plain.tails_len(), 0);
    assert_eq!(plain.tail(0).len, 0);
    assert_eq!(plain.message_len(), 33 + 41 + 2 * AUDIT_RECORD_LEN);
    assert_eq!(plain.capacity_blocks(), 3 + 2 * 7);
}

fn record() -> AuditRecord {
    AuditRecord {
        kind: RecordKind::Ring,
        amount: 0x0102_0304_0506_0708,
        owner_key: [4; 32],
        mint: [5; 32],
        nullifier_pk: [6; 32],
    }
}

#[test]
fn the_record_lays_out_its_contract_bytes() {
    let encoded = record().encode();
    assert_eq!(encoded[0], 1);
    assert_eq!(encoded[1..9], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(encoded[9..41], [4; 32]);
    assert_eq!(encoded[41..73], [5; 32]);
    assert_eq!(encoded[73..], [6; 32]);
    assert_eq!(AuditRecord::decode(&encoded), Ok(record()));
    assert_eq!(AuditRecord::default().encode(), [0; AUDIT_RECORD_LEN]);
    assert_eq!(
        AuditRecord::decode(&[0; AUDIT_RECORD_LEN]),
        Ok(AuditRecord::default())
    );
}

#[test]
fn a_record_off_its_form_is_refused() {
    let refused = |mutate: fn(&mut [u8; AUDIT_RECORD_LEN])| {
        let mut encoded = record().encode();
        mutate(&mut encoded);
        assert_eq!(
            AuditRecord::decode(&encoded),
            Err(CustomRingError::RingTransactLength)
        );
    };
    refused(|record| record[0] = 3);
    // A kind 0 record holding a value is refused.
    refused(|record| record[0] = 0);
    let encoded = record().encode();
    assert!(AuditRecord::decode(&encoded[..AUDIT_RECORD_LEN - 1]).is_err());
    assert!(AuditRecord::decode(&[&encoded[..], &[0]].concat()).is_err());
}

#[test]
fn an_opening_record_carries_the_record_and_its_secret() {
    let opening = OpeningRecord {
        record: record(),
        secret: [9; 32],
    };
    let encoded = opening.encode();
    assert_eq!(encoded[..AUDIT_RECORD_LEN], record().encode());
    assert_eq!(encoded[AUDIT_RECORD_LEN..RECORD_STRIDE], [0; 7]);
    assert_eq!(encoded[RECORD_STRIDE..], [9; 32]);
    assert_eq!(OpeningRecord::decode(&encoded), Ok(opening));
    let mut padded = encoded;
    padded[AUDIT_RECORD_LEN] = 1;
    assert!(OpeningRecord::decode(&padded).is_err());
    assert!(OpeningRecord::decode(&encoded[..AUDIT_RECORD_LEN]).is_err());
}

#[test]
fn a_tail_reads_back_at_its_length() {
    let tail = DataTail {
        data_hash: [1; 32],
        ring_data_hash: [2; 32],
    };
    assert_eq!(DataTail::decode(&tail.encode()), Ok(tail));
    assert!(DataTail::decode(&tail.encode()[..63]).is_err());
}

#[test]
fn envelopes_read_back_at_their_layout_length() {
    let entry_input = EntryInput {
        owner_key: [0x41; 32],
        nullifier_pk: [0x42; 32],
        amount: 5,
        mint: [0x43; 32],
        blinding: [0x44; 32],
        data_hash: [0x45; 32],
        ring_data_hash: [0x46; 32],
    };
    let cases = [
        (
            AuditKey {
                format: custom_ring_interface::DisclosureFormat::Standard,
                class: 8,
                entry: false,
            },
            3,
            AuditEvidence::None,
            41,
        ),
        (
            AuditKey {
                format: custom_ring_interface::DisclosureFormat::Standard,
                class: 8,
                entry: true,
            },
            2,
            AuditEvidence::Entry {
                default_input_bits: 0b01,
                inputs: vec![entry_input, EntryInput::default()],
            },
            49 + 2 * ENTRY_INPUT_LEN,
        ),
    ];
    for (key, inputs, evidence, len) in cases {
        let layout = AuditStreamLayout {
            key,
            inputs,
            outputs: 2,
            capacity: 2,
            has_data: false,
        };
        let envelope = AuditEnvelope {
            tx_viewing_secret: [0x33; 32],
            real_inputs: 2,
            address_input_bits: 0,
            evidence,
        };
        let encoded = envelope.encode();
        assert_eq!(encoded.len(), len, "{key:?}");
        assert_eq!(encoded.capacity(), encoded.len(), "{key:?}");
        assert_eq!(encoded.len(), layout.envelope().len, "{key:?}");
        assert_eq!(encoded[32], 2, "{key:?}");
        assert_eq!(
            AuditEnvelope::decode(&encoded, layout),
            Ok(envelope),
            "{key:?}"
        );
        let longer = [&encoded[..], &[0]].concat();
        assert!(AuditEnvelope::decode(&longer, layout).is_err(), "{key:?}");
        assert!(
            AuditEnvelope::decode(&encoded[..encoded.len() - 1], layout).is_err(),
            "{key:?}"
        );
    }
}

#[test]
fn the_auditor_message_cuts_by_the_layout() {
    let layout = AuditStreamLayout {
        key: AuditKey {
            format: custom_ring_interface::DisclosureFormat::Standard,
            class: 8,
            entry: false,
        },
        inputs: 2,
        outputs: 2,
        capacity: 4,
        has_data: true,
    };
    let (envelope, records, tails) = (
        [1; 41],
        [[2; AUDIT_RECORD_LEN], [3; AUDIT_RECORD_LEN]],
        [[4; DATA_TAIL_LEN], [5; DATA_TAIL_LEN]],
    );
    let data = AuditorMessage::data(
        &[7; 32],
        [
            &envelope[..],
            &records[0],
            &records[1],
            &tails[0],
            &tails[1],
        ]
        .into_iter(),
    );
    assert_eq!(data.len(), layout.message_len());
    let message = AuditorMessage::parse(&data, layout).expect("message");
    assert_eq!(message.envelope, envelope);
    assert_eq!(message.record(1), Some(records[1].as_slice()));
    assert_eq!(message.tail(0), Some(&tails[0]));
    assert_eq!(message.record(2), None);
    assert!(AuditorMessage::parse(&data[..data.len() - 1], layout).is_none());
    let dataless = AuditStreamLayout {
        has_data: false,
        ..layout
    };
    assert!(AuditorMessage::parse(&data, dataless).is_none());
}

#[test]
fn the_recipient_body_extends_past_its_plain_head() {
    let plain = RecipientBody {
        blinding: [1; 32],
        amount: 0x0102_0304_0506_0708,
        mint: [2; 32],
        ..RecipientBody::default()
    };
    let encoded = plain.encode().unwrap();
    assert_eq!(encoded.len(), RECIPIENT_BODY_LEN);
    assert_eq!(encoded[32..40], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(RecipientBody::decode(&encoded), Ok(plain.clone()));
    assert!(RecipientBody::decode(&encoded[..71]).is_err());

    let ring_data = RecipientBody {
        ring_data_hash: Some([3; 32]),
        ..plain.clone()
    };
    assert_eq!(
        ring_data.encode().unwrap().len(),
        RECIPIENT_BODY_LEN + 2 + 1 + 32
    );
    assert_eq!(
        RecipientBody::decode(&ring_data.encode().unwrap()),
        Ok(ring_data)
    );

    // Application data of a hash's length never reads as ring data.
    let application = RecipientBody {
        data: vec![9; 32],
        ..plain.clone()
    };
    assert_eq!(
        RecipientBody::decode(&application.encode().unwrap()),
        Ok(application)
    );

    let both = RecipientBody {
        ring_data_hash: Some([3; 32]),
        data: vec![9; 5],
        ..plain
    };
    assert_eq!(
        RecipientBody::decode(&both.encode().unwrap()),
        Ok(both.clone())
    );
    let mut off_form = both.encode().unwrap();
    off_form[RECIPIENT_BODY_LEN] = 2;
    assert!(RecipientBody::decode(&off_form).is_err());
}

#[test]
fn the_sender_bundle_follows_the_output_and_change_counts() {
    let bundle = SenderBundle {
        output_seed: [4; 32],
        change: vec![
            ChangeCell {
                mint: [3; 32],
                amount: 5,
            },
            ChangeCell {
                mint: [3; 32],
                amount: 6,
            },
        ],
        recipient_keys: vec![[7; 32], [8; 32]],
    };
    let encoded = bundle.encode();
    assert_eq!(
        encoded.len(),
        BundleLayout {
            outputs: 4,
            change: 2
        }
        .byte_len()
    );
    assert_eq!(encoded.capacity(), encoded.len());
    assert_eq!(encoded[64..72], 5u64.to_be_bytes());
    assert_eq!(encoded[104..112], 6u64.to_be_bytes());
    let layout = |outputs, change| BundleLayout { outputs, change };
    assert_eq!(bundle.layout(), layout(4, 2));
    assert_eq!(
        SenderBundle::decode(&encoded, layout(4, 2)).as_ref(),
        Ok(&bundle)
    );
    assert!(SenderBundle::decode(&encoded, layout(4, 1)).is_err());
    assert!(SenderBundle::decode(&encoded, layout(1, 2)).is_err());
}

#[derive(Deserialize)]
struct StreamVector {
    tx_viewing_sk: String,
    cases: Vec<StreamCase>,
}

#[derive(Deserialize)]
struct StreamCase {
    name: String,
    layout: u8,
    input_class: usize,
    outputs: usize,
    output_count: usize,
    input_count: usize,
    envelope_plaintext: String,
    envelope_ciphertext: String,
    records: Vec<String>,
    record_ciphertexts: Vec<String>,
    tails: Option<Vec<String>>,
    tail_ciphertexts: Option<Vec<String>>,
    envelope_digest: String,
    record_chain: String,
    tail_chain: String,
}

fn unhex(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap()
}

fn region_chain<const N: usize>(ciphertexts: &[String], capacity: usize) -> [u8; 32] {
    let mut hashes = vec![[0; 32]; capacity];
    for (hash, ciphertext) in hashes.iter_mut().zip(ciphertexts) {
        let bytes: [u8; N] = unhex(ciphertext).try_into().unwrap();
        *hash = hash_bytes(&bytes).unwrap();
    }
    create_hash_chain_4_from_slice(&hashes).unwrap()
}

#[test]
fn the_solved_go_stream_reads_back_under_the_rust_layout() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/audit/audit-stream.json"
    );
    let vector: StreamVector =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        vector
            .cases
            .iter()
            .map(|case| case.name.as_str())
            .collect::<Vec<_>>(),
        [
            "plain_with_exit_and_dummy",
            "single_asset_payout",
            "compact",
            "data",
            "entry",
            "address_only",
            "interleaved",
            "interleaved_entry",
        ]
    );
    for case in &vector.cases {
        let layout = AuditStreamLayout {
            key: AuditKey {
                format: if case.layout & 4 != 0 {
                    custom_ring_interface::DisclosureFormat::SingleAssetPayout
                } else {
                    custom_ring_interface::DisclosureFormat::Standard
                },
                class: case.input_class,
                entry: case.layout & 2 != 0,
            },
            inputs: case.input_count,
            outputs: case.output_count,
            capacity: case.outputs,
            has_data: case.layout & 1 != 0,
        }
        .checked()
        .unwrap();
        let plaintext = unhex(&case.envelope_plaintext);
        assert_eq!(plaintext.len(), layout.envelope().len, "{}", case.name);
        let envelope = AuditEnvelope::decode(&plaintext, layout).unwrap();
        assert_eq!(
            hex::encode(envelope.tx_viewing_secret),
            vector.tx_viewing_sk
        );
        assert_eq!(envelope.encode(), plaintext, "{}", case.name);
        let ciphertext = unhex(&case.envelope_ciphertext);
        assert_eq!(ciphertext.len(), layout.envelope().len, "{}", case.name);
        assert_eq!(
            hex::encode(ciphertext_digest(&ciphertext).unwrap()),
            case.envelope_digest,
            "{}",
            case.name
        );
        assert_eq!(case.records.len(), case.output_count, "{}", case.name);
        for record in &case.records {
            let bytes = unhex(record);
            match &envelope.evidence {
                AuditEvidence::SingleAssetPayout { mint } => assert_eq!(
                    AuditRecord::decode_compact(&bytes, mint)
                        .unwrap()
                        .encode_compact()[..],
                    bytes,
                    "{}",
                    case.name
                ),
                _ => assert_eq!(
                    AuditRecord::decode(&bytes).unwrap().encode()[..],
                    bytes,
                    "{}",
                    case.name
                ),
            }
        }
        assert_eq!(
            hex::encode(match layout.key.format {
                custom_ring_interface::DisclosureFormat::Standard =>
                    region_chain::<AUDIT_RECORD_LEN>(&case.record_ciphertexts, case.outputs),
                custom_ring_interface::DisclosureFormat::SingleAssetPayout =>
                    region_chain::<{ custom_ring_interface::COMPACT_AUDIT_RECORD_LEN }>(
                        &case.record_ciphertexts,
                        case.outputs
                    ),
            }),
            case.record_chain,
            "{}",
            case.name
        );
        match (&case.tails, &case.tail_ciphertexts) {
            (Some(tails), Some(ciphertexts)) => {
                assert!(layout.has_data, "{}", case.name);
                for tail in tails {
                    let bytes = unhex(tail);
                    assert_eq!(DataTail::decode(&bytes).unwrap().encode()[..], bytes);
                }
                assert_eq!(
                    hex::encode(region_chain::<DATA_TAIL_LEN>(ciphertexts, case.outputs)),
                    case.tail_chain,
                    "{}",
                    case.name
                );
            }
            _ => {
                assert!(!layout.has_data, "{}", case.name);
                assert_eq!(case.tail_chain, hex::encode([0u8; 32]), "{}", case.name);
            }
        }
    }
}

#[test]
fn compact_payout_regions_and_plaintexts_match() {
    use custom_ring_interface::{CompactRecipientBody, DisclosureFormat};
    let layout = AuditStreamLayout {
        key: AuditKey {
            class: 1,
            entry: false,
            format: DisclosureFormat::SingleAssetPayout,
        },
        inputs: 1,
        outputs: 16,
        capacity: 16,
        has_data: false,
    }
    .checked()
    .unwrap();
    assert_eq!(layout.envelope().len, 73);
    assert_eq!(layout.key.envelope_blocks(), 5);
    assert_eq!(layout.record(0).start_counter, 7);
    assert_eq!(layout.record(15).start_counter, 82);
    assert_eq!(layout.record(15).len, 73);
    assert_eq!(layout.capacity_blocks(), 85);
    let mint = [3; 32];
    let mut envelope = AuditEnvelope {
        tx_viewing_secret: [7; 32],
        real_inputs: 1,
        address_input_bits: 0,
        evidence: AuditEvidence::SingleAssetPayout { mint },
    };
    assert!(AuditEnvelope::decode(&envelope.encode(), layout).is_ok());
    envelope.real_inputs = 0;
    assert!(AuditEnvelope::decode(&envelope.encode(), layout).is_err());
    envelope.address_input_bits = 1;
    assert!(AuditEnvelope::decode(&envelope.encode(), layout).is_err());
    let record = AuditRecord {
        kind: RecordKind::Ring,
        amount: 7,
        owner_key: [2; 32],
        mint,
        nullifier_pk: [4; 32],
    };
    assert_eq!(
        AuditRecord::decode_compact(&record.encode_compact(), &mint),
        Ok(record)
    );
    assert!(AuditRecord::decode_compact(&record.encode(), &mint).is_err());
    assert!(AuditRecord::decode_compact(&AuditRecord::default().encode_compact(), &mint).is_err());
    let body = CompactRecipientBody {
        blinding: [1; 32],
        amount: 7,
        asset_id: 11,
    };
    assert_eq!(body.encode().len(), 48);
    assert_eq!(CompactRecipientBody::decode(&body.encode()), Ok(body));
    assert!(CompactRecipientBody::decode(&[0; 72]).is_err());
    for invalid in [
        AuditStreamLayout {
            has_data: true,
            ..layout
        },
        AuditStreamLayout {
            outputs: 15,
            ..layout
        },
        AuditStreamLayout {
            inputs: 2,
            ..layout
        },
    ] {
        assert!(invalid.checked().is_err());
    }
}

#[test]
fn padded_bodies_preserve_data_and_refuse_padding_changes() {
    let plain = RecipientBody {
        blinding: [1; 32],
        amount: 7,
        mint: [2; 32],
        ..Default::default()
    };
    let data = RecipientBody {
        data: vec![5; 80],
        ring_data_hash: Some([3; 32]),
        ..plain.clone()
    };
    let width = data.encoded_len();
    let mut plain_bytes = plain.encode_padded(width).unwrap();
    let data_bytes = data.encode_padded(width).unwrap();
    assert_eq!(plain_bytes.len(), data_bytes.len());
    assert_eq!(RecipientBody::decode(&plain_bytes), Ok(plain.clone()));
    assert_eq!(RecipientBody::decode(&data_bytes), Ok(data));
    *plain_bytes.last_mut().unwrap() = 1;
    assert!(RecipientBody::decode(&plain_bytes).is_err());
    assert!(plain.encode_padded(73).is_err());
    let too_long = RecipientBody {
        data: vec![0; u16::MAX as usize],
        ..plain
    };
    assert!(too_long.encode().is_err());
}

#[test]
fn compact_delivery_scheme_is_explicit() {
    use custom_ring_interface::{
        encode_ring_body_output, ring_body_format, ring_body_output, DisclosureFormat,
    };
    let compact = encode_ring_body_output(&[1; 48], &[]).unwrap();
    assert_eq!(compact[5], 11);
    assert_eq!(
        ring_body_format(&compact),
        Some(DisclosureFormat::SingleAssetPayout)
    );
    let standard = encode_ring_body_output(&[2; 72], &[]).unwrap();
    assert_eq!(
        ring_body_format(&standard),
        Some(DisclosureFormat::Standard)
    );
    let mut wrong_scheme = compact.clone();
    wrong_scheme[5] = 10;
    assert!(ring_body_output(&wrong_scheme).is_none());
    let mut wrong_scheme = standard;
    wrong_scheme[5] = 11;
    assert!(ring_body_output(&wrong_scheme).is_none());
    assert!(encode_ring_body_output(&[1; 48], &[3]).is_err());
}
