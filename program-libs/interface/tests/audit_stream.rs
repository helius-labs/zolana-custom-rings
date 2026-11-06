//! Pins the audit vectors the Go circuits read.

use custom_ring_interface::{
    ciphertext_digest, decode_recipient_keys, encode_recipient_keys, key_catalog::TRANSFER_SHAPES,
    AuditEnvelope, AuditEvidence, AuditKey, AuditStreamLayout, AuditorMessage, BundleLayout,
    CustomRingError, EntryRecord, OutputRecord, RecipientPayload, RecordKind, SenderBundle,
    ENTRY_RECORD_LEN, OUTPUT_RECORD_LEN, SEALED_KEY_LEN, STREAM_BLOCK_LEN,
};
use serde::Deserialize;
use serde_json::{json, Value};
use spr_hasher::{
    hash_chain::create_hash_chain_4_from_slice, primitives::hash_bytes, Hasher, Poseidon,
};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/audit/ring-disclosure-ranges.json"
);

fn layout(key: AuditKey, inputs: usize, outputs: usize, capacity: usize) -> AuditStreamLayout {
    AuditStreamLayout {
        key,
        inputs,
        outputs,
        capacity,
    }
}

fn key_vector(key: AuditKey, outputs: usize) -> Value {
    let bare = layout(key, 1, outputs, outputs);
    json!({
        "class": key.class(),
        "outputs": outputs,
        "entry": key.entry,
        "envelope_blocks": key.envelope_blocks(),
        "first_key_counter": key.first_key_counter(),
        "capacity_blocks": bare.capacity_blocks(),
        "key_start_counters": (0..outputs)
            .map(|slot| bare.recipient_key(slot).start_counter)
            .collect::<Vec<_>>(),
        "envelope_len_by_input_count": (1..=key.class())
            .map(|inputs| layout(key, inputs, outputs, outputs).envelope().len)
            .collect::<Vec<_>>(),
    })
}

fn compute_vector() -> Value {
    json!({
        "description": "Auditor stream ranges for each transfer key at full output capacity, the envelope then one sealed recipient key per slot.",
        "keys": TRANSFER_SHAPES
            .iter()
            .map(|shape| key_vector(shape.audit_key(), usize::from(shape.outputs)))
            .collect::<Vec<_>>(),
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

#[test]
fn the_contract_counts_each_key() {
    let plain = AuditKey {
        class: 24,
        entry: false,
    };
    assert_eq!(layout(plain, 3, 2, 2).envelope().len, 33);
    assert_eq!(plain.first_key_counter(), 5);
    let entry = AuditKey {
        class: 8,
        entry: true,
    };
    assert_eq!(
        layout(entry, 2, 4, 4).envelope().len,
        41 + 2 * ENTRY_RECORD_LEN
    );
    assert_eq!(
        entry.envelope_blocks(),
        (41 + 8 * ENTRY_RECORD_LEN).div_ceil(STREAM_BLOCK_LEN)
    );
    assert_eq!(layout(entry, 2, 3, 4).keys_len(), 3 * SEALED_KEY_LEN);
}

#[test]
fn no_counter_serves_two_regions_and_every_region_holds_its_bytes() {
    for shape in TRANSFER_SHAPES {
        let key = shape.audit_key();
        let full = layout(
            key,
            key.class(),
            usize::from(shape.outputs),
            usize::from(shape.outputs),
        );
        let envelope = full.envelope();
        assert!(envelope.len <= envelope.max_blocks * STREAM_BLOCK_LEN);
        let mut next = envelope.start_counter + envelope.max_blocks as u32;
        for slot in 0..full.capacity {
            let region = full.recipient_key(slot);
            assert_eq!(region.start_counter, next, "{shape:?}");
            assert!(region.len <= region.max_blocks * STREAM_BLOCK_LEN);
            next += region.max_blocks as u32;
        }
        assert_eq!(
            next as usize - envelope.start_counter as usize,
            full.capacity_blocks()
        );
    }
}

#[test]
fn counts_off_the_key_are_refused() {
    let key = AuditKey {
        class: 2,
        entry: false,
    };
    assert!(layout(key, 1, 2, 2).checked().is_ok());
    for refused in [
        layout(key, 0, 2, 2),
        layout(key, 3, 2, 2),
        layout(key, 1, 0, 2),
        layout(key, 1, 3, 2),
    ] {
        assert_eq!(refused.checked(), Err(CustomRingError::RingTransactLength));
    }
}

/// A frame with fewer slots transmits fewer keys, every published key keeps its counter.
#[test]
fn a_compact_frame_keeps_every_key_counter() {
    let key = AuditKey {
        class: 24,
        entry: false,
    };
    let (full, compact) = (layout(key, 2, 4, 4), layout(key, 2, 2, 4));
    for slot in 0..2 {
        assert_eq!(full.recipient_key(slot), compact.recipient_key(slot));
    }
    assert_eq!(compact.recipient_key(2).len, 0);
    assert_eq!(compact.sealed_len(), 33 + 2 * SEALED_KEY_LEN);
}

fn record() -> OutputRecord {
    OutputRecord {
        kind: RecordKind::Ring,
        amount: 0x0102_0304_0506_0708,
        owner_key: [0xa1; 32],
        mint: [0xa2; 32],
        nullifier_pk: [0xa3; 32],
        blinding: [0xa4; 32],
    }
}

#[test]
fn the_record_lays_out_its_contract_bytes() {
    let encoded = record().encode();
    assert_eq!(encoded.len(), OUTPUT_RECORD_LEN);
    assert_eq!(encoded[0], 1);
    assert_eq!(encoded[1..9], 0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(encoded[9..41], [0xa1; 32]);
    assert_eq!(encoded[41..73], [0xa2; 32]);
    assert_eq!(encoded[73..105], [0xa3; 32]);
    assert_eq!(encoded[105..], [0xa4; 32]);
    assert_eq!(OutputRecord::decode(&encoded).unwrap(), record());
}

#[test]
fn a_record_off_its_form_is_refused() {
    let mut unknown = record().encode();
    unknown[0] = 3;
    let mut dummy = [0; OUTPUT_RECORD_LEN];
    assert_eq!(
        OutputRecord::decode(&dummy).unwrap(),
        OutputRecord::default()
    );
    dummy[105] = 1;
    for refused in [&unknown[..], &dummy[..], &record().encode()[..136]] {
        assert_eq!(
            OutputRecord::decode(refused),
            Err(CustomRingError::RingTransactLength)
        );
    }
}

fn entry_key() -> AuditKey {
    AuditKey {
        class: 4,
        entry: true,
    }
}

fn entry_record() -> EntryRecord {
    EntryRecord {
        owner_key: [1; 32],
        nullifier_pk: [2; 32],
        amount: 3,
        mint: [4; 32],
        input_commitment: [5; 32],
    }
}

/// R counts notes, default bits and records follow note order.
#[test]
fn envelopes_read_back_by_note_order() {
    let plain = AuditEnvelope {
        tx_viewing_secret: [7; 32],
        real_inputs: 2,
        evidence: AuditEvidence::None,
    };
    let plain_layout = layout(
        AuditKey {
            class: 24,
            entry: false,
        },
        3,
        2,
        2,
    );
    assert_eq!(plain.encode().len(), plain_layout.envelope().len);
    assert_eq!(
        AuditEnvelope::decode(&plain.encode(), plain_layout).unwrap(),
        plain
    );
    let entry = AuditEnvelope {
        tx_viewing_secret: [7; 32],
        real_inputs: 2,
        evidence: AuditEvidence::Entry {
            default_note_bits: 0b01,
            inputs: vec![
                entry_record(),
                EntryRecord::default(),
                EntryRecord::default(),
            ],
        },
    };
    let entry_layout = layout(entry_key(), 3, 2, 4);
    assert_eq!(entry.encode().len(), entry_layout.envelope().len);
    assert_eq!(
        AuditEnvelope::decode(&entry.encode(), entry_layout).unwrap(),
        entry
    );
    let refuse = |envelope: AuditEnvelope, layout: AuditStreamLayout| {
        assert_eq!(
            AuditEnvelope::decode(&envelope.encode(), layout),
            Err(CustomRingError::RingTransactLength)
        );
    };
    refuse(
        AuditEnvelope {
            real_inputs: 4,
            ..plain.clone()
        },
        plain_layout,
    );
    let with_bits = |bits, inputs: Vec<EntryRecord>| AuditEnvelope {
        evidence: AuditEvidence::Entry {
            default_note_bits: bits,
            inputs,
        },
        ..entry.clone()
    };
    refuse(
        with_bits(
            0b100,
            vec![
                EntryRecord::default(),
                EntryRecord::default(),
                entry_record(),
            ],
        ),
        entry_layout,
    );
    refuse(
        with_bits(
            0b01,
            vec![entry_record(), entry_record(), EntryRecord::default()],
        ),
        entry_layout,
    );
}

#[test]
fn recipient_keys_read_back_per_published_slot() {
    let keys = [[1; 32], [2; 32]];
    let key = AuditKey {
        class: 2,
        entry: false,
    };
    let encoded = encode_recipient_keys(&keys);
    assert_eq!(encoded.len(), layout(key, 1, 2, 4).keys_len());
    assert_eq!(
        decode_recipient_keys(&encoded, layout(key, 1, 2, 4)).unwrap(),
        keys
    );
    assert!(decode_recipient_keys(&encoded, layout(key, 1, 1, 4)).is_err());
}

/// An exit's record travels in the auditor message, every other record opens its body.
#[test]
fn the_auditor_message_cuts_by_the_layout_and_the_exits() {
    let key = AuditKey {
        class: 24,
        entry: false,
    };
    let stream = layout(key, 2, 2, 2);
    let mut data = vec![4; 33];
    data.extend([0x11; 33]);
    data.extend([0x22; 2 * SEALED_KEY_LEN]);
    data.extend([0x33; OUTPUT_RECORD_LEN]);
    let message = AuditorMessage::parse(&data, stream, 1).unwrap();
    assert_eq!(message.envelope, &[0x11; 33]);
    assert_eq!(message.recipient_keys, &[0x22; 64]);
    assert_eq!(message.exit_record(0), Some(&[0x33; OUTPUT_RECORD_LEN]));
    assert_eq!(message.exit_record(1), None);
    assert!(AuditorMessage::parse(&data, stream, 0).is_none());
    assert!(AuditorMessage::parse(&data, stream, 2).is_none());
    data[0] = 2;
    assert!(AuditorMessage::parse(&data, stream, 1).is_none());
}

/// The payload carries both data hashes outside every proof, its padding stays zero.
#[test]
fn the_recipient_payload_reads_back_at_one_width() {
    let payload = RecipientPayload {
        ring_data_hash: Some([9; 32]),
        data: vec![1, 2, 3],
    };
    let padded = payload.encode_padded(64).unwrap();
    assert_eq!(padded.len(), 64);
    assert_eq!(RecipientPayload::decode(&padded).unwrap(), payload);
    let mut tampered = padded.clone();
    tampered[63] = 1;
    assert!(RecipientPayload::decode(&tampered).is_err());
    assert_eq!(
        payload.encode_padded(payload.encoded_len() - 1),
        Err(CustomRingError::OutputBodyLength)
    );
    let empty = RecipientPayload::default();
    assert_eq!(
        empty.encode_padded(2),
        Err(CustomRingError::OutputBodyLength)
    );
    assert_eq!(
        RecipientPayload::decode(&empty.encode_padded(3).unwrap()).unwrap(),
        empty
    );
}

#[test]
fn the_sender_bundle_holds_one_key_per_slot() {
    let bundle = SenderBundle {
        output_seed: [1; 32],
        recipient_keys: vec![[2; 32], [0; 32], [3; 32]],
    };
    let encoded = bundle.encode();
    assert_eq!(encoded.len(), BundleLayout { outputs: 3 }.byte_len());
    assert_eq!(
        SenderBundle::decode(&encoded, BundleLayout { outputs: 3 }).unwrap(),
        bundle
    );
    assert!(SenderBundle::decode(&encoded, BundleLayout { outputs: 2 }).is_err());
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
    recipient_keys: Vec<String>,
    recipient_keys_ciphertext: String,
    records: Vec<String>,
    record_ciphertexts: Vec<String>,
    envelope_digest: String,
    record_chain: String,
}

fn unhex(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap()
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
            "compact",
            "data",
            "entry",
            "no_spend",
            "entry_default_first",
        ]
    );
    for case in &vector.cases {
        let layout = layout(
            AuditKey {
                class: case.input_class,
                entry: case.layout & 2 != 0,
            },
            case.input_count,
            case.output_count,
            case.outputs,
        )
        .checked()
        .unwrap();
        let plaintext = unhex(&case.envelope_plaintext);
        let envelope = AuditEnvelope::decode(&plaintext, layout).unwrap();
        assert_eq!(
            hex::encode(envelope.tx_viewing_secret),
            vector.tx_viewing_sk
        );
        assert_eq!(envelope.encode(), plaintext, "{}", case.name);
        let keys: Vec<[u8; 32]> = case
            .recipient_keys
            .iter()
            .map(|key| unhex(key).try_into().unwrap())
            .collect();
        assert_eq!(keys.len(), case.output_count, "{}", case.name);
        let (sealed_envelope, sealed_keys) = (
            unhex(&case.envelope_ciphertext),
            unhex(&case.recipient_keys_ciphertext),
        );
        assert_eq!(
            sealed_envelope.len(),
            layout.envelope().len,
            "{}",
            case.name
        );
        assert_eq!(sealed_keys.len(), layout.keys_len(), "{}", case.name);
        let digest = Poseidon::hashv(&[
            &ciphertext_digest(&sealed_envelope).unwrap(),
            &ciphertext_digest(&sealed_keys).unwrap(),
        ])
        .unwrap();
        assert_eq!(hex::encode(digest), case.envelope_digest, "{}", case.name);
        for record in &case.records {
            let bytes = unhex(record);
            assert_eq!(OutputRecord::decode(&bytes).unwrap().encode()[..], bytes);
        }
        let mut hashes = vec![[0; 32]; case.outputs];
        for (hash, ciphertext) in hashes.iter_mut().zip(&case.record_ciphertexts) {
            let bytes: [u8; OUTPUT_RECORD_LEN] = unhex(ciphertext).try_into().unwrap();
            *hash = hash_bytes(&bytes).unwrap();
        }
        assert_eq!(
            hex::encode(create_hash_chain_4_from_slice(&hashes).unwrap()),
            case.record_chain,
            "{}",
            case.name
        );
    }
}

#[test]
fn a_ring_body_opens_with_its_record() {
    use custom_ring_interface::{encode_ring_body_output, ring_body_output, ring_body_record};
    let body = [record().encode().to_vec(), vec![0x55; 5]].concat();
    let data = encode_ring_body_output(&body, &[0x66; 97]).unwrap();
    let (read, reply) = ring_body_output(&data).unwrap();
    assert_eq!(read, &body[..]);
    assert_eq!(reply, &[0x66; 97]);
    assert_eq!(ring_body_record(read), Some(&record().encode()));
    assert_eq!(
        encode_ring_body_output(&body[..OUTPUT_RECORD_LEN - 1], &[]),
        Err(CustomRingError::OutputBodyLength)
    );
}
