use custom_ring_interface::{
    AuditEnvelope, AuditEvidence, AuditKey, AuditStreamLayout, CustomRingError, EntryRecord,
    InputClass, InputClassification, InputMap,
};

#[test]
fn interleaved_inputs_preserve_absolute_slots() {
    use InputClass::{Address, Dummy, Note};

    struct Case {
        classes: [InputClass; 4],
        published: usize,
        notes: u8,
        addresses: u64,
    }

    for case in [
        Case {
            classes: [Note, Address, Note, Dummy],
            published: 4,
            notes: 2,
            addresses: 2,
        },
        Case {
            classes: [Address, Note, Address, Dummy],
            published: 3,
            notes: 1,
            addresses: 5,
        },
        Case {
            classes: [Address, Address, Dummy, Dummy],
            published: 3,
            notes: 0,
            addresses: 3,
        },
        Case {
            classes: [Note, Note, Dummy, Dummy],
            published: 2,
            notes: 2,
            addresses: 0,
        },
        Case {
            classes: [Dummy; 4],
            published: 1,
            notes: 0,
            addresses: 0,
        },
    ] {
        let map = InputMap::from_classes(&case.classes, case.published).unwrap();
        assert_eq!(map.note_count(), case.notes);
        assert_eq!(map.address_input_bits(), case.addresses);
        assert_eq!(map.published_inputs(), case.published);
        assert_eq!(map.classes().collect::<Vec<_>>(), case.classes);
        assert_eq!(map.slot(4), None);
    }
}

#[test]
fn input_map_refuses_noncanonical_padding_and_counts() {
    use InputClass::{Address, Dummy, Note};

    for classes in [[Note, Dummy, Address], [Address, Dummy, Note]] {
        assert_eq!(
            InputMap::from_classes(&classes, 3),
            Err(CustomRingError::RingTransactLength)
        );
    }
    assert!(InputMap::from_classes(&[Note, Address], 1).is_err());
    assert!(InputMap::from_classes(&[Dummy; 65], 1).is_err());

    let valid = InputClassification {
        published_inputs: 3,
        capacity: 4,
        note_count: 1,
        address_input_bits: 1,
    };
    for invalid in [
        InputClassification {
            published_inputs: 0,
            ..valid
        },
        InputClassification {
            published_inputs: 5,
            ..valid
        },
        InputClassification {
            capacity: 65,
            ..valid
        },
        InputClassification {
            note_count: 4,
            ..valid
        },
        InputClassification {
            address_input_bits: 1 << 3,
            ..valid
        },
        InputClassification {
            address_input_bits: 1 << 2,
            ..valid
        },
    ] {
        assert_eq!(invalid.check(), Err(CustomRingError::RingTransactLength));
    }
}

#[test]
fn default_bits_select_only_note_positions() {
    use InputClass::{Address, Dummy, Note};

    let map = InputMap::from_classes(&[Address, Note, Note, Dummy], 3).unwrap();
    for accepted in [0, 2, 4, 6] {
        assert_eq!(map.validate_default_input_bits(accepted), Ok(()));
    }
    for rejected in [1, 3, 8, 1 << 63] {
        assert_eq!(
            map.validate_default_input_bits(rejected),
            Err(CustomRingError::RingTransactLength)
        );
    }
}

#[test]
fn ordinary_envelope_encodes_the_high_address_bit_in_big_endian_order() {
    let layout = AuditStreamLayout {
        key: AuditKey {
            format: custom_ring_interface::DisclosureFormat::Standard,
            class: 64,
            entry: false,
        },
        inputs: 64,
        outputs: 1,
        capacity: 2,
        has_data: false,
    };
    let envelope = AuditEnvelope {
        tx_viewing_secret: [0x23; 32],
        real_inputs: 63,
        address_input_bits: 1 << 63,
        evidence: AuditEvidence::None,
    };
    let plaintext = envelope.encode();
    assert_eq!(plaintext.len(), 41);
    assert_eq!(&plaintext[..32], &[0x23; 32]);
    assert_eq!(plaintext[32], 63);
    assert_eq!(&plaintext[33..41], &[0x80, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(layout.envelope().len, 41);
    assert_eq!(layout.first_record_counter(), 5);
    assert_eq!(AuditEnvelope::decode(&plaintext, layout).unwrap(), envelope);
    let map = envelope.input_map(layout).unwrap();
    assert_eq!(map.slot(62), Some(InputClass::Note));
    assert_eq!(map.slot(63), Some(InputClass::Address));
    assert_eq!(map.slot(64), None);
    assert!(map.validate_default_input_bits(1 << 62).is_ok());
    assert!(map.validate_default_input_bits(1 << 63).is_err());
    assert!(AuditEnvelope::decode(&plaintext[..33], layout).is_err());
    let mut trailing = plaintext;
    trailing.push(0);
    assert!(AuditEnvelope::decode(&trailing, layout).is_err());
}

#[test]
fn entry_envelope_keeps_records_and_stream_counters_at_capacity_offsets() {
    let layout = AuditStreamLayout {
        key: AuditKey {
            format: custom_ring_interface::DisclosureFormat::Standard,
            class: 4,
            entry: true,
        },
        inputs: 3,
        outputs: 2,
        capacity: 4,
        has_data: true,
    };
    let record = EntryRecord {
        amount: 0x0102_0304_0506_0708,
        owner_key: [0x31; 32],
        ..EntryRecord::default()
    };
    let envelope = AuditEnvelope {
        tx_viewing_secret: [0x23; 32],
        real_inputs: 2,
        address_input_bits: 2,
        evidence: AuditEvidence::Entry {
            default_input_bits: 4,
            inputs: vec![EntryRecord::default(), EntryRecord::default(), record],
        },
    };
    let plaintext = envelope.encode();
    assert_eq!(plaintext.len(), 457);
    assert_eq!(&plaintext[33..41], &[0, 0, 0, 0, 0, 0, 0, 2]);
    assert_eq!(&plaintext[41..49], &[0, 0, 0, 0, 0, 0, 0, 4]);
    assert_eq!(&plaintext[49..321], &[0; 272]);
    assert_eq!(&plaintext[321..353], &[0x31; 32]);
    assert_eq!(&plaintext[385..393], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(layout.envelope().len, 457);
    assert_eq!(layout.envelope().max_blocks, 38);
    assert_eq!(layout.first_record_counter(), 40);
    assert_eq!(layout.record(1).start_counter, 47);
    assert_eq!(layout.first_tail_counter(), 68);
    assert_eq!(layout.tail(1).start_counter, 72);
    assert_eq!(AuditEnvelope::decode(&plaintext, layout).unwrap(), envelope);

    for (offset, mask) in [(40, 1), (48, 2), (49, 1), (249, 1)] {
        let mut changed = plaintext.clone();
        changed[offset] ^= mask;
        assert!(AuditEnvelope::decode(&changed, layout).is_err(), "{offset}");
    }
    let mut old_layout = plaintext;
    old_layout.drain(33..41);
    assert!(AuditEnvelope::decode(&old_layout, layout).is_err());
}
