use custom_ring_interface::{
    AuditEvidence, AuditKey, AuditRecord, AuditStreamLayout, DataTail, EntryInput, InputClass,
    RecordKind,
};
use spr_hasher::primitives::BN254_SCALAR_MODULUS_BE;

use super::*;

const SALT: [u8; 16] = [7; 16];

fn field(byte: u8) -> [u8; 32] {
    let mut field = [byte; 32];
    field[0] = 0;
    field
}

fn plain_layout() -> AuditStreamLayout {
    AuditStreamLayout {
        key: AuditKey {
            format: DisclosureFormat::Standard,
            class: 2,
            entry: false,
        },
        inputs: 1,
        outputs: 2,
        capacity: 2,
        has_data: false,
    }
}

fn entry_layout() -> AuditStreamLayout {
    AuditStreamLayout {
        key: AuditKey {
            format: DisclosureFormat::Standard,
            class: 8,
            entry: true,
        },
        inputs: 2,
        outputs: 2,
        capacity: 2,
        has_data: false,
    }
}

fn data_layout() -> AuditStreamLayout {
    AuditStreamLayout {
        has_data: true,
        ..plain_layout()
    }
}

/// `notes` spent notes lead, dummies fill the key's input class.
fn notes(layout: AuditStreamLayout, notes: usize) -> InputMap {
    let classes: Vec<InputClass> = (0..layout.key.class())
        .map(|slot| match slot < notes {
            true => InputClass::Note,
            false => InputClass::Dummy,
        })
        .collect();
    InputMap::from_classes(&classes, layout.inputs).unwrap()
}

fn ring_record(byte: u8) -> AuditRecord {
    AuditRecord {
        kind: RecordKind::Ring,
        amount: u64::from(byte),
        owner_key: [byte; 32],
        mint: [byte ^ 1; 32],
        nullifier_pk: field(byte),
    }
}

fn entry_evidence() -> AuditEvidence {
    AuditEvidence::Entry {
        default_input_bits: 0b01,
        inputs: vec![
            EntryInput {
                owner_key: [0xa1; 32],
                nullifier_pk: field(0x5a),
                amount: 5000,
                mint: [0x60; 32],
                blinding: field(0x61),
                data_hash: [0; 32],
                ring_data_hash: [0; 32],
            },
            EntryInput::default(),
        ],
    }
}

fn opened_envelope(
    sealed: &SealedAuditStream,
    auditor: &X25519Keypair,
    layout: AuditStreamLayout,
) -> Result<OpenedAudit, AuditError> {
    AuditEnvelope {
        eph_u: sealed.eph_u,
        salt: &SALT,
        ciphertext: &sealed.envelope,
    }
    .open(auditor, layout)
}

/// Seals raw bytes as the envelope plaintext, no clamping runs on the way in.
fn raw_envelope(plaintext: &[u8], auditor: &X25519Keypair) -> SealedAuditStream {
    let ephemeral = X25519Keypair::new();
    let mut envelope = plaintext.to_vec();
    sealing_salted_stream(&ephemeral, &auditor.pubkey(), &SALT, AUDIT_STREAM_LABEL)
        .unwrap()
        .apply_at(STREAM_FIRST_COUNTER, &mut envelope);
    SealedAuditStream {
        eph_u: ephemeral.pubkey().u(),
        envelope,
        records: Vec::new(),
        tails: Vec::new(),
    }
}

#[test]
fn the_envelope_opens_to_the_sealed_key_and_a_resend_seals_another_stream() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let seal = |salt: &[u8; 16]| {
        AuditStreamSeal {
            layout: plain_layout(),
            tx_viewing_key: &tx_viewing_key,
            salt,
            inputs: notes(plain_layout(), 1),
            evidence: AuditEvidence::None,
            records: vec![ring_record(1), AuditRecord::default()],
            tails: Vec::new(),
        }
        .seal(&auditor.pubkey())
        .unwrap()
    };
    let first = seal(&SALT);
    assert_eq!(first.eph_u, tx_viewing_key.pubkey().u());
    assert_ne!(first.envelope, seal(&[8; 16]).envelope);
    let opened = opened_envelope(&first, &auditor, plain_layout()).unwrap();
    assert_eq!(opened.tx_viewing_key.pubkey(), tx_viewing_key.pubkey());
    assert_eq!(opened.inputs, notes(plain_layout(), 1));
    assert_eq!(opened.evidence, AuditEvidence::None);
    assert!(first.tails.is_empty());
}

#[test]
fn an_unclamped_envelope_secret_is_refused() {
    let auditor = X25519Keypair::new();
    let canonical = ViewingKey::new();
    let mut unclamped = *canonical.secret_bytes();
    unclamped[0] |= 0b111;
    let sealed = raw_envelope(&[&unclamped[..], &[1], &[0; 8]].concat(), &auditor);
    assert!(matches!(
        opened_envelope(&sealed, &auditor, plain_layout()),
        Err(AuditError::NonCanonicalViewingKey)
    ));
    let sealed = raw_envelope(
        &[&canonical.secret_bytes()[..], &[1], &[0; 8]].concat(),
        &auditor,
    );
    assert_eq!(
        opened_envelope(&sealed, &auditor, plain_layout())
            .unwrap()
            .tx_viewing_key
            .pubkey(),
        canonical.pubkey()
    );
}

/// Each record sits at its own counter, read at another it opens to other bytes.
#[test]
fn a_record_opens_only_at_the_counter_of_its_slot() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let record = ring_record(0x15);
    let sealed = AuditStreamSeal {
        layout: plain_layout(),
        tx_viewing_key: &tx_viewing_key,
        salt: &SALT,
        inputs: notes(plain_layout(), 1),
        evidence: AuditEvidence::None,
        records: vec![record, AuditRecord::default()],
        tails: Vec::new(),
    }
    .seal(&auditor.pubkey())
    .unwrap();
    let opened = opened_envelope(&sealed, &auditor, plain_layout()).unwrap();
    assert_eq!(opened.record(0, &sealed.records[0]).unwrap(), record);
    assert_eq!(
        opened.record(1, &sealed.records[1]).unwrap(),
        AuditRecord::default()
    );
    assert!(!matches!(
        opened.record(1, &sealed.records[0]),
        Ok(moved) if moved == record
    ));
}

#[test]
fn a_tail_opens_only_at_the_counter_of_its_slot() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let tail = DataTail {
        data_hash: field(0x31),
        ring_data_hash: field(0x32),
    };
    let sealed = AuditStreamSeal {
        layout: data_layout(),
        tx_viewing_key: &tx_viewing_key,
        salt: &SALT,
        inputs: notes(data_layout(), 1),
        evidence: AuditEvidence::None,
        records: vec![ring_record(1), AuditRecord::default()],
        tails: vec![tail, DataTail::default()],
    }
    .seal(&auditor.pubkey())
    .unwrap();
    let opened = opened_envelope(&sealed, &auditor, data_layout()).unwrap();
    assert_eq!(opened.tail(0, &sealed.tails[0]).unwrap(), tail);
    assert_eq!(
        opened.tail(1, &sealed.tails[1]).unwrap(),
        DataTail::default()
    );
    assert_ne!(opened.tail(1, &sealed.tails[0]).unwrap(), tail);
}

#[test]
fn the_entry_evidence_and_records_round_their_own_regions() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let sealed = AuditStreamSeal {
        layout: entry_layout(),
        tx_viewing_key: &tx_viewing_key,
        salt: &SALT,
        inputs: notes(entry_layout(), 1),
        evidence: entry_evidence(),
        records: vec![AuditRecord::default(), ring_record(0x27)],
        tails: Vec::new(),
    }
    .seal(&auditor.pubkey())
    .unwrap();
    let opened = opened_envelope(&sealed, &auditor, entry_layout()).unwrap();
    assert_eq!(opened.evidence, entry_evidence());
    assert_eq!(
        opened.record(0, &sealed.records[0]).unwrap(),
        AuditRecord::default()
    );
    assert_eq!(
        opened.record(1, &sealed.records[1]).unwrap(),
        ring_record(0x27)
    );
}

#[test]
fn a_seal_off_its_layout_is_refused() {
    let auditor = X25519Keypair::new().pubkey();
    let tx_viewing_key = ViewingKey::new();
    let seal = |layout, evidence, records, tails| {
        AuditStreamSeal {
            layout,
            tx_viewing_key: &tx_viewing_key,
            salt: &SALT,
            inputs: notes(layout, 1),
            evidence,
            records,
            tails,
        }
        .seal(&auditor)
    };
    let two = vec![AuditRecord::default(); 2];
    let tail = DataTail::default();
    let cases = [
        (
            plain_layout(),
            AuditEvidence::None,
            vec![AuditRecord::default()],
            vec![],
        ),
        (plain_layout(), entry_evidence(), two.clone(), vec![]),
        (plain_layout(), AuditEvidence::None, two.clone(), vec![tail]),
        (data_layout(), AuditEvidence::None, two.clone(), vec![tail]),
        (entry_layout(), AuditEvidence::None, two, vec![]),
    ];
    for (layout, evidence, records, tails) in cases {
        assert!(matches!(
            seal(layout, evidence, records, tails),
            Err(AuditError::DisclosureLayout)
        ));
    }
}

/// The proof binds canonical evidence, bytes it cannot have bound stop the audit.
#[test]
fn evidence_outside_the_field_is_refused() {
    let auditor = X25519Keypair::new();
    let secret = *ViewingKey::new().secret_bytes();
    let plaintext = |evidence: AuditEvidence| {
        custom_ring_interface::AuditEnvelope {
            tx_viewing_secret: secret,
            real_inputs: 1,
            address_input_bits: 0,
            evidence,
        }
        .encode()
    };
    type Spoil = fn(&mut EntryInput);
    let spoiled: [Spoil; 4] = [
        |input| input.nullifier_pk = BN254_SCALAR_MODULUS_BE,
        |input| input.blinding = BN254_SCALAR_MODULUS_BE,
        |input| input.data_hash = BN254_SCALAR_MODULUS_BE,
        |input| input.ring_data_hash = BN254_SCALAR_MODULUS_BE,
    ];
    for spoil in spoiled {
        let mut entry = entry_evidence();
        let AuditEvidence::Entry { inputs, .. } = &mut entry else {
            unreachable!("the entry evidence");
        };
        spoil(&mut inputs[0]);
        let sealed = raw_envelope(&plaintext(entry), &auditor);
        assert!(matches!(
            opened_envelope(&sealed, &auditor, entry_layout()),
            Err(AuditError::DisclosureField)
        ));
    }
    let sealed = raw_envelope(&plaintext(entry_evidence()), &auditor);
    assert!(opened_envelope(&sealed, &auditor, entry_layout()).is_ok());
}

fn interleaved_layout() -> AuditStreamLayout {
    AuditStreamLayout {
        key: AuditKey {
            format: DisclosureFormat::Standard,
            class: 4,
            entry: true,
        },
        inputs: 3,
        ..entry_layout()
    }
}

/// SPP order `note, address, note` with a dummy past `n`, the second note a default-ring entry.
fn interleaved() -> InputMap {
    use InputClass::{Address, Dummy, Note};
    InputMap::from_classes(&[Note, Address, Note, Dummy], 3).unwrap()
}

fn entry_at(default_input_bits: u64, slot: usize) -> AuditEvidence {
    let AuditEvidence::Entry { inputs, .. } = entry_evidence() else {
        unreachable!("the entry evidence");
    };
    let mut openings = vec![EntryInput::default(); 3];
    openings[slot] = inputs[0];
    AuditEvidence::Entry {
        default_input_bits,
        inputs: openings,
    }
}

#[test]
fn an_address_between_notes_opens_at_its_absolute_position() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let sealed = AuditStreamSeal {
        layout: interleaved_layout(),
        tx_viewing_key: &tx_viewing_key,
        salt: &SALT,
        inputs: interleaved(),
        evidence: entry_at(0b100, 2),
        records: vec![ring_record(1), AuditRecord::default()],
        tails: Vec::new(),
    }
    .seal(&auditor.pubkey())
    .unwrap();
    let opened = opened_envelope(&sealed, &auditor, interleaved_layout()).unwrap();
    assert_eq!(opened.inputs, interleaved());
    assert_eq!(opened.inputs.note_count(), 2);
    assert_eq!(opened.inputs.slot(1), Some(InputClass::Address));
    assert_eq!(opened.evidence, entry_at(0b100, 2));
}

/// Entry bits name notes alone, and a map off the layout's count or class seals nothing.
#[test]
fn a_default_bit_on_an_address_or_a_map_off_its_layout_is_refused() {
    let auditor = X25519Keypair::new();
    let secret = *ViewingKey::new().secret_bytes();
    let plaintext = custom_ring_interface::AuditEnvelope {
        tx_viewing_secret: secret,
        real_inputs: 2,
        address_input_bits: 0b010,
        evidence: entry_at(0b010, 1),
    }
    .encode();
    let sealed = raw_envelope(&plaintext, &auditor);
    assert!(matches!(
        opened_envelope(&sealed, &auditor, interleaved_layout()),
        Err(AuditError::DisclosureField)
    ));
    let tx_viewing_key = ViewingKey::new();
    let seal = |inputs| {
        AuditStreamSeal {
            layout: interleaved_layout(),
            tx_viewing_key: &tx_viewing_key,
            salt: &SALT,
            inputs,
            evidence: entry_at(0b100, 2),
            records: vec![AuditRecord::default(); 2],
            tails: Vec::new(),
        }
        .seal(&auditor.pubkey())
    };
    for off_layout in [notes(entry_layout(), 1), notes(plain_layout(), 1)] {
        assert!(matches!(
            seal(off_layout),
            Err(AuditError::DisclosureLayout)
        ));
    }
    let on_address = AuditStreamSeal {
        layout: interleaved_layout(),
        tx_viewing_key: &tx_viewing_key,
        salt: &SALT,
        inputs: interleaved(),
        evidence: entry_at(0b010, 1),
        records: vec![AuditRecord::default(); 2],
        tails: Vec::new(),
    };
    assert!(matches!(
        on_address.seal(&auditor.pubkey()),
        Err(AuditError::DisclosureLayout)
    ));
}

#[test]
fn compact_audit_records_open_with_the_encrypted_common_mint() {
    use custom_ring_interface::SINGLE_ASSET_PAYOUT_OUTPUTS;
    let layout = AuditStreamLayout {
        key: AuditKey {
            class: 1,
            entry: false,
            format: DisclosureFormat::SingleAssetPayout,
        },
        inputs: 1,
        outputs: SINGLE_ASSET_PAYOUT_OUTPUTS,
        capacity: SINGLE_ASSET_PAYOUT_OUTPUTS,
        has_data: false,
    };
    let tx_viewing_key = ViewingKey::new();
    let auditor = X25519Keypair::new();
    let mint = [9; 32];
    let records: Vec<_> = (0..SINGLE_ASSET_PAYOUT_OUTPUTS)
        .map(|slot| AuditRecord {
            mint,
            ..ring_record(slot as u8 + 1)
        })
        .collect();
    let seal = |records: Vec<AuditRecord>| {
        AuditStreamSeal {
            layout,
            tx_viewing_key: &tx_viewing_key,
            salt: &SALT,
            inputs: notes(layout, 1),
            evidence: AuditEvidence::SingleAssetPayout { mint },
            records,
            tails: Vec::new(),
        }
        .seal(&auditor.pubkey())
    };
    let sealed = seal(records.clone()).unwrap();
    let opened = opened_envelope(&sealed, &auditor, layout).unwrap();
    for (slot, expected) in records.iter().enumerate() {
        assert_eq!(
            opened.record(slot, &sealed.records[slot]).unwrap(),
            *expected
        );
    }
    let mut mixed = records;
    mixed[1].mint = [8; 32];
    assert!(matches!(seal(mixed), Err(AuditError::DisclosureLayout)));
    let mut standard = layout;
    standard.key.format = DisclosureFormat::Standard;
    assert!(opened_envelope(&sealed, &auditor, standard).is_err());
}
