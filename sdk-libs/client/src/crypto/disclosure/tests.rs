use custom_ring_interface::{
    AuditEvidence, AuditKey, AuditStreamLayout, EntryRecord, DEFAULT_INPUT_BITS_LEN,
    ENTRY_RECORD_LEN, ENVELOPE_HEAD_LEN,
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
            class: 2,
            entry: false,
        },
        inputs: 1,
        outputs: 2,
        capacity: 2,
    }
}

fn entry_layout() -> AuditStreamLayout {
    AuditStreamLayout {
        key: AuditKey {
            class: 8,
            entry: true,
        },
        inputs: 2,
        outputs: 2,
        capacity: 2,
    }
}

/// Two valid recipient keys, one per published slot.
fn recipient_keys() -> Vec<[u8; 32]> {
    vec![
        ViewingKey::new().pubkey().u(),
        ViewingKey::new().pubkey().u(),
    ]
}

fn entry_evidence() -> AuditEvidence {
    AuditEvidence::Entry {
        default_note_bits: 0b01,
        inputs: vec![
            EntryRecord {
                owner_key: [0xa1; 32],
                nullifier_pk: field(0x5a),
                amount: 5000,
                mint: [0x60; 32],
                input_commitment: field(0x61),
            },
            EntryRecord::default(),
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
        keys: Vec::new(),
    }
}

#[test]
fn the_envelope_opens_to_the_sealed_key_and_a_resend_seals_another_stream() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let keys = recipient_keys();
    let seal = |salt: &[u8; 16]| {
        AuditStreamSeal {
            layout: plain_layout(),
            tx_viewing_key: &tx_viewing_key,
            salt,
            real_inputs: 1,
            evidence: AuditEvidence::None,
            recipient_keys: keys.clone(),
        }
        .seal(&auditor.pubkey())
        .unwrap()
    };
    let first = seal(&SALT);
    assert_eq!(first.eph_u, tx_viewing_key.pubkey().u());
    assert_ne!(first.envelope, seal(&[8; 16]).envelope);
    let opened = opened_envelope(&first, &auditor, plain_layout()).unwrap();
    assert_eq!(opened.tx_viewing_key.pubkey(), tx_viewing_key.pubkey());
    assert_eq!(opened.real_inputs, 1);
    assert_eq!(opened.evidence, AuditEvidence::None);
}

#[test]
fn an_unclamped_envelope_secret_is_refused() {
    let auditor = X25519Keypair::new();
    let canonical = ViewingKey::new();
    let mut unclamped = *canonical.secret_bytes();
    unclamped[0] |= 0b111;
    let sealed = raw_envelope(&[&unclamped[..], &[1]].concat(), &auditor);
    assert!(matches!(
        opened_envelope(&sealed, &auditor, plain_layout()),
        Err(AuditError::NonCanonicalViewingKey)
    ));
    let sealed = raw_envelope(&[&canonical.secret_bytes()[..], &[1]].concat(), &auditor);
    assert_eq!(
        opened_envelope(&sealed, &auditor, plain_layout())
            .unwrap()
            .tx_viewing_key
            .pubkey(),
        canonical.pubkey()
    );
}

/// Each key sits at its own counter, read at another it opens to other bytes.
#[test]
fn a_recipient_key_opens_only_at_the_counter_of_its_slot() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let keys = recipient_keys();
    let sealed = AuditStreamSeal {
        layout: plain_layout(),
        tx_viewing_key: &tx_viewing_key,
        salt: &SALT,
        real_inputs: 1,
        evidence: AuditEvidence::None,
        recipient_keys: keys.clone(),
    }
    .seal(&auditor.pubkey())
    .unwrap();
    let opened = opened_envelope(&sealed, &auditor, plain_layout()).unwrap();
    let read: Vec<[u8; 32]> = opened
        .recipient_keys(&sealed.keys)
        .unwrap()
        .iter()
        .map(X25519Pubkey::u)
        .collect();
    assert_eq!(read, keys);
    let swapped = [&sealed.keys[32..], &sealed.keys[..32]].concat();
    assert!(!matches!(
        opened.recipient_keys(&swapped),
        Ok(moved) if moved.iter().map(X25519Pubkey::u).collect::<Vec<_>>() == keys
    ));
}

#[test]
fn the_entry_evidence_and_the_keys_round_their_own_regions() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let keys = recipient_keys();
    let sealed = AuditStreamSeal {
        layout: entry_layout(),
        tx_viewing_key: &tx_viewing_key,
        salt: &SALT,
        real_inputs: 1,
        evidence: entry_evidence(),
        recipient_keys: keys.clone(),
    }
    .seal(&auditor.pubkey())
    .unwrap();
    let opened = opened_envelope(&sealed, &auditor, entry_layout()).unwrap();
    assert_eq!(opened.evidence, entry_evidence());
    assert_eq!(
        opened
            .recipient_keys(&sealed.keys)
            .unwrap()
            .iter()
            .map(X25519Pubkey::u)
            .collect::<Vec<_>>(),
        keys
    );
}

#[test]
fn a_seal_off_its_layout_is_refused() {
    let auditor = X25519Keypair::new().pubkey();
    let tx_viewing_key = ViewingKey::new();
    let seal = |layout, evidence, recipient_keys| {
        AuditStreamSeal {
            layout,
            tx_viewing_key: &tx_viewing_key,
            salt: &SALT,
            real_inputs: 1,
            evidence,
            recipient_keys,
        }
        .seal(&auditor)
    };
    let one = vec![recipient_keys()[0]];
    let cases = [
        (plain_layout(), AuditEvidence::None, one),
        (plain_layout(), entry_evidence(), recipient_keys()),
        (entry_layout(), AuditEvidence::None, recipient_keys()),
    ];
    for (layout, evidence, keys) in cases {
        assert!(matches!(
            seal(layout, evidence, keys),
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
            evidence,
        }
        .encode()
    };
    type Spoil = fn(&mut EntryRecord);
    let spoiled: [Spoil; 2] = [
        |input| input.nullifier_pk = BN254_SCALAR_MODULUS_BE,
        |input| input.input_commitment = BN254_SCALAR_MODULUS_BE,
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

#[test]
fn an_entry_record_of_another_length_is_refused() {
    const FULL_OPENING_LEN: usize = 200;
    let auditor = X25519Keypair::new();
    let plaintext = custom_ring_interface::AuditEnvelope {
        tx_viewing_secret: *ViewingKey::new().secret_bytes(),
        real_inputs: 1,
        evidence: entry_evidence(),
    }
    .encode();
    let records_at = ENVELOPE_HEAD_LEN + DEFAULT_INPUT_BITS_LEN;
    assert_eq!(plaintext.len(), records_at + 2 * ENTRY_RECORD_LEN);
    let widened: Vec<u8> = plaintext[records_at..]
        .chunks(ENTRY_RECORD_LEN)
        .flat_map(|record| [record, &[0; FULL_OPENING_LEN - ENTRY_RECORD_LEN]].concat())
        .collect();
    let widened = [&plaintext[..records_at], &widened].concat();
    let short = &plaintext[..plaintext.len() - 1];
    for malformed in [widened.as_slice(), short] {
        let sealed = raw_envelope(malformed, &auditor);
        assert!(matches!(
            opened_envelope(&sealed, &auditor, entry_layout()),
            Err(AuditError::DisclosureField)
        ));
    }
    let sealed = raw_envelope(&plaintext, &auditor);
    assert_eq!(
        opened_envelope(&sealed, &auditor, entry_layout())
            .unwrap()
            .evidence,
        entry_evidence()
    );
}
