//! Pins `test-vectors/proof/ring-transact-expansion.json` for the TS SDK, the client and the ring program tests.

mod frames;
mod ring_policy;

use frames::{spp_b, Fixture};
use ring_policy::config;

use custom_ring_interface::{
    cosign::ApprovalMask, input_flag, key_catalog::RingCircuit, output_flag, shape_flag,
    stream::slot_tag, transact_flag, AuditKey, AuditStreamLayout, AuditorMessage,
    ConfidentialSender, CustomRingError, FramedSenderBundle, ParsedTransact, PlainGroth16Proof,
    Replies, RingPolicy, RingRail, RingTransactData, Settlement, SignerDataCounts, SignerSet,
    SlotBody, TransferBinding, TransferFamily, TransferRoots, ANONYMOUS_PARTIES, APPROVAL_BYTE,
};
use custom_ring_interface::{
    encode_ring_body_output, encode_ring_sender_bundle_output, ring_body_output,
    ring_sender_bundle_output_body, BundleLayout, CONFIDENTIAL_DATA_FREE_BODY_LEN, MIN_REPLY_LEN,
    OUTPUT_COUNT_BYTE, RECIPIENT_BODY_LEN, RING_BODY_SCHEME_TAG, RING_SENDER_BUNDLE_SCHEME_TAG,
};
use serde::{Deserialize, Serialize};
use spr_event::{
    confidential_encrypted_output_body, OutputDataEncoding, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
};
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::{
    instruction::{CircuitId, InterfaceTransfer, OwnerTag},
    shape::{Shape, SPP_SUPPORTED_SHAPES},
};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/proof/ring-transact-expansion.json"
);

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ExpansionVectors {
    description: String,
    auditor_pubkey: String,
    cases: Vec<Case>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Case {
    name: String,
    /// `confidential`, `anonymous` or `delegate`.
    rail: String,
    compact: String,
    /// Per public leg, the asset account then the user account.
    settlements: Vec<[String; 2]>,
    transact_ix_data: String,
    spp_instruction_data: String,
    external_data_hash: String,
}

/// A delegate move into eight delivered slots, a shape SPP keys no ring authority for.
fn delegate_delivered(fixture: &Fixture) -> RingTransactData<'_> {
    let mut data = fixture.base(RingRail::Delegate, 2, 8);
    data.outputs = (0..8).map(|slot| fixture.recipient(slot)).collect();
    data
}

fn settlements(legs: usize) -> Vec<[[u8; 32]; 2]> {
    (0..legs)
        .map(|leg| [[0xe0 + leg as u8; 32], [0xf0 + leg as u8; 32]])
        .collect()
}

fn compute_vectors() -> ExpansionVectors {
    let fixture = Fixture::new();
    let config = config();
    let cases = fixture
        .cases()
        .into_iter()
        .map(|(name, data)| {
            let legs = settlements(data.interface_transfers.len());
            let borrowed: Vec<Settlement<'_>> = legs
                .iter()
                .map(|[asset_account, user_account]| Settlement {
                    asset_account,
                    user_account,
                })
                .collect();
            Case {
                name: name.to_string(),
                rail: data.rail.to_string(),
                compact: hex::encode(data.encode().unwrap()),
                settlements: legs.iter().map(|leg| leg.map(hex::encode)).collect(),
                transact_ix_data: hex::encode(data.expand(&config).unwrap().serialize().unwrap()),
                spp_instruction_data: hex::encode(data.spp_instruction_data(&config).unwrap()),
                external_data_hash: hex::encode(
                    data.external_data_hash(&config, &borrowed).unwrap(),
                ),
            }
        })
        .collect();
    ExpansionVectors {
        description: "Compact ring transact data of each rail and what \
                      the ring program forwards for it, the SPP TransactIxData, the SPP instruction \
                      data and the external data hash over the SPP tag, the data before \
                      private_tx_hash and two settlement accounts per leg. Byte 0 carries the \
                      policy, curator, no_spend, in-proof owner, own root, second tree, reply \
                      metadata and extension flags. Byte 1 indexes SPP_SUPPORTED_SHAPES below the \
                      default owner tag (bit 6) and public owners (bit 7). Byte 2 is the input \
                      count below has_data (bit 6) and entry (bit 7), byte 3 is m, byte 4 the \
                      approval mask below the co-signer count. The ring proof and the tracking \
                      revision follow, the own revision under the own root flag, the curator \
                      revision under the curator flag, the expiry as a u32, the viewing key, the \
                      salt and the extensions under their flag. The interface transfers follow, \
                      the SPL withdrawal owners under the own root flag, exit_bits and bodiless_bits \
                      of ceil(m / 8) bytes each. A slot is a u16 body length under has_data, its \
                      hash, its tag of 8 bytes or 32 on an exit and its body, 72 bytes for a recipient body and 83 for an exit \
                      without has_data. Under reply metadata a u16 reply_len and reply_len bytes \
                      per body-bearing slot follow the slots. The anonymous frame's sender bundle \
                      follows as a 32-byte tag and 32 + 40 c + 32 (m - c) bytes for c bodiless \
                      slots, then the envelope, \
                      m records of 105 bytes and under has_data m tails of 64 bytes, the lengths \
                      those of ring-disclosure-ranges.json. The auditor message is 0x04 || tx_viewing_u \
                      || envelope || records || tails. Recipient bodies forward as ring body, \
                      u16le(body_len) || body || reply. Produced by \
                      program-libs/interface/tests/transact.rs."
            .to_string(),
        auditor_pubkey: hex::encode(config.auditor_pubkey),
        cases,
    }
}

fn rail(name: &str) -> RingRail {
    [
        RingRail::Confidential,
        RingRail::Anonymous,
        RingRail::Delegate,
        RingRail::AnonymousDelegate,
    ]
    .into_iter()
    .find(|rail| rail.to_string() == name)
    .unwrap_or_else(|| panic!("unknown rail {name}"))
}

#[test]
fn ring_transact_expansion_vector() {
    let committed: ExpansionVectors =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, compute_vectors());
    let config = config();
    for case in &committed.cases {
        let compact = hex::decode(&case.compact).unwrap();
        let data = RingTransactData::parse(&compact, rail(&case.rail))
            .unwrap()
            .into_data();
        assert_eq!(data.encode().unwrap(), compact, "{}", case.name);
        let spp = data.expand(&config).unwrap();
        assert_eq!(spp.proof.b, spp_b());
        assert_eq!(&spp.salt, data.salt, "{}", case.name);
        let (auditor, sender) = spp.messages.split_last().unwrap();
        assert_eq!(auditor.view_tag, config.auditor_pubkey[1..]);
        assert_eq!(auditor.data, data.auditor_message(), "{}", case.name);
        assert_eq!(auditor.data.capacity(), auditor.data.len(), "{}", case.name);
        let sender: Vec<_> = sender
            .iter()
            .map(|message| (message.view_tag, message.data.clone()))
            .collect();
        let expected: Vec<_> = data
            .sender
            .iter()
            .map(|bundle| {
                (
                    *bundle.tag,
                    encode_ring_sender_bundle_output(bundle.body).unwrap(),
                )
            })
            .chain(
                data.extensions
                    .messages
                    .iter()
                    .map(|message| (*message.view_tag, message.data.to_vec())),
            )
            .collect();
        assert_eq!(sender, expected, "{}", case.name);
        for ((output, slot), reply) in spp
            .outputs
            .iter()
            .zip(&data.outputs)
            .zip(data.slot_replies())
        {
            assert_eq!(output.owner_tag, OwnerTag::Inline(slot.owner_tag));
            match slot.body {
                SlotBody::None => assert_eq!(output.data, None, "{}", case.name),
                SlotBody::Recipient(body) => assert_eq!(
                    output.data,
                    Some(encode_ring_body_output(body, reply).unwrap()),
                    "{}",
                    case.name
                ),
                SlotBody::Exit(_) => assert!(output
                    .data
                    .as_deref()
                    .and_then(confidential_encrypted_output_body)
                    .is_some()),
            }
        }
        let mut forwarded = vec![data.rail.spp_tag()];
        forwarded.extend(spp.serialize().unwrap());
        assert_eq!(hex::encode(forwarded), case.spp_instruction_data);
    }
}

#[test]
#[ignore = "rewrites test-vectors/proof/ring-transact-expansion.json"]
fn write_ring_transact_expansion_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}

const FRAME_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/settlement/frame.hex"
);

fn frame_lines() -> String {
    Fixture::new()
        .cases()
        .iter()
        .map(|(_, data)| hex::encode(data.encode().unwrap()) + "\n")
        .collect()
}

#[test]
fn the_frames_are_the_shared_vector() {
    assert_eq!(
        std::fs::read_to_string(FRAME_VECTOR).expect("vector file"),
        frame_lines()
    );
}

#[test]
#[ignore = "rewrites test-vectors/settlement/frame.hex"]
fn write_frame_vector() {
    std::fs::write(FRAME_VECTOR, frame_lines()).expect("write vector file");
}

#[test]
fn recipient_and_exit_slots_keep_the_borsh_framing_at_exact_capacity() {
    let fixture = Fixture::new();
    let borsh_framing = |scheme: u8, payload: &[u8]| {
        borsh::to_vec(&OutputDataEncoding::Encrypted(
            [&[scheme][..], payload].concat(),
        ))
        .unwrap()
    };
    let reply = [0x77; MIN_REPLY_LEN];
    let len = (fixture.recipient_body.len() as u16).to_le_bytes();
    let body = [&len[..], &fixture.recipient_body].concat();
    let body_and_reply = [&body[..], &reply].concat();
    for (data, scheme, payload) in [
        (
            fixture
                .tagged(1)
                .transact_output(&[])
                .unwrap()
                .data
                .unwrap(),
            RING_BODY_SCHEME_TAG,
            &body[..],
        ),
        (
            fixture
                .tagged(1)
                .transact_output(&reply)
                .unwrap()
                .data
                .unwrap(),
            RING_BODY_SCHEME_TAG,
            &body_and_reply[..],
        ),
        (
            encode_ring_sender_bundle_output(&fixture.sender_body).unwrap(),
            RING_SENDER_BUNDLE_SCHEME_TAG,
            &fixture.sender_body[..],
        ),
        (
            fixture
                .exit(1, &fixture.payload)
                .transact_output(&[])
                .unwrap()
                .data
                .unwrap(),
            CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
            &fixture.payload[..],
        ),
    ] {
        assert_eq!(data, borsh_framing(scheme, payload), "scheme {scheme}");
        assert_eq!(data.capacity(), data.len(), "scheme {scheme}");
    }
    let framed = fixture
        .tagged(1)
        .transact_output(&reply)
        .unwrap()
        .data
        .unwrap();
    assert_eq!(
        ring_body_output(&framed),
        Some((&fixture.recipient_body[..], &reply[..]))
    );
    let bundle = encode_ring_sender_bundle_output(&fixture.sender_body).unwrap();
    assert_eq!(
        ring_sender_bundle_output_body(&bundle),
        Some(&fixture.sender_body[..])
    );
    assert_eq!(ring_body_output(&bundle), None);
    let short_body = &fixture.recipient_body[..71];
    assert_eq!(
        encode_ring_body_output(short_body, &[]),
        Err(CustomRingError::OutputBodyLength)
    );
    let short_payload = [&(short_body.len() as u16).to_le_bytes()[..], short_body].concat();
    let short = borsh_framing(RING_BODY_SCHEME_TAG, &short_payload);
    assert_eq!(ring_body_output(&short), None);
}

#[test]
fn the_counts_fix_every_length_and_trailing_bytes_are_refused() {
    let fixture = Fixture::new();
    for (name, data) in fixture.cases() {
        let mut compact = data.encode().unwrap();
        compact.push(0);
        assert_eq!(
            RingTransactData::parse(&compact, data.rail),
            Err(CustomRingError::RingTransactLength),
            "{name}"
        );
        compact.truncate(compact.len() - 2);
        assert_eq!(
            RingTransactData::parse(&compact, data.rail),
            Err(CustomRingError::RingTransactLength),
            "{name}"
        );
    }
}

#[test]
fn the_output_count_stays_between_one_and_the_capacity() {
    let fixture = Fixture::new();
    for data in [
        fixture.confidential_delivered(),
        fixture.anonymous(),
        fixture.delegate(),
    ] {
        let compact = data.encode().unwrap();
        for count in [0, data.n_out + 1] {
            let mut refused = compact.clone();
            refused[OUTPUT_COUNT_BYTE] = count;
            assert_eq!(
                RingTransactData::parse(&refused, data.rail),
                Err(CustomRingError::OutputCountOutOfRange),
                "{count}"
            );
        }
        let mut empty = data.clone();
        empty.outputs.clear();
        assert_eq!(empty.encode(), Err(CustomRingError::OutputCountOutOfRange));
    }
}

/// The wide owner bit names a key and never reaches `m`.
#[test]
fn the_wide_owner_bit_sits_above_the_output_count() {
    let fixture = Fixture::new();
    let mut data = fixture.confidential_compact();
    data.wide_owners = true;
    let compact = data.encode().unwrap();
    assert_eq!(compact[OUTPUT_COUNT_BYTE], output_flag::WIDE_OWNERS | 5);
    let parsed = RingTransactData::parse(&compact, RingRail::Confidential)
        .unwrap()
        .into_data();
    assert_eq!(parsed, data);
    assert_eq!(parsed.outputs.len(), 5);
}

/// `m` moves the chains' prefix, never a slot's index, the suffix leaves the frame.
#[test]
fn a_compact_frame_omits_the_suffix_and_keeps_the_capacity() {
    let fixture = Fixture::new();
    let data = fixture.confidential_compact();
    let compact = data.encode().unwrap();
    assert_eq!(compact[OUTPUT_COUNT_BYTE], 5);
    let parsed = RingTransactData::parse(&compact, RingRail::Confidential).unwrap();
    let stream = parsed.audit_stream();
    assert_eq!((stream.outputs, stream.capacity), (5, 8));
    assert_eq!(parsed.data().outputs.len(), 5);
    assert_eq!(parsed.data().n_out, 8);
    let full = fixture.confidential_delivered().encode().unwrap();
    assert!(compact.len() < full.len());
    assert_eq!(
        data.transfer_circuit(0),
        fixture.confidential_delivered().transfer_circuit(0)
    );
    let spp = data.expand(&config()).unwrap();
    assert_eq!(spp.outputs.len(), 5);
    let CircuitId::ConfidentialRingEddsa(1, 8, _) = spp.circuit else {
        panic!("the shape keeps the capacity");
    };
}

#[test]
fn the_frame_bitmaps_are_disjoint_and_stay_inside_the_count() {
    let fixture = Fixture::new();
    let data = fixture.anonymous();
    let compact = data.encode().unwrap();
    let exit_bits = bits_offset(&data, &compact);
    assert_eq!(compact[exit_bits], 0b0100);
    assert_eq!(compact[exit_bits + 1], 0b0001);
    for (exits, bodiless, refusal) in [
        (0b0100, 0b0100, CustomRingError::BodilessExit),
        (0b0100, 1 << 4, CustomRingError::InvalidInstructionData),
        (1 << 4, 0b0001, CustomRingError::InvalidInstructionData),
    ] {
        let mut refused = compact.clone();
        refused[exit_bits] = exits;
        refused[exit_bits + 1] = bodiless;
        assert_eq!(
            RingTransactData::parse(&refused, RingRail::Anonymous),
            Err(refusal),
            "{exits:#b} {bodiless:#b}"
        );
    }
}

/// The bitmaps follow the interface transfers, past the only field the frame repeats.
fn bits_offset(data: &RingTransactData<'_>, compact: &[u8]) -> usize {
    let first_hash = compact
        .windows(32)
        .position(|window| window == data.outputs[0].hash)
        .unwrap();
    first_hash - 2 * data.outputs.len().div_ceil(8)
}

/// A slot's class is framing alone, no statement element reads it.
#[test]
fn a_bodiless_slot_forwards_no_data_at_any_index() {
    let fixture = Fixture::new();
    let compact = fixture.anonymous_compact().encode().unwrap();
    let parsed = RingTransactData::parse(&compact, RingRail::Anonymous)
        .unwrap()
        .into_data();
    assert_eq!(parsed.outputs[0].body, SlotBody::None);
    let mut truncated = compact.clone();
    let body = compact
        .windows(fixture.recipient_body.len())
        .position(|window| window == fixture.recipient_body)
        .unwrap();
    truncated.remove(body);
    assert!(RingTransactData::parse(&truncated, RingRail::Anonymous).is_err());
    let spp = parsed.expand(&config()).unwrap();
    assert_eq!(spp.outputs[0].data, None);
    assert_eq!(
        spp.outputs[1].data,
        Some(encode_ring_body_output(&fixture.recipient_body, &[]).unwrap())
    );
    assert_eq!(
        parsed.sender.unwrap().body.len(),
        BundleLayout {
            outputs: parsed.outputs.len(),
            change: 1
        }
        .byte_len()
    );
    let mut later = fixture.anonymous();
    later.outputs[3].body = SlotBody::None;
    later.sender = Some(FramedSenderBundle {
        tag: &fixture.tags[0],
        body: &fixture.sender_body[..BundleLayout {
            outputs: 4,
            change: 2,
        }
        .byte_len()],
    });
    let compact = later.encode().unwrap();
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Anonymous)
            .unwrap()
            .into_data(),
        later
    );
}

/// SPP binds an exit's tag to its owner, any other tag is cut to what the frame carries.
#[test]
fn an_exit_keeps_its_whole_tag_and_a_ring_slot_refuses_a_longer_one() {
    let fixture = Fixture::new();
    let data = fixture.anonymous();
    let compact = data.encode().unwrap();
    let parsed = RingTransactData::parse(&compact, RingRail::Anonymous).unwrap();
    assert_eq!(parsed.data().outputs[2].owner_tag, fixture.bytes[14]);
    assert_eq!(
        parsed.data().outputs[1].owner_tag,
        slot_tag(fixture.tags[1])
    );
    let mut longer = data.clone();
    longer.outputs[1].owner_tag = fixture.tags[1];
    assert_eq!(longer.encode(), Err(CustomRingError::RingTransactLength));
}

/// The proof reads no tag, the frame carries any value the sender names.
#[test]
fn a_slot_tag_is_outside_the_frame_checks() {
    let fixture = Fixture::new();
    let mut data = fixture.anonymous();
    data.outputs[1].owner_tag = slot_tag([0xff; 32]);
    data.outputs[0].owner_tag = slot_tag([0xfe; 32]);
    let compact = data.encode().unwrap();
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Anonymous)
            .unwrap()
            .into_data(),
        data
    );
}

#[test]
fn reply_metadata_is_one_length_on_the_anonymous_frame_alone() {
    let fixture = Fixture::new();
    let data = fixture.anonymous_replies(MIN_REPLY_LEN as u16);
    let compact = data.encode().unwrap();
    let parsed = RingTransactData::parse(&compact, RingRail::Anonymous)
        .unwrap()
        .into_data();
    assert_eq!(parsed, data);
    let spp = parsed.expand(&config()).unwrap();
    let replies: Vec<&[u8]> = parsed.slot_replies().collect();
    assert_eq!(
        replies,
        [
            &[][..],
            &fixture.replies[..MIN_REPLY_LEN],
            &[][..],
            &fixture.replies[MIN_REPLY_LEN..2 * MIN_REPLY_LEN],
        ]
    );
    // A reply follows the body it shares a secret with, a change and an exit carry none.
    assert_eq!(spp.outputs[0].data, None);
    assert_eq!(
        ring_body_output(spp.outputs[1].data.as_deref().unwrap()),
        Some((&fixture.recipient_body[..], replies[1]))
    );
    assert_eq!(
        ring_body_output(spp.outputs[3].data.as_deref().unwrap()),
        Some((&fixture.recipient_body[..], replies[3]))
    );
    assert_eq!(
        Replies::new(
            MIN_REPLY_LEN as u16 - 1,
            &fixture.replies[..2 * (MIN_REPLY_LEN - 1)],
        ),
        Err(CustomRingError::ReplyLength),
    );
    let mut uneven = fixture.anonymous();
    uneven.replies =
        Some(Replies::new(MIN_REPLY_LEN as u16, &fixture.replies[..MIN_REPLY_LEN]).unwrap());
    assert_eq!(uneven.encode(), Err(CustomRingError::ReplyLength));
    let bare = fixture.anonymous().encode().unwrap();
    let mut claimed = bare.clone();
    claimed[transact_flag::BYTE] |= transact_flag::REPLY_METADATA;
    assert!(RingTransactData::parse(&claimed, RingRail::Anonymous).is_err());
    for (name, data) in fixture.cases() {
        if data.rail.anonymous_frame() {
            continue;
        }
        let mut foreign = data.encode().unwrap();
        foreign[transact_flag::BYTE] |= transact_flag::REPLY_METADATA;
        assert_eq!(
            RingTransactData::parse(&foreign, data.rail),
            Err(CustomRingError::FlagNotAllowed),
            "{name}"
        );
    }
}

fn shape_index(n_in: usize, n_out: usize) -> u8 {
    let shape = Shape::new(n_in, n_out);
    SPP_SUPPORTED_SHAPES
        .iter()
        .position(|supported| *supported == shape)
        .unwrap() as u8
}

#[test]
fn counts_outside_the_keyed_shapes_are_refused() {
    let fixture = Fixture::new();
    let policy = fixture.confidential_policy().encode().unwrap();
    let mut unindexed = policy.clone();
    unindexed[1] = SPP_SUPPORTED_SHAPES.len() as u8;
    assert_eq!(
        RingTransactData::parse(&unindexed, RingRail::Confidential),
        Err(CustomRingError::RingShapeUnkeyed)
    );
    let mut excess = policy;
    excess[2] = excess[2] & !0b0011_1111 | 3;
    assert_eq!(
        RingTransactData::parse(&excess, RingRail::Confidential),
        Err(CustomRingError::RingTransactLength)
    );
    let mut narrow = fixture.anonymous().encode().unwrap();
    narrow[1] = shape_index(8, 16) | (narrow[1] & !0b0011_1111);
    narrow[2] = narrow[2] & !0b0011_1111 | 6;
    assert_eq!(
        RingTransactData::parse(&narrow, RingRail::Anonymous),
        Err(CustomRingError::RingShapeUnkeyed)
    );
    let mut wide_entry = fixture.anonymous_entry().encode().unwrap();
    wide_entry[1] = shape_index(32, 2) | (wide_entry[1] & !0b0011_1111);
    wide_entry[2] = wide_entry[2] & !0b0011_1111 | 25;
    wide_entry[OUTPUT_COUNT_BYTE] |= output_flag::WIDE_OWNERS;
    assert_eq!(
        RingTransactData::parse(&wide_entry, RingRail::Anonymous),
        Err(CustomRingError::RingShapeUnkeyed)
    );
}

#[test]
fn anonymous_header_flags_off_the_anonymous_rail_are_refused() {
    let fixture = Fixture::new();
    for bit in [shape_flag::DEFAULT_OWNER_TAG, shape_flag::PUBLIC_OWNERS] {
        let mut flagged = fixture.confidential_policy().encode().unwrap();
        flagged[shape_flag::BYTE] |= bit;
        assert_eq!(
            RingTransactData::parse(&flagged, RingRail::Confidential),
            Err(CustomRingError::FlagNotAllowed),
            "{bit:#x}"
        );
    }
    let mut both = fixture.anonymous_public_owners().encode().unwrap();
    both[shape_flag::BYTE] |= shape_flag::DEFAULT_OWNER_TAG;
    assert_eq!(
        RingTransactData::parse(&both, RingRail::Anonymous),
        Err(CustomRingError::FlagNotAllowed)
    );
}

#[test]
fn the_delegate_reads_no_policy_and_spends_no_default_note() {
    let fixture = Fixture::new();
    for (byte, bit) in [
        (input_flag::BYTE, input_flag::ENTRY),
        (transact_flag::BYTE, transact_flag::POLICY),
        (transact_flag::BYTE, transact_flag::OWN_ROOT),
    ] {
        let mut compact = fixture.delegate().encode().unwrap();
        compact[byte] |= bit;
        assert_eq!(
            RingTransactData::parse(&compact, RingRail::Delegate),
            Err(CustomRingError::FlagNotAllowed),
            "byte {byte} bit {bit:#x}"
        );
    }
    let mut cached = fixture.delegate();
    cached.extensions.cache = Some(
        spr_interface::instruction::instruction_data::transact::CacheAccess {
            read_bitmap: 1,
            write_slots:
                spr_interface::instruction::instruction_data::transact::CacheAccess::NO_WRITES,
        },
    );
    assert_eq!(cached.encode(), Err(CustomRingError::FlagNotAllowed));
}

#[test]
fn a_frame_on_the_entry_key_parses_on_the_owner_rails() {
    let fixture = Fixture::new();
    let mut data = fixture.base(RingRail::Confidential, 2, 2);
    data.entry = true;
    data.outputs = vec![fixture.recipient(0), fixture.recipient(1)];
    let data = fixture.with_audit_stream(data);
    let compact = data.encode().unwrap();
    assert_eq!(
        compact[input_flag::BYTE] & input_flag::ENTRY,
        input_flag::ENTRY
    );
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Confidential)
            .unwrap()
            .audit_stream()
            .key,
        AuditKey {
            format: custom_ring_interface::DisclosureFormat::Standard,
            class: 8,
            entry: true
        }
    );
}

#[test]
fn flags_the_rail_forbids_are_refused() {
    let fixture = Fixture::new();
    let mut curator = fixture.confidential_delivered().encode().unwrap();
    curator[transact_flag::BYTE] |= transact_flag::CURATOR;
    assert_eq!(
        RingTransactData::parse(&curator, RingRail::Confidential),
        Err(CustomRingError::FlagNotAllowed)
    );
}

/// A delegate exit takes SPP's authority exit selector, a move keeps the authority rail.
#[test]
fn a_delegate_exit_selects_the_exit_circuit() {
    let fixture = Fixture::new();
    let mut exit = fixture.delegate();
    assert_eq!(exit.circuit(), CircuitId::RingAuthority(2, 2, 3));
    exit.outputs[1] = fixture.exit(1, &fixture.payload);
    let compact = fixture.with_audit_stream(exit).encode().unwrap();
    let parsed = RingTransactData::parse(&compact, RingRail::Delegate)
        .unwrap()
        .into_data();
    assert_eq!(parsed.circuit(), CircuitId::RingAuthorityExit(2, 2, 3));
}

#[test]
fn the_rail_follows_the_instruction_and_the_ring_mode() {
    use custom_ring_interface::{InstructionTag, RingMode};
    use InstructionTag::{AuthorityTransfer, Merge, Transfer};
    let delegate = solana_address::Address::new_from_array([3; 32]);
    let ring = |mode: RingMode, delegate: Option<solana_address::Address>| {
        let mut ring = <RingPolicy as bytemuck::Zeroable>::zeroed();
        ring.mode = mode as u8;
        ring.delegate = delegate.unwrap_or_default();
        ring
    };
    let rail = |tag, mode| RingRail::new(tag, &ring(mode, Some(delegate)));
    assert_eq!(
        rail(Transfer, RingMode::Confidential),
        Ok(RingRail::Confidential)
    );
    assert_eq!(rail(Transfer, RingMode::Anonymous), Ok(RingRail::Anonymous));
    assert_eq!(
        rail(AuthorityTransfer, RingMode::Confidential),
        Ok(RingRail::Delegate)
    );
    assert_eq!(
        rail(AuthorityTransfer, RingMode::Anonymous),
        Ok(RingRail::AnonymousDelegate)
    );
    assert_eq!(
        rail(Merge, RingMode::Confidential),
        Err(CustomRingError::InvalidInstructionData)
    );
    for mode in [RingMode::Confidential, RingMode::Anonymous] {
        assert_eq!(
            RingRail::new(AuthorityTransfer, &ring(mode, None)),
            Err(CustomRingError::DelegateDisabled)
        );
    }
    let mut unknown = ring(RingMode::Confidential, None);
    unknown.mode = 1;
    assert_eq!(
        RingRail::new(Transfer, &unknown),
        Err(CustomRingError::InvalidRingMode)
    );
}

/// Without `has_data` every body has one length, the frame carries none.
#[test]
fn a_body_past_its_plain_length_needs_has_data() {
    let fixture = Fixture::new();
    let long: Vec<u8> = (0..=CONFIDENTIAL_DATA_FREE_BODY_LEN as u8).collect();
    let mut exit = fixture.confidential_delivered();
    exit.outputs[3] = fixture.exit(3, &long);
    assert_eq!(exit.encode(), Err(CustomRingError::RingTransactLength));
    let mut body = fixture.confidential_delivered();
    body.outputs[0].body = SlotBody::Recipient(&fixture.extended_body);
    assert_eq!(body.encode(), Err(CustomRingError::RingTransactLength));
}

#[test]
fn a_data_frame_carries_each_length_and_each_tail() {
    let fixture = Fixture::new();
    let data = fixture.confidential_data();
    let compact = data.encode().unwrap();
    assert_eq!(
        compact[input_flag::BYTE] & input_flag::HAS_DATA,
        input_flag::HAS_DATA
    );
    let parsed = RingTransactData::parse(&compact, RingRail::Confidential)
        .unwrap()
        .into_data();
    assert_eq!(parsed, data);
    assert_eq!(parsed.outputs[0].tail, Some(&fixture.tails[0]));
    assert_eq!(
        parsed.outputs[0].body,
        SlotBody::Recipient(&fixture.extended_body)
    );
    let stream = data.audit_stream().unwrap();
    assert!(stream.has_data);
    let message = data.auditor_message();
    assert_eq!(message.len(), stream.message_len());
    let read = AuditorMessage::parse(&message, stream).unwrap();
    assert_eq!(read.tail(1), Some(&fixture.tails[1]));
    assert_eq!(read.record(1), Some(fixture.records[1].as_slice()));
    let mut tailless = data.clone();
    tailless.outputs[1].tail = None;
    assert_eq!(tailless.encode(), Err(CustomRingError::RingTransactLength));
    let mut unflagged = fixture.confidential_delivered();
    unflagged.outputs[0].tail = Some(&fixture.tails[0]);
    assert_eq!(unflagged.encode(), Err(CustomRingError::RingTransactLength));
    // The flag alone shifts every later field.
    let mut claimed = fixture.confidential_delivered().encode().unwrap();
    claimed[input_flag::BYTE] |= input_flag::HAS_DATA;
    assert!(RingTransactData::parse(&claimed, RingRail::Confidential).is_err());
}

#[test]
fn approval_totals_cost_a_digest_and_at_most_the_extension_flags() {
    let fixture = Fixture::new();
    for (mut data, delta) in [
        (fixture.confidential_thresholds(), 33),
        (fixture.confidential_extensions(), 32),
    ] {
        let before = data.encode().unwrap().len();
        data.extensions.approval_totals = Some(&fixture.fields[73]);
        let encoded = data.encode().unwrap();
        assert_eq!(encoded.len() - before, delta);
        let parsed = RingTransactData::parse(&encoded, RingRail::Confidential).unwrap();
        assert_eq!(
            parsed.into_data().extensions.approval_totals,
            Some(&fixture.fields[73])
        );
    }
}

#[test]
fn signer_data_counts_cost_a_u64_and_at_most_the_extension_flags() {
    let fixture = Fixture::new();
    let counts = SignerDataCounts::new(1 | 3 << SignerDataCounts::ENTRY_BITS).unwrap();
    for (mut data, delta) in [
        (fixture.confidential_thresholds(), 9),
        (fixture.confidential_extensions(), 8),
    ] {
        let before = data.encode().unwrap().len();
        assert_eq!(data.signer_data_counts(), SignerDataCounts::default());
        data.extensions.signer_data_counts = Some(counts);
        let encoded = data.encode().unwrap();
        assert_eq!(encoded.len() - before, delta);
        let parsed = RingTransactData::parse(&encoded, RingRail::Confidential).unwrap();
        assert_eq!(parsed.data().signer_data_counts(), counts);
    }
}

#[test]
fn the_frame_refuses_a_zero_count_and_a_bit_past_the_last_entry() {
    let fixture = Fixture::new();
    let mut data = fixture.confidential_extensions();
    data.extensions.signer_data_counts = Some(SignerDataCounts::default());
    assert_eq!(data.encode(), Err(CustomRingError::InvalidSignerDataCounts));
    let counts = SignerDataCounts::new(0x0123_4567_89ab_cdef & ((1 << 60) - 1)).unwrap();
    data.extensions.signer_data_counts = Some(counts);
    let encoded = data.encode().unwrap();
    let bytes = counts.packed().to_le_bytes();
    let at = encoded
        .windows(bytes.len())
        .position(|window| window == bytes)
        .unwrap();
    for (name, packed) in [("zero", 0u64), ("high bit", 1 << 60)] {
        let mut forged = encoded.clone();
        forged[at..at + bytes.len()].copy_from_slice(&packed.to_le_bytes());
        assert_eq!(
            RingTransactData::parse(&forged, RingRail::Confidential).err(),
            Some(CustomRingError::InvalidSignerDataCounts),
            "{name}"
        );
    }
}

#[test]
fn the_extensions_reach_the_forwarded_data() {
    let fixture = Fixture::new();
    let data = fixture.confidential_extensions();
    let compact = data.encode().unwrap();
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Confidential)
            .unwrap()
            .into_data(),
        data
    );
    let spp = data.expand(&config()).unwrap();
    assert_eq!(spp.data_hash, Some(fixture.fields[70]));
    assert_eq!(spp.ring_data_hash, Some(fixture.fields[71]));
    assert_eq!(spp.messages.len(), 2, "the auditor message stays last");
    assert_eq!(spp.messages[0].view_tag, fixture.fields[72]);
    assert_eq!(spp.messages[0].data, fixture.payload);
    assert_eq!(spp.messages[1].view_tag, config().auditor_pubkey[1..]);
    let mut unknown = compact.clone();
    let offset = compact
        .windows(fixture.salt.len())
        .position(|window| window == fixture.salt)
        .unwrap()
        + fixture.salt.len();
    unknown[offset] |= 1 << 7;
    assert_eq!(
        RingTransactData::parse(&unknown, RingRail::Confidential),
        Err(CustomRingError::FlagNotAllowed)
    );
}

#[test]
fn a_tag_on_the_wire_reaches_the_external_data_hash_at_its_width() {
    let fixture = Fixture::new();
    let config = config();
    let hash = |data: &RingTransactData<'_>| {
        let compact = data.encode().unwrap();
        RingTransactData::parse(&compact, RingRail::Confidential)
            .unwrap()
            .into_data()
            .external_data_hash(&config, &[])
            .unwrap()
    };
    let honest = fixture.confidential_delivered();
    assert!(honest.outputs[3].is_exit() && !honest.outputs[0].is_exit());
    assert_eq!(
        hash(&honest),
        honest.external_data_hash(&config, &[]).unwrap()
    );
    let mut slot = honest.clone();
    slot.outputs[0].owner_tag[31] ^= 1;
    assert_ne!(hash(&slot), hash(&honest));
    let mut exit = honest.clone();
    exit.outputs[3].owner_tag[0] ^= 1;
    assert_ne!(hash(&exit), hash(&honest));
    let mut wide = honest.clone();
    wide.outputs[0].owner_tag[0] ^= 1;
    assert!(wide.encode().is_err());
}

/// SPP's proof binds the hash, a byte the ring proof leaves out still cannot move under it.
#[test]
fn the_external_data_hash_binds_every_delivery_byte() {
    let fixture = Fixture::new();
    let config = config();
    let hash = |data: &RingTransactData<'_>| data.external_data_hash(&config, &[]).unwrap();
    let garbage = [0xee; RECIPIENT_BODY_LEN];
    let other_payload = [0xee; CONFIDENTIAL_DATA_FREE_BODY_LEN];
    for (name, honest) in [
        ("confidential", fixture.confidential_delivered()),
        ("anonymous", fixture.anonymous()),
        ("delegate", fixture.delegate()),
        ("anonymous delegate", fixture.anonymous_delegate()),
    ] {
        let reference = hash(&honest);
        let mut body = honest.clone();
        let slot = body
            .outputs
            .iter()
            .position(|output| matches!(output.body, SlotBody::Recipient(_)))
            .unwrap();
        body.outputs[slot].body = SlotBody::Recipient(&garbage);
        assert_ne!(hash(&body), reference, "{name} body");
        let mut tag = honest.clone();
        tag.outputs[slot].owner_tag = slot_tag(fixture.bytes[40]);
        assert_ne!(hash(&tag), reference, "{name} tag");
        let mut record = honest.clone();
        record.outputs[slot].record = &fixture.records[15];
        assert_ne!(hash(&record), reference, "{name} record");
    }
    let confidential = fixture.confidential_delivered();
    let mut exit = confidential.clone();
    exit.outputs[3].body = SlotBody::Exit(&other_payload);
    assert_ne!(hash(&exit), hash(&confidential), "exit body");
    let honest = fixture.anonymous();
    let mut bundle = honest.clone();
    let body = bundle.sender.unwrap().body;
    bundle.sender = Some(FramedSenderBundle {
        tag: &fixture.tags[6],
        body,
    });
    assert_ne!(hash(&bundle), hash(&honest), "bundle tag");
    let mut bundle = honest.clone();
    let tag = bundle.sender.unwrap().tag;
    bundle.sender = Some(FramedSenderBundle {
        tag,
        body: &fixture.envelope[..BundleLayout {
            outputs: 4,
            change: 1,
        }
        .byte_len()],
    });
    assert_ne!(hash(&bundle), hash(&honest), "bundle body");
    let replied = fixture.anonymous_replies(MIN_REPLY_LEN as u16);
    let mut reply = replied.clone();
    reply.replies =
        Some(Replies::new(MIN_REPLY_LEN as u16, &fixture.envelope[..2 * MIN_REPLY_LEN]).unwrap());
    assert_ne!(hash(&reply), hash(&replied), "reply");
}

#[test]
fn a_cached_selector_keeps_the_rail_key() {
    use spr_interface::instruction::instruction_data::transact::CacheAccess;
    let fixture = Fixture::new();
    let access = CacheAccess {
        read_bitmap: 0b1,
        write_slots: CacheAccess::NO_WRITES,
    };
    let mut data = fixture.confidential_extensions();
    data.extensions.cache = Some(access);
    assert_eq!(
        data.circuit(),
        CircuitId::ConfidentialRingEddsaCached(2, 2, 3, access)
    );
    let compact = data.encode().unwrap();
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Confidential)
            .unwrap()
            .into_data(),
        data
    );
}

/// A cache account past the settlement groups is no owner, a run through it reads an unsigned owner.
#[test]
fn a_cached_frames_owner_run_stops_short_of_its_cache_account() {
    use custom_ring_interface::InputTrees;
    use spr_interface::verifying_keys::CacheAccess;
    let fixture = Fixture::new();
    let mut data = fixture.confidential_extensions();
    let trees = match data.input_trees {
        InputTrees::One(_) => 1,
        InputTrees::Two { .. } => 2,
    };
    let start =
        custom_ring_interface::RING_TRANSACT_ACCOUNT_PREFIX_LEN + trees + data.nullifiers.len();
    let spp: Vec<usize> = (0..start + 3).collect();
    assert_eq!(
        data.owner_signers(&spp, 0).unwrap(),
        [start, start + 1, start + 2]
    );
    data.extensions.cache = Some(CacheAccess {
        read_bitmap: 0b1,
        write_slots: CacheAccess::NO_WRITES,
    });
    assert_eq!(data.owner_signers(&spp, 0).unwrap(), [start, start + 1]);
}

/// A public-owner frame carries no hidden owner's proof data and settles on SPP's confidential rail.
#[test]
fn public_owners_select_the_confidential_circuit() {
    let fixture = Fixture::new();
    let data = fixture.anonymous_public_owners();
    assert_eq!(data.circuit(), CircuitId::ConfidentialRingEddsa(2, 2, 3));
    let compact = data.encode().unwrap();
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Anonymous)
            .unwrap()
            .into_data(),
        data
    );
    let mut with_proof = data.clone();
    with_proof.anonymous = fixture.anonymous_compact().anonymous;
    assert!(with_proof.anonymous.unwrap().default_owner_tag.is_none());
    assert_eq!(
        ParsedTransact::new(with_proof.clone()).err(),
        Some(CustomRingError::FlagNotAllowed),
    );
    assert_eq!(with_proof.encode(), Err(CustomRingError::FlagNotAllowed));
    let hidden = fixture.anonymous();
    assert!(matches!(
        hidden.circuit(),
        CircuitId::AnonymousRingEddsa(3, 4, 3, _)
    ));
}

#[test]
fn the_approval_byte_sits_past_the_header() {
    let fixture = Fixture::new();
    let data = fixture.confidential_policy();
    let compact = data.encode().unwrap();
    assert_eq!(compact[APPROVAL_BYTE], data.approval.bits());
    for byte in [0b0000_0100, 0b0010_0000] {
        let mut refused = compact.clone();
        refused[APPROVAL_BYTE] = byte;
        assert!(RingTransactData::parse(&refused, RingRail::Confidential).is_err());
    }
    let parsed = RingTransactData::parse(&compact, RingRail::Confidential)
        .unwrap()
        .into_data();
    assert_eq!(parsed.approval, ApprovalMask::OUTFLOW);
}

#[test]
fn the_in_proof_owner_is_refused_off_the_confidential_rail() {
    let fixture = Fixture::new();
    for (name, data) in fixture.cases() {
        if data.rail == RingRail::Confidential {
            continue;
        }
        let mut compact = data.encode().unwrap();
        compact[transact_flag::BYTE] |= transact_flag::OWNER_IN_PROOF;
        assert_eq!(
            RingTransactData::parse(&compact, data.rail),
            Err(CustomRingError::FlagNotAllowed),
            "{name}"
        );
    }
}

#[test]
fn a_mixed_anonymous_output_set_round_trips_and_frames_each_body() {
    let fixture = Fixture::new();
    let data = fixture.anonymous();
    let compact = data.encode().unwrap();
    let parsed = RingTransactData::parse(&compact, RingRail::Anonymous)
        .unwrap()
        .into_data();
    assert_eq!(parsed.outputs, data.outputs);
    assert_eq!(parsed.sender, data.sender);
    let framed = |scheme: u8, body: &[u8]| {
        Some(
            borsh::to_vec(&OutputDataEncoding::Encrypted(
                [&[scheme][..], body].concat(),
            ))
            .unwrap(),
        )
    };
    let body = [
        &(fixture.recipient_body.len() as u16).to_le_bytes()[..],
        &fixture.recipient_body,
    ]
    .concat();
    let expected = [
        ([0; 32], None),
        (
            slot_tag(fixture.tags[1]),
            framed(RING_BODY_SCHEME_TAG, &body),
        ),
        (
            fixture.bytes[14],
            framed(CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, &fixture.payload),
        ),
        (
            slot_tag(fixture.tags[3]),
            framed(RING_BODY_SCHEME_TAG, &body),
        ),
    ];
    for (slot, (output, (owner_tag, data))) in parsed.outputs.iter().zip(expected).enumerate() {
        let spp = output.transact_output(&[]).unwrap();
        assert_eq!(spp.utxo_hash, fixture.fields[10 + slot], "slot {slot}");
        assert_eq!(spp.owner_tag, OwnerTag::Inline(owner_tag), "slot {slot}");
        assert_eq!(spp.data, data, "slot {slot}");
    }
}

#[test]
fn the_sender_bundle_length_follows_the_output_and_bodiless_counts() {
    let fixture = Fixture::new();
    let mut data = fixture.anonymous();
    for len in [
        0,
        BundleLayout {
            outputs: 3,
            change: 1,
        }
        .byte_len(),
        BundleLayout {
            outputs: 5,
            change: 1,
        }
        .byte_len(),
        BundleLayout {
            outputs: 4,
            change: 2,
        }
        .byte_len(),
    ] {
        data.sender = Some(FramedSenderBundle {
            tag: &fixture.tags[0],
            body: &fixture.sender_body[..len],
        });
        assert_eq!(data.encode(), Err(CustomRingError::RingTransactLength));
    }
}

#[test]
fn the_sender_bundle_is_present_exactly_on_the_anonymous_frame() {
    let fixture = Fixture::new();
    let mut anonymous = fixture.anonymous();
    anonymous.sender = None;
    assert_eq!(anonymous.encode(), Err(CustomRingError::RingTransactLength));
    let mut confidential = fixture.confidential_policy();
    confidential.sender = fixture.sender(2);
    assert_eq!(
        confidential.encode(),
        Err(CustomRingError::RingTransactLength)
    );
}

#[test]
fn bitmap_bits_past_the_count_are_refused() {
    let fixture = Fixture::new();
    let mut compact = fixture.confidential_policy().encode().unwrap();
    let tree_bitmap = compact.len() - 9;
    compact[tree_bitmap] |= 1 << 7;
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Confidential),
        Err(CustomRingError::InvalidInstructionData)
    );
}

#[test]
fn an_spp_point_off_the_curve_is_refused_at_expansion() {
    let fixture = Fixture::new();
    let off_curve = PlainGroth16Proof {
        proof_b: [0xff; 64],
        ..fixture.spp_proof
    };
    let mut data = fixture.delegate();
    data.spp_proof = &off_curve;
    let compact = data.encode().unwrap();
    let parsed = RingTransactData::parse(&compact, RingRail::Delegate).unwrap();
    assert_eq!(
        parsed.data().expand(&config()),
        Err(CustomRingError::InvalidSppProofPoint)
    );
}

#[test]
fn every_rail_reads_its_audit_stream() {
    let fixture = Fixture::new();
    let key = |class, entry| AuditKey {
        format: custom_ring_interface::DisclosureFormat::Standard,
        class,
        entry,
    };
    for (data, key, inputs, outputs, has_data) in [
        (fixture.confidential_policy(), key(24, false), 2, 2, false),
        (
            fixture.confidential_delivered(),
            key(16, false),
            1,
            8,
            false,
        ),
        (
            fixture.confidential_in_proof_owner(),
            key(24, false),
            2,
            4,
            false,
        ),
        (fixture.confidential_data(), key(24, false), 2, 2, true),
        (fixture.delegate(), key(24, false), 2, 2, false),
        (fixture.anonymous_delegate(), key(24, false), 2, 2, false),
        (fixture.anonymous(), key(24, false), 3, 4, false),
        (fixture.anonymous_entry(), key(8, true), 2, 2, false),
    ] {
        let expected = AuditStreamLayout {
            key,
            inputs,
            outputs,
            capacity: if key.entry { 4 } else { outputs },
            has_data,
        };
        assert_eq!(data.audit_stream(), Ok(expected), "{key:?}");
        assert_eq!(expected.checked(), Ok(expected), "{key:?}");
        let compact = data.encode().unwrap();
        assert_eq!(
            RingTransactData::parse(&compact, data.rail)
                .unwrap()
                .audit_stream(),
            expected,
            "{key:?}"
        );
    }
    assert_eq!(
        delegate_delivered(&fixture).audit_stream(),
        Err(CustomRingError::RingShapeUnkeyed)
    );
}

fn encoded_cases(fixture: &Fixture) -> Vec<(&'static str, RingTransactData<'_>, Vec<u8>)> {
    fixture
        .cases()
        .into_iter()
        .map(|(name, data)| {
            let compact = data.encode().unwrap();
            (name, data, compact)
        })
        .collect()
}

#[test]
fn the_compact_data_reads_back_at_exact_capacity() {
    let fixture = Fixture::new();
    for (name, data, compact) in encoded_cases(&fixture) {
        assert_eq!(compact.capacity(), compact.len(), "{name}");
        let parsed = RingTransactData::parse(&compact, data.rail)
            .unwrap()
            .into_data();
        assert_eq!(parsed, data, "{name}");
    }
}

#[test]
fn a_truncated_or_appended_ciphertext_is_refused() {
    let fixture = Fixture::new();
    for (name, data, compact) in encoded_cases(&fixture) {
        let stream = data.audit_stream().unwrap();
        let envelope = stream.envelope().len;
        // The envelope and the records sit whole ahead of private_tx_hash.
        let start = compact
            .windows(envelope)
            .position(|window| window == data.envelope)
            .unwrap();
        let end = start + envelope + stream.records_len() + stream.tails_len();
        assert_eq!(compact[start..start + envelope], *data.envelope, "{name}");
        assert_eq!(&compact[end..end + 32], data.private_tx_hash, "{name}");
        // A byte fewer or more shifts every later section.
        let mut truncated = compact.clone();
        truncated.remove(end - 1);
        let mut appended = compact.clone();
        appended.insert(end, 0x7a);
        for refused in [truncated, appended] {
            assert_eq!(
                RingTransactData::parse(&refused, data.rail),
                Err(CustomRingError::RingTransactLength),
                "{name}"
            );
        }
        for len in [envelope - 1, envelope + 1] {
            let mut resized = data.clone();
            resized.envelope = &fixture.envelope[..len];
            assert_eq!(
                resized.encode(),
                Err(CustomRingError::RingTransactLength),
                "{name}"
            );
        }
        let message = data.auditor_message();
        assert_eq!(message.len(), stream.message_len(), "{name}");
        let parsed = AuditorMessage::parse(&message, stream).unwrap();
        assert_eq!(parsed.envelope, data.envelope, "{name}");
        for (slot, output) in data.outputs.iter().enumerate() {
            assert_eq!(parsed.record(slot), Some(output.record), "{name}");
        }
        assert_eq!(
            AuditorMessage::parse(&message[..message.len() - 1], stream),
            None
        );
        let longer = [&message[..], &[0]].concat();
        assert_eq!(AuditorMessage::parse(&longer, stream), None);
        let mut untagged = message.clone();
        untagged[0] = 2;
        assert_eq!(AuditorMessage::parse(&untagged, stream), None);
    }
}

#[test]
fn the_in_proof_owner_proves_on_spp_anonymous_rail_under_the_sender_key() {
    let fixture = Fixture::new();
    let data = fixture.confidential_in_proof_owner();
    let CircuitId::AnonymousRingEddsa(2, 4, _, proof) = data.circuit() else {
        panic!("the in-proof owner proves on SPP's anonymous rail");
    };
    assert_eq!(proof.default_owner_tag, None);
    assert_eq!(proof.bsb22_commitment.commitment, fixture.bytes[20]);
    assert_eq!(
        data.transfer_circuit(1),
        Ok(RingCircuit::Transfer {
            format: custom_ring_interface::DisclosureFormat::Standard,
            outputs: 4,
            inputs: 24,
            withdrawals: 4,
            owners: 4,
            entry: false,
            wide: false,
        })
    );
    assert_eq!(
        data.transfer_circuit(33),
        Err(CustomRingError::RingShapeUnkeyed)
    );
}

fn binding<'a>(
    fixture: &'a Fixture,
    config: &'a RingPolicy,
    roots: &'a TransferRoots,
) -> TransferBinding<'a> {
    TransferBinding {
        ring_id: &fixture.fields[60],
        auditor_pubkey: &config.auditor_pubkey,
        sender: &fixture.fields[61],
        signers: SignerSet::default(),
        party_identities: &[[0; 32]; ANONYMOUS_PARTIES],
        roots,
        public_assets: &[[0; 32]; 3],
        public_amounts: &[[0; 32]; 3],
        public_gross: &[[0; 32]; 3],
        withdrawal_hash: &fixture.fields[62],
    }
}

#[test]
fn the_transfer_statement_reads_the_frame_and_names_its_family() {
    let fixture = Fixture::new();
    let config = config();
    let roots_for = |_: &RingTransactData<'_>| TransferRoots::default();
    let parties = [[0; 32]; ANONYMOUS_PARTIES];
    let parsed = ParsedTransact::new(fixture.anonymous()).unwrap();
    let data = parsed.data();
    let roots = roots_for(data);
    let statement = parsed
        .transfer_statement(binding(&fixture, &config, &roots))
        .unwrap();
    assert_eq!(statement.head.first_nullifier, &data.nullifiers[0]);
    assert_eq!(statement.head.salt, data.salt);
    assert_eq!(statement.head.envelope, data.envelope);
    assert_eq!(statement.input_count, data.nullifiers.len());
    assert_eq!(statement.private_tx_hash, data.private_tx_hash);
    assert_eq!(statement.output_capacity, 4);
    for (data, family, layout, no_spend) in [
        (
            fixture.anonymous(),
            TransferFamily::Anonymous {
                party_identities: &parties,
                public_owners: false,
                delegate: false,
            },
            0,
            false,
        ),
        (
            fixture.anonymous_public_owners(),
            TransferFamily::Anonymous {
                party_identities: &parties,
                public_owners: true,
                delegate: false,
            },
            0,
            false,
        ),
        (
            fixture.anonymous_delegate(),
            TransferFamily::Anonymous {
                party_identities: &parties,
                public_owners: false,
                delegate: true,
            },
            0,
            false,
        ),
        (
            fixture.anonymous_entry(),
            TransferFamily::Anonymous {
                party_identities: &parties,
                public_owners: false,
                delegate: false,
            },
            2,
            false,
        ),
        (
            fixture.confidential_delivered(),
            TransferFamily::Confidential {
                sender: ConfidentialSender::Signer,
            },
            0,
            false,
        ),
        (
            fixture.confidential_data(),
            TransferFamily::Confidential {
                sender: ConfidentialSender::Signer,
            },
            1,
            false,
        ),
        (
            fixture.confidential_no_spend(),
            TransferFamily::Confidential {
                sender: ConfidentialSender::Signer,
            },
            0,
            true,
        ),
        (
            fixture.confidential_in_proof_owner(),
            TransferFamily::Confidential {
                sender: ConfidentialSender::InProof(&fixture.fields[61]),
            },
            0,
            false,
        ),
        (
            fixture.delegate(),
            TransferFamily::Confidential {
                sender: ConfidentialSender::Authority,
            },
            0,
            false,
        ),
    ] {
        let parsed = ParsedTransact::new(data).unwrap();
        let roots = roots_for(parsed.data());
        let statement = parsed
            .transfer_statement(binding(&fixture, &config, &roots))
            .unwrap();
        assert_eq!(statement.family, family);
        assert_eq!(statement.head.layout.value(), layout, "{family:?}");
        assert_eq!(statement.no_spend, no_spend, "{family:?}");
    }
    assert_eq!(
        fixture.confidential_in_proof_owner().in_proof_sender(),
        Ok(Some(solana_owner_identity(&fixture.bytes[16]).unwrap()))
    );
}

#[test]
fn withdrawal_owner_metadata_is_required_in_transfer_order() {
    let fixture = Fixture::new();
    let owners = [[0x61; 32], [0x62; 32]];
    let mut data = fixture.confidential_policy();
    data.interface_transfers = vec![
        InterfaceTransfer::SplWithdrawal {
            amount: 7,
            spl_interface_bump: 0,
        },
        InterfaceTransfer::SolDeposit { amount: 100 },
        InterfaceTransfer::SplWithdrawal {
            amount: 8,
            spl_interface_bump: 0,
        },
    ];
    assert!(data.encode().is_err());
    data.spl_withdrawal_owners = &owners;
    let encoded = data.encode().unwrap();
    let parsed = RingTransactData::parse(&encoded, RingRail::Confidential).unwrap();
    assert_eq!(parsed.data().spl_withdrawal_owners, owners);
    assert_eq!(parsed.data().interface_transfers, data.interface_transfers);
    data.spl_withdrawal_owners = &owners[..1];
    assert!(data.encode().is_err());
}

#[test]
fn payout_frame_binds_format_and_rejects_mixed_widths() {
    use custom_ring_interface::{
        DisclosureFormat, COMPACT_AUDIT_RECORD_LEN, COMPACT_RECIPIENT_BODY_LEN,
    };
    let fixture = Fixture::new();
    let body = [5; COMPACT_RECIPIENT_BODY_LEN];
    let record = [6; COMPACT_AUDIT_RECORD_LEN];
    let mut payout = fixture.base(RingRail::Confidential, 1, 16);
    payout.extensions.format = DisclosureFormat::SingleAssetPayout;
    payout.outputs = (0..16)
        .map(|slot| {
            let mut output = fixture.recipient(slot);
            output.body = SlotBody::Recipient(&body);
            output.record = &record;
            output
        })
        .collect();
    let payout = fixture.with_audit_stream(payout);
    let bytes = payout.encode().unwrap();
    let decoded = RingTransactData::parse(&bytes, RingRail::Confidential)
        .unwrap()
        .into_data();
    assert_eq!(decoded, payout);
    assert_eq!(decoded.audit_layout().value(), 4);
    assert_eq!(decoded.outputs.len(), 16);
    let mut wrong = payout.clone();
    wrong.extensions.format = DisclosureFormat::Standard;
    assert!(wrong.encode().is_err());
    let mut wrong = payout.clone();
    wrong.outputs[0].record = &fixture.records[0];
    assert!(wrong.encode().is_err());
    let mut wrong = payout.clone();
    wrong.outputs[0].body = SlotBody::Recipient(&fixture.recipient_body);
    assert!(wrong.encode().is_err());
    let mut wrong = payout;
    wrong.outputs[0].body = SlotBody::None;
    assert!(wrong.encode().is_err());
}
