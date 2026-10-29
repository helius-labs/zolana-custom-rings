//! Pins `test-vectors/proof/ring-transact-expansion.json` for the TS SDK and the ring program tests.

mod common;

use bytemuck::Zeroable;
use custom_ring_interface::{
    encode_anonymous_recipient_output, encode_anonymous_sender_output,
    ring_confidential_delivered_output_body, ring_owner_delivered_output,
    CONFIDENTIAL_DATA_FREE_BODY_LEN,
};
use custom_ring_interface::{
    input_flag, shape_flag,
    storage::{Revision, Root, StorageRegistry},
    transact_flag, AnonymousAuditKey, AnonymousLayout, AnonymousProofData, AuditBinding, AuditKind,
    CustomRingError, CustomRingProof, DeliveredLayout, DisclosureLayout, InProofOwner, InputTrees,
    InstructionTag, ParsedTransact, PlainGroth16Proof, PolicyBinding, PolicyProof,
    PolicyRecipients, RailSigner, RingMode, RingOutput, RingPolicy, RingProgramConfig, RingRail,
    RingTransactData, SenderBundle, Settlement, SourceSlot, RING_PROGRAM_CONFIG,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_bn254::compression::prelude::alt_bn128_g2_compress_be;
use spr_event::{
    confidential_encrypted_output_body, OutputDataEncoding,
    ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG, ANONYMOUS_SENDER_ENCRYPTED_SCHEME_TAG,
    CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
};
use spr_interface::{
    instruction::{InterfaceTransfer, OwnerTag, TreeContext},
    shape::{Shape, SPP_SUPPORTED_SHAPES},
};
use zolana_ring_policy::ListId;

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

struct Fixture {
    proofs: [CustomRingProof; 2],
    spp_proof: PlainGroth16Proof,
    fields: Vec<[u8; 32]>,
    bytes: [[u8; 32]; 24],
    bodies: [[u8; 40]; 8],
    tags: [[u8; 32]; 4],
    recipient_body: Vec<u8>,
    sender_body: Vec<u8>,
    payload: Vec<u8>,
    salt: [u8; 16],
}

impl Fixture {
    fn new() -> Self {
        let proof = |seed: u8| CustomRingProof {
            groth16: PlainGroth16Proof {
                proof_a: [seed; 32],
                proof_b: [seed + 1; 64],
                proof_c: [seed + 2; 32],
            },
            commitment: [seed + 3; 32],
            commitment_pok: [seed + 4; 32],
        };
        Self {
            proofs: [proof(0x10), proof(0x20)],
            spp_proof: PlainGroth16Proof {
                proof_a: [0x31; 32],
                proof_b: alt_bn128_g2_compress_be(&common::spp_b()).unwrap(),
                proof_c: [0x32; 32],
            },
            fields: (0..64u8).map(field).collect(),
            bytes: core::array::from_fn(|i| [0x40 + i as u8; 32]),
            bodies: core::array::from_fn(|i| [0x80 + i as u8; 40]),
            tags: core::array::from_fn(|i| [0xa0 + i as u8; 32]),
            recipient_body: (0..120u8).map(|byte| byte ^ 0x5a).collect(),
            sender_body: (0..90u8).map(|byte| byte ^ 0x2d).collect(),
            payload: (0..CONFIDENTIAL_DATA_FREE_BODY_LEN as u8)
                .map(|byte| byte ^ 0x66)
                .collect(),
            salt: [0x5c; 16],
        }
    }

    fn base(&self, rail: RingRail, n_in: u8, n_out: u8) -> RingTransactData<'_> {
        RingTransactData {
            withdrawal_exemption: Default::default(),
            rail,
            n_in,
            n_out,
            audit_proof: &self.proofs[0],
            policy: None,
            approval_required: false,
            expiry_unix_ts: 1_800_000_000,
            tx_viewing_u: &self.bytes[0],
            salt: &self.salt,
            interface_transfers: Vec::new(),
            key_escrow: false,
            full_openings: false,
            outputs: Vec::new(),
            sender: None,
            eph_u: &self.bytes[1],
            sealed: &self.bytes[2],
            disclosure: &[],
            private_tx_hash: &self.fields[0],
            anonymous: None,
            in_proof_owner: None,
            spp_proof: &self.spp_proof,
            nullifiers: &self.fields[1..1 + usize::from(n_in)],
            input_trees: InputTrees::One(TreeContext {
                utxo_tree_root_index: 11,
                nullifier_tree_root_index: 12,
            }),
        }
    }

    fn exit<'a>(&'a self, slot: usize, payload: &'a [u8]) -> RingOutput<'a> {
        RingOutput::Exit {
            hash: &self.fields[10 + slot],
            owner_tag: &self.bytes[12 + slot],
            payload,
        }
    }

    fn with_disclosure<'a>(&'a self, mut data: RingTransactData<'a>) -> RingTransactData<'a> {
        let count = data.disclosure_layout().unwrap().field_count();
        data.disclosure = &self.fields[30..30 + count];
        data
    }

    fn confidential_policy(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 2, 2);
        data.key_escrow = true;
        data.policy = Some(PolicyProof {
            spl_withdrawal_owners: &[],
            proof: &self.proofs[1],
            own_revision: Revision::from(7),
            curator_revision: Some(Revision::from(3)),
            sender_commitment: None,
            recipients: PolicyRecipients::Framed(&self.fields[50..52]),
        });
        data.approval_required = true;
        data.interface_transfers = vec![
            InterfaceTransfer::SolWithdrawal { amount: 5_000 },
            InterfaceTransfer::SplDeposit {
                amount: 77,
                spl_interface_bump: 254,
            },
        ];
        data.outputs = vec![self.delivered(0), self.exit(1, &self.payload)];
        data.input_trees = InputTrees::Two {
            first: TreeContext {
                utxo_tree_root_index: 1,
                nullifier_tree_root_index: 2,
            },
            second: TreeContext {
                utxo_tree_root_index: 3,
                nullifier_tree_root_index: 4,
            },
            second_inputs: 0b10,
        };
        self.with_disclosure(data)
    }

    /// No owner signs, the ring slots and the change publish their owners, slot 3 a dummy.
    fn confidential_in_proof_owner(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 2, 4);
        data.policy = Some(PolicyProof {
            spl_withdrawal_owners: &[],
            proof: &self.proofs[1],
            own_revision: Revision::from(5),
            curator_revision: None,
            sender_commitment: None,
            recipients: PolicyRecipients::Published { dummies: 0b1000 },
        });
        data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 4_000 }];
        data.outputs = (0..4)
            .map(|slot| match slot {
                1 => self.exit(slot, &self.payload),
                _ => self.owned(slot),
            })
            .collect();
        data.in_proof_owner = Some(InProofOwner {
            owner: &self.bytes[16],
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
        });
        self.with_disclosure(data)
    }

    fn confidential_delivered(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 1, 8);
        data.outputs = (0..8)
            .map(|slot| match slot {
                3 | 6 => self.exit(slot, &self.payload),
                _ => self.delivered(slot),
            })
            .collect();
        self.with_disclosure(data)
    }

    fn anonymous(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Anonymous, 3, 4);
        data.policy = Some(PolicyProof {
            spl_withdrawal_owners: &[],
            proof: &self.proofs[1],
            own_revision: Revision::from(31),
            curator_revision: None,
            sender_commitment: Some(&self.fields[4]),
            recipients: PolicyRecipients::Hidden,
        });
        data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 9_999 }];
        data.outputs = (0..4)
            .map(|slot| match slot {
                2 => self.exit(slot, &self.payload),
                _ => self.tagged(slot),
            })
            .collect();
        data.sender = self.sender();
        data.anonymous = Some(AnonymousProofData {
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
            default_owner_tag: Some(&self.bytes[22]),
        });
        self.with_disclosure(data)
    }

    fn anonymous_entry(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Anonymous, 2, 2);
        data.full_openings = true;
        data.outputs = vec![self.tagged(0), self.exit(1, &self.payload)];
        data.sender = self.sender();
        data.anonymous = Some(AnonymousProofData {
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
            default_owner_tag: None,
        });
        self.with_disclosure(data)
    }

    fn delegate(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Delegate, 2, 2);
        data.key_escrow = true;
        data.policy = Some(self.delegate_policy(2));
        data.outputs = vec![self.delivered(0), self.delivered(1)];
        self.with_disclosure(data)
    }

    /// A delegate move into eight delivered slots, a shape SPP keys no ring authority for.
    fn delegate_delivered(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Delegate, 2, 8);
        data.key_escrow = true;
        data.policy = Some(self.delegate_policy(8));
        data.outputs = (0..8).map(|slot| self.delivered(slot)).collect();
        data
    }

    fn delegate_policy(&self, outputs: usize) -> PolicyProof<'_> {
        PolicyProof {
            spl_withdrawal_owners: &[],
            proof: &self.proofs[1],
            own_revision: Revision::from(0),
            curator_revision: None,
            sender_commitment: None,
            recipients: PolicyRecipients::Framed(&self.fields[50..50 + outputs]),
        }
    }

    fn delivered(&self, slot: usize) -> RingOutput<'_> {
        RingOutput::Delivered {
            hash: &self.fields[10 + slot],
            u: &self.bytes[3 + slot],
            body: &self.bodies[slot],
        }
    }

    /// Slots 0 and 3 under the in-proof owner, the change and the dummy.
    fn owned(&self, slot: usize) -> RingOutput<'_> {
        RingOutput::Owned {
            hash: &self.fields[10 + slot],
            owner: match slot {
                0 | 3 => &self.bytes[16],
                _ => &self.bytes[17 + slot],
            },
            u: &self.bytes[3 + slot],
            body: &self.bodies[slot],
        }
    }

    /// Slot 0 a change output, any other slot a recipient body.
    fn tagged(&self, slot: usize) -> RingOutput<'_> {
        RingOutput::Anonymous {
            hash: &self.fields[10 + slot],
            tag: &self.tags[slot],
            body: (slot != 0).then_some(&self.recipient_body[..]),
        }
    }

    fn sender(&self) -> Option<SenderBundle<'_>> {
        Some(SenderBundle {
            tag: &self.tags[0],
            body: &self.sender_body,
        })
    }

    fn cases(&self) -> [(&'static str, RingTransactData<'_>); 6] {
        [
            ("confidential_delivered_policy", self.confidential_policy()),
            (
                "confidential_in_proof_owner_policy",
                self.confidential_in_proof_owner(),
            ),
            (
                "confidential_delivered_audit_only",
                self.confidential_delivered(),
            ),
            ("anonymous_policy", self.anonymous()),
            ("anonymous_entry_audit_only", self.anonymous_entry()),
            ("delegate_move", self.delegate()),
        ]
    }
}

fn field(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[0] = 0x0f;
    value
}

fn config() -> RingProgramConfig {
    let mut config: RingProgramConfig = Zeroable::zeroed();
    config.discriminator = RING_PROGRAM_CONFIG;
    config.auditor_pubkey[0] = 4;
    config.auditor_pubkey[1..].copy_from_slice(&[0xa1; 32]);
    config
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
        description: "Compact ring transact data of each rail and what the ring program forwards \
                      for it, the SPP TransactIxData, the SPP instruction data (tag 19 or 21 then the \
                      data) and the external data \
                      hash over the SPP tag, the data before private_tx_hash and two settlement \
                      accounts per leg. Byte 1 of the compact data indexes \
                      SPP_SUPPORTED_SHAPES below the default owner tag flag (bit 6), bit 7 refused. \
                      Byte 2 is the input count below the key escrow flag (bit 6) and the \
                      anonymous entry key flag (bit 7), the expiry is a u32, every rail \
                      publishes all n_out slots with no output count, exit payloads take 83 \
                      bytes without a u16 prefix, an anonymous slot is its hash, a 32-byte \
                      owner tag, a u16 little-endian length and the scheme 1 body, empty on \
                      a change output, the anonymous rail's scheme 2 sender bundle follows \
                      the outputs as a 32-byte tag, a nonzero u16 length and the body, and \
                      the random 16-byte salt follows the transaction viewing key. Under the \
                      in-proof owner flag (byte 0 bit 3) each ring slot names its owner ahead \
                      of its key and forwards under scheme 11, a dummy slot bitmap takes the \
                      place of the recipients, and the owner key, commitment and commitment pok \
                      follow private_tx_hash. Produced by \
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
        assert_eq!(spp.proof.b, common::spp_b());
        assert_eq!(&spp.salt, data.salt, "{}", case.name);
        let (auditor, sender) = spp.messages.split_last().unwrap();
        assert_eq!(auditor.view_tag, config.auditor_pubkey[1..]);
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
                    encode_anonymous_sender_output(bundle.body).unwrap(),
                )
            })
            .collect();
        assert_eq!(sender, expected, "{}", case.name);
        for (output, slot) in spp.outputs.iter().zip(&data.outputs) {
            match slot {
                RingOutput::Delivered { .. } => assert!(output
                    .data
                    .as_deref()
                    .and_then(ring_confidential_delivered_output_body)
                    .is_some()),
                RingOutput::Owned { owner, u, body, .. } => {
                    assert_eq!(output.owner_tag, OwnerTag::Inline(**owner));
                    assert_eq!(
                        output.data.as_deref().and_then(ring_owner_delivered_output),
                        Some((*u, *body)),
                        "{}",
                        case.name
                    );
                }
                RingOutput::Anonymous { tag, body, .. } => {
                    assert_eq!(output.owner_tag, OwnerTag::Inline(**tag));
                    assert_eq!(
                        output.data,
                        body.map(|body| encode_anonymous_recipient_output(body).unwrap()),
                        "{}",
                        case.name
                    );
                }
                RingOutput::Exit { .. } => assert!(output
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

#[test]
fn anonymous_and_exit_slots_keep_the_borsh_framing_at_exact_capacity() {
    let fixture = Fixture::new();
    let borsh_framing = |scheme: u8, payload: &[u8]| {
        borsh::to_vec(&OutputDataEncoding::Encrypted(
            [&[scheme][..], payload].concat(),
        ))
        .unwrap()
    };
    for (data, scheme, payload) in [
        (
            fixture.tagged(1).transact_output().unwrap().data.unwrap(),
            ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG,
            &fixture.recipient_body[..],
        ),
        (
            encode_anonymous_sender_output(&fixture.sender_body).unwrap(),
            ANONYMOUS_SENDER_ENCRYPTED_SCHEME_TAG,
            &fixture.sender_body[..],
        ),
        (
            fixture
                .exit(1, &fixture.payload)
                .transact_output()
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
fn a_delivered_rail_publishes_every_output_slot() {
    let fixture = Fixture::new();
    let mut data = fixture.confidential_delivered();
    data.outputs.pop();
    assert_eq!(data.encode(), Err(CustomRingError::RingTransactLength));
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
    let mut wide = fixture.anonymous().encode().unwrap();
    wide[1] = shape_index(2, 16) | (wide[1] & !0b0011_1111);
    assert_eq!(
        RingTransactData::parse(&wide, RingRail::Anonymous),
        Err(CustomRingError::RingShapeUnkeyed)
    );
}

#[test]
fn anonymous_header_flags_off_the_anonymous_rail_are_refused() {
    let fixture = Fixture::new();
    let mut entry = fixture.confidential_policy().encode().unwrap();
    entry[input_flag::BYTE] |= input_flag::FULL_OPENINGS;
    assert_eq!(
        RingTransactData::parse(&entry, RingRail::Confidential),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut owner_tag = fixture.confidential_policy().encode().unwrap();
    owner_tag[shape_flag::BYTE] |= shape_flag::DEFAULT_OWNER_TAG;
    assert_eq!(
        RingTransactData::parse(&owner_tag, RingRail::Confidential),
        Err(CustomRingError::FlagNotAllowed)
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
    let mut exit = fixture.delegate();
    exit.rail = RingRail::Confidential;
    exit.outputs[1] = fixture.exit(1, &fixture.payload);
    let compact = fixture.with_disclosure(exit).encode().unwrap();
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Delegate),
        Err(CustomRingError::FlagNotAllowed)
    );
}

#[test]
fn an_exit_payload_of_another_length_is_refused() {
    let fixture = Fixture::new();
    let long: Vec<u8> = (0..=CONFIDENTIAL_DATA_FREE_BODY_LEN as u8).collect();
    let mut data = fixture.confidential_delivered();
    data.outputs[3] = fixture.exit(3, &long);
    assert_eq!(data.encode(), Err(CustomRingError::DataFreeBodyLength));
}

#[test]
fn the_reserved_frame_bits_are_refused() {
    let fixture = Fixture::new();
    for (byte, bit) in [
        (transact_flag::BYTE, 1 << 6),
        (transact_flag::BYTE, 1 << 7),
        (shape_flag::BYTE, shape_flag::RESERVED),
    ] {
        let mut compact = fixture.delegate().encode().unwrap();
        compact[byte] |= bit;
        assert_eq!(
            RingTransactData::parse(&compact, RingRail::Delegate),
            Err(CustomRingError::FlagNotAllowed),
            "byte {byte} bit {bit:#x}"
        );
    }
}

#[test]
fn flag_bit_4_is_refused_on_every_rail_and_the_in_proof_owner_off_the_confidential_rail() {
    let fixture = Fixture::new();
    assert_eq!(transact_flag::KNOWN & 1 << 4, 0);
    for (name, data) in fixture.cases() {
        let foreign_owner =
            (data.rail != RingRail::Confidential).then_some(transact_flag::OWNER_IN_PROOF);
        for bit in [Some(1 << 4), foreign_owner].into_iter().flatten() {
            let mut compact = data.encode().unwrap();
            compact[transact_flag::BYTE] |= bit;
            assert_eq!(
                RingTransactData::parse(&compact, data.rail),
                Err(CustomRingError::FlagNotAllowed),
                "{name} bit {bit:#x}"
            );
        }
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
    let expected = [
        (fixture.tags[0], None),
        (
            fixture.tags[1],
            framed(
                ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG,
                &fixture.recipient_body,
            ),
        ),
        (
            fixture.bytes[14],
            framed(CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, &fixture.payload),
        ),
        (
            fixture.tags[3],
            framed(
                ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG,
                &fixture.recipient_body,
            ),
        ),
    ];
    for (slot, (output, (owner_tag, data))) in parsed.outputs.iter().zip(expected).enumerate() {
        let spp = output.transact_output().unwrap();
        assert_eq!(spp.utxo_hash, fixture.fields[10 + slot], "slot {slot}");
        assert_eq!(spp.owner_tag, OwnerTag::Inline(owner_tag), "slot {slot}");
        assert_eq!(spp.data, data, "slot {slot}");
    }
}

/// The offset of the anonymous slot frame that publishes `tag`, past its hash.
fn tag_offset(compact: &[u8], tag: &[u8; 32]) -> usize {
    compact
        .windows(32)
        .position(|window| window == tag)
        .expect("the frame carries the tag")
}

#[test]
fn an_anonymous_body_length_past_the_data_is_refused() {
    let fixture = Fixture::new();
    let compact = fixture.anonymous().encode().unwrap();
    let len = tag_offset(&compact, &fixture.tags[1]) + 32;
    assert_eq!(
        compact[len..len + 2],
        u16::try_from(fixture.recipient_body.len())
            .unwrap()
            .to_le_bytes()
    );
    let mut refused = compact.clone();
    refused[len..len + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(
        RingTransactData::parse(&refused, RingRail::Anonymous),
        Err(CustomRingError::RingTransactLength),
    );
}

#[test]
fn an_empty_sender_bundle_is_refused() {
    let fixture = Fixture::new();
    let compact = fixture.anonymous().encode().unwrap();
    let outputs_end =
        tag_offset(&compact, &fixture.tags[3]) + 32 + 2 + fixture.recipient_body.len();
    let len = outputs_end + 32;
    assert_eq!(compact[outputs_end..len], fixture.tags[0]);
    let mut refused = compact[..len].to_vec();
    refused.extend_from_slice(&0u16.to_le_bytes());
    refused.extend_from_slice(&compact[len + 2 + fixture.sender_body.len()..]);
    assert_eq!(
        RingTransactData::parse(&refused, RingRail::Anonymous),
        Err(CustomRingError::AnonymousBodyLength),
    );
}

#[test]
fn an_anonymous_body_the_frame_cannot_carry_is_refused_at_encoding() {
    let fixture = Fixture::new();
    let oversized = vec![0x11; usize::from(u16::MAX) + 1];
    for body in [&[][..], &oversized] {
        let mut data = fixture.anonymous();
        data.outputs[1] = RingOutput::Anonymous {
            hash: &fixture.fields[11],
            tag: &fixture.tags[1],
            body: Some(body),
        };
        assert_eq!(
            data.encode(),
            Err(CustomRingError::AnonymousBodyLength),
            "{} body bytes",
            body.len()
        );
        let mut data = fixture.anonymous();
        data.sender = Some(SenderBundle {
            tag: &fixture.tags[0],
            body,
        });
        assert_eq!(data.encode(), Err(CustomRingError::AnonymousBodyLength));
    }
}

#[test]
fn the_sender_bundle_is_present_exactly_on_the_anonymous_rail() {
    let fixture = Fixture::new();
    let mut anonymous = fixture.anonymous();
    anonymous.sender = None;
    assert_eq!(anonymous.encode(), Err(CustomRingError::RingTransactLength));
    let mut confidential = fixture.confidential_policy();
    confidential.sender = fixture.sender();
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
fn the_policy_proof_follows_the_ring_policy() {
    let fixture = Fixture::new();
    let policy = fixture.confidential_policy();
    let records = Address::new_from_array([2; 32]);
    let curator = Address::new_from_array([3; 32]);
    let mut ring_policy = RingPolicy::new(254, records);
    assert_eq!(
        policy.check_policy(None, 0),
        Err(CustomRingError::UnexpectedPolicyProof)
    );
    assert_eq!(
        policy.check_policy(Some(&ring_policy), 0),
        Err(CustomRingError::FlagNotAllowed)
    );
    ring_policy.sources[0] = SourceSlot {
        list_id: ListId::Allow as u8,
        registry: curator,
    };
    let mut uncurated = policy.clone();
    uncurated.policy = uncurated.policy.map(|policy| PolicyProof {
        spl_withdrawal_owners: &[],
        curator_revision: None,
        ..policy
    });
    assert_eq!(
        uncurated.check_policy(Some(&ring_policy), 0),
        Err(CustomRingError::FlagNotAllowed)
    );
    assert_eq!(
        policy.check_policy(Some(&ring_policy), 0),
        Err(CustomRingError::PolicyNotSet)
    );
    ring_policy.policy_hash = [9; 32];
    assert_eq!(
        policy.check_policy(Some(&ring_policy), 0),
        Err(CustomRingError::MirrorNotSynced)
    );
    let registry = |revision: u64, hash: u8| {
        let mut registry = StorageRegistry::new(Address::default(), 0);
        registry.roots[0] = Root {
            hash: [hash; 32],
            revision: Revision::from(revision),
            expires_at: [0; 8],
        };
        registry
    };
    ring_policy.sync(&records, &registry(7, 7)).unwrap();
    ring_policy.sync(&curator, &registry(3, 3)).unwrap();
    assert_eq!(
        ring_policy.sync(&Address::new_from_array([4; 32]), &registry(3, 3)),
        Err(CustomRingError::UnmirroredRegistry)
    );
    assert_eq!(
        policy.check_policy(Some(&ring_policy), 0),
        Ok(Some(PolicyBinding {
            proof: policy.policy.unwrap(),
            policy_hash: [9; 32],
            own_root: [7; 32],
            curator_root: Some([3; 32]),
        }))
    );
    ring_policy.sync(&records, &registry(8, 8)).unwrap();
    assert_eq!(
        policy.check_policy(Some(&ring_policy), 0),
        Err(CustomRingError::MirrorRootExpired)
    );
    assert_eq!(
        fixture
            .confidential_delivered()
            .check_policy(Some(&ring_policy), 0),
        Err(CustomRingError::MissingPolicyProof)
    );
    assert_eq!(
        fixture.confidential_delivered().check_policy(None, 0),
        Ok(None)
    );
}

#[test]
fn every_rail_reads_its_disclosure_layout() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.confidential_policy().disclosure_layout(),
        Ok(DisclosureLayout::Delivered(DeliveredLayout {
            outputs: 2,
            exits: true,
            key_escrow: true,
        }))
    );
    assert_eq!(
        fixture.confidential_delivered().disclosure_layout(),
        Ok(DisclosureLayout::Delivered(DeliveredLayout {
            outputs: 8,
            exits: true,
            key_escrow: false,
        }))
    );
    assert_eq!(
        fixture.anonymous().disclosure_layout(),
        Ok(DisclosureLayout::Anonymous(AnonymousLayout {
            key: AnonymousAuditKey::Commitment { class: 4 },
            inputs: 3,
            outputs: 4,
            exits: true,
        }))
    );
    assert_eq!(
        fixture.anonymous_entry().disclosure_layout(),
        Ok(DisclosureLayout::Anonymous(AnonymousLayout {
            key: AnonymousAuditKey::Entry,
            inputs: 2,
            outputs: 2,
            exits: true,
        }))
    );
    assert_eq!(
        fixture.delegate_delivered().disclosure_layout(),
        Err(CustomRingError::RingShapeUnkeyed)
    );
}

#[test]
fn the_rail_follows_the_instruction_and_the_ring_mode() {
    use InstructionTag::{DelegateTransact, Transact};
    let delegate = Address::new_from_array([0xd1; 32]);
    let ring = |mode: RingMode, has_policy: u8| {
        let mut config = config();
        config.mode = mode as u8;
        config.has_policy = has_policy;
        if mode == RingMode::ConfidentialEscrow {
            config.delegate = delegate;
        }
        config
    };
    assert_eq!(
        RingRail::new(Transact, &ring(RingMode::Confidential, 0)),
        Ok(RingRail::Confidential)
    );
    assert_eq!(
        RingRail::new(Transact, &ring(RingMode::Anonymous, 1)),
        Ok(RingRail::Anonymous)
    );
    assert_eq!(
        RailSigner::new(DelegateTransact, &ring(RingMode::ConfidentialEscrow, 1)),
        Ok(RailSigner::Delegate(delegate))
    );
    assert_eq!(
        RingRail::new(DelegateTransact, &ring(RingMode::Anonymous, 1)),
        Err(CustomRingError::AnonymousRingRefused)
    );
    assert_eq!(
        RingRail::new(DelegateTransact, &ring(RingMode::Confidential, 1)),
        Err(CustomRingError::DelegateDisabled)
    );
    assert_eq!(
        RingRail::new(InstructionTag::Merge, &ring(RingMode::Confidential, 1)),
        Err(CustomRingError::InvalidInstructionData)
    );
    let mut unknown = ring(RingMode::Confidential, 0);
    unknown.mode = RingMode::Anonymous as u8 + 1;
    assert_eq!(unknown.mode(), Err(CustomRingError::InvalidRingMode));
    assert_eq!(
        RingRail::new(Transact, &unknown),
        Err(CustomRingError::InvalidRingMode)
    );
}

#[test]
fn the_audit_statement_reads_the_frame_salt_and_the_policy_sender() {
    let fixture = Fixture::new();
    let parsed = ParsedTransact::new(fixture.anonymous()).unwrap();
    let data = parsed.data();
    let binding = AuditBinding {
        party_identities: &[[0; 32]; 3],
        ring_id: &fixture.fields[60],
        auditor_pubkey: &config().auditor_pubkey,
        key_escrow: false,
    };
    let statement = parsed.audit_statement(binding).unwrap();
    assert_eq!(statement.head.first_nullifier, &data.nullifiers[0]);
    assert_eq!(statement.head.salt, data.salt);
    assert_eq!(statement.head.layout.value(), 0b0001);
    assert_eq!(statement.disclosure, data.disclosure);
    let AuditKind::Anonymous(anonymous) = statement.kind else {
        panic!("an anonymous rail binds the anonymous tail");
    };
    assert_eq!(anonymous.sender_commitment, &fixture.fields[4]);
    assert_eq!(anonymous.private_tx_hash, data.private_tx_hash);
    let delivered = ParsedTransact::new(fixture.confidential_delivered()).unwrap();
    assert_eq!(
        delivered.audit_statement(binding).unwrap().kind,
        AuditKind::Delivered
    );
}

#[test]
fn a_key_escrow_flag_off_the_ring_mode_is_refused() {
    let fixture = Fixture::new();
    let config = config();
    let binding = |key_escrow| AuditBinding {
        party_identities: &[[0; 32]; 3],
        ring_id: &fixture.fields[60],
        auditor_pubkey: &config.auditor_pubkey,
        key_escrow,
    };
    let statement = |data: &RingTransactData<'_>, key_escrow| {
        ParsedTransact::new(data.clone())
            .unwrap()
            .audit_statement(binding(key_escrow))
            .map(|statement| statement.head.layout.value())
    };
    let escrowed = fixture.confidential_policy();
    assert_eq!(
        statement(&escrowed, false),
        Err(CustomRingError::FlagNotAllowed)
    );
    assert_eq!(statement(&escrowed, true), Ok(0b0011));
    assert_eq!(
        statement(&fixture.confidential_delivered(), true),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut anonymous = fixture.anonymous();
    anonymous.key_escrow = true;
    assert_eq!(
        statement(&fixture.with_disclosure(anonymous), false),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut delegate = fixture.delegate();
    delegate.key_escrow = false;
    assert_eq!(
        statement(&fixture.with_disclosure(delegate), true),
        Err(CustomRingError::FlagNotAllowed)
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
    data.policy.as_mut().unwrap().spl_withdrawal_owners = &owners;
    let encoded = data.encode().unwrap();
    let parsed = RingTransactData::parse(&encoded, RingRail::Confidential).unwrap();
    assert_eq!(parsed.data().policy.unwrap().spl_withdrawal_owners, owners);
    assert_eq!(parsed.data().interface_transfers, data.interface_transfers);
    assert!(RingTransactData::parse_legacy(&encoded, RingRail::Confidential).is_err());
    data.policy.as_mut().unwrap().spl_withdrawal_owners = &owners[..1];
    assert!(data.encode().is_err());
}

#[test]
fn withdrawal_exemption_suffix_round_trips_and_rejects_partial_proofs() {
    use custom_ring_interface::WithdrawalExemptionProof;
    let fixture = Fixture::new();
    let exemption = WithdrawalExemptionProof {
        proof: CustomRingProof::zeroed(),
        own_revision: Revision::from(7),
    };
    let (_, mut data) = fixture
        .cases()
        .into_iter()
        .find(|(_, data)| data.rail == RingRail::Confidential)
        .unwrap();
    let bare = data.encode().unwrap();
    data.withdrawal_exemption = Some(&exemption);
    let encoded = data.encode().unwrap();
    assert_eq!(encoded.len(), bare.len() + WithdrawalExemptionProof::SIZE);
    let parsed = RingTransactData::parse(&encoded, data.rail).unwrap();
    assert_eq!(parsed.data().withdrawal_exemption, Some(&exemption));
    assert_eq!(parsed.data().encode().unwrap(), encoded);
    for length in [bare.len() + 1, encoded.len() - 1] {
        assert_eq!(
            RingTransactData::parse(&encoded[..length], data.rail),
            Err(CustomRingError::RingTransactLength)
        );
    }
}
