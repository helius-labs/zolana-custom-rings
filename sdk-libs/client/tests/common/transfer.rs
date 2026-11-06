//! Ring transfers as the ring program publishes them, under the keys of the Go `ringaudit` fixture.

use custom_ring_interface::stream::slot_tag;
use custom_ring_interface::{
    blinding::ring_blinding_seed,
    encode_ring_body_output, encode_ring_sender_bundle_output,
    key_catalog::FrameKey,
    ring_body_output,
    stream::{DeliveredSlot, SlotSecret},
    tag as ring_tag, tagged_x25519, AnonymousProofData, AuditEvidence, AuditKey, AuditStreamLayout,
    AuditorMessage, BundleLayout, CustomRingProof, EntryRecord, FrameExtensions,
    FramedSenderBundle, InProofOwner, InputTrees, OutputRecord, PlainGroth16Proof,
    RecipientPayload, RecordKind, RingOutput, RingRail, RingTransactData, SlotBody,
    CONFIDENTIAL_DATA_FREE_BODY_LEN, OUTPUT_RECORD_LEN,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::ProofInputUtxo;
use spr_event::MessageData;
use spr_hasher::{
    primitives::{hash_bytes, right_align, solana_owner_identity},
    Hasher, Poseidon,
};
use spr_interface::{
    instruction::{instruction_data::transact::TreeContext, OwnerTag},
    shape::SPP_SUPPORTED_SHAPES,
    tree_slot::tree_id_field,
};
use spr_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use spr_transaction::{
    derive_output_blinding_seed,
    utxo::{derive_transact_output_blinding, DUMMY_DOMAIN, UTXO_DOMAIN},
    OutputContext, OutputSlot, ShieldedTransaction,
};
use zolana_ring_client::{
    AuditStreamSeal, AuditedUtxo, KnownUtxo, OutputOpening, RingOwnerTag, SealedAuditStream,
    UtxoOwner,
};
use zolana_ring_transaction::seal_recipient_body;

/// Byte `i` is `seed ^ i` under a `0x01` lead byte, the Go `ringaudit.Scalar`.
pub fn scalar(seed: u8) -> [u8; 32] {
    let mut out = core::array::from_fn(|i| seed ^ i as u8);
    out[0] = 0x01;
    out
}

/// `byte` repeated behind a zero lead byte, a canonical field.
pub fn field(byte: u8) -> [u8; 32] {
    let mut out = [byte; 32];
    out[0] = 0;
    out
}

pub fn x25519_u(seed: u8) -> [u8; 32] {
    X25519Keypair::from_bytes(&scalar(seed)).pubkey().u()
}

/// The auditor of the Go fixture.
pub fn auditor() -> X25519Keypair {
    X25519Keypair::from_bytes(&scalar(0x33))
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UtxoFields {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub asset_address: Address,
    pub amount: u64,
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub struct Placement {
    pub blinding: [u8; 32],
    pub ring: Option<Address>,
    pub tree_id: u16,
}

impl UtxoFields {
    pub fn asset(&self) -> [u8; 32] {
        hash_bytes(self.asset_address.as_array()).unwrap()
    }

    pub fn owner_hash(&self) -> [u8; 32] {
        Poseidon::hashv(&[
            &solana_owner_identity(&self.owner_key).unwrap(),
            &self.nullifier_pk,
        ])
        .unwrap()
    }

    pub fn commitment(&self, placement: Placement) -> [u8; 32] {
        let ring = placement
            .ring
            .map(|ring| hash_bytes(ring.as_array()).unwrap());
        ProofInputUtxo {
            domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(placement.tree_id),
            owner_hash: self.owner_hash(),
            asset: self.asset(),
            amount: right_align(&self.amount.to_be_bytes()),
            blinding: placement.blinding,
            data_hash: self.data_hash,
            ring_data_hash: self.ring_data_hash,
            ring_program_id: ring.unwrap_or_default(),
        }
        .hash()
        .unwrap()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Output {
    /// A `None` `tag` publishes `recipient_u`.
    Ring {
        utxo: UtxoFields,
        recipient_u: [u8; 32],
        tag: Option<[u8; 32]>,
    },
    Exit(UtxoFields),
    Dummy,
}

impl Output {
    /// The data hashes a ring body carries past its record, none on an exit or a dummy.
    pub fn payload(&self) -> RecipientPayload {
        match self {
            Self::Ring { utxo, .. } => RecipientPayload {
                ring_data_hash: Some(utxo.ring_data_hash).filter(|hash| *hash != [0; 32]),
                data: Some(utxo.data_hash)
                    .filter(|hash| *hash != [0; 32])
                    .map_or_else(Vec::new, |hash| hash.to_vec()),
            },
            Self::Exit(_) | Self::Dummy => RecipientPayload::default(),
        }
    }

    pub fn carries_data(&self) -> bool {
        match self {
            Self::Ring { utxo, .. } | Self::Exit(utxo) => {
                utxo.data_hash != [0; 32] || utxo.ring_data_hash != [0; 32]
            }
            Self::Dummy => false,
        }
    }

    pub fn record(&self, blinding: [u8; 32]) -> OutputRecord {
        let of = |kind, utxo: &UtxoFields| OutputRecord {
            kind,
            amount: utxo.amount,
            owner_key: utxo.owner_key,
            mint: utxo.asset_address.to_bytes(),
            nullifier_pk: utxo.nullifier_pk,
            blinding,
        };
        match self {
            Self::Ring { utxo, .. } => of(RecordKind::Ring, utxo),
            Self::Exit(utxo) => of(RecordKind::Exit, utxo),
            Self::Dummy => OutputRecord::default(),
        }
    }

    /// `V_i`, the recipient's key, the auditor's on an exit, a fixed key on a dummy.
    pub fn recipient_key(&self, index: u32) -> [u8; 32] {
        match self {
            Self::Ring { recipient_u, .. } => *recipient_u,
            Self::Exit(_) => auditor().pubkey().u(),
            Self::Dummy => x25519_u(0xd0 + index as u8),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rail {
    Delivered,
    Anonymous,
}

/// The auditor stream's plaintext of one transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclosure {
    pub layout: AuditStreamLayout,
    /// The frame names its owner, the layout reads the same on the signer rail.
    pub in_proof: bool,
    pub real_inputs: u8,
    pub evidence: AuditEvidence,
    /// One per slot, sealed into its body or the auditor message at publish.
    pub records: Vec<OutputRecord>,
    pub recipient_keys: Vec<[u8; 32]>,
    /// One per slot under the frame's data flag.
    pub payloads: Option<Vec<RecipientPayload>>,
}

impl Disclosure {
    /// One width per frame, the widest payload's.
    fn payload_width(&self) -> Option<usize> {
        self.payloads
            .as_ref()
            .and_then(|payloads| payloads.iter().map(RecipientPayload::encoded_len).max())
    }
}

pub struct Slot {
    pub output: OutputSlot,
    pub ring_data_hash: [u8; 32],
    pub blinding: [u8; 32],
}

/// A body before publish seals the slot's record over it.
pub const ANONYMOUS_BODY: [u8; OUTPUT_RECORD_LEN] = [0xb1; OUTPUT_RECORD_LEN];
pub const SENDER_BUNDLE_BYTE: u8 = 0xb2;
pub const SENDER_TAG: [u8; 32] = [0x1e; 32];

pub struct Transfer {
    pub tx_key: ViewingKey,
    pub ring: Address,
    pub first_nullifier: [u8; 32],
    pub salt: [u8; 16],
    pub tree_id: u16,
    pub nullifiers: Vec<[u8; 32]>,
}

pub struct Publish<'a> {
    pub slots: Vec<OutputSlot>,
    pub disclosure: &'a Disclosure,
    pub auditor: &'a X25519Pubkey,
    pub rail: Rail,
}

pub struct Frame<'a> {
    pub tx: &'a ShieldedTransaction,
    pub disclosure: &'a Disclosure,
    pub rail: Rail,
}

impl Transfer {
    /// The values of Go `ringaudit.newTransfer`.
    pub fn fixture() -> Self {
        let first_nullifier = right_align(&[0x1f, 0x1f]);
        Self {
            tx_key: ViewingKey::from_bytes(&scalar(0x11)),
            ring: Address::new_from_array([0x90; 32]),
            first_nullifier,
            salt: core::array::from_fn(|i| 0xa0 + i as u8),
            tree_id: 9,
            nullifiers: vec![first_nullifier],
        }
    }

    pub fn ring_id(&self) -> [u8; 32] {
        hash_bytes(self.ring.as_array()).unwrap()
    }

    pub fn blinding_seed(&self) -> [u8; 32] {
        ring_blinding_seed(&self.tx_key.secret_bytes(), &self.salt).unwrap()
    }

    pub fn seed_out(&self) -> [u8; 32] {
        derive_output_blinding_seed(&self.first_nullifier, &self.blinding_seed()).unwrap()
    }

    pub fn blinding(&self, index: u32) -> [u8; 32] {
        derive_transact_output_blinding(&self.first_nullifier, &self.seed_out(), index).unwrap()
    }

    pub fn delivered_secret(&self, recipient_u: &[u8; 32], index: u32) -> SlotSecret {
        let recipient = X25519Pubkey::from_u(*recipient_u).unwrap();
        DeliveredSlot {
            agreement: &self.tx_key.ecdh(&recipient).unwrap(),
            tx_viewing_pk: self.tx_key.pubkey().as_bytes(),
            recipient_viewing_pk: &tagged_x25519(recipient_u),
            salt: &self.salt,
            output_index: index,
            first_nullifier: &self.first_nullifier,
        }
        .secret()
        .unwrap()
    }

    pub fn slot(&self, index: u32, output: &Output) -> Slot {
        let blinding = self.blinding(index);
        let record = [0; OUTPUT_RECORD_LEN];
        let published = |hash: [u8; 32], owner_tag: [u8; 32], body: SlotBody<'_>| {
            indexed(
                RingOutput {
                    hash: &hash,
                    owner_tag: match body {
                        SlotBody::Exit(_) => owner_tag,
                        SlotBody::Recipient(_) => slot_tag(owner_tag),
                    },
                    body,
                    record: &record,
                },
                self.tree_id,
                u64::from(index),
            )
        };
        match *output {
            Output::Ring {
                utxo,
                recipient_u,
                tag,
            } => {
                let hash = utxo.commitment(Placement {
                    blinding,
                    ring: Some(self.ring),
                    tree_id: self.tree_id,
                });
                Slot {
                    output: published(
                        hash,
                        tag.unwrap_or(recipient_u),
                        SlotBody::Recipient(&ANONYMOUS_BODY),
                    ),
                    ring_data_hash: utxo.ring_data_hash,
                    blinding,
                }
            }
            Output::Exit(utxo) => {
                let hash = utxo.commitment(Placement {
                    blinding,
                    ring: None,
                    tree_id: self.tree_id,
                });
                Slot {
                    output: published(
                        hash,
                        utxo.owner_key,
                        SlotBody::Exit(&[0xe0; CONFIDENTIAL_DATA_FREE_BODY_LEN]),
                    ),
                    ring_data_hash: utxo.ring_data_hash,
                    blinding,
                }
            }
            Output::Dummy => {
                let hash = ProofInputUtxo {
                    domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
                    tree_id: tree_id_field(self.tree_id),
                    blinding,
                    ..ProofInputUtxo::default()
                }
                .hash()
                .unwrap();
                // A dummy publishes random bytes in its rail's encoding.
                Slot {
                    output: published(
                        hash,
                        field(0xd1 + index as u8),
                        SlotBody::Recipient(&ANONYMOUS_BODY),
                    ),
                    ring_data_hash: [0; 32],
                    blinding,
                }
            }
        }
    }

    pub fn slots(&self, outputs: &[Output]) -> Vec<Slot> {
        (0u32..)
            .zip(outputs)
            .map(|(index, output)| self.slot(index, output))
            .collect()
    }

    /// The stream of `disclosure` under the fixture's viewing key.
    pub fn seal(&self, disclosure: &Disclosure, auditor: &X25519Pubkey) -> SealedAuditStream {
        AuditStreamSeal {
            layout: disclosure.layout,
            tx_viewing_key: &self.tx_key,
            salt: &self.salt,
            real_inputs: disclosure.real_inputs,
            evidence: disclosure.evidence.clone(),
            recipient_keys: disclosure.recipient_keys.clone(),
        }
        .seal(auditor)
        .unwrap()
    }

    /// Slot `index`'s record sealed to its recipient key, an exit's without its payload.
    pub fn sealed_record(&self, disclosure: &Disclosure, index: usize) -> Vec<u8> {
        let payload = disclosure
            .payloads
            .as_ref()
            .zip(disclosure.payload_width())
            .filter(|_| disclosure.records[index].kind != RecordKind::Exit)
            .map(|(payloads, width)| (&payloads[index], width));
        seal_recipient_body(
            &disclosure.records[index],
            payload,
            &self.delivered_secret(&disclosure.recipient_keys[index], index as u32),
        )
        .unwrap()
    }

    /// The indexed transaction, each record sealed into its body or the auditor message.
    pub fn publish(&self, publish: Publish<'_>) -> ShieldedTransaction {
        let sealed = self.seal(publish.disclosure, publish.auditor);
        let mut slots = publish.slots;
        let mut exit_records = Vec::new();
        for (index, slot) in slots.iter_mut().enumerate() {
            let body = self.sealed_record(publish.disclosure, index);
            let reply = ring_body_output(&slot.payload).map(|(_, reply)| reply.to_vec());
            match reply {
                Some(reply) => slot.payload = encode_ring_body_output(&body, &reply).unwrap(),
                None => exit_records.push(body),
            }
        }
        let bundle = MessageData {
            view_tag: SENDER_TAG,
            data: encode_ring_sender_bundle_output(&vec![
                SENDER_BUNDLE_BYTE;
                BundleLayout {
                    outputs: publish.disclosure.layout.outputs,
                }
                .byte_len()
            ])
            .unwrap(),
        };
        ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::default(),
            event_index: Some(0),
            tx_viewing_pk: Some(self.tx_key.pubkey()),
            salt: Some(self.salt),
            output_slots: slots,
            messages: (publish.rail == Rail::Anonymous)
                .then_some(bundle)
                .into_iter()
                .chain([MessageData {
                    view_tag: publish.auditor.u(),
                    data: AuditorMessage::data(
                        &sealed.eph_u,
                        [sealed.envelope.as_slice(), sealed.keys.as_slice()]
                            .into_iter()
                            .chain(exit_records.iter().map(Vec::as_slice)),
                    ),
                }])
                .collect(),
            nullifiers: self.nullifiers.clone(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(self.ring),
        }
    }

    /// `R` is every published input.
    pub fn disclosure(&self, rail: Rail, outputs: &[Output]) -> Disclosure {
        self.keyed(Keyed {
            rail: match rail {
                Rail::Delivered => RingRail::Confidential,
                Rail::Anonymous => RingRail::Anonymous,
            },
            entry: false,
            outputs,
            evidence: AuditEvidence::None,
        })
    }

    /// Bit `k` and record `k` name note `k`.
    pub fn entry_disclosure(
        &self,
        outputs: &[Output],
        default_note_bits: u64,
        inputs: Vec<EntryRecord>,
    ) -> Disclosure {
        self.keyed(Keyed {
            rail: RingRail::Confidential,
            entry: true,
            outputs,
            evidence: AuditEvidence::Entry {
                default_note_bits,
                inputs,
            },
        })
    }

    pub fn with_data(mut disclosure: Disclosure, outputs: &[Output]) -> Disclosure {
        disclosure.payloads = Some(outputs.iter().map(Output::payload).collect());
        disclosure
    }

    fn keyed(&self, keyed: Keyed<'_>) -> Disclosure {
        let Keyed {
            rail,
            entry,
            outputs,
            evidence,
        } = keyed;
        let shape = FrameKey {
            rail,
            inputs: self.nullifiers.len(),
            outputs: outputs.len(),
            spends_default_ring: entry,
            wide: false,
        }
        .shape()
        .expect("a key serves the outputs");
        let carries_data = outputs.iter().any(Output::carries_data);
        let disclosure = Disclosure {
            layout: AuditStreamLayout {
                key: AuditKey {
                    class: usize::from(shape.inputs),
                    entry,
                },
                inputs: self.nullifiers.len(),
                outputs: outputs.len(),
                capacity: usize::from(shape.outputs),
            },
            in_proof: false,
            real_inputs: self.nullifiers.len() as u8,
            evidence,
            records: (0u32..)
                .zip(outputs)
                .map(|(index, output)| output.record(self.blinding(index)))
                .collect(),
            recipient_keys: (0u32..)
                .zip(outputs)
                .map(|(index, output)| output.recipient_key(index))
                .collect(),
            payloads: None,
        };
        match carries_data {
            true => Self::with_data(disclosure, outputs),
            false => disclosure,
        }
    }

    /// `tag || RingTransactData` the ring program received for `frame.tx`, every proof zero.
    pub fn frame(&self, frame: Frame<'_>) -> Vec<u8> {
        let Frame {
            tx,
            disclosure,
            rail,
        } = frame;
        let layout = disclosure.layout;
        let shape = SPP_SUPPORTED_SHAPES
            .into_iter()
            .find(|shape| {
                shape.n_inputs() >= tx.nullifiers.len() && shape.n_outputs() == layout.outputs
            })
            .unwrap();
        let exits = tx
            .output_slots
            .iter()
            .filter(|slot| ring_body_output(&slot.payload).is_none())
            .count();
        let message =
            AuditorMessage::parse(&tx.messages.last().unwrap().data, layout, exits).unwrap();
        let tx_viewing_u = self.tx_key.pubkey().u();
        let zero = [0; 32];
        let groth16 = PlainGroth16Proof {
            proof_a: zero,
            proof_b: [0; 64],
            proof_c: zero,
        };
        let proof = CustomRingProof {
            groth16,
            commitment: zero,
            commitment_pok: zero,
        };
        let anonymous = rail == Rail::Anonymous;
        let data = RingTransactData {
            rail: match anonymous {
                true => RingRail::Anonymous,
                false => RingRail::Confidential,
            },
            n_in: shape.n_inputs() as u8,
            n_out: shape.n_outputs() as u8,
            proof: &proof,
            tracking_revision: Default::default(),
            own_revision: None,
            policy: None,
            spl_withdrawal_owners: &[],
            approval: Default::default(),
            no_spend: disclosure.real_inputs == 0,
            public_owners: false,
            expiry_unix_ts: 0,
            tx_viewing_u: &tx_viewing_u,
            salt: &self.salt,
            extensions: FrameExtensions::default(),
            interface_transfers: Vec::new(),
            has_data: disclosure.payloads.is_some(),
            entry: layout.key.entry,
            wide_owners: false,
            outputs: {
                let mut exit = 0;
                tx.output_slots
                    .iter()
                    .map(|output| {
                        let record = match ring_body_output(&output.payload) {
                            Some((body, _)) => body.first_chunk().unwrap(),
                            None => {
                                exit += 1;
                                message.exit_record(exit - 1).unwrap()
                            }
                        };
                        wire(output, record)
                    })
                    .collect()
            },
            replies: None,
            sender: anonymous.then(|| {
                let bundle = tx.messages.first().unwrap();
                FramedSenderBundle {
                    tag: &bundle.view_tag,
                    body: custom_ring_interface::ring_sender_bundle_output_body(&bundle.data)
                        .unwrap(),
                }
            }),
            envelope: message.envelope,
            recipient_keys: message.recipient_keys,
            private_tx_hash: &zero,
            anonymous: anonymous.then_some(AnonymousProofData {
                commitment: &zero,
                commitment_pok: &zero,
                default_owner_tag: None,
            }),
            in_proof_owner: disclosure.in_proof.then_some(InProofOwner {
                owner: &zero,
                commitment: &zero,
                commitment_pok: &zero,
            }),
            spp_proof: &groth16,
            nullifiers: &tx.nullifiers,
            input_trees: InputTrees::One(TreeContext {
                utxo_tree_root_index: 0,
                nullifier_tree_root_index: 0,
            }),
        };
        [vec![ring_tag::TRANSFER], data.encode().unwrap()].concat()
    }
}

struct Keyed<'a> {
    rail: RingRail,
    entry: bool,
    outputs: &'a [Output],
    evidence: AuditEvidence,
}

/// The inverse of `RingOutput::transact_output`, an exit's record from the auditor message.
fn wire<'a>(slot: &'a OutputSlot, record: &'a [u8; OUTPUT_RECORD_LEN]) -> RingOutput<'a> {
    let payload = &slot.payload;
    let body = match ring_body_output(payload) {
        Some((body, _)) => SlotBody::Recipient(body),
        None => SlotBody::Exit(custom_ring_interface::encrypted_output(payload).unwrap().1),
    };
    RingOutput {
        hash: &slot.output_context.hash,
        owner_tag: match body {
            SlotBody::Exit(_) => slot.view_tag,
            SlotBody::Recipient(_) => slot_tag(slot.view_tag),
        },
        body,
        record,
    }
}

pub fn audited_opening(output: &Output, slot: &Slot) -> OutputOpening {
    let audited = |utxo: &UtxoFields| AuditedUtxo {
        owner_key: utxo.owner_key,
        nullifier_pk: utxo.nullifier_pk,
        asset: utxo.asset(),
        mint: Some(utxo.asset_address),
        amount: utxo.amount,
        blinding: slot.blinding,
        data_hash: Some(utxo.data_hash),
        ring_data_hash: Some(slot.ring_data_hash),
    };
    match output {
        Output::Ring {
            utxo,
            recipient_u,
            tag,
        } => OutputOpening::Ring {
            utxo: audited(utxo),
            owner_tag: RingOwnerTag(slot_tag(tag.unwrap_or(*recipient_u))),
        },
        Output::Exit(utxo) => OutputOpening::Exit(audited(utxo)),
        Output::Dummy => OutputOpening::Dummy,
    }
}

/// `note` at `placement` as an earlier audit opened it.
pub fn known_utxo(utxo: &UtxoFields, placement: Placement) -> KnownUtxo {
    KnownUtxo {
        owner_key: utxo.owner_key,
        owner: UtxoOwner::Keyed {
            nullifier_pk: utxo.nullifier_pk,
        },
        asset: utxo.asset(),
        mint: Some(utxo.asset_address),
        amount: utxo.amount,
        blinding: placement.blinding,
        data_hash: Some(utxo.data_hash),
        ring_data_hash: Some(utxo.ring_data_hash),
        tree_id: placement.tree_id,
    }
}

pub fn entry_record(utxo: &UtxoFields, input_commitment: [u8; 32]) -> EntryRecord {
    EntryRecord {
        owner_key: utxo.owner_key,
        nullifier_pk: utxo.nullifier_pk,
        amount: utxo.amount,
        mint: utxo.asset_address.to_bytes(),
        input_commitment,
    }
}

/// The slot the indexer returns for `output`, its owner tag rebuilt by the program.
fn indexed(output: RingOutput<'_>, tree_id: u16, leaf_index: u64) -> OutputSlot {
    let output = output.transact_output(&[]).unwrap();
    let OwnerTag::Inline(view_tag) = output.owner_tag else {
        panic!("ring outputs publish inline owner tags");
    };
    OutputSlot {
        view_tag,
        output_context: OutputContext {
            hash: output.utxo_hash,
            tree_id,
            leaf_index,
        },
        payload: output.data.unwrap_or_default(),
    }
}
