//! Ring transfers as the ring program publishes them, under the keys of the Go `ringaudit` fixture.

use custom_ring_interface::{
    anonymous_recipient_output_body, anonymous_sender_output_body, encode_anonymous_sender_output,
    ring_confidential_delivered_output_body,
};
use custom_ring_interface::{
    blinding::ring_blinding_seed,
    stream::{DeliveredSlot, SlotSecret},
    tag as ring_tag, tagged_x25519, AnonymousAuditKey, AnonymousLayout, AnonymousProofData,
    AnonymousSpend, AuditorMessage, CustomRingProof, DeliveredLayout, DisclosureLayout, InputTrees,
    PlainGroth16Proof, RingOutput, RingRail, RingTransactData, SenderBundle,
    CONFIDENTIAL_DATA_FREE_BODY_LEN, RING_DELIVERED_BODY_LEN,
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
    instruction::{
        instruction_data::transact::{confidential_encrypted_output_body, TreeContext},
        OwnerTag,
    },
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
    AnonymousDisclosure, AnonymousInputOpening, AnonymousInputs, AnonymousOutputOpening,
    AuditDisclosure, AuditEnvelope, AuditedUtxo, DeliveredOutputOpening, DisclosurePad, KnownUtxo,
    OutputOpening, RingOwnerTag, UtxoOwner,
};
use zolana_ring_transaction::RingDeliveredBody;

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
    /// `tag` is the published view tag on an anonymous ring.
    Ring {
        utxo: UtxoFields,
        recipient_u: [u8; 32],
        tag: Option<[u8; 32]>,
    },
    Exit(UtxoFields),
    Dummy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rail {
    Delivered,
    Anonymous,
}

pub struct Slot {
    pub output: OutputSlot,
    pub slot_secret: Option<[u8; 32]>,
    pub ring_data_hash: [u8; 32],
    pub blinding: [u8; 32],
    /// The delivered body, an anonymous body is unproven and never opened.
    pub body: Option<[u8; RING_DELIVERED_BODY_LEN]>,
}

/// Bytes as long as a scheme 1 body with no data.
pub const ANONYMOUS_BODY: [u8; 116] = [0xb1; 116];
pub const SENDER_BUNDLE: [u8; 150] = [0xb2; 150];
pub const SENDER_TAG: [u8; 32] = [0x5e; 32];

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
    pub disclosure: &'a AuditDisclosure,
    pub auditor: &'a X25519Pubkey,
}

pub struct Frame<'a> {
    pub tx: &'a ShieldedTransaction,
    pub layout: DisclosureLayout,
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

    pub fn slot(&self, rail: Rail, index: u32, output: &Output) -> Slot {
        let leaf_index = u64::from(index);
        match *output {
            Output::Ring {
                utxo,
                recipient_u,
                tag,
            } => {
                let blinding = self.blinding(index);
                let hash = utxo.commitment(Placement {
                    blinding,
                    ring: Some(self.ring),
                    tree_id: self.tree_id,
                });
                let tag = tag.unwrap_or_default();
                let (published, secret, body) = match rail {
                    Rail::Delivered => {
                        let secret = self.delivered_secret(&recipient_u, index);
                        let body = RingDeliveredBody {
                            blinding,
                            amount: utxo.amount,
                        }
                        .seal(&secret)
                        .unwrap();
                        (
                            indexed(
                                RingOutput::Delivered {
                                    hash: &hash,
                                    u: &recipient_u,
                                    body: &body,
                                },
                                self.tree_id,
                                leaf_index,
                            ),
                            Some(*secret.as_bytes()),
                            Some(body),
                        )
                    }
                    Rail::Anonymous => (
                        indexed(
                            RingOutput::Anonymous {
                                hash: &hash,
                                tag: &tag,
                                body: Some(&ANONYMOUS_BODY),
                            },
                            self.tree_id,
                            leaf_index,
                        ),
                        None,
                        None,
                    ),
                };
                Slot {
                    output: published,
                    slot_secret: secret,
                    ring_data_hash: utxo.ring_data_hash,
                    blinding,
                    body,
                }
            }
            Output::Exit(utxo) => {
                let blinding = self.blinding(index);
                let hash = utxo.commitment(Placement {
                    blinding,
                    ring: None,
                    tree_id: self.tree_id,
                });
                let published = RingOutput::Exit {
                    hash: &hash,
                    owner_tag: &utxo.owner_key,
                    payload: &[0xe0; CONFIDENTIAL_DATA_FREE_BODY_LEN],
                };
                Slot {
                    output: indexed(published, self.tree_id, leaf_index),
                    slot_secret: None,
                    ring_data_hash: utxo.ring_data_hash,
                    blinding,
                    body: None,
                }
            }
            Output::Dummy => {
                let blinding = self.blinding(index);
                let hash = ProofInputUtxo {
                    domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
                    tree_id: tree_id_field(self.tree_id),
                    blinding,
                    ..ProofInputUtxo::default()
                }
                .hash()
                .unwrap();
                // A dummy publishes random bytes in its rail's encoding.
                let u = [0xd1 + index as u8; 32];
                let tag = field(0xd1 + index as u8);
                let body = core::array::from_fn(|j| 0xd0 + j as u8);
                let (published, body) = match rail {
                    Rail::Delivered => (
                        RingOutput::Delivered {
                            hash: &hash,
                            u: &u,
                            body: &body,
                        },
                        Some(body),
                    ),
                    Rail::Anonymous => (
                        RingOutput::Anonymous {
                            hash: &hash,
                            tag: &tag,
                            body: Some(&ANONYMOUS_BODY),
                        },
                        None,
                    ),
                };
                Slot {
                    output: indexed(published, self.tree_id, leaf_index),
                    slot_secret: None,
                    ring_data_hash: [0; 32],
                    blinding,
                    body,
                }
            }
        }
    }

    pub fn slots(&self, rail: Rail, outputs: &[Output]) -> Vec<Slot> {
        (0u32..)
            .zip(outputs)
            .map(|(index, output)| self.slot(rail, index, output))
            .collect()
    }

    /// The indexed transaction, the disclosure masked under a fresh envelope to the auditor.
    pub fn publish(&self, publish: Publish<'_>) -> ShieldedTransaction {
        let plaintext = publish.disclosure.fields().unwrap();
        let disclosure = DisclosurePad::new(&self.tx_key, &self.salt)
            .unwrap()
            .encrypt(&plaintext)
            .unwrap();
        let envelope = AuditEnvelope::seal(&self.tx_key, publish.auditor)
            .unwrap()
            .envelope;
        ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::default(),
            event_index: Some(0),
            tx_viewing_pk: Some(self.tx_key.pubkey()),
            salt: Some(self.salt),
            output_slots: publish.slots,
            messages: matches!(publish.disclosure, AuditDisclosure::Anonymous(_))
                .then(|| MessageData {
                    view_tag: SENDER_TAG,
                    data: encode_anonymous_sender_output(&SENDER_BUNDLE).unwrap(),
                })
                .into_iter()
                .chain([MessageData {
                    view_tag: publish.auditor.u(),
                    data: AuditorMessage::data(&envelope.eph_u, &envelope.sealed, &disclosure),
                }])
                .collect(),
            nullifiers: self.nullifiers.clone(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(self.ring),
        }
    }
}

impl Transfer {
    fn published_seed_out(&self, outputs: &[Output]) -> Option<[u8; 32]> {
        outputs
            .iter()
            .any(|output| matches!(output, Output::Exit(_)))
            .then(|| self.seed_out())
    }

    pub fn disclosure(&self, rail: Rail, outputs: &[Output], key_escrow: bool) -> AuditDisclosure {
        let seed_out = self.published_seed_out(outputs);
        let exits = seed_out.is_some();
        let escrowed = |nullifier_pk: Option<[u8; 32]>| nullifier_pk.filter(|_| !key_escrow);
        match rail {
            Rail::Delivered => AuditDisclosure::Delivered {
                layout: DeliveredLayout {
                    outputs: outputs.len(),
                    exits,
                    key_escrow,
                    sender_class: None,
                },
                seed_out,
                outputs: outputs
                    .iter()
                    .map(|output| match delivered_opening(output) {
                        DeliveredOutputOpening::Ring {
                            owner_key,
                            nullifier_pk,
                        } => DeliveredOutputOpening::Ring {
                            owner_key,
                            nullifier_pk: escrowed(nullifier_pk),
                        },
                        DeliveredOutputOpening::Exit {
                            nullifier_pk,
                            asset,
                            amount,
                        } => DeliveredOutputOpening::Exit {
                            nullifier_pk: escrowed(nullifier_pk),
                            asset,
                            amount,
                        },
                        DeliveredOutputOpening::Dummy => DeliveredOutputOpening::Dummy,
                    })
                    .collect(),
            },
            Rail::Anonymous => panic!("an anonymous disclosure names its spent notes"),
        }
    }

    /// The anonymous disclosure, the entry key when `inputs` open in full.
    pub fn anonymous_disclosure(
        &self,
        outputs: &[Output],
        inputs: AnonymousInputs,
    ) -> AuditDisclosure {
        let (count, spends_default_ring) = match &inputs {
            AnonymousInputs::Commitments { prefixes, .. } => (prefixes.len() + 1, false),
            AnonymousInputs::Openings { inputs, .. } => (inputs.len(), true),
        };
        let seed_out = self.published_seed_out(outputs);
        AuditDisclosure::Anonymous(AnonymousDisclosure {
            layout: AnonymousLayout {
                key: AnonymousSpend {
                    inputs: count,
                    outputs: outputs.len(),
                    spends_default_ring,
                }
                .audit_key()
                .expect("an anonymous audit key serves the spend"),
                inputs: count,
                outputs: outputs.len(),
                exits: seed_out.is_some(),
            },
            seed_out,
            outputs: outputs.iter().map(anonymous_opening).collect(),
            inputs,
        })
    }
}

impl Transfer {
    /// `tag || RingTransactData` the ring program received for `frame.tx`, every proof zero.
    pub fn frame(&self, frame: Frame<'_>) -> Vec<u8> {
        let Frame { tx, layout } = frame;
        let (rail, n_out, key_escrow, full_openings) = match layout {
            DisclosureLayout::Delivered(delivered) => (
                RingRail::Confidential,
                delivered.outputs,
                delivered.key_escrow,
                false,
            ),
            DisclosureLayout::Anonymous(anonymous) => (
                RingRail::Anonymous,
                anonymous.outputs,
                false,
                anonymous.key == AnonymousAuditKey::Entry,
            ),
        };
        let shape = SPP_SUPPORTED_SHAPES
            .into_iter()
            .find(|shape| shape.n_inputs() >= tx.nullifiers.len() && shape.n_outputs() == n_out)
            .unwrap();
        let message = AuditorMessage::parse(&tx.messages.last().unwrap().data, layout).unwrap();
        let eph_u = X25519Pubkey::from_bytes(*message.eph_pk).unwrap().u();
        let tx_viewing_u = self.tx_key.pubkey().u();
        let zero = [0; 32];
        let groth16 = PlainGroth16Proof {
            proof_a: zero,
            proof_b: [0; 64],
            proof_c: zero,
        };
        let audit_proof = CustomRingProof {
            groth16,
            commitment: zero,
            commitment_pok: zero,
        };
        let data = RingTransactData {
            withdrawal_exemption: Default::default(),
            rail,
            n_in: shape.n_inputs() as u8,
            n_out: shape.n_outputs() as u8,
            audit_proof: &audit_proof,
            policy: None,
            approval_required: false,
            expiry_unix_ts: 0,
            tx_viewing_u: &tx_viewing_u,
            salt: &self.salt,
            interface_transfers: Vec::new(),
            key_escrow,
            full_openings,
            outputs: tx.output_slots.iter().map(wire).collect(),
            sender: (rail == RingRail::Anonymous).then(|| {
                let message = tx.messages.first().unwrap();
                SenderBundle {
                    tag: &message.view_tag,
                    body: anonymous_sender_output_body(&message.data).unwrap(),
                }
            }),
            eph_u: &eph_u,
            sealed: message.sealed,
            disclosure: message.disclosure,
            private_tx_hash: &zero,
            anonymous: (rail == RingRail::Anonymous).then_some(AnonymousProofData {
                commitment: &zero,
                commitment_pok: &zero,
                default_owner_tag: None,
            }),
            in_proof_owner: None,
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

/// The inverse of `RingOutput::transact_output`.
fn wire(slot: &OutputSlot) -> RingOutput<'_> {
    let hash = &slot.output_context.hash;
    let payload = &slot.payload;
    if let Some(payload) = confidential_encrypted_output_body(payload) {
        return RingOutput::Exit {
            hash,
            owner_tag: &slot.view_tag,
            payload,
        };
    }
    if let Some(body) = ring_confidential_delivered_output_body(payload) {
        return RingOutput::Delivered {
            hash,
            u: &slot.view_tag,
            body,
        };
    }
    RingOutput::Anonymous {
        hash,
        tag: &slot.view_tag,
        body: (!payload.is_empty()).then(|| anonymous_recipient_output_body(payload).unwrap()),
    }
}

pub fn delivered_opening(output: &Output) -> DeliveredOutputOpening {
    match output {
        Output::Ring { utxo, .. } => DeliveredOutputOpening::Ring {
            owner_key: utxo.owner_key,
            nullifier_pk: Some(utxo.nullifier_pk),
        },
        Output::Exit(utxo) => DeliveredOutputOpening::Exit {
            nullifier_pk: Some(utxo.nullifier_pk),
            asset: utxo.asset(),
            amount: utxo.amount,
        },
        Output::Dummy => DeliveredOutputOpening::Dummy,
    }
}

pub fn anonymous_opening(output: &Output) -> AnonymousOutputOpening {
    match output {
        Output::Ring { utxo, .. } => AnonymousOutputOpening::Ring {
            owner_key: utxo.owner_key,
            nullifier_pk: utxo.nullifier_pk,
            asset: utxo.asset(),
            amount: utxo.amount,
        },
        Output::Exit(utxo) => AnonymousOutputOpening::Exit {
            nullifier_pk: utxo.nullifier_pk,
            asset: utxo.asset(),
            amount: utxo.amount,
        },
        Output::Dummy => AnonymousOutputOpening::Dummy,
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
        data_hash: utxo.data_hash,
        ring_data_hash: slot.ring_data_hash,
    };
    match output {
        Output::Ring {
            utxo,
            recipient_u,
            tag,
        } => OutputOpening::Ring {
            utxo: audited(utxo),
            owner_tag: match tag {
                Some(tag) => RingOwnerTag::View(*tag),
                None => RingOwnerTag::Recipient(*recipient_u),
            },
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
        data_hash: utxo.data_hash,
        ring_data_hash: utxo.ring_data_hash,
        tree_id: placement.tree_id,
    }
}

pub fn input_opening(utxo: &UtxoFields, blinding: [u8; 32]) -> AnonymousInputOpening {
    AnonymousInputOpening {
        asset: utxo.asset(),
        amount: utxo.amount,
        blinding,
    }
}

/// The slot the indexer returns for `output`, its owner tag rebuilt by the program.
fn indexed(output: RingOutput<'_>, tree_id: u16, leaf_index: u64) -> OutputSlot {
    let output = output.transact_output().unwrap();
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
