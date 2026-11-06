//! Frames of every rail, shared by the codec and the heap budget tests.

use custom_ring_interface::{
    cosign::ApprovalMask, storage::Revision, stream::slot_tag, AnonymousProofData, AppMessage,
    BundleLayout, CustomRingProof, FrameExtensions, FramedSenderBundle, InProofOwner, InputTrees,
    PlainGroth16Proof, PolicyProof, Replies, RingOutput, RingRail, RingTransactData, SlotBody,
    AUDIT_RECORD_LEN, CONFIDENTIAL_DATA_FREE_BODY_LEN, DATA_TAIL_LEN, RECIPIENT_BODY_LEN,
};
use solana_bn254::compression::prelude::alt_bn128_g2_compress_be;
use spr_interface::instruction::{InterfaceTransfer, TreeContext};

#[path = "../common/mod.rs"]
mod common;

pub use common::spp_b;

pub const ZERO_TAG: [u8; 32] = [0; 32];

pub struct Fixture {
    pub proofs: [CustomRingProof; 2],
    pub spp_proof: PlainGroth16Proof,
    pub fields: Vec<[u8; 32]>,
    pub bytes: [[u8; 32]; 64],
    pub records: [[u8; AUDIT_RECORD_LEN]; 16],
    pub tails: [[u8; DATA_TAIL_LEN]; 16],
    /// Cut to the stream layout's envelope length.
    pub envelope: Vec<u8>,
    pub tags: [[u8; 32]; 16],
    pub recipient_body: [u8; RECIPIENT_BODY_LEN],
    /// A body past the plain head, a data-bearing frame's.
    pub extended_body: [u8; RECIPIENT_BODY_LEN + 33],
    /// Cut to the frame's `m`.
    pub sender_body: Vec<u8>,
    /// Cut to one length per body-bearing slot.
    pub replies: Vec<u8>,
    pub payload: Vec<u8>,
    pub salt: [u8; 16],
}

impl Fixture {
    pub fn new() -> Self {
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
                proof_b: alt_bn128_g2_compress_be(&spp_b()).unwrap(),
                proof_c: [0x32; 32],
            },
            fields: (0..=u8::MAX).map(field).collect(),
            bytes: core::array::from_fn(|i| [0x40 + i as u8; 32]),
            records: core::array::from_fn(|i| [0x80 + i as u8; AUDIT_RECORD_LEN]),
            tails: core::array::from_fn(|i| [0xc0 + i as u8; DATA_TAIL_LEN]),
            envelope: (0..8192u32).map(|byte| byte as u8 ^ 0x93).collect(),
            tags: core::array::from_fn(|i| field(0xa0 + i as u8)),
            recipient_body: core::array::from_fn(|byte| byte as u8 ^ 0x5a),
            extended_body: core::array::from_fn(|byte| byte as u8 ^ 0x3c),
            sender_body: (0..BundleLayout {
                outputs: 16,
                change: 16,
            }
            .byte_len() as u16)
                .map(|byte| byte as u8 ^ 0x2d)
                .collect(),
            replies: (0..2048u32).map(|byte| byte as u8 ^ 0x17).collect(),
            payload: (0..CONFIDENTIAL_DATA_FREE_BODY_LEN as u8)
                .map(|byte| byte ^ 0x66)
                .collect(),
            salt: [0x5c; 16],
        }
    }

    pub fn base(&self, rail: RingRail, n_in: u8, n_out: u8) -> RingTransactData<'_> {
        RingTransactData {
            rail,
            n_in,
            n_out,
            proof: &self.proofs[0],
            tracking_revision: Revision::from(9),
            own_revision: None,
            policy: None,
            spl_withdrawal_owners: &[],
            approval: ApprovalMask::default(),
            no_spend: false,
            public_owners: false,
            expiry_unix_ts: 1_800_000_000,
            tx_viewing_u: &self.bytes[0],
            salt: &self.salt,
            extensions: FrameExtensions::default(),
            interface_transfers: Vec::new(),
            has_data: false,
            entry: false,
            wide_owners: false,
            outputs: Vec::new(),
            replies: None,
            sender: None,
            envelope: &[],
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

    pub fn exit<'a>(&'a self, slot: usize, payload: &'a [u8]) -> RingOutput<'a> {
        RingOutput {
            hash: &self.fields[10 + slot],
            owner_tag: self.bytes[12 + slot],
            body: SlotBody::Exit(payload),
            record: &self.records[slot],
            tail: None,
        }
    }

    /// Cuts the envelope to the frame's stream layout and hands each slot a tail under `has_data`.
    pub fn with_audit_stream<'a>(&'a self, mut data: RingTransactData<'a>) -> RingTransactData<'a> {
        let stream = data.audit_stream().unwrap();
        data.envelope = &self.envelope[..stream.envelope().len];
        for (slot, output) in data.outputs.iter_mut().enumerate() {
            output.tail = data.has_data.then_some(&self.tails[slot]);
        }
        data
    }

    pub fn confidential_policy(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 2, 2);
        data.own_revision = Some(Revision::from(7));
        data.policy = Some(PolicyProof {
            curator_revision: Some(Revision::from(3)),
        });
        data.approval = ApprovalMask::OUTFLOW;
        data.interface_transfers = vec![
            InterfaceTransfer::SolWithdrawal { amount: 5_000 },
            InterfaceTransfer::SplDeposit {
                amount: 77,
                spl_interface_bump: 254,
            },
        ];
        data.outputs = vec![self.recipient(0), self.exit(1, &self.payload)];
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
        self.with_audit_stream(data)
    }

    /// No owner signs, SPP's anonymous rail hides the owner the frame names.
    pub fn confidential_in_proof_owner(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 2, 4);
        data.own_revision = Some(Revision::from(5));
        data.policy = Some(PolicyProof {
            curator_revision: None,
        });
        data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 4_000 }];
        data.outputs = (0..4)
            .map(|slot| match slot {
                1 => self.exit(slot, &self.payload),
                _ => self.recipient(slot),
            })
            .collect();
        data.in_proof_owner = Some(InProofOwner {
            owner: &self.bytes[16],
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
        });
        self.with_audit_stream(data)
    }

    pub fn confidential_delivered(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 1, 8);
        data.outputs = (0..8)
            .map(|slot| match slot {
                3 | 6 => self.exit(slot, &self.payload),
                _ => self.recipient(slot),
            })
            .collect();
        self.with_audit_stream(data)
    }

    /// A ring with an own registry and no policy, the proof reads thresholds off the own root.
    pub fn confidential_thresholds(&self) -> RingTransactData<'_> {
        let mut data = self.confidential_delivered();
        data.own_revision = Some(Revision::from(7));
        data.approval = ApprovalMask::WITHDRAWAL;
        data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 2_500 }];
        data
    }

    /// Bodies past the plain head and one tail per published slot.
    pub fn confidential_data(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 2, 2);
        data.has_data = true;
        data.outputs = vec![
            RingOutput {
                body: SlotBody::Recipient(&self.extended_body),
                ..self.recipient(0)
            },
            self.exit(1, &self.extended_body),
        ];
        self.with_audit_stream(data)
    }

    /// Every optional SPP field a frame carries.
    pub fn confidential_extensions(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 2, 2);
        data.extensions = FrameExtensions {
            format: custom_ring_interface::DisclosureFormat::Standard,
            data_hash: Some(&self.fields[70]),
            ring_data_hash: Some(&self.fields[71]),
            messages: vec![AppMessage {
                view_tag: &self.fields[72],
                data: &self.payload,
            }],
            cache: None,
            approval_totals: None,
            signer_data_counts: None,
        };
        data.outputs = vec![self.recipient(0), self.recipient(1)];
        self.with_audit_stream(data)
    }

    /// A public leg with no spend, every input a dummy under the frame's published count.
    pub fn confidential_no_spend(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 2, 2);
        data.no_spend = true;
        data.interface_transfers = vec![InterfaceTransfer::SolDeposit { amount: 3_000 }];
        data.outputs = vec![self.recipient(0), self.recipient(1)];
        self.with_audit_stream(data)
    }

    pub fn anonymous(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Anonymous, 3, 4);
        data.own_revision = Some(Revision::from(31));
        data.policy = Some(PolicyProof {
            curator_revision: None,
        });
        data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 9_999 }];
        data.outputs = (0..4)
            .map(|slot| match slot {
                2 => self.exit(slot, &self.payload),
                _ => self.tagged(slot),
            })
            .collect();
        data.sender = self.sender(4);
        data.anonymous = Some(AnonymousProofData {
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
            default_owner_tag: Some(&self.bytes[22]),
        });
        self.with_audit_stream(data)
    }

    pub fn anonymous_entry(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Anonymous, 2, 2);
        data.entry = true;
        data.outputs = vec![self.tagged(0), self.exit(1, &self.payload)];
        data.sender = self.sender(2);
        data.anonymous = Some(AnonymousProofData {
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
            default_owner_tag: None,
        });
        self.with_audit_stream(data)
    }

    pub fn delegate(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Delegate, 2, 2);
        data.outputs = vec![self.recipient(0), self.recipient(1)];
        self.with_audit_stream(data)
    }

    /// The anonymous frame under the authority tag, its statement names the delegate.
    pub fn anonymous_delegate(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::AnonymousDelegate, 2, 2);
        data.outputs = vec![self.tagged(0), self.tagged(1)];
        data.sender = self.sender(2);
        self.with_audit_stream(data)
    }

    /// Every live owner a published signer, SPP's confidential rail settles it on an anonymous ring.
    pub fn anonymous_public_owners(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Anonymous, 2, 2);
        data.public_owners = true;
        data.outputs = vec![self.tagged(0), self.tagged(1)];
        data.sender = self.sender(2);
        self.with_audit_stream(data)
    }

    pub fn recipient(&self, slot: usize) -> RingOutput<'_> {
        RingOutput {
            hash: &self.fields[10 + slot],
            owner_tag: slot_tag(self.bytes[3 + slot]),
            body: SlotBody::Recipient(&self.recipient_body),
            record: &self.records[slot],
            tail: None,
        }
    }

    /// Slot 0 a change output, any other slot a recipient body.
    pub fn tagged(&self, slot: usize) -> RingOutput<'_> {
        RingOutput {
            hash: &self.fields[10 + slot],
            owner_tag: if slot == 0 {
                ZERO_TAG
            } else {
                slot_tag(self.tags[slot])
            },
            body: match slot {
                0 => SlotBody::None,
                _ => SlotBody::Recipient(&self.recipient_body),
            },
            record: &self.records[slot],
            tail: None,
        }
    }

    /// `outputs` is the frame's `m`, slot 0 its one bodiless slot as [`Self::tagged`] builds it.
    pub fn sender(&self, outputs: usize) -> Option<FramedSenderBundle<'_>> {
        Some(FramedSenderBundle {
            tag: &self.tags[0],
            body: &self.sender_body[..BundleLayout { outputs, change: 1 }.byte_len()],
        })
    }

    /// The anonymous frame's replies, one of `len` bytes per body-bearing slot.
    pub fn anonymous_replies(&self, len: u16) -> RingTransactData<'_> {
        let mut data = self.anonymous();
        data.replies = Some(Replies::new(len, &self.replies[..2 * usize::from(len)]).unwrap());
        data
    }

    pub fn anonymous_compact(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Anonymous, 3, 4);
        data.outputs = vec![self.tagged(0), self.tagged(1)];
        data.sender = self.sender(2);
        data.anonymous = Some(AnonymousProofData {
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
            default_owner_tag: None,
        });
        self.with_audit_stream(data)
    }

    pub fn confidential_compact(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 1, 8);
        data.outputs = (0..5).map(|slot| self.recipient(slot)).collect();
        self.with_audit_stream(data)
    }

    pub fn cases(&self) -> [(&'static str, RingTransactData<'_>); 15] {
        [
            ("confidential_policy", self.confidential_policy()),
            (
                "confidential_in_proof_owner_policy",
                self.confidential_in_proof_owner(),
            ),
            ("confidential_audit_only", self.confidential_delivered()),
            ("confidential_thresholds", self.confidential_thresholds()),
            ("confidential_data", self.confidential_data()),
            ("confidential_extensions", self.confidential_extensions()),
            ("confidential_no_spend", self.confidential_no_spend()),
            ("anonymous_policy", self.anonymous()),
            ("anonymous_entry_audit_only", self.anonymous_entry()),
            ("anonymous_public_owners", self.anonymous_public_owners()),
            ("delegate_move", self.delegate()),
            ("anonymous_delegate_move", self.anonymous_delegate()),
            ("anonymous_reply_metadata", self.anonymous_replies(97)),
            ("anonymous_compact", self.anonymous_compact()),
            ("confidential_compact", self.confidential_compact()),
        ]
    }
}

pub fn field(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[0] = 0x0f;
    value
}
