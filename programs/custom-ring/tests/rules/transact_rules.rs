//! The transact refusals ahead of either ring pairing.

use bytemuck::Zeroable;
use custom_ring_interface::{
    cosign::ApprovalMask,
    funder_account_position, input_flag,
    key_catalog::{FrameKey, RingCircuit},
    shape_flag, spl_withdrawal_count, tag, transact_flag, AnonymousProofData, BundleLayout,
    CoSignScope, CustomRingError, CustomRingProof, FramedSenderBundle, InputTrees,
    PlainGroth16Proof, PolicyProof, RingOutput, RingPolicy, RingRail, RingRole, RingTransactData,
    RootRead, SlotBody, CONFIDENTIAL_DATA_FREE_BODY_LEN, OUTPUT_RECORD_LEN,
    RING_TRANSACT_RING_CONFIG_INDEX, TRANSACT_PAYER_INDEX,
};
use solana_address::Address;
use solana_bn254::compression::prelude::alt_bn128_g2_compress_be;
use solana_instruction::AccountMeta;
use solana_keypair::{Keypair, Signer};
use spr_interface::{
    instruction::{CircuitId, InterfaceTransfer, TreeContext},
    shape::SPP_SUPPORTED_SHAPES,
    MAX_INTERFACE_TRANSFERS, SHIELDED_POOL_PROGRAM_ID,
};
use wincode::{containers, len::FixIntLen, Serialize};

use crate::common::{
    delegate_ring, off_curve_g2, on_curve_g2, policy_pda, reaches_verification, refused, ring_auth,
    set_co_signer, set_delegate, tracking_registry, transact, CoSignerSlot, Ring, Sent, Setup,
    PROGRAM, RECORDS, SYSTEM,
};

pub const SPP: Address = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);

/// A canonical field value, never zero.
fn field(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[0] = 0x0f;
    value
}

pub struct Fixture {
    proofs: [CustomRingProof; 2],
    spp_proof: PlainGroth16Proof,
    fields: Vec<[u8; 32]>,
    keys: [[u8; 32]; 16],
    /// Slot `i`'s record, a body with no payload.
    records: [[u8; OUTPUT_RECORD_LEN]; 16],
    /// Cut to the frame's output count.
    bundle: Vec<u8>,
    /// Cut to the stream layout's envelope length.
    envelope: Vec<u8>,
    /// Cut to one sealed key per published slot.
    recipient_keys: Vec<u8>,
    tags: [[u8; 32]; 16],
    salt: [u8; 16],
    spl_owners: [[u8; 32]; 8],
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
                proof_b: alt_bn128_g2_compress_be(&on_curve_g2()).unwrap(),
                proof_c: [0x32; 32],
            },
            fields: (1..=120u8).map(field).collect(),
            keys: core::array::from_fn(|i| [0x40 + i as u8; 32]),
            records: core::array::from_fn(|i| [0x80 + i as u8; OUTPUT_RECORD_LEN]),
            bundle: vec![0x3c; BundleLayout { outputs: 16 }.byte_len()],
            envelope: (0..5000u32).map(|byte| byte as u8 ^ 0x93).collect(),
            recipient_keys: (0..512u32).map(|byte| byte as u8 ^ 0x71).collect(),
            tags: core::array::from_fn(|i| field(0xa0 + i as u8)),
            salt: [0x5c; 16],
            spl_owners: [[0x73; 32]; 8],
        }
    }

    pub fn settle_legs<'a>(
        &'a self,
        data: &mut RingTransactData<'a>,
        transfers: Vec<InterfaceTransfer>,
    ) {
        data.spl_withdrawal_owners = &self.spl_owners[..spl_withdrawal_count(&transfers)];
        data.interface_transfers = transfers;
    }

    /// Identity points decompress and fail the pairing.
    pub fn with_identity_proof(mut self) -> Self {
        self.proofs = [CustomRingProof::zeroed(); 2];
        self
    }

    /// The own root read off the authority rails as `Ring::new` binds records.
    pub fn transfer(
        &self,
        rail: RingRail,
        n_in: u8,
        n_out: u8,
        policy: bool,
    ) -> RingTransactData<'_> {
        let hidden_sender = rail == RingRail::Anonymous;
        let mut data = RingTransactData {
            rail,
            n_in,
            n_out,
            proof: &self.proofs[0],
            tracking_revision: Default::default(),
            own_revision: (!rail.is_delegate()).then(Default::default),
            policy: policy.then_some(PolicyProof {
                curator_revision: None,
            }),
            spl_withdrawal_owners: &[],
            approval: ApprovalMask::default(),
            no_spend: false,
            public_owners: false,
            expiry_unix_ts: 1_800_000_000,
            tx_viewing_u: &self.keys[0],
            salt: &self.salt,
            extensions: custom_ring_interface::FrameExtensions::default(),
            interface_transfers: Vec::new(),
            has_data: false,
            entry: false,
            wide_owners: FrameKey {
                rail,
                inputs: usize::from(n_in),
                outputs: usize::from(n_out),
                spends_default_ring: false,
                wide: false,
            }
            .shape()
            .is_none(),
            outputs: Vec::new(),
            replies: None,
            sender: rail.anonymous_frame().then(|| FramedSenderBundle {
                tag: &self.tags[15],
                body: &[],
            }),
            envelope: &[],
            recipient_keys: &[],
            private_tx_hash: &self.fields[0],
            anonymous: hidden_sender.then(|| AnonymousProofData {
                commitment: &self.keys[3],
                commitment_pok: &self.keys[4],
                default_owner_tag: None,
            }),
            in_proof_owner: None,
            spp_proof: &self.spp_proof,
            nullifiers: &self.fields[1..1 + usize::from(n_in)],
            input_trees: InputTrees::One(TreeContext {
                utxo_tree_root_index: 1,
                nullifier_tree_root_index: 2,
            }),
        };
        data.outputs = (0..usize::from(n_out))
            .map(|slot| RingOutput {
                hash: &self.fields[10 + slot],
                owner_tag: custom_ring_interface::stream::slot_tag(self.tags[slot]),
                body: SlotBody::Recipient(&self.records[slot]),
                record: &self.records[slot],
            })
            .collect();
        self.fit_stream(&mut data);
        self.fit_bundle(&mut data);
        data
    }

    pub fn public_owners(&self, n_in: u8, n_out: u8, policy: bool) -> RingTransactData<'_> {
        let mut data = self.transfer(RingRail::Anonymous, n_in, n_out, policy);
        data.public_owners = true;
        data.anonymous = None;
        data
    }

    /// A confidential transfer `owner` signs inside SPP's anonymous rail proof.
    pub fn in_proof_owner<'a>(
        &'a self,
        owner: &'a [u8; 32],
        n_in: u8,
        n_out: u8,
        policy: bool,
    ) -> RingTransactData<'a> {
        let mut data = self.transfer(RingRail::Confidential, n_in, n_out, policy);
        data.in_proof_owner = Some(custom_ring_interface::InProofOwner {
            owner,
            commitment: &self.keys[3],
            commitment_pok: &self.keys[4],
        });
        self.fit_stream(&mut data);
        data
    }

    pub fn fit_stream<'a>(&'a self, data: &mut RingTransactData<'a>) {
        let stream = data.audit_stream().unwrap();
        data.envelope = &self.envelope[..stream.envelope().len];
        data.recipient_keys = &self.recipient_keys[..stream.keys_len()];
    }

    pub fn fit_bundle<'a>(&'a self, data: &mut RingTransactData<'a>) {
        let len = data.bundle_layout().byte_len();
        if let Some(sender) = &mut data.sender {
            sender.body = &self.bundle[..len];
        }
    }
}

/// The forwarded SPP list, the payer first, `owners` as the owner signer run.
pub fn spp_list(
    payer: &Address,
    data: &RingTransactData<'_>,
    owners: &[AccountMeta],
) -> Vec<AccountMeta> {
    let trees = match data.input_trees {
        InputTrees::One(_) => 1,
        InputTrees::Two { .. } => 2,
    };
    let mut accounts = vec![
        AccountMeta::new(*payer, true),
        AccountMeta::new(Address::new_unique(), false),
        AccountMeta::new_readonly(SPP, false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new(ring_auth(), false),
    ];
    accounts.extend(
        (0..trees + data.nullifiers.len()).map(|_| AccountMeta::new(Address::new_unique(), false)),
    );
    accounts.extend_from_slice(owners);
    accounts
}

pub fn send(
    ring: &mut Ring,
    instruction_tag: u8,
    prefix: Vec<AccountMeta>,
    bytes: Vec<u8>,
    spp: Vec<AccountMeta>,
    signers: &[&Keypair],
) -> Sent {
    let policy: RingPolicy = ring.read(&policy_pda());
    let delegate_rail = instruction_tag == tag::AUTHORITY_TRANSFER;
    let accounts = [
        vec![AccountMeta::new_readonly(policy_pda(), false)],
        ring.registries(RootRead::transfer(&policy, delegate_rail)),
        prefix,
        spp,
    ]
    .concat();
    ring.send(transact(instruction_tag, accounts, bytes), signers)
}

/// The payer repeated as the one owner signer, the lean confidential set.
fn payer_owner(ring: &Ring) -> Vec<AccountMeta> {
    vec![AccountMeta::new_readonly(ring.payer.pubkey(), true)]
}

/// A confidential transfer from the payer, `prefix` after the ring account.
pub fn confidential(
    ring: &mut Ring,
    prefix: Vec<AccountMeta>,
    data: &RingTransactData<'_>,
) -> Sent {
    let spp = spp_list(&ring.payer.pubkey(), data, &payer_owner(ring));
    send(
        ring,
        tag::TRANSFER,
        prefix,
        data.encode().unwrap(),
        spp,
        &[],
    )
}

#[test]
fn a_transfer_passing_every_check_names_exactly_one_ring_account() {
    let fixture = Fixture::new();
    for (setup, policy) in [(Setup::AuditOnly, false), (Setup::Policy, true)] {
        let mut ring = Ring::new(setup);
        let data = fixture.transfer(RingRail::Confidential, 2, 2, policy);
        let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
        let accounts = [
            vec![AccountMeta::new_readonly(policy_pda(), false)],
            vec![
                AccountMeta::new_readonly(RECORDS, false),
                AccountMeta::new_readonly(tracking_registry(), false),
            ],
            spp,
        ]
        .concat();
        let ring_owned = accounts
            .iter()
            .filter(|meta| ring.owner(&meta.pubkey) == Some(PROGRAM))
            .count();
        assert_eq!(ring_owned, 1);
        let instruction = transact(tag::TRANSFER, accounts, data.encode().unwrap());
        reaches_verification(ring.send(instruction, &[]));
    }
}

#[test]
fn trailing_or_missing_bytes_disagree_with_the_shape() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
    let encoded = data.encode().unwrap();
    let trailing = [&encoded[..], &[0]].concat();
    for bytes in [trailing, encoded[..encoded.len() - 1].to_vec()] {
        refused(
            send(
                &mut ring,
                tag::TRANSFER,
                Vec::new(),
                bytes,
                spp.clone(),
                &[],
            ),
            CustomRingError::RingTransactLength,
        );
    }
}

#[test]
fn flags_follow_the_rings_mode_and_policy() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let mut bytes = data.encode().unwrap();
    bytes[transact_flag::BYTE] |= 1 << 6;
    let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
    refused(
        send(&mut ring, tag::TRANSFER, Vec::new(), bytes, spp, &[]),
        CustomRingError::FlagNotAllowed,
    );
    refused(
        confidential(
            &mut ring,
            Vec::new(),
            &fixture.transfer(RingRail::Confidential, 2, 2, true),
        ),
        CustomRingError::UnexpectedPolicyProof,
    );
    let mut policy_ring = Ring::new(Setup::Policy);
    refused(
        confidential(&mut policy_ring, Vec::new(), &data),
        CustomRingError::MissingPolicyProof,
    );
}

#[test]
fn a_spend_takes_at_least_one_owner_signer_up_to_the_key_slots() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let data = fixture.transfer(RingRail::Confidential, 2, 8, true);
    let second = Keypair::new();
    let owners = [
        AccountMeta::new_readonly(ring.payer.pubkey(), true),
        AccountMeta::new_readonly(second.pubkey(), true),
    ];
    let spp = spp_list(&ring.payer.pubkey(), &data, &owners);
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[&second],
    ));
    let repeated = [owners[0].clone(), owners[0].clone()];
    let spp = spp_list(&ring.payer.pubkey(), &data, &repeated);
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[],
    ));
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::OwnerSignerCount,
    );
}

#[test]
fn every_confidential_owner_slot_signs() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let owners = [AccountMeta::new_readonly(Keypair::new().pubkey(), false)];
    let spp = spp_list(&ring.payer.pubkey(), &data, &owners);
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::MissingOwnerSigner,
    );
}

/// A stray signer takes no co-signer cell, the wallet decides whether it names the hidden owner.
#[test]
fn an_anonymous_owner_run_signs_and_another_signer_reaches_the_proof() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    let owner = Keypair::new();
    let run = [AccountMeta::new_readonly(owner.pubkey(), true)];
    let spp = spp_list(&ring.payer.pubkey(), &data, &run);
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[&owner],
    ));
    let mut stray = spp_list(&ring.payer.pubkey(), &data, &[]);
    stray[RING_TRANSACT_RING_CONFIG_INDEX + 1].pubkey = owner.pubkey();
    stray[RING_TRANSACT_RING_CONFIG_INDEX + 1].is_signer = true;
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        stray,
        &[&owner],
    ));
    let unsigned = [AccountMeta::new_readonly(owner.pubkey(), false)];
    let spp = spp_list(&ring.payer.pubkey(), &data, &unsigned);
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::MissingOwnerSigner,
    );
}

/// A public default-ring owner signs beside a hidden ring sender.
#[test]
fn the_entry_key_takes_an_owner_run() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    data.entry = true;
    fixture.fit_stream(&mut data);
    let owner = Keypair::new();
    let run = [AccountMeta::new_readonly(owner.pubkey(), true)];
    let spp = spp_list(&ring.payer.pubkey(), &data, &run);
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[&owner],
    ));
}

/// A run wider than `S` cannot fit the chain the key binds.
#[test]
fn an_owner_run_past_the_key_slots_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    // The two input entry key binds the narrowest run.
    let mut data = fixture.transfer(RingRail::Confidential, 2, 8, false);
    data.entry = true;
    fixture.fit_stream(&mut data);
    assert_eq!(data.audit_stream().unwrap().key.signer_slots(), 2);
    let slots = data.audit_stream().unwrap().key.signer_slots();
    let owners: Vec<Keypair> = (0..=slots).map(|_| Keypair::new()).collect();
    let run: Vec<AccountMeta> = owners
        .iter()
        .map(|owner| AccountMeta::new_readonly(owner.pubkey(), true))
        .collect();
    let signers: Vec<&Keypair> = owners.iter().collect();
    let spp = spp_list(&ring.payer.pubkey(), &data, &run);
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &signers,
        ),
        CustomRingError::OwnerSignerCount,
    );
}

/// `m` shrinks the frame, the shape's key still serves and the ring's rules still read it.
#[test]
fn a_compact_transfer_reaches_the_key_of_its_capacity() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 4, false);
    data.outputs.truncate(3);
    fixture.fit_stream(&mut data);
    let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[],
    ));
    let mut anonymous_ring = Ring::new(Setup::Anonymous);
    let mut hidden = fixture.transfer(RingRail::Anonymous, 2, 4, false);
    hidden.outputs.truncate(2);
    fixture.fit_bundle(&mut hidden);
    fixture.fit_stream(&mut hidden);
    let spp = spp_list(&anonymous_ring.payer.pubkey(), &hidden, &[]);
    reaches_verification(send(
        &mut anonymous_ring,
        tag::TRANSFER,
        Vec::new(),
        hidden.encode().unwrap(),
        spp,
        &[],
    ));
}

/// SPP's external data hash binds the ring body and the reply, SPP stores both.
#[test]
fn reply_metadata_reaches_the_key_on_the_anonymous_rail_and_no_other() {
    let fixture = Fixture::new();
    let replies = [0x71; 291];
    let mut ring = Ring::new(Setup::Anonymous);
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 4, false);
    data.replies = Some(custom_ring_interface::Replies::new(97, &replies).unwrap());
    data.outputs.truncate(3);
    fixture.fit_bundle(&mut data);
    fixture.fit_stream(&mut data);
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[],
    ));
    let mut confidential_ring = Ring::new(Setup::AuditOnly);
    let plain = fixture.transfer(RingRail::Confidential, 2, 4, false);
    let spp = spp_list(
        &confidential_ring.payer.pubkey(),
        &plain,
        &payer_owner(&confidential_ring),
    );
    let mut bytes = plain.encode().unwrap();
    bytes[transact_flag::BYTE] |= transact_flag::REPLY_METADATA;
    refused(
        send(
            &mut confidential_ring,
            tag::TRANSFER,
            Vec::new(),
            bytes,
            spp,
            &[],
        ),
        CustomRingError::FlagNotAllowed,
    );
}

/// A ring with records holds thresholds, the frame cannot omit the root that reads them.
#[test]
fn an_anonymous_transfer_binds_a_live_own_root() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    data.own_revision = Some(7u64.into());
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            data.encode().unwrap(),
            spp.clone(),
            &[],
        ),
        CustomRingError::RootNotServed,
    );
    data.own_revision = Some(Default::default());
    let accounts = [vec![AccountMeta::new_readonly(policy_pda(), false)], spp].concat();
    refused(
        ring.send(
            transact(tag::TRANSFER, accounts, data.encode().unwrap()),
            &[],
        ),
        CustomRingError::UnboundRegistry,
    );
}

#[test]
fn an_off_curve_spp_point_is_refused_before_either_pairing() {
    let mut fixture = Fixture::new();
    fixture.spp_proof.proof_b = off_curve_g2();
    let mut ring = Ring::new(Setup::AuditOnly);
    refused(
        confidential(
            &mut ring,
            Vec::new(),
            &fixture.transfer(RingRail::Confidential, 2, 2, false),
        ),
        CustomRingError::InvalidSppProofPoint,
    );
}

/// An all-zero ciphertext reaches the proof, its digest and length tag bind it.
#[test]
fn a_zero_ciphertext_reaches_verification() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let stream = data.audit_stream().unwrap();
    let zeros = [0; 256];
    data.envelope = &zeros[..stream.envelope().len];
    reaches_verification(confidential(&mut ring, Vec::new(), &data));
}

/// Family, layout and counts fix each length, the program refuses any other before a pairing.
#[test]
fn a_truncated_or_appended_ciphertext_is_refused() {
    let fixture = Fixture::new();
    for (setup, rail) in [
        (Setup::AuditOnly, RingRail::Confidential),
        (Setup::Anonymous, RingRail::Anonymous),
    ] {
        let mut ring = Ring::new(setup);
        let data = fixture.transfer(rail, 2, 2, false);
        let stream = data.audit_stream().unwrap();
        let compact = data.encode().unwrap();
        let end = compact
            .windows(data.envelope.len())
            .position(|window| window == data.envelope)
            .unwrap()
            + stream.sealed_len();
        let mut truncated = compact.clone();
        truncated.remove(end - 1);
        let mut appended = compact;
        appended.insert(end, 0x7a);
        for bytes in [truncated, appended] {
            let owners = match rail {
                RingRail::Anonymous => Vec::new(),
                _ => payer_owner(&ring),
            };
            let spp = spp_list(&ring.payer.pubkey(), &data, &owners);
            refused(
                send(&mut ring, tag::TRANSFER, Vec::new(), bytes, spp, &[]),
                CustomRingError::RingTransactLength,
            );
        }
    }
}

#[test]
fn a_default_ring_spend_takes_the_entry_key_up_to_eight_inputs() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    data.entry = true;
    fixture.fit_stream(&mut data);
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[],
    ));

    let wide = fixture.transfer(RingRail::Anonymous, 12, 2, false);
    let spp = spp_list(&ring.payer.pubkey(), &wide, &[]);
    let mut bytes = wide.encode().unwrap();
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        bytes.clone(),
        spp.clone(),
        &[],
    ));
    bytes[input_flag::BYTE] |= input_flag::ENTRY;
    refused(
        send(&mut ring, tag::TRANSFER, Vec::new(), bytes, spp, &[]),
        CustomRingError::RingShapeUnkeyed,
    );
}

/// The compact bytes of a `test-vectors/proof/ring-transact-expansion.json` case.
fn vector_case(name: &str) -> Vec<u8> {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/proof/ring-transact-expansion.json"
    )))
    .unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap();
    hex::decode(case["compact"].as_str().unwrap()).unwrap()
}

#[test]
fn the_vector_transfers_without_public_legs_reach_their_keys() {
    let mut bare = Ring::new(Setup::Bare);
    let bytes = vector_case("confidential_audit_only");
    let data = RingTransactData::parse(&bytes, RingRail::Confidential)
        .unwrap()
        .into_data();
    bare.serve_tracking(data.tracking_revision);
    let spp = spp_list(&bare.payer.pubkey(), &data, &payer_owner(&bare));
    reaches_verification(send(
        &mut bare,
        tag::TRANSFER,
        Vec::new(),
        bytes.clone(),
        spp,
        &[],
    ));

    let mut anonymous = Ring::new(Setup::BareAnonymous);
    let bytes = vector_case("anonymous_entry_audit_only");
    let parsed = RingTransactData::parse(&bytes, RingRail::Anonymous).unwrap();
    let data = parsed.data();
    assert!(matches!(
        data.transfer_circuit(0),
        Ok(RingCircuit::Transfer { entry: true, .. })
    ));
    anonymous.serve_tracking(data.tracking_revision);
    let spp = spp_list(&anonymous.payer.pubkey(), data, &[]);
    reaches_verification(send(
        &mut anonymous,
        tag::TRANSFER,
        Vec::new(),
        bytes.clone(),
        spp,
        &[],
    ));

    let delegate = Keypair::new();
    let mut delegated = delegate_ring(&delegate);
    let bytes = vector_case("delegate_move");
    let data = RingTransactData::parse(&bytes, RingRail::Delegate)
        .unwrap()
        .into_data();
    delegated.serve_tracking(data.tracking_revision);
    reaches_verification(delegate_move(
        &mut delegated,
        &delegate,
        &data,
        bytes.clone(),
    ));
}

/// No records means no thresholds, the frame names no own root.
#[test]
fn a_bare_ring_reads_the_tracking_root_alone() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Bare);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    refused(
        confidential(&mut ring, Vec::new(), &data),
        CustomRingError::FlagNotAllowed,
    );
    data.own_revision = None;
    reaches_verification(confidential(&mut ring, Vec::new(), &data));
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(
        account
            .root_registries(RootRead::transfer(&account, false))
            .collect::<Vec<_>>(),
        vec![tracking_registry()]
    );
}

#[test]
fn a_ring_without_a_policy_hash_reads_as_audit_only() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let mut policy: RingPolicy = ring.read(&policy_pda());
    policy.policy_hash = [0; 32];
    ring.write(&policy_pda(), &policy);
    refused(
        confidential(
            &mut ring,
            Vec::new(),
            &fixture.transfer(RingRail::Confidential, 2, 2, true),
        ),
        CustomRingError::UnexpectedPolicyProof,
    );
}

#[test]
fn a_demanded_co_signer_signs_with_the_configured_key() {
    let fixture = Fixture::new();
    let data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let co_signer = Keypair::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    set_co_signer(&mut ring, &co_signer.pubkey(), 1);
    let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            CoSignerSlot::own(co_signer.pubkey()).unsigned(),
            data.encode().unwrap(),
            spp.clone(),
            &[],
        ),
        CustomRingError::MissingCoSigner,
    );
    let other = Keypair::new();
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            CoSignerSlot {
                record_of: co_signer.pubkey(),
                signer: other.pubkey(),
            }
            .signed(),
            data.encode().unwrap(),
            spp.clone(),
            &[&other],
        ),
        CustomRingError::UnauthorizedCoSigner,
    );
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            CoSignerSlot::own(other.pubkey()).signed(),
            data.encode().unwrap(),
            spp.clone(),
            &[&other],
        ),
        CustomRingError::InvalidCoSignerRecord,
    );
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        CoSignerSlot::own(co_signer.pubkey()).signed(),
        data.encode().unwrap(),
        spp,
        &[&co_signer],
    ));
}

/// A plain transfer from the payer, co-signed by `co_signer` under its own record.
fn co_signed_transfer(ring: &mut Ring, co_signer: &Keypair) -> Sent {
    let fixture = Fixture::new();
    let data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(ring));
    let slot = CoSignerSlot::own(co_signer.pubkey()).signed();
    send(
        ring,
        tag::TRANSFER,
        slot.to_vec(),
        data.encode().unwrap(),
        spp,
        &[co_signer],
    )
}

#[test]
fn a_second_co_signer_signs_a_transfer_in_its_scope() {
    let (first, second) = (Keypair::new(), Keypair::new());
    let mut ring = Ring::new(Setup::AuditOnly);
    set_co_signer(&mut ring, &first.pubkey(), CoSignScope::TRANSFERS.bits());
    set_co_signer(&mut ring, &second.pubkey(), CoSignScope::ALL.bits());
    reaches_verification(co_signed_transfer(&mut ring, &first));
    reaches_verification(co_signed_transfer(&mut ring, &second));
}

#[test]
fn a_co_signer_whose_scope_misses_the_demanded_class_is_refused() {
    let (transfers, withdrawals) = (Keypair::new(), Keypair::new());
    let mut ring = Ring::new(Setup::AuditOnly);
    set_co_signer(
        &mut ring,
        &transfers.pubkey(),
        CoSignScope::TRANSFERS.bits(),
    );
    set_co_signer(
        &mut ring,
        &withdrawals.pubkey(),
        CoSignScope::WITHDRAWALS.bits(),
    );
    refused(
        co_signed_transfer(&mut ring, &withdrawals),
        CustomRingError::CoSignerOutOfScope,
    );
}

/// `prefix` holds one co-signer slot or none.
fn withdraw(ring: &mut Ring, legs: &[u64], prefix: Vec<AccountMeta>, signers: &[&Keypair]) -> Sent {
    let fixture = Fixture::new();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    data.interface_transfers = legs
        .iter()
        .map(|amount| InterfaceTransfer::SolWithdrawal { amount: *amount })
        .collect();
    let mut spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(ring));
    for transfer in &data.interface_transfers {
        spp.extend(
            (0..transfer.settlement_account_count())
                .map(|_| AccountMeta::new(Address::new_unique(), false)),
        );
    }
    send(
        ring,
        tag::TRANSFER,
        prefix,
        data.encode().unwrap(),
        spp,
        signers,
    )
}

#[test]
fn a_configured_withdrawals_record_demands_its_co_signer() {
    let co_signer = Keypair::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    set_co_signer(&mut ring, &co_signer.pubkey(), 4);
    refused(
        withdraw(
            &mut ring,
            &[101],
            CoSignerSlot::own(co_signer.pubkey()).unsigned(),
            &[],
        ),
        CustomRingError::MissingCoSigner,
    );
    reaches_verification(withdraw(
        &mut ring,
        &[101],
        CoSignerSlot::own(co_signer.pubkey()).signed(),
        &[&co_signer],
    ));
    refused(
        withdraw(&mut ring, &[60, 60], Vec::new(), &[]),
        CustomRingError::InvalidCoSignerRecord,
    );
}

#[test]
fn a_withdrawal_co_signed_by_its_own_owner_is_refused() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let owner = ring.payer.insecure_clone();
    set_co_signer(&mut ring, &owner.pubkey(), 4);
    refused(
        withdraw(
            &mut ring,
            &[1_000],
            CoSignerSlot::own(owner.pubkey()).signed(),
            &[&owner],
        ),
        CustomRingError::CoSignerIsOwner,
    );
}

fn approved(ring: &mut Ring, mask: ApprovalMask, co_signers: &[&Keypair]) -> Sent {
    let fixture = Fixture::new();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    data.approval = mask;
    let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(ring));
    let prefix = co_signers
        .iter()
        .flat_map(|co_signer| CoSignerSlot::own(co_signer.pubkey()).signed())
        .collect();
    send(
        ring,
        tag::TRANSFER,
        prefix,
        data.encode().unwrap(),
        spp,
        co_signers,
    )
}

#[test]
fn a_proven_bit_fails_closed_without_an_approver_of_its_class() {
    for (bit, other) in [
        (ApprovalMask::OUTFLOW, CoSignScope::APPROVE_WITHDRAWAL),
        (ApprovalMask::WITHDRAWAL, CoSignScope::APPROVE_OUTFLOW),
    ] {
        let mut ring = Ring::new(Setup::AuditOnly);
        refused(
            approved(&mut ring, bit, &[]),
            CustomRingError::InvalidCoSignerRecord,
        );
        let unrelated = Keypair::new();
        set_co_signer(&mut ring, &unrelated.pubkey(), other.bits());
        refused(
            approved(&mut ring, bit, &[&unrelated]),
            CustomRingError::CoSignerOutOfScope,
        );
    }
}

#[test]
fn a_ring_with_no_record_settles_below_every_threshold_with_no_co_signer() {
    let mut ring = Ring::new(Setup::AuditOnly);
    reaches_verification(approved(&mut ring, ApprovalMask::default(), &[]));
}

/// Withdrawing 5000 under `cosign_above` 100 and `withdrawal_threshold` 1000 sets both bits.
#[test]
fn separate_approvers_settle_a_transaction_past_both_thresholds() {
    let (outflow, withdrawal, both_classes) = (Keypair::new(), Keypair::new(), Keypair::new());
    let mut ring = Ring::new(Setup::AuditOnly);
    set_co_signer(
        &mut ring,
        &outflow.pubkey(),
        CoSignScope::APPROVE_OUTFLOW.bits(),
    );
    set_co_signer(
        &mut ring,
        &withdrawal.pubkey(),
        CoSignScope::APPROVE_WITHDRAWAL.bits(),
    );
    let both =
        ApprovalMask::new(ApprovalMask::OUTFLOW.bits() | ApprovalMask::WITHDRAWAL.bits()).unwrap();
    reaches_verification(approved(&mut ring, both, &[&outflow, &withdrawal]));
    reaches_verification(approved(&mut ring, both, &[&withdrawal, &outflow]));
    refused(
        approved(&mut ring, both, &[&outflow]),
        CustomRingError::InvalidCoSignerRecord,
    );
    refused(
        approved(&mut ring, both, &[&outflow, &outflow]),
        CustomRingError::CoSignerOutOfScope,
    );
    refused(
        approved(&mut ring, ApprovalMask::OUTFLOW, &[&outflow, &withdrawal]),
        CustomRingError::MissingRingAuth,
    );
    set_co_signer(
        &mut ring,
        &both_classes.pubkey(),
        (CoSignScope::APPROVE_OUTFLOW | CoSignScope::APPROVE_WITHDRAWAL).bits(),
    );
    reaches_verification(approved(&mut ring, both, &[&both_classes]));
}

/// A deposit enters through a transfer, tag 58 names no instruction.
#[test]
fn the_program_names_no_instruction_at_tag_58() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let instruction = solana_instruction::Instruction {
        program_id: PROGRAM,
        accounts: vec![AccountMeta::new_readonly(policy_pda(), false)],
        data: vec![58; 219],
    };
    refused(
        ring.send(instruction, &[]),
        CustomRingError::InvalidInstructionData,
    );
}

#[test]
fn optional_classes_follow_the_economic_operation() {
    let (transfers, co_signer) = (Keypair::new(), Keypair::new());
    let mut ring = Ring::new(Setup::AuditOnly);
    set_co_signer(
        &mut ring,
        &transfers.pubkey(),
        CoSignScope::TRANSFERS.bits(),
    );
    set_co_signer(&mut ring, &co_signer.pubkey(), CoSignScope::DEPOSITS.bits());
    let fixture = Fixture::new();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    data.no_spend = true;
    data.interface_transfers = vec![InterfaceTransfer::SolDeposit { amount: 5 }];
    let mut spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    spp.extend([
        AccountMeta::new(Address::new_unique(), false),
        AccountMeta::new(ring.payer.pubkey(), true),
    ]);
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        CoSignerSlot::own(co_signer.pubkey()).signed(),
        data.encode().unwrap(),
        spp.clone(),
        &[&co_signer],
    ));
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            CoSignerSlot::own(transfers.pubkey()).signed(),
            data.encode().unwrap(),
            spp,
            &[&transfers],
        ),
        CustomRingError::CoSignerOutOfScope,
    );
}

#[test]
fn an_approval_co_signed_by_its_own_owner_is_refused() {
    let mut ring = Ring::new(Setup::LimitedPolicy);
    let fixture = Fixture::new();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.approval = ApprovalMask::OUTFLOW;
    let co_signed = |ring: &mut Ring, co_signer: &Keypair| {
        let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(ring));
        let prefix = CoSignerSlot::own(co_signer.pubkey()).signed();
        send(
            ring,
            tag::TRANSFER,
            prefix,
            data.encode().unwrap(),
            spp,
            &[co_signer],
        )
    };
    let owner = ring.payer.insecure_clone();
    let scope = CoSignScope::APPROVE_OUTFLOW.bits();
    set_co_signer(&mut ring, &owner.pubkey(), scope);
    refused(
        co_signed(&mut ring, &owner),
        CustomRingError::CoSignerIsOwner,
    );
    let co_signer = Keypair::new();
    set_co_signer(&mut ring, &co_signer.pubkey(), scope);
    reaches_verification(co_signed(&mut ring, &co_signer));
}

/// A leg the encoder accepts, its amount unique in the frame.
const PLACEHOLDER_LEG: InterfaceTransfer = InterfaceTransfer::SolWithdrawal {
    amount: 0x5a5a_5a5a_5a5a_5a5a,
};

fn leg_list(legs: &[InterfaceTransfer]) -> Vec<u8> {
    <containers::Vec<InterfaceTransfer, FixIntLen<u8>> as Serialize>::serialize(&legs.to_vec())
        .unwrap()
}

/// `data` encoded, then its legs replaced on the wire by `legs` the encoder refuses.
fn with_raw_legs(data: &RingTransactData<'_>, legs: &[InterfaceTransfer]) -> Vec<u8> {
    let frame = data.encode().unwrap();
    let encoded = leg_list(&data.interface_transfers);
    let mut found = frame
        .windows(encoded.len())
        .enumerate()
        .filter_map(|(at, window)| (window == encoded).then_some(at));
    let at = found.next().expect("the legs in the frame");
    assert!(found.next().is_none());
    [&frame[..at], &leg_list(legs), &frame[at + encoded.len()..]].concat()
}

/// A confidential transfer from the payer settling `transfers`, `funder` at each funder slot.
fn settle(ring: &mut Ring, transfers: Vec<InterfaceTransfer>, funder: &AccountMeta) -> Sent {
    settle_frame(ring, &transfers, funder, |data| data.encode().unwrap())
}

/// As `settle`, the frame built past the encoder, the program alone judges `transfers`.
fn settle_raw(ring: &mut Ring, transfers: &[InterfaceTransfer], funder: &AccountMeta) -> Sent {
    settle_frame(ring, transfers, funder, |data| {
        let mut data = data.clone();
        data.interface_transfers = vec![PLACEHOLDER_LEG];
        with_raw_legs(&data, transfers)
    })
}

fn settle_frame(
    ring: &mut Ring,
    transfers: &[InterfaceTransfer],
    funder: &AccountMeta,
    frame: impl FnOnce(&RingTransactData<'_>) -> Vec<u8>,
) -> Sent {
    let fixture = Fixture::new();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    fixture.settle_legs(&mut data, transfers.to_vec());
    let mut spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(ring));
    for transfer in &data.interface_transfers {
        let mut group: Vec<AccountMeta> = (0..transfer.settlement_account_count())
            .map(|_| AccountMeta::new(Address::new_unique(), false))
            .collect();
        if let Some(position) = funder_account_position(transfer) {
            group[position] = funder.clone();
        }
        spp.extend(group);
    }
    send(ring, tag::TRANSFER, Vec::new(), frame(&data), spp, &[])
}

#[test]
fn public_legs_are_refused_with_the_rings_own_errors() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let payer = AccountMeta::new(ring.payer.pubkey(), true);
    // `validate_under` refuses a zero leg in the encoder and again in the program's frame parse.
    let zero = [InterfaceTransfer::SolWithdrawal { amount: 0 }];
    let fixture = Fixture::new();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    fixture.settle_legs(&mut data, zero.to_vec());
    assert_eq!(data.encode(), Err(CustomRingError::ZeroPublicLegAmount));
    refused(
        settle_raw(&mut ring, &zero, &payer),
        CustomRingError::ZeroPublicLegAmount,
    );
    // The raw path parses a valid list, the refusal above is the zero leg's.
    refused(
        settle_raw(
            &mut ring,
            &[
                InterfaceTransfer::SolDeposit { amount: 5 },
                InterfaceTransfer::SolWithdrawal { amount: 5 },
            ],
            &payer,
        ),
        CustomRingError::ZeroNetPublicAmount,
    );
    let mints = InterfaceTransfer::SplWithdrawal {
        amount: 9,
        spl_interface_bump: 255,
    };
    refused(
        settle(
            &mut ring,
            vec![
                InterfaceTransfer::SolWithdrawal { amount: 7 },
                mints,
                mints,
                mints,
            ],
            &payer,
        ),
        CustomRingError::TooManyPublicAssets,
    );
    refused(
        settle(
            &mut ring,
            vec![InterfaceTransfer::SolWithdrawal { amount: u64::MAX }; 2],
            &payer,
        ),
        CustomRingError::PublicAmountOverflow,
    );
    let unsigned = AccountMeta::new(Address::new_unique(), false);
    refused(
        settle(
            &mut ring,
            vec![InterfaceTransfer::SolDeposit { amount: 5 }],
            &unsigned,
        ),
        CustomRingError::MissingFundingSigner,
    );
}

#[test]
fn public_legs_fit_the_account_list_and_the_leg_cap() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let spl = InterfaceTransfer::SplWithdrawal {
        amount: 9,
        spl_interface_bump: 255,
    };
    fixture.settle_legs(&mut data, vec![spl; 4]);
    let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::InvalidSettlementAccounts,
    );
    // `validate_under` refuses a list past the cap in the encoder and again in the program's frame parse.
    let legs = vec![InterfaceTransfer::SolWithdrawal { amount: 1 }; MAX_INTERFACE_TRANSFERS + 1];
    fixture.settle_legs(&mut data, legs.clone());
    assert_eq!(data.encode(), Err(CustomRingError::TooManyPublicLegs));
    fixture.settle_legs(&mut data, vec![PLACEHOLDER_LEG]);
    let mut spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
    let settlement = AccountMeta::new(Address::new_unique(), false);
    spp.extend(std::iter::repeat_n(settlement, 2 * legs.len()));
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            with_raw_legs(&data, &legs),
            spp,
            &[],
        ),
        CustomRingError::TooManyPublicLegs,
    );
}

/// A leg's funder stands apart from the owner run, a signer on a withdrawal takes no cell either.
#[test]
fn an_anonymous_leg_admits_its_funder_and_a_withdrawal_signer() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let signer = Keypair::new();
    let frame = |leg: InterfaceTransfer| {
        let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
        data.interface_transfers = vec![leg];
        data
    };
    let group = [
        AccountMeta::new(Address::new_unique(), false),
        AccountMeta::new(signer.pubkey(), true),
    ];
    let funded = frame(InterfaceTransfer::SolDeposit { amount: 5 });
    let mut spp = spp_list(&ring.payer.pubkey(), &funded, &[]);
    spp.extend_from_slice(&group);
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        funded.encode().unwrap(),
        spp,
        &[&signer],
    ));
    let withdrawn = frame(InterfaceTransfer::SolWithdrawal { amount: 5 });
    let mut spp = spp_list(&ring.payer.pubkey(), &withdrawn, &[]);
    spp.extend_from_slice(&group);
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        withdrawn.encode().unwrap(),
        spp,
        &[&signer],
    ));
}

#[test]
fn the_forwarded_list_holds_the_ring_pda_and_a_signing_payer() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    for (index, error) in [
        (
            RING_TRANSACT_RING_CONFIG_INDEX,
            CustomRingError::MissingRingAuth,
        ),
        (TRANSACT_PAYER_INDEX, CustomRingError::MissingFundingSigner),
    ] {
        let mut spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
        spp[index] = AccountMeta::new(Address::new_unique(), false);
        refused(
            send(
                &mut ring,
                tag::TRANSFER,
                Vec::new(),
                data.encode().unwrap(),
                spp,
                &[],
            ),
            error,
        );
    }
}

#[test]
fn a_second_ring_pda_in_the_forwarded_list_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    let spp = spp_list(
        &ring.payer.pubkey(),
        &data,
        &[AccountMeta::new_readonly(ring_auth(), false)],
    );
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::RingAuthOutOfSlot,
    );
}

#[test]
fn only_the_configured_delegate_moves_withdraws_and_takes_no_deposit() {
    let fixture = Fixture::new();
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    let mut data = fixture.transfer(RingRail::Delegate, 2, 2, false);
    let prefix = |signer: &Keypair| vec![AccountMeta::new_readonly(signer.pubkey(), true)];
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    let other = Keypair::new();
    refused(
        send(
            &mut ring,
            tag::AUTHORITY_TRANSFER,
            prefix(&other),
            data.encode().unwrap(),
            spp.clone(),
            &[&other],
        ),
        CustomRingError::UnauthorizedDelegate,
    );
    refused(
        send(
            &mut ring,
            tag::AUTHORITY_TRANSFER,
            vec![AccountMeta::new_readonly(delegate.pubkey(), false)],
            data.encode().unwrap(),
            spp.clone(),
            &[],
        ),
        CustomRingError::UnauthorizedDelegate,
    );
    reaches_verification(send(
        &mut ring,
        tag::AUTHORITY_TRANSFER,
        prefix(&delegate),
        data.encode().unwrap(),
        spp.clone(),
        &[&delegate],
    ));
    data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 5 }];
    let mut settled = spp.clone();
    settled.extend([
        AccountMeta::new(Address::new_unique(), false),
        AccountMeta::new(Address::new_unique(), false),
    ]);
    reaches_verification(send(
        &mut ring,
        tag::AUTHORITY_TRANSFER,
        prefix(&delegate),
        data.encode().unwrap(),
        settled.clone(),
        &[&delegate],
    ));
    data.interface_transfers = vec![InterfaceTransfer::SolDeposit { amount: 5 }];
    refused(
        send(
            &mut ring,
            tag::AUTHORITY_TRANSFER,
            prefix(&delegate),
            data.encode().unwrap(),
            settled,
            &[&delegate],
        ),
        CustomRingError::DelegatePublicLeg,
    );
    let mut undelegated = Ring::new(Setup::AuditOnly);
    let data = fixture.transfer(RingRail::Delegate, 2, 2, false);
    let spp = spp_list(&undelegated.payer.pubkey(), &data, &[]);
    refused(
        send(
            &mut undelegated,
            tag::AUTHORITY_TRANSFER,
            prefix(&delegate),
            data.encode().unwrap(),
            spp,
            &[&delegate],
        ),
        CustomRingError::DelegateDisabled,
    );
}

/// A curator's restrictive update cannot fail a proof made before it.
#[test]
fn a_delegate_reads_no_policy_root_and_keeps_the_tracking_root() {
    let fixture = Fixture::new();
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    ring.apply_immediate(RECORDS, [0x0d; 32]);
    let data = fixture.transfer(RingRail::Delegate, 2, 2, false);
    let bytes = data.encode().unwrap();
    reaches_verification(delegate_move(&mut ring, &delegate, &data, bytes.clone()));
    let mut stale = data.clone();
    stale.tracking_revision = 9u64.into();
    let stale_bytes = stale.encode().unwrap();
    refused(
        delegate_move(&mut ring, &delegate, &stale, stale_bytes),
        CustomRingError::RootNotServed,
    );
    let mut with_own = bytes;
    with_own[transact_flag::BYTE] |= transact_flag::OWN_ROOT;
    refused(
        delegate_move(&mut ring, &delegate, &data, with_own),
        CustomRingError::FlagNotAllowed,
    );
}

#[test]
fn a_delegate_exit_selects_the_exit_circuit_and_reaches_its_key() {
    let fixture = Fixture::new();
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    let mut data = fixture.transfer(RingRail::Delegate, 2, 2, false);
    let kept = data.circuit();
    assert!(matches!(kept, CircuitId::RingAuthority(2, 2, _)));
    let payload = [0x77; CONFIDENTIAL_DATA_FREE_BODY_LEN];
    data.outputs[1].body = SlotBody::Exit(&payload);
    assert!(matches!(
        data.circuit(),
        CircuitId::RingAuthorityExit(2, 2, _)
    ));
    let bytes = data.encode().unwrap();
    reaches_verification(delegate_move(&mut ring, &delegate, &data, bytes));
}

#[test]
fn an_anonymous_ring_delegate_settles_on_the_authority_rail() {
    let fixture = Fixture::new();
    let delegate = Keypair::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let admin = ring.holder(RingRole::Admin);
    ring.send(
        set_delegate(&admin.pubkey(), &delegate.pubkey()),
        &[&admin, &delegate],
    )
    .expect("an anonymous ring takes a delegate");
    let data = fixture.transfer(RingRail::AnonymousDelegate, 2, 2, false);
    assert!(data.anonymous.is_none());
    let bytes = data.encode().unwrap();
    reaches_verification(delegate_move(&mut ring, &delegate, &data, bytes));
}

#[test]
fn a_delegate_ignores_every_co_signer_record_and_carries_none() {
    let fixture = Fixture::new();
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    let co_signer = Keypair::new();
    set_co_signer(&mut ring, &co_signer.pubkey(), CoSignScope::ALL.bits());
    let data = fixture.transfer(RingRail::Delegate, 2, 2, false);
    let bytes = data.encode().unwrap();
    reaches_verification(delegate_move(&mut ring, &delegate, &data, bytes));
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    let mut prefix = CoSignerSlot::own(co_signer.pubkey()).signed();
    prefix.push(AccountMeta::new_readonly(delegate.pubkey(), true));
    refused(
        send(
            &mut ring,
            tag::AUTHORITY_TRANSFER,
            prefix,
            data.encode().unwrap(),
            spp,
            &[&co_signer, &delegate],
        ),
        CustomRingError::MissingRingAuth,
    );
}

fn delegate_move(
    ring: &mut Ring,
    delegate: &Keypair,
    data: &RingTransactData<'_>,
    bytes: Vec<u8>,
) -> Sent {
    let spp = spp_list(&ring.payer.pubkey(), data, &[]);
    send(
        ring,
        tag::AUTHORITY_TRANSFER,
        vec![AccountMeta::new_readonly(delegate.pubkey(), true)],
        bytes,
        spp,
        &[delegate],
    )
}

#[test]
fn every_ring_authority_shape_reaches_the_delegate_key_lookup() {
    let fixture = Fixture::new();
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    for shape in SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| shape.is_ring_authority())
    {
        let n_in = u8::try_from(shape.n_inputs()).unwrap();
        let n_out = u8::try_from(shape.n_outputs()).unwrap();
        let mut data = fixture.transfer(RingRail::Delegate, n_in, n_out, false);
        data.nullifiers = &fixture.fields[1..2];
        fixture.fit_stream(&mut data);
        let bytes = data.encode().unwrap();
        reaches_verification(delegate_move(&mut ring, &delegate, &data, bytes));
    }
}

#[test]
fn a_delegate_shape_without_a_ring_authority_key_is_refused() {
    let fixture = Fixture::new();
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    let data = fixture.transfer(RingRail::Delegate, 2, 2, false);
    let mut bytes = data.encode().unwrap();
    let unkeyed = SPP_SUPPORTED_SHAPES
        .iter()
        .position(|shape| !shape.is_ring_authority())
        .expect("an SPP shape the ring authority rail refuses");
    bytes[shape_flag::BYTE] = u8::try_from(unkeyed).unwrap();
    refused(
        delegate_move(&mut ring, &delegate, &data, bytes),
        CustomRingError::RingShapeUnkeyed,
    );
}

#[test]
fn a_ring_account_of_another_owner_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let account: RingPolicy = ring.read(&policy_pda());
    ring.store(
        policy_pda(),
        Address::new_from_array([0x63; 32]),
        bytemuck::bytes_of(&account).to_vec(),
    );
    refused(
        confidential(
            &mut ring,
            Vec::new(),
            &fixture.transfer(RingRail::Confidential, 2, 2, false),
        ),
        CustomRingError::InvalidRingPolicy,
    );
}

/// An anonymous transfer whose public legs settle against `settlements`.
fn anonymous_exit(
    ring: &mut Ring,
    legs: &[InterfaceTransfer],
    settlements: Vec<AccountMeta>,
) -> Sent {
    let fixture = Fixture::new();
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    fixture.settle_legs(&mut data, legs.to_vec());
    let mut spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    spp.extend(settlements);
    send(
        ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[],
    )
}

/// The program reads no exit destination, a hidden sender may leave to any account and the wallet decides.
#[test]
fn an_anonymous_spend_leaves_to_any_destination() {
    let mut ring = Ring::new(Setup::Anonymous);
    let sol = InterfaceTransfer::SolWithdrawal { amount: 5 };
    let sol_group = |recipient: Address| {
        vec![
            AccountMeta::new(Address::new_unique(), false),
            AccountMeta::new(recipient, false),
        ]
    };
    let wallet = Address::new_unique();
    reaches_verification(anonymous_exit(
        &mut ring,
        &[sol, sol],
        [sol_group(wallet), sol_group(Address::new_unique())].concat(),
    ));
    let with_data = Address::new_unique();
    ring.store(with_data, SYSTEM, vec![1]);
    reaches_verification(anonymous_exit(&mut ring, &[sol], sol_group(with_data)));
}

#[test]
fn policy_spl_metadata_must_match_the_live_token_owner() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let mint = Address::new_unique();
    let token = Address::new_unique();
    let owner = Address::new_unique();
    let token_program = Address::new_from_array(spr_interface::SPL_TOKEN_PROGRAM_ID);
    let mut token_data = vec![0; spr_interface::SPL_TOKEN_ACCOUNT_LEN];
    token_data[..32].copy_from_slice(mint.as_ref());
    token_data[32..64].copy_from_slice(owner.as_ref());
    // The base SPL token account's state byte follows its delegate COption.
    token_data[108] = spr_interface::SPL_TOKEN_ACCOUNT_INITIALIZED;
    ring.store(token, token_program, token_data.clone());
    let owners = [owner.to_bytes()];
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.interface_transfers = vec![InterfaceTransfer::SplWithdrawal {
        amount: 5,
        spl_interface_bump: 255,
    }];
    data.spl_withdrawal_owners = &owners;
    let mut spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
    spp.extend([
        AccountMeta::new_readonly(
            Address::new_from_array(spr_interface::SHIELDED_POOL_CPI_AUTHORITY),
            false,
        ),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new(Address::new_unique(), false),
        AccountMeta::new(token, false),
        AccountMeta::new_readonly(token_program, false),
    ]);
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp.clone(),
        &[],
    ));
    token_data[32..64].copy_from_slice(Address::new_unique().as_ref());
    ring.store(token, token_program, token_data);
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::InvalidSettlementAccounts,
    );
}

/// `RootRead` fixes the account list, a frame cannot omit the own root that switches thresholds on.
#[test]
fn a_ring_with_records_binds_its_own_root_without_a_policy() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    data.own_revision = Some(1u64.into());
    refused(
        confidential(&mut ring, Vec::new(), &data),
        CustomRingError::RootNotServed,
    );
    data.own_revision = None;
    refused(
        confidential(&mut ring, Vec::new(), &data),
        CustomRingError::FlagNotAllowed,
    );
    data.own_revision = Some(0u64.into());
    reaches_verification(confidential(&mut ring, Vec::new(), &data));
}

/// Only a hidden sender has a destination the proof must tell apart from itself.
#[test]
fn public_owners_settle_on_the_confidential_selector_with_any_destinations() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let mut data = fixture.public_owners(2, 2, false);
    assert!(matches!(
        data.circuit(),
        CircuitId::ConfidentialRingEddsa(..)
    ));
    let owner = payer_owner(&ring);
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::OwnerSignerCount,
    );
    let spp = spp_list(&ring.payer.pubkey(), &data, &owner);
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[],
    ));
    data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 5 }; 2];
    let mut spp = spp_list(&ring.payer.pubkey(), &data, &owner);
    for _ in 0..4 {
        spp.push(AccountMeta::new(Address::new_unique(), false));
    }
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[],
    ));
}

#[test]
fn an_in_proof_owner_signs_beside_a_co_owner_run() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let owner = [0x71; 32];
    let data = fixture.in_proof_owner(&owner, 2, 2, true);
    let run = payer_owner(&ring);
    let spp = spp_list(&ring.payer.pubkey(), &data, &run);
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[],
    ));
}
