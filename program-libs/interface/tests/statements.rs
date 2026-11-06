//! Pins `test-vectors/proof/ring-statements.json` for the Go circuits and the TS SDK.

use custom_ring_interface::tracking::{TrackingEntry, TRACKING_EMPTY_ROOT};
use custom_ring_interface::{
    ciphertext_digest, cosign::ApprovalMask, domain, record_chain, tail_chain,
    ApplyEnrollmentsStatement, ApplyRecordsStatement, AuditHead, AuditKey, AuditLayout,
    AuditStreamLayout, ConfidentialSender, CustomRingError, PrivateWrites, RegisterKeyStatement,
    RingOutput, SignerDataCounts, SignerSet, SlotBody, TransferFamily, TransferRoots,
    TransferStatement, ANONYMOUS_PARTIES, AUDIT_HEAD_ELEMENTS, AUDIT_RECORD_LEN, DATA_TAIL_LEN,
    RECIPIENT_BODY_LEN,
};
use custom_ring_interface::{PublicLeg, PublicSlotError, PublicSlots, SOL_ASSET_ADDRESS};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_hasher::{
    hash_chain::create_hash_chain_4_from_slice,
    primitives::{hash_bytes, right_align, solana_owner_identity},
    Hasher, Poseidon,
};
use spr_interface::instruction::InterfaceTransfer;
use zolana_ring_policy::{Member, OutflowLimit};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/proof/ring-statements.json"
);
/// `q - 1200`, the amount field of a 1200 withdrawal.
const WITHDRAWAL_1200: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffb51";

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct StatementVectors {
    description: String,
    transfer: Vec<TransferCase>,
    apply_records: ApplyCase,
    apply_records_public: ApplyPublicCase,
    apply_enrollments: ApplyEnrollmentsCase,
    tracking: TrackingCase,
    register_key: RegisterKeyCase,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ApplyEnrollmentsCase {
    old_root: String,
    new_root: String,
    old_next_index: u64,
    new_next_index: u64,
    chain_start: String,
    chain_end: String,
    count: u64,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct TrackingCase {
    empty_root: String,
    member: String,
    nullifier_pk: String,
    ct_hash: String,
    list_tag: String,
    entry_hash: String,
    chain_from_zero: String,
    list_salt: String,
    secret_list_tag: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct OutputCase {
    hash: String,
    record: String,
    /// Null while `has_data` is clear.
    tail: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct TransferCase {
    /// `confidential` or `anonymous`.
    family: String,
    /// `signer`, `in_proof`, `delegate`, `anonymous`, `public_owners`, `anonymous_delegate` or `entry`.
    rail: String,
    in_proof: Option<bool>,
    public_owners: Option<bool>,
    delegate: bool,
    approval_mask: u8,
    signer_data_counts: u64,
    no_spend: bool,
    first_nullifier: String,
    ring_id: String,
    tx_viewing_u: String,
    auditor_pubkey: String,
    envelope: String,
    envelope_digest: String,
    salt: String,
    layout: u8,
    outputs: Vec<OutputCase>,
    output_capacity: usize,
    record_chain: String,
    tail_chain: String,
    input_count: usize,
    input_nullifier_chain: String,
    private_tx_hash: String,
    sender: Option<String>,
    party_identities: Option<Vec<String>>,
    signer_count: usize,
    signer_chain: String,
    policy_hash: String,
    own_root: String,
    curator_root: String,
    tracking_root: String,
    public_assets: Vec<String>,
    public_amounts: Vec<String>,
    public_gross: Vec<String>,
    withdrawal_hash: String,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ApplyCase {
    old_root: String,
    new_root: String,
    old_next_index: u32,
    new_next_index: u32,
    chain_start: String,
    chain_end: String,
    count: u64,
    restrictive: bool,
    private_writes: u16,
    tracking_root: String,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ApplyPublicCase {
    old_root: String,
    new_root: String,
    old_next_index: u32,
    new_next_index: u32,
    chain_start: String,
    chain_end: String,
    count: u64,
    restrictive: bool,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct RegisterKeyCase {
    ring_id: String,
    member: String,
    nullifier_pk: String,
    list_tag: String,
    auditor_pubkey: String,
    eph_u: String,
    ciphertext: String,
    elements: Vec<String>,
    public_input_hash: String,
}

fn field(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[0] = 0x1e;
    value
}

fn tagged(seed: u8) -> [u8; 33] {
    let mut key = [seed; 33];
    key[0] = 4;
    key
}

fn hexes(values: &[[u8; 32]]) -> Vec<String> {
    values.iter().map(hex::encode).collect()
}

struct Values {
    fields: Vec<[u8; 32]>,
    keys: Vec<[u8; 32]>,
    records: [[u8; AUDIT_RECORD_LEN]; 8],
    tails: [[u8; DATA_TAIL_LEN]; 8],
    envelope: Vec<u8>,
    auditor_pubkey: [u8; 33],
    ring_id: [u8; 32],
    salt: [u8; 16],
}

impl Values {
    fn new() -> Self {
        Self {
            fields: (0..80).map(field).collect(),
            keys: (0..16).map(|seed| [0x60 + seed; 32]).collect(),
            records: core::array::from_fn(|slot| [0x90 + slot as u8; AUDIT_RECORD_LEN]),
            tails: core::array::from_fn(|slot| [0xc0 + slot as u8; DATA_TAIL_LEN]),
            envelope: (0..1024u32).map(|byte| byte as u8 ^ 0x93).collect(),
            auditor_pubkey: tagged(0xa1),
            ring_id: hash_bytes(&[0x77; 32]).unwrap(),
            salt: [0x5c; 16],
        }
    }

    fn head(&self, layout: AuditLayout, envelope: AuditStreamLayout) -> AuditHead<'_> {
        AuditHead {
            first_nullifier: &self.fields[1],
            ring_id: &self.ring_id,
            tx_viewing_u: &self.keys[0],
            auditor_pubkey: &self.auditor_pubkey,
            envelope: &self.envelope[..envelope.envelope().len],
            salt: &self.salt,
            layout,
        }
    }

    fn outputs(&self, count: usize, tails: bool) -> Vec<RingOutput<'_>> {
        (0..count)
            .map(|slot| RingOutput {
                hash: &self.fields[20 + slot],
                owner_tag: custom_ring_interface::stream::slot_tag(self.keys[4 + slot % 4]),
                body: SlotBody::None,
                record: &self.records[slot],
                tail: tails.then_some(&self.tails[slot]),
            })
            .collect()
    }
}

/// The stream of a statement fixture.
fn stream(key: AuditKey, inputs: usize, outputs: &[RingOutput<'_>]) -> AuditStreamLayout {
    AuditStreamLayout {
        key,
        inputs,
        outputs: outputs.len(),
        capacity: outputs.len(),
        has_data: outputs.iter().any(|output| output.tail.is_some()),
    }
}

fn output_case(output: &RingOutput<'_>) -> OutputCase {
    OutputCase {
        hash: hex::encode(output.hash),
        record: hex::encode(output.record),
        tail: output.tail.map(hex::encode),
    }
}

fn transfer_case(statement: &TransferStatement<'_>) -> TransferCase {
    let head = statement.head;
    let (family, rail, in_proof, public_owners, delegate, sender, parties) = match statement.family
    {
        TransferFamily::Confidential { sender } => (
            "confidential",
            match sender {
                ConfidentialSender::Signer => "signer",
                ConfidentialSender::InProof(_) => "in_proof",
                ConfidentialSender::Authority => "delegate",
            },
            Some(matches!(sender, ConfidentialSender::InProof(_))),
            None,
            matches!(sender, ConfidentialSender::Authority),
            Some(hex::encode(sender.identity())),
            None,
        ),
        TransferFamily::Anonymous {
            party_identities,
            public_owners,
            delegate,
        } => (
            "anonymous",
            match (delegate, public_owners, head.layout.entry) {
                (true, ..) => "anonymous_delegate",
                (_, true, _) => "public_owners",
                (_, _, true) => "entry",
                _ => "anonymous",
            },
            None,
            Some(public_owners),
            delegate,
            None,
            Some(hexes(party_identities)),
        ),
    };
    TransferCase {
        family: family.to_string(),
        rail: rail.to_string(),
        in_proof,
        public_owners,
        delegate,
        approval_mask: statement.approval_mask.bits(),
        signer_data_counts: statement.signer_data_counts.packed(),
        no_spend: statement.no_spend,
        first_nullifier: hex::encode(head.first_nullifier),
        ring_id: hex::encode(head.ring_id),
        tx_viewing_u: hex::encode(head.tx_viewing_u),
        auditor_pubkey: hex::encode(head.auditor_pubkey),
        envelope: hex::encode(head.envelope),
        envelope_digest: hex::encode(ciphertext_digest(head.envelope).unwrap()),
        salt: hex::encode(head.salt),
        layout: head.layout.value(),
        outputs: statement.outputs.iter().map(output_case).collect(),
        output_capacity: statement.output_capacity,
        record_chain: hex::encode(
            record_chain(statement.outputs, statement.output_capacity).unwrap(),
        ),
        tail_chain: hex::encode(tail_chain(statement.outputs, statement.output_capacity).unwrap()),
        input_count: statement.input_count,
        input_nullifier_chain: hex::encode(statement.input_nullifier_chain),
        private_tx_hash: hex::encode(statement.private_tx_hash),
        sender,
        party_identities: parties,
        signer_count: statement.signers.count,
        signer_chain: hex::encode(statement.signers.chain),
        policy_hash: hex::encode(statement.roots.policy_hash),
        own_root: hex::encode(statement.roots.own_root),
        curator_root: hex::encode(statement.roots.curator_root),
        tracking_root: hex::encode(statement.roots.tracking_root),
        public_assets: hexes(statement.public_assets),
        public_amounts: hexes(statement.public_amounts),
        public_gross: hexes(statement.public_gross),
        withdrawal_hash: hex::encode(statement.withdrawal_hash),
        elements: hexes(&statement.elements().unwrap()),
        public_input_hash: hex::encode(statement.hash().unwrap()),
    }
}

fn compute_vectors() -> StatementVectors {
    let values = Values::new();
    let (two, eight, four) = (
        values.outputs(2, false),
        values.outputs(8, false),
        values.outputs(4, false),
    );
    let with_tails = values.outputs(2, true);
    let wide_key = AuditKey {
        format: custom_ring_interface::DisclosureFormat::Standard,
        class: 16,
        entry: false,
    };
    let entry_key = AuditKey {
        format: custom_ring_interface::DisclosureFormat::Standard,
        class: 8,
        entry: true,
    };
    let assets = [values.fields[60], values.fields[61], [0; 32]];
    let mut withdrawal = [0u8; 32];
    hex::decode_to_slice(WITHDRAWAL_1200, &mut withdrawal).unwrap();
    let amounts = [right_aligned(500), withdrawal, [0; 32]];
    let owner_signer = solana_owner_identity(&[0x42; 32]).unwrap();
    let zero = [0u8; 32];
    let gross = [zero, right_aligned(1200), zero];
    let no_withdrawals = custom_ring_interface::policy_withdrawal_hash(&[]).unwrap();
    let no_flags = AuditLayout::default();
    let policy_roots = TransferRoots {
        policy_hash: values.fields[6],
        own_root: values.fields[7],
        curator_root: values.fields[8],
        tracking_root: values.fields[9],
    };
    let thresholds_roots = TransferRoots {
        own_root: values.fields[7],
        tracking_root: values.fields[9],
        ..TransferRoots::default()
    };
    let tracking_roots = TransferRoots {
        tracking_root: values.fields[9],
        ..TransferRoots::default()
    };
    let signer_policy = TransferStatement {
        head: values.head(no_flags, stream(wide_key, 2, &eight)),
        family: TransferFamily::Confidential {
            sender: ConfidentialSender::Signer,
        },
        approval_mask: ApprovalMask::OUTFLOW,
        approval_totals: &[0; 32],
        signer_data_counts: SignerDataCounts::default(),
        no_spend: false,
        outputs: &eight,
        output_capacity: 8,
        input_count: 2,
        input_nullifier_chain: values.fields[4],
        private_tx_hash: &values.fields[3],
        signers: SignerSet::new([[0x42; 32], [0x43; 32], [0x42; 32]].iter(), 16).unwrap(),
        roots: &policy_roots,
        public_assets: &assets,
        public_amounts: &amounts,
        public_gross: &gross,
        withdrawal_hash: &no_withdrawals,
    };
    let signer_thresholds = TransferStatement {
        approval_mask: ApprovalMask::WITHDRAWAL,
        roots: &thresholds_roots,
        ..signer_policy
    };
    let signer_no_spend = TransferStatement {
        approval_mask: ApprovalMask::default(),
        no_spend: true,
        roots: &tracking_roots,
        signers: SignerSet::default(),
        ..signer_policy
    };
    let signer_data = TransferStatement {
        head: values.head(
            AuditLayout {
                format: custom_ring_interface::DisclosureFormat::Standard,
                has_data: true,
                entry: false,
            },
            stream(wide_key, 2, &with_tails),
        ),
        outputs: &with_tails,
        output_capacity: 2,
        signer_data_counts: SignerDataCounts::new(1 | 1 << SignerDataCounts::ENTRY_BITS).unwrap(),
        ..signer_policy
    };
    let in_proof_policy = TransferStatement {
        family: TransferFamily::Confidential {
            sender: ConfidentialSender::InProof(&owner_signer),
        },
        signers: SignerSet::default(),
        ..signer_policy
    };
    let no_slots = [zero; 3];
    let delegate_move = TransferStatement {
        head: values.head(no_flags, stream(wide_key, 2, &two)),
        family: TransferFamily::Confidential {
            sender: ConfidentialSender::Authority,
        },
        approval_mask: ApprovalMask::default(),
        outputs: &two,
        output_capacity: 2,
        signers: SignerSet::default(),
        roots: &tracking_roots,
        public_assets: &no_slots,
        public_amounts: &no_slots,
        public_gross: &no_slots,
        ..signer_policy
    };
    let mut parties = [zero; ANONYMOUS_PARTIES];
    parties[0] = right_aligned(11);
    parties[1] = right_aligned(12);
    parties[2] = right_aligned(13);
    let anonymous_policy_transfer = TransferStatement {
        head: values.head(no_flags, stream(wide_key, 3, &four)),
        family: TransferFamily::Anonymous {
            party_identities: &parties,
            public_owners: false,
            delegate: false,
        },
        approval_mask: ApprovalMask::default(),
        outputs: &four,
        output_capacity: 4,
        input_count: 3,
        input_nullifier_chain: values.fields[5],
        signers: SignerSet::new([[0x44; 32]].iter(), 16).unwrap(),
        ..signer_policy
    };
    let public_owners = TransferStatement {
        family: TransferFamily::Anonymous {
            party_identities: &parties,
            public_owners: true,
            delegate: false,
        },
        ..anonymous_policy_transfer
    };
    let anonymous_delegate = TransferStatement {
        family: TransferFamily::Anonymous {
            party_identities: &[zero; ANONYMOUS_PARTIES],
            public_owners: false,
            delegate: true,
        },
        signers: SignerSet::default(),
        roots: &tracking_roots,
        public_assets: &no_slots,
        public_amounts: &no_slots,
        public_gross: &no_slots,
        ..anonymous_policy_transfer
    };
    let anonymous_compact = TransferStatement {
        outputs: &four[..2],
        ..anonymous_policy_transfer
    };
    let entry = TransferStatement {
        head: values.head(
            AuditLayout {
                entry: true,
                ..no_flags
            },
            stream(entry_key, 3, &four),
        ),
        roots: &tracking_roots,
        signers: SignerSet::default(),
        ..anonymous_policy_transfer
    };
    let confidential_compact = TransferStatement {
        outputs: &eight[..5],
        ..signer_policy
    };
    let transfers = [
        signer_policy,
        signer_thresholds,
        signer_no_spend,
        signer_data,
        in_proof_policy,
        delegate_move,
        anonymous_policy_transfer,
        public_owners,
        anonymous_delegate,
        entry,
        anonymous_compact,
        confidential_compact,
    ];
    let apply = ApplyRecordsStatement {
        old_root: values.fields[9],
        new_root: values.fields[10],
        old_next_index: 5,
        new_next_index: 17,
        chain_start: values.fields[11],
        chain_end: values.fields[12],
        count: 16,
        restrictive: true,
        private: Some(PrivateWrites {
            private_writes: 1,
            tracking_root: values.fields[21],
        }),
    };
    let private = apply.private.expect("private apply statement");
    let public_apply = ApplyRecordsStatement {
        count: 3,
        restrictive: false,
        private: None,
        ..apply.clone()
    };
    let apply_enrollments = ApplyEnrollmentsStatement {
        old_root: values.fields[11],
        new_root: values.fields[12],
        old_next_index: 7,
        new_next_index: 9,
        chain_start: values.fields[9],
        chain_end: values.fields[10],
        count: 2,
    };
    let tracking_entry = TrackingEntry {
        member: values.fields[14],
        nullifier_pk: values.fields[13],
        ct_hash: values.fields[15],
        list_tag: values.fields[16],
    };
    let ring_id = values.fields[17];
    let list_salt = right_aligned(0x07);
    let list_tag = values.fields[16];
    let register_ciphertext = [0x44; 64];
    let register = RegisterKeyStatement {
        ring_id: &ring_id,
        member: &owner_signer,
        nullifier_pk: &values.fields[13],
        list_tag: &list_tag,
        auditor_pubkey: &values.auditor_pubkey,
        eph_u: &values.keys[9],
        ciphertext: &register_ciphertext,
    };
    StatementVectors {
        description: "Every ring statement and its public input HashChain4(elements). The transfer \
                      head is [CRTX, n0, ring_id, pack_be(0x04 || tx_u), pack_be(auditor_pubkey), \
                      digest(envelope), salt, layout] with the frame's \
                      random salt and layout = has_data | entry << 1. \
                      digest(ct) = Poseidon(u32 len(ct), HashChain4(pack_left31(ct))). Each \
                      envelope has the length of its stream layout. The transfer statements are HashChain4 over the \
                      audit head under CRTX, in_proof, hidden, delegate, \
                      approval_mask, no_spend, output_count, output_chain, record_chain \
                      HashChain4(hash_bytes(record_i)), tail_chain HashChain4(hash_bytes(tail_i)) or \
                      zero while has_data is clear, input_count, input_nullifier_chain, private_tx_hash, the sender, the \
                      party identities, signer_count, signer_chain, policy_hash, own_root, \
                      curator_root, tracking_root, asset, net and gross per public \
                      slot, withdrawal_hash and the element count. No body, tag, \
                      bundle or reply digest and no slot class enters it. Every per-slot chain is \
                      zero filled to the capacity. signer_chain is HashChain4 over the deduplicated \
                      owner identities zero filled to the key's S, and zero when signer_count is \
                      zero on every rail. The apply statement ends at the restrictive bit, and \
                      a private key appends private_writes and the tracking root. Produced by \
                      program-libs/interface/tests/statements.rs."
            .to_string(),
        transfer: transfers.iter().map(transfer_case).collect(),
        apply_records: ApplyCase {
            old_root: hex::encode(apply.old_root),
            new_root: hex::encode(apply.new_root),
            old_next_index: apply.old_next_index,
            new_next_index: apply.new_next_index,
            chain_start: hex::encode(apply.chain_start),
            chain_end: hex::encode(apply.chain_end),
            count: apply.count,
            restrictive: apply.restrictive,
            private_writes: private.private_writes,
            tracking_root: hex::encode(private.tracking_root),
            elements: hexes(&apply.elements()),
            public_input_hash: hex::encode(apply.hash().unwrap()),
        },
        apply_records_public: ApplyPublicCase {
            old_root: hex::encode(public_apply.old_root),
            new_root: hex::encode(public_apply.new_root),
            old_next_index: public_apply.old_next_index,
            new_next_index: public_apply.new_next_index,
            chain_start: hex::encode(public_apply.chain_start),
            chain_end: hex::encode(public_apply.chain_end),
            count: public_apply.count,
            restrictive: public_apply.restrictive,
            elements: hexes(&public_apply.elements()),
            public_input_hash: hex::encode(public_apply.hash().unwrap()),
        },
        apply_enrollments: ApplyEnrollmentsCase {
            old_root: hex::encode(apply_enrollments.old_root),
            new_root: hex::encode(apply_enrollments.new_root),
            old_next_index: apply_enrollments.old_next_index,
            new_next_index: apply_enrollments.new_next_index,
            chain_start: hex::encode(apply_enrollments.chain_start),
            chain_end: hex::encode(apply_enrollments.chain_end),
            count: apply_enrollments.count,
            elements: hexes(&apply_enrollments.elements()),
            public_input_hash: hex::encode(apply_enrollments.hash().unwrap()),
        },
        tracking: TrackingCase {
            empty_root: hex::encode(TRACKING_EMPTY_ROOT),
            member: hex::encode(tracking_entry.member),
            nullifier_pk: hex::encode(tracking_entry.nullifier_pk),
            ct_hash: hex::encode(tracking_entry.ct_hash),
            list_tag: hex::encode(tracking_entry.list_tag),
            entry_hash: hex::encode(tracking_entry.hash().unwrap()),
            chain_from_zero: hex::encode(tracking_entry.chained(&[0; 32]).unwrap()),
            list_salt: hex::encode(list_salt),
            secret_list_tag: hex::encode(domain::list_tag(&list_salt).unwrap()),
        },
        register_key: RegisterKeyCase {
            ring_id: hex::encode(register.ring_id),
            member: hex::encode(register.member),
            nullifier_pk: hex::encode(register.nullifier_pk),
            list_tag: hex::encode(register.list_tag),
            auditor_pubkey: hex::encode(register.auditor_pubkey),
            eph_u: hex::encode(register.eph_u),
            ciphertext: hex::encode(register.ciphertext),
            elements: hexes(&register.elements().unwrap()),
            public_input_hash: hex::encode(register.hash().unwrap()),
        },
    }
}

fn right_aligned(amount: u64) -> [u8; 32] {
    spr_hasher::primitives::right_align(&amount.to_be_bytes())
}

#[test]
fn ring_statements_vector() {
    let committed: StatementVectors =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, compute_vectors());
    let transfer: Vec<usize> = committed
        .transfer
        .iter()
        .map(|case| case.elements.len())
        .collect();
    assert!(transfer.iter().all(|len| *len == 42 + ANONYMOUS_PARTIES));
}

#[test]
#[ignore = "rewrites test-vectors/proof/ring-statements.json"]
fn write_ring_statements_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}

#[test]
fn the_ciphertext_digest_tags_the_length_over_the_left_packed_chain() {
    let ciphertext: Vec<u8> = (1..=40).collect();
    let mut first = [0u8; 32];
    first[1..].copy_from_slice(&ciphertext[..31]);
    let mut second = [0u8; 32];
    second[1..10].copy_from_slice(&ciphertext[31..]);
    let chain = create_hash_chain_4_from_slice(&[first, second]).unwrap();
    assert_eq!(
        ciphertext_digest(&ciphertext).unwrap(),
        Poseidon::hashv(&[&right_align(&40u32.to_be_bytes()), &chain]).unwrap()
    );
    // Trailing zeros pack to the same chain, the length tag alone tells the two apart.
    let padded = [&ciphertext[..], &[0]].concat();
    assert_ne!(
        ciphertext_digest(&padded).unwrap(),
        ciphertext_digest(&ciphertext).unwrap()
    );
}

#[test]
fn the_region_chains_hash_each_published_slot() {
    let values = Values::new();
    let outputs = values.outputs(4, true);
    let records: Vec<[u8; 32]> = (0..4)
        .map(|slot| hash_bytes(&values.records[slot]).unwrap())
        .collect();
    let tails: Vec<[u8; 32]> = (0..4)
        .map(|slot| hash_bytes(&values.tails[slot]).unwrap())
        .collect();
    assert_eq!(
        record_chain(&outputs, 4).unwrap(),
        create_hash_chain_4_from_slice(&records).unwrap()
    );
    assert_eq!(
        tail_chain(&outputs, 4).unwrap(),
        create_hash_chain_4_from_slice(&tails).unwrap()
    );
    // An omitted slot reads zero at the key's width.
    let mut filled = records.clone();
    filled[3] = [0; 32];
    assert_eq!(
        record_chain(&outputs[..3], 4).unwrap(),
        create_hash_chain_4_from_slice(&filled).unwrap()
    );
    // A clear has_data binds zero, no chain of zeros.
    assert_eq!(tail_chain(&values.outputs(4, false), 4).unwrap(), [0; 32]);
}

/// Repeats collapse in run order, only the run's owners count, a reorder moves the chain.
#[test]
fn the_signer_set_dedups_by_first_occurrence_and_fills_to_the_slots() {
    let (first, second) = ([0x41; 32], [0x42; 32]);
    let identity = |key| solana_owner_identity(key).unwrap();
    let set = SignerSet::new([first, second, first].iter(), 4).unwrap();
    assert_eq!(set.count, 2);
    assert_eq!(
        set.chain,
        create_hash_chain_4_from_slice(&[identity(&first), identity(&second), [0; 32], [0; 32]])
            .unwrap()
    );
    assert_ne!(
        set.chain,
        SignerSet::new([second, first].iter(), 4).unwrap().chain
    );
    assert_eq!(
        SignerSet::new([first, second].iter(), 1),
        Err(CustomRingError::OwnerSignerCount)
    );
    assert_eq!(
        SignerSet::new([first, first].iter(), 1).unwrap().count,
        1,
        "a repeat takes one slot"
    );
    for slots in [0, 2, 16] {
        assert_eq!(
            SignerSet::new(core::iter::empty(), slots),
            Ok(SignerSet::default())
        );
    }
    assert_eq!(SignerSet::default().chain, [0; 32]);
}

/// One statement of each family at every keyed output count, no element follows the capacity.
#[test]
fn the_element_count_follows_the_family_alone() {
    let values = Values::new();
    let zero = [0u8; 32];
    let slots = [zero; 3];
    let parties = [zero; ANONYMOUS_PARTIES];
    let roots = TransferRoots::default();
    let outputs = values.outputs(8, false);
    let key = AuditKey {
        format: custom_ring_interface::DisclosureFormat::Standard,
        class: 16,
        entry: false,
    };
    // Head, rail bits, mask, totals digest, signer data counts, no_spend, m, three chains, n, nullifier chain, private_tx_hash, sender, parties, signer count and chain, four roots, nine public cells, withdrawals and length.
    let cells = AUDIT_HEAD_ELEMENTS + 3 + 4 + 4 + 3 + 1 + ANONYMOUS_PARTIES + 2 + 4 + 9 + 1 + 1;
    for capacity in [2usize, 4, 8] {
        for published in [1, capacity] {
            let statement = TransferStatement {
                head: values.head(
                    AuditLayout::default(),
                    stream(key, 1, &outputs[..published]),
                ),
                family: TransferFamily::Confidential {
                    sender: ConfidentialSender::Signer,
                },
                approval_mask: ApprovalMask::default(),
                approval_totals: &[0; 32],
                signer_data_counts: SignerDataCounts::default(),
                no_spend: false,
                outputs: &outputs[..published],
                output_capacity: capacity,
                input_count: 1,
                input_nullifier_chain: values.fields[4],
                private_tx_hash: &zero,
                signers: SignerSet::default(),
                roots: &roots,
                public_assets: &slots,
                public_amounts: &slots,
                public_gross: &slots,
                withdrawal_hash: &zero,
            };
            let expected = cells;
            assert_eq!(statement.element_count(), expected);
            let elements = statement.elements().unwrap();
            assert_eq!(elements.len(), expected);
            assert_eq!(
                elements[AUDIT_HEAD_ELEMENTS + 7],
                right_aligned(published as u64)
            );
            assert_eq!(elements[elements.len() - 1], right_aligned(expected as u64));
            let anonymous = TransferStatement {
                family: TransferFamily::Anonymous {
                    party_identities: &parties,
                    public_owners: false,
                    delegate: false,
                },
                ..statement
            };
            assert_eq!(anonymous.element_count(), expected);
            let elements = anonymous.elements().unwrap();
            assert_eq!(elements.len(), expected);
            assert_eq!(elements[elements.len() - 1], right_aligned(expected as u64));
        }
    }
}

#[test]
fn the_anonymous_transfer_statement_follows_the_contract_order() {
    let values = Values::new();
    let outputs = values.outputs(4, false);
    let mut parties = [[0u8; 32]; ANONYMOUS_PARTIES];
    for (slot, party) in parties.iter_mut().enumerate() {
        *party = field(70 + slot as u8);
    }
    let key = AuditKey {
        format: custom_ring_interface::DisclosureFormat::Standard,
        class: 16,
        entry: false,
    };
    let zero = [0u8; 32];
    let slots = [zero; 3];
    let signers = SignerSet::new([[0x44; 32]].iter(), 16).unwrap();
    let roots = TransferRoots {
        policy_hash: values.fields[6],
        own_root: values.fields[7],
        curator_root: zero,
        tracking_root: values.fields[9],
    };
    let statement = TransferStatement {
        head: values.head(AuditLayout::default(), stream(key, 3, &outputs)),
        family: TransferFamily::Anonymous {
            party_identities: &parties,
            public_owners: true,
            delegate: false,
        },
        approval_mask: ApprovalMask::WITHDRAWAL,
        approval_totals: &[0; 32],
        signer_data_counts: SignerDataCounts::default(),
        no_spend: true,
        outputs: &outputs,
        output_capacity: 4,
        input_count: 3,
        input_nullifier_chain: values.fields[5],
        private_tx_hash: &values.fields[3],
        signers,
        roots: &roots,
        public_assets: &slots,
        public_amounts: &slots,
        public_gross: &slots,
        withdrawal_hash: &values.fields[8],
    };
    let elements = statement.elements().unwrap();
    assert_eq!(
        elements[7],
        ciphertext_digest(statement.head.envelope).unwrap()
    );
    let hashes: Vec<[u8; 32]> = outputs.iter().map(|output| *output.hash).collect();
    let mut tail = vec![
        right_aligned(0),
        right_aligned(0),
        right_aligned(0),
        right_aligned(2),
        zero,
        zero,
        right_aligned(1),
        right_aligned(4),
        create_hash_chain_4_from_slice(&hashes).unwrap(),
        record_chain(&outputs, 4).unwrap(),
        zero,
        right_aligned(3),
        values.fields[5],
        values.fields[3],
        zero,
    ];
    tail.extend(parties);
    tail.extend([
        right_aligned(1),
        signers.chain,
        values.fields[6],
        values.fields[7],
        zero,
        values.fields[9],
    ]);
    tail.extend([zero; 9]);
    tail.extend([
        values.fields[8],
        right_aligned((AUDIT_HEAD_ELEMENTS + tail.len() + 2) as u64),
    ]);
    assert_eq!(elements.len(), AUDIT_HEAD_ELEMENTS + tail.len());
    assert_eq!(elements[AUDIT_HEAD_ELEMENTS..], tail);
}

/// A body, a tag and a slot's class leave the statement, the SPP external data hash binds their bytes.
#[test]
fn delivery_bytes_stay_outside_the_statement() {
    let values = Values::new();
    let outputs = values.outputs(4, false);
    let parties = [[0u8; 32]; ANONYMOUS_PARTIES];
    let zero = [0u8; 32];
    let slots = [zero; 3];
    let roots = TransferRoots::default();
    let statement = TransferStatement {
        head: values.head(
            AuditLayout::default(),
            stream(
                AuditKey {
                    format: custom_ring_interface::DisclosureFormat::Standard,
                    class: 16,
                    entry: false,
                },
                3,
                &outputs,
            ),
        ),
        family: TransferFamily::Anonymous {
            party_identities: &parties,
            public_owners: false,
            delegate: false,
        },
        approval_mask: ApprovalMask::default(),
        approval_totals: &[0; 32],
        signer_data_counts: SignerDataCounts::default(),
        no_spend: false,
        outputs: &outputs,
        output_capacity: 4,
        input_count: 3,
        input_nullifier_chain: values.fields[5],
        private_tx_hash: &zero,
        signers: SignerSet::default(),
        roots: &roots,
        public_assets: &slots,
        public_amounts: &slots,
        public_gross: &slots,
        withdrawal_hash: &zero,
    };
    let body = [7u8; RECIPIENT_BODY_LEN];
    let mut rewritten = outputs.clone();
    rewritten[1].owner_tag = custom_ring_interface::stream::slot_tag(values.keys[9]);
    rewritten[1].body = SlotBody::Recipient(&body);
    rewritten[2].body = SlotBody::Exit(&body);
    let moved = TransferStatement {
        outputs: &rewritten,
        ..statement
    };
    assert_eq!(moved.hash().unwrap(), statement.hash().unwrap());
    // A record does reach it.
    let mut record = outputs.clone();
    record[1].record = &values.records[7];
    let moved = TransferStatement {
        outputs: &record,
        ..statement
    };
    assert_ne!(moved.hash().unwrap(), statement.hash().unwrap());
}

/// The policy circuit matches a limit row against the asset fields of the public slots.
#[test]
fn an_outflow_limit_carries_the_public_asset_field_of_its_mint() {
    let mint = [9u8; 32];
    let legs = [
        PublicLeg {
            transfer: InterfaceTransfer::SplWithdrawal {
                amount: 5,
                spl_interface_bump: 255,
            },
            mint: Some(mint),
        },
        PublicLeg {
            transfer: InterfaceTransfer::SolWithdrawal { amount: 7 },
            mint: None,
        },
    ];
    let fields = PublicSlots::fold(legs.map(Ok::<_, PublicSlotError>))
        .unwrap()
        .asset_fields()
        .unwrap();
    for (asset, field) in [mint, SOL_ASSET_ADDRESS].into_iter().zip(fields) {
        let limit = OutflowLimit::of(&Member::asset(&Address::new_from_array(asset)).unwrap());
        assert_eq!(*limit.asset(), field);
        assert_ne!(*limit.asset(), asset);
    }
}
