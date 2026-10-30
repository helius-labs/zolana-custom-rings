//! Pins `test-vectors/proof/ring-statements.json` for the Go circuits and the TS SDK.

use custom_ring_interface::{
    AnonymousAudit, AnonymousAuditKey, AnonymousLayout, ApplyRecordsStatement, AuditHead,
    AuditKind, AuditLayout, AuditStatement, DeliveredLayout, DeliveredSender, DepositContext,
    DepositPublicInput, DepositRegistry, DepositedAsset, DisclosureLayout, PolicyKey,
    PolicyStatement, RegisterKeyStatement, RingOutput, ANONYMOUS_SLOT_BYTES, AUDIT_HEAD_ELEMENTS,
    DEPOSIT_PUBLIC_INPUT_ELEMENTS,
};
use custom_ring_interface::{PublicLeg, PublicSlotError, PublicSlots, SOL_ASSET_ADDRESS};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_hasher::{
    hash_chain::create_hash_chain_4_from_slice,
    primitives::{hash_bytes, solana_owner_identity},
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
    audit: Vec<AuditCase>,
    policy: Vec<PolicyCase>,
    apply_records: ApplyCase,
    register_key: RegisterKeyCase,
    deposit: DepositCase,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct AuditCase {
    /// `delivered`, `delivered_sender` or `anonymous`.
    kind: String,
    first_nullifier: String,
    ring_id: String,
    tx_viewing_u: String,
    auditor_pubkey: String,
    eph_u: String,
    sealed: String,
    salt: String,
    /// `exits | key_escrow << 1 | full_openings << 3`.
    layout: u8,
    outputs: Vec<OutputCase>,
    disclosure: Vec<String>,
    private_tx_hash: Option<String>,
    sender: Option<String>,
    sender_commitment: Option<String>,
    party_identities: Option<Vec<String>>,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct OutputCase {
    /// `delivered`, `anonymous` or `exit`.
    kind: String,
    hash: String,
    u: Option<String>,
    body: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct PolicyCase {
    withdrawal_hash: String,
    /// `member` or `delegate`.
    key: String,
    anonymous: Option<bool>,
    private_tx_hash: String,
    policy_hash: String,
    ring_id: String,
    approval_required: bool,
    key_escrow: bool,
    own_root: String,
    curator_root: String,
    sender: String,
    recipients: Vec<String>,
    public_assets: Vec<String>,
    public_amounts: Vec<String>,
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
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct RegisterKeyCase {
    member: String,
    nullifier_pk: String,
    auditor_pubkey: String,
    eph_u: String,
    ciphertext: String,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct DepositCase {
    program_id: String,
    tree: String,
    spp_data: String,
    context_hash: String,
    anonymous: bool,
    owner_utxo_hashes: Vec<String>,
    ciphertexts: Vec<String>,
    auditor_pubkey: String,
    eph_pk: String,
    assets: Vec<String>,
    amounts: Vec<u64>,
    key_escrow: bool,
    member_registry_root: Option<String>,
    curator_root: Option<String>,
    policy_hash: Option<String>,
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
    bodies: [[u8; 40]; 8],
    tags: [[u8; 32]; 8],
    auditor_pubkey: [u8; 33],
    ring_id: [u8; 32],
    salt: [u8; 16],
}

impl Values {
    fn new() -> Self {
        Self {
            fields: (0..80).map(field).collect(),
            keys: (0..16).map(|seed| [0x60 + seed; 32]).collect(),
            bodies: core::array::from_fn(|slot| [0x90 + slot as u8; 40]),
            tags: core::array::from_fn(|slot| [0xb0 + slot as u8; 32]),
            auditor_pubkey: tagged(0xa1),
            ring_id: hash_bytes(&[0x77; 32]).unwrap(),
            salt: [0x5c; 16],
        }
    }

    fn disclosure(&self, layout: DisclosureLayout) -> &[[u8; 32]] {
        &self.fields[40..40 + layout.field_count()]
    }

    fn head(&self, layout: AuditLayout) -> AuditHead<'_> {
        AuditHead {
            first_nullifier: &self.fields[1],
            ring_id: &self.ring_id,
            tx_viewing_u: &self.keys[0],
            auditor_pubkey: &self.auditor_pubkey,
            eph_u: &self.keys[1],
            sealed: &self.keys[2],
            salt: &self.salt,
            layout,
        }
    }

    fn exit(&self, slot: usize) -> RingOutput<'_> {
        RingOutput::Exit {
            hash: &self.fields[20 + slot],
            owner_tag: &self.keys[8],
            payload: &[],
        }
    }

    fn delivered_outputs(&self, outputs: usize, exits: &[usize]) -> Vec<RingOutput<'_>> {
        (0..outputs)
            .map(|slot| match exits.contains(&slot) {
                true => self.exit(slot),
                false => RingOutput::Delivered {
                    hash: &self.fields[20 + slot],
                    u: &self.keys[4 + slot % 4],
                    body: &self.bodies[slot],
                },
            })
            .collect()
    }

    fn anonymous_outputs(&self) -> Vec<RingOutput<'_>> {
        (0..4)
            .map(|slot| match slot {
                3 => self.exit(slot),
                _ => self.anonymous(slot, self.anonymous_body(slot)),
            })
            .collect()
    }

    fn anonymous<'a>(&'a self, slot: usize, body: Option<&'a [u8]>) -> RingOutput<'a> {
        RingOutput::Anonymous {
            hash: &self.fields[20 + slot],
            tag: &self.tags[slot],
            body,
        }
    }

    fn anonymous_body(&self, slot: usize) -> Option<&[u8]> {
        (slot != 1).then_some(&self.bodies[slot][..])
    }
}

fn audit_case(statement: &AuditStatement<'_>) -> AuditCase {
    let head = statement.head;
    let (anonymous, sender) = match statement.kind {
        AuditKind::Anonymous(anonymous) => (Some(anonymous), None),
        AuditKind::Delivered(sender) => (None, sender),
    };
    let kind = match statement.kind {
        AuditKind::Delivered(None) => "delivered",
        AuditKind::Delivered(Some(_)) => "delivered_sender",
        AuditKind::Anonymous(_) => "anonymous",
    };
    AuditCase {
        kind: kind.to_string(),
        first_nullifier: hex::encode(head.first_nullifier),
        ring_id: hex::encode(head.ring_id),
        tx_viewing_u: hex::encode(head.tx_viewing_u),
        auditor_pubkey: hex::encode(head.auditor_pubkey),
        eph_u: hex::encode(head.eph_u),
        sealed: hex::encode(head.sealed),
        salt: hex::encode(head.salt),
        layout: head.layout.value(),
        outputs: statement.outputs.iter().map(output_case).collect(),
        disclosure: hexes(statement.disclosure),
        private_tx_hash: anonymous
            .map(|anonymous| anonymous.private_tx_hash)
            .or(sender.map(|sender| sender.private_tx_hash))
            .map(hex::encode),
        sender: sender.map(|sender| hex::encode(sender.sender)),
        sender_commitment: anonymous.map(|anonymous| hex::encode(anonymous.sender_commitment)),
        party_identities: anonymous.map(|anonymous| hexes(anonymous.party_identities)),
        elements: hexes(&statement.elements().unwrap()),
        public_input_hash: hex::encode(statement.hash().unwrap()),
    }
}

fn output_case(output: &RingOutput<'_>) -> OutputCase {
    let (kind, u, body) = match output {
        RingOutput::Delivered { u, body, .. } => ("delivered", Some(*u), Some(*body)),
        RingOutput::Anonymous { .. } => ("anonymous", None, None),
        RingOutput::Exit { .. } => ("exit", None, None),
    };
    OutputCase {
        kind: kind.to_string(),
        hash: hex::encode(output.hash()),
        u: u.map(hex::encode),
        body: body.map(hex::encode),
    }
}

fn policy_case(statement: &PolicyStatement<'_>) -> PolicyCase {
    let (key, anonymous) = match statement.key {
        PolicyKey::Member { anonymous } => ("member", Some(anonymous)),
        PolicyKey::Delegate => ("delegate", None),
    };
    PolicyCase {
        withdrawal_hash: hex::encode(statement.withdrawal_hash),
        key: key.to_string(),
        anonymous,
        private_tx_hash: hex::encode(statement.private_tx_hash),
        policy_hash: hex::encode(statement.policy_hash),
        ring_id: hex::encode(statement.ring_id),
        approval_required: statement.approval_required,
        key_escrow: statement.key_escrow,
        own_root: hex::encode(statement.own_root),
        curator_root: hex::encode(statement.curator_root),
        sender: hex::encode(statement.sender),
        recipients: hexes(statement.recipients),
        public_assets: hexes(statement.public_assets),
        public_amounts: hexes(statement.public_amounts),
        elements: hexes(&statement.elements()),
        public_input_hash: hex::encode(statement.hash().unwrap()),
    }
}

fn compute_vectors() -> StatementVectors {
    let values = Values::new();
    let (escrowed, delivered, anonymous) = (
        values.delivered_outputs(2, &[1]),
        values.delivered_outputs(8, &[2, 5]),
        values.anonymous_outputs(),
    );
    let anonymous_tail = AuditKind::Anonymous(AnonymousAudit {
        party_identities: &[right_aligned(11), right_aligned(12), [0; 32]],
        private_tx_hash: &values.fields[3],
        sender_commitment: &values.fields[5],
    });
    let commitment = AnonymousLayout {
        key: AnonymousAuditKey::Commitment { class: 4 },
        inputs: 3,
        outputs: 4,
        exits: true,
    };
    let audit = [
        AuditStatement {
            head: values.head(AuditLayout {
                exits: true,
                key_escrow: true,
                full_openings: false,
            }),
            outputs: &escrowed,
            disclosure: values.disclosure(DisclosureLayout::Delivered(DeliveredLayout {
                outputs: 2,
                exits: true,
                key_escrow: true,
                sender_class: None,
            })),
            kind: AuditKind::Delivered(None),
        },
        AuditStatement {
            head: values.head(AuditLayout {
                exits: true,
                ..AuditLayout::default()
            }),
            outputs: &delivered,
            disclosure: values.disclosure(DisclosureLayout::Delivered(DeliveredLayout {
                outputs: 8,
                exits: true,
                key_escrow: false,
                sender_class: None,
            })),
            kind: AuditKind::Delivered(None),
        },
        AuditStatement {
            head: values.head(AuditLayout {
                exits: true,
                ..AuditLayout::default()
            }),
            outputs: &delivered,
            disclosure: values.disclosure(DisclosureLayout::Delivered(DeliveredLayout {
                outputs: 8,
                exits: true,
                key_escrow: false,
                sender_class: Some(16),
            })),
            kind: AuditKind::Delivered(Some(DeliveredSender {
                private_tx_hash: &values.fields[3],
                sender: solana_owner_identity(&[0x42; 32]).unwrap(),
            })),
        },
        AuditStatement {
            head: values.head(AuditLayout {
                exits: true,
                ..AuditLayout::default()
            }),
            outputs: &anonymous,
            disclosure: values.disclosure(DisclosureLayout::Anonymous(commitment)),
            kind: anonymous_tail,
        },
        AuditStatement {
            head: values.head(AuditLayout {
                exits: true,
                full_openings: true,
                ..AuditLayout::default()
            }),
            outputs: &anonymous,
            disclosure: values.disclosure(DisclosureLayout::Anonymous(AnonymousLayout {
                key: AnonymousAuditKey::Entry,
                ..commitment
            })),
            kind: anonymous_tail,
        },
    ];
    let assets = [values.fields[60], values.fields[61], [0; 32]];
    let mut withdrawal = [0u8; 32];
    hex::decode_to_slice(WITHDRAWAL_1200, &mut withdrawal).unwrap();
    let amounts = [right_aligned(500), withdrawal, [0; 32]];
    let owner_signer = solana_owner_identity(&[0x42; 32]).unwrap();
    let zero = [0u8; 32];
    let recipients = [values.fields[62], zero];
    let confidential = PolicyStatement {
        withdrawal_hash: &custom_ring_interface::policy_withdrawal_hash(&[]).unwrap(),
        key: PolicyKey::Member { anonymous: false },
        private_tx_hash: &values.fields[3],
        policy_hash: &values.fields[6],
        ring_id: &values.ring_id,
        approval_required: true,
        key_escrow: false,
        own_root: &values.fields[7],
        curator_root: &values.fields[8],
        sender: &owner_signer,
        recipients: &recipients,
        public_assets: &assets,
        public_amounts: &amounts,
    };
    let anonymous_policy = PolicyStatement {
        key: PolicyKey::Member { anonymous: true },
        approval_required: false,
        sender: &values.fields[5],
        recipients: &[zero; 2],
        ..confidential
    };
    let delegate = PolicyStatement {
        key: PolicyKey::Delegate,
        approval_required: false,
        key_escrow: true,
        curator_root: &zero,
        sender: &zero,
        recipients: &[values.fields[62], values.fields[63]],
        ..confidential
    };
    let apply = ApplyRecordsStatement {
        old_root: values.fields[9],
        new_root: values.fields[10],
        old_next_index: 5,
        new_next_index: 17,
        chain_start: values.fields[11],
        chain_end: values.fields[12],
        count: 16,
    };
    let register = RegisterKeyStatement {
        member: &owner_signer,
        nullifier_pk: &values.fields[13],
        auditor_pubkey: &values.auditor_pubkey,
        eph_u: &values.keys[9],
        ciphertext: &values.keys[10],
    };
    let program_id = [0x77; 32];
    let tree = [0x55; 32];
    let spp_data: Vec<u8> = (0..75u8).map(|byte| byte ^ 0x3c).collect();
    let context_hash = DepositContext {
        program_id: &program_id,
        tree: &tree,
        spp_data: &spp_data,
    }
    .hash()
    .unwrap();
    let owners = [values.fields[14], values.fields[15]];
    let ciphertexts = [[0x21; 96], [0x22; 96]];
    let eph_pk = tagged(0xa2);
    let deposited = [
        DepositedAsset {
            asset: values.fields[17],
            amount: 1_000,
        },
        DepositedAsset {
            asset: values.fields[18],
            amount: 2_000,
        },
    ];
    let deposit = DepositPublicInput {
        context_hash: &context_hash,
        anonymous: false,
        owner_utxo_hashes: &owners,
        ciphertexts: &ciphertexts,
        assets: &deposited,
        auditor_pk: &values.auditor_pubkey,
        eph_pk: &eph_pk,
        registry: Some(DepositRegistry {
            own_root: &values.fields[16],
            curator_root: Some(&values.fields[20]),
            key_escrow: true,
            policy_hash: Some(&values.fields[19]),
        }),
    };
    StatementVectors {
        description: "Every ring statement and its public input HashChain4(elements). Audit \
                      heads are [CRAU, n0, ring_id, pack_be(0x04 || tx_u), \
                      pack_be(auditor_pubkey), pack_be(0x04 || eph_u), hash_bytes(sealed), \
                      salt, layout] with the frame's random salt and layout = exits | key_escrow << 1 \
                      | full_openings << 3, the tails chain the published output \
                      hashes, then on the delivered rail the body hashes (zero for an exit), the \
                      disclosure fields and pack_be(u) per delivered slot, then on the in-proof \
                      owner rail private_tx_hash and the sender identity, on the anonymous rail \
                      the disclosure fields, private_tx_hash, the sender commitment and the three \
                      party identities, no tag or body of an anonymous slot. Each disclosure holds the field count of its layout, delivered with 2 \
                      escrowed outputs and with 8, anonymous of commitment class 4 and of the entry \
                      key with 3 inputs and 4 outputs. The deposit statement is HashChain(elements) \
                      over CRDP, the context hash of the program id, tree and SPP data, the \
                      count, the anonymous flag, each owner hash with its capsule ciphertext hash \
                      zero padded to 8 slots, both tagged keys packed, the escrow flag, the \
                      registry root, the curator root, the policy hash and each asset hash with its amount zero \
                      padded to 8 slots. Produced by program-libs/interface/tests/statements.rs."
            .to_string(),
        audit: audit.iter().map(audit_case).collect(),
        policy: [confidential, anonymous_policy, delegate]
            .iter()
            .map(policy_case)
            .collect(),
        apply_records: ApplyCase {
            old_root: hex::encode(apply.old_root),
            new_root: hex::encode(apply.new_root),
            old_next_index: apply.old_next_index,
            new_next_index: apply.new_next_index,
            chain_start: hex::encode(apply.chain_start),
            chain_end: hex::encode(apply.chain_end),
            count: apply.count,
            elements: hexes(&apply.elements()),
            public_input_hash: hex::encode(apply.hash().unwrap()),
        },
        register_key: RegisterKeyCase {
            member: hex::encode(register.member),
            nullifier_pk: hex::encode(register.nullifier_pk),
            auditor_pubkey: hex::encode(register.auditor_pubkey),
            eph_u: hex::encode(register.eph_u),
            ciphertext: hex::encode(register.ciphertext),
            elements: hexes(&register.elements().unwrap()),
            public_input_hash: hex::encode(register.hash().unwrap()),
        },
        deposit: DepositCase {
            program_id: hex::encode(program_id),
            tree: hex::encode(tree),
            spp_data: hex::encode(&spp_data),
            context_hash: hex::encode(context_hash),
            anonymous: deposit.anonymous,
            owner_utxo_hashes: hexes(&owners),
            ciphertexts: ciphertexts.iter().map(hex::encode).collect(),
            auditor_pubkey: hex::encode(deposit.auditor_pk),
            eph_pk: hex::encode(deposit.eph_pk),
            assets: deposited.iter().map(|value| hex::encode(value.asset)).collect(),
            amounts: deposited.iter().map(|value| value.amount).collect(),
            key_escrow: deposit.registry.is_some_and(|registry| registry.key_escrow),
            member_registry_root: deposit
                .registry
                .map(|registry| hex::encode(registry.own_root)),
            curator_root: deposit
                .registry
                .and_then(|registry| registry.curator_root)
                .map(hex::encode),
            policy_hash: deposit
                .registry
                .and_then(|registry| registry.policy_hash)
                .map(hex::encode),
            elements: hexes(&deposit.elements().unwrap()),
            public_input_hash: hex::encode(deposit.hash().unwrap()),
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
    let lengths: Vec<usize> = committed
        .audit
        .iter()
        .map(|case| case.elements.len())
        .collect();
    assert_eq!(lengths, [16, 16, 18, 19, 19]);
    let policy: Vec<usize> = committed
        .policy
        .iter()
        .map(|case| case.elements.len())
        .collect();
    assert_eq!(policy, [20, 20, 19]);
    assert_eq!(
        committed.deposit.elements.len(),
        DEPOSIT_PUBLIC_INPUT_ELEMENTS
    );
}

#[test]
#[ignore = "rewrites test-vectors/proof/ring-statements.json"]
fn write_ring_statements_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}

#[test]
fn anonymous_and_exit_slots_contribute_no_body_hash_or_recipient_key() {
    let values = Values::new();
    for output in values.anonymous_outputs() {
        assert_eq!(output.body_hash(), Ok([0; 32]));
        assert_eq!(output.recipient_key_fields(), [[0; 32]; 2]);
    }
}

#[test]
fn the_anonymous_statement_chains_outputs_disclosure_private_tx_sender_and_parties() {
    let values = Values::new();
    let outputs = values.anonymous_outputs();
    let parties = [field(70), field(71), field(72)];
    let layout = DisclosureLayout::Anonymous(AnonymousLayout {
        key: AnonymousAuditKey::Commitment { class: 4 },
        inputs: 3,
        outputs: 4,
        exits: true,
    });
    let statement = AuditStatement {
        head: values.head(AuditLayout {
            exits: true,
            ..AuditLayout::default()
        }),
        outputs: &outputs,
        disclosure: values.disclosure(layout),
        kind: AuditKind::Anonymous(AnonymousAudit {
            party_identities: &parties,
            private_tx_hash: &values.fields[3],
            sender_commitment: &values.fields[5],
        }),
    };
    let elements = statement.elements().unwrap();
    let hashes: Vec<[u8; 32]> = outputs.iter().map(|output| *output.hash()).collect();
    let tail = [
        create_hash_chain_4_from_slice(&hashes).unwrap(),
        create_hash_chain_4_from_slice(values.disclosure(layout)).unwrap(),
        values.fields[3],
        values.fields[5],
        parties[0],
        parties[1],
        parties[2],
    ];
    assert_eq!(elements.len(), AUDIT_HEAD_ELEMENTS + tail.len());
    assert_eq!(elements[AUDIT_HEAD_ELEMENTS..], tail);
}

/// The audit proof binds no tag or body, a wallet picks both freely.
#[test]
fn an_anonymous_statement_ignores_every_tag_and_body() {
    let values = Values::new();
    let other_tag = [0xff; 32];
    let statement_hash = |outputs: &[RingOutput<'_>]| {
        AuditStatement {
            head: values.head(AuditLayout::default()),
            outputs,
            disclosure: &[],
            kind: AuditKind::Anonymous(AnonymousAudit {
                party_identities: &[[0; 32]; 3],
                private_tx_hash: &values.fields[3],
                sender_commitment: &values.fields[5],
            }),
        }
        .hash()
        .unwrap()
    };
    let published = values.anonymous_outputs();
    let mut rewritten = published.clone();
    rewritten[0] = RingOutput::Anonymous {
        hash: published[0].hash(),
        tag: &other_tag,
        body: Some(&values.bodies[6]),
    };
    rewritten[2] = values.anonymous(2, None);
    assert_eq!(statement_hash(&published), statement_hash(&rewritten));
}

/// Counted by hand from 72-byte slots packed 31 bytes to a field.
#[test]
fn anonymous_disclosures_take_seventy_two_bytes_per_output_slot() {
    let layout = |key, inputs, outputs, exits| {
        DisclosureLayout::Anonymous(AnonymousLayout {
            key,
            inputs,
            outputs,
            exits,
        })
    };
    let commitment = AnonymousAuditKey::Commitment { class: 4 };
    assert_eq!(ANONYMOUS_SLOT_BYTES, 72);
    for (layout, fields) in [
        (layout(commitment, 2, 2, false), 2 + 5 + 1 + 1),
        (layout(commitment, 3, 4, true), 1 + 4 + 10 + 1 + 1),
        (layout(commitment, 2, 8, false), 8 + 19 + 1 + 1),
        (
            layout(AnonymousAuditKey::Entry, 3, 4, true),
            1 + 1 + 4 + 11 + 3 + 6,
        ),
    ] {
        assert_eq!(layout.field_count(), fields, "{layout:?}");
    }
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
