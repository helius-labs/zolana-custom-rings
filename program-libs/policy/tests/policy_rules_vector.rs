//! Pins `test-vectors/policy/ring-policy-rules.json` for the policy circuit and the TS SDK.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use spr_hasher::primitives::right_align;
use zolana_ring_policy::{
    registry_field, DebitInput, ListId, ListSet, OutputSubjects, PolicySource, RecordLists, Rule,
    RuleRefusal, RuleTable, RuleTableBuilder, SourceMap, Subject, TableParts, TransferSubject,
    TransferSubjects,
};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/policy/ring-policy-rules.json"
);

const ALLOW: u64 = ListId::Allow.record_bit();
const BLOCK: u64 = ListId::Block.record_bit();
const FROZEN: u64 = ListId::Frozen.record_bit();
const APPROVAL: u64 = ListId::Approval.record_bit();

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct PolicyRulesVectors {
    description: String,
    cases: Vec<Case>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Case {
    name: String,
    sources: Vec<Source>,
    rules: Vec<String>,
    inline_assets: Vec<String>,
    inline_limits: Vec<u64>,
    own_records: Vec<Record>,
    curator_records: Vec<Record>,
    sender: String,
    ring_inputs: Vec<RingInput>,
    outputs: Vec<Output>,
    outcome: Outcome,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Source {
    list_id: u8,
    registry: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Record {
    member: String,
    lists: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct RingInput {
    owner: String,
    asset: String,
    amount: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Output {
    ring: bool,
    owner: String,
    asset: String,
    amount: u64,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Outcome {
    Pass,
    Lists {
        rule: usize,
        subject: SubjectKind,
        output: Option<usize>,
    },
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum SubjectKind {
    Sender,
    Owner,
    Asset,
}

impl Outcome {
    fn of(result: Result<(), RuleRefusal>) -> Self {
        match result {
            Ok(()) => Self::Pass,
            Err(RuleRefusal::Lists { rule, subject }) => Self::lists(rule, subject),
        }
    }

    const fn lists(rule: usize, subject: TransferSubject) -> Self {
        match subject {
            TransferSubject::InputAsset(_) => panic!("admit reads no input asset"),
            TransferSubject::Sender => Self::Lists {
                rule,
                subject: SubjectKind::Sender,
                output: None,
            },
            TransferSubject::Owner(output) => Self::Lists {
                rule,
                subject: SubjectKind::Owner,
                output: Some(output),
            },
            TransferSubject::Asset(output) => Self::Lists {
                rule,
                subject: SubjectKind::Asset,
                output: Some(output),
            },
        }
    }
}

fn field(byte: u8) -> [u8; 32] {
    right_align(&[byte])
}

const ZERO_OWNER: [u8; 32] = [0; 32];

fn sender() -> [u8; 32] {
    field(0x51)
}

fn owner_a() -> [u8; 32] {
    field(0x11)
}

fn owner_b() -> [u8; 32] {
    field(0x12)
}

fn asset_x() -> [u8; 32] {
    field(0xa1)
}

fn asset_y() -> [u8; 32] {
    field(0xa2)
}

fn curator() -> [u8; 32] {
    registry_field(&[0x15; 32]).expect("registry field")
}

/// One transfer against one policy, the outcome derived from the circuit by hand.
struct Spec {
    name: &'static str,
    table: RuleTableBuilder,
    thresholds: Vec<([u8; 32], u64)>,
    /// Lists a curator registry serves, every other referenced list is the ring's own.
    curated: ListSet,
    own: Vec<([u8; 32], u64)>,
    curated_records: Vec<([u8; 32], u64)>,
    /// Same-ring inputs, a receipt nets only these.
    ring_inputs: Vec<([u8; 32], [u8; 32], u64)>,
    outputs: Vec<([u8; 32], [u8; 32], u64)>,
    /// Positions in `outputs` that leave the ring.
    exits: Vec<usize>,
    expected: Outcome,
}

impl Spec {
    fn case(self) -> Case {
        let table = self.table.build();
        let entries: Vec<(ListId, [u8; 32])> = table
            .referenced()
            .iter()
            .map(|list_id| {
                let registry = if self.curated.contains(list_id) {
                    curator()
                } else {
                    [0; 32]
                };
                (list_id, registry)
            })
            .collect();
        let sources = SourceMap::new(&entries).expect("positional sources");
        let own: BTreeMap<[u8; 32], u64> = self.own.iter().copied().collect();
        let curated: BTreeMap<[u8; 32], u64> = self.curated_records.iter().copied().collect();
        let outputs: Vec<Output> = self
            .outputs
            .iter()
            .enumerate()
            .map(|(position, (owner, asset, amount))| Output {
                ring: !self.exits.contains(&position),
                owner: hex::encode(owner),
                asset: hex::encode(asset),
                amount: *amount,
            })
            .collect();
        let case = Case {
            name: self.name.to_string(),
            sources: sources
                .slots()
                .iter()
                .map(|slot| Source {
                    list_id: slot.list_id,
                    registry: hex::encode(slot.registry),
                })
                .collect(),
            rules: table
                .rules()
                .iter()
                .map(|rule| hex::encode(rule.encoded()))
                .collect(),
            inline_assets: self
                .thresholds
                .iter()
                .map(|(asset, _)| hex::encode(asset))
                .collect(),
            inline_limits: self.thresholds.iter().map(|(_, limit)| *limit).collect(),
            own_records: records(&own),
            curator_records: records(&curated),
            sender: hex::encode(sender()),
            ring_inputs: self
                .ring_inputs
                .iter()
                .map(|(owner, asset, amount)| RingInput {
                    owner: hex::encode(owner),
                    asset: hex::encode(asset),
                    amount: *amount,
                })
                .collect(),
            outputs,
            outcome: self.expected,
        };
        assert_eq!(case.admit(), self.expected, "{}", self.name);
        case
    }
}

fn records(records: &BTreeMap<[u8; 32], u64>) -> Vec<Record> {
    records
        .iter()
        .map(|(member, lists)| Record {
            member: hex::encode(member),
            lists: *lists,
        })
        .collect()
}

impl Case {
    /// Reads every value from the case, as the Go circuit tests and the SDKs do.
    fn admit(&self) -> Outcome {
        let rows: Vec<[u8; 32]> = self.rules.iter().map(|row| bytes(row)).collect();
        let inline_assets: Vec<[u8; 32]> = self
            .inline_assets
            .iter()
            .map(|asset| bytes(asset))
            .collect();
        let table = TableParts { rows: &rows }
            .encode()
            .and_then(|encoded| encoded.decode())
            .expect("the rows decode");
        let slots: Vec<PolicySource> = self
            .sources
            .iter()
            .map(|source| PolicySource {
                list_id: source.list_id,
                registry: bytes(&source.registry),
            })
            .collect();
        let sources = SourceMap::from_slots(slots.try_into().expect("one source per slot"))
            .expect("positional sources");
        let lists_of = |member: &[u8; 32]| RecordLists {
            own: lookup(&self.own_records, member),
            curator: lookup(&self.curator_records, member),
            salted: 0,
        };
        let outputs: Vec<OutputSubjects> = self
            .outputs
            .iter()
            .map(|output| {
                let owner = bytes(&output.owner);
                let asset = bytes(&output.asset);
                OutputSubjects {
                    ring: output.ring,
                    owner,
                    asset,
                    amount: output.amount,
                    mint_policy: zolana_ring_policy::MintPolicy {
                        threshold: inline_assets
                            .iter()
                            .position(|mint| *mint == asset)
                            .map_or(0, |i| self.inline_limits[i]),
                        ..Default::default()
                    },
                    owner_lists: lists_of(&owner),
                    asset_lists: lists_of(&asset),
                }
            })
            .collect();
        let ring_inputs: Vec<DebitInput> = self
            .ring_inputs
            .iter()
            .map(|input| DebitInput {
                owner: bytes(&input.owner),
                asset: bytes(&input.asset),
                amount: input.amount,
            })
            .collect();
        let transfer = TransferSubjects {
            sender: lists_of(&bytes(&self.sender)),
            ring_inputs: &ring_inputs,
            outputs: &outputs,
        };
        Outcome::of(table.admit(&sources, &transfer))
    }
}

fn lookup(records: &[Record], member: &[u8; 32]) -> u64 {
    records
        .iter()
        .find(|record| bytes(&record.member) == *member)
        .map_or(0, |record| record.lists)
}

fn bytes(value: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(value, &mut out).expect("32-byte hex");
    out
}

fn specs() -> Vec<Spec> {
    let require = |subject, list_id| RuleTable::builder().rule(Rule::require(subject, list_id));
    let forbid = |subject, list_id| RuleTable::builder().rule(Rule::forbid(subject, list_id));
    let owner_allow = || require(Subject::OutputOwner, ListId::Allow);
    let both = vec![(owner_a(), asset_x(), 10), (owner_b(), asset_x(), 10)];
    vec![
        Spec {
            name: "an_empty_table_admits_any_transfer",
            table: RuleTable::builder(),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "a_sender_on_the_required_list_passes",
            table: require(Subject::Sender, ListId::Allow),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(sender(), ALLOW)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "an_absent_sender_misses_the_required_list",
            table: require(Subject::Sender, ListId::Allow),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(owner_a(), ALLOW)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Sender),
        },
        Spec {
            name: "a_sender_on_a_forbidden_list_is_refused",
            table: forbid(Subject::Sender, ListId::Block),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(sender(), BLOCK)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Sender),
        },
        Spec {
            name: "an_absent_rule_over_two_lists_admits_a_sender_on_one",
            table: RuleTable::builder().rule(Rule::forbid_only_on_all(
                Subject::Sender,
                ListSet::of(&[ListId::Block, ListId::Frozen]),
            )),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(sender(), FROZEN)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "an_absent_rule_over_two_lists_refuses_a_sender_on_both",
            table: RuleTable::builder().rule(Rule::forbid_only_on_all(
                Subject::Sender,
                ListSet::of(&[ListId::Block, ListId::Frozen]),
            )),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(sender(), BLOCK | FROZEN)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Sender),
        },
        Spec {
            name: "an_absent_rule_over_two_lists_admits_a_sender_off_both",
            table: RuleTable::builder().rule(Rule::forbid_only_on_all(
                Subject::Sender,
                ListSet::of(&[ListId::Block, ListId::Frozen]),
            )),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(sender(), ALLOW)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "an_owner_off_the_required_list_is_refused_at_its_output",
            table: owner_allow(),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(owner_a(), ALLOW)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Owner(1)),
        },
        Spec {
            name: "a_zero_owner_carries_no_owner_obligation",
            table: owner_allow(),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(owner_a(), ALLOW)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: vec![(owner_a(), asset_x(), 10), (ZERO_OWNER, asset_x(), 10)],
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "an_owner_off_every_alternative_list_passes",
            table: RuleTable::builder().rule(Rule::any_of(
                Subject::OutputOwner,
                ListSet::single(ListId::Allow),
                ListSet::single(ListId::Frozen),
            )),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(owner_a(), ALLOW)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "an_owner_on_the_alternative_list_and_off_the_primary_is_refused",
            table: RuleTable::builder().rule(Rule::any_of(
                Subject::OutputOwner,
                ListSet::single(ListId::Allow),
                ListSet::single(ListId::Frozen),
            )),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(owner_a(), ALLOW), (owner_b(), FROZEN)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Owner(1)),
        },
        Spec {
            name: "an_owner_on_one_of_two_alternative_lists_passes",
            table: RuleTable::builder().rule(Rule::any_of(
                Subject::OutputOwner,
                ListSet::single(ListId::Allow),
                ListSet::of(&[ListId::Block, ListId::Frozen]),
            )),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(owner_a(), ALLOW), (owner_b(), BLOCK)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "an_owner_on_both_alternative_lists_and_off_the_primary_is_refused",
            table: RuleTable::builder().rule(Rule::any_of(
                Subject::OutputOwner,
                ListSet::single(ListId::Allow),
                ListSet::of(&[ListId::Block, ListId::Frozen]),
            )),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(owner_a(), ALLOW), (owner_b(), BLOCK | FROZEN)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Owner(1)),
        },
        Spec {
            name: "an_owner_on_any_one_of_the_required_lists_passes",
            table: RuleTable::builder().rule(Rule::require_any(
                Subject::OutputOwner,
                ListSet::of(&[ListId::Allow, ListId::Approval]),
            )),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(owner_a(), ALLOW), (owner_b(), APPROVAL)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "an_asset_off_the_required_list_is_refused_at_its_output",
            table: require(Subject::Asset, ListId::Allow),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(asset_x(), ALLOW)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: vec![(owner_a(), asset_x(), 10), (owner_a(), asset_y(), 10)],
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Asset(1)),
        },
        Spec {
            name: "an_asset_rule_screens_a_zero_owner_output",
            table: forbid(Subject::Asset, ListId::Block),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(asset_y(), BLOCK)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: vec![(owner_a(), asset_x(), 10), (ZERO_OWNER, asset_y(), 10)],
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Asset(1)),
        },
        Spec {
            name: "a_curated_list_reads_the_curator_record_not_the_own_record",
            table: forbid(Subject::Sender, ListId::Block),
            thresholds: vec![],
            curated: ListSet::single(ListId::Block),
            own: vec![(sender(), BLOCK)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "a_curated_list_refuses_a_sender_the_curator_blocks",
            table: forbid(Subject::Sender, ListId::Block),
            thresholds: vec![],
            curated: ListSet::single(ListId::Block),
            own: vec![],
            curated_records: vec![(sender(), BLOCK)],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Sender),
        },
        Spec {
            name: "a_curated_asset_list_refuses_the_asset_the_curator_blocks",
            table: forbid(Subject::Asset, ListId::Block),
            thresholds: vec![],
            curated: ListSet::single(ListId::Block),
            own: vec![(asset_y(), BLOCK)],
            curated_records: vec![(asset_x(), BLOCK)],
            ring_inputs: vec![],
            outputs: vec![(owner_a(), asset_y(), 10), (owner_b(), asset_x(), 10)],
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Asset(1)),
        },
        Spec {
            name: "own_and_curated_lists_apply_side_by_side",
            table: owner_allow().rule(Rule::forbid(Subject::OutputOwner, ListId::Block)),
            thresholds: vec![],
            curated: ListSet::single(ListId::Block),
            own: vec![(owner_a(), ALLOW | BLOCK), (owner_b(), ALLOW)],
            curated_records: vec![(owner_b(), BLOCK)],
            ring_inputs: vec![],
            outputs: both.clone(),
            exits: vec![],
            expected: Outcome::lists(1, TransferSubject::Owner(1)),
        },
        Spec {
            name: "a_scalar_owner_guard_exempts_an_owner_total_at_the_threshold",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(100)),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: vec![(owner_b(), asset_x(), 60), (owner_b(), asset_x(), 40)],
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "a_scalar_owner_guard_sums_both_outputs_of_the_owner",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(100)),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: vec![(owner_b(), asset_x(), 60), (owner_b(), asset_x(), 41)],
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Owner(0)),
        },
        Spec {
            name: "a_scalar_owner_guard_reads_each_asset_apart",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(100)),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: vec![(owner_a(), asset_x(), 100), (owner_a(), asset_y(), 100)],
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "a_scalar_asset_guard_sums_the_asset_across_owners",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::Asset, ListId::Allow).above(100)),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(asset_x(), ALLOW)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: vec![
                (owner_a(), asset_y(), 60),
                (owner_b(), asset_y(), 50),
                (owner_a(), asset_x(), 500),
            ],
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Asset(0)),
        },
        Spec {
            name: "an_asset_guard_exempts_an_owner_within_the_asset_limit",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset()),
            thresholds: vec![(asset_x(), 50)],
            curated: ListSet::EMPTY,
            own: vec![],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: vec![(owner_b(), asset_x(), 30), (owner_b(), asset_x(), 20)],
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "an_asset_guard_sums_one_owner_and_one_asset_past_the_limit",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset()),
            thresholds: vec![(asset_x(), 50)],
            curated: ListSet::EMPTY,
            own: vec![],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: vec![(owner_b(), asset_x(), 30), (owner_b(), asset_x(), 21)],
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Owner(0)),
        },
        Spec {
            name: "a_mint_without_a_limit_admits_a_listed_owner",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset()),
            thresholds: vec![(asset_x(), 50)],
            curated: ListSet::EMPTY,
            own: vec![(owner_a(), ALLOW)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: vec![(owner_a(), asset_x(), 10), (owner_a(), asset_y(), 10)],
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "a_mint_without_a_limit_refuses_an_unlisted_owner",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset()),
            thresholds: vec![(asset_x(), 50)],
            curated: ListSet::EMPTY,
            own: vec![],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: vec![(owner_a(), asset_x(), 10), (owner_a(), asset_y(), 10)],
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Owner(1)),
        },
        Spec {
            name: "change_adds_no_receipt",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(100)),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![],
            curated_records: vec![],
            ring_inputs: vec![(owner_a(), asset_x(), 160)],
            outputs: vec![(owner_b(), asset_x(), 60), (owner_a(), asset_x(), 100)],
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "another_owners_input_funds_a_receipt",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(100)),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![],
            curated_records: vec![],
            ring_inputs: vec![(owner_b(), asset_x(), 200), (owner_a(), asset_x(), 10)],
            outputs: vec![(owner_a(), asset_x(), 210)],
            exits: vec![],
            expected: Outcome::lists(0, TransferSubject::Owner(0)),
        },
        Spec {
            name: "an_exit_stays_gross_against_its_owners_inputs",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(100)),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![],
            curated_records: vec![],
            ring_inputs: vec![(owner_a(), asset_x(), 101)],
            outputs: vec![(owner_a(), asset_x(), 101)],
            exits: vec![0],
            expected: Outcome::lists(0, TransferSubject::Owner(0)),
        },
        Spec {
            name: "a_scalar_asset_guard_nets_change",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::Asset, ListId::Allow).above(100)),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![],
            curated_records: vec![],
            ring_inputs: vec![(owner_a(), asset_x(), 160)],
            outputs: vec![(owner_b(), asset_x(), 60), (owner_a(), asset_x(), 100)],
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "an_asset_guard_asks_no_limit_of_a_zero_owner_output",
            table: RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset()),
            thresholds: vec![(asset_x(), 50)],
            curated: ListSet::EMPTY,
            own: vec![(owner_a(), ALLOW)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: vec![(owner_a(), asset_x(), 10), (ZERO_OWNER, asset_y(), 10)],
            exits: vec![],
            expected: Outcome::Pass,
        },
        Spec {
            name: "the_first_failing_rule_in_table_order_is_named",
            table: require(Subject::Sender, ListId::Allow)
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
                .rule(Rule::forbid(Subject::Asset, ListId::Block)),
            thresholds: vec![],
            curated: ListSet::EMPTY,
            own: vec![(sender(), ALLOW), (owner_a(), ALLOW), (asset_x(), BLOCK)],
            curated_records: vec![],
            ring_inputs: vec![],
            outputs: both,
            exits: vec![],
            expected: Outcome::lists(1, TransferSubject::Owner(1)),
        },
    ]
}

fn compute_vectors() -> PolicyRulesVectors {
    PolicyRulesVectors {
        description: "Transfers the policy circuits' list rules admit or refuse. Each case \
                      carries table rows and mint thresholds installed into asset records, \
                      the eight source slots, the records of the ring's own and of the curator \
                      registry by member, the sender member and every UTXO output's owner, asset \
                      and amount. A subject reads list i + 1 from the curator record when source \
                      slot i names a registry field, else from its own record, an absent member \
                      reads zero. A rule holds when the subject is on any list of its present set \
                      or off any list of its absent set. A zero owner carries no owner obligation. \
                      An owner's guard per asset is its same-ring outputs less its ring_inputs, floored \
                      at zero, plus its outputs with ring false. A scalar guard exempts that guard, \
                      or on an asset rule its sum over the asset's owners, at or below the threshold. \
                      An asset guard reads the mint's record threshold, zero without one. The outcome \
                      is pass, or the first refusal in table order then output order. \
                      Produced by program-libs/policy/tests/policy_rules_vector.rs."
            .to_string(),
        cases: specs().into_iter().map(Spec::case).collect(),
    }
}

fn committed() -> PolicyRulesVectors {
    serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
        .expect("vector json")
}

#[test]
fn ring_policy_rules_vector() {
    assert_eq!(committed(), compute_vectors());
}

#[test]
#[ignore = "rewrites test-vectors/policy/ring-policy-rules.json"]
fn write_ring_policy_rules_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}
