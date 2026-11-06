import type { MintPolicy } from "./mint-policy.js";
import type { Address } from "@solana/kit";

import { RingDomain, domainField } from "../../crypto/derivation/ring-domain.js";
import type { PolicyTableProofInputs } from "../../rpc/prover/ring.js";
import {
  hashBytes,
  solanaOwnerIdentity,
  Reader,
  Writer,
  addressBytes,
  ZERO_32,
  bigIntBytes,
  bytesToBigInt,
  decodeAddress,
  poseidon,
  rightAlign,
  equalBytes,
  isZero,
} from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { RING_RULE_SLOTS, RING_SOURCE_SLOTS } from "../../rpc/prover/types.js";

import {
  registryCurator,
  type EncodedRuleTable,
  type RingPolicy,
  type RingSourceSlot,
} from "../codec/ring-codecs.js";
import { RingError } from "../error.js";
import { GuardScope, type DebitInput } from "./owner-debits.js";

/** Mirrors Rust `ListId`, the on-chain discriminant of a list, never `0`. */
export const ListId = Object.freeze({
  allow: 1,
  block: 2,
  frozen: 3,
  ringViewing: 4,
  privateBlock: 5,
  reader: 6,
  approval: 7,
  privateAllow: 8,
  privateFrozen: 9,
} as const);
export type ListId = (typeof ListId)[keyof typeof ListId];

/** Source-slot order, the id of `LIST_IDS[i]` is `i + 1`. */
export const LIST_IDS: readonly ListId[] = Object.freeze(Object.values(ListId));

/** A reader grant moves no funds. */
export const POLICY_LISTS: readonly ListId[] = Object.freeze([
  ListId.allow,
  ListId.block,
  ListId.frozen,
  ListId.privateBlock,
  ListId.approval,
  ListId.privateAllow,
  ListId.privateFrozen,
]);

/** Presence satisfies a grant. */
const GRANT_LISTS: readonly ListId[] = Object.freeze([
  ListId.allow,
  ListId.approval,
  ListId.privateAllow,
]);
/** Absence is required. */
const DENY_LISTS: readonly ListId[] = Object.freeze([
  ListId.block,
  ListId.frozen,
  ListId.privateBlock,
  ListId.privateFrozen,
]);

/** Rust `ListSet::PRIVATE_LISTS`, an owner reads them at a salted key on every ring. */
export const PRIVATE_LIST_BITS =
  (1 << (ListId.privateBlock - 1)) |
  (1 << (ListId.privateAllow - 1)) |
  (1 << (ListId.privateFrozen - 1));

/** Owners read it at salted keys, its source needs a tracking floor. */
export function isPrivateList(id: ListId): boolean {
  return (PRIVATE_LIST_BITS & listBit(id)) !== 0;
}

export function listIdFromByte(byte: number): ListId | undefined {
  return LIST_IDS.find((id) => id === byte);
}

/** Mirrors Rust `ListSet`, bit `i` is list `i + 1`. */
export function listSet(bits: number): readonly ListId[] {
  return Object.freeze(LIST_IDS.filter((id) => (bits & listBit(id)) !== 0));
}

function listBit(id: ListId): number {
  return 1 << (checkedListId(id) - 1);
}

/** Rust `ListId::record_bit`, the bit of a member record's `lists` bitmap. */
export function recordBit(id: ListId): bigint {
  return BigInt(listBit(id));
}

/** A byte outside `LIST_IDS` never reaches a mask, a seed or the wire. */
export function checkedListId(id: ListId): ListId {
  if (listIdFromByte(id) === undefined) throw ruleTableInvalid("UnknownList");
  return id;
}

function listBits(ids: readonly ListId[]): number {
  return ids.reduce((bits, id) => bits | listBit(id), 0);
}

/** Rust `ListSet::NAMED`, a row bit past it names no list. */
const NAMED_LIST_BITS = listBits(LIST_IDS);

export type RuleSubject = "outputOwner" | "sender" | "asset";

export type RuleSource = Readonly<{
  kind: "lists";
  present: readonly ListId[];
  absent: readonly ListId[];
}>;

export type RuleGuard =
  | Readonly<{ kind: "always" }>
  | Readonly<{ kind: "aboveAmount"; amount: bigint }>
  | Readonly<{ kind: "aboveAmountByAsset" }>;

export interface Rule {
  readonly subject: RuleSubject;
  readonly source: RuleSource;
  readonly guard: RuleGuard;
}

/** Mirrors Rust `OutflowLimit`, a zero bound is no bound. */
export interface OutflowLimit {
  /** `memberOfAsset` of the mint. */
  readonly asset: Member;
  /** The most one transfer moves out. */
  readonly cap: bigint;
  /** The co-signer signs an outflow above it. */
  readonly cosignAbove: bigint;
}

/** Mirrors Rust `PolicySource`, the field of one source slot, a zero registry names the ring's own. */
export interface PolicySource {
  readonly listId: number;
  readonly registry: Bytes32;
}

/** Mirrors Rust `SourceMap`, the salted set reads from the mapped private slots. */
export type PolicySources = readonly PolicySource[];

/** Go `sourceView`. */
export interface SourceView {
  /** Bits a curator serves. */
  readonly foreign: number;
  /** Rust `SourceMap::salted`, the mapped private lists. */
  readonly salted: number;
  readonly saltedOwn: boolean;
  readonly saltedCurated: boolean;
  /** Clear, an owner takes no curator row under its public key. */
  readonly publicForeign: boolean;
}

/** Rules and their list sources; per-mint amounts live in authenticated asset records. */
export interface RuleTable {
  readonly rules: readonly Rule[];
}

const U64_MAX = (1n << 64n) - 1n;

/** By wire byte, Rust `Subject`, byte 3 names no subject. */
const SUBJECT_BYTES: Readonly<Record<RuleSubject, number>> = Object.freeze({
  outputOwner: 1,
  sender: 2,
  asset: 4,
});

export type RuleMode = "present" | "absent";

export interface RuleAlternative {
  readonly listId: ListId;
  readonly mode: RuleMode;
}

/** Mirrors Rust `Rule::alternatives`, presences first, each in slot order. */
export function ruleAlternatives(rule: Rule): readonly RuleAlternative[] {
  if (rule.source.kind !== "lists") return Object.freeze([]);
  const { present, absent } = rule.source;
  return Object.freeze([
    ...listSet(listBits(present)).map((listId) => ({ listId, mode: "present" as const })),
    ...listSet(listBits(absent)).map((listId) => ({ listId, mode: "absent" as const })),
  ]);
}

/** Mirrors Rust `Rule::encoded`, an absent-only rule carries its lists in the mask. */
export function encodeRule(rule: Rule): Bytes32 {
  checkRule(rule);
  let mask = 0;
  let alternative = 0;
  let mode = 1;
  if (rule.source.kind === "lists") {
    const present = listBits(rule.source.present);
    if (present === 0) {
      mask = listBits(rule.source.absent);
      mode = 2;
    } else {
      mask = present;
      alternative = listBits(rule.source.absent);
    }
  }
  const [guardTag, threshold] =
    rule.guard.kind === "always"
      ? [0, 0n]
      : rule.guard.kind === "aboveAmount"
        ? [1, rule.guard.amount]
        : [2, 0n];
  if (threshold < 0n || threshold > U64_MAX) throw ruleTableInvalid("ThresholdRange");
  return new Writer()
    .bytes(new Uint8Array(17))
    .bytes(bigIntBytes(BigInt(alternative), 2))
    .bytes(bigIntBytes(threshold, 8))
    .u8(guardTag, "guardTag")
    .bytes(bigIntBytes(BigInt(mask), 2))
    .u8(mode, "mode")
    .u8(SUBJECT_BYTES[rule.subject], "subject")
    .finish() as Bytes32;
}

/** Mirrors Rust `Rule::decode` and `Rule::check`, `details.reason` names the Rust variant. */
export function decodeRule(row: Bytes32): Rule {
  const reader = new Reader(row);
  const reserved = reader.bytes(17, "reserved");
  const alternative = Number(bytesToBigInt(reader.bytes(2, "alternative")));
  const threshold = bytesToBigInt(reader.bytes(8, "threshold"));
  const guardTag = reader.u8("guardTag");
  const mask = Number(bytesToBigInt(reader.bytes(2, "mask")));
  const mode = reader.u8("mode");
  const subjectByte = reader.u8("subject");
  reader.done();
  if (reserved.some((byte) => byte !== 0)) throw ruleTableInvalid("ReservedBytes");
  const subject = (Object.keys(SUBJECT_BYTES) as RuleSubject[]).find(
    (named) => SUBJECT_BYTES[named] === subjectByte,
  );
  if (subject === undefined) throw ruleTableInvalid("UnknownSubject");
  if (mode !== 1 && mode !== 2) throw ruleTableInvalid("UnknownMode");
  if (((mask | alternative) & ~NAMED_LIST_BITS) !== 0) throw ruleTableInvalid("UnknownList");
  let source: RuleSource;
  if (mask === 0) {
    throw ruleTableInvalid("EmptyLists");
  } else if (mode === 1) {
    source = { kind: "lists", present: listSet(mask), absent: listSet(alternative) };
  } else {
    if (alternative !== 0) throw ruleTableInvalid("NonCanonicalAlternative");
    source = { kind: "lists", present: [], absent: listSet(mask) };
  }
  let guard: RuleGuard;
  if (guardTag === 0) {
    if (threshold !== 0n) throw ruleTableInvalid("ThresholdWithoutGuard");
    guard = { kind: "always" };
  } else if (guardTag === 1) {
    guard = { kind: "aboveAmount", amount: threshold };
  } else if (guardTag === 2) {
    if (threshold !== 0n) throw ruleTableInvalid("ThresholdWithoutGuard");
    guard = { kind: "aboveAmountByAsset" };
  } else {
    throw ruleTableInvalid("UnknownGuardTag");
  }
  const rule: Rule = Object.freeze({ subject, source, guard });
  checkRule(rule);
  return rule;
}

function checkRule(rule: Rule): void {
  if (rule.source.kind === "lists") {
    const { present, absent } = rule.source;
    if (present.length + absent.length === 0) throw ruleTableInvalid("EmptyLists");
    if ((listBits(present) & listBits(absent)) !== 0) throw ruleTableInvalid("ListInBothSets");
  } else {
    throw ruleTableInvalid("InlineNotAsset");
  }
  if (rule.guard.kind === "aboveAmount") {
    if (rule.subject === "sender") throw ruleTableInvalid("SenderGuard");
    if (rule.guard.amount === 0n) throw ruleTableInvalid("ZeroThreshold");
  }
  if (rule.guard.kind === "aboveAmountByAsset") {
    if (rule.subject !== "outputOwner") throw ruleTableInvalid("PerAssetGuardNotOwner");
  }
}

/**
 * Rust `RuleTable::validate`, every policy write runs it. The guarantee is that configured list
 * operations have consistent semantics, never that every accepted policy is restrictive. A rule is
 * a grant met by presence in any of its grant lists, or a denial met by absence from its one deny
 * list, and every rule holds at once. The row layout evaluates any OR, and three forms read against
 * those semantics. A mixed row passes on either branch, a grant lifts the denial for a blocked
 * owner. Multi-list absence passes a subject off any one list, a publicly blocked owner with no
 * private entry passes a row over both. Inverted polarity makes a set deny bit grant.
 */
export function validateRuleTable(table: RuleTable): void {
  for (const { source } of table.rules) {
    const { present, absent } = source;
    if (present.length > 0 && absent.length > 0) throw ruleTableInvalid("MixedPolarity");
    if (absent.length > 1) throw ruleTableInvalid("MultiListAbsence");
    if (
      !present.every((id) => GRANT_LISTS.includes(id)) ||
      !absent.every((id) => DENY_LISTS.includes(id))
    )
      throw ruleTableInvalid("InvertedPolarity");
  }
}

/** Mirrors Rust `EncodedRuleTable::decode`, the padding is checked by `decodeRingPolicy`. */
export function decodeRuleTable(config: EncodedRuleTable): RuleTable {
  if (config.rules.length > RING_RULE_SLOTS) throw ruleTableInvalid("TooManyRules");
  return checkedRuleTable({ ...config, rules: config.rules.map(decodeRule) });
}

export interface RuleTableInput {
  readonly rules: readonly Rule[];
}

export function buildRuleTable(input: RuleTableInput): RuleTable {
  return checkedRuleTable(input);
}

/** Mirrors Rust `RuleTable::encode`, counted rows without the zero padding. */
export function encodeRuleTable(table: RuleTable): EncodedRuleTable {
  return Object.freeze({
    rules: Object.freeze(table.rules.map(encodeRule)),
  });
}

/** Rust `try_build` in its order, a decoded and a built table refuse alike. */
function checkedRuleTable(
  table: Omit<EncodedRuleTable, "rules"> & Readonly<{ rules: readonly Rule[] }>,
): RuleTable {
  const { rules } = table;
  if (rules.length > RING_RULE_SLOTS) throw ruleTableInvalid("TooManyRules");
  const signatures = new Set<string>();
  for (const rule of rules) {
    checkRule(rule);
    const signature = ruleSignature(rule);
    if (signatures.has(signature)) throw ruleTableInvalid("DuplicateRule");
    signatures.add(signature);
  }
  return Object.freeze({ rules: Object.freeze([...rules]) });
}

function ruleSignature(rule: Rule): string {
  const [present, absent] =
    rule.source.kind === "lists"
      ? [listBits(rule.source.present), listBits(rule.source.absent)]
      : [0, 0];
  return `${rule.subject}:${present}:${absent}`;
}

/** In slot order. */
export function referencedLists(rules: readonly Rule[]): readonly ListId[] {
  const bits = rules.reduce(
    (set, rule) =>
      rule.source.kind === "lists"
        ? set | listBits(rule.source.present) | listBits(rule.source.absent)
        : set,
    0,
  );
  return listSet(bits);
}

/** The lists a policy reads, in slot order. */
export function policySourceLists(rules: readonly Rule[]): readonly ListId[] {
  const lists = referencedLists(rules);
  if (lists.some((listId) => listWriter(listId) === "member"))
    throw ruleTableInvalid("MemberWrittenList");
  if (lists.some((listId) => !POLICY_LISTS.includes(listId)))
    throw ruleTableInvalid("ListNotPolicyReadable");
  return lists;
}

/** Rust `RecordLists`, a member's record lists in each registry, zero for an absent member. */
export interface RecordLists {
  readonly own: bigint;
  /** Read only for a list a curator serves. */
  readonly curator: bigint;
  /** Read only for an owner's salted list, zero with no tracking row. */
  readonly salted?: bigint;
}

/** Rust `OutputSubjects`. */
export interface OutputSubjects {
  /** Set on a same-ring output, clear on an exit or a withdrawal. */
  readonly ring: boolean;
  /** Zero carries no owner obligation. */
  readonly owner: Bytes32;
  /** `memberOfAsset` of the mint. */
  readonly asset: Bytes32;
  readonly amount: bigint;
  readonly ownerLists: RecordLists;
  readonly assetLists: RecordLists;
  readonly mintPolicy: MintPolicy;
}

/** Rust `TransferSubjects`. */
export interface TransferSubjects {
  readonly sender: RecordLists;
  /** Live inputs of the ring, a default-ring note and a deposit net no receipt. */
  readonly ringInputs: readonly DebitInput[];
  /** The payments in slot order, dummies and compact padding left out. */
  readonly outputs: readonly OutputSubjects[];
}

/** The side of a transfer the owner and asset rules read, it holds no sender row. */
export type PaymentSubjects = Pick<TransferSubjects, "ringInputs" | "outputs">;

/** Rust `TransferSubject`, `output` a position in `TransferSubjects.outputs`, `input` a published input slot. */
export type TransferSubject =
  | Readonly<{ kind: "sender" }>
  | Readonly<{ kind: "owner"; output: number }>
  | Readonly<{ kind: "asset"; output: number }>
  | Readonly<{ kind: "inputAsset"; input: number }>;

/** Rust `RuleRefusal`. */
export type RuleRefusal = Readonly<{ kind: "lists"; rule: number; subject: TransferSubject }>;

/** Rust `RuleTable::admit`, the first refusal in the table's order, caps, outflow and co-sign left out. */
export function admitTransfer(
  table: RuleTable,
  sources: PolicySources,
  transfer: TransferSubjects,
): RuleRefusal | undefined {
  return screen(table, sources, { senders: [transfer.sender], payments: transfer });
}

/** Rust `RuleTable::evaluate_senders`, an owner or asset rule is not read. */
export function evaluateSenders(
  table: RuleTable,
  sources: PolicySources,
  senders: readonly RecordLists[],
): RuleRefusal | undefined {
  return screen(table, sources, { senders, payments: { ringInputs: [], outputs: [] } });
}

/**
 * Rust `RuleTable::evaluate_payments`, a sender rule is not read. The circuit screens each payment
 * whatever the sender rows hold, a transfer with no live sender row owes the check all the same.
 */
export function evaluatePayments(
  table: RuleTable,
  sources: PolicySources,
  payments: PaymentSubjects,
): RuleRefusal | undefined {
  return screen(table, sources, { senders: [], payments });
}

/**
 * Every live input's asset meets the unconditional asset rules, Go `assertInputAssetRules`. A zero
 * value input can name any asset with nothing paid in it, the one spend the payment section never
 * reads. A guarded rule stays out, its total reads payments alone and an input adds nothing to it.
 */
export function evaluateInputAssets(
  table: RuleTable,
  sources: PolicySources,
  inputs: readonly Readonly<{ input: number; lists: RecordLists }>[],
): RuleRefusal | undefined {
  const reads = listReads(sources);
  for (const [index, rule] of table.rules.entries()) {
    if (rule.subject !== "asset" || rule.guard.kind !== "always") continue;
    for (const { input, lists } of inputs) {
      const subject: TransferSubject = { kind: "inputAsset", input };
      if (!holds(rule, reads(subject, lists))) return { kind: "lists", rule: index, subject };
    }
  }
  return undefined;
}

function screen(
  table: RuleTable,
  sources: PolicySources,
  screened: Readonly<{ senders: readonly RecordLists[]; payments: PaymentSubjects }>,
): RuleRefusal | undefined {
  const reads = listReads(sources);
  const { senders } = screened;
  const { outputs, ringInputs } = screened.payments;
  const scope = new GuardScope({ ringInputs, payments: outputs });
  for (const [index, rule] of table.rules.entries()) {
    const refused = (subject: TransferSubject, records: RecordLists): boolean =>
      !holds(rule, reads(subject, records));
    if (rule.subject === "sender") {
      const subject: TransferSubject = { kind: "sender" };
      if (senders.some((sender) => refused(subject, sender)))
        return { kind: "lists", rule: index, subject };
      continue;
    }
    const onAsset = rule.subject === "asset";
    for (const [position, output] of outputs.entries()) {
      if (!onAsset && isZero(output.owner)) continue;
      if (passesGuard(rule, scope, output)) continue;
      const subject: TransferSubject = onAsset
        ? { kind: "asset", output: position }
        : { kind: "owner", output: position };
      if (refused(subject, onAsset ? output.assetLists : output.ownerLists))
        return { kind: "lists", rule: index, subject };
    }
  }
  return undefined;
}

/** The lists a subject is on, an asset never reads a salted key. */
function listReads(sources: PolicySources) {
  const view = policySourceView(sources);
  const foreign = BigInt(view.foreign);
  const salted = BigInt(view.salted);
  return (subject: TransferSubject, records: RecordLists): bigint => {
    const owned = subject.kind === "asset" || subject.kind === "inputAsset" ? 0n : salted;
    const onPublic = (records.own & ~foreign) | (records.curator & foreign);
    return (onPublic & ~owned) | ((records.salted ?? 0n) & owned);
  };
}

/** A guard reads `guard(o,a)` per asset, never a scalar across assets, a mint with no record reads threshold zero. */
function passesGuard(rule: Rule, scope: GuardScope, output: OutputSubjects): boolean {
  const { guard } = rule;
  if (guard.kind === "always") return false;
  if (guard.kind === "aboveAmountByAsset")
    return scope.owner(output.owner, output.asset) <= output.mintPolicy.threshold;
  return rule.subject === "asset"
    ? scope.asset(output.asset) <= guard.amount
    : scope.owner(output.owner, output.asset) <= guard.amount;
}

/** On any list of the present set, or off any list of the absent set. */
function holds(rule: Rule, on: bigint): boolean {
  const present = BigInt(listBits(rule.source.present));
  const absent = BigInt(listBits(rule.source.absent));
  return (present & on) !== 0n || (absent & ~on) !== 0n;
}

function ruleTableInvalid(reason: string): RingError {
  return new RingError("RING_RULE_TABLE_INVALID", { details: { reason } });
}

/** Mirrors Rust `SourceMap::from_slots`. */
export function policySourceOwners(sources: readonly RingSourceSlot[]): readonly PolicySource[] {
  return checkedSourceOwners(
    sources.map((slot) =>
      Object.freeze(
        slot.listId === 0
          ? { listId: 0, registry: new Uint8Array(32) as Bytes32 }
          : {
              listId: slot.listId,
              registry: equalBytes(addressBytes(slot.registry), ZERO_32)
                ? ZERO_32
                : (hashBytes(addressBytes(slot.registry)) as Bytes32),
            },
      ),
    ),
  );
}

export function policySourceView(sources: PolicySources): SourceView {
  const bits = (keep: (slot: PolicySource) => boolean): number =>
    sources.reduce(
      (set, slot) => (slot.listId !== 0 && keep(slot) ? set | (1 << (slot.listId - 1)) : set),
      0,
    );
  const salted = bits(() => true) & PRIVATE_LIST_BITS;
  const foreign = bits((slot) => !equalBytes(slot.registry, ZERO_32));
  return Object.freeze({
    foreign,
    salted,
    saltedOwn: (salted & ~foreign) !== 0,
    saltedCurated: (salted & foreign) !== 0,
    publicForeign: (foreign & ~salted) !== 0,
  });
}

function checkedSourceOwners(owners: readonly PolicySource[]): readonly PolicySource[] {
  if (owners.length !== RING_SOURCE_SLOTS) {
    throw sourceInvalid("SlotCount", { slots: owners.length });
  }
  owners.forEach((slot, index) => {
    const empty = slot.listId === 0 && equalBytes(slot.registry, ZERO_32);
    const positional = slot.listId === index + 1;
    if (!empty && !positional) throw sourceInvalid("NotPositional", { index });
  });
  const foreign = new Set(
    owners
      .filter((slot) => !equalBytes(slot.registry, ZERO_32))
      .map((slot) => Array.from(slot.registry).join(",")),
  );
  if (foreign.size > 1) throw sourceInvalid("MultipleCurators", {});
  return Object.freeze([...owners]);
}

function sourceInvalid(reason: string, details: Readonly<Record<string, unknown>>): RingError {
  return new RingError("RING_POLICY_SOURCE_INVALID", { details: { reason, ...details } });
}

/** Fields absorbed per Poseidon call beside the accumulator, the 12-input syscall maximum. */
const POLICY_TABLE_RATE = 11;

/** The table at its slot widths, every slot past a count zero, the one layout the hash and the policy proof read. */
export function policyTableProofInputs(
  input: RuleTable,
  sources: PolicySources,
): PolicyTableProofInputs {
  const table = buildRuleTable(input);
  const owners = checkedSourceOwners(sources);
  for (const listId of referencedLists(table.rules))
    if (owners[listId - 1]?.listId !== listId) throw sourceInvalid("MissingSource", { listId });
  return Object.freeze({
    sources: owners,
    salted: policySourceView(owners).salted,
    policyLen: table.rules.length,
    rules: Array.from({ length: RING_RULE_SLOTS }, (_, index) => {
      const rule = table.rules[index];
      return rule === undefined ? ZERO_32 : encodeRule(rule);
    }),
  });
}

/** Rust `EncodedRuleTable::fields`, the fields the policy circuit opens, zero to a full rate. */
export function policyTableFields(table: RuleTable, sources: PolicySources): readonly Bytes32[] {
  const slots = policyTableProofInputs(table, sources);
  const values = [
    domainField(RingDomain.policyTable),
    ...slots.sources.flatMap((owner) => [fieldU8(owner.listId), owner.registry]),
    rightAlign(bigIntBytes(BigInt(slots.salted), 2)),
    fieldU8(slots.policyLen),
    ...slots.rules,
  ];
  const padding = (POLICY_TABLE_RATE - (values.length % POLICY_TABLE_RATE)) % POLICY_TABLE_RATE;
  return Object.freeze([...values, ...Array<Bytes32>(padding).fill(ZERO_32)]);
}

/** `acc = Poseidon(acc, fields[11c .. 11c + 11])` from `acc = 0`, Rust `EncodedRuleTable::hash`. */
export function policyTableHash(table: RuleTable, sources: PolicySources): Bytes32 {
  const fields = policyTableFields(table, sources);
  let acc = ZERO_32;
  for (let offset = 0; offset < fields.length; offset += POLICY_TABLE_RATE) {
    acc = poseidon([acc, ...fields.slice(offset, offset + POLICY_TABLE_RATE)]);
  }
  return acc;
}

/** The policy table the registry pins, trusted once it reproduces the pinned hash, Rust `PinnedPolicy`. */
export interface PinnedPolicy {
  readonly table: RuleTable;
  readonly sources: readonly PolicySource[];
  readonly policyHash: Bytes32;
  /** The one curator registry a source names. */
  readonly curator?: Address;
}

/** Mirrors Rust `PinnedPolicy::of`, `RING_POLICY_HASH_MISMATCH` unless the stored table reproduces the hash. */
export function pinnedPolicy(
  registry: Pick<RingPolicy, "policyHash" | "sources" | "rules" | "generation">,
): PinnedPolicy {
  if (equalBytes(registry.policyHash, ZERO_32))
    throw new RingError("RING_POLICY_NOT_SET", { details: { generation: registry.generation } });
  const sources = policySourceOwners(registry.sources);
  const table = decodeRuleTable(registry.rules);
  if (!equalBytes(policyTableHash(table, sources), registry.policyHash))
    throw new RingError("RING_POLICY_HASH_MISMATCH", {
      details: { generation: registry.generation },
    });
  const curator = registryCurator(registry);
  return Object.freeze({
    table,
    sources,
    policyHash: registry.policyHash,
    ...(curator === undefined ? {} : { curator }),
  });
}

declare const memberBrand: unique symbol;
/** Mirrors Rust `Member`, never zero. */
export type Member = Bytes32 & { readonly [memberBrand]: true };

/** Mirrors Rust `Member::owner_tag`, the derivation `zolana-ring list add` applies to `--owner`. */
export function memberOfTag(tag: Uint8Array): Member {
  if (tag.length !== 32) throw entryInvalid("tagLength");
  return checkedMember(solanaOwnerIdentity(tag) as Bytes32);
}

/** Mirrors Rust `Member::owner_identity`, an owner of any curve by `ownerProofInputHash`. */
export function memberOfIdentity(identity: Bytes32): Member {
  return checkedMember(identity);
}

/** Mirrors Rust `Member::asset`, the mint as the UTXO asset field. */
export function memberOfAsset(mint: Address): Member {
  return checkedMember(hashBytes(decodeAddress(mint)) as Bytes32);
}

/** Mirrors Rust `Member::wallet_grant`, its `reader` list is the wallet's grant to `reader`. */
export function walletGrantMember(wallet: Member, reader: Member): Member {
  return checkedMember(
    poseidon([
      domainField(RingDomain.walletGrant),
      checkedMember(wallet),
      checkedMember(reader),
    ]) as Bytes32,
  );
}

function checkedMember(bytes: Bytes32): Member {
  if (equalBytes(bytes, ZERO_32)) throw entryInvalid("zeroMember");
  return bytes as Member;
}

export type ListWriter = "authority" | "member";

/** Mirrors Rust `ListId::writer`. */
export function listWriter(listId: ListId): ListWriter {
  switch (checkedListId(listId)) {
    case ListId.ringViewing:
      return "member";
    case ListId.allow:
    case ListId.block:
    case ListId.frozen:
    case ListId.privateBlock:
    case ListId.reader:
    case ListId.approval:
    case ListId.privateAllow:
    case ListId.privateFrozen:
      return "authority";
  }
}

function entryInvalid(reason: string): RingError {
  return new RingError("RING_ENTRY_INVALID", { details: { reason } });
}

function fieldU8(value: number): Bytes32 {
  return rightAlign(Uint8Array.of(value));
}
