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
} from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { RING_RULE_SLOTS, RING_SOURCE_SLOTS } from "../../rpc/prover/types.js";

import {
  registryCurator,
  type EncodedRuleTable,
  type RingMemberRegistry,
  type RingSourceSlot,
} from "../codec/ring-codecs.js";
import { RingError } from "../error.js";

/** Mirrors Rust `ListId`, the on-chain discriminant of a list, never `0`. */
export const ListId = Object.freeze({
  allow: 1,
  block: 2,
  frozen: 3,
  ringViewing: 4,
  recovery: 5,
  reader: 6,
  approval: 7,
  escrow: 8,
} as const);
export type ListId = (typeof ListId)[keyof typeof ListId];

/** Source-slot order, the id of `LIST_IDS[i]` is `i + 1`. */
export const LIST_IDS: readonly ListId[] = Object.freeze(Object.values(ListId));

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

export type RuleSubject = "outputOwner" | "sender" | "exitDestination" | "asset";

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

/** Rules and their list sources; per-mint amounts live in authenticated asset records. */
export interface RuleTable {
  readonly rules: readonly Rule[];
}

const U64_MAX = (1n << 64n) - 1n;

const SUBJECTS: readonly RuleSubject[] = ["outputOwner", "sender", "exitDestination", "asset"];

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
    .bytes(new Uint8Array(19))
    .u8(alternative, "alternative")
    .bytes(bigIntBytes(threshold, 8))
    .u8(guardTag, "guardTag")
    .u8(mask, "mask")
    .u8(mode, "mode")
    .u8(SUBJECTS.indexOf(rule.subject) + 1, "subject")
    .finish() as Bytes32;
}

/** Mirrors Rust `Rule::decode` and `Rule::check`, `details.reason` names the Rust variant. */
export function decodeRule(row: Bytes32): Rule {
  const reader = new Reader(row);
  const reserved = reader.bytes(19, "reserved");
  const alternative = reader.u8("alternative");
  const threshold = bytesToBigInt(reader.bytes(8, "threshold"));
  const guardTag = reader.u8("guardTag");
  const mask = reader.u8("mask");
  const mode = reader.u8("mode");
  const subjectByte = reader.u8("subject");
  reader.done();
  if (reserved.some((byte) => byte !== 0)) throw ruleTableInvalid("ReservedBytes");
  const subject = SUBJECTS[subjectByte - 1];
  if (subject === undefined) throw ruleTableInvalid("UnknownSubject");
  if (mode !== 1 && mode !== 2) throw ruleTableInvalid("UnknownMode");
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
  if (rule.subject === "exitDestination") throw ruleTableInvalid("ExitDestination");
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

/** Mirrors Rust `EncodedRuleTable::decode`, the padding is checked by `decodeRingMemberRegistry`. */
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

/** Rust `EncodedRuleTable::validate`, a policy reads only lists the authority writes, in slot order. */
export function policySourceLists(rules: readonly Rule[]): readonly ListId[] {
  const lists = referencedLists(rules);
  if (lists.some((listId) => listWriter(listId) !== "authority"))
    throw ruleTableInvalid("MemberWrittenList");
  return lists;
}

/** Rust `RecordLists`, a member's record lists in each registry, zero for an absent member. */
export interface RecordLists {
  readonly own: bigint;
  /** Read only for a list a curator serves. */
  readonly curator: bigint;
}

/** Rust `OutputSubjects`. */
export interface OutputSubjects {
  /** Zero carries no owner obligation. */
  readonly owner: Bytes32;
  /** `memberOfAsset` of the mint. */
  readonly asset: Bytes32;
  readonly amount: bigint;
  readonly ownerLists: RecordLists;
  readonly assetLists: RecordLists;
  readonly mintPolicy: MintPolicy;
}

/** Rust `TransferSubjects`, the UTXO outputs in slot order with every dummy left out. */
export interface TransferSubjects {
  readonly sender: RecordLists;
  readonly outputs: readonly OutputSubjects[];
}

/** Rust `TransferSubject`, `output` a position in `TransferSubjects.outputs`. */
export type TransferSubject =
  | Readonly<{ kind: "sender" }>
  | Readonly<{ kind: "owner"; output: number }>
  | Readonly<{ kind: "asset"; output: number }>;

/** Rust `RuleRefusal`. */
export type RuleRefusal =
  | Readonly<{ kind: "lists"; rule: number; subject: TransferSubject }>
  | Readonly<{ kind: "noAssetLimit"; rule: number; output: number }>
  | Readonly<{ kind: "mixedAssets"; rule: number; output: number }>;

/** Rust `RuleTable::admit`, the first refusal in the circuit's constraint order, caps, outflow and co-sign left out. */
export function admitTransfer(
  table: RuleTable,
  sources: readonly PolicySource[],
  transfer: TransferSubjects,
): RuleRefusal | undefined {
  const { outputs } = transfer;
  const scalarOwner = table.rules.findIndex(
    (rule) => rule.subject === "outputOwner" && rule.guard.kind === "aboveAmount",
  );
  const [first] = outputs;
  const mixed =
    first === undefined
      ? -1
      : outputs.findIndex((output) => !equalBytes(output.asset, first.asset));
  if (scalarOwner >= 0 && mixed >= 0)
    return { kind: "mixedAssets", rule: scalarOwner, output: mixed };
  const foreign = sources.reduce(
    (bits, slot, index) =>
      equalBytes(slot.registry, ZERO_32) ? bits : bits | (1n << BigInt(index)),
    0n,
  );
  const listed = (
    rule: Rule,
    index: number,
    subject: TransferSubject,
    records: RecordLists,
  ): RuleRefusal | undefined => {
    const on = (records.own & ~foreign) | (records.curator & foreign);
    const present = BigInt(listBits(rule.source.present));
    const absent = BigInt(listBits(rule.source.absent));
    return (present & on) !== 0n || (absent & ~on) !== 0n
      ? undefined
      : { kind: "lists", rule: index, subject };
  };
  const total = (grouped: (other: OutputSubjects) => boolean): bigint =>
    outputs.reduce((sum, other) => (grouped(other) ? sum + other.amount : sum), 0n);
  for (const [index, rule] of table.rules.entries()) {
    if (rule.subject === "sender") {
      const refused = listed(rule, index, { kind: "sender" }, transfer.sender);
      if (refused !== undefined) return refused;
      continue;
    }
    if (rule.subject === "exitDestination") continue;
    const onAsset = rule.subject === "asset";
    for (const [position, output] of outputs.entries()) {
      if (!onAsset && equalBytes(output.owner, ZERO_32)) continue;
      const limit = output.mintPolicy.threshold === 0n ? undefined : output.mintPolicy.threshold;
      if (rule.guard.kind === "aboveAmountByAsset" && limit === undefined)
        return { kind: "noAssetLimit", rule: index, output: position };
      const liveOwner = (other: OutputSubjects): boolean =>
        !equalBytes(other.owner, ZERO_32) && equalBytes(other.owner, output.owner);
      const sameAsset = (other: OutputSubjects): boolean => equalBytes(other.asset, output.asset);
      const { guard } = rule;
      const exempt =
        guard.kind === "aboveAmount"
          ? total(onAsset ? sameAsset : liveOwner) <= guard.amount
          : guard.kind === "aboveAmountByAsset" &&
            limit !== undefined &&
            total((other) => liveOwner(other) && sameAsset(other)) <= limit;
      if (exempt) continue;
      const refused = onAsset
        ? listed(rule, index, { kind: "asset", output: position }, output.assetLists)
        : listed(rule, index, { kind: "owner", output: position }, output.ownerLists);
      if (refused !== undefined) return refused;
    }
  }
  return undefined;
}

function ruleTableInvalid(reason: string): RingError {
  return new RingError("RING_RULE_TABLE_INVALID", { details: { reason } });
}

/** Mirrors Rust `SourceMap::from_namespaces`. */
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

/** Rust `POLICY_TABLE_VERSION`, the second field of the table hash. */
export const POLICY_TABLE_VERSION = 12;
/** Fields absorbed per Poseidon call beside the accumulator, the 12-input syscall maximum. */
const POLICY_TABLE_RATE = 11;

/** The table at its slot widths, every slot past a count zero, the one layout the hash and the policy proof read. */
export function policyTableProofInputs(
  input: RuleTable,
  sources: readonly PolicySource[],
): PolicyTableProofInputs {
  const table = buildRuleTable(input);
  const owners = checkedSourceOwners(sources);
  for (const listId of referencedLists(table.rules)) {
    if (owners[listId - 1]?.listId !== listId) throw sourceInvalid("MissingSource", { listId });
  }
  const slot = <T, U>(values: readonly T[], count: number, at: (value: T) => U, zero: U): U[] =>
    Array.from({ length: count }, (_, index) => {
      const value = values[index];
      return value === undefined ? zero : at(value);
    });
  return Object.freeze({
    sources: owners,
    policyLen: table.rules.length,
    rules: slot(table.rules, RING_RULE_SLOTS, encodeRule, ZERO_32),
  });
}

/** Rust `EncodedRuleTable::fields`, the 77 fields the policy circuit opens. */
export function policyTableFields(
  table: RuleTable,
  sources: readonly PolicySource[],
): readonly Bytes32[] {
  const slots = policyTableProofInputs(table, sources);
  return Object.freeze([
    domainField(RingDomain.policyTable),
    fieldU8(POLICY_TABLE_VERSION),
    ...slots.sources.flatMap((owner) => [fieldU8(owner.listId), owner.registry]),
    fieldU8(slots.policyLen),
    ...slots.rules,
    ...Array<Bytes32>(9).fill(ZERO_32),
  ]);
}

/** `acc = Poseidon(acc, fields[11c .. 11c + 11])` from `acc = 0`, Rust `EncodedRuleTable::hash`. */
export function policyTableHash(table: RuleTable, sources: readonly PolicySource[]): Bytes32 {
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
  registry: Pick<RingMemberRegistry, "policyHash" | "sources" | "rules" | "generation">,
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

function checkedMember(bytes: Bytes32): Member {
  if (equalBytes(bytes, ZERO_32)) throw entryInvalid("zeroMember");
  return bytes as Member;
}

export type ListWriter = "authority" | "member";

/** Mirrors Rust `ListId::writer`. */
export function listWriter(listId: ListId): ListWriter {
  switch (checkedListId(listId)) {
    case ListId.ringViewing:
    case ListId.recovery:
    case ListId.escrow:
      return "member";
    case ListId.allow:
    case ListId.block:
    case ListId.frozen:
    case ListId.reader:
    case ListId.approval:
      return "authority";
  }
}

function entryInvalid(reason: string): RingError {
  return new RingError("RING_ENTRY_INVALID", { details: { reason } });
}

function fieldU8(value: number): Bytes32 {
  return rightAlign(Uint8Array.of(value));
}
