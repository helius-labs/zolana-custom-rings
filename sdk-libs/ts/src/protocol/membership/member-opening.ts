import {
  ASSET_LIMIT_KEYS,
  EMPTY_MINT_POLICY,
  assetLimitsFields,
  isEmptyMintPolicy,
  mintPolicyField,
  mintPolicyWriteField,
} from "./mint-policy.js";
import { hexToBytes } from "@noble/hashes/utils.js";

import { type RingMemberOpening, type RingServedRecord } from "../../rpc/ports.js";
import {
  BN254_SCALAR_ORDER,
  checkedBytes,
  ZERO_32,
  bigIntBytes,
  bytesToBigInt,
  copy,
  equalBytes,
  poseidon,
} from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import {
  MEMBER_REGISTRY_CAPACITY,
  QUAD_ARITY,
  QUAD_HEIGHT,
  canopyLevels,
  type ApplyProofInputs,
  type MemberRecord,
  type QuadPath,
  type RecordWrite,
  type RecordOpening,
  type RecordPool,
  type RecordWriteProofInput,
} from "./member-registry.js";

import { RingDomain, domainField } from "../../crypto/derivation/ring-domain.js";
import { RingError } from "../error.js";
import { ListId, PRIVATE_LIST_BITS, recordBit } from "./policy.js";
import type { ApplyRecordsStatement } from "../proof/statement.js";
import { applyKeyWidth } from "../proof/proving-keys.js";

/** `q - 1`, the sentinel's next, every member sorts strictly below it. */
export const FIELD_MAX = bigIntBytes(BN254_SCALAR_ORDER - 1n) as Bytes32;
/** Rust `MEMBER_REGISTRY_EMPTY_ROOT`, the tree holding only the sentinel, a registry's first root. */
export const MEMBER_REGISTRY_EMPTY_ROOT = hexToBytes(
  "053b2136ce0e6cffb89cb76c7a81b6d7e1bd424159ff4579f284a7e5f198956d",
) as Bytes32;

const U64_MAX = 0xffff_ffff_ffff_ffffn;
const CURVE25519_FIELD = 2n ** 255n - 19n;
const CAPACITY = Number(MEMBER_REGISTRY_CAPACITY);

/** Leaf 0, every member sorts strictly between it and `FIELD_MAX`. */
export const SENTINEL_RECORD: MemberRecord = Object.freeze({
  member: ZERO_32,
  next: FIELD_MAX,
  lists: 0n,
  mintPolicy: EMPTY_MINT_POLICY,
});

/** The sentinel `(0, q - 1)` brackets every member in `[1, q - 2]` strictly. */
export function checkMember(member: Bytes32): Bytes32 {
  const value = checkedBytes<Bytes32>(member, 32, "member");
  if (bytesToBigInt(value) === 0n || bytesToBigInt(value) >= bytesToBigInt(FIELD_MAX))
    invalid("MemberOutOfRange");
  return value;
}

export function memberRecordHash(record: MemberRecord): Bytes32 {
  return poseidon([
    checkedBytes<Bytes32>(record.member, 32, "record member"),
    checkedBytes<Bytes32>(record.next, 32, "record next"),
    u64Field(record.lists, "lists"),
    mintPolicyField(record.mintPolicy),
    u64Field(record.mintPolicy.withdrawalThreshold, "withdrawal threshold"),
    ...assetLimitsFields(record.mintPolicy.limits),
  ]);
}

/** Little endian below `2^255 - 19` and nonzero, the Storage program refuses anything else at enrollment. */
export function checkedViewingU(viewingU: Bytes32): Bytes32 {
  const value = bytesToBigInt(
    Uint8Array.from(checkedBytes<Bytes32>(viewingU, 32, "viewing key")).reverse(),
  );
  if (value === 0n || value >= CURVE25519_FIELD)
    throw new RingError("RING_NONCANONICAL_VIEWING_KEY");
  return viewingU;
}

/** The pool of a key whose queries are all inactive, its canopy admits the zero record and binds no root, Rust `RecordPool::unopened`. */
export function unopenedRecordPool(openings: number): RecordPool {
  const levels = canopyLevels(openings);
  const siblings = Array.from({ length: QUAD_HEIGHT - levels }, () =>
    Object.freeze(Array.from({ length: QUAD_ARITY - 1 }, () => ZERO_32)),
  );
  const path: QuadPath = Object.freeze({ index: 0, siblings: Object.freeze(siblings) });
  const record: MemberRecord = Object.freeze({
    member: ZERO_32,
    next: ZERO_32,
    lists: 0n,
    mintPolicy: EMPTY_MINT_POLICY,
  });
  // Index 0 is the first child at every level, the fold lands at canopy position 0.
  let node = memberRecordHash(record);
  for (const level of siblings) node = poseidon([node, ...level]);
  const canopy = Array.from({ length: QUAD_ARITY ** levels }, (_, position) =>
    position === 0 ? node : ZERO_32,
  );
  return Object.freeze({
    records: Object.freeze(Array.from({ length: openings }, () => record)),
    canopy: Object.freeze(canopy),
    paths: Object.freeze(Array.from({ length: openings }, () => path)),
    subjects: Object.freeze(
      Array.from({ length: openings }, () => Object.freeze({ member: ZERO_32, recordIndex: 0 })),
    ),
  });
}

/** The root `leaf` folds to along `path`, Rust `QuadPath::root`. */
export function quadPathRoot(path: QuadPath, leaf: Bytes32): Bytes32 {
  checkedIndex(path.index);
  if (path.siblings.length !== QUAD_HEIGHT) invalid("PathHeight");
  let node = leaf;
  path.siblings.forEach((siblings, level) => {
    if (siblings.length !== QUAD_ARITY - 1) invalid("PathArity");
    const digit = (path.index >>> (2 * level)) & 3;
    const children = siblings.map((sibling) => checkedBytes<Bytes32>(sibling, 32, "sibling"));
    children.splice(digit, 0, node);
    node = poseidon(children);
  });
  return node;
}

/** The member's record under `root`, `undefined` for an absent member, Rust `RecordOpening::verify`. */
export function verifyRecordOpening(
  opening: RecordOpening,
  root: Bytes32,
  member: Bytes32,
): MemberRecord | undefined {
  checkMember(member);
  const leaf = opening.kind === "present" ? opening.record : opening.low;
  if (opening.kind === "present" ? !equalBytes(leaf.member, member) : !brackets(leaf, member))
    invalid("NotBracketed");
  if (!equalBytes(quadPathRoot(opening.path, memberRecordHash(leaf)), root))
    invalid("RootMismatch");
  return opening.kind === "present" ? opening.record : undefined;
}

/** A member's record, or the low record bracketing its absence, read under one root, Rust `MemberOpeningRead`. */
export class MemberOpeningRead {
  readonly opening: RingMemberOpening;

  private constructor(opening: RingMemberOpening) {
    this.opening = opening;
    Object.freeze(this);
  }

  /** `member`'s opening under `root`, refused unless its path reaches the root. */
  static verify(opening: RingMemberOpening, root: Bytes32, member: Bytes32): MemberOpeningRead {
    verifyRecordOpening(opening, root, member);
    return new MemberOpeningRead(opening);
  }

  /** `undefined` for an absent member. */
  record(): MemberRecord | undefined {
    return this.opening.kind === "present" ? this.opening.record : undefined;
  }

  listed(list: ListId): boolean {
    return ((this.record()?.lists ?? 0n) & recordBit(list)) !== 0n;
  }
}

/** Every member's read under `root`, each pool path folding through the canopy into `root`. */
export function verifyRecordPool(
  pool: Readonly<{
    records: readonly RingServedRecord[];
    canopy: readonly Bytes32[];
    subjects: readonly number[];
  }>,
  root: Bytes32,
  members: readonly Bytes32[],
  openings: number,
): readonly MemberOpeningRead[] {
  const levels = canopyLevels(openings);
  if (
    pool.canopy.length !== QUAD_ARITY ** levels ||
    pool.records.length < 1 ||
    pool.records.length > openings ||
    pool.subjects.length !== members.length
  )
    invalid("PoolShape");
  const canopy = [pool.canopy.map((node) => checkedBytes<Bytes32>(node, 32, "canopy"))];
  for (let level = 0; level < levels; level += 1) {
    const below = canopy[level] ?? [];
    canopy.push(
      Array.from({ length: below.length / QUAD_ARITY }, (_, parent) =>
        poseidon(below.slice(parent * QUAD_ARITY, (parent + 1) * QUAD_ARITY)),
      ),
    );
  }
  if (!equalBytes(canopy[levels]?.[0] ?? ZERO_32, root)) invalid("RootMismatch");
  const height = QUAD_HEIGHT - levels;
  const paths = pool.records.map(({ record, path }) => {
    if (path.siblings.length !== height) invalid("PathHeight");
    const full: QuadPath = {
      index: path.index,
      siblings: [
        ...path.siblings,
        ...canopy.slice(0, levels).map((nodes, level) => {
          const node = path.index >>> (2 * (height + level));
          const first = node - (node % QUAD_ARITY);
          return nodes
            .slice(first, first + QUAD_ARITY)
            .filter((_, child) => first + child !== node);
        }),
      ],
    };
    if (!equalBytes(quadPathRoot(full, memberRecordHash(record)), root)) invalid("RootMismatch");
    return full;
  });
  return members.map((member, subject) => {
    const at = pool.subjects[subject];
    const served = at === undefined ? undefined : pool.records[at];
    const path = at === undefined ? undefined : paths[at];
    if (served === undefined || path === undefined) invalid("SubjectIndex");
    const opening: RingMemberOpening = equalBytes(served.record.member, member)
      ? { kind: "present", record: served.record, path }
      : { kind: "absent", low: served.record, path };
    return MemberOpeningRead.verify(opening, root, member);
  });
}

export function recordWriteHash(entry: RecordWrite): Bytes32 {
  return poseidon([
    domainField(RingDomain.recordWrite),
    checkedBytes<Bytes32>(entry.member, 32, "entry member"),
    u64Field(entry.mask, "mask"),
    u64Field(entry.value, "value"),
    mintPolicyWriteField(entry.mintPolicy),
    u64Field(entry.mintPolicy?.withdrawalThreshold ?? 0n, "withdrawal threshold"),
    ...assetLimitsFields((entry.mintPolicy ?? EMPTY_MINT_POLICY).limits),
  ]);
}

/** `chain(p) = Poseidon(chain(p - 1), entry_p)` from `chain_start` of the registry and revision. */
export function writeChain(previous: Bytes32, entry: RecordWrite): Bytes32 {
  return poseidon([checkedBytes<Bytes32>(previous, 32, "chain"), recordWriteHash(entry)]);
}

/**
 * Replays `writes` from the registry state the indexer served, each step against the
 * running root as the apply circuit checks it, Rust `RecordTree::apply`.
 */
export function replayRecordWrites(
  input: Readonly<{
    oldRoot: Bytes32;
    oldNextIndex: number;
    chainStart: Bytes32;
    writes: readonly RecordWriteProofInput[];
  }>,
): ApplyProofInputs {
  let root = checkedBytes<Bytes32>(input.oldRoot, 32, "old root");
  let nextIndex = checkedNextIndex(input.oldNextIndex);
  let chain = checkedBytes<Bytes32>(input.chainStart, 32, "chain start");
  for (const write of input.writes) {
    checkEntry(write.entry);
    [root, nextIndex] = replayWrite(write, root, nextIndex);
    chain = writeChain(chain, write.entry);
  }
  return Object.freeze({
    oldRoot: copy(input.oldRoot),
    newRoot: root,
    oldNextIndex: input.oldNextIndex,
    newNextIndex: nextIndex,
    chainStart: copy(input.chainStart),
    chainEnd: chain,
    writes: Object.freeze([...input.writes]),
  });
}

/** Rust `ApplyProofInputs::statement` under `ApplyMode::Public`, a private list write refused. */
export function applyRecordsStatement(inputs: ApplyProofInputs): ApplyRecordsStatement {
  if (inputs.writes.some((write) => (write.entry.mask & BigInt(PRIVATE_LIST_BITS)) !== 0n))
    throw new RingError("RING_STORAGE_WRITE_INVALID", {
      details: { reason: "PrivateWriteWithoutTracking" },
    });
  // A count no apply key holds has no statement.
  applyKeyWidth(inputs.writes.length);
  return Object.freeze({
    oldRoot: inputs.oldRoot,
    newRoot: inputs.newRoot,
    oldNextIndex: inputs.oldNextIndex,
    newNextIndex: inputs.newNextIndex,
    chainStart: inputs.chainStart,
    chainEnd: inputs.chainEnd,
    count: BigInt(inputs.writes.length),
    restrictive: inputs.writes.some(restricts),
  });
}

/** Rust `RecordWriteProofInput::restricts` for a write on no private list. */
function restricts(write: RecordWriteProofInput): boolean {
  const { mask, value, mintPolicy } = write.entry;
  const grants = recordBit(ListId.allow) | recordBit(ListId.approval);
  const denies = recordBit(ListId.block) | recordBit(ListId.frozen);
  if ((write.oldLists & mask & ~value & grants) !== 0n || (value & ~write.oldLists & denies) !== 0n)
    return true;
  if (mintPolicy === undefined) return false;
  const old = write.oldMintPolicy;
  // A zero cap, cosign or withdrawal bound is no bound and orders above every amount.
  const bound = (amount: bigint) => (amount === 0n ? U64_MAX : amount - 1n);
  return (
    mintPolicy.threshold < old.threshold ||
    bound(mintPolicy.cap) < bound(old.cap) ||
    bound(mintPolicy.cosignAbove) < bound(old.cosignAbove) ||
    bound(mintPolicy.withdrawalThreshold) < bound(old.withdrawalThreshold) ||
    ASSET_LIMIT_KEYS.some((key) => mintPolicy.limits[key] !== old.limits[key])
  );
}

/** List bits outside the mask keep their value. */
function writtenRecord(record: MemberRecord, entry: RecordWrite): MemberRecord {
  return Object.freeze({
    ...record,
    lists: (record.lists & ~entry.mask & U64_MAX) | entry.value,
    mintPolicy: entry.mintPolicy ?? record.mintPolicy,
  });
}

function replayWrite(
  write: RecordWriteProofInput,
  root: Bytes32,
  nextIndex: number,
): readonly [Bytes32, number] {
  const { entry } = write;
  if (write.exists) {
    const record: MemberRecord = {
      member: entry.member,
      next: write.oldNext,
      lists: write.oldLists,
      mintPolicy: write.oldMintPolicy,
    };
    if (!equalBytes(quadPathRoot(write.slot, memberRecordHash(record)), root))
      invalid("RootMismatch");
    return [quadPathRoot(write.slot, memberRecordHash(writtenRecord(record, entry))), nextIndex];
  }
  const { low } = write;
  if (
    !brackets(low, entry.member) ||
    !equalBytes(write.oldNext, low.next) ||
    write.oldLists !== 0n ||
    !isEmptyMintPolicy(write.oldMintPolicy)
  )
    invalid("NotBracketed");
  if (!equalBytes(quadPathRoot(write.lowPath, memberRecordHash(low)), root))
    invalid("RootMismatch");
  const inserted = writtenRecord(
    {
      member: entry.member,
      next: low.next,
      lists: 0n,
      mintPolicy: EMPTY_MINT_POLICY,
    },
    entry,
  );
  // An empty record is never inserted, the write proves the absence and keeps the root.
  if (inserted.lists === 0n && isEmptyMintPolicy(inserted.mintPolicy)) {
    // The circuit range-checks a no-op's slot and nothing else.
    checkedIndex(write.slot.index);
    return [root, nextIndex];
  }
  if (nextIndex >= CAPACITY) throw new RingError("RING_REGISTRY_FULL");
  if (write.slot.index !== nextIndex) invalid("SlotIndex");
  const relinked = quadPathRoot(write.lowPath, memberRecordHash({ ...low, next: entry.member }));
  if (!equalBytes(quadPathRoot(write.slot, ZERO_32), relinked)) invalid("RootMismatch");
  return [quadPathRoot(write.slot, memberRecordHash(inserted)), nextIndex + 1];
}

/** An entry the program refuses fails before the first write. */
function checkEntry(entry: RecordWrite): void {
  checkMember(entry.member);
  checkedU64(entry.mask, "mask");
  if ((checkedU64(entry.value, "value") & ~entry.mask) !== 0n) invalid("ValueOutsideMask");
}

function brackets(record: MemberRecord, member: Bytes32): boolean {
  const value = bytesToBigInt(member);
  return bytesToBigInt(record.member) < value && value < bytesToBigInt(record.next);
}

function checkedIndex(index: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= CAPACITY) invalid("IndexOutOfRange");
}

function checkedNextIndex(index: number): number {
  if (!Number.isInteger(index) || index < 1 || index > CAPACITY) invalid("IndexOutOfRange");
  return index;
}

function u64Field(value: bigint, name: string): Bytes32 {
  return bigIntBytes(checkedU64(value, name)) as Bytes32;
}

function checkedU64(value: bigint, name: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "U64", name } });
  return value;
}

function invalid(reason: string): never {
  throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason } });
}
