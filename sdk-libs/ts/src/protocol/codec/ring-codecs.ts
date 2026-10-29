import { CUSTOM_RING_PROOF_LENGTH } from "../proof/custom-ring-proof.js";
import { Reader, encodeBase58, ZERO_32, equalBytes } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import { RING_RULE_SLOTS, RING_SOURCE_SLOTS } from "../../rpc/prover/types.js";
import {
  APPLY_BATCH,
  MEMBER_REGISTRY_CAPACITY,
  ROOT_HISTORY,
} from "../membership/member-registry.js";

import { RingError } from "../error.js";

/** Mirrors Rust `RingMode`, set once at creation and never cleared. */
export type RingMode = "confidential" | "confidentialEscrow" | "anonymous";

/** Rust `CustomRingConfig`, the ring's governance as its config account holds it. */
export interface RingProgramConfig {
  readonly authority: Address;
  readonly auditorPublicKey: X25519PublicKey;
  readonly bump: number;
  /** A policy ring enforces its table, an audit-only ring proves only the audit statement. */
  readonly hasPolicy: boolean;
  readonly mode: RingMode;
  /** `mode === "confidentialEscrow"`, every output nullifier key is escrowed in the registry. */
  readonly keyEscrow: boolean;
  /** Lamports a record write by a signer other than the authority pays the authority. */
  readonly insertFee: bigint;
  /** `RING_COSIGN_*` bits some `CoSigner` record covers, absent without a record. */
  readonly coSignerClasses?: number;
  readonly delegate?: Address;
  /** The slot `CreateConfig` ran in. */
  readonly createdSlot: bigint;
}

/** Rust `CustomRingCoSigner`, the signer's `CoSigner` record. */
export interface RingCoSigner {
  readonly signer: Address;
  /** `RING_COSIGN_*` bits. */
  readonly scope: number;
}

export const RING_COSIGN_TRANSFERS = 1;
export const RING_COSIGN_DEPOSITS = 2;
export const RING_COSIGN_WITHDRAWALS = 4;
export const RING_COSIGN_SCOPE_MASK = 7;

/** Rust `RootEntry`, `applied` the queue position the application reached. */
export interface RingRootEntry {
  readonly root: Bytes32;
  readonly applied: bigint;
  readonly slot: bigint;
}

/** Mirrors Rust `SourceSlot`, slot `i` is empty (`listId === 0`) or serves list `i + 1`. */
export interface RingSourceSlot {
  readonly listId: number;
  /** The curator's member registry account, the zero address for the ring's own. */
  readonly registry: Address;
}

/** Rust `EncodedRuleTable`, counted rows without their zero padding. */
export interface EncodedRuleTable {
  readonly rules: readonly Bytes32[];
}

/** Rust `MemberRegistry`, what every policy transfer reads of the ring's lists. */
export interface RingMemberRegistry {
  readonly bump: number;
  /** Slot of the newest root in `history`. */
  readonly historyCursor: number;
  /** The leaf the next insert takes. */
  readonly nextIndex: number;
  /** The applied position every own-ring root must reach. */
  readonly floor: bigint;
  readonly priorFloor: bigint;
  /** The slot of the last floor raise. */
  readonly floorSlot: bigint;
  /** `ROOT_HISTORY` slots, `undefined` where no root was pushed. */
  readonly history: readonly (RingRootEntry | undefined)[];
  /** Zero before the first policy write. */
  readonly policyHash: Bytes32;
  readonly sources: readonly RingSourceSlot[];
  readonly rules: EncodedRuleTable;
  readonly generation: number;
  readonly generationSlot: bigint;
}

/** Rust `Root` as a mirror copied it. */
export interface StorageRegistryRoot {
  readonly hash: Bytes32;
  readonly revision: bigint;
  /** Zero on the current root. */
  readonly expiresAt: bigint;
}

/** Rust `RootMirror`, newest first, `undefined` where the registry held no root. */
export interface RootMirror {
  /** Absent before the first `SyncRoots`. */
  readonly registry?: Address;
  readonly roots: readonly (StorageRegistryRoot | undefined)[];
}

/** Rust `RingPolicy`, the ring's table and the storage roots its transfers bind. */
export interface RingPolicy {
  readonly bump: number;
  /** The ring's own `StorageRegistry`. */
  readonly records: Address;
  /** Zero before the first policy write. */
  readonly policyHash: Bytes32;
  readonly sources: readonly RingSourceSlot[];
  readonly rules: EncodedRuleTable;
  readonly generation: number;
  readonly generationSlot: bigint;
  readonly ownRoots: RootMirror;
  readonly curatorRoots: RootMirror;
}

export type RootMirrorKind = "own" | "curator";

/** Rust `QueueCheckpoint`, `chain(p)` and the slot `p` was queued at. */
export interface RingQueueCheckpoint {
  readonly chain: Bytes32;
  readonly slot: bigint;
}

/** Rust `RecordQueue`, the chain checkpoints of the pending record writes. */
export interface RingRecordQueue {
  readonly bump: number;
  /** The position of the oldest pending write. */
  readonly head: bigint;
  /** The position the next write takes. */
  readonly tail: bigint;
  /** `chain(head - 1)`. */
  readonly chainHead: Bytes32;
  /** Position `p` sits at `p mod APPLY_BATCH`. */
  readonly checkpoints: readonly RingQueueCheckpoint[];
  /** The first slot a permissionless application may land in. */
  readonly nextApplySlot: bigint;
}

/** Rust `MEMBER_QUEUE_LIMIT`, the member share of the queue. */
export const MEMBER_QUEUE_LIMIT = 8n;
/** Rust `AUTHORITY_RESERVED_LEAVES`, the leaves only authority writes take. */
export const AUTHORITY_RESERVED_LEAVES = 1n << 16n;
/** Rust `APPLY_DELAY_SLOTS`, the age a queued write reaches before anyone may apply it. */
export const APPLY_DELAY_SLOTS = 150n;
/** Rust `GRACE_SLOTS`, the slots a curator root stays usable at the prior floor after a raise. */
export const GRACE_SLOTS = 750n;
/** Rust `DEFAULT_INSERT_FEE`, the lamports `CreateConfig` charges a member's record write. */
export const DEFAULT_INSERT_FEE = 1_000_000n;

const RING_MODES: readonly RingMode[] = ["confidential", "confidentialEscrow", "anonymous"];
export const RING_PROGRAM_CONFIG_DISCRIMINATOR = 10;
export const RING_PROGRAM_CONFIG_SIZE = 120;
export const RING_CO_SIGNER_DISCRIMINATOR = 14;
export const RING_CO_SIGNER_SIZE = 35;
const RING_COSIGN_CLASSES = [RING_COSIGN_TRANSFERS, RING_COSIGN_DEPOSITS, RING_COSIGN_WITHDRAWALS];
export const MEMBER_REGISTRY_DISCRIMINATOR = 11;
export const MEMBER_REGISTRY_SIZE = 2388;
export const RECORD_QUEUE_DISCRIMINATOR = 12;
export const RECORD_QUEUE_SIZE = 698;
export const RING_POLICY_DISCRIMINATOR = 13;
export const RING_POLICY_SIZE = 3991;

/** Mirrors Rust `CustomRingConfig::new` over `RingProgramConfig::valid`. */
export function decodeRingProgramConfig(data: Uint8Array): RingProgramConfig {
  const reader = accountReader(data, {
    discriminator: RING_PROGRAM_CONFIG_DISCRIMINATOR,
    size: RING_PROGRAM_CONFIG_SIZE,
    code: "RING_CONFIG_INVALID",
  });
  const authority = encodeBase58(reader.bytes(32, "authority"));
  const auditorPublicKey = auditorKey(reader.bytes(33, "auditorPubkey") as Bytes33);
  const bump = reader.u8("bump");
  const hasPolicy = reader.u8("hasPolicy");
  const modeByte = reader.u8("mode");
  const mode = RING_MODES[modeByte];
  const insertFee = reader.u64("insertFee");
  const counts = reader.bytes(RING_COSIGN_CLASSES.length, "coSigners");
  const delegate = reader.bytes(32, "delegate");
  const createdSlot = reader.u64("createdSlot");
  reader.done();
  if (mode === undefined || hasPolicy > 1)
    throw new RingError("RING_CONFIG_INVALID", {
      details: { mode: modeByte, hasPolicy },
    });
  const classes = RING_COSIGN_CLASSES.reduce(
    (covered, bit, index) => (counts[index] === 0 ? covered : covered | bit),
    0,
  );
  return Object.freeze({
    authority,
    auditorPublicKey,
    bump,
    hasPolicy: hasPolicy === 1,
    mode,
    keyEscrow: mode === "confidentialEscrow",
    insertFee,
    ...(classes === 0 ? {} : { coSignerClasses: classes }),
    ...(equalBytes(delegate, ZERO_32) ? {} : { delegate: encodeBase58(delegate) }),
    createdSlot,
  });
}

/** Mirrors Rust `CoSigner::valid`, a nonzero signer under a valid scope. */
export function decodeRingCoSigner(data: Uint8Array): RingCoSigner & Readonly<{ bump: number }> {
  const reader = accountReader(data, {
    discriminator: RING_CO_SIGNER_DISCRIMINATOR,
    size: RING_CO_SIGNER_SIZE,
    code: "RING_CO_SIGNER_INVALID",
  });
  const signer = reader.bytes(32, "signer");
  const scope = reader.u8("scope");
  const bump = reader.u8("bump");
  reader.done();
  if (equalBytes(signer, ZERO_32) || !validScope(scope))
    throw new RingError("RING_CO_SIGNER_INVALID", { details: { scope } });
  return Object.freeze({ signer: encodeBase58(signer), scope, bump });
}

/** Mirrors Rust `MemberRegistry::valid`, every rule row past its count zero. */
export function decodeRingMemberRegistry(data: Uint8Array): RingMemberRegistry {
  const reader = accountReader(data, {
    discriminator: MEMBER_REGISTRY_DISCRIMINATOR,
    size: MEMBER_REGISTRY_SIZE,
    code: "RING_MEMBER_REGISTRY_INVALID",
  });
  const bump = reader.u8("bump");
  const historyCursor = reader.u8("historyCursor");
  const nextIndex = reader.u32("nextIndex");
  const floor = reader.u64("floor");
  const priorFloor = reader.u64("priorFloor");
  const floorSlot = reader.u64("floorSlot");
  const history = Array.from({ length: ROOT_HISTORY }, () => {
    const root = reader.bytes(32, "history.root") as Bytes32;
    const applied = reader.u64("history.applied");
    const slot = reader.u64("history.slot");
    return equalBytes(root, ZERO_32) ? undefined : Object.freeze({ root, applied, slot });
  });
  const policy = readPolicyFields(reader, "RING_MEMBER_REGISTRY_INVALID");
  reader.done();
  if (historyCursor >= ROOT_HISTORY || BigInt(nextIndex) > MEMBER_REGISTRY_CAPACITY)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", {
      details: { historyCursor, nextIndex },
    });
  return Object.freeze({
    bump,
    historyCursor,
    nextIndex,
    floor,
    priorFloor,
    floorSlot,
    history: Object.freeze(history),
    ...policy,
  });
}

/** Mirrors Rust `RingPolicy::from_data`, every rule row past its count zero. */
export function decodeRingPolicy(data: Uint8Array): RingPolicy {
  const reader = accountReader(data, {
    discriminator: RING_POLICY_DISCRIMINATOR,
    size: RING_POLICY_SIZE,
    code: "RING_POLICY_INVALID",
  });
  const bump = reader.u8("bump");
  const records = encodeBase58(reader.bytes(32, "records"));
  const policy = readPolicyFields(reader, "RING_POLICY_INVALID");
  const ownRoots = readRootMirror(reader);
  const curatorRoots = readRootMirror(reader);
  reader.done();
  return Object.freeze({ bump, records, ...policy, ownRoots, curatorRoots });
}

/** Mirrors Rust `RecordQueue::valid`. */
export function decodeRingRecordQueue(data: Uint8Array): RingRecordQueue {
  const reader = accountReader(data, {
    discriminator: RECORD_QUEUE_DISCRIMINATOR,
    size: RECORD_QUEUE_SIZE,
    code: "RING_RECORD_QUEUE_INVALID",
  });
  const bump = reader.u8("bump");
  const head = reader.u64("head");
  const tail = reader.u64("tail");
  const chainHead = reader.bytes(32, "chainHead") as Bytes32;
  const checkpoints = Array.from({ length: APPLY_BATCH }, () =>
    Object.freeze({
      chain: reader.bytes(32, "checkpoint.chain") as Bytes32,
      slot: reader.u64("checkpoint.slot"),
    }),
  );
  const nextApplySlot = reader.u64("nextApplySlot");
  reader.done();
  if (head > tail || tail - head > BigInt(APPLY_BATCH))
    throw new RingError("RING_RECORD_QUEUE_INVALID", {
      details: { head, tail },
    });
  return Object.freeze({
    bump,
    head,
    tail,
    chainHead,
    checkpoints: Object.freeze(checkpoints),
    nextApplySlot,
  });
}

/** Rust `MemberRegistry::own_root`, the entry must reach the floor. */
export function registryOwnRoot(registry: RingMemberRegistry, index: number): RingRootEntry {
  const entry = registryEntry(registry, index);
  if (entry.applied < registry.floor)
    throw new RingError("RING_MEMBER_REGISTRY_STALE", {
      details: { reason: "RootBelowFloor", index },
    });
  return entry;
}

/** Rust `MemberRegistry::curator_root`, at the floor or inside the grace window at the prior floor. */
export function registryCuratorRoot(
  registry: RingMemberRegistry,
  index: number,
  slot: bigint,
): RingRootEntry {
  const entry = registryEntry(registry, index);
  const inGrace = slot < registry.floorSlot + GRACE_SLOTS;
  if (entry.applied >= registry.floor || (inGrace && entry.applied >= registry.priorFloor))
    return entry;
  throw new RingError("RING_MEMBER_REGISTRY_STALE", {
    details: { reason: "CuratorRootStale", index },
  });
}

/** Rust `MemberRegistry::current_root`, the root the next application starts from. */
export function registryCurrentRoot(registry: RingMemberRegistry): RingRootEntry {
  return registryEntry(registry, registry.historyCursor);
}

/** Rust `MemberRegistry::curator`, the one curator registry the sources name. */
export function registryCurator(
  registry: Pick<RingMemberRegistry, "sources">,
): Address | undefined {
  return registry.sources.find((source) => !isZeroAddress(source.registry))?.registry;
}

export function rootMirror(policy: RingPolicy, kind: RootMirrorKind): RootMirror {
  return kind === "own" ? policy.ownRoots : policy.curatorRoots;
}

/** Rust `RootMirror::root`, the current root or a retired one before its expiry. */
export function mirrorRoot(mirror: RootMirror, revision: bigint, slot: bigint): Bytes32 {
  const current = mirror.roots[0]?.revision;
  const root = mirror.roots.find(
    (entry) =>
      entry !== undefined &&
      entry.revision === revision &&
      (revision === current || slot < entry.expiresAt),
  );
  if (root === undefined)
    throw new RingError("RING_ROOT_NOT_MIRRORED", {
      details: { registry: mirror.registry, revision: revision.toString() },
    });
  return root.hash;
}

/** The newest root `SyncRoots` copied from `registry`, refused when the mirror holds another registry. */
export function mirrorCurrentRoot(mirror: RootMirror, registry: Address): StorageRegistryRoot {
  const current = mirror.roots[0];
  if (mirror.registry !== registry || current === undefined)
    throw new RingError("RING_ROOT_NOT_MIRRORED", {
      details: { registry, mirrored: mirror.registry },
    });
  return current;
}

/** Rust `RecordQueue::pending`. */
export function queuePending(queue: RingRecordQueue): bigint {
  return queue.tail - queue.head;
}

/** Rust `RecordQueue::chain_tail`, the chain an application of every pending write ends at. */
export function queueChainTail(queue: RingRecordQueue): Bytes32 {
  if (queuePending(queue) === 0n) return queue.chainHead;
  return queueCheckpoint(queue, queue.tail - 1n).chain;
}

/** Rust `RecordQueue::apply_due`, a permissionless application needs a full or aged queue. */
export function queueApplyDue(queue: RingRecordQueue, slot: bigint): boolean {
  const pending = queuePending(queue);
  if (pending === 0n) return false;
  const aged = slot >= queueCheckpoint(queue, queue.head).slot + APPLY_DELAY_SLOTS;
  return (pending >= MEMBER_QUEUE_LIMIT || aged) && slot >= queue.nextApplySlot;
}

/** Rust `RecordQueue::admit_member_write`, the member share of the queue and of the leaves. */
export function queueAdmitsMemberWrite(
  queue: RingRecordQueue,
  registry: RingMemberRegistry,
): "admitted" | "queueFull" | "authorityLeafReserve" {
  if (queuePending(queue) >= MEMBER_QUEUE_LIMIT) return "queueFull";
  const reserved = BigInt(registry.nextIndex) + queuePending(queue) + 1n;
  return reserved > MEMBER_REGISTRY_CAPACITY - AUTHORITY_RESERVED_LEAVES
    ? "authorityLeafReserve"
    : "admitted";
}

export { CUSTOM_RING_PROOF_LENGTH };

export function checkedCustomRingProof(proof: Uint8Array): Uint8Array {
  if (proof.length !== CUSTOM_RING_PROOF_LENGTH) {
    throw new RingError("RING_PROOF_LENGTH", {
      details: { expected: CUSTOM_RING_PROOF_LENGTH, actual: proof.length },
    });
  }
  return new Uint8Array(proof);
}

function accountReader(
  data: Uint8Array,
  account: Readonly<{
    discriminator: number;
    size: number;
    code: AccountInvalidCode;
  }>,
): Reader {
  if (data.length !== account.size || data[0] !== account.discriminator)
    throw new RingError(account.code, {
      details: { length: data.length, discriminator: data[0] },
    });
  const reader = new Reader(data);
  reader.u8("discriminator");
  return reader;
}

/** A key the program would refuse to encrypt to reads as an invalid config. */
function auditorKey(bytes: Bytes33): X25519PublicKey {
  try {
    return X25519PublicKey.fromBytes(bytes);
  } catch (cause) {
    throw new RingError("RING_CONFIG_INVALID", {
      details: { field: "auditorPubkey" },
      cause,
    });
  }
}

function validScope(scope: number): boolean {
  return scope !== 0 && (scope & ~RING_COSIGN_SCOPE_MASK) === 0;
}

type AccountInvalidCode =
  | "RING_CONFIG_INVALID"
  | "RING_MEMBER_REGISTRY_INVALID"
  | "RING_RECORD_QUEUE_INVALID"
  | "RING_CO_SIGNER_INVALID"
  | "RING_POLICY_INVALID";

/** Laid out alike in `MemberRegistry` and `RingPolicy`. */
function readPolicyFields(reader: Reader, code: AccountInvalidCode) {
  const policyHash = reader.bytes(32, "policyHash") as Bytes32;
  const sources = Array.from({ length: RING_SOURCE_SLOTS }, () =>
    Object.freeze({
      listId: reader.u8("source.listId"),
      registry: encodeBase58(reader.bytes(32, "source.registry")),
    }),
  );
  const rules = readEncodedRuleTable(reader, code);
  const generation = reader.u32("generation");
  const generationSlot = reader.u64("generationSlot");
  return { policyHash, sources: Object.freeze(sources), rules, generation, generationSlot };
}

function readRootMirror(reader: Reader): RootMirror {
  const registry = reader.bytes(32, "mirror.registry");
  const roots = Array.from({ length: ROOT_HISTORY }, () => {
    const hash = reader.bytes(32, "mirror.root") as Bytes32;
    const revision = reader.u64("mirror.revision");
    const expiresAt = reader.u64("mirror.expiresAt");
    return equalBytes(hash, ZERO_32) ? undefined : Object.freeze({ hash, revision, expiresAt });
  });
  return Object.freeze({
    ...(equalBytes(registry, ZERO_32) ? {} : { registry: encodeBase58(registry) }),
    roots: Object.freeze(roots),
  });
}

/** Mirrors Rust `EncodedRuleTable::decode`, every slot past a count zero. */
function readEncodedRuleTable(reader: Reader, code: AccountInvalidCode): EncodedRuleTable {
  const rules = countedRows(reader, RING_RULE_SLOTS, "rules", code);
  return Object.freeze({ rules });
}

function countedRows(
  reader: Reader,
  slots: number,
  field: string,
  code: AccountInvalidCode,
): readonly Bytes32[] {
  const count = reader.u8(`${field}.count`);
  if (count > slots) throw new RingError(code, { details: { field, count } });
  const rows = Array.from({ length: slots }, () => reader.bytes(32, field) as Bytes32);
  if (rows.slice(count).some((row) => !equalBytes(row, ZERO_32)))
    throw new RingError(code, { details: { field, padding: true } });
  return Object.freeze(rows.slice(0, count));
}

function registryEntry(registry: RingMemberRegistry, index: number): RingRootEntry {
  const entry = Number.isInteger(index) ? registry.history[index] : undefined;
  if (entry === undefined)
    throw new RingError("RING_MEMBER_REGISTRY_STALE", {
      details: { reason: "RootIndexEmpty", index },
    });
  return entry;
}

function queueCheckpoint(queue: RingRecordQueue, position: bigint): RingQueueCheckpoint {
  const checkpoint = queue.checkpoints[Number(position % BigInt(APPLY_BATCH))];
  if (checkpoint === undefined) throw new RingError("RING_RECORD_QUEUE_INVALID");
  return checkpoint;
}

function isZeroAddress(address: Address): boolean {
  return address === ZERO_ADDRESS;
}

const ZERO_ADDRESS = encodeBase58(ZERO_32);
