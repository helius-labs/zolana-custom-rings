import { ASSET_LIMIT_KEYS, type MintPolicy } from "../membership/mint-policy.js";
import type { Address } from "@heliuslabs/zolana";
import type { indexerTypes } from "@heliuslabs/zolana/internal";
import { U64_MAX, indexerCodec, indexerScalars } from "@heliuslabs/zolana/internal";

import {
  APPLY_BATCH,
  MEMBER_REGISTRY_CAPACITY,
  MEMBER_REGISTRY_ROOT_HISTORY,
  QUAD_ARITY,
  QUAD_HEIGHT,
  canopyLevels,
} from "../membership/member-registry.js";
import { MAX_RING_MEMBER_BATCH } from "./indexer-limits.js";
import type {
  RingApplyProofInputsRequest,
  RingApplyProofInputsResponse,
  RingMemberOpeningResponse,
  RingMemberOpeningView,
  RingMemberOpeningsRequest,
  RingMemberOpeningsResponse,
  RingMemberPageResponse,
  RingMemberProofRequest,
  RingMemberRecordView,
  RingMemberRecordsRequest,
  RingMemberRequest,
  RingRecordPathView,
  RingRecordPoolRequest,
  RingRecordPoolResponse,
  RingRecordQueueResponse,
  RingRecordWriteView,
  RingRegistryRootView,
  RingRegistryStateResponse,
  StorageApplyProofInputsRequest,
  StorageApplyProofInputsResponse,
  StorageMemberOpeningsRequest,
  StorageMemberOpeningsResponse,
  StorageRecordPoolRequest,
  StorageRecordPoolResponse,
  StorageRootView,
} from "./indexer-types.js";

const { array, context, object, toWireInteger, wireInteger } = indexerCodec;
const { checkedAddress, checkedBase64, checkedHash, schemaFailure } = indexerScalars;

type WireObject = Record<string, unknown>;
type Hash = indexerTypes.Hash;

/** No leading zero, no sign on zero, no exponent: one spelling per value. */
const DECIMAL_INTEGER = /^(?:0|-?[1-9][0-9]*)$/;

function boolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") {
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", path, "a boolean", value);
  }
  return value;
}

/** A slot, a JSON number or the decimal string an indexer sends past `2^53`. */
function unboundedU64(value: unknown, path: string): bigint {
  if (typeof value !== "string") return u64(value, path);
  if (!DECIMAL_INTEGER.test(value)) {
    return schemaFailure("INDEXER_SCHEMA_INVALID_INTEGER", path, "a decimal integer string", value);
  }
  const integer = BigInt(value);
  if (integer > U64_MAX) {
    return schemaFailure("INDEXER_SCHEMA_INVALID_INTEGER", path, "a u64", value);
  }
  return integer;
}

function u64(value: unknown, path: string): bigint {
  return wireInteger(value, path, 0n, U64_MAX);
}

function toU64(value: bigint, path: string): number {
  return toWireInteger(value, path, 0n, U64_MAX);
}

export function encodeRingMemberRequest(
  value: RingMemberRequest,
): Readonly<Record<string, unknown>> {
  return {
    ringProgramId: checkedAddress(value.ringProgramId, "ringProgramId"),
    member: checkedHash(value.member, "member"),
  };
}

export function encodeRingMemberProofRequest(
  value: RingMemberProofRequest,
): Readonly<Record<string, unknown>> {
  return {
    ...encodeRingMemberRequest(value),
    expectedRoot: checkedHash(value.expectedRoot, "expectedRoot"),
    expectedNextIndex: toWireInteger(
      value.expectedNextIndex,
      "expectedNextIndex",
      1n,
      MEMBER_REGISTRY_CAPACITY,
    ),
  };
}

export function encodeRingMemberRecordsRequest(value: RingMemberRecordsRequest): WireObject {
  return {
    ringProgramId: checkedAddress(value.ringProgramId, "ringProgramId"),
    expectedRoot: checkedHash(value.expectedRoot, "expectedRoot"),
    expectedNextIndex: toWireInteger(
      value.expectedNextIndex,
      "expectedNextIndex",
      1n,
      MEMBER_REGISTRY_CAPACITY,
    ),
    startIndex: toWireInteger(value.startIndex, "startIndex", 1n, value.expectedNextIndex),
    limit: toWireInteger(BigInt(value.limit), "limit", 1n, BigInt(MAX_RING_MEMBER_BATCH)),
  };
}

function memberFields(record: WireObject) {
  return {
    member: checkedHash(record["member"], "member"),
    next: checkedHash(record["next"], "next"),
    lists: wireInteger(record["lists"], "lists", 0n, (1n << 64n) - 1n),
    escrowKey: checkedHash(record["escrowKey"], "escrowKey"),
    mintPolicy: decodeMintPolicy(record["mintPolicy"]),
  };
}

function sealedMemberRecord(value: unknown, path: string): RingMemberRecordView {
  const record = object(value, path, [
    "member",
    "next",
    "lists",
    "escrowKey",
    "mintPolicy",
    "ownerPubkey",
    "nullifierPk",
    "ephPk",
    "ciphertext",
  ]);
  const ephPk = record["ephPk"] == null ? null : checkedBase64(record["ephPk"], `${path}.ephPk`);
  const ciphertext =
    record["ciphertext"] == null ? null : checkedBase64(record["ciphertext"], `${path}.ciphertext`);
  if ((ephPk === null) !== (ciphertext === null))
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", path, "paired sealed key", record);
  return {
    ...memberFields(record),
    ownerPubkey:
      record["ownerPubkey"] == null
        ? null
        : checkedAddress(record["ownerPubkey"], `${path}.ownerPubkey`),
    nullifierPk:
      record["nullifierPk"] == null
        ? null
        : checkedHash(record["nullifierPk"], `${path}.nullifierPk`),
    ephPk,
    ciphertext,
  };
}

/** `index` then `levels` levels of 3 siblings, leaf level first. */
function recordPath(value: unknown, path: string, levels = QUAD_HEIGHT): RingRecordPathView {
  const row = object(value, path, ["index", "siblings"]);
  const siblings = array(row["siblings"], `${path}.siblings`, (level, levelPath) => {
    const hashes = array(level, levelPath, checkedHash);
    if (hashes.length !== QUAD_ARITY - 1)
      return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", levelPath, "3 siblings", level);
    return hashes;
  });
  if (siblings.length !== levels)
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_TYPE",
      `${path}.siblings`,
      `${String(levels)} levels`,
      row["siblings"],
    );
  return {
    index: wireInteger(row["index"], `${path}.index`, 0n, MEMBER_REGISTRY_CAPACITY - 1n),
    siblings,
  };
}

function registryRoot(value: unknown, path: string): RingRegistryRootView {
  const row = object(value, path, ["root", "rootIndex", "applied", "nextIndex"]);
  return {
    root: checkedHash(row["root"], `${path}.root`),
    rootIndex: Number(
      wireInteger(
        row["rootIndex"],
        `${path}.rootIndex`,
        0n,
        BigInt(MEMBER_REGISTRY_ROOT_HISTORY - 1),
      ),
    ),
    applied: unboundedU64(row["applied"], `${path}.applied`),
    nextIndex: wireInteger(row["nextIndex"], `${path}.nextIndex`, 1n, MEMBER_REGISTRY_CAPACITY),
  };
}

function storageRoot(value: unknown, path: string): StorageRootView {
  const row = object(value, path, ["root", "revision", "nextIndex"]);
  return {
    root: checkedHash(row["root"], `${path}.root`),
    revision: unboundedU64(row["revision"], `${path}.revision`),
    nextIndex: wireInteger(row["nextIndex"], `${path}.nextIndex`, 1n, MEMBER_REGISTRY_CAPACITY),
  };
}

function memberOpening(value: unknown, path: string): RingMemberOpeningView {
  const row = object(value, path, ["present", "record", "path"]);
  return {
    present: boolean(row["present"], `${path}.present`),
    record: sealedMemberRecord(row["record"], `${path}.record`),
    path: recordPath(row["path"], `${path}.path`),
  };
}

/** The `getRingMemberRecord` response. */
export function decodeRingMemberOpening(value: unknown): RingMemberOpeningResponse {
  const row = object(value, "$", ["context", "root", "opening"]);
  return {
    context: context(row["context"], "context"),
    root: registryRoot(row["root"], "root"),
    opening: memberOpening(row["opening"], "opening"),
  };
}

export function encodeRingMemberOpeningsRequest(value: RingMemberOpeningsRequest): WireObject {
  return {
    ringProgramId: checkedAddress(value.ringProgramId, "ringProgramId"),
    ...openingsFields(value),
  };
}

/** Rust `GetStorageMemberOpeningsRequest`. */
export function encodeStorageMemberOpeningsRequest(
  value: StorageMemberOpeningsRequest,
): WireObject {
  return { registry: checkedAddress(value.registry, "registry"), ...openingsFields(value) };
}

function openingsFields(value: Readonly<{ members: readonly Hash[]; expectedRoot: Hash }>) {
  const members: unknown = value.members;
  if (!Array.isArray(members) || members.length < 1 || members.length > MAX_RING_MEMBER_BATCH)
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_TYPE",
      "$.members",
      `1 to ${String(MAX_RING_MEMBER_BATCH)} members`,
      members,
    );
  return {
    members: members.map((member, index) => checkedHash(member, `$.members[${String(index)}]`)),
    expectedRoot: checkedHash(value.expectedRoot, "expectedRoot"),
  };
}

export function decodeRingMemberOpenings(value: unknown): RingMemberOpeningsResponse {
  return decodeOpenings(value, registryRoot);
}

/** Rust `GetStorageMemberOpeningsResponse`. */
export function decodeStorageMemberOpenings(value: unknown): StorageMemberOpeningsResponse {
  return decodeOpenings(value, storageRoot);
}

function decodeOpenings<Root>(value: unknown, root: (value: unknown, path: string) => Root) {
  const row = object(value, "$", ["context", "root", "openings"]);
  return {
    context: context(row["context"], "context"),
    root: root(row["root"], "root"),
    openings: array(row["openings"], "openings", memberOpening),
  };
}

export function encodeRingRecordPoolRequest(value: RingRecordPoolRequest): WireObject {
  return { ...encodeRingMemberOpeningsRequest(value), ...poolOpenings(value) };
}

/** Rust `GetStorageRecordPoolRequest`. */
export function encodeStorageRecordPoolRequest(value: StorageRecordPoolRequest): WireObject {
  return { ...encodeStorageMemberOpeningsRequest(value), ...poolOpenings(value) };
}

function poolOpenings(value: Readonly<{ members: readonly Hash[]; openings: number }>) {
  const openings = toWireInteger(
    BigInt(value.openings),
    "openings",
    1n,
    BigInt(MAX_RING_MEMBER_BATCH),
  );
  if (value.members.length > openings)
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_TYPE",
      "$.members",
      `at most ${String(openings)} members`,
      value.members,
    );
  return { openings };
}

/** The `getRingRecordPool` response, its canopy width fixing the path height. */
export function decodeRingRecordPool(value: unknown): RingRecordPoolResponse {
  return decodeRecordPool(value, registryRoot);
}

/** Rust `GetStorageRecordPoolResponse`. */
export function decodeStorageRecordPool(value: unknown): StorageRecordPoolResponse {
  return decodeRecordPool(value, storageRoot);
}

function decodeRecordPool<Root>(value: unknown, root: (value: unknown, path: string) => Root) {
  const row = object(value, "$", ["context", "root", "records", "canopy", "subjects"]);
  const canopy = array(row["canopy"], "canopy", checkedHash);
  const levels = canopyLevels(canopy.length);
  if (canopy.length !== QUAD_ARITY ** levels)
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", "canopy", "a power of 4", row["canopy"]);
  const records = array(row["records"], "records", (entry, path) => {
    const item = object(entry, path, ["record", "path"]);
    return {
      record: sealedMemberRecord(item["record"], `${path}.record`),
      path: recordPath(item["path"], `${path}.path`, QUAD_HEIGHT - levels),
    };
  });
  if (records.length > MAX_RING_MEMBER_BATCH)
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_TYPE",
      "records",
      `at most ${String(MAX_RING_MEMBER_BATCH)}`,
      row["records"],
    );
  return {
    context: context(row["context"], "context"),
    root: root(row["root"], "root"),
    records,
    canopy,
    subjects: array(row["subjects"], "subjects", (index, path) =>
      Number(wireInteger(index, path, 0n, BigInt(MAX_RING_MEMBER_BATCH - 1))),
    ),
  };
}

/** The `getRingMemberRecords` response. */
export function decodeRingMemberPage(value: unknown): RingMemberPageResponse {
  const row = object(value, "$", ["context", "root", "records", "nextLeafIndex"]);
  const root = registryRoot(row["root"], "root");
  const records = array(row["records"], "records", (entry, path) => {
    const item = object(entry, path, ["record", "path"]);
    return {
      record: sealedMemberRecord(item["record"], `${path}.record`),
      path: recordPath(item["path"], `${path}.path`),
    };
  });
  if (records.length > MAX_RING_MEMBER_BATCH)
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_TYPE",
      "records",
      `at most ${String(MAX_RING_MEMBER_BATCH)}`,
      row["records"],
    );
  return {
    context: context(row["context"], "context"),
    root,
    records,
    nextLeafIndex:
      row["nextLeafIndex"] === null
        ? null
        : wireInteger(row["nextLeafIndex"], "nextLeafIndex", 1n, root.nextIndex),
  };
}

/** The `getRingMemberRegistryRoot` response. */
export function decodeRingRegistryState(value: unknown): RingRegistryStateResponse {
  const row = object(value, "$", [
    "context",
    "history",
    "historyCursor",
    "nextIndex",
    "floor",
    "priorFloor",
    "floorSlot",
    "appendPath",
  ]);
  const history = array(row["history"], "history", (entry, path) => {
    if (entry === null) return null;
    const item = object(entry, path, ["root", "applied", "slot"]);
    return {
      root: checkedHash(item["root"], `${path}.root`),
      applied: unboundedU64(item["applied"], `${path}.applied`),
      slot: unboundedU64(item["slot"], `${path}.slot`),
    };
  });
  if (history.length !== MEMBER_REGISTRY_ROOT_HISTORY)
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_TYPE",
      "history",
      `${String(MEMBER_REGISTRY_ROOT_HISTORY)} entries`,
      row["history"],
    );
  return {
    context: context(row["context"], "context"),
    history,
    historyCursor: Number(
      wireInteger(
        row["historyCursor"],
        "historyCursor",
        0n,
        BigInt(MEMBER_REGISTRY_ROOT_HISTORY - 1),
      ),
    ),
    nextIndex: wireInteger(row["nextIndex"], "nextIndex", 1n, MEMBER_REGISTRY_CAPACITY),
    floor: unboundedU64(row["floor"], "floor"),
    priorFloor: unboundedU64(row["priorFloor"], "priorFloor"),
    floorSlot: unboundedU64(row["floorSlot"], "floorSlot"),
    appendPath: row["appendPath"] === null ? null : recordPath(row["appendPath"], "appendPath"),
  };
}

export function decodeRingRecordQueue(value: unknown): RingRecordQueueResponse {
  const row = object(value, "$", ["context", "head", "tail", "chainHead", "entries"]);
  const head = unboundedU64(row["head"], "head");
  const tail = unboundedU64(row["tail"], "tail");
  const entries = array(row["entries"], "entries", (entry, path) => {
    const item = object(entry, path, [
      "position",
      "member",
      "mask",
      "value",
      "escrowKey",
      "mintPolicy",
      "slot",
    ]);
    return {
      position: unboundedU64(item["position"], `${path}.position`),
      member: checkedHash(item["member"], `${path}.member`),
      mask: u64(item["mask"], `${path}.mask`),
      value: u64(item["value"], `${path}.value`),
      escrowKey: checkedHash(item["escrowKey"], `${path}.escrowKey`),
      mintPolicy: item["mintPolicy"] == null ? null : decodeMintPolicy(item["mintPolicy"]),
      slot: unboundedU64(item["slot"], `${path}.slot`),
    };
  });
  if (
    tail < head ||
    tail - head > BigInt(APPLY_BATCH) ||
    BigInt(entries.length) !== tail - head ||
    entries.some((entry, index) => entry.position !== head + BigInt(index))
  )
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_TYPE",
      "entries",
      "positions head..tail",
      row["entries"],
    );
  return {
    context: context(row["context"], "context"),
    head,
    tail,
    chainHead: checkedHash(row["chainHead"], "chainHead"),
    entries,
  };
}

export function encodeRingApplyProofInputsRequest(value: RingApplyProofInputsRequest): WireObject {
  return {
    ringProgramId: checkedAddress(value.ringProgramId, "ringProgramId"),
    authorityWrites: value.authorityWrites.map((write, index) => {
      const path = `$.authorityWrites[${String(index)}]`;
      return {
        member: checkedHash(write.member, `${path}.member`),
        mask: toU64(write.mask, `${path}.mask`),
        value: toU64(write.value, `${path}.value`),
        mintPolicy: encodeMintPolicy(write.mintPolicy),
      };
    }),
  };
}

/** Rust `GetStorageApplyProofInputsRequest`, each write in Rust `StorageWriteView` order. */
export function encodeStorageApplyProofInputsRequest(
  value: StorageApplyProofInputsRequest,
): WireObject {
  return {
    registry: checkedAddress(value.registry, "registry"),
    writes: value.writes.map((write, index) => {
      const path = `$.writes[${String(index)}]`;
      return {
        member: checkedHash(write.member, `${path}.member`),
        mask: toU64(write.mask, `${path}.mask`),
        value: toU64(write.value, `${path}.value`),
        escrowKey: checkedHash(write.escrowKey, `${path}.escrowKey`),
        mintPolicy: encodeMintPolicy(write.mintPolicy),
      };
    }),
  };
}

/** Rust `MintPolicy` in its field order, `null` keeps the stored settings. */
export function encodeMintPolicy(policy: MintPolicy | null): WireObject | null {
  return policy === null
    ? null
    : {
        threshold: toU64(policy.threshold, "threshold"),
        cap: toU64(policy.cap, "cap"),
        cosignAbove: toU64(policy.cosignAbove, "cosignAbove"),
        withdrawalThreshold: toU64(policy.withdrawalThreshold, "withdrawalThreshold"),
        limits: Object.fromEntries(
          ASSET_LIMIT_KEYS.map((key) => [key, toU64(policy.limits[key], `limits.${key}`)]),
        ),
      };
}

export function decodeRingApplyProofInputs(value: unknown): RingApplyProofInputsResponse {
  return applyProofInputs(object(value, "$", APPLY_FIELDS));
}

/** Rust `GetStorageApplyProofInputsResponse`. */
export function decodeStorageApplyProofInputs(value: unknown): StorageApplyProofInputsResponse {
  const row = object(value, "$", ["revision", ...APPLY_FIELDS]);
  return { ...applyProofInputs(row), revision: unboundedU64(row["revision"], "revision") };
}

const APPLY_FIELDS = [
  "context",
  "oldRoot",
  "newRoot",
  "oldNextIndex",
  "newNextIndex",
  "chainStart",
  "chainEnd",
  "writes",
] as const;

function applyProofInputs(row: WireObject): RingApplyProofInputsResponse {
  return {
    context: context(row["context"], "context"),
    oldRoot: checkedHash(row["oldRoot"], "oldRoot"),
    newRoot: checkedHash(row["newRoot"], "newRoot"),
    oldNextIndex: wireInteger(row["oldNextIndex"], "oldNextIndex", 1n, MEMBER_REGISTRY_CAPACITY),
    newNextIndex: wireInteger(row["newNextIndex"], "newNextIndex", 1n, MEMBER_REGISTRY_CAPACITY),
    chainStart: checkedHash(row["chainStart"], "chainStart"),
    chainEnd: checkedHash(row["chainEnd"], "chainEnd"),
    writes: array(row["writes"], "writes", recordWrite),
  };
}

function recordWrite(entry: unknown, path: string): RingRecordWriteView {
  const item = object(entry, path, [
    "member",
    "mask",
    "value",
    "escrowKey",
    "mintPolicy",
    "exists",
    "oldNext",
    "oldLists",
    "oldEscrow",
    "oldMintPolicy",
    "slot",
    "low",
    "lowPath",
  ]);
  return {
    member: checkedHash(item["member"], `${path}.member`),
    mask: u64(item["mask"], `${path}.mask`),
    value: u64(item["value"], `${path}.value`),
    escrowKey: checkedHash(item["escrowKey"], `${path}.escrowKey`),
    mintPolicy: item["mintPolicy"] == null ? null : decodeMintPolicy(item["mintPolicy"]),
    exists: boolean(item["exists"], `${path}.exists`),
    oldNext: checkedHash(item["oldNext"], `${path}.oldNext`),
    oldLists: unboundedU64(item["oldLists"], `${path}.oldLists`),
    oldEscrow: checkedHash(item["oldEscrow"], `${path}.oldEscrow`),
    oldMintPolicy: decodeMintPolicy(item["oldMintPolicy"]),
    slot: recordPath(item["slot"], `${path}.slot`),
    low: sealedMemberRecord(item["low"], `${path}.low`),
    lowPath: recordPath(item["lowPath"], `${path}.lowPath`),
  };
}

export function encodeRingMemberRegistryRootRequest(
  value: Readonly<{ ringProgramId: Address }>,
): WireObject {
  return { ringProgramId: checkedAddress(value.ringProgramId, "ringProgramId") };
}

function decodeMintPolicy(value: unknown): MintPolicy {
  const row = object(value, "mintPolicy", [
    "threshold",
    "cap",
    "cosignAbove",
    "withdrawalThreshold",
    "limits",
  ]);
  const amount = (from: WireObject, key: string): bigint =>
    wireInteger(from[key], `mintPolicy.${key}`, 0n, (1n << 64n) - 1n);
  const limits = object(row["limits"], "mintPolicy.limits", ASSET_LIMIT_KEYS);
  return Object.freeze({
    threshold: amount(row, "threshold"),
    cap: amount(row, "cap"),
    cosignAbove: amount(row, "cosignAbove"),
    withdrawalThreshold: amount(row, "withdrawalThreshold"),
    limits: Object.freeze({
      senderCap: amount(limits, "senderCap"),
      senderWindowSlots: amount(limits, "senderWindowSlots"),
      volumeCap: amount(limits, "volumeCap"),
      volumeWindowSlots: amount(limits, "volumeWindowSlots"),
      depositCap: amount(limits, "depositCap"),
      depositWindowSlots: amount(limits, "depositWindowSlots"),
      withdrawalCap: amount(limits, "withdrawalCap"),
      withdrawalWindowSlots: amount(limits, "withdrawalWindowSlots"),
    }),
  });
}
