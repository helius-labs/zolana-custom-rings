/** The per-ring tracking registry, Rust `custom_ring_interface::tracking`. */
import { hexToBytes } from "@noble/hashes/utils.js";
import type { Address } from "@solana/kit";

import {
  checkedBytes,
  encodeBase58,
  equalBytes,
  poseidon,
  Reader,
  ZERO_32,
} from "@heliuslabs/spr/internal";
import type { Bytes32, Bytes33, Bytes64 } from "@heliuslabs/spr/interface";

import { domainField, RingDomain } from "../../crypto/derivation/ring-domain.js";
import { RingError } from "../error.js";
import type { StorageRegistryRoot } from "../codec/ring-codecs.js";
import {
  QUAD_ARITY,
  ROOT_HISTORY,
  canopyLevels,
  type PoolSubject,
  type QuadPath,
} from "./member-registry.js";
import { FIELD_MAX } from "./member-opening.js";

export const TRACKING_QUAD_HEIGHT = 16;
export const TRACKING_CAPACITY = 1n << BigInt(2 * TRACKING_QUAD_HEIGHT);
export const TRACKING_GRACE_SLOTS = 750n;
/** The sentinel at leaf 0 under zero subtrees. */
export const TRACKING_EMPTY_ROOT = hexToBytes(
  "2425fb189630d5f84bcc34f42804377d8564a55959c92ad1fa6fee86a590614e",
) as Bytes32;

const REGISTRY_DISCRIMINATOR = 3;
const AUTHORIZATION_DISCRIMINATOR = 4;
const OWNER_GRANT_DISCRIMINATOR = 5;
const REGISTRY_SIZE = 1610;
const AUTHORIZATION_SIZE = 258;
const OWNER_GRANT_SIZE = 2;

export interface TrackingRegistry {
  readonly ringId: Bytes32;
  readonly auditorPubkey: Bytes33;
  /** At most `TRACKING_CAPACITY`, the last leaf index is `TRACKING_CAPACITY - 1`. */
  readonly nextIndex: bigint;
  /** Newest first. */
  readonly roots: readonly (StorageRegistryRoot | undefined)[];
}

export interface TrackingAuthorization {
  readonly registry: Address;
  readonly owner: Address;
  readonly nullifierPk: Bytes32;
  readonly listTag: Bytes32;
  readonly viewingU: Bytes32;
  readonly ephU: Bytes32;
  readonly ciphertext: Bytes64;
  /** Set once an apply inserts the owner's row, a rotation leaves it. */
  readonly applied: boolean;
}

/** The address names the registry, the owner and the reader. */
export interface OwnerGrant {
  readonly active: boolean;
}

/** The write an apply proof chains, the program computes it from the owner's account. */
export interface TrackingEntry {
  readonly member: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly ctHash: Bytes32;
  readonly listTag: Bytes32;
}

export interface TrackingRecord extends TrackingEntry {
  readonly next: Bytes32;
}

/** A member under one root, its row or the low row bracketing its absence. */
export type TrackingOpening =
  | Readonly<{ kind: "present"; record: TrackingRecord; path: QuadPath }>
  | Readonly<{ kind: "absent"; low: TrackingRecord; path: QuadPath }>;

export const TRACKING_SENTINEL: TrackingRecord = Object.freeze({
  member: ZERO_32,
  next: FIELD_MAX,
  nullifierPk: ZERO_32,
  ctHash: ZERO_32,
  listTag: ZERO_32,
});

export function decodeTrackingRegistry(data: Uint8Array): TrackingRegistry {
  const reader = account(data, REGISTRY_DISCRIMINATOR, REGISTRY_SIZE, "RING_TRACKING_INVALID");
  const ringId = reader.bytes(32, "ringId") as Bytes32;
  const auditorPubkey = reader.bytes(33, "auditorPubkey") as Bytes33;
  const nextIndex = reader.u64("nextIndex");
  const roots = Array.from({ length: ROOT_HISTORY }, () => {
    const hash = reader.bytes(32, "root.hash") as Bytes32;
    const revision = reader.u64("root.revision");
    const expiresAt = reader.u64("root.expiresAt");
    return equalBytes(hash, ZERO_32) ? undefined : Object.freeze({ hash, revision, expiresAt });
  });
  reader.done();
  if (nextIndex < 1n || nextIndex > TRACKING_CAPACITY)
    throw new RingError("RING_TRACKING_INVALID", { details: { nextIndex: nextIndex.toString() } });
  return Object.freeze({
    ringId,
    auditorPubkey,
    nextIndex,
    roots: Object.freeze(roots),
  });
}

export function decodeTrackingAuthorization(data: Uint8Array): TrackingAuthorization {
  const reader = account(
    data,
    AUTHORIZATION_DISCRIMINATOR,
    AUTHORIZATION_SIZE,
    "RING_TRACKING_INVALID",
  );
  const authorization = Object.freeze({
    registry: encodeBase58(reader.bytes(32, "registry")),
    owner: encodeBase58(reader.bytes(32, "owner")),
    nullifierPk: reader.bytes(32, "nullifierPk") as Bytes32,
    listTag: reader.bytes(32, "listTag") as Bytes32,
    viewingU: reader.bytes(32, "viewingU") as Bytes32,
    ephU: reader.bytes(32, "ephU") as Bytes32,
    ciphertext: reader.bytes(64, "ciphertext") as Bytes64,
    applied: reader.u8("applied") !== 0,
  });
  reader.done();
  return authorization;
}

export function decodeOwnerGrant(data: Uint8Array): OwnerGrant {
  const reader = account(
    data,
    OWNER_GRANT_DISCRIMINATOR,
    OWNER_GRANT_SIZE,
    "RING_TRACKING_INVALID",
  );
  const grant = Object.freeze({
    active: reader.u8("active") === 1,
  });
  reader.done();
  return grant;
}

export function isEnrollmentPending(authorization: TrackingAuthorization): boolean {
  return !authorization.applied;
}

/** `Poseidon(CRTQ, member, nullifier_pk, ct_hash, list_tag)`. */
export function trackingEntryHash(entry: TrackingEntry): Bytes32 {
  return poseidon([
    domainField(RingDomain.trackingEntry),
    checkedBytes<Bytes32>(entry.member, 32, "member"),
    checkedBytes<Bytes32>(entry.nullifierPk, 32, "nullifier pk"),
    checkedBytes<Bytes32>(entry.ctHash, 32, "ct hash"),
    checkedBytes<Bytes32>(entry.listTag, 32, "list tag"),
  ]) as Bytes32;
}

/** `Poseidon(previous, entry)`. */
export function trackingEntryChained(previous: Bytes32, entry: TrackingEntry): Bytes32 {
  return poseidon([
    checkedBytes<Bytes32>(previous, 32, "chain"),
    trackingEntryHash(entry),
  ]) as Bytes32;
}

/** `Poseidon(CRTK, member, next, nullifier_pk, ct_hash, list_tag)`. */
export function trackingRecordHash(record: TrackingRecord): Bytes32 {
  return poseidon([
    domainField(RingDomain.trackingLeaf),
    checkedBytes<Bytes32>(record.member, 32, "member"),
    checkedBytes<Bytes32>(record.next, 32, "next"),
    checkedBytes<Bytes32>(record.nullifierPk, 32, "nullifier pk"),
    checkedBytes<Bytes32>(record.ctHash, 32, "ct hash"),
    checkedBytes<Bytes32>(record.listTag, 32, "list tag"),
  ]) as Bytes32;
}

/** The member's row under `root`, `undefined` proves it unenrolled there. */
export function verifyTrackingOpening(
  opening: TrackingOpening,
  root: Bytes32,
  member: Bytes32,
): TrackingRecord | undefined {
  const leaf = opening.kind === "present" ? opening.record : opening.low;
  const held =
    opening.kind === "present"
      ? equalBytes(leaf.member, member)
      : fieldBelow(leaf.member, member) && fieldBelow(member, leaf.next);
  if (!held) throw invalid("NotBracketed");
  if (!equalBytes(trackingPathRoot(opening.path, trackingRecordHash(leaf)), root))
    throw invalid("RootMismatch");
  return opening.kind === "present" ? opening.record : undefined;
}

/** A leaf the indexer served, its path cut at the canopy. */
export interface ServedTrackingRecord {
  readonly record: TrackingRecord;
  readonly path: QuadPath;
}

/** Rust `GetTrackingRecordPoolResponse`, unverified until `verifyTrackingPool` checks it. */
export interface ServedTrackingPool {
  /** Distinct leaves in first use order. */
  readonly records: readonly ServedTrackingRecord[];
  readonly canopy: readonly Bytes32[];
  /** `subjects[i]` indexes the record holding or bracketing member `i`. */
  readonly subjects: readonly number[];
}

/** A tracking pool at its capacity, records and subjects repeating cyclically. */
export interface VerifiedTrackingPool {
  readonly records: readonly TrackingRecord[];
  readonly canopy: readonly Bytes32[];
  readonly paths: readonly QuadPath[];
  readonly subjects: readonly PoolSubject[];
  /** Each member's row in member order, `undefined` proves it unenrolled under the root. */
  readonly rows: readonly (TrackingRecord | undefined)[];
}

/** Every member's read under `root`, each pool path folding through the canopy into `root`. */
export function verifyTrackingPool(
  input: Readonly<{
    pool: ServedTrackingPool;
    root: Bytes32;
    members: readonly Bytes32[];
    openings: number;
  }>,
): VerifiedTrackingPool {
  const { pool, root, members, openings } = input;
  const levels = canopyLevels(openings);
  if (
    pool.canopy.length !== QUAD_ARITY ** levels ||
    pool.records.length < 1 ||
    pool.records.length > openings ||
    pool.subjects.length !== members.length ||
    members.length > openings
  )
    throw invalid("PoolShape");
  const canopy: Bytes32[][] = [
    pool.canopy.map((node) => checkedBytes<Bytes32>(node, 32, "canopy")),
  ];
  for (let level = 0; level < levels; level += 1) {
    const below = canopy[level] ?? [];
    canopy.push(
      Array.from(
        { length: below.length / QUAD_ARITY },
        (_, parent) =>
          poseidon(below.slice(parent * QUAD_ARITY, (parent + 1) * QUAD_ARITY)) as Bytes32,
      ),
    );
  }
  const height = TRACKING_QUAD_HEIGHT - levels;
  const fullPaths = pool.records.map(({ path }): QuadPath => {
    if (path.siblings.length !== height) throw invalid("PathHeight");
    return {
      index: path.index,
      siblings: [
        ...path.siblings,
        ...canopy.slice(0, levels).map((nodes, level) => {
          const node = Math.floor(path.index / QUAD_ARITY ** (height + level));
          const first = node - (node % QUAD_ARITY);
          return nodes
            .slice(first, first + QUAD_ARITY)
            .filter((_, child) => first + child !== node);
        }),
      ],
    };
  });
  const rows = members.map((member, subject) => {
    const at = pool.subjects[subject];
    const served = at === undefined ? undefined : pool.records[at];
    const path = at === undefined ? undefined : fullPaths[at];
    if (served === undefined || path === undefined) throw invalid("SubjectIndex");
    const opening: TrackingOpening = equalBytes(served.record.member, member)
      ? { kind: "present", record: served.record, path }
      : { kind: "absent", low: served.record, path };
    return verifyTrackingOpening(opening, root, member);
  });
  const records = cyclic(pool.records, openings);
  return Object.freeze({
    records: Object.freeze(records.map(({ record }) => record)),
    canopy: Object.freeze([...pool.canopy]),
    paths: Object.freeze(records.map(({ path }) => path)),
    subjects: Object.freeze(
      cyclic(
        members.map((member, index) =>
          Object.freeze({ member, recordIndex: pool.subjects[index] ?? 0 }),
        ),
        openings,
      ),
    ),
    rows: Object.freeze(rows),
  });
}

function cyclic<T>(values: readonly T[], length: number): readonly T[] {
  return Array.from({ length }, (_, index) => values[index % values.length] as T);
}

function trackingPathRoot(path: QuadPath, leaf: Bytes32): Bytes32 {
  if (path.siblings.length !== TRACKING_QUAD_HEIGHT) throw invalid("PathHeight");
  if (
    !Number.isSafeInteger(path.index) ||
    path.index < 0 ||
    BigInt(path.index) >= TRACKING_CAPACITY
  )
    throw invalid("PathIndex");
  let node = leaf;
  path.siblings.forEach((siblings, level) => {
    if (siblings.length !== QUAD_ARITY - 1) throw invalid("PathArity");
    const digit = Math.floor(path.index / QUAD_ARITY ** level) % QUAD_ARITY;
    const children = siblings.map((sibling) => checkedBytes<Bytes32>(sibling, 32, "sibling"));
    children.splice(digit, 0, node);
    node = poseidon(children) as Bytes32;
  });
  return node;
}

function fieldBelow(left: Bytes32, right: Bytes32): boolean {
  for (let at = 0; at < 32; at += 1) {
    const difference = (left[at] ?? 0) - (right[at] ?? 0);
    if (difference !== 0) return difference < 0;
  }
  return false;
}

function account(
  data: Uint8Array,
  discriminator: number,
  size: number,
  code: "RING_TRACKING_INVALID",
): Reader {
  if (data.length !== size || data[0] !== discriminator)
    throw new RingError(code, { details: { length: data.length, discriminator: data[0] } });
  const reader = new Reader(data);
  reader.u8("discriminator");
  return reader;
}

function invalid(reason: string): RingError {
  return new RingError("RING_TRACKING_INVALID", { details: { reason } });
}
