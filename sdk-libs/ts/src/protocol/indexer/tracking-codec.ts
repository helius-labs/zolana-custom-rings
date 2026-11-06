/** Rust `zolana_ring_indexer::tracking`. */
import { indexerCodec, indexerScalars, type MethodDescriptor } from "@heliuslabs/spr/internal";
import type { Address, Bytes32 } from "@heliuslabs/spr/interface";

import { QUAD_ARITY, type QuadPath } from "../membership/member-registry.js";
import {
  TRACKING_CAPACITY,
  TRACKING_QUAD_HEIGHT,
  type ServedTrackingPool,
  type TrackingOpening,
  type TrackingRecord,
} from "../membership/tracking.js";
import { MAX_RING_MEMBER_BATCH } from "./indexer-limits.js";

const { array, context, object, wireInteger } = indexerCodec;
const { checkedAddress, checkedBase64, checkedHash, hash, hashBytes, schemaFailure } =
  indexerScalars;

const U64_MAX = (1n << 64n) - 1n;

export interface TrackingOpeningsRequest {
  readonly registry: Address;
  readonly members: readonly Bytes32[];
  readonly expectedRoot: Bytes32;
}

export interface TrackingSeal {
  readonly owner: Address;
  readonly ephPk: Uint8Array;
  readonly ciphertext: Uint8Array;
}

/** Unverified until `verifyTrackingOpening` checks it under the bound root. */
export type ServedTrackingOpening = TrackingOpening & Readonly<{ seal?: TrackingSeal }>;

export interface TrackingOpenings {
  readonly slot: bigint;
  readonly root: Bytes32;
  readonly revision: bigint;
  readonly openings: readonly ServedTrackingOpening[];
}

export interface PendingEnrollmentsRequest {
  readonly registry: Address;
  readonly after?: Address;
  readonly limit: number;
}

/** A first enrollment no apply has inserted, pending state grants nothing. */
export interface PendingEnrollment {
  readonly owner: Address;
  readonly member: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly ctHash: Bytes32;
  readonly listTag: Bytes32;
}

export interface PendingEnrollments {
  readonly slot: bigint;
  readonly enrollments: readonly PendingEnrollment[];
  readonly nextAfter?: Address;
}

export const getTrackingOpeningsMethod: MethodDescriptor<
  TrackingOpeningsRequest,
  TrackingOpenings
> = {
  name: "getTrackingOpenings",
  encodeRequest: (request) => {
    if (request.members.length < 1 || request.members.length > MAX_RING_MEMBER_BATCH)
      schemaFailure(
        "INDEXER_SCHEMA_INVALID_TYPE",
        "$.members",
        `1 to ${String(MAX_RING_MEMBER_BATCH)} members`,
        request.members,
      );
    return {
      registry: checkedAddress(request.registry, "registry"),
      members: request.members.map((member) => hash(member)),
      expectedRoot: hash(request.expectedRoot),
    };
  },
  decodeResponse: (value) => {
    const row = object(value, "$", ["context", "root", "openings"]);
    const root = object(row["root"], "root", ["root", "revision", "nextIndex"]);
    return Object.freeze({
      slot: context(row["context"], "context").slot,
      root: hashBytes(checkedHash(root["root"], "root.root")),
      revision: u64(root["revision"], "root.revision"),
      openings: Object.freeze(array(row["openings"], "openings", opening)),
    });
  },
};

export interface TrackingRecordPoolRequest extends TrackingOpeningsRequest {
  readonly openings: number;
}

export const getTrackingRecordPoolMethod: MethodDescriptor<
  TrackingRecordPoolRequest,
  ServedTrackingPool
> = {
  name: "getTrackingRecordPool",
  encodeRequest: (request) => ({
    ...getTrackingOpeningsMethod.encodeRequest(request),
    openings: request.openings,
  }),
  decodeResponse: (value) => {
    const row = object(value, "$", ["context", "root", "records", "canopy", "subjects"]);
    return Object.freeze({
      records: Object.freeze(
        array(row["records"], "records", (entry, path) => {
          const served = object(entry, path, ["record", "path"]);
          return Object.freeze({
            record: servedRecord(served["record"], `${path}.record`).record,
            path: poolPath(served["path"], `${path}.path`),
          });
        }),
      ),
      canopy: Object.freeze(array(row["canopy"], "canopy", field)),
      subjects: Object.freeze(
        array(row["subjects"], "subjects", (entry, path) =>
          Number(wireInteger(entry, path, 0n, 0xffff_ffffn)),
        ),
      ),
    });
  },
};

export const getPendingEnrollmentsMethod: MethodDescriptor<
  PendingEnrollmentsRequest,
  PendingEnrollments
> = {
  name: "getPendingEnrollments",
  encodeRequest: (request) => ({
    registry: checkedAddress(request.registry, "registry"),
    ...(request.after === undefined ? {} : { after: checkedAddress(request.after, "after") }),
    limit: request.limit,
  }),
  decodeResponse: (value) => {
    const row = object(value, "$", ["context", "enrollments", "nextAfter"]);
    const nextAfter = row["nextAfter"];
    return Object.freeze({
      slot: context(row["context"], "context").slot,
      enrollments: Object.freeze(array(row["enrollments"], "enrollments", pendingEnrollment)),
      ...(nextAfter == null ? {} : { nextAfter: checkedAddress(nextAfter, "nextAfter") }),
    });
  },
};

function opening(value: unknown, path: string): ServedTrackingOpening {
  const row = object(value, path, ["present", "record", "path"]);
  const present = row["present"];
  if (typeof present !== "boolean")
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", `${path}.present`, "a boolean", present);
  const { record, seal } = servedRecord(row["record"], `${path}.record`);
  const proofPath = quadPath(row["path"], `${path}.path`);
  return Object.freeze(
    present
      ? { kind: "present", record, path: proofPath, ...(seal === undefined ? {} : { seal }) }
      : { kind: "absent", low: record, path: proofPath },
  );
}

function servedRecord(
  value: unknown,
  path: string,
): Readonly<{ record: TrackingRecord; seal?: TrackingSeal }> {
  const row = object(value, path, ["member", "next", "nullifierPk", "ctHash", "listTag", "seal"]);
  const seal = row["seal"];
  return {
    record: Object.freeze({
      member: field(row["member"], `${path}.member`),
      next: field(row["next"], `${path}.next`),
      nullifierPk: field(row["nullifierPk"], `${path}.nullifierPk`),
      ctHash: field(row["ctHash"], `${path}.ctHash`),
      listTag: field(row["listTag"], `${path}.listTag`),
    }),
    ...(seal == null ? {} : { seal: sealOf(seal, `${path}.seal`) }),
  };
}

function sealOf(value: unknown, path: string): TrackingSeal {
  const row = object(value, path, ["owner", "ephPk", "ciphertext"]);
  return Object.freeze({
    owner: checkedAddress(row["owner"], `${path}.owner`),
    ephPk: indexerScalars.base64Bytes(checkedBase64(row["ephPk"], `${path}.ephPk`)),
    ciphertext: indexerScalars.base64Bytes(checkedBase64(row["ciphertext"], `${path}.ciphertext`)),
  });
}

function quadPath(value: unknown, path: string): QuadPath {
  const read = poolPath(value, path);
  if (read.siblings.length !== TRACKING_QUAD_HEIGHT)
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_TYPE",
      `${path}.siblings`,
      `${String(TRACKING_QUAD_HEIGHT)} levels`,
      read.siblings,
    );
  return read;
}

/** A pool path stops at the canopy, `verifyTrackingPool` checks its height. */
function poolPath(value: unknown, path: string): QuadPath {
  const row = object(value, path, ["index", "siblings"]);
  const siblings = array(row["siblings"], `${path}.siblings`, (level, levelPath) => {
    const hashes = array(level, levelPath, field);
    if (hashes.length !== QUAD_ARITY - 1)
      return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", levelPath, "3 siblings", level);
    return Object.freeze(hashes);
  });
  return Object.freeze({
    index: Number(wireInteger(row["index"], `${path}.index`, 0n, TRACKING_CAPACITY - 1n)),
    siblings: Object.freeze(siblings),
  });
}

function pendingEnrollment(value: unknown, path: string): PendingEnrollment {
  const row = object(value, path, ["owner", "member", "nullifierPk", "ctHash", "listTag"]);
  return Object.freeze({
    owner: checkedAddress(row["owner"], `${path}.owner`),
    member: field(row["member"], `${path}.member`),
    nullifierPk: field(row["nullifierPk"], `${path}.nullifierPk`),
    ctHash: field(row["ctHash"], `${path}.ctHash`),
    listTag: field(row["listTag"], `${path}.listTag`),
  });
}

function field(value: unknown, path: string): Bytes32 {
  return hashBytes(checkedHash(value, path));
}

function u64(value: unknown, path: string): bigint {
  return wireInteger(value, path, 0n, U64_MAX);
}
