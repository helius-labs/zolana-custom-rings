import { ClientError, type Bytes32, type RequestContext } from "@heliuslabs/spr";
import {
  ApiError,
  equalBytes,
  indexerScalars,
  wrapIndexer,
  type SprApi,
} from "@heliuslabs/spr/internal";

import {
  getStorageMemberOpeningsMethod,
  getStorageMemberRecordsMethod,
  getStorageRecordPoolMethod,
} from "./indexer-methods.js";
import type {
  RingMemberRecordView as WireRingMemberRecordView,
  RingMemberOpeningView as WireRingMemberOpeningView,
  RingRecordPathView as WireRingRecordPathView,
  StorageMemberOpeningsResponse as WireStorageMemberOpenings,
  StorageRecordPoolResponse as WireStorageRecordPool,
  StorageRootView as WireStorageRootView,
} from "../protocol/indexer/indexer-types.js";
import {
  QUAD_ARITY,
  canopyLevels,
  type MemberRecord,
  type QuadPath,
  type RecordOpening,
} from "../protocol/membership/member-registry.js";
import {
  getPendingEnrollmentsMethod,
  getTrackingOpeningsMethod,
  getTrackingRecordPoolMethod,
  type PendingEnrollments,
  type PendingEnrollmentsRequest,
  type TrackingOpenings,
  type TrackingOpeningsRequest,
  type TrackingRecordPoolRequest,
} from "../protocol/indexer/tracking-codec.js";
import type { ServedTrackingPool } from "../protocol/membership/tracking.js";
import type {
  RingMemberOpening,
  RingRecordReader,
  TrackingReader,
  RingServedRecord,
  StorageMemberOpenings,
  StorageMemberPage,
  StorageOpeningsRequest,
  StoragePageRequest,
  StorageRecordPool,
  StorageRecordPoolRequest,
  StorageRoot,
} from "./ports.js";
import { RingError, type RingErrorCode } from "../protocol/error.js";

const { hash, hashBytes } = indexerScalars;

/** The ring indexer's refusal codes, Rust `zolana_ring_indexer::rpc::RingRpcError`. */
const RING_PROJECTION_CODES: ReadonlyMap<number, RingErrorCode> = new Map([
  [-32070, "RING_REGISTRY_OUT_OF_SYNC"],
  [-32071, "RING_REGISTRY_ROOT_CHANGED"],
  [-32075, "RING_REGISTRY_PAGE_GAP"],
]);

export class RingIndexer implements RingRecordReader, TrackingReader {
  readonly #api: SprApi;

  constructor(api: SprApi) {
    this.#api = api;
  }

  async getStorageMemberOpenings(
    request: StorageOpeningsRequest,
    context?: RequestContext,
  ): Promise<StorageMemberOpenings> {
    const method = "getStorageMemberOpenings";
    try {
      const wire = openingsRequest(request);
      const response = await this.#api.call(
        getStorageMemberOpeningsMethod,
        { registry: request.registry, ...wire },
        context,
      );
      return Object.freeze({
        ...servedOpenings(response, wire, method),
        root: storageRoot(response.root),
      });
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }

  async getTrackingOpenings(
    request: TrackingOpeningsRequest,
    context?: RequestContext,
  ): Promise<TrackingOpenings> {
    const method = "getTrackingOpenings";
    try {
      const response = await this.#api.call(getTrackingOpeningsMethod, request, context);
      if (
        !equalBytes(response.root, request.expectedRoot) ||
        response.openings.length !== request.members.length
      )
        throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", { details: { method, path: "$" } });
      return response;
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }

  async getTrackingRecordPool(
    request: TrackingRecordPoolRequest,
    context?: RequestContext,
  ): Promise<ServedTrackingPool> {
    const method = "getTrackingRecordPool";
    try {
      return await this.#api.call(getTrackingRecordPoolMethod, request, context);
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }

  async getPendingEnrollments(
    request: PendingEnrollmentsRequest,
    context?: RequestContext,
  ): Promise<PendingEnrollments> {
    const method = "getPendingEnrollments";
    try {
      return await this.#api.call(getPendingEnrollmentsMethod, request, context);
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }

  async getStorageMemberRecords(
    request: StoragePageRequest,
    context?: RequestContext,
  ): Promise<StorageMemberPage> {
    const method = "getStorageMemberRecords";
    try {
      const wire = {
        registry: request.registry,
        expectedRoot: hash(request.expectedRoot),
        startIndex: BigInt(request.startIndex),
        limit: request.limit,
      };
      const response = await this.#api.call(getStorageMemberRecordsMethod, wire, context);
      if (response.root.root !== wire.expectedRoot)
        throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
          details: { method, path: "$.root" },
        });
      return Object.freeze({
        context: response.context,
        root: storageRoot(response.root),
        records: Object.freeze(response.records.map(servedRecord)),
        nextLeafIndex: response.nextLeafIndex === null ? undefined : Number(response.nextLeafIndex),
      });
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }

  async getStorageRecordPool(
    request: StorageRecordPoolRequest,
    context?: RequestContext,
  ): Promise<StorageRecordPool> {
    const method = "getStorageRecordPool";
    try {
      const wire = { ...openingsRequest(request), openings: request.openings };
      const response = await this.#api.call(
        getStorageRecordPoolMethod,
        { registry: request.registry, ...wire },
        context,
      );
      return Object.freeze({
        ...servedPool(response, wire, method),
        root: storageRoot(response.root),
      });
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }
}

function openingsRequest(
  request: Readonly<{ members: readonly Bytes32[]; expectedRoot: Bytes32 }>,
) {
  return {
    members: request.members.map((member) => hash(member)),
    expectedRoot: hash(request.expectedRoot),
  };
}

type OpeningsWire = ReturnType<typeof openingsRequest>;

/** The served root is the expected one and every member has its opening. */
function servedOpenings(
  response: WireStorageMemberOpenings,
  wire: OpeningsWire,
  method: string,
): Omit<StorageMemberOpenings, "root"> {
  if (response.root.root !== wire.expectedRoot || response.openings.length !== wire.members.length)
    throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", { details: { method, path: "$" } });
  return {
    context: response.context,
    openings: Object.freeze(response.openings.map(memberOpening)),
  };
}

/** The served root is the expected one and the pool fits the openings asked for. */
function servedPool(
  response: WireStorageRecordPool,
  wire: OpeningsWire & Readonly<{ openings: number }>,
  method: string,
): Omit<StorageRecordPool, "root"> {
  if (
    response.root.root !== wire.expectedRoot ||
    response.records.length < 1 ||
    response.records.length > wire.openings ||
    response.canopy.length !== QUAD_ARITY ** canopyLevels(wire.openings) ||
    response.subjects.length !== wire.members.length
  )
    throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", { details: { method, path: "$" } });
  return {
    context: response.context,
    records: Object.freeze(response.records.map(servedRecord)),
    canopy: Object.freeze(response.canopy.map(hashBytes)),
    subjects: Object.freeze([...response.subjects]),
  };
}

function storageRoot(root: WireStorageRootView): StorageRoot {
  return Object.freeze({
    root: hashBytes(root.root),
    revision: root.revision,
    nextIndex: Number(root.nextIndex),
  });
}

function recordPath(path: WireRingRecordPathView): QuadPath {
  return Object.freeze({
    index: Number(path.index),
    siblings: Object.freeze(path.siblings.map((level) => Object.freeze(level.map(hashBytes)))),
  });
}

function memberRecord(record: WireRingMemberRecordView): MemberRecord {
  return Object.freeze({
    member: hashBytes(record.member),
    next: hashBytes(record.next),
    lists: record.lists,
    mintPolicy: record.mintPolicy,
  });
}

function memberOpening(opening: WireRingMemberOpeningView): RingMemberOpening {
  const opened: RecordOpening = opening.present
    ? { kind: "present", record: memberRecord(opening.record), path: recordPath(opening.path) }
    : { kind: "absent", low: memberRecord(opening.record), path: recordPath(opening.path) };
  return Object.freeze(opened);
}

function servedRecord(
  entry: Readonly<{ record: WireRingMemberRecordView; path: WireRingRecordPathView }>,
): RingServedRecord {
  return Object.freeze({ record: memberRecord(entry.record), path: recordPath(entry.path) });
}

function ringIndexerError(cause: unknown, method: string): Error {
  if (cause instanceof ApiError && cause.code === "API_JSON_RPC") {
    const rpcCode = cause.details?.["rpcCode"];
    const code = typeof rpcCode === "number" ? RING_PROJECTION_CODES.get(rpcCode) : undefined;
    if (code !== undefined) return new RingError(code, { details: { method }, cause });
  }
  return wrapIndexer(cause, method);
}
