import { ClientError, type Bytes32, type RequestContext } from "@heliuslabs/zolana";
import {
  ApiError,
  decodeBase64,
  decodeX25519,
  indexerScalars,
  invalidResponse,
  wrapIndexer,
  type ZolanaApi,
} from "@heliuslabs/zolana/internal";

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
import type {
  RingMemberOpening,
  RingRecordReader,
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
  // -32076 retired.
]);

export class RingIndexer implements RingRecordReader {
  readonly #api: ZolanaApi;

  constructor(api: ZolanaApi) {
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
        records: Object.freeze(
          response.records.map((entry, index) =>
            servedRecord(entry, method, `records[${String(index)}]`),
          ),
        ),
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
    openings: Object.freeze(
      response.openings.map((opening, index) =>
        memberOpening(opening, method, `openings[${String(index)}]`),
      ),
    ),
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
    records: Object.freeze(
      response.records.map((entry, index) =>
        servedRecord(entry, method, `records[${String(index)}]`),
      ),
    ),
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
    escrowKey: hashBytes(record.escrowKey),
    mintPolicy: record.mintPolicy,
  });
}

/** A sealed key is served whole or not at all. */
function memberOpening(
  opening: WireRingMemberOpeningView,
  method: string,
  path: string,
): RingMemberOpening {
  const { record } = opening;
  const sealed = [record.ownerPubkey, record.nullifierPk, record.ephPk, record.ciphertext];
  const present = sealed.filter((value) => value !== null && value !== undefined).length;
  if (present !== 0 && present !== sealed.length)
    throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
      details: { method, path: `${path}.record` },
    });
  const sealedKey =
    record.ownerPubkey == null ||
    record.nullifierPk == null ||
    record.ephPk === null ||
    record.ciphertext === null
      ? undefined
      : Object.freeze({
          owner: record.ownerPubkey,
          nullifierPk: hashBytes(record.nullifierPk),
          ephemeralPublicKey: decodeX25519(record.ephPk, method, `${path}.record.ephPk`),
          ciphertext: decodeCiphertext(record.ciphertext, method, `${path}.record.ciphertext`),
        });
  const opened: RecordOpening = opening.present
    ? { kind: "present", record: memberRecord(record), path: recordPath(opening.path) }
    : { kind: "absent", low: memberRecord(record), path: recordPath(opening.path) };
  return Object.freeze({ ...opened, ...(sealedKey === undefined ? {} : { sealedKey }) });
}

function servedRecord(
  entry: Readonly<{ record: WireRingMemberRecordView; path: WireRingRecordPathView }>,
  method: string,
  path: string,
): RingServedRecord {
  const opening = memberOpening(
    { present: true, record: entry.record, path: entry.path },
    method,
    path,
  );
  return Object.freeze({
    record: memberRecord(entry.record),
    path: opening.path,
    ...(opening.sealedKey === undefined ? {} : { sealedKey: opening.sealedKey }),
  });
}

function decodeCiphertext(value: string, method: string, path: string): Bytes32 {
  const bytes = decodeBase64(value, path);
  if (bytes.length !== 32) throw invalidResponse(method, path, 32, bytes.length);
  return bytes as Bytes32;
}

function ringIndexerError(cause: unknown, method: string): Error {
  if (cause instanceof ApiError && cause.code === "API_JSON_RPC") {
    const rpcCode = cause.details?.["rpcCode"];
    const code = typeof rpcCode === "number" ? RING_PROJECTION_CODES.get(rpcCode) : undefined;
    if (code !== undefined) return new RingError(code, { details: { method }, cause });
  }
  return wrapIndexer(cause, method);
}
