import type { MintPolicy } from "../protocol/membership/mint-policy.js";
import { ClientError, type Address, type Bytes32, type RequestContext } from "@heliuslabs/zolana";
import {
  ApiError,
  decodeBase64,
  decodeX25519,
  indexerScalars,
  invalidResponse,
  wrapIndexer,
  type ZolanaApi,
  type indexerTypes,
} from "@heliuslabs/zolana/internal";

import {
  getRingApplyProofInputsMethod,
  getRingMemberOpeningsMethod,
  getRingMemberRecordMethod,
  getRingMemberRecordsMethod,
  getRingMemberRegistryRootMethod,
  getRingRecordPoolMethod,
  getRingRecordQueueMethod,
  getStorageMemberOpeningsMethod,
  getStorageRecordPoolMethod,
} from "./indexer-methods.js";
import type {
  RingMemberRecordView as WireRingMemberRecordView,
  RingMemberOpeningView as WireRingMemberOpeningView,
  RingRecordPathView as WireRingRecordPathView,
  RingRegistryRootView as WireRingRegistryRootView,
  RingMemberOpeningsResponse as WireRingMemberOpenings,
  RingRecordPoolResponse as WireRingRecordPool,
  StorageRootView as WireStorageRootView,
} from "../protocol/indexer/indexer-types.js";
import {
  QUAD_ARITY,
  canopyLevels,
  type MemberRecord,
  type QuadPath,
  type QueueEntry,
  type RecordOpening,
} from "../protocol/membership/member-registry.js";
import type {
  RecordWrite,
  RingApplyProofInputs,
  RingMemberOpening,
  RingMemberOpenings,
  RingMemberPage,
  RingMemberPageRequest,
  RingMemberProofRequest,
  RingMemberRecordResult,
  RingQueueState,
  RingRecordPool,
  RingRecordPoolRequest,
  RingRecordReader,
  RingRegistryRoot,
  RingRegistryState,
  RingServedRecord,
  StorageMemberOpenings,
  StorageOpeningsRequest,
  StorageRecordPool,
  StorageRecordPoolRequest,
  StorageRoot,
} from "./ports.js";
import { RingError, type RingErrorCode } from "../protocol/error.js";

type Hash = indexerTypes.Hash;

const { hash, hashBytes } = indexerScalars;

/** The ring indexer's refusal codes, Rust `zolana_ring_indexer::rpc::RingRpcError`. */
const RING_PROJECTION_CODES: ReadonlyMap<number, RingErrorCode> = new Map([
  [-32070, "RING_REGISTRY_OUT_OF_SYNC"],
  [-32071, "RING_REGISTRY_ROOT_CHANGED"],
  [-32075, "RING_REGISTRY_PAGE_GAP"],
  [-32076, "RING_RECORD_QUEUE_CHANGED"],
]);

export class RingIndexer implements RingRecordReader {
  readonly #api: ZolanaApi;

  constructor(api: ZolanaApi) {
    this.#api = api;
  }

  async getRingMemberRecord(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingMemberRecordResult> {
    const method = "getRingMemberRecord";
    try {
      const wire = memberRequest(request);
      const response = await this.#api.call(getRingMemberRecordMethod, wire, context);
      if (
        response.root.root !== wire.expectedRoot ||
        response.root.nextIndex !== wire.expectedNextIndex ||
        (response.opening.present && response.opening.record.member !== wire.member)
      )
        throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", { details: { method, path: "$" } });
      return Object.freeze({
        context: response.context,
        root: registryRoot(response.root),
        opening: memberOpening(response.opening, method, "opening"),
      });
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }

  async getRingMemberRecords(
    request: RingMemberPageRequest,
    context?: RequestContext,
  ): Promise<RingMemberPage> {
    const method = "getRingMemberRecords";
    try {
      const wire = {
        ringProgramId: request.ringProgramId,
        expectedRoot: hash(request.expectedRoot),
        expectedNextIndex: BigInt(request.expectedNextIndex),
        startIndex: BigInt(request.startIndex),
        limit: request.limit,
      };
      const response = await this.#api.call(getRingMemberRecordsMethod, wire, context);
      const end = Math.min(request.startIndex + request.limit, request.expectedNextIndex);
      if (
        response.root.root !== wire.expectedRoot ||
        response.root.nextIndex !== wire.expectedNextIndex ||
        response.records.length !== end - request.startIndex ||
        response.records.some(
          (entry, index) => entry.path.index !== BigInt(request.startIndex + index),
        ) ||
        response.nextLeafIndex !== (end < request.expectedNextIndex ? BigInt(end) : null)
      )
        throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", { details: { method, path: "$" } });
      return Object.freeze({
        context: response.context,
        root: registryRoot(response.root),
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

  async getRingMemberRegistryRoot(
    request: Readonly<{ ringProgramId: Address }>,
    context?: RequestContext,
  ): Promise<RingRegistryState> {
    const method = "getRingMemberRegistryRoot";
    try {
      const response = await this.#api.call(getRingMemberRegistryRootMethod, request, context);
      return Object.freeze({
        context: response.context,
        history: Object.freeze(
          response.history.map((entry) =>
            entry === null
              ? undefined
              : Object.freeze({
                  root: hashBytes(entry.root),
                  applied: entry.applied,
                  slot: entry.slot,
                }),
          ),
        ),
        historyCursor: response.historyCursor,
        nextIndex: Number(response.nextIndex),
        floor: response.floor,
        priorFloor: response.priorFloor,
        floorSlot: response.floorSlot,
        ...(response.appendPath === null ? {} : { appendPath: recordPath(response.appendPath) }),
      });
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }

  async getRingMemberOpenings(
    request: Readonly<{
      ringProgramId: Address;
      members: readonly Bytes32[];
      expectedRoot: Bytes32;
    }>,
    context?: RequestContext,
  ): Promise<RingMemberOpenings> {
    const method = "getRingMemberOpenings";
    try {
      const wire = openingsRequest(request);
      const response = await this.#api.call(
        getRingMemberOpeningsMethod,
        { ringProgramId: request.ringProgramId, ...wire },
        context,
      );
      return Object.freeze({
        ...servedOpenings(response, wire, method),
        root: registryRoot(response.root),
      });
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
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

  async getRingRecordPool(
    request: RingRecordPoolRequest,
    context?: RequestContext,
  ): Promise<RingRecordPool> {
    const method = "getRingRecordPool";
    try {
      const wire = { ...openingsRequest(request), openings: request.openings };
      const response = await this.#api.call(
        getRingRecordPoolMethod,
        { ringProgramId: request.ringProgramId, ...wire },
        context,
      );
      return Object.freeze({
        ...servedPool(response, wire, method),
        root: registryRoot(response.root),
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

  async getRingRecordQueue(
    request: Readonly<{ ringProgramId: Address }>,
    context?: RequestContext,
  ): Promise<RingQueueState> {
    const method = "getRingRecordQueue";
    try {
      const response = await this.#api.call(getRingRecordQueueMethod, request, context);
      return Object.freeze({
        context: response.context,
        head: response.head,
        tail: response.tail,
        chainHead: hashBytes(response.chainHead),
        entries: Object.freeze(
          response.entries.map((entry) =>
            Object.freeze({
              position: entry.position,
              entry: queueEntry(entry),
              slot: entry.slot,
            }),
          ),
        ),
      });
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }

  async getRingApplyProofInputs(
    request: Readonly<{ ringProgramId: Address; authorityWrites: readonly RecordWrite[] }>,
    context?: RequestContext,
  ): Promise<RingApplyProofInputs> {
    const method = "getRingApplyProofInputs";
    try {
      const response = await this.#api.call(
        getRingApplyProofInputsMethod,
        {
          ringProgramId: request.ringProgramId,
          authorityWrites: request.authorityWrites.map((write) => ({
            member: hash(write.member),
            mask: write.mask,
            value: write.value,
            mintPolicy: write.mintPolicy ?? null,
          })),
        },
        context,
      );
      return Object.freeze({
        context: response.context,
        inputs: Object.freeze({
          oldRoot: hashBytes(response.oldRoot),
          newRoot: hashBytes(response.newRoot),
          oldNextIndex: Number(response.oldNextIndex),
          newNextIndex: Number(response.newNextIndex),
          chainStart: hashBytes(response.chainStart),
          chainEnd: hashBytes(response.chainEnd),
          writes: Object.freeze(
            response.writes.map((write) =>
              Object.freeze({
                entry: queueEntry(write),
                exists: write.exists,
                oldNext: hashBytes(write.oldNext),
                oldLists: write.oldLists,
                oldEscrow: hashBytes(write.oldEscrow),
                oldMintPolicy: write.oldMintPolicy,
                slot: recordPath(write.slot),
                low: memberRecord(write.low),
                lowPath: recordPath(write.lowPath),
              }),
            ),
          ),
        }),
      });
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }
}

function memberRequest(request: RingMemberProofRequest) {
  return Object.freeze({
    ringProgramId: request.ringProgramId,
    member: hash(request.member),
    expectedRoot: hash(request.expectedRoot),
    expectedNextIndex: BigInt(request.expectedNextIndex),
  });
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
  response: Omit<WireRingMemberOpenings, "root"> & Readonly<{ root: Readonly<{ root: Hash }> }>,
  wire: OpeningsWire,
  method: string,
): Omit<RingMemberOpenings, "root"> {
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
  response: Omit<WireRingRecordPool, "root"> & Readonly<{ root: Readonly<{ root: Hash }> }>,
  wire: OpeningsWire & Readonly<{ openings: number }>,
  method: string,
): Omit<RingRecordPool, "root"> {
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

function registryRoot(root: WireRingRegistryRootView): RingRegistryRoot {
  return Object.freeze({
    root: hashBytes(root.root),
    rootIndex: root.rootIndex,
    applied: root.applied,
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

function queueEntry(
  entry: Readonly<{
    member: Hash;
    mask: bigint;
    value: bigint;
    escrowKey: Hash;
    mintPolicy: MintPolicy | null;
  }>,
): QueueEntry {
  return Object.freeze({
    member: hashBytes(entry.member),
    mask: entry.mask,
    value: entry.value,
    escrowKey: hashBytes(entry.escrowKey),
    ...(entry.mintPolicy === null ? {} : { mintPolicy: entry.mintPolicy }),
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
