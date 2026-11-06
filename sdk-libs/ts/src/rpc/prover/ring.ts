import {
  EMPTY_MINT_POLICY,
  assetLimitsFields,
  mintPolicyField,
  mintPolicyWriteField,
  type AssetLimits,
  type MintPolicy,
} from "../../protocol/membership/mint-policy.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { rawJson } from "../../protocol/codec/raw-json.js";

import { InterfaceError } from "@heliuslabs/spr/interface";
import { bigIntBytes, bytesField, type ExpectedProvingKey } from "@heliuslabs/spr/internal";
import type { Bytes16, Bytes32 } from "@heliuslabs/spr/interface";
import { ClientError } from "@heliuslabs/spr/client";
import {
  APPLY_BATCH,
  MEMBER_REGISTRY_CAPACITY,
  QUAD_ARITY,
  QUAD_HEIGHT,
  canopyLevels,
  type ApplyProofInputs,
  type MemberRecord,
  type PoolSubject,
  type QuadPath,
  type RecordWrite,
  type RecordPool,
  type RecordWriteProofInput,
} from "../../protocol/membership/member-registry.js";
import {
  TRACKING_CAPACITY,
  TRACKING_QUAD_HEIGHT,
  type TrackingEntry,
  type TrackingOpening,
  type TrackingRecord,
} from "../../protocol/membership/tracking.js";
import {
  applyKeyWidth,
  ringCircuitType,
  ringProvingKey,
  type RingKeyCircuit,
} from "../../protocol/proof/proving-keys.js";
import {
  transferKeys,
  transferPoolCapacity,
  type PolicyPoolCapacity,
  type TransferKeyCircuit,
} from "../../protocol/proof/transfer-shapes.js";
import {
  auditLayoutValue,
  disclosureFormat,
  type AuditLayout,
} from "../../protocol/codec/ring-disclosure-layout.js";
import { ANONYMOUS_PARTIES } from "../../protocol/transaction/transact.js";
import { RING_RULE_SLOTS, RING_SOURCE_SLOTS } from "./types.js";
import { N_PUBLIC_SLOTS } from "../../protocol/transaction/spp.js";

/** Go `Opening`, one transaction slot as the ring circuits open it. */
export interface RingSlotOpening {
  readonly domain: Bytes32;
  readonly treeId: Bytes32;
  readonly ownerPkHash: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly asset: Bytes32;
  readonly amount: Bytes32;
  readonly blinding: Bytes32;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
  readonly ringProgramId: Bytes32;
}

/** Go `AuditParams`, the envelope inputs every transfer proof opens with. */
export interface AuditEnvelopeProofInputs {
  readonly firstNullifier: Bytes32;
  /** The clamped secret the envelope seals and the stream's key. */
  readonly txViewingSk: Bytes32;
  /** The auditor's X25519 u without the tag byte. */
  readonly auditorPk: Bytes32;
  readonly salt: Bytes16;
  /** The statement's layout element. */
  readonly layout: AuditLayout;
}

/** Go `OutputOpening`, one output slot and the preimages its record names. */
export interface OutputOpeningProofInput {
  readonly output: RingSlotOpening;
  readonly ownerKey: Bytes32;
  readonly mintChunks: readonly Bytes32[];
}

/** Go `EntryOpening`, zero off a default-ring input. */
export interface EntryOpeningProofInput {
  readonly ownerKey: Bytes32;
  readonly mintChunks: readonly Bytes32[];
}

/** Go `Source`, a zero `registry` names the ring's own registry. */
export interface PolicySourceProofInput {
  readonly listId: number;
  readonly registry: Bytes32;
}

/** Go `PolicyTable`, every row past its count zero. */
export interface PolicyTableProofInputs {
  readonly sources: readonly PolicySourceProofInput[];
  /** Bit `i` puts list `i + 1` at owners' salted keys, the mapped private lists. */
  readonly salted: number;
  readonly policyLen: number;
  readonly rules: readonly Bytes32[];
}

/** Go `PooledEntry`, the curator index 0 without a curator registry. */
export interface PolicySubjectEntry {
  readonly own: number;
  readonly curator: number;
}

/** Go `PooledOwnerEntry`, a zero salt with no tracking row. */
export interface PolicyOwnerEntry extends PolicySubjectEntry {
  readonly tracking: number;
  readonly listSalt: Bytes32;
  readonly ownSalted: number;
  readonly curatorSalted: number;
}

/** Go `PolicyParams`, one owner and one asset entry per output and withdrawal slot, both pools at the key's widths. */
export interface PolicyProofInputs extends PolicyTableProofInputs {
  readonly withdrawalCount: number;
  readonly withdrawalHash: Bytes32;
  readonly withdrawals: readonly Readonly<{ owner: Bytes32; asset: Bytes32; amount: bigint }>[];
  readonly policyHash: Bytes32;
  readonly ringId: Bytes32;
  readonly ownRoot: Bytes32;
  readonly curatorRoot: Bytes32;
  readonly publicAssets: readonly Bytes32[];
  readonly publicAmounts: readonly Bytes32[];
  /** Gross withdrawals per slot as right aligned u128. */
  readonly publicGross: readonly Bytes32[];
  readonly ownPool: RecordPool;
  readonly curatorPool: RecordPool;
  /** The pool rows of the key's owner rows. */
  readonly senderEntries: readonly PolicyOwnerEntry[];
  readonly ownerEntries: readonly PolicyOwnerEntry[];
  readonly assetEntries: readonly PolicySubjectEntry[];
  readonly publicAssetEntries: readonly number[];
}

/** Go `TrackingRecordParams` rows, their shared proof and the subjects they open. */
export interface TrackingPoolProofInput {
  readonly records: readonly TrackingRecord[];
  readonly canopy: readonly Bytes32[];
  /** `paths[i]` opens `records[i]` up to the canopy, leaf level first. */
  readonly paths: readonly QuadPath[];
  readonly subjects: readonly PoolSubject[];
}

/** Go `TrackingParams`, every owner row and live ring output under the frame's tracking root. */
export interface TrackingProofInputs {
  readonly trackingRoot: Bytes32;
  readonly trackingPool: TrackingPoolProofInput;
  /** Index `trackingPool.subjects`, 0 on a zero row. */
  readonly rowEntries: readonly number[];
  /** Index `trackingPool.subjects`, 0 off a live ring output. */
  readonly outputEntries: readonly number[];
}

/** Go `TransferParams`, what every transfer key reads. */
export interface TransferProofInputs
  extends AuditEnvelopeProofInputs, PolicyProofInputs, TrackingProofInputs {
  readonly publicInputHash: Bytes32;
  /** The statement's proven bits. */
  readonly approvalMask: number;
  /** Absent reads zero, a frame that discloses nothing. */
  readonly approvalTotals?: Bytes32;
  /** Fresh per transaction, absent reads zero. */
  readonly approvalBlinder?: Bytes32;
  /** `m`, the slots past it leave the frame. */
  readonly outputCount: number;
  readonly outputs: readonly OutputOpeningProofInput[];
  /** The published nullifier count, the input slots past it carry no UTXO. */
  readonly inputCount: number;
  /** `HashChain4([inputCount, ...inputNullifiers])`, the statement element past `inputCount`. */
  readonly inputNullifierChain: Bytes32;
  /** The published nullifiers zero filled to the key's input class. */
  readonly inputNullifiers: readonly Bytes32[];
  /** At the key's input class. */
  readonly inputs: readonly RingSlotOpening[];
  /** One per input class slot on an entry key, empty otherwise. */
  readonly entries: readonly EntryOpeningProofInput[];
  readonly signerCount: number;
  /** Absent reads zero, Go `SignerDataCounts`. */
  readonly signerDataCounts?: bigint;
  /** SPP's owner signer run, zero filled to the input class. */
  readonly signers: readonly Bytes32[];
  /** The distinct live input owners ascending, zero rows last, at the key's owner rows. */
  readonly rows: readonly Bytes32[];
  readonly privateTxHash: Bytes32;
  /** SPP's blinding of the hash. */
  readonly privateTxBlinding: Bytes32;
}

/** Go `TransferParams`, the statement's rail bits pick the rail. */
export interface TransferProofRequest extends TransferProofInputs {
  readonly kind: "transfer";
  readonly inProof: boolean;
  readonly hidden: boolean;
  readonly delegate: boolean;
  /** The in-proof owner, zero on every other rail. */
  readonly sender: Bytes32;
  /** Payer, each co-signer and exit destination, zero when absent. */
  readonly partyIdentities: readonly Bytes32[];
}

/** Go `ApplyRecordsParams`, the write count picks the width and `private` the family. */
export interface ApplyRecordsProofRequest extends ApplyProofInputs {
  readonly kind: "applyRecords";
  readonly publicInputHash: Bytes32;
  /** Absent on a public update, the public apply key takes no tracking field. */
  readonly private?: PrivateApplyProofInput;
}

/** Go `PrivateApplyRecordsParams` beside the shared apply fields. */
export interface PrivateApplyProofInput {
  /** Bit `i` marks write `i` private, never zero. */
  readonly privateWrites: number;
  /** The pinned tracking registry's root at the batch's tracking revision. */
  readonly trackingRoot: Bytes32;
  /** One per marked write, `undefined` elsewhere. */
  readonly owners: readonly (PrivateOwnerProofInput | undefined)[];
}

/** Go `PrivateOwnerParams`, a marked write's owner row, present under a nonzero key. */
export interface PrivateOwnerProofInput {
  readonly listSalt: Bytes32;
  readonly record: TrackingRecord;
  readonly path: QuadPath;
}

/** Go `TrackingWrite`, the witness of one inserted entry. */
export interface TrackingWriteProofInput {
  readonly entry: TrackingEntry;
  readonly slot: QuadPath;
  readonly lowRecord: TrackingRecord;
  readonly lowPath: QuadPath;
}

/** Go `ApplyEnrollmentsParams`. */
export interface ApplyEnrollmentsProofRequest {
  readonly kind: "applyEnrollments";
  readonly publicInputHash: Bytes32;
  readonly oldRoot: Bytes32;
  readonly newRoot: Bytes32;
  readonly oldNextIndex: bigint;
  readonly newNextIndex: bigint;
  readonly chainStart: Bytes32;
  readonly chainEnd: Bytes32;
  readonly writes: readonly TrackingWriteProofInput[];
}

/** Go `RegisterKeyParams`. */
export interface RegisterKeyProofRequest {
  readonly kind: "registerKey";
  readonly publicInputHash: Bytes32;
  /** The tracking registry's. */
  readonly ringId: Bytes32;
  /** The owner identity of the signing member. */
  readonly member: Bytes32;
  /** A zero lead byte then the 31 secret bytes. */
  readonly nullifierSecret: Bytes32;
  /** A zero lead byte then the 31 salt bytes. */
  readonly listSalt: Bytes32;
  readonly ephSk: Bytes32;
  readonly auditorPk: Bytes32;
}

/** Go `MergeParams`, seals a ring's SPP merge output to its auditor. */
export interface MergeProofRequest {
  readonly kind: "merge";
  readonly publicInputHash: Bytes32;
  readonly outputUtxoHash: Bytes32;
  readonly firstNullifier: Bytes32;
  readonly ringProgramId: Bytes32;
  readonly auditorPk: Bytes32;
  readonly payer: Bytes32;
  readonly trackingRoot: Bytes32;
  readonly ephSk: Bytes32;
  readonly ownerKey: Bytes32;
  readonly ownerPkHash: Bytes32;
  readonly mintChunks: readonly Bytes32[];
  readonly asset: Bytes32;
  readonly amount: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly seed: Bytes32;
  readonly outputTreeId: Bytes32;
  readonly outputRingDataHash: Bytes32;
  /** Undefined under a zero key. */
  readonly tracking?: TrackingOpening;
}

export type RingProofRequest =
  | TransferProofRequest
  | ApplyRecordsProofRequest
  | ApplyEnrollmentsProofRequest
  | RegisterKeyProofRequest
  | MergeProofRequest;

/** The key a request proves under, its list widths pick the shape. */
export function ringProofCircuit(request: RingProofRequest): RingKeyCircuit {
  switch (request.kind) {
    case "transfer":
      return transferCircuit(request);
    case "applyRecords":
      return {
        family: "applyRecords",
        writes: applyCapacity(listLength(request.writes)),
        private: request.private !== undefined,
      };
    case "applyEnrollments":
      return { family: "applyEnrollments", writes: applyCapacity(listLength(request.writes)) };
    case "registerKey":
      return { family: "registerKey" };
    case "merge":
      return { family: "merge" };
    default:
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
}

/** The transfer key the request's list widths name, Rust `RingCircuit::Transfer`. */
function transferCircuit(request: TransferProofRequest): TransferKeyCircuit {
  const narrow: TransferKeyCircuit = {
    family: "transfer",
    format: disclosureFormat(request.layout.format),
    outputs: listLength(request.outputs),
    class: listLength(request.inputs),
    withdrawals: listLength(request.withdrawals),
    owners: listLength(request.rows),
    entry: flag(request.layout.entry),
    wide: false,
  };
  // The layout carries no wide flag, the own pool's length names it.
  const records = listLength(request.ownPool.records);
  return (
    transferKeys().find(
      (key) =>
        key.format === narrow.format &&
        key.outputs === narrow.outputs &&
        key.class === narrow.class &&
        key.withdrawals === narrow.withdrawals &&
        key.owners === narrow.owners &&
        key.entry === narrow.entry &&
        transferPoolCapacity(key).own === records,
    ) ?? narrow
  );
}

export function ringRequestKey(request: RingProofRequest): ExpectedProvingKey {
  return proofInput(() => ringProvingKey(ringProofCircuit(request)));
}

/** The body the prover's strict decoder accepts, keys in Go declaration order. */
export function ringProofRequestBody(request: RingProofRequest): Readonly<Record<string, unknown>> {
  const head = {
    circuitType: keyedCircuitType(request),
    publicInputHash: field(request.publicInputHash, "publicInputHash"),
  };
  switch (request.kind) {
    case "transfer":
      return { ...head, ...transferJson(request) };
    case "applyRecords": {
      const capacity = applyCapacity(request.writes.length);
      return {
        ...head,
        ...applyHeadJson(request, [
          integer(request.oldNextIndex, "oldNextIndex", 0, U32_MAX),
          integer(request.newNextIndex, "newNextIndex", 0, U32_MAX),
        ]),
        count: request.writes.length,
        writes: paddedWrites(request.writes, capacity, writeJson),
        ...(request.private === undefined ? {} : privateApplyJson(request.private, capacity)),
      };
    }
    case "applyEnrollments": {
      const capacity = applyCapacity(request.writes.length);
      return {
        ...head,
        ...applyHeadJson(request, [
          trackingNextIndex(request.oldNextIndex, "oldNextIndex"),
          trackingNextIndex(request.newNextIndex, "newNextIndex"),
        ]),
        count: request.writes.length,
        writes: paddedWrites(request.writes, capacity, trackingWriteJson),
      };
    }
    case "registerKey":
      return {
        ...head,
        ringId: field(request.ringId, "ringId"),
        member: field(request.member, "member"),
        nullifierSecret: hexBytes(request.nullifierSecret, 32, "nullifierSecret"),
        listSalt: hexBytes(request.listSalt, 32, "listSalt"),
        ephSk: hexBytes(request.ephSk, 32, "ephSk"),
        auditorPk: hexBytes(request.auditorPk, 32, "auditorPk"),
      };
    case "merge":
      return {
        ...head,
        outputUtxoHash: field(request.outputUtxoHash, "outputUtxoHash"),
        firstNullifier: field(request.firstNullifier, "firstNullifier"),
        ringProgramId: field(request.ringProgramId, "ringProgramId"),
        auditorPk: hexBytes(request.auditorPk, 32, "auditorPk"),
        payer: field(request.payer, "payer"),
        trackingRoot: field(request.trackingRoot, "trackingRoot"),
        ephSk: hexBytes(request.ephSk, 32, "ephSk"),
        ownerKey: hexBytes(request.ownerKey, 32, "ownerKey"),
        ownerPkHash: field(request.ownerPkHash, "ownerPkHash"),
        mintChunks: fields(request.mintChunks, MINT_CHUNKS, "mintChunks"),
        asset: field(request.asset, "asset"),
        amount: field(request.amount, "amount"),
        nullifierPk: field(request.nullifierPk, "nullifierPk"),
        seed: field(request.seed, "seed"),
        outputTreeId: field(request.outputTreeId, "outputTreeId"),
        outputRingDataHash: field(request.outputRingDataHash, "outputRingDataHash"),
        tracking: trackingOpeningJson(request.tracking, "tracking"),
      };
  }
}

type Json = Readonly<Record<string, unknown>>;

const U8_MAX = 0xff;
const U32_MAX = 0xffff_ffff;
/** Go `[2]Field`, the two `hash_bytes_32` halves of a mint. */
const MINT_CHUNKS = 2;
const MAX_LEAF_INDEX = Number(MEMBER_REGISTRY_CAPACITY) - 1;
const MAX_TRACKING_INDEX = Number(TRACKING_CAPACITY) - 1;

/** A count no apply key holds keeps its own width and fails the catalog lookup. */
function applyCapacity(count: number): number {
  return count >= 1 && count <= APPLY_BATCH ? applyKeyWidth(count) : count;
}

/** A list width no key serves fails here, before any encoding. */
function keyedCircuitType(request: RingProofRequest): string {
  return proofInput(() => ringCircuitType(ringProofCircuit(request)));
}

/** An interface refusal of a request value is an invalid proof input. */
function proofInput<T>(read: () => T): T {
  try {
    return read();
  } catch (cause) {
    if (cause instanceof InterfaceError) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    throw cause;
  }
}

type PolicySectionShape = Readonly<{
  rows: number;
  outputs: number;
  withdrawals: number;
  /** Input slots, each reads an asset entry past the payments'. */
  spent: number;
  publicAssets: number;
  pools: PolicyPoolCapacity;
}>;

function transferJson(request: TransferProofRequest): Json {
  const circuit = transferCircuit(request);
  const slots = request.inputs.length;
  const shape: PolicySectionShape = {
    rows: circuit.owners,
    outputs: circuit.outputs,
    withdrawals: circuit.withdrawals,
    spent: circuit.class,
    publicAssets: N_PUBLIC_SLOTS,
    pools: transferPoolCapacity(circuit),
  };
  return {
    ...envelopeJson(request),
    inProof: flag(request.inProof),
    hidden: flag(request.hidden),
    delegate: flag(request.delegate),
    sender: field(request.sender, "sender"),
    partyIdentities: fields(request.partyIdentities, ANONYMOUS_PARTIES, "partyIdentities"),
    approvalMask: integer(request.approvalMask, "approvalMask", 0, APPROVAL_MASK_MAX),
    ...(request.approvalTotals === undefined
      ? {}
      : { approvalTotals: field(request.approvalTotals, "approvalTotals") }),
    ...(request.approvalBlinder === undefined
      ? {}
      : { approvalBlinder: field(request.approvalBlinder, "approvalBlinder") }),
    outputCount: integer(request.outputCount, "outputCount", 1, request.outputs.length),
    outputs: request.outputs.map((output, i) => outputJson(output, `outputs[${i}]`)),
    inputCount: integer(request.inputCount, "inputCount", 1, slots),
    inputNullifierChain: field(request.inputNullifierChain, "inputNullifierChain"),
    inputNullifiers: fields(request.inputNullifiers, slots, "inputNullifiers"),
    inputs: request.inputs.map((input, i) => openingJson(input, `inputs[${i}]`)),
    ...(flag(request.layout.entry)
      ? {
          entries: sized(request.entries, slots, "entries").map((entry, i) =>
            entryOpeningJson(entry, `entries[${i}]`),
          ),
        }
      : {}),
    signerCount: integer(request.signerCount, "signerCount", 0, slots),
    signers: fields(request.signers, slots, "signers"),
    // Go reads a `uint64` number, 60 bits pass no double exact.
    ...(request.signerDataCounts === undefined || request.signerDataCounts === 0n
      ? {}
      : { signerDataCounts: rawJson(request.signerDataCounts.toString()) }),
    rows: fields(request.rows, circuit.owners, "rows"),
    privateTxHash: field(request.privateTxHash, "privateTxHash"),
    privateTxBlinding: field(request.privateTxBlinding, "privateTxBlinding"),
    ...trackingJson(request, shape),
    ...policyJson(request, shape),
  };
}

const APPROVAL_MASK_MAX = 3;

function envelopeJson(envelope: AuditEnvelopeProofInputs): Json {
  return {
    firstNullifier: field(envelope.firstNullifier, "firstNullifier"),
    txViewingSk: hexBytes(envelope.txViewingSk, 32, "txViewingSk"),
    auditorPk: hexBytes(envelope.auditorPk, 32, "auditorPk"),
    salt: hexBytes(envelope.salt, 16, "salt"),
    layout: proofInput(() => auditLayoutValue(envelope.layout)),
  };
}

function openingJson(opening: RingSlotOpening, name: string): Json {
  return {
    domain: field(opening.domain, `${name}.domain`),
    treeId: field(opening.treeId, `${name}.treeId`),
    ownerPkHash: field(opening.ownerPkHash, `${name}.ownerPkHash`),
    nullifierPk: field(opening.nullifierPk, `${name}.nullifierPk`),
    asset: field(opening.asset, `${name}.asset`),
    amount: field(opening.amount, `${name}.amount`),
    blinding: field(opening.blinding, `${name}.blinding`),
    dataHash: field(opening.dataHash, `${name}.dataHash`),
    ringDataHash: field(opening.ringDataHash, `${name}.ringDataHash`),
    ringProgramId: field(opening.ringProgramId, `${name}.ringProgramId`),
  };
}

function outputJson(slot: OutputOpeningProofInput, name: string): Json {
  return {
    output: openingJson(slot.output, `${name}.output`),
    ...entryOpeningJson(slot, name),
  };
}

function entryOpeningJson(entry: EntryOpeningProofInput, name: string): Json {
  return {
    ownerKey: hexBytes(entry.ownerKey, 32, `${name}.ownerKey`),
    mintChunks: fields(entry.mintChunks, MINT_CHUNKS, `${name}.mintChunks`),
  };
}

function trackingJson(tracking: TrackingProofInputs, shape: PolicySectionShape): Json {
  const capacity = shape.pools.tracking;
  const { trackingPool: pool } = tracking;
  const levels = canopyLevels(capacity);
  const entry = (index: number, name: string): number => integer(index, name, 0, capacity - 1);
  return {
    trackingRoot: field(tracking.trackingRoot, "trackingRoot"),
    trackingRecords: sized(pool.records, capacity, "trackingRecords").map((record, i) =>
      trackingRecordJson(record, `trackingRecords[${i}]`),
    ),
    trackingProof: {
      canopy: fields(pool.canopy, QUAD_ARITY ** levels, "trackingProof.canopy"),
      paths: sized(pool.paths, capacity, "trackingProof.paths").map((path, i) =>
        sharedPathJson(
          path,
          TRACKING_QUAD_HEIGHT - levels,
          MAX_TRACKING_INDEX,
          `trackingProof.paths[${i}]`,
        ),
      ),
    },
    trackingSubjects: subjectsJson(pool.subjects, capacity, "trackingSubjects"),
    rowEntries: sized(tracking.rowEntries, shape.rows, "rowEntries").map((index, i) =>
      entry(index, `rowEntries[${i}]`),
    ),
    outputEntries: sized(tracking.outputEntries, shape.outputs, "outputEntries").map((index, i) =>
      entry(index, `outputEntries[${i}]`),
    ),
  };
}

/** Go `TrackingRecordParams` and `TrackingLeaf`, one wire shape. */
function trackingRecordJson(record: TrackingRecord, name: string): Json {
  return {
    member: field(record.member, `${name}.member`),
    next: field(record.next, `${name}.next`),
    ...trackingFieldsJson(record, name),
  };
}

function trackingFieldsJson(entry: TrackingEntry, name: string): Json {
  return {
    nullifierPk: field(entry.nullifierPk, `${name}.nullifierPk`),
    ctHash: field(entry.ctHash, `${name}.ctHash`),
    listTag: field(entry.listTag, `${name}.listTag`),
  };
}

/** Go `TrackingOpening`, a padding slot and a zero key send null. */
function trackingOpeningJson(opening: TrackingOpening | undefined, name: string): Json | null {
  if (opening === undefined) return null;
  const present = opening.kind === "present";
  return {
    present,
    record: trackingRecordJson(present ? opening.record : opening.low, `${name}.record`),
    path: sharedPathJson(opening.path, TRACKING_QUAD_HEIGHT, MAX_TRACKING_INDEX, `${name}.path`),
  };
}

/** Go `SharedRegistryPath`. */
function sharedPathJson(path: QuadPath, height: number, maxIndex: number, name: string): Json {
  return {
    index: integer(path.index, `${name}.index`, 0, maxIndex),
    siblings: sized(path.siblings, height, `${name}.siblings`).map((level, l) =>
      fields(level, QUAD_ARITY - 1, `${name}.siblings[${l}]`),
    ),
  };
}

function subjectsJson(
  subjects: readonly PoolSubject[],
  capacity: number,
  name: string,
): readonly Json[] {
  return sized(subjects, capacity, name).map((subject, i) => ({
    member: field(subject.member, `${name}[${i}].member`),
    recordIndex: integer(subject.recordIndex, `${name}[${i}].recordIndex`, 0, capacity - 1),
  }));
}

function policyJson(policy: PolicyProofInputs, shape: PolicySectionShape): Json {
  const slots = shape.outputs + shape.withdrawals;
  const capacity = shape.pools;
  const own = poolJson(policy.ownPool, capacity.own, "ownPool");
  const curator = poolJson(policy.curatorPool, capacity.curator, "curatorPool");
  return {
    withdrawalCount: integer(
      policy.withdrawalCount,
      "withdrawalCount",
      0,
      policy.withdrawals.length,
    ),
    withdrawalHash: field(policy.withdrawalHash, "withdrawalHash"),
    withdrawals: sized(policy.withdrawals, shape.withdrawals, "withdrawals").map((w) => ({
      owner: field(w.owner, "withdrawal.owner"),
      asset: field(w.asset, "withdrawal.asset"),
      amount: withdrawalAmount(w.amount),
    })),
    policyHash: field(policy.policyHash, "policyHash"),
    ringId: field(policy.ringId, "ringId"),
    ownRoot: field(policy.ownRoot, "ownRoot"),
    curatorRoot: field(policy.curatorRoot, "curatorRoot"),
    publicAssets: fields(policy.publicAssets, N_PUBLIC_SLOTS, "publicAssets"),
    publicAmounts: fields(policy.publicAmounts, N_PUBLIC_SLOTS, "publicAmounts"),
    publicGross: fields(policy.publicGross, N_PUBLIC_SLOTS, "publicGross"),
    ...tableJson(policy),
    ownRecords: own.records,
    curatorRecords: curator.records,
    ownProof: own.proof,
    curatorProof: curator.proof,
    ownSubjects: own.subjects,
    curatorSubjects: curator.subjects,
    senderEntries: sized(policy.senderEntries, shape.rows, "senderEntries").map((entry, i) =>
      ownerEntryJson(entry, capacity, `senderEntries[${i}]`),
    ),
    ownerEntries: sized(policy.ownerEntries, slots, "ownerEntries").map((entry, i) =>
      ownerEntryJson(entry, capacity, `ownerEntries[${i}]`),
    ),
    assetEntries: sized(policy.assetEntries, slots + shape.spent, "assetEntries").map((entry, i) =>
      entryJson(entry, capacity, `assetEntries[${i}]`),
    ),
    publicAssetEntries: sized(
      policy.publicAssetEntries,
      shape.publicAssets,
      "publicAssetEntries",
    ).map((index, i) => integer(index, `publicAssetEntries[${i}]`, 0, capacity.own - 1)),
  };
}

function tableJson(table: PolicyTableProofInputs): Json {
  return {
    sources: sized(table.sources, RING_SOURCE_SLOTS, "sources").map((source, i) => ({
      listId: integer(source.listId, `sources[${i}].listId`, 0, U8_MAX),
      registry: field(source.registry, `sources[${i}].registry`),
    })),
    salted: integer(table.salted, "salted", 0, (1 << RING_SOURCE_SLOTS) - 1),
    policyLen: integer(table.policyLen, "policyLen", 0, RING_RULE_SLOTS),
    rules: fields(table.rules, RING_RULE_SLOTS, "rules"),
  };
}

type PoolJson = Readonly<{
  records: readonly Json[];
  proof: Readonly<{ canopy: readonly string[]; paths: readonly Json[] }>;
  subjects: readonly Json[];
}>;

/** Go `PooledRecord`, `SharedRegistryProof` and `PooledSubject` rows at the key's capacity. */
function poolJson(pool: RecordPool, capacity: number, name: string): PoolJson {
  const levels = canopyLevels(capacity);
  return {
    records: sized(pool.records, capacity, `${name}.records`).map((record, i) => ({
      member: field(record.member, `${name}.records[${i}].member`),
      ...recordFieldsJson(record, `${name}.records[${i}]`),
    })),
    proof: {
      canopy: fields(pool.canopy, QUAD_ARITY ** levels, `${name}.canopy`),
      paths: sized(pool.paths, capacity, `${name}.paths`).map((path, i) =>
        sharedPathJson(path, QUAD_HEIGHT - levels, MAX_LEAF_INDEX, `${name}.paths[${i}]`),
      ),
    },
    subjects: subjectsJson(pool.subjects, capacity, `${name}.subjects`),
  };
}

function entryJson(entry: PolicySubjectEntry, capacity: PolicyPoolCapacity, name: string): Json {
  return {
    own: integer(entry.own, `${name}.own`, 0, capacity.own - 1),
    curator: [integer(entry.curator, `${name}.curator`, 0, capacity.curator - 1)],
  };
}

function ownerEntryJson(entry: PolicyOwnerEntry, capacity: PolicyPoolCapacity, name: string): Json {
  return {
    ...entryJson(entry, capacity, name),
    tracking: integer(entry.tracking, `${name}.tracking`, 0, capacity.tracking - 1),
    listSalt: field(entry.listSalt, `${name}.listSalt`),
    ownSalted: integer(entry.ownSalted, `${name}.ownSalted`, 0, capacity.own - 1),
    curatorSalted: [integer(entry.curatorSalted, `${name}.curatorSalted`, 0, capacity.curator - 1)],
  };
}

function recordFieldsJson(record: MemberRecord, name: string): Json {
  return {
    next: field(record.next, `${name}.next`),
    lists: u64(record.lists, `${name}.lists`),
    ...mintPolicyJson(record.mintPolicy, name, ""),
  };
}

/** The mint policy columns of one record, `prefix` names its side in the Go struct. */
function mintPolicyJson(policy: MintPolicy, name: string, prefix: "" | "low" | "old"): Json {
  const key = (column: string): string =>
    prefix === "" ? column : `${prefix}${column.charAt(0).toUpperCase()}${column.slice(1)}`;
  return {
    [key("mintPolicy")]: field(mintPolicyField(policy), `${name}.${key("mintPolicy")}`),
    [key("withdrawalThreshold")]: field(
      bigIntBytes(policy.withdrawalThreshold, 32) as Bytes32,
      `${name}.${key("withdrawalThreshold")}`,
    ),
    [key("assetLimits")]: limitsJson(policy.limits, `${name}.${key("assetLimits")}`),
  };
}

function privateApplyJson(input: PrivateApplyProofInput, capacity: number): Json {
  return {
    privateWrites: integer(input.privateWrites, "privateWrites", 1, (1 << capacity) - 1),
    trackingRoot: field(input.trackingRoot, "trackingRoot"),
    owners: paddedWrites(
      input.owners,
      capacity,
      (owner, name) => ({
        listSalt: field(owner.listSalt, `${name}.listSalt`),
        record: trackingRecordJson(owner.record, `${name}.record`),
        ...trackingPathJson(owner.path, name, "index", "path"),
      }),
      "owners",
    ),
  };
}

/** Go field order, each family checks its own next index width. */
function applyHeadJson(
  request: Readonly<{ oldRoot: Bytes32; newRoot: Bytes32; chainStart: Bytes32; chainEnd: Bytes32 }>,
  [oldNextIndex, newNextIndex]: readonly [number, number],
): Json {
  return {
    oldRoot: field(request.oldRoot, "oldRoot"),
    newRoot: field(request.newRoot, "newRoot"),
    oldNextIndex,
    newNextIndex,
    chainStart: field(request.chainStart, "chainStart"),
    chainEnd: field(request.chainEnd, "chainEnd"),
  };
}

/** A slot past the count assigns zeros. */
function paddedWrites<T>(
  writes: readonly (T | undefined)[],
  capacity: number,
  encode: (write: T, name: string) => Json,
  list = "writes",
): readonly (Json | null)[] {
  if (writes.length > capacity)
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: { field: list, expected: capacity, actual: writes.length },
    });
  return Array.from({ length: capacity }, (_, i) => {
    const write = writes[i];
    return write === undefined ? null : encode(write, `${list}[${i}]`);
  });
}

function writeJson(write: RecordWriteProofInput, name: string): Json {
  return {
    entry: recordWriteJson(write.entry, `${name}.entry`),
    exists: flag(write.exists),
    oldNext: field(write.oldNext, `${name}.oldNext`),
    oldLists: u64(write.oldLists, `${name}.oldLists`),
    ...mintPolicyJson(write.oldMintPolicy, name, "old"),
    ...quadPathJson(write.slot, name, "index", "path"),
    lowMember: field(write.low.member, `${name}.lowMember`),
    lowNext: field(write.low.next, `${name}.lowNext`),
    lowLists: u64(write.low.lists, `${name}.lowLists`),
    ...mintPolicyJson(write.low.mintPolicy, name, "low"),
    ...quadPathJson(write.lowPath, name, "lowIndex", "lowPath"),
  };
}

function trackingWriteJson(write: TrackingWriteProofInput, name: string): Json {
  return {
    member: field(write.entry.member, `${name}.member`),
    ...trackingFieldsJson(write.entry, name),
    ...trackingPathJson(write.slot, name, "index", "path"),
    lowRecord: trackingRecordJson(write.lowRecord, `${name}.lowRecord`),
    ...trackingPathJson(write.lowPath, name, "lowIndex", "lowPath"),
  };
}

/** Go `uint64`, a tracking next index stops at the tree's capacity. */
function trackingNextIndex(value: bigint, name: string): number {
  if (value > TRACKING_CAPACITY)
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: name, length: 8 } });
  return u64(value, name);
}

/** The flat siblings `newQuadPath` chunks, leaf level first. */
function trackingPathJson(path: QuadPath, name: string, index: string, siblings: string): Json {
  const levels = sized(path.siblings, TRACKING_QUAD_HEIGHT, `${name}.${siblings}`);
  return {
    [index]: integer(path.index, `${name}.${index}`, 0, MAX_TRACKING_INDEX),
    [siblings]: levels.flatMap((level, l) =>
      fields(level, QUAD_ARITY - 1, `${name}.${siblings}[${l}]`),
    ),
  };
}

function recordWriteJson(entry: RecordWrite, name: string): Json {
  return {
    member: field(entry.member, `${name}.member`),
    mask: u64(entry.mask, `${name}.mask`),
    value: u64(entry.value, `${name}.value`),
    mintPolicy: field(mintPolicyWriteField(entry.mintPolicy), `${name}.mintPolicy`),
    withdrawalThreshold: field(
      bigIntBytes(entry.mintPolicy?.withdrawalThreshold ?? 0n, 32) as Bytes32,
      `${name}.withdrawalThreshold`,
    ),
    assetLimits: limitsJson((entry.mintPolicy ?? EMPTY_MINT_POLICY).limits, `${name}.assetLimits`),
  };
}

function limitsJson(limits: AssetLimits, name: string): string[] {
  return assetLimitsFields(limits).map((limit, index) => field(limit, `${name}[${String(index)}]`));
}

/** Go keeps the index and the flat siblings, leaf level first, three per level in child order. */
function quadPathJson(path: QuadPath, name: string, index: string, siblings: string): Json {
  const levels = sized(path.siblings, QUAD_HEIGHT, `${name}.${siblings}`);
  return {
    [index]: integer(path.index, `${name}.${index}`, 0, Number.MAX_SAFE_INTEGER),
    [siblings]: levels.flatMap((level, l) =>
      fields(level, QUAD_ARITY - 1, `${name}.${siblings}[${l}]`),
    ),
  };
}

/** Go `Field`, `0x` and 64 lowercase hex digits below the modulus. */
function field(value: Bytes32, name: string): string {
  const bytes = checkedLength(value, 32, name);
  bytesField(bytes, name);
  return `0x${bytesToHex(bytes)}`;
}

function fields(values: readonly Bytes32[], length: number, name: string): readonly string[] {
  return sized(values, length, name).map((value, i) => field(value, `${name}[${i}]`));
}

/** Go `Bytes`, the circuit array it fills fixes its length. */
function hexBytes(value: Uint8Array, length: number, name: string): string {
  return `0x${bytesToHex(checkedLength(value, length, name))}`;
}

function checkedLength(value: Uint8Array, length: number, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length)
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: {
        field: name,
        expected: length,
        actual: value instanceof Uint8Array ? value.length : -1,
      },
    });
  return value;
}

function listLength(values: readonly unknown[]): number {
  if (!Array.isArray(values)) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  return values.length;
}

function sized<T>(values: readonly T[], length: number, name: string): readonly T[] {
  if (!Array.isArray(values) || values.length !== length)
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: {
        field: name,
        expected: length,
        actual: Array.isArray(values) ? values.length : -1,
      },
    });
  return values;
}

function integer(value: number, name: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new ClientError("CLIENT_INVALID_INTEGER", {
      details: { field: name, length: byteWidth(maximum) },
    });
  return value;
}

/** Go `uint64`, sent as a JSON number, so above the safe range no JSON number is exact. */
function u64(value: bigint, name: string): number {
  if (typeof value !== "bigint" || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER))
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: name, length: 8 } });
  return Number(value);
}

function flag(value: boolean): boolean {
  if (typeof value !== "boolean") throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  return value;
}

function byteWidth(maximum: number): number {
  return maximum <= U8_MAX ? 1 : maximum <= U32_MAX ? 4 : 8;
}

/** The circuit bounds this canonical field to u64; JSON numbers cannot carry that full range. */
function withdrawalAmount(amount: bigint): string {
  if (typeof amount !== "bigint" || amount < 0n || amount > 0xffff_ffff_ffff_ffffn)
    throw new ClientError("CLIENT_INVALID_INTEGER", {
      details: { field: "withdrawal.amount", length: 8 },
    });
  return field(bigIntBytes(amount) as Bytes32, "withdrawal.amount");
}
