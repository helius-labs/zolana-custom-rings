import type { MintPolicy } from "../protocol/membership/mint-policy.js";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import type { Bytes32, RequestContext } from "@heliuslabs/zolana";
import type { Bytes64, Transaction } from "@heliuslabs/zolana/interface";
import type {
  BlockhashProvider,
  ChainReader,
  MergeAssembler,
  Proof,
  ProofAuthority,
  ProvenRingTransact,
  RingProvingConfig,
  TreeContext,
} from "@heliuslabs/zolana/client";
import type { SppProofInputs } from "@heliuslabs/zolana/transaction";
import type { Address, Signature } from "@solana/kit";

import type {
  ApplyProofInputs,
  MemberRecord,
  QuadPath,
  QueueEntry,
  RecordOpening,
} from "../protocol/membership/member-registry.js";
import type { RingTransactInstructionData } from "../protocol/proof/circuit.js";
import type { RingMergeDisclosureRequest } from "../crypto/audit/merge-disclosure.js";
import type { RingProofRequest } from "./prover/ring.js";

export interface RingMemberRequest {
  readonly ringProgramId: Address;
  readonly member: Bytes32;
}

/** A member under the registry state the caller read, Photon refuses another root. */
export interface RingMemberProofRequest extends RingMemberRequest {
  readonly expectedRoot: Bytes32;
  readonly expectedNextIndex: number;
}

/** A root the registry history holds, `applied` the queue position the floor rule reads. */
export interface RingRegistryRoot {
  readonly root: Bytes32;
  readonly rootIndex: number;
  readonly applied: bigint;
  readonly nextIndex: number;
}

/** The nullifier key a member escrowed through `RegisterKey`, sealed to the auditor. */
export interface RingSealedKey {
  /** The signer whose owner identity is the record's member. */
  readonly owner: Address;
  readonly nullifierPk: Bytes32;
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly ciphertext: Bytes32;
}

/** An opening the indexer served, unverified until checked against the bound root. */
export type RingMemberOpening = RecordOpening & Readonly<{ sealedKey?: RingSealedKey }>;

export interface RingMemberOpenings {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly root: RingRegistryRoot;
  /** In request order. */
  readonly openings: readonly RingMemberOpening[];
}

/** At most `MAX_RING_MEMBER_BATCH` openings, `members` distinct and at most `openings`. */
export interface RingRecordPoolRequest {
  readonly ringProgramId: Address;
  readonly members: readonly Bytes32[];
  readonly expectedRoot: Bytes32;
  readonly openings: number;
}

/** A root a `StorageRegistry` history holds, named by the revision the ring program reads. */
export interface StorageRoot {
  readonly root: Bytes32;
  readonly revision: bigint;
  readonly nextIndex: number;
}

/** At most `MAX_RING_MEMBER_BATCH` members of one `StorageRegistry`, all under `expectedRoot`. */
export interface StorageOpeningsRequest {
  readonly registry: Address;
  readonly members: readonly Bytes32[];
  readonly expectedRoot: Bytes32;
}

export interface StorageRecordPoolRequest extends StorageOpeningsRequest {
  readonly openings: number;
}

export type StorageMemberOpenings = Omit<RingMemberOpenings, "root"> &
  Readonly<{ root: StorageRoot }>;

/** Leaves of one `StorageRegistry` from `startIndex`, all under `expectedRoot`. */
export interface StoragePageRequest {
  readonly registry: Address;
  readonly expectedRoot: Bytes32;
  readonly startIndex: number;
  readonly limit: number;
}

export type StorageMemberPage = Omit<RingMemberPage, "root"> & Readonly<{ root: StorageRoot }>;

export type StorageRecordPool = Omit<RingRecordPool, "root"> & Readonly<{ root: StorageRoot }>;

/** A leaf the indexer served, with the key its member escrowed. */
export type RingServedRecord = Readonly<{
  record: MemberRecord;
  path: QuadPath;
  sealedKey?: RingSealedKey;
}>;

/** Records under one root, unverified until `verifyRecordPool` checks them against it. */
export interface RingRecordPool {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly root: RingRegistryRoot;
  /** Distinct leaves in first use order, each path cut at the canopy. */
  readonly records: readonly RingServedRecord[];
  readonly canopy: readonly Bytes32[];
  /** `subjects[i]` indexes the record holding or bracketing member `i`. */
  readonly subjects: readonly number[];
}

/** The record queue Photon projects, every pending write in queue order. */
export interface RingQueueState {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly head: bigint;
  readonly tail: bigint;
  /** `chain(head - 1)`. */
  readonly chainHead: Bytes32;
  readonly entries: readonly Readonly<{ position: bigint; entry: QueueEntry; slot: bigint }>[];
}

/** An authority list write, the queue entry without an escrow key. */
export interface RecordWrite {
  readonly mintPolicy?: MintPolicy;
  readonly member: Bytes32;
  readonly mask: bigint;
  readonly value: bigint;
}

export interface RingApplyProofInputs {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  /** Unverified until replayed from the registry the program holds. */
  readonly inputs: ApplyProofInputs;
}

/** The member's record or the low record bracketing its absence. */
export interface RingMemberRecordResult {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly root: RingRegistryRoot;
  readonly opening: RingMemberOpening;
}

export interface RingMemberPageRequest {
  readonly ringProgramId: Address;
  readonly expectedRoot: Bytes32;
  readonly expectedNextIndex: number;
  readonly startIndex: number;
  readonly limit: number;
}

/** Leaves from `startIndex` at one root, each with its path. */
export interface RingMemberPage {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly root: RingRegistryRoot;
  readonly records: readonly RingServedRecord[];
  /** `undefined` on the last page. */
  readonly nextLeafIndex: number | undefined;
}

/** The registry as Photon projects it, the account itself is the authority. */
export interface RingRegistryState {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  /** `MEMBER_REGISTRY_ROOT_HISTORY` slots, `undefined` where no root was pushed. */
  readonly history: readonly (
    | Readonly<{ root: Bytes32; applied: bigint; slot: bigint }>
    | undefined
  )[];
  readonly historyCursor: number;
  readonly nextIndex: number;
  readonly floor: bigint;
  readonly priorFloor: bigint;
  readonly floorSlot: bigint;
  /** The path of the empty leaf at `nextIndex`, absent once the registry is full. */
  readonly appendPath?: QuadPath;
}

/** Photon's record projection, the queue and the proof inputs of an application. */
export interface RingRecordReader {
  getRingMemberRecord(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingMemberRecordResult>;
  getRingMemberRecords(
    request: RingMemberPageRequest,
    context?: RequestContext,
  ): Promise<RingMemberPage>;
  getRingMemberRegistryRoot(
    request: Readonly<{ ringProgramId: Address }>,
    context?: RequestContext,
  ): Promise<RingRegistryState>;
  /** At most `MAX_RING_MEMBER_BATCH` members, all under `expectedRoot`. */
  getRingMemberOpenings(
    request: Readonly<{
      ringProgramId: Address;
      members: readonly Bytes32[];
      expectedRoot: Bytes32;
    }>,
    context?: RequestContext,
  ): Promise<RingMemberOpenings>;
  getRingRecordPool(
    request: RingRecordPoolRequest,
    context?: RequestContext,
  ): Promise<RingRecordPool>;
  getStorageMemberOpenings(
    request: StorageOpeningsRequest,
    context?: RequestContext,
  ): Promise<StorageMemberOpenings>;
  getStorageMemberRecords(
    request: StoragePageRequest,
    context?: RequestContext,
  ): Promise<StorageMemberPage>;
  getStorageRecordPool(
    request: StorageRecordPoolRequest,
    context?: RequestContext,
  ): Promise<StorageRecordPool>;
  getRingRecordQueue(
    request: Readonly<{ ringProgramId: Address }>,
    context?: RequestContext,
  ): Promise<RingQueueState>;
  /** Every pending write, then `authorityWrites`. */
  getRingApplyProofInputs(
    request: Readonly<{ ringProgramId: Address; authorityWrites: readonly RecordWrite[] }>,
    context?: RequestContext,
  ): Promise<RingApplyProofInputs>;
}

export type RingSubmissionStatus =
  | Readonly<{ kind: "unknown" }>
  | Readonly<{ kind: "confirmed"; slot: bigint }>
  | Readonly<{ kind: "failed"; instructionIndex?: number; customCode?: number }>
  | Readonly<{ kind: "expired" }>;

/** Identifies a broadcast awaiting confirmation or expiry. */
export interface RingSubmissionPending {
  readonly signature: Signature;
  readonly lastValidBlockHeight: bigint;
}

/** Separates signing and broadcast from submission status resolution. */
export interface RingSubmissionTransport {
  sign(transaction: Transaction, context?: RequestContext): Promise<Transaction>;
  /** A refusal before broadcast returns `failed`, a throw leaves the signature pending. */
  send(
    transaction: Transaction,
    context?: RequestContext,
  ): Promise<RingSubmissionStatus | undefined>;
  status(pending: RingSubmissionPending, context?: RequestContext): Promise<RingSubmissionStatus>;
}

export interface RingProver {
  /** One ring proof, the 192-byte `CustomRingProof` the ring program verifies. */
  proveRing(request: RingProofRequest, context?: RequestContext): Promise<Uint8Array>;
}

export type RingMergeClient = TreeContext &
  BlockhashProvider &
  Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getStorageMemberOpenings"> &
  Pick<MergeAssembler, "proveMerge"> &
  RingProver;

/** A nullifier key encrypted to the ring auditor. */
export interface RingSealedNullifierKey {
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly ciphertext: Bytes32;
}

/** The hidden owner's Ed25519 signature over the transfer's `messageHash`. */
export interface HiddenOwnerAuthorization {
  readonly publicKey: Bytes32;
  readonly signature: Bytes64;
}

export interface AnonymousRingTransactProofInput {
  readonly proofInputs: SppProofInputs;
  readonly ringProgramId: Address;
  readonly owner: HiddenOwnerAuthorization;
  /** The owner SPP reads from the SPL withdrawal's token account. */
  readonly exitTokenOwner?: Address;
  readonly keys: ProofAuthority;
  readonly config?: RingProvingConfig;
}

export type ProvenAnonymousRingTransact = Omit<ProvenRingTransact, "data"> &
  Readonly<{ data: RingTransactInstructionData }>;

/** The anonymous rail's SPP proof, absent from the pinned TS prover. */
export interface AnonymousRingTransactProver {
  proveAnonymousRingTransact(
    input: AnonymousRingTransactProofInput,
    context?: RequestContext,
  ): Promise<ProvenAnonymousRingTransact>;
}

/** The anonymous merge disclosure proof only the nullifier key holder makes. */
export interface RingSecretProver {
  proveRingWithSecret(
    request: RingMergeDisclosureRequest,
    context?: RequestContext,
  ): Promise<Proof>;
}
