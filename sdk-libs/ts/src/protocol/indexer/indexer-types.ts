import type { MintPolicy } from "../membership/mint-policy.js";
import type { Address } from "@heliuslabs/zolana";
import type { indexerTypes } from "@heliuslabs/zolana/internal";

type Hash = indexerTypes.Hash;
type Base64String = indexerTypes.Base64String;
type IndexerContext = indexerTypes.IndexerContext;

export interface RingMemberRequest {
  readonly ringProgramId: Address;
  readonly member: Hash;
}

export interface RingMemberProofRequest extends RingMemberRequest {
  readonly expectedRoot: Hash;
  readonly expectedNextIndex: bigint;
}

export interface RingMemberRecordView {
  readonly member: Hash;
  readonly next: Hash;
  readonly lists: bigint;
  readonly escrowKey: Hash;
  readonly ownerPubkey?: Address | null;
  /** `escrowKey` is `Poseidon(nullifierPk, hash_bytes(ciphertext))`. */
  readonly nullifierPk?: Hash | null;
  readonly ephPk: Base64String | null;
  readonly ciphertext: Base64String | null;
  readonly mintPolicy: MintPolicy;
}
export interface RingMemberRecordsRequest {
  readonly ringProgramId: Address;
  readonly expectedRoot: Hash;
  readonly expectedNextIndex: bigint;
  readonly startIndex: bigint;
  readonly limit: number;
}

/** A leaf and the other three children of each level in child order, leaf level first. */
export interface RingRecordPathView {
  readonly index: bigint;
  readonly siblings: readonly (readonly Hash[])[];
}

/** A root the on-chain registry history holds. */
export interface RingRegistryRootView {
  readonly root: Hash;
  readonly rootIndex: number;
  /** The queue position applied at the root, checked against the registry floor. */
  readonly applied: bigint;
  readonly nextIndex: bigint;
}

/** A member's record under one root, or the low record bracketing its absence. */
export interface RingMemberOpeningView {
  readonly present: boolean;
  readonly record: RingMemberRecordView;
  readonly path: RingRecordPathView;
}

export interface RingMemberOpeningResponse {
  readonly context: IndexerContext;
  readonly root: RingRegistryRootView;
  readonly opening: RingMemberOpeningView;
}

/** At most `MAX_RING_MEMBER_PAGE_LIMIT` members under one history root. */
export interface RingMemberOpeningsRequest {
  readonly ringProgramId: Address;
  readonly members: readonly Hash[];
  readonly expectedRoot: Hash;
}

export interface RingMemberOpeningsResponse {
  readonly context: IndexerContext;
  readonly root: RingRegistryRootView;
  /** In request order. */
  readonly openings: readonly RingMemberOpeningView[];
}

/** At most `MAX_RING_MEMBER_BATCH` openings, `members` distinct and at most `openings`. */
export interface RingRecordPoolRequest {
  readonly ringProgramId: Address;
  readonly members: readonly Hash[];
  readonly expectedRoot: Hash;
  readonly openings: number;
}

export interface RingRecordPoolResponse {
  readonly context: IndexerContext;
  readonly root: RingRegistryRootView;
  /** Distinct leaves in first use order, each path cut at the canopy. */
  readonly records: readonly Readonly<{ record: RingMemberRecordView; path: RingRecordPathView }>[];
  readonly canopy: readonly Hash[];
  /** `subjects[i]` indexes the record holding or bracketing member `i`. */
  readonly subjects: readonly number[];
}

export interface RingMemberPageResponse {
  readonly context: IndexerContext;
  readonly root: RingRegistryRootView;
  readonly records: readonly Readonly<{ record: RingMemberRecordView; path: RingRecordPathView }>[];
  readonly nextLeafIndex: bigint | null;
}

export interface RingRootEntryView {
  readonly root: Hash;
  readonly applied: bigint;
  readonly slot: bigint;
}

/** The registry account as projected. */
export interface RingRegistryStateResponse {
  readonly context: IndexerContext;
  /** Entry `i` sits at history slot `i`, `null` for a slot never written. */
  readonly history: readonly (RingRootEntryView | null)[];
  readonly historyCursor: number;
  readonly nextIndex: bigint;
  readonly floor: bigint;
  readonly priorFloor: bigint;
  readonly floorSlot: bigint;
  /** The empty leaf at `nextIndex` under the newest root, `null` once the registry is full. */
  readonly appendPath: RingRecordPathView | null;
}

export interface RingQueueEntryView {
  readonly position: bigint;
  readonly member: Hash;
  readonly mask: bigint;
  readonly value: bigint;
  /** Zero except on a RegisterKey write. */
  readonly escrowKey: Hash;
  readonly slot: bigint;
  readonly mintPolicy: MintPolicy | null;
}

export interface RingRecordQueueResponse {
  readonly context: IndexerContext;
  readonly head: bigint;
  readonly tail: bigint;
  /** `chain(head - 1)`, zero at head 0. */
  readonly chainHead: Hash;
  /** Positions `head .. tail`. */
  readonly entries: readonly RingQueueEntryView[];
}

export interface RingListWriteView {
  readonly member: Hash;
  readonly mask: bigint;
  readonly value: bigint;
  readonly mintPolicy: MintPolicy | null;
}

export interface RingApplyProofInputsRequest {
  readonly ringProgramId: Address;
  /** Applied after every pending write. */
  readonly authorityWrites: readonly RingListWriteView[];
}

/** Paths are under the root the preceding writes reached. */
export interface RingRecordWriteView {
  readonly member: Hash;
  readonly mask: bigint;
  readonly value: bigint;
  readonly escrowKey: Hash;
  readonly exists: boolean;
  readonly oldNext: Hash;
  readonly oldLists: bigint;
  readonly oldEscrow: Hash;
  readonly oldMintPolicy: MintPolicy;
  readonly slot: RingRecordPathView;
  readonly low: RingMemberRecordView;
  readonly lowPath: RingRecordPathView;
  readonly mintPolicy: MintPolicy | null;
}

export interface RingApplyProofInputsResponse {
  readonly context: IndexerContext;
  readonly oldRoot: Hash;
  readonly newRoot: Hash;
  readonly oldNextIndex: bigint;
  readonly newNextIndex: bigint;
  readonly chainStart: Hash;
  readonly chainEnd: Hash;
  /** Queue order. */
  readonly writes: readonly RingRecordWriteView[];
}

/** Rust `StorageRootView`. */
export interface StorageRootView {
  readonly root: Hash;
  readonly revision: bigint;
  readonly nextIndex: bigint;
}

/** Rust `GetStorageMemberOpeningsRequest`, `registry` a `StorageRegistry` account. */
export interface StorageMemberOpeningsRequest {
  readonly registry: Address;
  readonly members: readonly Hash[];
  readonly expectedRoot: Hash;
}

export interface StorageMemberOpeningsResponse extends Omit<RingMemberOpeningsResponse, "root"> {
  readonly root: StorageRootView;
}

/** Rust `GetStorageRecordPoolRequest`. */
export interface StorageRecordPoolRequest extends StorageMemberOpeningsRequest {
  readonly openings: number;
}

export interface StorageRecordPoolResponse extends Omit<RingRecordPoolResponse, "root"> {
  readonly root: StorageRootView;
}

/** Rust `StorageWriteView`, `escrowKey` zero except on an escrow write. */
export interface StorageWriteView extends RingListWriteView {
  readonly escrowKey: Hash;
}

/** Rust `GetStorageApplyProofInputsRequest`. */
export interface StorageApplyProofInputsRequest {
  readonly registry: Address;
  readonly writes: readonly StorageWriteView[];
}

export interface StorageApplyProofInputsResponse extends RingApplyProofInputsResponse {
  readonly revision: bigint;
}
