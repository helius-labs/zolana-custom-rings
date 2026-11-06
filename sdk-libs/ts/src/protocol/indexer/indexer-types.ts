import type { MintPolicy } from "../membership/mint-policy.js";
import type { Address } from "@heliuslabs/spr";
import type { indexerTypes } from "@heliuslabs/spr/internal";

type Hash = indexerTypes.Hash;
type IndexerContext = indexerTypes.IndexerContext;

export interface RingMemberRecordView {
  readonly member: Hash;
  readonly next: Hash;
  readonly lists: bigint;
  readonly mintPolicy: MintPolicy;
}
/** A leaf and the other three children of each level in child order, leaf level first. */
export interface RingRecordPathView {
  readonly index: bigint;
  readonly siblings: readonly (readonly Hash[])[];
}

/** A member's record under one root, or the low record bracketing its absence. */
export interface RingMemberOpeningView {
  readonly present: boolean;
  readonly record: RingMemberRecordView;
  readonly path: RingRecordPathView;
}

export interface RingListWriteView {
  readonly member: Hash;
  readonly mask: bigint;
  readonly value: bigint;
  readonly mintPolicy: MintPolicy | null;
}

/** Paths are under the root the preceding writes reached. */
export interface RingRecordWriteView {
  readonly member: Hash;
  readonly mask: bigint;
  readonly value: bigint;
  readonly exists: boolean;
  readonly oldNext: Hash;
  readonly oldLists: bigint;
  readonly oldMintPolicy: MintPolicy;
  readonly slot: RingRecordPathView;
  readonly low: RingMemberRecordView;
  readonly lowPath: RingRecordPathView;
  readonly mintPolicy: MintPolicy | null;
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

export interface StorageMemberOpeningsResponse {
  readonly context: IndexerContext;
  readonly root: StorageRootView;
  /** In request order. */
  readonly openings: readonly RingMemberOpeningView[];
}

/** Rust `GetStorageMemberRecordsRequest`. */
export interface StorageMemberRecordsRequest {
  readonly registry: Address;
  readonly expectedRoot: Hash;
  readonly startIndex: bigint;
  readonly limit: number;
}

export interface StorageMemberPageResponse {
  readonly context: IndexerContext;
  readonly root: StorageRootView;
  readonly records: readonly Readonly<{ record: RingMemberRecordView; path: RingRecordPathView }>[];
  readonly nextLeafIndex: bigint | null;
}

/** Rust `GetStorageRecordPoolRequest`. */
export interface StorageRecordPoolRequest extends StorageMemberOpeningsRequest {
  readonly openings: number;
}

export interface StorageRecordPoolResponse {
  readonly context: IndexerContext;
  readonly root: StorageRootView;
  /** Distinct leaves in first use order, each path cut at the canopy. */
  readonly records: readonly Readonly<{ record: RingMemberRecordView; path: RingRecordPathView }>[];
  readonly canopy: readonly Hash[];
  /** `subjects[i]` indexes the record holding or bracketing member `i`. */
  readonly subjects: readonly number[];
}

/** Rust `StorageWriteView`. */
export type StorageWriteView = RingListWriteView;

/** Rust `GetStorageApplyProofInputsRequest`. */
export interface StorageApplyProofInputsRequest {
  readonly registry: Address;
  readonly writes: readonly StorageWriteView[];
}

export interface StorageApplyProofInputsResponse {
  readonly context: IndexerContext;
  readonly revision: bigint;
  readonly oldRoot: Hash;
  readonly newRoot: Hash;
  readonly oldNextIndex: bigint;
  readonly newNextIndex: bigint;
  readonly chainStart: Hash;
  readonly chainEnd: Hash;
  /** In request order. */
  readonly writes: readonly RingRecordWriteView[];
}
