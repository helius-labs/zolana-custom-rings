import type { Address } from "@heliuslabs/zolana";
import type { MethodDescriptor } from "@heliuslabs/zolana/internal";

import {
  decodeRingApplyProofInputs,
  decodeRingMemberOpening,
  decodeRingMemberOpenings,
  decodeRingMemberPage,
  decodeRingRecordPool,
  decodeRingRecordQueue,
  decodeRingRegistryState,
  encodeRingApplyProofInputsRequest,
  encodeRingMemberOpeningsRequest,
  encodeRingMemberProofRequest,
  encodeRingMemberRecordsRequest,
  encodeRingMemberRegistryRootRequest,
  encodeRingRecordPoolRequest,
  decodeStorageMemberOpenings,
  decodeStorageRecordPool,
  encodeStorageMemberOpeningsRequest,
  encodeStorageRecordPoolRequest,
} from "../protocol/indexer/indexer-codec.js";
import type {
  RingApplyProofInputsRequest,
  RingApplyProofInputsResponse,
  RingMemberOpeningResponse,
  RingMemberOpeningsRequest,
  RingMemberOpeningsResponse,
  RingMemberPageResponse,
  RingMemberProofRequest,
  RingMemberRecordsRequest,
  RingRecordPoolRequest,
  RingRecordPoolResponse,
  RingRecordQueueResponse,
  RingRegistryStateResponse,
  StorageMemberOpeningsRequest,
  StorageMemberOpeningsResponse,
  StorageRecordPoolRequest,
  StorageRecordPoolResponse,
} from "../protocol/indexer/indexer-types.js";

export const getRingMemberRecordMethod: MethodDescriptor<
  RingMemberProofRequest,
  RingMemberOpeningResponse
> = {
  name: "getRingMemberRecord",
  encodeRequest: encodeRingMemberProofRequest,
  decodeResponse: decodeRingMemberOpening,
};
export const getRingMemberRecordsMethod: MethodDescriptor<
  RingMemberRecordsRequest,
  RingMemberPageResponse
> = {
  name: "getRingMemberRecords",
  encodeRequest: encodeRingMemberRecordsRequest,
  decodeResponse: decodeRingMemberPage,
};
export const getRingMemberRegistryRootMethod: MethodDescriptor<
  Readonly<{ ringProgramId: Address }>,
  RingRegistryStateResponse
> = {
  name: "getRingMemberRegistryRoot",
  encodeRequest: encodeRingMemberRegistryRootRequest,
  decodeResponse: decodeRingRegistryState,
};

export const getRingMemberOpeningsMethod: MethodDescriptor<
  RingMemberOpeningsRequest,
  RingMemberOpeningsResponse
> = {
  name: "getRingMemberOpenings",
  encodeRequest: encodeRingMemberOpeningsRequest,
  decodeResponse: decodeRingMemberOpenings,
};
export const getRingRecordPoolMethod: MethodDescriptor<
  RingRecordPoolRequest,
  RingRecordPoolResponse
> = {
  name: "getRingRecordPool",
  encodeRequest: encodeRingRecordPoolRequest,
  decodeResponse: decodeRingRecordPool,
};
export const getRingRecordQueueMethod: MethodDescriptor<
  Readonly<{ ringProgramId: Address }>,
  RingRecordQueueResponse
> = {
  name: "getRingRecordQueue",
  encodeRequest: encodeRingMemberRegistryRootRequest,
  decodeResponse: decodeRingRecordQueue,
};
export const getRingApplyProofInputsMethod: MethodDescriptor<
  RingApplyProofInputsRequest,
  RingApplyProofInputsResponse
> = {
  name: "getRingApplyProofInputs",
  encodeRequest: encodeRingApplyProofInputsRequest,
  decodeResponse: decodeRingApplyProofInputs,
};
export const getStorageMemberOpeningsMethod: MethodDescriptor<
  StorageMemberOpeningsRequest,
  StorageMemberOpeningsResponse
> = {
  name: "getStorageMemberOpenings",
  encodeRequest: encodeStorageMemberOpeningsRequest,
  decodeResponse: decodeStorageMemberOpenings,
};
export const getStorageRecordPoolMethod: MethodDescriptor<
  StorageRecordPoolRequest,
  StorageRecordPoolResponse
> = {
  name: "getStorageRecordPool",
  encodeRequest: encodeStorageRecordPoolRequest,
  decodeResponse: decodeStorageRecordPool,
};
