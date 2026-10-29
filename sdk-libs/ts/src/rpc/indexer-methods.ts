import type { MethodDescriptor } from "@heliuslabs/zolana/internal";

import {
  decodeStorageMemberOpenings,
  decodeStorageMemberPage,
  decodeStorageRecordPool,
  encodeStorageMemberOpeningsRequest,
  encodeStorageMemberRecordsRequest,
  encodeStorageRecordPoolRequest,
} from "../protocol/indexer/indexer-codec.js";
import type {
  StorageMemberOpeningsRequest,
  StorageMemberOpeningsResponse,
  StorageMemberPageResponse,
  StorageMemberRecordsRequest,
  StorageRecordPoolRequest,
  StorageRecordPoolResponse,
} from "../protocol/indexer/indexer-types.js";

export const getStorageMemberOpeningsMethod: MethodDescriptor<
  StorageMemberOpeningsRequest,
  StorageMemberOpeningsResponse
> = {
  name: "getStorageMemberOpenings",
  encodeRequest: encodeStorageMemberOpeningsRequest,
  decodeResponse: decodeStorageMemberOpenings,
};
export const getStorageMemberRecordsMethod: MethodDescriptor<
  StorageMemberRecordsRequest,
  StorageMemberPageResponse
> = {
  name: "getStorageMemberRecords",
  encodeRequest: encodeStorageMemberRecordsRequest,
  decodeResponse: decodeStorageMemberPage,
};
export const getStorageRecordPoolMethod: MethodDescriptor<
  StorageRecordPoolRequest,
  StorageRecordPoolResponse
> = {
  name: "getStorageRecordPool",
  encodeRequest: encodeStorageRecordPoolRequest,
  decodeResponse: decodeStorageRecordPool,
};
