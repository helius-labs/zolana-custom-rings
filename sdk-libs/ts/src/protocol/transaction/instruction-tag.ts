import { InstructionTag } from "@heliuslabs/zolana/interface";

/** Rust `tag`, the first byte of the ring program's instruction data. */
export const RingInstructionTag = Object.freeze({
  transfer: 43,
  legacyTransact: 3,
  legacyDelegateTransact: 25,
  grantReadAccess: 4,
  revokeReadAccess: 5,
  updateAuthority: 6,
  setPaused: 11,
  clearCoSigner: 21,
  merge: InstructionTag.ringMergeTransact,
  setDelegate: 24,
  authorityTransfer: 44,
  setCoSigner: 27,
  createMemberRegistry: 28,
  registerKey: 29,
  deposit: 31,
  writeRecords: 39,
  authorityWriteRecords: 40,
  applyRecords: 41,
  setInsertFee: 42,
  syncRoots: 48,
  initialize: 53,
  updatePolicy: 54,
} as const);
export type RingInstructionTag = (typeof RingInstructionTag)[keyof typeof RingInstructionTag];
