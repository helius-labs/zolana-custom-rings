import { InstructionTag } from "@heliuslabs/zolana/interface";

/** Rust `tag`, the first byte of the ring program's instruction data. */
export const RingInstructionTag = Object.freeze({
  createConfig: 1,
  initSppRingConfig: 2,
  transact: 43,
  legacyTransact: 3,
  legacyDelegateTransact: 25,
  grantReadAccess: 4,
  revokeReadAccess: 5,
  setAuthority: 6,
  createPolicy: 7,
  setPolicySource: 10,
  setPaused: 11,
  setPolicyRules: 12,
  /** SPP's `RING_DEPOSIT`, always refused, `auditedDeposit` replaces it. */
  deposit: InstructionTag.ringDeposit,
  clearCoSigner: 21,
  merge: InstructionTag.ringMergeTransact,
  setDelegate: 24,
  delegateTransact: 44,
  setCoSigner: 27,
  createMemberRegistry: 28,
  registerKey: 29,
  auditedDeposit: 31,
  writeRecords: 39,
  authorityWriteRecords: 40,
  applyRecords: 41,
  setInsertFee: 42,
  syncRoots: 48,
} as const);
export type RingInstructionTag = (typeof RingInstructionTag)[keyof typeof RingInstructionTag];
