import { InstructionTag } from "@heliuslabs/zolana/interface";

/** Rust `tag`, the first byte of the ring program's instruction data. */
export const RingInstructionTag = Object.freeze({
  createConfig: 1,
  initSppRingConfig: 2,
  transact: 43,
  legacyTransact: 3,
  legacyDelegateTransact: 25,
  // Tags 4 and 5 are retired, never reuse them.
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
  // Tags 28 and 29 are retired, never reuse them.
  auditedDeposit: 31,
  // Tags 39 to 42 are retired, never reuse them.
  syncRoots: 48,
} as const);
export type RingInstructionTag = (typeof RingInstructionTag)[keyof typeof RingInstructionTag];
