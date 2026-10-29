import { InstructionTag } from "@heliuslabs/zolana/interface";

/** Rust `tag`, the first byte of the ring program's instruction data. */
export const RingInstructionTag = Object.freeze({
  transfer: 43,
  legacyTransact: 3,
  legacyDelegateTransact: 25,
  // Tags 4 and 5 are retired, never reuse them.
  updateAuthority: 6,
  setPaused: 11,
  clearCoSigner: 21,
  merge: InstructionTag.ringMergeTransact,
  setDelegate: 24,
  authorityTransfer: 44,
  setCoSigner: 27,
  // Tags 28 and 29 are retired, never reuse them.
  deposit: 31,
  // Tags 39 to 42 are retired, never reuse them.
  syncRoots: 48,
  initialize: 53,
  updatePolicy: 54,
} as const);
export type RingInstructionTag = (typeof RingInstructionTag)[keyof typeof RingInstructionTag];
