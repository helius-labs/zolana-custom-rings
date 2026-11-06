/** Rust `tag`, the first byte of the ring program's instruction data. */
export const RingInstructionTag = Object.freeze({
  transfer: 55,
  merge: 57,
  updateAuthority: 6,
  setPaused: 11,
  setCoSigner: 27,
  clearCoSigner: 62,
  setDelegate: 64,
  authorityTransfer: 56,
  initialize: 53,
  updatePolicy: 54,
} as const);
export type RingInstructionTag = (typeof RingInstructionTag)[keyof typeof RingInstructionTag];
