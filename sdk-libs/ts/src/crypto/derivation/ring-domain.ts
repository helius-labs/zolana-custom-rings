import { rightAlign, u32be } from "@heliuslabs/spr/internal";
import { type Bytes32, poseidon } from "@heliuslabs/spr/keypair";

/** Distinct ASCII tags, the first Poseidon input, mirroring Rust `custom_ring_interface::domain`. */
export const RingDomain = Object.freeze({
  deliveredSlotSecret: 0x4352_4453, // "CRDS"
  recipientTagDomain: 0x4352_5254, // "CRRT"
  senderTagDomain: 0x4352_5354, // "CRST"
  blindingSeed: 0x4352_4253, // "CRBS"
  transferStatement: 0x4352_5458, // "CRTX"
  policyTable: 0x4352_5442, // "CRTB"
  recordWrite: 0x4352_5157, // "CRQW"
  applyRecords: 0x4352_4150, // "CRAP"
  registerKey: 0x4352_5247, // "CRRG"
  mergeStatement: 0x4352_4d47, // "CRMG"
  withdrawals: 0x4352_5057, // "CRPW"
  recordUpdate: 0x4352_5255, // "CRRU"
  walletGrant: 0x4352_5747, // "CRWG"
  trackingLeaf: 0x4352_544b,
  trackingEntry: 0x4352_5451,
  applyEnrollments: 0x4352_5441,
  listTag: 0x4352_5054,
  listPosition: 0x4352_504c,
  /** Rust `zolana_ring_keys::DUMMY_KEY_DOMAIN`. */
  dummyKey: 0x4352_444b, // "CRDK"
} as const);
export type RingDomain = (typeof RingDomain)[keyof typeof RingDomain];

export function domainField(domain: RingDomain): Bytes32 {
  return rightAlign(u32be(domain));
}

/** `Poseidon(domain, ...fields)` over fresh copies, wiped once hashed since they may hold secrets. */
export function domainHash(domain: RingDomain, fields: readonly Uint8Array[]): Bytes32 {
  try {
    return poseidon([domainField(domain), ...fields]) as Bytes32;
  } finally {
    fields.forEach((field) => field.fill(0));
  }
}
