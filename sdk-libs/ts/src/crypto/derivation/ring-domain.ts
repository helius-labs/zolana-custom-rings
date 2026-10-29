import { rightAlign, checkedBytes, u32be } from "@heliuslabs/zolana/internal";
import { type Bytes32, poseidon } from "@heliuslabs/zolana/keypair";

/** Distinct ASCII tags, the first Poseidon input, mirroring Rust `custom_ring_interface::domain`. */
export const RingDomain = Object.freeze({
  auditStatement: 0x4352_4155, // "CRAU"
  deliveredSlotSecret: 0x4352_4453, // "CRDS"
  blindingSeed: 0x4352_4253, // "CRBS"
  senderCommitment: 0x4352_5343, // "CRSC"
  disclosurePad: 0x4352_4f44, // "CROD"
  policyStatement: 0x4352_504f, // "CRPO"
  policyTable: 0x4352_5442, // "CRTB"
  queueWrite: 0x4352_5157, // "CRQW"
  applyRecords: 0x4352_4150, // "CRAP"
  registerKey: 0x4352_5247, // "CRRG"
  depositBlinding: 0x4352_4442, // "CRDB"
  depositStatement: 0x4352_4450, // "CRDP"
  mergeStatement: 0x4352_4d47, // "CRMG"
  withdrawals: 0x4352_5057, // "CRPW"
  withdrawalExemption: 0x4352_5758, // "CRWX"
} as const);
export type RingDomain = (typeof RingDomain)[keyof typeof RingDomain];

/** Bound into every policy statement, a layout change raises it. */
export const POLICY_STATEMENT_VERSION = 4n;

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

/** `Poseidon(CRDB, blinding_secret)`. */
export function depositBlinding(blindingSecret: Bytes32): Bytes32 {
  return domainHash(RingDomain.depositBlinding, [
    checkedBytes<Bytes32>(blindingSecret, 32, "deposit blinding secret"),
  ]);
}
