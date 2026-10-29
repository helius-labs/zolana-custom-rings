/** The Ring RPC JSON-RPC refusal codes, `RingRpc` reports each as `RING_RPC_REFUSED` with its name. */
export const RingRpcRefusal = Object.freeze({
  ringNotServed: -32100,
  quoteFeePayer: -32101,
  quoteExpired: -32102,
  quoteWindow: -32103,
  invalidProofInputs: -32104,
  ringMismatch: -32105,
  railMismatch: -32106,
  ownerSignature: -32107,
  transferRefused: -32108,
  coSignRefused: -32109,
  unknownRelay: -32110,
  unexpectedSigner: -32111,
  signerSignature: -32112,
  sendRefused: -32113,
  recordsUnsynced: -32130,
  grantsInTree: -32131,
  recordWritesDisabled: -32140,
  entryCount: -32141,
  invalidEntry: -32142,
  recordUpdateSignature: -32143,
  recordUpdateExpired: -32144,
  unknownRing: -32145,
  registryNotServed: -32146,
  unauthorizedWriter: -32147,
  escrowProof: -32148,
  unknownUpdate: -32149,
  coSignDisabled: -32160,
  overLimit: -32161,
  repeatedAsset: -32162,
  limitsUnavailable: -32163,
  mergeSettingsUnavailable: -32170,
  staleMergeSettings: -32171,
  wrongCluster: -32190,
  escrowOnAnonymousRing: -32191,
  escrowRegistered: -32192,
  tokenAccountSetup: -32200,
  depositorIsFeePayer: -32201,
  notDelegate: -32220,
  escrowUnserved: -32221,
  sourceUnescrowed: -32222,
  sourceKey: -32223,
  relayUnavailable: -32224,
  readerGrantsInDatabase: -32230,
  enrolmentLists: -32240,
  notConfigAuthority: -32241,
  enrolmentBatch: -32242,
  unknownEnrolment: -32244,
  enrolmentWindow: -32245,
  enrolmentsFull: -32246,
} as const);

export type RingRpcRefusalName = keyof typeof RingRpcRefusal;

const REFUSAL_NAMES: ReadonlyMap<number, RingRpcRefusalName> = new Map(
  Object.entries(RingRpcRefusal).map(([name, code]) => [code, name as RingRpcRefusalName]),
);

export function ringRpcRefusalName(code: unknown): RingRpcRefusalName | undefined {
  return typeof code === "number" ? REFUSAL_NAMES.get(code) : undefined;
}
