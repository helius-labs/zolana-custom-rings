/** The SPP anonymous ring rail on the pinned SPP wire, Rust `CircuitId::AnonymousRingEddsa`. */
import type { Bytes32 } from "@heliuslabs/spr";
import {
  checkedBytes,
  encodeTransactExternalData,
  encodeTransactInstructionData,
} from "@heliuslabs/spr/internal";
import type { CircuitId, TransactInstructionData } from "@heliuslabs/spr/interface";

const ANONYMOUS_RING_EDDSA_TAG = 3;
/** Rust `CircuitId::RingAuthorityExit`, its payload is `RingAuthority`'s. */
const RING_AUTHORITY_EXIT_TAG = 9;
/** `u16 kind ‖ u8 inputs ‖ u8 outputs ‖ u8 publicAssetSlots`. */
const CIRCUIT_HEAD_LEN = 5;

export type AnonymousRingEddsaCircuit = Readonly<{
  kind: "anonymousRingEddsa";
  inputs: number;
  outputs: number;
  publicAssetSlots: number;
  proofData: Readonly<{
    bsb22Commitment: Readonly<{ commitment: Bytes32; commitmentPok: Bytes32 }>;
    defaultOwnerTag?: Bytes32;
  }>;
}>;

export type RingAuthorityExitCircuit = Readonly<{
  kind: "ringAuthorityExit";
  inputs: number;
  outputs: number;
  publicAssetSlots: number;
}>;

export type RingCircuitId = CircuitId | AnonymousRingEddsaCircuit | RingAuthorityExitCircuit;

export type RingTransactInstructionData = Omit<TransactInstructionData, "circuit"> &
  Readonly<{ circuit: RingCircuitId }>;

/** Splices the anonymous and exit selectors into the pinned encoding of the same shape. */
export function encodeRingTransactInstructionData(value: RingTransactInstructionData): Uint8Array {
  const { circuit } = value;
  const at = encodeTransactExternalData(value).length + 32;
  if (circuit.kind === "ringAuthorityExit") {
    const encoded = encodeTransactInstructionData({
      ...value,
      circuit: { ...circuit, kind: "ringAuthority" },
    });
    new DataView(encoded.buffer, encoded.byteOffset).setUint16(at, RING_AUTHORITY_EXIT_TAG, true);
    return encoded;
  }
  if (circuit.kind !== "anonymousRingEddsa")
    return encodeTransactInstructionData({ ...value, circuit });
  const encoded = encodeTransactInstructionData({
    ...value,
    circuit: {
      kind: "confidentialRingEddsa",
      inputs: circuit.inputs,
      outputs: circuit.outputs,
      publicAssetSlots: circuit.publicAssetSlots,
    },
  });
  const head = encoded.slice(at, at + CIRCUIT_HEAD_LEN);
  new DataView(head.buffer).setUint16(0, ANONYMOUS_RING_EDDSA_TAG, true);
  const { bsb22Commitment, defaultOwnerTag } = circuit.proofData;
  const out = new Uint8Array(encoded.length + 32 + 32 + 1 + 32);
  let offset = 0;
  for (const part of [
    encoded.subarray(0, at),
    head,
    checkedBytes<Bytes32>(bsb22Commitment.commitment, 32, "circuit.bsb22Commitment.commitment"),
    checkedBytes<Bytes32>(
      bsb22Commitment.commitmentPok,
      32,
      "circuit.bsb22Commitment.commitmentPok",
    ),
    // Rust `FixedOptionOwnerTag`, an absent tag still writes its 32 zero bytes.
    Uint8Array.of(defaultOwnerTag === undefined ? 0 : 1),
    defaultOwnerTag === undefined
      ? new Uint8Array(32)
      : checkedBytes<Bytes32>(defaultOwnerTag, 32, "circuit.defaultOwnerTag"),
    encoded.subarray(at + CIRCUIT_HEAD_LEN),
  ]) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
