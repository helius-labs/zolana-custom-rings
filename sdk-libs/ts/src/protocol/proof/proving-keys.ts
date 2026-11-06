import { type ExpectedProvingKey } from "@heliuslabs/spr/internal";
import { InterfaceError } from "@heliuslabs/spr/interface";

import { RingError } from "../error.js";
import { RING_PROVING_KEY_SHA256S } from "./ring-proving-keys.js";
import { APPLY_BATCH } from "../membership/member-registry.js";
import {
  transferCircuitType,
  transferKeys,
  transferPoolCapacity,
  type PolicyPoolCapacity,
  type TransferKeyCircuit,
} from "./transfer-shapes.js";

export { RING_PROVING_KEY_SHA256S };
export { transferPoolCapacity as policyPoolCapacity, type PolicyPoolCapacity };

/** A ring circuit by the shape its key serves, Rust `RingCircuit`. */
export type RingKeyCircuit =
  | TransferKeyCircuit
  | Readonly<{ family: "applyRecords"; writes: number; private: boolean }>
  | Readonly<{ family: "applyEnrollments"; writes: number }>
  | Readonly<{ family: "registerKey" }>
  | Readonly<{ family: "merge" }>;

/** Go `registry.ApplyWidths`. */
const APPLY_WIDTHS: readonly number[] = Object.freeze([1, 2, 4, 8, APPLY_BATCH]);

/** Rust `RingCircuit::apply_records`, the narrowest apply key holding `count` writes. */
export function applyKeyWidth(count: number): number {
  const width = APPLY_WIDTHS.find((writes) => count <= writes);
  if (count < 1 || width === undefined)
    throw new RingError("RING_STORAGE_WRITE_INVALID", { details: { reason: "UnsupportedBatch" } });
  return width;
}

/** Rust `RING_KEYS`, every ring key in its order, `name` the circuit type the prover serves. */
export const RING_KEYS: readonly Readonly<{
  circuit: RingKeyCircuit;
  name: string;
}>[] = Object.freeze(
  (
    [
      ...transferKeys().map((circuit) => [circuit, transferCircuitType(circuit)] as const),
      ...[false, true].flatMap((isPrivate) =>
        APPLY_WIDTHS.map(
          (writes) =>
            [
              { family: "applyRecords", writes, private: isPrivate },
              `custom-ring-apply-records-${isPrivate ? "private-" : ""}${writes}`,
            ] as const,
        ),
      ),
      ...APPLY_WIDTHS.map(
        (writes) =>
          [
            { family: "applyEnrollments", writes },
            `custom-ring-apply-enrollments-${writes}`,
          ] as const,
      ),
      [{ family: "registerKey" }, "custom-ring-register-key"],
      [{ family: "merge" }, "custom-ring-merge"],
    ] as const
  ).map(([circuit, name]) =>
    Object.freeze({ circuit: Object.freeze<RingKeyCircuit>(circuit), name }),
  ),
);

/** The circuit type the prover serves `circuit` under, refused for a shape no ring key serves. */
export function ringCircuitType(circuit: RingKeyCircuit): string {
  const key = RING_KEYS.find((entry) => sameRingCircuit(entry.circuit, circuit));
  if (key === undefined)
    throw new InterfaceError("INTERFACE_INVALID_SHAPE", {
      circuit: circuit.family,
    });
  return key.name;
}

/** The ring key a proof must come from, the file name Go `Key.KeyFile` derives from the circuit type. */
export function ringProvingKey(circuit: RingKeyCircuit): ExpectedProvingKey {
  return pinnedProvingKey(`${ringCircuitType(circuit).replaceAll("-", "_")}.key`);
}

/** SPP's authority exit keys, zolana's prover serves them. */
export const RING_AUTHORITY_EXIT_SHAPES: readonly Readonly<{
  nInputs: number;
  nOutputs: number;
}>[] = Object.freeze([
  Object.freeze({ nInputs: 2, nOutputs: 2 }),
  Object.freeze({ nInputs: 4, nOutputs: 4 }),
]);

/** A shape off the two keys is refused by name. */
export function ringAuthorityExitKeyName(
  shape: Readonly<{ nInputs: number; nOutputs: number }>,
): string {
  const { nInputs, nOutputs } = shape;
  if (!RING_AUTHORITY_EXIT_SHAPES.some((s) => s.nInputs === nInputs && s.nOutputs === nOutputs))
    throw new RingError("RING_PROVING_KEYS_MISSING", {
      details: { keyNames: `transfer_ring_authority_exit_${nInputs}_${nOutputs}.key` },
    });
  return `transfer_ring_authority_exit_${nInputs}_${nOutputs}.key`;
}

/** A key without a pin has no committed verifying key, the proof is refused by the key's name. */
function pinnedProvingKey(name: string): ExpectedProvingKey {
  const sha256 = Object.hasOwn(RING_PROVING_KEY_SHA256S, name)
    ? RING_PROVING_KEY_SHA256S[name]
    : undefined;
  if (sha256 === undefined)
    throw new RingError("RING_PROVING_KEYS_MISSING", { details: { keyNames: name } });
  return Object.freeze({ name, sha256 });
}

function sameRingCircuit(left: RingKeyCircuit, right: RingKeyCircuit): boolean {
  if (left.family !== right.family) return false;
  const shape = (circuit: RingKeyCircuit): readonly unknown[] =>
    Object.entries(circuit)
      .sort(([a], [b]) => a.localeCompare(b))
      .flat();
  const [first, second] = [shape(left), shape(right)];
  return first.length === second.length && first.every((value, i) => value === second[i]);
}
