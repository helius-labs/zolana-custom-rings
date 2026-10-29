import { type ExpectedProvingKey } from "@heliuslabs/zolana/internal";
import { InterfaceError } from "@heliuslabs/zolana/interface";

import { RING_PROVING_KEY_SHA256S } from "./ring-proving-keys.js";
import { APPLY_BATCH } from "../membership/member-registry.js";
import {
  ANONYMOUS_AUDIT_CLASSES,
  ANONYMOUS_ENTRY_CLASS,
  ANONYMOUS_ENTRY_OUTPUTS,
  MERGE_WIDTHS,
  DELIVERED_AUDIT_CAPACITIES,
} from "../codec/ring-disclosure-layout.js";
import { N_PUBLIC_SLOTS, RING_AUTHORITY_SHAPES } from "../transaction/spp.js";

export { RING_PROVING_KEY_SHA256S };

/** A ring circuit by the shape its key serves, Rust `RingCircuit`. */
export type RingKeyCircuit =
  | Readonly<{ family: "deliveredAudit"; outputs: number }>
  | Readonly<{ family: "anonymousAudit"; inputClass: number; outputs: number }>
  /** Opens every spent UTXO, the key of a transfer spending a default-ring note. */
  | Readonly<{ family: "anonymousEntryAudit"; inputClass: number; outputs: number }>
  | Readonly<{ family: "memberPolicy"; outputs: number; withdrawals: number; ownOnly: boolean }>
  | Readonly<{ family: "delegatePolicy"; inputs: number; outputs: number; ownOnly: boolean }>
  | Readonly<{ family: "applyRecords"; writes: number }>
  | Readonly<{ family: "registerKey" }>
  | Readonly<{ family: "withdrawalExemption" }>
  | Readonly<{ family: "deposit"; capacity: number }>
  | Readonly<{ family: "merge"; width: number }>;

export type PolicyKeyCircuit = Extract<
  RingKeyCircuit,
  { family: "memberPolicy" | "delegatePolicy" }
>;

/** Record pool widths, each subject pool as wide. */
export interface PolicyPoolCapacity {
  readonly own: number;
  /** Zero on the own-only key. */
  readonly curator: number;
}

/** Go `PolicyInputs.recordCapacity` over deduplicated subjects. */
export function policyPoolCapacity(circuit: PolicyKeyCircuit): PolicyPoolCapacity {
  const member = circuit.family === "memberPolicy";
  const withdrawals = member ? circuit.withdrawals : 0;
  // Withdrawal assets settle through the public slots.
  const withdrawalAssets = Math.min(withdrawals, N_PUBLIC_SLOTS);
  const distinct = 1 + 2 * circuit.outputs + withdrawals;
  return Object.freeze({
    own: distinct + Math.max(withdrawalAssets, member ? N_PUBLIC_SLOTS : 0),
    curator: circuit.ownOnly ? 0 : distinct + withdrawalAssets,
  });
}

/** Rust `RING_KEYS`, every ring key in its order, `name` the circuit type the prover serves. */
export const RING_KEYS: readonly Readonly<{
  circuit: RingKeyCircuit;
  name: string;
}>[] = Object.freeze(
  (
    [
      ...DELIVERED_AUDIT_CAPACITIES.map(
        (outputs) =>
          [
            { family: "deliveredAudit", outputs },
            `custom-ring-audit-delivered-${outputs}`,
          ] as const,
      ),
      ...ANONYMOUS_AUDIT_CLASSES.flatMap(({ outputs, classes }) =>
        classes.map(
          (inputClass) =>
            [
              { family: "anonymousAudit", inputClass, outputs },
              `custom-ring-audit-anonymous-v2-${inputClass}-${outputs}`,
            ] as const,
        ),
      ),
      ...ANONYMOUS_ENTRY_OUTPUTS.map(
        (outputs) =>
          [
            { family: "anonymousEntryAudit", inputClass: ANONYMOUS_ENTRY_CLASS, outputs },
            `custom-ring-audit-anonymous-entry-v2-${ANONYMOUS_ENTRY_CLASS}-${outputs}`,
          ] as const,
      ),
      ...[2, 4, 8, 16].flatMap((outputs) =>
        [0, 1, 2, 4, 8, 16, 32].flatMap((withdrawals) =>
          [false, true].map(
            (ownOnly) =>
              [
                { family: "memberPolicy", outputs, withdrawals, ownOnly },
                `custom-ring-policy-member-v3-${outputs}-w${withdrawals}-${ownOnly ? "own" : "curator"}`,
              ] as const,
          ),
        ),
      ),
      ...RING_AUTHORITY_SHAPES.flatMap(({ inputs, outputs }) =>
        [false, true].map(
          (ownOnly) =>
            [
              { family: "delegatePolicy", inputs, outputs, ownOnly },
              `custom-ring-policy-delegate-v3-${inputs}x${outputs}-${ownOnly ? "own" : "curator"}`,
            ] as const,
        ),
      ),
      ...[1, 2, 4, 8, APPLY_BATCH].map(
        (writes) =>
          [{ family: "applyRecords", writes }, `custom-ring-apply-records-${writes}`] as const,
      ),
      [{ family: "registerKey" }, "custom-ring-register-key"],
      [{ family: "withdrawalExemption" }, "custom-ring-withdrawal-exemption"],
      ...[1, 2, 4, 8].map(
        (capacity) => [{ family: "deposit", capacity }, `custom-ring-deposit-${capacity}`] as const,
      ),
      ...MERGE_WIDTHS.map(
        (width) => [{ family: "merge", width }, `custom-ring-merge-v3-${width}`] as const,
      ),
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

/** The ring key a proof must come from, the file name Go `RingKeyFile` derives from the circuit type. */
export function ringProvingKey(circuit: RingKeyCircuit): ExpectedProvingKey {
  return pinnedProvingKey(`${ringCircuitType(circuit).replaceAll("-", "_")}.key`, circuit.family);
}

/** A key without a pin has no committed verifying key, the program refuses its proofs. */
function pinnedProvingKey(name: string, circuit: string): ExpectedProvingKey {
  const sha256 = Object.hasOwn(RING_PROVING_KEY_SHA256S, name)
    ? RING_PROVING_KEY_SHA256S[name]
    : undefined;
  if (sha256 === undefined) throw new InterfaceError("INTERFACE_INVALID_SHAPE", { circuit });
  return Object.freeze({ name, sha256 });
}

function sameRingCircuit(left: RingKeyCircuit, right: RingKeyCircuit): boolean {
  switch (left.family) {
    case "deliveredAudit":
      return right.family === left.family && right.outputs === left.outputs;
    case "memberPolicy":
      return (
        right.family === left.family &&
        right.outputs === left.outputs &&
        right.withdrawals === left.withdrawals &&
        right.ownOnly === left.ownOnly
      );
    case "anonymousAudit":
    case "anonymousEntryAudit":
      return (
        right.family === left.family &&
        right.inputClass === left.inputClass &&
        right.outputs === left.outputs
      );
    case "delegatePolicy":
      return (
        right.family === left.family &&
        right.ownOnly === left.ownOnly &&
        right.inputs === left.inputs &&
        right.outputs === left.outputs
      );
    case "applyRecords":
      return right.family === left.family && right.writes === left.writes;
    case "merge":
      return right.family === left.family && right.width === left.width;
    case "withdrawalExemption":
    case "registerKey":
      return right.family === left.family;
    case "deposit":
      return right.family === left.family && right.capacity === left.capacity;
  }
}
