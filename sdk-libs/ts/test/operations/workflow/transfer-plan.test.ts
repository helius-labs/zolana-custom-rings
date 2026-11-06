import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import type { TransferKeyCircuit } from "../../../src/protocol/proof/transfer-shapes.js";
import { ringStreamLayout, type RingRail } from "../../../src/protocol/transaction/transact.js";
import {
  NO_RECORD_POOLS,
  planTransfer,
  planTransferAt,
  type PlanFrame,
} from "../../../src/operations/workflow/transfer-plan.js";

interface RustCircuit {
  readonly outputs: number;
  readonly inputs: number;
  readonly withdrawals: number;
  readonly owners: number;
  readonly entry: boolean;
  readonly wide: boolean;
}

/** One case of Rust `a_read_keeps_a_seal_of_one_stream_and_refuses_another`, its keys alone. */
interface RekeyCase {
  readonly name: string;
  readonly rail: RingRail;
  readonly inputs: number;
  readonly outputs: number;
  readonly spendsDefaultRing: boolean;
  readonly hasData: boolean;
  readonly readPools: Readonly<{ own: number; curator: number; tracking: number }>;
  readonly sealed: RustCircuit;
  readonly read: RustCircuit;
}

const CASES = JSON.parse(
  readFileSync(
    new URL("../../../../sdk/tests/fixtures/transfer-plan-rekey.json", import.meta.url),
    "utf8",
  ),
) as readonly RekeyCase[];

function frameOf(rekey: RekeyCase): PlanFrame {
  return {
    subjects: {
      rail: rekey.rail,
      inputs: rekey.inputs,
      outputs: rekey.outputs,
      spendsDefaultRing: rekey.spendsDefaultRing,
      legs: 0,
      owners: 1,
      pools: NO_RECORD_POOLS,
      wide: false,
    },
    layoutUnder: (wideOwners) =>
      ringStreamLayout({
        rail: rekey.rail,
        nIn: rekey.inputs,
        nOut: rekey.outputs,
        inputs: rekey.inputs,
        outputs: rekey.outputs,
        entry: rekey.spendsDefaultRing,
        wideOwners,
      }),
  };
}

function rustCircuit(circuit: TransferKeyCircuit): RustCircuit {
  const { outputs, withdrawals, owners, entry, wide } = circuit;
  return { outputs, inputs: circuit.class, withdrawals, owners, entry, wide };
}

describe("a planned transfer", () => {
  for (const rekey of CASES)
    it(`takes the Rust keys of ${rekey.name}`, () => {
      const frame = frameOf(rekey);
      expect(rustCircuit(planTransfer(frame, NO_RECORD_POOLS).circuit)).toEqual(rekey.sealed);
      const read = planTransfer(frame, rekey.readPools);
      expect(rustCircuit(read.circuit)).toEqual(rekey.read);
      // Every fixture read takes the wide row, so a wide reseal takes the read's key.
      expect(planTransferAt(frame, "wide").circuit).toEqual(read.circuit);
    });
});
