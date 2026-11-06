import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { RING_KEYS, type RingKeyCircuit } from "../../src/protocol/proof/proving-keys.js";

import {
  fittedSpend,
  ringTransferCircuit,
  TRANSFER_SHAPES,
  transferPoolCapacity,
  transferKeys,
  type TransferShape,
  type TransferSpend,
} from "../../src/protocol/proof/transfer-shapes.js";

const NO_POOLS = { own: 0, curator: 0, tracking: 0 };

function loaded(entry: TransferShape, pools = NO_POOLS): TransferSpend {
  return {
    rail: "confidential",
    inputs: entry.inputs,
    outputs: entry.outputs,
    spendsDefaultRing: entry.entry,
    legs: entry.withdrawals,
    owners: entry.owners,
    pools,
    wide: false,
  };
}

function row(outputs: number, inputs: number, entry: boolean): TransferShape {
  const rows = TRANSFER_SHAPES.filter(
    (shape) => shape.outputs === outputs && shape.inputs === inputs && shape.entry === entry,
  );
  const [first] = rows;
  if (first === undefined) throw new Error(`no ${inputs}x${outputs} row`);
  return first;
}

describe("the entry keys", () => {
  it("serves five inputs at an eight output entry and eight on the wide entry key", () => {
    const five = ringTransferCircuit(fittedSpend(loaded(row(8, 5, true))));
    expect(five).toMatchObject({
      outputs: 8,
      class: 5,
      withdrawals: 4,
      owners: 4,
      entry: true,
    });
    expect(transferPoolCapacity(five!)).toEqual({ own: 46, curator: 46, tracking: 15 });
    const wide = ringTransferCircuit(fittedSpend(loaded(row(8, 8, true))));
    expect(wide).toMatchObject({
      outputs: 8,
      class: 8,
      withdrawals: 32,
      owners: 8,
      entry: true,
      wide: true,
    });
    expect(transferPoolCapacity(wide!)).toEqual({ own: 91, curator: 91, tracking: 38 });
    // No single-asset payout key, a general key covers the payout.
    expect(transferKeys()).toHaveLength(9);
  });

  it("refuses an entry past the wide entry key", () => {
    const past = { ...loaded(row(8, 8, true)), inputs: 9 };
    expect(ringTransferCircuit(fittedSpend(past))).toBeUndefined();
  });
});

/** Rust `RING_KEYS` as TS circuits, a transfer's `inputs` is the TS `class`. */
function rustRingKeys(): readonly Readonly<{ circuit: RingKeyCircuit; name: string }>[] {
  const source = readFileSync(
    new URL("../../../../program-libs/interface/src/proof/ring_keys.rs", import.meta.url),
    "utf8",
  );
  return [
    ...source.matchAll(/circuit: RingCircuit::(\w+)(?: \{([^}]*)\})?,\s*name: "([a-z0-9-]+)"/gu),
  ].map(([, variant = "", body = "", name = ""]) => {
    const fields = [...body.matchAll(/(\w+): ([\w:]+)/gu)].map(([, field = "", value = ""]) => {
      if (field === "mode") return ["private", value.endsWith("::Private")];
      return [
        field === "inputs" ? "class" : field,
        value === "true" || value === "false" ? value === "true" : Number(value),
      ];
    });
    const family = `${variant.slice(0, 1).toLowerCase()}${variant.slice(1)}`;
    return { circuit: { family, ...Object.fromEntries(fields) } as RingKeyCircuit, name };
  });
}

describe("the ring key catalog", () => {
  it("lists every key of ring_keys.rs in its order and no other", () => {
    const rust = rustRingKeys();
    expect(rust.map((key) => key.circuit.family)).toContain("applyEnrollments");
    expect(RING_KEYS).toEqual(rust);
  });
});
