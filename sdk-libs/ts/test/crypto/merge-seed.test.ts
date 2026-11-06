import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";
import type { Bytes32 } from "@heliuslabs/spr";

import {
  seededMergeDummyNullifier,
  seededMergeOutputBlinding,
  seededMergeOutputKey,
  seededMergePrivateTxBlinding,
} from "../../src/crypto/derivation/merge-seed.js";

const vector = JSON.parse(
  readFileSync(new URL("../../../../zolana/test-vectors/merge_ring.json", import.meta.url), "utf8"),
) as Readonly<{
  merge_seed: string;
  first_nullifier: string;
  output_blinding: string;
  output_key: string;
  private_tx_blinding: string;
  dummy_nullifier: string;
  dummy_slot_index: number;
}>;

function bytes(value: string): Bytes32 {
  return Uint8Array.from(Buffer.from(value, "hex")) as Bytes32;
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

describe("seeded merge derivations", () => {
  it("match the Rust and Go derivations on the shared vector", () => {
    const seed = bytes(vector.merge_seed);
    const first = bytes(vector.first_nullifier);
    expect(hex(seededMergeOutputBlinding(seed, first))).toBe(vector.output_blinding);
    expect(hex(seededMergeOutputKey(seed, first))).toBe(vector.output_key);
    expect(hex(seededMergePrivateTxBlinding(seed, first))).toBe(vector.private_tx_blinding);
    expect(hex(seededMergeDummyNullifier(seed, first, vector.dummy_slot_index))).toBe(
      vector.dummy_nullifier,
    );
  });

  it("refuses a dummy slot past a u8", () => {
    expect(() =>
      seededMergeDummyNullifier(bytes(vector.merge_seed), bytes(vector.first_nullifier), 256),
    ).toThrow(RangeError);
  });
});
