/** The packed element a signer checks its data-bearing outputs against. */
import { describe, expect, it } from "vitest";

import type { Bytes32 } from "@heliuslabs/spr/interface";

import { TRANSFER_SHAPES } from "../../../src/protocol/proof/transfer-shapes.js";
import {
  SIGNER_DATA_ENTRIES,
  SIGNER_DATA_ENTRY_BITS,
  signerDataCountAt,
  signerDataCountsOf,
  validSignerDataCounts,
} from "../../../src/protocol/membership/signer-data-counts.js";

const key = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;
const NONE = new Uint8Array(32) as Bytes32;
const DATA = key(7);
const slot = (owner: number, dataHash: Bytes32 = DATA) => ({
  ownerIdentity: key(owner),
  dataHash,
});

describe("signer data counts", () => {
  it("counts each run entry's own data-bearing slots", () => {
    const packed = signerDataCountsOf(
      [key(1), key(2)],
      [slot(2), slot(1, NONE), slot(2), slot(1), slot(3)],
    );
    expect(packed).toBe(1n | (2n << BigInt(SIGNER_DATA_ENTRY_BITS)));
    expect(signerDataCountAt(packed ?? 0n, 0)).toBe(1);
    expect(signerDataCountAt(packed ?? 0n, 1)).toBe(2);
    expect(signerDataCountAt(packed ?? 0n, 2)).toBe(0);
    expect(signerDataCountAt(packed ?? 0n, SIGNER_DATA_ENTRIES)).toBe(0);
  });

  it("counts nothing on an empty run", () => {
    expect(signerDataCountsOf([], [slot(1)])).toBe(0n);
  });

  it("keeps a run past the entries while the member past them owns no data slot", () => {
    const run = Array.from({ length: SIGNER_DATA_ENTRIES + 1 }, (_, at) => key(at + 1));
    expect(signerDataCountsOf(run, [])).toBe(0n);
    expect(signerDataCountsOf(run, [slot(SIGNER_DATA_ENTRIES + 1)])).toBeUndefined();
  });

  it("refuses a count past its bits", () => {
    expect(
      signerDataCountsOf(
        [key(1)],
        Array.from({ length: 32 }, () => slot(1)),
      ),
    ).toBeUndefined();
  });

  it("reads a present value as nonzero inside the entries", () => {
    expect(validSignerDataCounts((1n << 60n) - 1n)).toBe(true);
    expect(validSignerDataCounts(1n << 60n)).toBe(false);
    expect(validSignerDataCounts(0n)).toBe(false);
  });

  it("fits every key's outputs in one entry", () => {
    for (const shape of TRANSFER_SHAPES)
      expect(shape.outputs).toBeLessThan(1 << SIGNER_DATA_ENTRY_BITS);
  });
});
