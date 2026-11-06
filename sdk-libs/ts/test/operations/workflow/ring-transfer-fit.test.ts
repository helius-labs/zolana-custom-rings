import { TRANSACTION_SIZE_LIMIT, transactionSize } from "@heliuslabs/spr/interface";
import { compileUnsignedTransaction } from "@heliuslabs/spr/internal";
import { address, blockhash, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { checkTransferFits } from "../../../src/operations/workflow/compile.js";

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const PROGRAM: Address = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const SHAPE = { inputs: 24, outputs: 2 };

function transaction(length: number) {
  return {
    feePayer: PAYER,
    instructions: [{ programAddress: PROGRAM, data: new Uint8Array(length) }],
    computeUnitLimit: 1_400_000,
  };
}

describe("checkTransferFits", () => {
  it("takes a transaction at the limit and refuses one byte past it, no margin reserved", () => {
    const size = (length: number): number =>
      transactionSize(
        compileUnsignedTransaction({
          ...transaction(length),
          lifetime: {
            blockhash: blockhash("11111111111111111111111111111111"),
            lastValidBlockHeight: 0n,
          },
        }),
      );
    const filling = TRANSACTION_SIZE_LIMIT - size(1_000) + 1_000;
    expect(size(filling)).toBe(TRANSACTION_SIZE_LIMIT);
    expect(() => checkTransferFits(SHAPE, transaction(filling))).not.toThrow();
    expect(() => checkTransferFits(SHAPE, transaction(filling + 1))).toThrow(
      expect.objectContaining({
        code: "RING_TRANSFER_TOO_WIDE",
        details: { ...SHAPE, size: TRANSACTION_SIZE_LIMIT + 1, limit: TRANSACTION_SIZE_LIMIT },
      }),
    );
  });

  it("counts a priority fee against the limit", () => {
    const size = (length: number, priorityFeeLamports?: bigint): number =>
      transactionSize(
        compileUnsignedTransaction({
          ...transaction(length),
          ...(priorityFeeLamports === undefined ? {} : { priorityFeeLamports }),
          lifetime: {
            blockhash: blockhash("11111111111111111111111111111111"),
            lastValidBlockHeight: 0n,
          },
        }),
      );
    const withFee = size(1_000, 5n);
    const filling = TRANSACTION_SIZE_LIMIT - size(1_000) + 1_000;
    expect(withFee).toBeGreaterThan(size(1_000));
    expect(() => checkTransferFits(SHAPE, transaction(filling))).not.toThrow();
    expect(() =>
      checkTransferFits(SHAPE, { ...transaction(filling), priorityFeeLamports: 5n }),
    ).toThrow(expect.objectContaining({ code: "RING_TRANSFER_TOO_WIDE" }));
  });
});
