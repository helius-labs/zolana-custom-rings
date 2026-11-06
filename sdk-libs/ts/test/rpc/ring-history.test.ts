import type { Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { transactionsPage } from "../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { RowOrigins } from "../../src/operations/audit/row-origins.js";
import { readRingHistory, scanLimits } from "../../src/rpc/history.js";

const RING = "11111111111111111111111111111111" as Address;

function read(pages: readonly ReturnType<typeof transactionsPage>[], maxPages = 8) {
  const reader = vi.fn(
    async (request: { paginationToken?: string }) =>
      pages[request.paginationToken === undefined ? 0 : 1]!,
  );
  const origin = { origin: vi.fn() } as unknown as ConstructorParameters<typeof RowOrigins>[0];
  return {
    reader,
    reach: readRingHistory(
      {
        client: { getShieldedTransactionsByTags: reader },
        ringProgramId: RING,
        rows: new RowOrigins(origin, RING, undefined),
        afterSlot: 4n,
        limits: scanLimits({ maxPages }),
      },
      () => undefined,
      undefined,
    ),
  };
}

describe("readRingHistory", () => {
  it("reads above its floor and sets the checkpoint from the final page only", async () => {
    const low = { slot: 8n, blockTime: 0n };
    const high = { slot: 9n, blockTime: 0n };
    const { reader, reach } = read([
      transactionsPage({ context: high, paginationToken: "t1" }),
      transactionsPage({ context: low }),
    ]);
    await expect(reach).resolves.toEqual({ checkpoint: 8n });
    expect(reader.mock.calls.map(([request]) => request)).toEqual([
      expect.objectContaining({ limit: 1000, filters: { slot: { gt: 4n } } }),
      expect.objectContaining({
        paginationToken: "t1",
        filters: { slot: { gt: 4n } },
      }),
    ]);
  });

  it("has no checkpoint when the page cap stopped it", async () => {
    const { reach } = read([transactionsPage({ paginationToken: "t1" })], 1);
    await expect(reach).resolves.toEqual({ nextCursor: `${RING}:ring:t1` });
  });
});
