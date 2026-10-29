import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";
import type { Bytes32 } from "@heliuslabs/zolana";
import { ZolanaApi, indexerScalars } from "@heliuslabs/zolana/internal";

import { QUAD_HEIGHT } from "../../src/protocol/membership/member-registry.js";
import { RingIndexer } from "../../src/rpc/indexer.js";

const { hash } = indexerScalars;
// base58 of 32 zero bytes.
const TAG = hash("11111111111111111111111111111111");
const REGISTRY = address("8hcir6LNDXjqKSof1KV41SBZxGaEQFB3WTtcoYn3Atpg");

describe("ring member registry wire", () => {
  const MEMBER = hash(new Uint8Array(32).fill(5) as Bytes32);
  const OTHER = hash(new Uint8Array(32).fill(6) as Bytes32);
  const CONTEXT = { slot: 1, blockTime: 2 };
  const level = () => [TAG, TAG, TAG];
  const quadPath = (index: number, levels = QUAD_HEIGHT) => ({
    index,
    siblings: Array.from({ length: levels }, level),
  });
  const record = {
    mintPolicy: {
      threshold: 0,
      cap: 0,
      cosignAbove: 0,
      withdrawalThreshold: 0,
      limits: {
        senderCap: 0,
        senderWindowSlots: 0,
        volumeCap: 0,
        volumeWindowSlots: 0,
        depositCap: 0,
        depositWindowSlots: 0,
        withdrawalCap: 0,
        withdrawalWindowSlots: 0,
      },
    },
    member: MEMBER,
    next: TAG,
    lists: 3,
    escrowKey: TAG,
    ownerPubkey: null,
    nullifierPk: null,
    ephPk: null,
    ciphertext: null,
  };
  const root = { root: TAG, revision: 1, nextIndex: 2 };
  const opening = { present: true, record, path: quadPath(1) };
  const openings = { context: CONTEXT, root, openings: [opening] };
  const indexerFor = (body: Readonly<Record<string, unknown>>) =>
    new RingIndexer(
      new ZolanaApi({
        url: "https://indexer.example",
        fetch: async () => Response.json({ jsonrpc: "2.0", id: "test-account", ...body }),
      }),
    );
  const zero = new Uint8Array(32) as Bytes32;

  it("refuses an opening under another root or with part of a sealed key", async () => {
    const request = {
      registry: REGISTRY,
      members: [new Uint8Array(32).fill(5) as Bytes32],
      expectedRoot: zero,
    };
    const decoded = await indexerFor({ result: openings }).getStorageMemberOpenings(request);
    expect(decoded.openings[0]).toMatchObject({ kind: "present", path: { index: 1 } });
    expect(decoded.openings[0]?.path.siblings).toHaveLength(QUAD_HEIGHT);
    for (const changed of [
      { root: { ...root, root: OTHER } },
      { openings: [{ ...opening, record: { ...record, ownerPubkey: REGISTRY } }] },
    ])
      await expect(
        indexerFor({ result: { ...openings, ...changed } }).getStorageMemberOpenings(request),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_RPC_RESPONSE" });
  });

  it("distinguishes every typed registry RPC failure", async () => {
    const request = { registry: REGISTRY, members: [zero], expectedRoot: zero };
    for (const [rpcCode, code] of [
      [-32070, "RING_REGISTRY_OUT_OF_SYNC"],
      [-32071, "RING_REGISTRY_ROOT_CHANGED"],
      [-32075, "RING_REGISTRY_PAGE_GAP"],
    ] as const) {
      const indexer = indexerFor({ error: { code: rpcCode, message: "private diagnostics" } });
      await expect(indexer.getStorageMemberOpenings(request)).rejects.toMatchObject({ code });
    }
    for (const retired of [-32072, -32073, -32076]) {
      const indexer = indexerFor({ error: { code: retired, message: "private diagnostics" } });
      await expect(indexer.getStorageMemberOpenings(request)).rejects.toMatchObject({
        code: "CLIENT_INDEXER",
      });
    }
  });

  it("decodes contiguous member pages", async () => {
    const request = { registry: REGISTRY, expectedRoot: zero, startIndex: 1, limit: 100 };
    const page = {
      context: CONTEXT,
      root: { ...root, nextIndex: 3 },
      records: [
        { record, path: quadPath(1) },
        { record: { ...record, member: OTHER }, path: quadPath(2) },
      ],
      nextLeafIndex: null,
    };
    const decoded = await indexerFor({ result: page }).getStorageMemberRecords(request);
    expect(decoded.records.map((entry) => entry.path.index)).toEqual([1, 2]);
    expect(decoded.nextLeafIndex).toBeUndefined();
  });
});
