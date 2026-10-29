import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";
import type { Bytes32 } from "@heliuslabs/zolana";
import { ZolanaApi, indexerScalars } from "@heliuslabs/zolana/internal";

import {
  decodeRingMemberOpening,
  decodeRingMemberPage,
  decodeRingRecordQueue,
  decodeRingRegistryState,
  encodeRingMemberProofRequest,
  encodeRingMemberRecordsRequest,
} from "../../src/protocol/indexer/indexer-codec.js";
import {
  MEMBER_REGISTRY_CAPACITY,
  QUAD_HEIGHT,
} from "../../src/protocol/membership/member-registry.js";
import { RingIndexer } from "../../src/rpc/indexer.js";

const { hash } = indexerScalars;
// base58 of 32 zero bytes.
const TAG = hash("11111111111111111111111111111111");
const RING = address("8hcir6LNDXjqKSof1KV41SBZxGaEQFB3WTtcoYn3Atpg");

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
        withdrawalCap: 0,
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
  const root = { root: TAG, rootIndex: 0, applied: 0, nextIndex: 2 };
  const opening = {
    context: CONTEXT,
    root,
    opening: { present: true, record, path: quadPath(1) },
  };
  const indexerFor = (body: Readonly<Record<string, unknown>>) =>
    new RingIndexer(
      new ZolanaApi({
        url: "https://indexer.example",
        fetch: async () => Response.json({ jsonrpc: "2.0", id: "test-account", ...body }),
      }),
    );
  const zero = new Uint8Array(32) as Bytes32;
  const refusedAt = (path: string) =>
    expect.objectContaining({ details: expect.objectContaining({ path }) });

  it("bounds the expected next index at the registry capacity", () => {
    const request = { ringProgramId: RING, member: TAG, expectedRoot: TAG };
    expect(
      encodeRingMemberProofRequest({ ...request, expectedNextIndex: MEMBER_REGISTRY_CAPACITY }),
    ).toMatchObject({ expectedNextIndex: Number(MEMBER_REGISTRY_CAPACITY) });
    expect(() =>
      encodeRingMemberProofRequest({
        ...request,
        expectedNextIndex: MEMBER_REGISTRY_CAPACITY + 1n,
      }),
    ).toThrow();
  });

  it("decodes a 4-ary opening and refuses a path or root of another registry", () => {
    expect(decodeRingMemberOpening(opening)).toMatchObject({
      root: { rootIndex: 0, nextIndex: 2n },
      opening: { present: true, path: { index: 1n } },
    });
    for (const [changed, path] of [
      [{ path: quadPath(1, QUAD_HEIGHT - 1) }, "opening.path.siblings"],
      [
        { path: { index: 1, siblings: [[TAG, TAG], ...quadPath(1, QUAD_HEIGHT - 1).siblings] } },
        "opening.path.siblings[0]",
      ],
      [{ path: quadPath(Number(MEMBER_REGISTRY_CAPACITY)) }, "opening.path.index"],
      [{ record: { ...record, ephPk: Buffer.alloc(33, 4).toString("base64") } }, "opening.record"],
    ] as const)
      expect(() =>
        decodeRingMemberOpening({ ...opening, opening: { ...opening.opening, ...changed } }),
      ).toThrow(refusedAt(path));
    for (const [changed, path] of [
      [{ rootIndex: 32 }, "root.rootIndex"],
      [{ nextIndex: 0 }, "root.nextIndex"],
      [{ nextIndex: Number(MEMBER_REGISTRY_CAPACITY) + 1 }, "root.nextIndex"],
    ] as const)
      expect(() => decodeRingMemberOpening({ ...opening, root: { ...root, ...changed } })).toThrow(
        refusedAt(path),
      );
  });

  it("decodes the registry state with its floor and refuses a history of another width", () => {
    const state = {
      context: CONTEXT,
      history: [{ root: TAG, applied: 0, slot: 5 }, ...Array.from({ length: 31 }, () => null)],
      historyCursor: 0,
      nextIndex: 1,
      floor: 0,
      priorFloor: 0,
      floorSlot: 0,
      appendPath: quadPath(1),
    };
    expect(decodeRingRegistryState(state)).toMatchObject({
      historyCursor: 0,
      nextIndex: 1n,
      appendPath: { index: 1n },
    });
    for (const [changed, path] of [
      [{ history: state.history.slice(1) }, "history"],
      [{ historyCursor: 32 }, "historyCursor"],
      [{ nextIndex: 0 }, "nextIndex"],
      [{ appendPath: quadPath(1, 0) }, "appendPath.siblings"],
    ] as const)
      expect(() => decodeRingRegistryState({ ...state, ...changed })).toThrow(refusedAt(path));
  });

  it("decodes the record queue only as the run of positions from head to tail", () => {
    const entry = (position: number) => ({
      position,
      member: MEMBER,
      mask: 4,
      value: 4,
      escrowKey: TAG,
      slot: 9,
    });
    const queue = {
      context: CONTEXT,
      head: 3,
      tail: 5,
      chainHead: TAG,
      entries: [entry(3), entry(4)],
    };
    expect(decodeRingRecordQueue(queue).entries).toHaveLength(2);
    for (const changed of [
      { entries: [entry(3)] },
      { entries: [entry(4), entry(3)] },
      { tail: 2 },
      { head: 0, tail: 17, entries: Array.from({ length: 17 }, (_, index) => entry(index)) },
    ])
      expect(() => decodeRingRecordQueue({ ...queue, ...changed })).toThrow(refusedAt("entries"));
  });

  it("refuses an opening under another root, of another member or with part of a sealed key", async () => {
    const request = {
      ringProgramId: RING,
      member: new Uint8Array(32).fill(5) as Bytes32,
      expectedRoot: zero,
      expectedNextIndex: 2,
    };
    const decoded = await indexerFor({ result: opening }).getRingMemberRecord(request);
    expect(decoded.opening).toMatchObject({ kind: "present", path: { index: 1 } });
    expect(decoded.opening.path.siblings).toHaveLength(QUAD_HEIGHT);
    for (const changed of [
      { root: { ...root, root: OTHER } },
      { root: { ...root, nextIndex: 3 } },
      { opening: { ...opening.opening, record: { ...record, member: OTHER } } },
      { opening: { ...opening.opening, record: { ...record, ownerPubkey: RING } } },
    ])
      await expect(
        indexerFor({ result: { ...opening, ...changed } }).getRingMemberRecord(request),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_RPC_RESPONSE" });
  });

  it("distinguishes every typed registry RPC failure", async () => {
    const request = {
      ringProgramId: RING,
      member: zero,
      expectedRoot: zero,
      expectedNextIndex: 2,
    };
    for (const [rpcCode, code] of [
      [-32070, "RING_REGISTRY_OUT_OF_SYNC"],
      [-32071, "RING_REGISTRY_ROOT_CHANGED"],
      [-32075, "RING_REGISTRY_PAGE_GAP"],
      [-32076, "RING_RECORD_QUEUE_CHANGED"],
    ] as const) {
      const indexer = indexerFor({ error: { code: rpcCode, message: "private diagnostics" } });
      await expect(indexer.getRingMemberRecord(request)).rejects.toMatchObject({ code });
      await expect(
        indexer.getRingApplyProofInputs({ ringProgramId: RING, authorityWrites: [] }),
      ).rejects.toMatchObject({ code });
    }
    for (const retired of [-32072, -32073]) {
      const indexer = indexerFor({ error: { code: retired, message: "private diagnostics" } });
      await expect(indexer.getRingMemberRecord(request)).rejects.toMatchObject({
        code: "CLIENT_INDEXER",
      });
    }
  });

  it("decodes contiguous member pages and rejects gaps", async () => {
    const request = {
      ringProgramId: RING,
      expectedRoot: zero,
      expectedNextIndex: 3,
      startIndex: 1,
      limit: 100,
    };
    expect(
      encodeRingMemberRecordsRequest({
        ...request,
        expectedRoot: TAG,
        expectedNextIndex: 3n,
        startIndex: 1n,
      }),
    ).toMatchObject({ startIndex: 1, limit: 100 });
    const page = {
      context: CONTEXT,
      root: { ...root, nextIndex: 3 },
      records: [
        { record, path: quadPath(1) },
        { record: { ...record, member: OTHER }, path: quadPath(2) },
      ],
      nextLeafIndex: null,
    };
    expect(decodeRingMemberPage(page).records).toHaveLength(2);
    const decoded = await indexerFor({ result: page }).getRingMemberRecords(request);
    expect(decoded.records.map((entry) => entry.path.index)).toEqual([1, 2]);
    expect(decoded.nextLeafIndex).toBeUndefined();
    for (const changed of [
      { records: page.records.slice(0, 1) },
      { records: [page.records[0], { ...page.records[1], path: quadPath(3) }] },
      { nextLeafIndex: 2 },
    ])
      await expect(
        indexerFor({ result: { ...page, ...changed } }).getRingMemberRecords(request),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_RPC_RESPONSE" });
  });
});
