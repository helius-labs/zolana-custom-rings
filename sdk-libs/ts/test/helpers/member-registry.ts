import { EMPTY_MINT_POLICY, type MintPolicy } from "../../src/protocol/membership/mint-policy.js";
import {
  type RingMemberOpening,
  type RingSealedKey,
  type RingServedRecord,
} from "../../src/rpc/ports.js";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { ZERO_32, bytesToBigInt, poseidon } from "@heliuslabs/zolana/internal";
import {
  QUAD_ARITY,
  QUAD_HEIGHT,
  canopyLevels,
  type MemberRecord,
  type QuadPath,
} from "../../src/protocol/membership/member-registry.js";
import { FIELD_MAX, memberRecordHash } from "../../src/protocol/membership/member-opening.js";

/** One record the fixture holds, its key escrow served beside it when `sealed` is set. */
export interface FixtureRecord {
  readonly member: Bytes32;
  readonly lists: bigint;
  readonly mintPolicy?: MintPolicy;
  readonly escrowKey?: Bytes32;
  readonly sealed?: RingSealedKey;
}

/** An independent sparse 4-ary record tree, leaf 0 the sentinel and the members in key order after it. */
export function recordTree(records: readonly FixtureRecord[] = []) {
  const sorted = [...records].sort((a, b) =>
    bytesToBigInt(a.member) < bytesToBigInt(b.member) ? -1 : 1,
  );
  const rows: MemberRecord[] = [
    {
      mintPolicy: EMPTY_MINT_POLICY,
      member: ZERO_32,
      lists: 0n,
      escrowKey: ZERO_32,
      next: sorted[0]?.member ?? FIELD_MAX,
    },
    ...sorted.map((record, index) => ({
      member: record.member,
      lists: record.lists,
      mintPolicy: record.mintPolicy ?? EMPTY_MINT_POLICY,
      escrowKey: record.escrowKey ?? ZERO_32,
      next: sorted[index + 1]?.member ?? FIELD_MAX,
    })),
  ];
  const zeros = [ZERO_32];
  for (let level = 0; level < QUAD_HEIGHT; level += 1) {
    const below = zeros[level] ?? ZERO_32;
    zeros.push(poseidon([below, below, below, below]));
  }
  const layers: Map<number, Bytes32>[] = [
    new Map(rows.map((row, index) => [index, memberRecordHash(row)])),
  ];
  for (let level = 0; level < QUAD_HEIGHT; level += 1) {
    const below = layers[level] ?? new Map<number, Bytes32>();
    const above = new Map<number, Bytes32>();
    for (const index of below.keys()) {
      const parent = index >> 2;
      if (above.has(parent)) continue;
      const children = Array.from(
        { length: QUAD_ARITY },
        (_, child) => below.get(parent * QUAD_ARITY + child) ?? zeros[level] ?? ZERO_32,
      );
      above.set(parent, poseidon(children));
    }
    layers.push(above);
  }
  const root = layers[QUAD_HEIGHT]?.get(0) ?? ZERO_32;
  const path = (index: number): QuadPath => ({
    index,
    siblings: Array.from({ length: QUAD_HEIGHT }, (_, level) => {
      const node = index >> (2 * level);
      const parent = node >> 2;
      return Array.from({ length: QUAD_ARITY }, (_, child) => parent * QUAD_ARITY + child)
        .filter((sibling) => sibling !== node)
        .map((sibling) => layers[level]?.get(sibling) ?? zeros[level] ?? ZERO_32);
    }),
  });
  const opening = (member: Bytes32): RingMemberOpening => {
    const index = rows.findIndex(
      (row, at) => at > 0 && bytesToBigInt(row.member) === bytesToBigInt(member),
    );
    const record = rows[index];
    if (index > 0 && record !== undefined) {
      const sealed = sorted[index - 1]?.sealed;
      return {
        kind: "present",
        record,
        path: path(index),
        ...(sealed === undefined ? {} : { sealedKey: sealed }),
      };
    }
    const value = bytesToBigInt(member);
    const lowIndex = rows.findIndex(
      (row) => bytesToBigInt(row.member) < value && value < bytesToBigInt(row.next),
    );
    const low = rows[lowIndex];
    if (low === undefined) throw new Error("member outside the fixture registry");
    return { kind: "absent", low, path: path(lowIndex) };
  };
  /** The `getStorageRecordPool` body, distinct leaves in first use order. */
  const pool = (members: readonly Bytes32[], openings: number) => {
    const levels = canopyLevels(openings);
    const height = QUAD_HEIGHT - levels;
    const records: RingServedRecord[] = [];
    const subjects = members.map((member) => {
      const { index, siblings } = opening(member).path;
      const at = records.findIndex((served) => served.path.index === index);
      if (at >= 0) return at;
      const record = rows[index];
      if (record === undefined) throw new Error("leaf outside the fixture registry");
      // The seal belongs to the leaf, whichever subject reaches it first.
      const sealed = index > 0 ? sorted[index - 1]?.sealed : undefined;
      records.push({
        record,
        path: { index, siblings: siblings.slice(0, height) },
        ...(sealed === undefined ? {} : { sealedKey: sealed }),
      });
      return records.length - 1;
    });
    const canopy = Array.from(
      { length: QUAD_ARITY ** levels },
      (_, node) => layers[height]?.get(node) ?? zeros[height] ?? ZERO_32,
    );
    return { records, canopy, subjects };
  };
  return { root, nextIndex: rows.length, rows, path, opening, pool };
}
