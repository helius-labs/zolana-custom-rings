import { describe, expect, it } from "vitest";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { ZERO_32 } from "@heliuslabs/zolana/internal";
import vector from "../../../../../test-vectors/registry/mint-records.json" with { type: "json" };
import {
  EMPTY_MINT_POLICY,
  assetLimitsFields,
  mintPolicyField,
  mintPolicyWrite,
} from "../../../src/protocol/membership/mint-policy.js";
import {
  queueEntryHash,
  verifyRecordOpening,
} from "../../../src/protocol/membership/member-opening.js";
import { recordTree } from "../../helpers/member-registry.js";

const field = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex")) as Bytes32;
const records = vector.rows.map((row) => ({
  member: field(row.member),
  lists: 0n,
  mintPolicy: {
    threshold: BigInt(row.amount),
    cap: BigInt(row.amount),
    cosignAbove: BigInt(row.amount),
    withdrawalThreshold: BigInt(row.amount),
    limits: {
      senderCap: BigInt(row.amount) - 1n,
      senderWindowSlots: BigInt(row.amount) - 2n,
      volumeCap: BigInt(row.amount) - 3n,
      volumeWindowSlots: BigInt(row.amount) - 4n,
      depositCap: BigInt(row.amount) - 5n,
      depositWindowSlots: BigInt(row.amount) - 6n,
      withdrawalCap: BigInt(row.amount) - 7n,
      withdrawalWindowSlots: BigInt(row.amount) - 8n,
    },
  },
}));
describe("mint records shared with Rust and Go", () => {
  it("authenticates twelve settings including u64 maximums", () => {
    const tree = recordTree(records);
    expect(Buffer.from(tree.root).toString("hex")).toBe(vector.root);
    for (const [i, record] of records.entries()) {
      expect(Buffer.from(mintPolicyField(record.mintPolicy)).toString("hex")).toBe(
        vector.rows[i]!.field,
      );
      expect(
        assetLimitsFields(record.mintPolicy.limits).map((limit) =>
          Buffer.from(limit).toString("hex"),
        ),
      ).toEqual(vector.rows[i]!.limits);
      expect(Buffer.from(mintPolicyWrite(record.mintPolicy).subarray(1)).toString("hex")).toBe(
        vector.rows[i]!.wire,
      );
      expect(
        Buffer.from(
          queueEntryHash({ ...record, mask: 0n, value: 0n, escrowKey: ZERO_32 }),
        ).toString("hex"),
      ).toBe(vector.rows[i]!.entry_hash);
      expect(() =>
        verifyRecordOpening(tree.opening(record.member), tree.root, record.member),
      ).not.toThrow();
    }
    const opening = tree.opening(records[8]!.member);
    if (opening.kind !== "present") throw new Error("missing ninth mint");
    expect(() =>
      verifyRecordOpening(
        { ...opening, record: { ...opening.record, mintPolicy: EMPTY_MINT_POLICY } },
        tree.root,
        opening.record.member,
      ),
    ).toThrow();
  });
  it.each(["threshold", "cap", "cosignAbove", "withdrawalThreshold"] as const)(
    "rejects %s outside u64",
    (name) => {
      for (const amount of [-1n, 1n << 64n])
        expect(() => mintPolicyField({ ...EMPTY_MINT_POLICY, [name]: amount })).toThrow();
    },
  );
});
