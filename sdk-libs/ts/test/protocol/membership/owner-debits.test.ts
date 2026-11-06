import { describe, expect, it } from "vitest";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import vectors from "../../../../../test-vectors/rpc/owner_debits.json" with { type: "json" };
import type { Bytes32 } from "@heliuslabs/spr/interface";

import { ownerDebits } from "../../../src/protocol/membership/owner-debits.js";

const field = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;
const ALICE = field(1);
const BOB = field(2);
const ASSET = field(9);

describe("ownerDebits", () => {
  const hash = (value: string): Bytes32 => hexToBytes(value) as Bytes32;
  type Row = Readonly<{ owner: string; asset: string; amount: number; ring?: boolean }>;
  const cases = vectors.cases as unknown as readonly Readonly<{
    name: string;
    inputs: readonly Row[];
    outputs: readonly Row[];
    ownerSigners?: readonly string[];
    flows: readonly Readonly<{ owner: string; debit: number }>[];
  }>[];
  const byOwner = (
    rows: readonly Readonly<{ owner: string; debit: bigint }>[],
  ): readonly Readonly<{ owner: string; debit: bigint }>[] =>
    [...rows].sort((left, right) => left.owner.localeCompare(right.owner));
  it.each(cases.map((vector) => [vector.name, vector] as const))(
    "matches the service's flows on %s",
    (_, vector) => {
      const unique = (values: readonly string[]) => [...new Set(values)].map(hash);
      const debits = ownerDebits({
        senders: unique([...(vector.ownerSigners ?? []), ...vector.inputs.map((row) => row.owner)]),
        assets: unique([...vector.inputs, ...vector.outputs].map((row) => row.asset)),
        inputs: vector.inputs.map((input) => ({
          owner: hash(input.owner),
          asset: hash(input.asset),
          amount: BigInt(input.amount),
        })),
        outputs: vector.outputs.map((output) => ({
          owner: hash(output.owner),
          asset: hash(output.asset),
          amount: BigInt(output.amount),
          ring: output.ring === true,
        })),
        publicGross: [],
      });
      expect(
        byOwner(debits.map(({ owner, debit }) => ({ owner: bytesToHex(owner), debit }))),
      ).toEqual(
        byOwner(
          vector.flows
            .filter((row) => row.debit !== 0)
            .map((row) => ({ owner: row.owner, debit: BigInt(row.debit) })),
        ),
      );
    },
  );

  it("keeps credits apart between owners", () => {
    const debits = ownerDebits({
      senders: [ALICE, BOB],
      assets: [ASSET],
      inputs: [
        { owner: ALICE, asset: ASSET, amount: 100n },
        { owner: BOB, asset: ASSET, amount: 40n },
      ],
      outputs: [{ owner: BOB, asset: ASSET, amount: 90n, ring: true }],
      publicGross: [],
    });
    expect(debits).toMatchObject([{ owner: ALICE, asset: ASSET, debit: 100n }]);
  });

  it("counts an exit to the same owner as leaving", () => {
    const debits = ownerDebits({
      senders: [ALICE],
      assets: [ASSET],
      inputs: [{ owner: ALICE, asset: ASSET, amount: 100n }],
      outputs: [{ owner: ALICE, asset: ASSET, amount: 100n, ring: false }],
      publicGross: [],
    });
    expect(debits).toMatchObject([{ owner: ALICE, asset: ASSET, debit: 100n }]);
  });

  it("clamps to zero when a deposit funds what returns", () => {
    const debits = ownerDebits({
      senders: [ALICE],
      assets: [ASSET],
      inputs: [{ owner: ALICE, asset: ASSET, amount: 10n }],
      outputs: [{ owner: ALICE, asset: ASSET, amount: 50n, ring: true }],
      publicGross: [],
    });
    expect(debits).toEqual([]);
  });

  it("charges a returned spend beside a public withdrawal, the intended composition cost", () => {
    // A spends 100 and receives 100 back, B's public deposit of 100 funds a public withdrawal of 100.
    const debits = ownerDebits({
      senders: [ALICE],
      assets: [ASSET],
      inputs: [{ owner: ALICE, asset: ASSET, amount: 100n }],
      outputs: [{ owner: ALICE, asset: ASSET, amount: 100n, ring: true }],
      publicGross: [{ asset: ASSET, gross: 100n }],
    });
    expect(debits).toEqual([
      { owner: ALICE, asset: ASSET, debit: 0n, kept: 100n, charge: 100n, chargedOutflow: 100n },
    ]);
  });

  it("names a repeated subject once", () => {
    const debits = ownerDebits({
      senders: [ALICE, ALICE],
      assets: [ASSET, ASSET],
      inputs: [{ owner: ALICE, asset: ASSET, amount: 7n }],
      outputs: [],
      publicGross: [],
    });
    expect(debits).toMatchObject([{ owner: ALICE, asset: ASSET, debit: 7n }]);
  });
});
