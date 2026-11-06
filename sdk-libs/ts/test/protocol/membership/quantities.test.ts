import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import { bigIntBytes } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";

import vectors from "../../../../../test-vectors/policy/quantities.json" with { type: "json" };
import { EMPTY_MINT_POLICY } from "../../../src/protocol/membership/mint-policy.js";
import {
  GuardScope,
  approvalMask,
  ownerDebits,
} from "../../../src/protocol/membership/owner-debits.js";

await initializePoseidon();

const field = (value: number): Bytes32 => bigIntBytes(BigInt(value)) as Bytes32;

type Slot = Readonly<{ owner: number; asset: number; amount: number; ring?: boolean }>;
type Case = Readonly<{
  name: string;
  inputs?: readonly Slot[];
  outputs?: readonly Slot[];
  withdrawals?: readonly Slot[];
  public?: readonly Readonly<{ asset: number; gross: number }>[];
  rows?: readonly Readonly<{
    owner: number;
    asset: number;
    debit: number;
    kept: number;
    charge: number;
    charged_outflow: number;
  }>[];
  guards: readonly Readonly<{ owner: number; asset: number; guard: number }>[];
  asset_guards: readonly Readonly<{ asset: number; guard: number }>[];
  thresholds?: readonly Readonly<{
    asset: number;
    cosign_above?: number;
    withdrawal_threshold?: number;
  }>[];
  mask?: number;
}>;

const slot = (row: Slot) => ({
  owner: field(row.owner),
  asset: field(row.asset),
  amount: BigInt(row.amount),
});
const cases = vectors.cases as unknown as readonly Case[];

describe("quantities.json", () => {
  it.each(cases.map((vector) => [vector.name, vector] as const))("%s", (_, vector) => {
    const inputs = vector.inputs ?? [];
    const outputs = vector.outputs ?? [];
    const withdrawals = vector.withdrawals ?? [];
    const debitOutputs = outputs.map((row) => ({ ...slot(row), ring: row.ring === true }));
    const publicGross = (vector.public ?? []).map((row) => ({
      asset: field(row.asset),
      gross: BigInt(row.gross),
    }));
    const flows = ownerDebits({
      senders: inputs.map((row) => field(row.owner)),
      assets: [...inputs, ...outputs, ...withdrawals].map((row) => field(row.asset)),
      inputs: inputs.map(slot),
      outputs: debitOutputs,
      publicGross,
    });
    expect(flows).toEqual(
      (vector.rows ?? []).map((row) => ({
        owner: field(row.owner),
        asset: field(row.asset),
        debit: BigInt(row.debit),
        kept: BigInt(row.kept),
        charge: BigInt(row.charge),
        chargedOutflow: BigInt(row.charged_outflow),
      })),
    );
    const scope = new GuardScope({
      ringInputs: inputs.filter((row) => row.ring === true).map(slot),
      payments: [...debitOutputs, ...withdrawals.map((row) => ({ ...slot(row), ring: false }))],
    });
    for (const guard of vector.guards)
      expect(scope.owner(field(guard.owner), field(guard.asset))).toBe(BigInt(guard.guard));
    for (const guard of vector.asset_guards)
      expect(scope.asset(field(guard.asset))).toBe(BigInt(guard.guard));
    const policyOf = (asset: Bytes32) => {
      const row = vector.thresholds?.find((entry) =>
        field(entry.asset).every((byte, at) => byte === asset[at]),
      );
      return {
        ...EMPTY_MINT_POLICY,
        cosignAbove: BigInt(row?.cosign_above ?? 0),
        withdrawalThreshold: BigInt(row?.withdrawal_threshold ?? 0),
      };
    };
    if (vector.thresholds !== undefined)
      expect(approvalMask({ flows, publicGross, policyOf })).toBe(vector.mask ?? 0);
  });

  it("reads no threshold from a zero bound or a missing record", () => {
    const flows = [
      {
        owner: field(1),
        asset: field(2),
        debit: 10n,
        kept: 0n,
        charge: 0n,
        chargedOutflow: 10n,
      },
    ];
    expect(
      approvalMask({
        flows,
        publicGross: [{ asset: field(2), gross: 10n }],
        policyOf: () => EMPTY_MINT_POLICY,
      }),
    ).toBe(0);
  });
});
