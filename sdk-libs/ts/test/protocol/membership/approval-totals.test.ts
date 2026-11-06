import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import { bigIntBytes } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";

import digests from "../../../../../test-vectors/policy/approval_totals.json" with { type: "json" };
import quantities from "../../../../../test-vectors/policy/quantities.json" with { type: "json" };
import {
  ApprovalTotals,
  approvalOpeningOf,
  openingTotals,
} from "../../../src/protocol/membership/approval-totals.js";
import type { DebitTransfer } from "../../../src/protocol/membership/owner-debits.js";

await initializePoseidon();

const PUBLIC_SLOTS = 3;

type Note = Readonly<{ owner: number; asset: number; amount: number; ring?: boolean }>;
type Case = Readonly<{
  name: string;
  inputs?: readonly Note[];
  outputs?: readonly Note[];
  public?: readonly Readonly<{ asset: number; gross: number }>[];
}>;

const identity = (value: number): Bytes32 => bigIntBytes(BigInt(value)) as Bytes32;
const fromHex = (text: string): Bytes32 => Uint8Array.from(Buffer.from(text, "hex")) as Bytes32;
const note = (row: Note) => ({
  owner: identity(row.owner),
  asset: identity(row.asset),
  amount: BigInt(row.amount),
});

const cases = quantities.cases as unknown as readonly Case[];

function totalsOf(vector: Case, slots: number): ApprovalTotals {
  const inputs = (vector.inputs ?? []).map(note);
  const outputs = (vector.outputs ?? []).map((row) => ({ ...note(row), ring: row.ring === true }));
  const publicGross = (vector.public ?? []).map((row) => ({
    asset: identity(row.asset),
    gross: BigInt(row.gross),
  }));
  const transfer: DebitTransfer = {
    senders: inputs.map((input) => input.owner),
    assets: [],
    inputs,
    outputs,
    publicGross,
  };
  return ApprovalTotals.new({
    transfer,
    slotAssets: Array.from({ length: slots }, (_, slot) => outputs[slot]?.asset),
    publicSlots: Array.from(
      { length: PUBLIC_SLOTS },
      (_, slot) => publicGross[slot] ?? { asset: identity(0), gross: 0n },
    ),
  });
}

describe("approval_totals.json", () => {
  it("pairs every digest with its quantities", () => {
    expect(digests.cases.map((digest) => digest.name)).toEqual(cases.map((entry) => entry.name));
  });

  it.each(digests.cases.map((digest, at) => [digest.name, digest, cases[at] as Case] as const))(
    "%s",
    (_, digest, vector) => {
      const commitment = totalsOf(vector, digest.slots).commitment(fromHex(digest.blinder));
      expect(Buffer.from(commitment).toString("hex")).toBe(digest.commitment);
    },
  );
});

describe("ApprovalTotals reads", () => {
  const totals = ApprovalTotals.new({
    transfer: {
      senders: [identity(1), identity(2)],
      assets: [],
      inputs: [
        { owner: identity(1), asset: identity(7), amount: 10n },
        { owner: identity(2), asset: identity(7), amount: 4n },
      ],
      outputs: [{ owner: identity(3), asset: identity(7), amount: 14n, ring: true }],
      publicGross: [],
    },
    slotAssets: [identity(7), undefined],
    publicSlots: [{ asset: identity(8), gross: 5n }],
  });

  it("reads one owner's peak and the sum over owners", () => {
    expect(totals.peakOf(identity(7))).toBe(10n);
    expect(totals.outflowOf(identity(7))).toBe(14n);
  });

  it("reads zero for an asset no slot names and for a dummy slot", () => {
    expect(totals.peakOf(identity(9))).toBe(0n);
    expect(totals.outflowOf(identity(9))).toBe(0n);
    expect(totals.outputs[1]).toEqual({ asset: identity(0), peak: 0n, chargedOutflow: 0n });
  });

  it("moves the commitment with the blinder and with a total", () => {
    const blinder = identity(0x51);
    const base = totals.commitment(blinder);
    expect(totals.commitment(identity(0x52))).not.toEqual(base);
    const bigger = ApprovalTotals.new({
      transfer: {
        senders: [identity(1)],
        assets: [],
        inputs: [{ owner: identity(1), asset: identity(7), amount: 11n }],
        outputs: [{ owner: identity(3), asset: identity(7), amount: 11n, ring: true }],
        publicGross: [],
      },
      slotAssets: [identity(7), undefined],
      publicSlots: [{ asset: identity(8), gross: 5n }],
    });
    expect(bigger.commitment(blinder)).not.toEqual(base);
  });
});

describe("ApprovalOpening", () => {
  const totals = ApprovalTotals.new({
    transfer: {
      senders: [identity(1)],
      assets: [],
      inputs: [{ owner: identity(1), asset: identity(7), amount: 10n }],
      outputs: [{ owner: identity(3), asset: identity(7), amount: 10n, ring: true }],
      publicGross: [],
    },
    slotAssets: [identity(7), undefined],
    publicSlots: [{ asset: identity(8), gross: 5n }],
  });
  const blinder = identity(0x51);

  it("rebuilds the commitment from its text", () => {
    const opened = openingTotals(approvalOpeningOf(totals, blinder));
    expect(opened?.commitment(blinder)).toEqual(totals.commitment(blinder));
  });

  it.each(["", " 4 ", "0x10", "-1", "1e3", "340282366920938463463374607431768211456"])(
    "refuses the amount %j as Rust `u128::from_str` does",
    (peak) => {
      const opening = approvalOpeningOf(totals, blinder);
      const [slot, ...rest] = opening.outputs;
      expect(openingTotals({ ...opening, outputs: [{ ...slot!, peak }, ...rest] })).toBeUndefined();
    },
  );

  it.each([
    ["+4", 4n],
    ["04", 4n],
    ["340282366920938463463374607431768211455", (1n << 128n) - 1n],
  ])("reads the amount %j as Rust `u128::from_str` does", (peak, expected) => {
    const opening = approvalOpeningOf(totals, blinder);
    const [slot, ...rest] = opening.outputs;
    expect(
      openingTotals({ ...opening, outputs: [{ ...slot!, peak }, ...rest] })?.outputs[0]?.peak,
    ).toBe(expected);
  });
});
