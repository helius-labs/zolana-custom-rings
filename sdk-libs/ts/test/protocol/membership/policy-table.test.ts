import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { Bytes32 } from "@heliuslabs/spr/interface";

import rulesVector from "../../../../../test-vectors/policy/ring-policy-rules.json" with { type: "json" };
import { EMPTY_MINT_POLICY } from "../../../src/protocol/membership/mint-policy.js";
import {
  admitTransfer,
  decodeRule,
  decodeRuleTable,
  evaluateInputAssets,
  evaluatePayments,
  evaluateSenders,
  ListId,
  policyTableFields,
  policyTableHash,
  type RecordLists,
} from "../../../src/protocol/membership/policy.js";

await initializePoseidon();

const field = (text: string): Bytes32 => hexToBytes(text) as Bytes32;

interface TableCase {
  readonly name: string;
  readonly sources: readonly Readonly<{ list_id: number; registry: string }>[];
  readonly rules: readonly string[];
  readonly fields: readonly string[];
  readonly policy_hash: string;
}

/** A u64 threshold passes a double, the rows carry it as hex and `rule_parts` is unread. */
const tableVector = JSON.parse(
  readFileSync(
    new URL("../../../../../test-vectors/policy/ring-policy-table.json", import.meta.url),
    "utf8",
  ),
) as Readonly<{ cases: readonly TableCase[] }>;

describe("ring-policy-table.json", () => {
  it.each(tableVector.cases.map((vector) => [vector.name, vector] as const))("%s", (_, vector) => {
    const table = { rules: vector.rules.map((row) => decodeRule(field(row))) };
    const sources = vector.sources.map((slot) => ({
      listId: slot.list_id,
      registry: field(slot.registry),
    }));
    expect(policyTableFields(table, sources).map((row) => bytesToHex(row))).toEqual(vector.fields);
    expect(bytesToHex(policyTableHash(table, sources))).toBe(vector.policy_hash);
  });
});

describe("ring-policy-rules.json", () => {
  type Case = (typeof rulesVector.cases)[number];
  const expected = (outcome: Case["outcome"]) =>
    outcome.kind === "pass"
      ? undefined
      : {
          kind: "lists",
          rule: outcome.rule,
          subject:
            outcome.subject === "sender"
              ? { kind: "sender" }
              : { kind: outcome.subject, output: outcome.output },
        };

  it.each(rulesVector.cases.map((vector) => [vector.name, vector] as const))("%s", (_, vector) => {
    const lookup = (list: readonly { member: string; lists: number }[], member: string): bigint =>
      BigInt(list.find((record) => record.member === member)?.lists ?? 0);
    const lists = (member: string): RecordLists => ({
      own: lookup(vector.own_records, member),
      curator: lookup(vector.curator_records, member),
    });
    const refusal = admitTransfer(
      decodeRuleTable({ rules: vector.rules.map(field) }),
      vector.sources.map((source) => ({
        listId: source.list_id,
        registry: field(source.registry),
      })),
      {
        sender: lists(vector.sender),
        ringInputs: (
          vector.ring_inputs as readonly { owner: string; asset: string; amount: number }[]
        ).map((input) => ({
          owner: field(input.owner),
          asset: field(input.asset),
          amount: BigInt(input.amount),
        })),
        outputs: vector.outputs.map((output) => ({
          ring: output.ring,
          owner: field(output.owner),
          asset: field(output.asset),
          amount: BigInt(output.amount),
          ownerLists: lists(output.owner),
          assetLists: lists(output.asset),
          mintPolicy: {
            ...EMPTY_MINT_POLICY,
            threshold: BigInt(
              vector.inline_limits[
                (vector.inline_assets as readonly string[]).indexOf(output.asset)
              ] ?? 0,
            ),
          },
        })),
      },
    );
    expect(refusal).toEqual(expected(vector.outcome));
  });
});

describe("sender, payment and input asset evaluation", () => {
  const member = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;
  const sources = [] as const;
  const onBlock = 1n << BigInt(ListId.block - 1);
  const off: RecordLists = { own: 0n, curator: 0n };
  const on: RecordLists = { own: onBlock, curator: 0n };
  const table = (subject: "sender" | "outputOwner" | "asset") =>
    Object.freeze({
      rules: [
        {
          subject,
          source: { kind: "lists" as const, present: [], absent: [ListId.block] },
          guard: { kind: "always" as const },
        },
      ],
    });
  const payment = (ownerLists: RecordLists, assetLists: RecordLists) => ({
    ring: true,
    owner: member(1),
    asset: member(2),
    amount: 5n,
    ownerLists,
    assetLists,
    mintPolicy: EMPTY_MINT_POLICY,
  });
  const noSenders = (subject: "outputOwner" | "asset", lists: RecordLists) =>
    evaluatePayments(table(subject), sources, {
      ringInputs: [],
      outputs: [payment(lists, lists)],
    });

  it("refuses a blocked recipient and asset with no sender row", () => {
    expect(noSenders("outputOwner", on)?.subject).toEqual({ kind: "owner", output: 0 });
    expect(noSenders("asset", on)?.subject).toEqual({ kind: "asset", output: 0 });
    expect(noSenders("outputOwner", off)).toBeUndefined();
    expect(noSenders("asset", off)).toBeUndefined();
  });

  it("holds sender rules to the sender alone", () => {
    expect(evaluateSenders(table("sender"), sources, [off, on])?.subject).toEqual({
      kind: "sender",
    });
    expect(evaluateSenders(table("sender"), sources, [off])).toBeUndefined();
    expect(evaluateSenders(table("sender"), sources, [])).toBeUndefined();
    expect(
      evaluatePayments(table("sender"), sources, { ringInputs: [], outputs: [payment(on, on)] }),
    ).toBeUndefined();
  });

  it("refuses a delisted input asset under an unconditional asset rule alone", () => {
    const inputs = [{ input: 1, lists: on }];
    expect(evaluateInputAssets(table("asset"), sources, inputs)?.subject).toEqual({
      kind: "inputAsset",
      input: 1,
    });
    expect(evaluateInputAssets(table("outputOwner"), sources, inputs)).toBeUndefined();
    const guarded = {
      rules: [{ ...table("asset").rules[0]!, guard: { kind: "aboveAmount" as const, amount: 9n } }],
    };
    expect(evaluateInputAssets(guarded, sources, inputs)).toBeUndefined();
  });
});
