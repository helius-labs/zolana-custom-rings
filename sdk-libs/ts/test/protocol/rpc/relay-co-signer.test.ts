/** An outside co-signer's verdicts against the Rust check's vector, each refused before a signature. */
import { readFileSync } from "node:fs";

import {
  getBase58Encoder,
  getBase64Encoder,
  type Address,
  type TransactionPartialSigner,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import type { indexerTypes } from "@heliuslabs/spr/internal";

import { CoSignerApproval } from "../../../src/proof/cosign.js";
import type { ApprovalOpening } from "../../../src/protocol/membership/approval-totals.js";
import {
  checkRelayMessage,
  decodeApprovalOpening,
  encodeApprovalOpening,
  expectedCoSigner,
  type CoSignerRule,
} from "../../../src/rpc/relay-message.js";
import type { RingRelayClient } from "../../../src/rpc/relay.js";

await initializePoseidon();

interface Case {
  readonly name: string;
  readonly accepts: number;
  readonly opening: unknown;
  readonly limits: readonly Readonly<{
    mint: Address;
    peak: string;
    outflow: string;
    gross: string;
  }>[];
  readonly seenBlinders: readonly string[];
  readonly message: string;
  readonly verdict: string;
}

const vector = JSON.parse(
  readFileSync(
    new URL("../../../../../test-vectors/rpc/relay_co_signer_messages.json", import.meta.url),
    "utf8",
  ),
) as Readonly<{ ring: Address; feePayer: Address; signer: Address; cases: readonly Case[] }>;

const base58 = getBase58Encoder();
const base64 = getBase64Encoder();
const hash = (text: string): Bytes32 => new Uint8Array(base58.encode(text)) as Bytes32;
const RELAY_ID = "11111111111111111111111111111111" as indexerTypes.Hash;

function ruleOf(entry: Case): CoSignerRule {
  if (entry.opening === null) return { kind: "threshold", accepts: entry.accepts };
  return {
    kind: "exact",
    approval: {
      opening: decodeApprovalOpening(JSON.stringify(entry.opening)),
      limits: entry.limits.map((limit) => ({
        mint: limit.mint,
        peak: BigInt(limit.peak),
        outflow: BigInt(limit.outflow),
        gross: BigInt(limit.gross),
      })),
      seenBlinders: entry.seenBlinders.map(hash),
    },
  };
}

async function verdict(
  rule: CoSignerRule,
  message: string,
  signer: Address = vector.signer,
): Promise<string> {
  const expected = await expectedCoSigner({
    ring: vector.ring,
    feePayer: vector.feePayer,
    signer: vector.signer,
    config: { mode: "anonymous" },
    setup: [],
    rule,
  });
  try {
    checkRelayMessage(expected, new Uint8Array(base64.encode(message)), signer);
    return "Accepted";
  } catch (error) {
    return String((error as { details?: { mismatch?: unknown } }).details?.mismatch);
  }
}

const named = (name: string): Case => {
  const found = vector.cases.find((entry) => entry.name === name);
  if (found === undefined) throw new Error(`no case ${name}`);
  return found;
};

describe("co-signer message check", () => {
  it.each(vector.cases)("reaches the Rust verdict on $name", async (entry) => {
    expect(await verdict(ruleOf(entry), entry.message)).toBe(entry.verdict);
  });

  it.each(vector.cases.filter((entry) => entry.opening !== null))(
    "encodes the opening of $name byte for byte as Rust serde",
    (entry) => {
      const text = JSON.stringify(entry.opening);
      expect(encodeApprovalOpening(decodeApprovalOpening(text))).toBe(text);
    },
  );

  it("refuses an opening of an unknown field or a numeric amount", () => {
    const honest = named("exactHonest").opening as Record<string, unknown>;
    expect(() => decodeApprovalOpening(JSON.stringify({ ...honest, extra: 1 }))).toThrow();
    const outputs = honest["outputs"] as readonly Record<string, unknown>[];
    expect(() =>
      decodeApprovalOpening(
        JSON.stringify({ ...honest, outputs: [{ ...outputs[0], peak: 4 }, ...outputs.slice(1)] }),
      ),
    ).toThrow();
  });

  describe("an opening past the vector", () => {
    const honest = named("exactHonest");
    const exact = (change: (opening: ApprovalOpening) => ApprovalOpening): CoSignerRule => {
      const rule = ruleOf(honest);
      if (rule.kind !== "exact") throw new Error("no opening");
      return {
        kind: "exact",
        approval: { ...rule.approval, opening: change(rule.approval.opening) },
      };
    };

    it("refuses an amount Rust cannot parse", async () => {
      const rule = exact((opening) => ({
        ...opening,
        outputs: opening.outputs.map((slot) => ({ ...slot, peak: "0x4" })),
      }));
      expect(await verdict(rule, honest.message)).toBe("FalseApprovalOpening");
    });

    it("refuses a zero blinder", async () => {
      const rule = exact((opening) => ({ ...opening, blinder: new Uint8Array(32) as Bytes32 }));
      expect(await verdict(rule, honest.message)).toBe("ZeroApprovalBlinder");
    });

    it("refuses a blinder or an asset at or past the modulus", async () => {
      const past = new Uint8Array(32).fill(0xff) as Bytes32;
      for (const rule of [
        exact((opening) => ({ ...opening, blinder: past })),
        exact((opening) => ({
          ...opening,
          outputs: opening.outputs.map((slot) => ({ ...slot, asset: past })),
        })),
      ])
        expect(await verdict(rule, honest.message)).toBe("FalseApprovalOpening");
    });

    it("refuses a layout of another length before the chain reads it", async () => {
      for (const rule of [
        exact((opening) => ({ ...opening, outputs: opening.outputs.slice(1) })),
        exact((opening) => ({ ...opening, public: opening.public.slice(1) })),
      ])
        expect(await verdict(rule, honest.message)).toBe("ApprovalOpeningLayout");
    });

    it("reads another signer as unrequested ahead of the rule", async () => {
      expect(await verdict(ruleOf(honest), honest.message, vector.feePayer)).toBe("Unrequested");
    });
  });

  it("signs an accepted frame and leaves a refused one unsigned", async () => {
    const submitRelay = vi.fn(async () => ({ status: "awaitingSignature" }));
    const relay = { submitRelay } as unknown as RingRelayClient;
    const signer = {
      address: vector.signer,
      signTransactions: vi.fn(async () => [{ [vector.signer]: new Uint8Array(64) }]),
    } as unknown as TransactionPartialSigner & { signTransactions: ReturnType<typeof vi.fn> };
    const pending = (entry: Case) =>
      new CoSignerApproval({
        relayId: RELAY_ID,
        message: new Uint8Array(base64.encode(entry.message)),
        ring: vector.ring,
        feePayer: vector.feePayer,
        signer: vector.signer,
        config: { mode: "anonymous" },
        setup: [],
        rule: ruleOf(entry),
      }).pending();
    await (await pending(named("noLimit"))).sign(relay, signer).then(
      () => expect.unreachable(),
      (error: unknown) =>
        expect(error).toMatchObject({ details: { mismatch: "ApprovalOverLimit" } }),
    );
    expect(signer.signTransactions).not.toHaveBeenCalled();
    await (await pending(named("exactHonest"))).sign(relay, signer);
    expect(submitRelay).toHaveBeenCalledWith(
      expect.objectContaining({ relayId: RELAY_ID, signer: vector.signer }),
      undefined,
    );
  });
});
