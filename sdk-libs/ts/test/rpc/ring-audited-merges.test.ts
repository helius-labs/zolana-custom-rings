import {
  generateKeyPairSigner,
  getAddressDecoder,
  getBase58Decoder,
  type Address,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32 } from "@heliuslabs/spr/interface";
import { assetField } from "@heliuslabs/spr/transaction";
import { initializePoseidon } from "@heliuslabs/spr";

import {
  RingReadRequest,
  RingRpc,
  messageSignerReader,
  type RingReadSigner,
  type RingReadTarget,
} from "../../src/rpc/ring-rpc.js";

await initializePoseidon();

function filled(byte: number, length = 32): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

function base58Of(byte: number): string {
  return getBase58Decoder().decode(filled(byte));
}

function addressOf(byte: number): Address {
  return getAddressDecoder().decode(filled(byte));
}

function signatureOf(byte: number): string {
  return getBase58Decoder().decode(filled(byte, 64));
}

const TARGET: RingReadTarget = {
  cluster: filled(1) as Bytes32,
  service: addressOf(2),
  ringProgramId: addressOf(7),
};

type Wire = Record<string, unknown>;

function answering(result: unknown): { rpc: RingRpc; bodies: Wire[] } {
  const bodies: Wire[] = [];
  const fetch = (async (_input: URL | string, init?: RequestInit) => {
    bodies.push(JSON.parse(String(init?.body)) as Wire);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), {
      headers: { "content-type": "application/json" },
    });
  }) as typeof globalThis.fetch;
  return {
    rpc: new RingRpc("http://ring.example", { fetch, allowInsecureHttp: true }),
    bodies,
  };
}

async function reader(): Promise<RingReadSigner> {
  return messageSignerReader(await generateKeyPairSigner());
}

describe("audited merge records", () => {
  const mint = addressOf(9);
  const opened = {
    slot: 12,
    txSignature: signatureOf(1),
    eventIndex: 0,
    outputCommitment: base58Of(1),
    ownerKey: base58Of(8),
    asset: getAddressDecoder().decode(assetField(mint)),
    mint,
    amount: 21,
    realNullifiers: [base58Of(6), base58Of(7)],
  };

  async function merges(opened: readonly Wire[]) {
    const { rpc } = answering({
      context: { slot: 14, blockTime: 1 },
      value: { opened, cursor: null },
    });
    const read = await RingReadRequest.auditedMerges(TARGET).sign(await reader());
    return rpc.readSignedMerges(read);
  }

  it("reads an inherited record", async () => {
    await expect(merges([opened])).resolves.toEqual({
      slot: 14n,
      blockTime: 1n,
      opened: [
        {
          slot: 12n,
          signature: signatureOf(1),
          eventIndex: 0,
          outputCommitment: filled(1),
          ownerKey: filled(8),
          asset: assetField(mint),
          mint,
          amount: 21n,
          realNullifiers: [filled(6), filled(7)],
        },
      ],
    });
  });

  it.each<readonly [string, Wire, string]>([
    ["a blinding", { ...opened, blinding: base58Of(3) }, "result.value.opened[0].shape"],
    ["a mint off its asset", { ...opened, mint: addressOf(8) }, "result.value.opened[0].mint"],
    ["an input list", { ...opened, inputCommitments: [] }, "result.value.opened[0].shape"],
  ])("refuses a record with %s", async (_name, record, path) => {
    await expect(merges([record])).rejects.toMatchObject({ details: { path } });
  });
});
