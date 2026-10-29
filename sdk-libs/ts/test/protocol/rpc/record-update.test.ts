import { readFileSync } from "node:fs";

import { createKeyPairSignerFromPrivateKeyBytes, getBase58Decoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Address } from "@heliuslabs/zolana/interface";
import { addressBytes, indexerScalars } from "@heliuslabs/zolana/internal";
import { WalletRecordUpdate } from "../../../src/operations/management/record-updates.js";
import { listWrite } from "../../../src/operations/management/record-writes.js";
import { ListId, memberOfTag } from "../../../src/protocol/membership/policy.js";
import { verifyRecordUpdate } from "../../../src/protocol/ring-rpc/record-update.js";
import { encodeSubmitRecordUpdateRequest } from "../../../src/protocol/ring-rpc/ring-rpc-codec.js";

const base58 = getBase58Decoder();

function filled(byte: number): Address {
  return base58.decode(new Uint8Array(32).fill(byte)) as Address;
}

describe("submitRecordUpdate", () => {
  it("signs a wallet update byte for byte as the Rust vector and verifies it", async () => {
    const vector = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/record_update.json", import.meta.url),
        "utf8",
      ),
    ) as { wire: string; updateId: string };
    const wallet = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(7));
    const signed = await new WalletRecordUpdate({
      ringProgramId: filled(1),
      registry: filled(2),
      wallet: wallet.address,
      validUntilSlot: 4242n,
    })
      .withLists(listWrite({ set: [ListId.ringViewing] }))
      .withWalletGrant(memberOfTag(addressBytes(filled(9))), "granted")
      .sign(wallet);
    expect(JSON.stringify(encodeSubmitRecordUpdateRequest(signed))).toBe(vector.wire);
    expect(verifyRecordUpdate(signed)).toEqual(
      indexerScalars.hashBytes(vector.updateId as Parameters<typeof indexerScalars.hashBytes>[0]),
    );
    // The signature covers the slot bound, a later one names another statement.
    const extended = { ...signed, update: { ...signed.update, validUntilSlot: 4243n } };
    expect(() => verifyRecordUpdate(extended)).toThrow();
  });
});
