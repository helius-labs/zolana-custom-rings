import { readFileSync } from "node:fs";

import { createKeyPairSignerFromPrivateKeyBytes, getBase58Decoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Address, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import { indexerScalars } from "@heliuslabs/zolana/internal";
import { P256ReaderKey } from "../../../src/operations/management/reader-access.js";
import { WalletRecordUpdate } from "../../../src/operations/management/record-updates.js";
import { listWrite } from "../../../src/operations/management/record-writes.js";
import { ListId } from "../../../src/protocol/membership/policy.js";
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
      genesisHash: new Uint8Array(32).fill(3) as Bytes32,
      ringProgramId: filled(1),
      registry: filled(2),
      wallet: wallet.address,
      validUntilSlot: 4242n,
    })
      .withLists(listWrite({ set: [ListId.ringViewing] }))
      .withWalletGrant(
        P256ReaderKey.fromBytes(
          Uint8Array.from(
            Buffer.from(
              "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
              "hex",
            ),
          ) as Bytes33,
        ),
        "granted",
      )
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

describe("enrolment", () => {
  it("signs an enrolment byte for byte as the Rust vector and binds its awaited lists", async () => {
    const vector = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/enrolment_update.json", import.meta.url),
        "utf8",
      ),
    ) as { wire: string; updateId: string };
    const wallet = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(7));
    const signed = await new WalletRecordUpdate({
      genesisHash: new Uint8Array(32).fill(3) as Bytes32,
      ringProgramId: filled(1),
      registry: filled(2),
      wallet: wallet.address,
      validUntilSlot: 4242n,
    })
      .withLists(listWrite({ set: [ListId.ringViewing] }))
      .awaitingAuthority([ListId.allow])
      .sign(wallet);
    expect(JSON.stringify(encodeSubmitRecordUpdateRequest(signed))).toBe(vector.wire);
    expect(verifyRecordUpdate(signed)).toEqual(
      indexerScalars.hashBytes(vector.updateId as Parameters<typeof indexerScalars.hashBytes>[0]),
    );
    // An enrolment signature never verifies as a plain update.
    const plain = { ...signed, update: { ...signed.update, awaitedLists: 0n } };
    expect(() => verifyRecordUpdate(plain)).toThrow();
  });
});
