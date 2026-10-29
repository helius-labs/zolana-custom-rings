import { readFileSync } from "node:fs";

import { createKeyPairSignerFromPrivateKeyBytes, getBase58Decoder } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import type { Address, Bytes32, Signature } from "@heliuslabs/zolana/interface";
import type { indexerTypes } from "@heliuslabs/zolana/internal";
import { ShieldedKeypair, SigningKey } from "@heliuslabs/zolana/keypair";
import {
  encodePrepareAuthorityTransferRequest,
  encodePrepareRelayRequest,
} from "../../../src/protocol/ring-rpc/ring-rpc-codec.js";
import {
  RingAuthorityTransferRequest,
  authorityTransferAttestation,
} from "../../../src/rpc/ring-rpc.js";

const base58 = getBase58Decoder();

function filled(byte: number, length: number): string {
  return base58.decode(new Uint8Array(length).fill(byte));
}

describe("prepareRelay", () => {
  it("encodes the request byte for byte as the Rust vector", () => {
    const vector = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/relay_request.json", import.meta.url),
        "utf8",
      ),
    ) as { wire: string };
    const wire = encodePrepareRelayRequest({
      ring: filled(1, 32) as Address,
      quote: { feePayer: filled(2, 32) as Address, validUntilSlot: 4242n },
      intent: {
        operation: "anonymous",
        proofInputs: "AwQF" as indexerTypes.Base64String,
        ownerSignature: filled(7, 64) as Signature,
      },
    });
    expect(JSON.stringify(wire)).toBe(vector.wire);
  });
});

describe("prepareAuthorityTransfer", () => {
  it("signs the delegate's request byte for byte as the Rust vector", async () => {
    const vector = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/authority_transfer.json", import.meta.url),
        "utf8",
      ),
    ) as { message: string; wire: string };
    const address = (seed: number) =>
      ShieldedKeypair.fromKeypair(
        SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
      ).shieldedAddress();
    const delegate = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(8));
    const target = {
      cluster: new Uint8Array(32).fill(1) as Bytes32,
      service: filled(2, 32) as Address,
      ringProgramId: filled(7, 32) as Address,
    };
    const transfer = {
      source: address(5),
      mint: filled(3, 32) as Address,
      payments: [{ recipient: address(9), amount: 250n }],
    };
    const message = authorityTransferAttestation({
      target,
      delegate: delegate.address,
      transfer,
      timestamp: 1_700_000_000n,
      nonce: new Uint8Array(32).fill(4) as Bytes32,
    });
    expect(new TextDecoder().decode(message)).toBe(vector.message);
    const nonce = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((array) => {
      (array as Uint8Array).fill(4);
      return array;
    });
    const signed = await RingAuthorityTransferRequest.forTransfer(target, transfer)
      .at(1_700_000_000n)
      .sign(delegate)
      .finally(() => nonce.mockRestore());
    expect(JSON.stringify(encodePrepareAuthorityTransferRequest(signed))).toBe(vector.wire);
  });
});
