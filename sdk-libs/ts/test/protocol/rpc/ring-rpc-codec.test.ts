import { readFileSync } from "node:fs";

import { getBase58Decoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Address, Signature } from "@heliuslabs/zolana/interface";
import type { indexerTypes } from "@heliuslabs/zolana/internal";
import { encodePrepareRelayRequest } from "../../../src/protocol/ring-rpc/ring-rpc-codec.js";

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
