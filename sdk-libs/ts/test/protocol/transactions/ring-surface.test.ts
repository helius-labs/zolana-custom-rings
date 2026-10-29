import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";
import { compressProof, parseProof } from "@heliuslabs/zolana/client";
import { customRingProof } from "../../../src/rpc/prover/proof.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../../../src/protocol/proof/custom-ring-proof.js";
import {
  RING_PROVING_KEY_SHA256S,
  ringProvingKey,
} from "../../../src/protocol/proof/proving-keys.js";
import { RingError, wrapRingError } from "../../../src/protocol/error.js";

const ZERO_POINT = ["0x0", "0x0"];
const ZERO_PROOF = {
  ar: ZERO_POINT,
  bs: [ZERO_POINT, ZERO_POINT],
  krs: ZERO_POINT,
};

type Lockfile = { keys: Record<string, { sha256: string }> };

// The file the ring prover verifies every ring key it loads against.
const lock = JSON.parse(
  readFileSync(new URL("../../../../../prover/ring/proving-keys.lock", import.meta.url), "utf8"),
) as Lockfile;

describe("ring error envelope", () => {
  it("keeps the cause reachable but out of serialization", () => {
    const cause = new Error("inner");
    const error = new RingError("RING_RPC", { cause });
    expect(error.cause).toBe(cause);
    expect(JSON.stringify(error)).not.toContain("inner");
    expect(JSON.parse(JSON.stringify(error))).toEqual({ name: "RingError", code: "RING_RPC" });
  });

  it("returns a same-code wrap unchanged", () => {
    const inner = new RingError("RING_BUILD_TRANSFER");
    expect(wrapRingError("RING_BUILD_TRANSFER", inner)).toBe(inner);
  });
});

describe("custom ring proof layout", () => {
  it("needs the BSB22 commitment pair and lays out the custom-ring proof", () => {
    const generator = ["0x1", "0x2"];
    expect(() => customRingProof(parseProof(ZERO_PROOF))).toThrow(
      expect.objectContaining({ code: "CLIENT_PROOF_PARSE" }),
    );
    const proof = parseProof({
      ...ZERO_PROOF,
      ar: generator,
      proofCommitment: generator,
      proofCommitmentPok: ZERO_POINT,
    });
    const compressed = compressProof(proof);
    const audit = customRingProof(proof);
    expect(audit).toHaveLength(CUSTOM_RING_PROOF_LENGTH);
    expect(audit.subarray(0, 32)).toEqual(compressed.a);
    expect(audit.subarray(32, 96)).toEqual(new Uint8Array(64));
    expect(audit.subarray(96, 128)).toEqual(compressed.c);
    expect(audit.subarray(128, 160)).toEqual(compressed.commitment);
    expect(audit.subarray(160, 192)).toEqual(compressed.commitmentPok);
  });
});

describe("RING_PROVING_KEY_SHA256S", () => {
  it("equals proving-keys.lock, no key missing or extra", () => {
    const locked = Object.fromEntries(
      Object.entries(lock.keys).map(([name, entry]) => [name, entry.sha256]),
    );
    expect({ ...RING_PROVING_KEY_SHA256S }).toEqual(locked);
  });

  it("names the key file the prover proves each ring circuit with", () => {
    expect([
      ringProvingKey({ family: "registerKey" }),
      ringProvingKey({ family: "deposit", capacity: 8 }),
    ]).toEqual(
      ["custom_ring_register_key.key", "custom_ring_deposit_8.key"].map((name) => ({
        name,
        sha256: lock.keys[name]?.sha256,
      })),
    );
  });
});

describe("public package surface", () => {
  it("serves the ring surface from its entry points", async () => {
    const [root, client, keypair, advanced] = await Promise.all([
      import("../../../src/index.js"),
      import("../../../src/client/index.js"),
      import("../../../src/keypair/index.js"),
      import("../../../src/ring-advanced.js"),
    ]);
    for (const name of [
      "ringConfigAddress",
      "initializeRingInstruction",
      "ringTransactInstruction",
      "CustomRingTransfer",
      "AnonymousTransfer",
      "DelegateTransfer",
      "updateRingPolicyInstruction",
      "updateRingAuthorityInstruction",
      "buildRingUpdatePolicyTransaction",
      "deployRingProgram",
      "KeyRegistration",
      "recoverRingMemberNotes",
      "createCustomRingClient",
      "decryptRingDepositUtxo",
      "customRingDepositPayload",
    ] as const) {
      expect(root[name]).toBeTypeOf("function");
    }
    expect(client.createCustomRingClient).toBe(root.createCustomRingClient);
    expect(client.ringInputOpening).toBeTypeOf("function");
    expect(keypair.RingAddress).toBeTypeOf("function");
    expect(advanced.sealRingDisclosure).toBeTypeOf("function");
  });
});
