import { describe, expect, it, vi } from "vitest";
import type { Bytes32 } from "@heliuslabs/zolana";
import { parseProof } from "@heliuslabs/zolana/client";
import { ProverClient } from "@heliuslabs/zolana/internal";

import { RING_PROVING_KEY_SHA256S } from "../../src/protocol/proof/proving-keys.js";
import { CustomRingProver } from "../../src/rpc/prover/client.js";
import type { RegisterKeyProofRequest } from "../../src/rpc/prover/ring.js";
import { proofFor } from "../helpers/proofs.js";

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function ringProver(fetch: typeof globalThis.fetch): CustomRingProver {
  return new CustomRingProver(new ProverClient({ url: "http://127.0.0.1:3001", fetch }));
}

describe("ring prover contracts", () => {
  const registerKey: RegisterKeyProofRequest = {
    kind: "registerKey",
    publicInputHash: bytes(1),
    member: bytes(2),
    nullifierSecret: new Uint8Array(32) as Bytes32,
    ephSk: bytes(3),
    auditorPk: bytes(4),
  };

  it("decodes a ring proof and refuses a malformed response", async () => {
    const proof = proofFor({ circuitType: "custom-ring-register-key" });
    const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json(proof));
    const prover = ringProver(fetch);
    await expect(prover.proveRing(registerKey)).resolves.toEqual(parseProof(proof));
    fetch.mockResolvedValueOnce(Response.json({ ...proof, ar: [] }));
    await expect(prover.proveRing(registerKey)).rejects.toMatchObject({
      code: "CLIENT_PROOF_PARSE",
    });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("refuses a key catalog that leaves out a pinned ring key", async () => {
    const keys = Object.entries(RING_PROVING_KEY_SHA256S).map(([name, sha256]) => ({
      name,
      artifacts: [{ format: "gnark", sha256, size: 1, url: `https://keys.test/${name}` }],
    }));
    const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json({ keys }));
    await expect(ringProver(fetch).checkProvingKeys()).resolves.toMatchObject({
      keys: expect.arrayContaining([expect.objectContaining({ name: keys[0]?.name })]),
    });
    const [dropped, ...served] = keys;
    fetch.mockResolvedValueOnce(Response.json({ keys: served }));
    await expect(ringProver(fetch).checkProvingKeys()).rejects.toMatchObject({
      code: "RING_PROVING_KEYS_MISSING",
      details: { keyNames: dropped?.name },
    });
  });

  it("refuses a ring proof from another ring key", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      Response.json(proofFor({ circuitType: "custom-ring-deposit-8" })),
    );
    await expect(ringProver(fetch).proveRing(registerKey)).rejects.toMatchObject({
      code: "CLIENT_PROVING_KEY_MISMATCH",
      details: { keyName: "custom_ring_register_key.key" },
    });
  });
});
