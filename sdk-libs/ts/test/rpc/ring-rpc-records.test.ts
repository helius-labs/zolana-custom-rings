import { createKeyPairSignerFromPrivateKeyBytes } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";
import { RingRpc, signCreateRecordsRegistryRequest } from "../../src/rpc/ring-rpc.js";

const RING = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx" as Address;
const STORAGE_AUTHORITY = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR" as Address;
// `solana find-program-derived-address` over the storage program seeds of RING under STORAGE_AUTHORITY.
const RECORDS = "EYDriRqQxnFgroPabnS1CcnQQGaKF6zWSrxqV76n9tE6" as Address;

function answering(registry: Address): RingRpc {
  const fetch: typeof globalThis.fetch = () =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: { registry, storageAuthority: STORAGE_AUTHORITY },
        }),
        { headers: { "content-type": "application/json" } },
      ),
    );
  return new RingRpc("http://ring.example", { fetch, allowInsecureHttp: true });
}

describe("createRecordsRegistry", () => {
  it("accepts only the ring's records under the storage authority it names", async () => {
    const authority = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(8));
    const request = await signCreateRecordsRegistryRequest(
      {
        cluster: new Uint8Array(32).fill(1) as Bytes32,
        service: STORAGE_AUTHORITY,
        ringProgramId: RING,
      },
      authority,
    );
    await expect(answering(RECORDS).createRecordsRegistry(request)).resolves.toEqual({
      registry: RECORDS,
      storageAuthority: STORAGE_AUTHORITY,
    });
    await expect(answering(STORAGE_AUTHORITY).createRecordsRegistry(request)).rejects.toMatchObject(
      { code: "RING_RPC" },
    );
  });
});
