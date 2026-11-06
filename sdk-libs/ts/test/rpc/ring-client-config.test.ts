import { describe, expect, expectTypeOf, it, vi } from "vitest";
import type { SprClientConfig } from "@heliuslabs/spr";

import vector from "../../../../zolana/test-vectors/runtime_proving_keys.json" with { type: "json" };
import { provingKeySetFromCatalog } from "../../../../zolana/sdk-libs/ts/src/client/prover/key-set.js";
import {
  CustomRingClient,
  createCustomRingClient,
  type CustomRingClientConfig,
} from "../../src/rpc/client.js";

describe("ring client proving keys", () => {
  it("refuses a runtime set before constructing the shared prover", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const config = {
      proofDataSource: "client",
      provingKeys: provingKeySetFromCatalog(vector),
      get proverUrl(): string {
        throw new Error("prover configuration read");
      },
      fetch,
    } satisfies SprClientConfig;
    const refusal = {
      code: "CLIENT_INVALID_CONFIG",
      details: { field: "provingKeys" },
    };

    expectTypeOf(config).not.toExtend<CustomRingClientConfig>();
    expect(() => Reflect.construct(CustomRingClient, [config])).toThrow(
      expect.objectContaining(refusal),
    );
    await expect(Reflect.apply(createCustomRingClient, undefined, [config])).rejects.toMatchObject(
      refusal,
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it("keeps the default pinned keys without a runtime set", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();

    expect(() => new CustomRingClient({ fetch })).not.toThrow();
    await expect(createCustomRingClient({ fetch })).resolves.toBeInstanceOf(CustomRingClient);
    expect(fetch).not.toHaveBeenCalled();
  });
});
