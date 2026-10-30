import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32 } from "@heliuslabs/zolana/interface";
import {
  decodeRingPolicy,
  decodeStorageRegistry,
  registryRoot,
  ringRootRegistries,
  type RingMode,
  type RootReader,
} from "../../../src/protocol/codec/ring-codecs.js";
import {
  ringPolicyData,
  storageRegistryAccount,
  ZERO_ADDRESS,
} from "../../helpers/ring-accounts.js";

const RECORDS = address("Stor111111111111111111111111111111111111111");
const CURATOR = address("Cura111111111111111111111111111111111111111");
const POLICY_HASH = new Uint8Array(32).fill(1) as Bytes32;

function ring(input: Readonly<{ mode?: RingMode; policy?: boolean; curator?: boolean }>) {
  return decodeRingPolicy(
    ringPolicyData({
      bump: 255,
      records: RECORDS,
      ...(input.mode === undefined ? {} : { mode: input.mode }),
      ...(input.policy === true
        ? {
            policyHash: POLICY_HASH,
            sources: Array.from({ length: 8 }, (_, slot) =>
              slot === 0
                ? { listId: 1, registry: input.curator === true ? CURATOR : ZERO_ADDRESS }
                : { listId: 0, registry: ZERO_ADDRESS },
            ),
          }
        : {}),
    }),
  );
}

describe("live root registries", () => {
  it("passes no curator account on a ring without a curator source, the records then the curator with one", () => {
    expect(ringRootRegistries(ring({ policy: true }), "transfer")).toEqual([RECORDS]);
    expect(ringRootRegistries(ring({ policy: true, curator: true }), "transfer")).toEqual([
      RECORDS,
      CURATOR,
    ]);
  });

  it.each<[Parameters<typeof ring>[0], RootReader, readonly string[]]>([
    [{}, "transfer", []],
    [{}, "exemptTransfer", [RECORDS]],
    [{ policy: true, curator: true }, "exemptTransfer", [RECORDS, CURATOR]],
    [{}, "deposit", []],
    [{ mode: "confidentialEscrow" }, "deposit", [RECORDS]],
    [{ policy: true, curator: true }, "deposit", [RECORDS, CURATOR]],
    [{ policy: true, curator: true }, "merge", []],
    [{ mode: "confidentialEscrow", policy: true, curator: true }, "merge", [RECORDS]],
  ])("reads the roots Rust `RootRead` names for %o on %s", (input, reader, registries) => {
    expect(ringRootRegistries(ring(input), reader)).toEqual(registries);
  });

  it("serves the current root and a retired one only before its expiry", () => {
    const current = new Uint8Array(32).fill(4) as Bytes32;
    const retired = new Uint8Array(32).fill(3) as Bytes32;
    const registry = decodeStorageRegistry(
      storageRegistryAccount([
        { hash: current, revision: 4n, expiresAt: 0n },
        { hash: retired, revision: 3n, expiresAt: 100n },
      ]).data,
    );
    expect(registryRoot(registry, 4n, 1_000n)).toEqual(current);
    expect(registryRoot(registry, 3n, 99n)).toEqual(retired);
    expect(registryRoot(registry, 3n, 100n)).toBeUndefined();
    expect(registryRoot(registry, 5n, 0n)).toBeUndefined();
  });
});
