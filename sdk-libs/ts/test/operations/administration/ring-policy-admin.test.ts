import { storageRegistryAccount } from "../../helpers/ring-accounts.js";
import { address, blockhash, type Address } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { RpcAccount } from "@heliuslabs/spr/client";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { initializePoseidon } from "@heliuslabs/spr";
import { ringPolicyPda } from "../../../src/protocol/pda/index.js";
import type { RingSourceSlot } from "../../../src/protocol/codec/ring-codecs.js";
import {
  LIST_IDS,
  ListId,
  buildRuleTable,
  type Rule,
} from "../../../src/protocol/membership/policy.js";
import { buildRingUpdatePolicyTransaction } from "../../../src/operations/management/policy-admin.js";
import type { RingPolicySourceOwner } from "../../../src/operations/management/admin.js";
import { ZERO_ADDRESS, ownedAccount, ringPolicyData } from "../../helpers/ring-accounts.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const CURATOR_A = address("CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8");
const CURATOR_B = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const RECORDS = address("6NxnStrvfxkDAnWHyvc6SVXkZvBKtpHS3Bd9WfCSgUSv");
const AUTHORITY = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const LIFETIME = Object.freeze({
  blockhash: blockhash("11111111111111111111111111111111"),
  lastValidBlockHeight: 10n,
});

const RULES: readonly Rule[] = [
  {
    subject: "outputOwner",
    source: { kind: "lists", present: [ListId.allow], absent: [] },
    guard: { kind: "always" },
  },
  {
    subject: "outputOwner",
    source: { kind: "lists", present: [], absent: [ListId.block] },
    guard: { kind: "always" },
  },
];

beforeAll(initializePoseidon);

/** The ring's policy reads allow from its own records and block from curator A. */
async function chain(input: Readonly<{ hasPolicy?: boolean; privateBlock?: boolean }> = {}) {
  const accounts = new Map<Address, RpcAccount>();
  const sources: RingSourceSlot[] = LIST_IDS.map((listId) =>
    listId === ListId.allow || (input.privateBlock === true && listId === ListId.privateBlock)
      ? { listId, registry: ZERO_ADDRESS }
      : listId === ListId.block
        ? { listId, registry: CURATOR_A }
        : { listId: 0, registry: ZERO_ADDRESS },
  );
  const [policy, policyBump] = await ringPolicyPda(RING);
  accounts.set(
    policy,
    ownedAccount(
      RING,
      ringPolicyData({
        bump: policyBump,
        roles: { policy: AUTHORITY },
        records: RECORDS,
        ...(input.privateBlock === true ? { tracking: CURATOR_A } : {}),
        sources,
        ...(input.hasPolicy === false ? {} : { policyHash: new Uint8Array(32).fill(1) as Bytes32 }),
      }),
    ),
  );
  for (const registry of [RECORDS, CURATOR_A])
    accounts.set(
      registry,
      storageRegistryAccount([
        { hash: new Uint8Array(32).fill(1) as Bytes32, revision: 1n, expiresAt: 0n },
      ]),
    );
  return {
    getAccount: vi.fn(async (account: Address) => accounts.get(account)),
    getLatestBlockhash: vi.fn(async () => LIFETIME),
  };
}

describe("policy transactions", () => {
  it("compiles a table write under the authority after reading the curator registry", async () => {
    const client = await chain();
    const transaction = await buildRingUpdatePolicyTransaction({
      client,
      ringProgramId: RING,
      authority: AUTHORITY,
      update: {
        kind: "rules",
        table: buildRuleTable({ rules: RULES }),
        sharedSources: [{ listId: ListId.block, curatorRegistry: CURATOR_A }],
      },
    });
    expect(Object.keys(transaction.signatures)).toEqual([AUTHORITY]);
    expect(client.getAccount).toHaveBeenCalledWith(CURATOR_A, undefined);
  });

  it("refuses a curator without a registry before the blockhash", async () => {
    const client = await chain();
    await expect(
      buildRingUpdatePolicyTransaction({
        client,
        ringProgramId: RING,
        authority: AUTHORITY,
        update: {
          kind: "rules",
          table: buildRuleTable({ rules: RULES }),
          sharedSources: [{ listId: ListId.block, curatorRegistry: CURATOR_B }],
        },
      }),
    ).rejects.toMatchObject({
      code: "RING_BUILD_POLICY",
      causeCode: "RING_MEMBER_REGISTRY_MISSING",
    });
    expect(client.getLatestBlockhash).not.toHaveBeenCalled();
  });

  it("refuses an audit-only ring before the curator or the blockhash", async () => {
    const client = await chain({ hasPolicy: false });
    const shared = [{ listId: ListId.block, curatorRegistry: CURATOR_A }];
    const table = buildRuleTable({ rules: RULES });
    await expect(
      buildRingUpdatePolicyTransaction({
        client,
        ringProgramId: RING,
        authority: AUTHORITY,
        update: { kind: "rules", table, sharedSources: shared },
      }),
    ).rejects.toMatchObject({
      code: "RING_BUILD_POLICY",
      causeCode: "RING_POLICY_TIER_MISMATCH",
    });
    expect(client.getAccount).not.toHaveBeenCalledWith(CURATOR_A, undefined);
    expect(client.getLatestBlockhash).not.toHaveBeenCalled();
  });

  it("refuses an unpaired source for a private list whatever the stored bits say", async () => {
    const client = await chain({ privateBlock: true });
    await expect(
      buildRingUpdatePolicyTransaction({
        client,
        ringProgramId: RING,
        authority: AUTHORITY,
        update: { kind: "source", listId: ListId.privateBlock, source: { kind: "own" } },
      }),
    ).rejects.toMatchObject({
      causeCode: "RING_POLICY_SOURCE_INVALID",
    });
  });

  it("re-points a referenced list and keeps the sources to one curator", async () => {
    const client = await chain();
    const build = (listId: ListId, source: RingPolicySourceOwner) =>
      buildRingUpdatePolicyTransaction({
        client,
        ringProgramId: RING,
        authority: AUTHORITY,
        update: { kind: "source", listId, source },
      });
    await expect(build(ListId.block, { kind: "own" })).resolves.toBeDefined();
    await expect(
      build(ListId.allow, { kind: "curator", registry: CURATOR_A }),
    ).resolves.toBeDefined();
    await expect(build(ListId.frozen, { kind: "own" })).rejects.toMatchObject({
      code: "RING_BUILD_POLICY",
      causeCode: "RING_POLICY_SOURCE_INVALID",
    });
    await expect(
      build(ListId.allow, { kind: "curator", registry: CURATOR_B }),
    ).rejects.toMatchObject({ code: "RING_BUILD_POLICY", causeCode: "RING_POLICY_SOURCE_INVALID" });
    await expect(build(ListId.block, { kind: "curator", registry: RECORDS })).rejects.toMatchObject(
      {
        code: "RING_BUILD_POLICY",
        causeCode: "RING_POLICY_SOURCE_INVALID",
        cause: { details: { reason: "OwnCurator" } },
      },
    );
  });
});
