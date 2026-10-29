import { address, blockhash, type Address } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { RpcAccount } from "@heliuslabs/zolana/client";
import { initializePoseidon } from "@heliuslabs/zolana";
import { X25519Keypair } from "@heliuslabs/zolana/keypair";
import { ringConfigPda, ringPolicyPda } from "../../../src/protocol/pda/index.js";
import type { RingSourceSlot } from "../../../src/protocol/codec/ring-codecs.js";
import {
  LIST_IDS,
  ListId,
  buildRuleTable,
  type Rule,
} from "../../../src/protocol/membership/policy.js";
import {
  buildRingCreatePolicyTransaction,
  buildRingSetPolicyRulesTransaction,
  buildRingSetPolicySourceTransaction,
} from "../../../src/operations/management/policy-admin.js";
import {
  ZERO_ADDRESS,
  ownedAccount,
  ringPolicyData,
  ringProgramConfigData,
} from "../../helpers/ring-accounts.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const CURATOR_A = address("CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8");
const CURATOR_B = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const RECORDS = address("6NxnStrvfxkDAnWHyvc6SVXkZvBKtpHS3Bd9WfCSgUSv");
const STORAGE = address("29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2");
const AUTHORITY = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const LIFETIME = Object.freeze({
  blockhash: blockhash("11111111111111111111111111111111"),
  lastValidBlockHeight: 10n,
});

const RULES: readonly Rule[] = [
  {
    subject: "outputOwner",
    source: { kind: "lists", present: [ListId.allow], absent: [ListId.block] },
    guard: { kind: "always" },
  },
];

beforeAll(initializePoseidon);

/** The ring's policy reads allow from its own records and block from curator A. */
async function chain(input: Readonly<{ hasPolicy?: boolean }> = {}) {
  const accounts = new Map<Address, RpcAccount>();
  const [config, configBump] = await ringConfigPda(RING);
  accounts.set(
    config,
    ownedAccount(
      RING,
      ringProgramConfigData({
        authority: AUTHORITY,
        auditorPublicKey: X25519Keypair.generate().publicKey().toBytes(),
        bump: configBump,
        hasPolicy: input.hasPolicy ?? true,
      }),
    ),
  );
  const sources: RingSourceSlot[] = LIST_IDS.map((listId) =>
    listId === ListId.allow
      ? { listId, registry: ZERO_ADDRESS }
      : listId === ListId.block
        ? { listId, registry: CURATOR_A }
        : { listId: 0, registry: ZERO_ADDRESS },
  );
  const [policy, policyBump] = await ringPolicyPda(RING);
  accounts.set(
    policy,
    ownedAccount(RING, ringPolicyData({ bump: policyBump, records: RECORDS, sources })),
  );
  accounts.set(CURATOR_A, ownedAccount(STORAGE, new Uint8Array(1)));
  return {
    getAccount: vi.fn(async (account: Address) => accounts.get(account)),
    getLatestBlockhash: vi.fn(async () => LIFETIME),
  };
}

describe("policy transactions", () => {
  it("compiles create policy under the authority after reading the curator registry", async () => {
    const client = await chain();
    const transaction = await buildRingCreatePolicyTransaction({
      client,
      ringProgramId: RING,
      authority: AUTHORITY,
      table: buildRuleTable({ rules: RULES }),
      sharedSources: [{ listId: ListId.block, curatorRegistry: CURATOR_A }],
    });
    expect(Object.keys(transaction.signatures)).toEqual([AUTHORITY]);
    expect(client.getAccount).toHaveBeenCalledWith(CURATOR_A, undefined);
  });

  it("refuses a curator without a registry before the blockhash", async () => {
    const client = await chain();
    await expect(
      buildRingCreatePolicyTransaction({
        client,
        ringProgramId: RING,
        authority: AUTHORITY,
        table: buildRuleTable({ rules: RULES }),
        sharedSources: [{ listId: ListId.block, curatorRegistry: CURATOR_B }],
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
    for (const build of [buildRingCreatePolicyTransaction, buildRingSetPolicyRulesTransaction])
      await expect(
        build({ client, ringProgramId: RING, authority: AUTHORITY, table, sharedSources: shared }),
      ).rejects.toMatchObject({
        code: "RING_BUILD_POLICY",
        causeCode: "RING_POLICY_TIER_MISMATCH",
      });
    expect(client.getAccount).not.toHaveBeenCalledWith(CURATOR_A, undefined);
    expect(client.getLatestBlockhash).not.toHaveBeenCalled();
  });

  it("re-points a referenced list and keeps the sources to one curator", async () => {
    const client = await chain();
    const build = (
      listId: ListId,
      source: Parameters<typeof buildRingSetPolicySourceTransaction>[0]["source"],
    ) =>
      buildRingSetPolicySourceTransaction({
        client,
        ringProgramId: RING,
        authority: AUTHORITY,
        listId,
        source,
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
    await expect(
      build(ListId.block, { kind: "curator", registry: RECORDS }),
    ).rejects.toMatchObject({
      code: "RING_BUILD_POLICY",
      causeCode: "RING_POLICY_SOURCE_INVALID",
      cause: { details: { reason: "OwnCurator" } },
    });
  });
});
