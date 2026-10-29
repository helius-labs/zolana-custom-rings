import { address, type Address, type Instruction } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import { SYSTEM_PROGRAM, addressBytes, protocolConfigAddress } from "@heliuslabs/zolana/internal";
import { SHIELDED_POOL_PROGRAM_ID } from "@heliuslabs/zolana/interface";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import {
  ShieldedKeypair,
  SigningKey,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import {
  ringAuthAddress,
  ringCoSignerAddress,
  ringConfigAddress,
  ringMemberRegistryAddress,
  ringPolicyAddress,
  ringRecordQueueAddress,
} from "../../../src/protocol/pda/index.js";
import {
  RingInstructionTag,
  clearRingCoSignerInstruction,
  createMemberRegistryInstruction,
  initializeRingInstruction,
  ringComputeUnitLimit,
  setRingCoSignerInstruction,
  setRingDelegateInstruction,
  setRingInsertFeeInstruction,
  setRingPausedInstruction,
  updateRingAuthorityInstruction,
  updateRingPolicyInstruction,
  type RingKind,
  type RingPolicyTableInput,
} from "../../../src/operations/management/admin.js";
import { decodeRingProgramConfig } from "../../../src/protocol/codec/ring-codecs.js";
import { ringProgramDataAddress } from "../../../src/protocol/membership/config.js";
import {
  ListId,
  buildRuleTable,
  encodeRule,
  type Rule,
} from "../../../src/protocol/membership/policy.js";
import {
  grantReadAccessInstruction,
  readAccessRecordAddress,
  readerKeyBytes,
  revokeReadAccessInstruction,
} from "../../../src/operations/management/reader-access.js";

import { solanaRpcReads } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { ringProgramConfigData } from "../../helpers/ring-accounts.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const CURATOR = address("CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8");
const AUTHORITY = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const NEXT = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const PAYER = address("29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2");
const RECORDS = address("7BgBvyjrZX1YKz4oh9mjb8ZScatkkwb8DzFx7LoiVkM3");
const STORAGE_AUTHORITY = address("GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL");

const READ = 0;
const WRITE = 1;
const SIGN = 2;
const SIGN_WRITE = 3;

beforeAll(initializePoseidon);

function metas(instruction: Instruction): readonly (readonly [Address, number])[] {
  return (instruction.accounts ?? []).map(({ address: account, role }) => [account, role] as const);
}

/** A client whose rent read answers `minimum` and records every space it was asked for. */
function rentClient(minimum: bigint) {
  const spaces: bigint[] = [];
  const solanaRpc = solanaRpcReads({
    getMinimumBalanceForRentExemption: (space: bigint) => ({
      send: async () => {
        spaces.push(space);
        return minimum;
      },
    }),
  });
  return { client: { solanaRpc }, spaces };
}

function u64le(value: bigint): number[] {
  return Array.from({ length: 8 }, (_, index) => Number((value >> BigInt(8 * index)) & 0xffn));
}

const RULES: readonly Rule[] = [
  {
    subject: "outputOwner",
    source: { kind: "lists", present: [ListId.allow], absent: [ListId.block] },
    guard: { kind: "always" },
  },
];

describe("initialize and policy update", () => {
  it("creates the config, the policy and the pool registration in one instruction", async () => {
    const auditor = X25519Keypair.generate().publicKey();
    const table = buildRuleTable({ rules: RULES });
    const [rule] = table.rules;
    if (rule === undefined) throw new Error("table without its rule");
    const head = [
      [PAYER, SIGN_WRITE],
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), WRITE],
      [SYSTEM_PROGRAM, READ],
      [RING, READ],
      [await ringProgramDataAddress(RING), READ],
      [await protocolConfigAddress(), READ],
      [await ringAuthAddress(RING), WRITE],
      [SHIELDED_POOL_PROGRAM_ID, READ],
    ];
    const policy = await initializeRingInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      auditorPublicKey: auditor,
      kind: "policy",
      policy: { records: RECORDS, storageAuthority: STORAGE_AUTHORITY, table },
    });
    expect(policy.data).toEqual(
      Uint8Array.of(
        53,
        ...auditor.toBytes(),
        1,
        1,
        ...addressBytes(STORAGE_AUTHORITY),
        2,
        ListId.allow,
        0,
        ListId.block,
        0,
        1,
        ...encodeRule(rule),
      ),
    );
    expect(metas(policy)).toEqual([
      ...head,
      [await ringPolicyAddress(RING), WRITE],
      [RECORDS, READ],
    ]);
    const auditOnly = await initializeRingInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      auditorPublicKey: auditor,
      kind: "auditOnly",
    });
    expect(auditOnly.data).toEqual(Uint8Array.of(53, ...auditor.toBytes(), 0, 0));
    expect(metas(auditOnly)).toEqual(head);
  });

  it("rebinds the records to a registry the trailing account names", async () => {
    const instruction = await updateRingPolicyInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      update: { kind: "records", records: RECORDS, storageAuthority: STORAGE_AUTHORITY },
    });
    expect(instruction.data).toEqual(Uint8Array.of(54, 2, ...addressBytes(STORAGE_AUTHORITY)));
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [await ringPolicyAddress(RING), WRITE],
      [RECORDS, READ],
    ]);
  });
});

describe("ring setup", () => {
  it.each<readonly [RingKind, number]>([
    ["auditOnly", 0],
    ["policy", 1],
    ["anonymous", 2],
    ["anonymousPolicy", 3],
  ])("initializes under the upgrade authority with the %s kind byte", async (kind, byte) => {
    const auditor = X25519Keypair.generate().publicKey();
    const instruction = await initializeRingInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      auditorPublicKey: auditor,
      kind,
    });
    expect(instruction.programAddress).toBe(RING);
    expect(instruction.data).toEqual(Uint8Array.of(53, ...auditor.toBytes(), byte, 0));
  });

  it("refuses a kind the program does not know", async () => {
    await expect(
      initializeRingInstruction({
        ringProgramId: RING,
        payer: PAYER,
        authority: AUTHORITY,
        auditorPublicKey: X25519Keypair.generate().publicKey(),
        kind: "registry" as RingKind,
      }),
    ).rejects.toMatchObject({ code: "RING_CONFIG_INVALID", details: { reason: "kind" } });
  });

  it("refuses a low-order auditor key like Rust `InvalidAuditorPubkey`", async () => {
    await expect(
      initializeRingInstruction({
        ringProgramId: RING,
        payer: PAYER,
        authority: AUTHORITY,
        auditorPublicKey: X25519PublicKey.fromBytes(Uint8Array.of(4, 1, ...new Uint8Array(31))),
        kind: "auditOnly",
      }),
    ).rejects.toMatchObject({
      code: "RING_CONFIG_INVALID",
      details: { reason: "InvalidAuditorPubkey" },
    });
  });

  it("creates the registry and the queue beside a read-only config", async () => {
    const instruction = await createMemberRegistryInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
    });
    expect(instruction.data).toEqual(Uint8Array.of(28));
    expect(metas(instruction)).toEqual([
      [PAYER, SIGN_WRITE],
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [await ringMemberRegistryAddress(RING), WRITE],
      [await ringRecordQueueAddress(RING), WRITE],
      [SYSTEM_PROGRAM, READ],
    ]);
  });
});

describe("config account", () => {
  const MODE_OFFSET = 68;
  const CREATED_SLOT_OFFSET = 112;
  const account = () =>
    ringProgramConfigData({
      authority: AUTHORITY,
      auditorPublicKey: X25519Keypair.fromBytes(new Uint8Array(32).fill(9)).publicKey().toBytes(),
      bump: 254,
      hasPolicy: false,
    });

  it("reads the created slot after the delegate", () => {
    const data = account();
    const slot = 3n * (1n << 18n) + 7n;
    data.set(u64le(slot), CREATED_SLOT_OFFSET);
    expect(data).toHaveLength(120);
    expect(decodeRingProgramConfig(data)).toMatchObject({ createdSlot: slot });
  });

  it("refuses the layout without a created slot and an unknown mode like Rust `InvalidRingMode`", () => {
    const data = account();
    expect(() => decodeRingProgramConfig(data.subarray(0, CREATED_SLOT_OFFSET))).toThrow(
      expect.objectContaining({
        code: "RING_CONFIG_INVALID",
        details: { length: CREATED_SLOT_OFFSET, discriminator: 10 },
      }),
    );
    data[MODE_OFFSET] = 3;
    expect(() => decodeRingProgramConfig(data)).toThrow(
      expect.objectContaining({
        code: "RING_CONFIG_INVALID",
        details: expect.objectContaining({ mode: 3 }),
      }),
    );
  });
});

describe("config writes", () => {
  it("hands the authority over only with both signatures", async () => {
    const instruction = await updateRingAuthorityInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      newAuthority: NEXT,
    });
    expect(instruction.data).toEqual(Uint8Array.of(6));
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
      [NEXT, SIGN],
      [await ringConfigAddress(RING), WRITE],
    ]);
  });

  it("pauses through the pool's ring config", async () => {
    const instruction = await setRingPausedInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      paused: true,
    });
    expect(instruction.data).toEqual(Uint8Array.of(11, 1));
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [await ringAuthAddress(RING), WRITE],
      [SHIELDED_POOL_PROGRAM_ID, READ],
    ]);
  });

  it("writes the co-signer's record, its clearing and the insert fee", async () => {
    const config = await ringConfigAddress(RING);
    const record = await ringCoSignerAddress(RING, NEXT);
    const cosigner = await setRingCoSignerInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      signer: NEXT,
      scope: 5,
    });
    expect(cosigner.data).toEqual(Uint8Array.of(27, ...addressBytes(NEXT), 5));
    expect(metas(cosigner)).toEqual([
      [PAYER, SIGN_WRITE],
      [AUTHORITY, SIGN],
      [config, WRITE],
      [record, WRITE],
      [SYSTEM_PROGRAM, READ],
    ]);
    const clear = await clearRingCoSignerInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      signer: NEXT,
      rentRecipient: PAYER,
    });
    expect(clear.data).toEqual(Uint8Array.of(21));
    expect(metas(clear)).toEqual([
      [AUTHORITY, SIGN],
      [config, WRITE],
      [record, WRITE],
      [PAYER, WRITE],
    ]);
    const fee = await setRingInsertFeeInstruction({
      client: rentClient(890_880n).client,
      ringProgramId: RING,
      authority: AUTHORITY,
      fee: 1_000_000n,
    });
    expect(fee.data).toEqual(Uint8Array.of(42, ...u64le(1_000_000n)));
    expect(metas(fee)).toEqual([
      [AUTHORITY, SIGN],
      [config, WRITE],
    ]);
  });

  it("refuses a nonzero insert fee below the rent of an empty account and reads no rent for a free write", async () => {
    const write = (fee: bigint, rent: ReturnType<typeof rentClient>) =>
      setRingInsertFeeInstruction({
        client: rent.client,
        ringProgramId: RING,
        authority: AUTHORITY,
        fee,
      });
    const floor = rentClient(890_880n);
    await expect(write(890_879n, floor)).rejects.toMatchObject({
      code: "RING_CONFIG_INVALID",
      details: { reason: "InsertFeeBelowRent", fee: "890879", minimum: "890880" },
    });
    expect((await write(890_880n, floor)).data).toEqual(Uint8Array.of(42, ...u64le(890_880n)));
    expect(floor.spaces).toEqual([0n, 0n]);
    const free = rentClient(890_880n);
    expect((await write(0n, free)).data).toEqual(Uint8Array.of(42, ...u64le(0n)));
    expect(free.spaces).toEqual([]);
  });

  it.each([
    ["a zero signer", { signer: address("11111111111111111111111111111111") }, "InvalidCoSigner"],
    ["an empty scope", { scope: 0 }, "InvalidCoSignerScope"],
    ["an unknown scope bit", { scope: 8 }, "InvalidCoSignerScope"],
    [
      "a zero signer under an empty scope, the scope read first like Rust",
      { signer: address("11111111111111111111111111111111"), scope: 0 },
      "InvalidCoSignerScope",
    ],
  ] as const)("refuses a co-signer with %s", async (_case, change, reason) => {
    await expect(
      setRingCoSignerInstruction({
        ringProgramId: RING,
        payer: PAYER,
        authority: AUTHORITY,
        signer: NEXT,
        scope: 1,
        ...change,
      }),
    ).rejects.toMatchObject({ code: "RING_CO_SIGNER_INVALID", details: { reason } });
  });

  it("appoints the delegate under the config authority with the delegate signing", async () => {
    const instruction = await setRingDelegateInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      delegate: NEXT,
    });
    expect(instruction.data).toEqual(Uint8Array.of(24));
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), WRITE],
      [NEXT, SIGN],
      [await ringPolicyAddress(RING), READ],
    ]);
  });

  it("grants and revokes a reader with its tagged key", async () => {
    const reader = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(3) as Bytes32),
    )
      .shieldedAddress()
      .solanaAddress();
    const record = await readAccessRecordAddress(RING, reader);
    const grant = await grantReadAccessInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      reader,
    });
    const revoke = await revokeReadAccessInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      reader,
      rentRecipient: PAYER,
    });
    expect(grant.data).toEqual(Uint8Array.of(4, ...readerKeyBytes(reader)));
    expect(revoke.data).toEqual(Uint8Array.of(5, ...readerKeyBytes(reader)));
    expect(metas(grant)).toEqual([
      [PAYER, SIGN_WRITE],
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [record, WRITE],
      [SYSTEM_PROGRAM, READ],
    ]);
    expect(metas(revoke)).toEqual([
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [record, WRITE],
      [PAYER, WRITE],
    ]);
  });
});

describe("policy writes", () => {
  const tableWrites = [
    (input: RingPolicyTableInput) =>
      initializeRingInstruction({
        ringProgramId: RING,
        payer: PAYER,
        authority: AUTHORITY,
        auditorPublicKey: X25519Keypair.generate().publicKey(),
        kind: "policy",
        policy: { records: RECORDS, storageAuthority: AUTHORITY, ...input },
      }),
    (input: RingPolicyTableInput) =>
      updateRingPolicyInstruction({
        ringProgramId: RING,
        authority: AUTHORITY,
        update: { kind: "rules", ...input },
      }),
  ];

  it("replaces the table with one source per referenced list and the curator registry after", async () => {
    const table = buildRuleTable({ rules: RULES });
    const [rule] = table.rules;
    if (rule === undefined) throw new Error("table without its rule");
    const instruction = await updateRingPolicyInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      update: {
        kind: "rules",
        table,
        sharedSources: [{ listId: ListId.block, curatorRingProgramId: CURATOR }],
      },
    });
    expect(instruction.data).toEqual(
      Uint8Array.of(54, 0, 2, ListId.allow, 0, ListId.block, 1, 1, ...encodeRule(rule)),
    );
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [await ringPolicyAddress(RING), WRITE],
      [await ringMemberRegistryAddress(CURATOR), READ],
    ]);
  });

  it.each([
    [
      "a list the table does not reference",
      [{ listId: ListId.frozen, curatorRingProgramId: CURATOR }],
      "UnreferencedList",
    ],
    [
      "a list shared twice",
      [
        { listId: ListId.block, curatorRingProgramId: CURATOR },
        { listId: ListId.block, curatorRingProgramId: CURATOR },
      ],
      "DuplicateList",
    ],
    [
      "two curators",
      [
        { listId: ListId.allow, curatorRingProgramId: CURATOR },
        { listId: ListId.block, curatorRingProgramId: NEXT },
      ],
      "MultipleCurators",
    ],
    [
      "the ring as its own curator",
      [{ listId: ListId.block, curatorRingProgramId: RING }],
      "OwnCurator",
    ],
  ] as const)("refuses %s", async (_case, sharedSources, reason) => {
    for (const write of tableWrites)
      await expect(
        write({ table: buildRuleTable({ rules: RULES }), sharedSources }),
      ).rejects.toMatchObject({ code: "RING_POLICY_SOURCE_INVALID", details: { reason } });
  });

  it.each([ListId.ringViewing, ListId.recovery, ListId.escrow])(
    "refuses a rule over list %i its members write, like Rust `EncodedRuleTable::validate`",
    async (listId) => {
      const required: Rule = {
        subject: "outputOwner",
        source: { kind: "lists", present: [listId], absent: [] },
        guard: { kind: "always" },
      };
      const alternative: Rule = {
        subject: "sender",
        source: { kind: "lists", present: [ListId.allow], absent: [listId] },
        guard: { kind: "always" },
      };
      for (const rule of [required, alternative])
        for (const write of tableWrites)
          await expect(write({ table: buildRuleTable({ rules: [rule] }) })).rejects.toMatchObject({
            code: "RING_RULE_TABLE_INVALID",
            details: { reason: "MemberWrittenList" },
          });
    },
  );

  it("refuses a hand-built table its builder refuses before the authority signs", async () => {
    for (const write of tableWrites)
      await expect(write({ table: { rules: [...RULES, ...RULES] } })).rejects.toMatchObject({
        code: "RING_RULE_TABLE_INVALID",
        details: { reason: "DuplicateRule" },
      });
  });

  it("re-points one list at a curator or back at the ring", async () => {
    const source = (to: { kind: "own" } | { kind: "curator"; ringProgramId: Address }) =>
      updateRingPolicyInstruction({
        ringProgramId: RING,
        authority: AUTHORITY,
        update: { kind: "source", listId: ListId.block, source: to },
      });
    const curator = await source({ kind: "curator", ringProgramId: CURATOR });
    const own = await source({ kind: "own" });
    const head = [
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [await ringPolicyAddress(RING), WRITE],
    ];
    expect(curator.data).toEqual(Uint8Array.of(54, 1, ListId.block, 1));
    expect(metas(curator)).toEqual([...head, [await ringMemberRegistryAddress(CURATOR), READ]]);
    expect(own.data).toEqual(Uint8Array.of(54, 1, ListId.block, 0));
    expect(metas(own)).toEqual(head);
  });

  it("budgets each instruction like Rust `compute_unit_limit`", () => {
    expect(ringComputeUnitLimit(RingInstructionTag.initialize)).toBe(250_000);
    expect(ringComputeUnitLimit(RingInstructionTag.updatePolicy)).toBe(150_000);
    expect(ringComputeUnitLimit(RingInstructionTag.registerKey)).toBe(1_400_000);
    expect(ringComputeUnitLimit(RingInstructionTag.applyRecords)).toBe(1_400_000);
    expect(ringComputeUnitLimit(RingInstructionTag.deposit)).toBe(1_400_000);
    expect(ringComputeUnitLimit(RingInstructionTag.setInsertFee)).toBe(50_000);
  });
});
