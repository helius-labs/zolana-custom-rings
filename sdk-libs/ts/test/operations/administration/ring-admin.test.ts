import { address, type Address, type Instruction } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import { SYSTEM_PROGRAM, addressBytes, protocolConfigAddress } from "@heliuslabs/zolana/internal";
import { SHIELDED_POOL_PROGRAM_ID } from "@heliuslabs/zolana/interface";
import { X25519Keypair, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  ringAuthAddress,
  ringCoSignerAddress,
  ringPolicyAddress,
} from "../../../src/protocol/pda/index.js";
import {
  RingInstructionTag,
  clearRingCoSignerInstruction,
  initializeRingInstruction,
  ringComputeUnitLimit,
  setRingCoSignerInstruction,
  setRingDelegateInstruction,
  setRingPausedInstruction,
  updateRingAuthorityInstruction,
  updateRingPolicyInstruction,
  type RingKind,
  type RingPolicyTableInput,
} from "../../../src/operations/management/admin.js";
import { RING_ROLES, decodeRingPolicy } from "../../../src/protocol/codec/ring-codecs.js";
import { ringProgramDataAddress } from "../../../src/protocol/membership/config.js";
import {
  ListId,
  buildRuleTable,
  encodeRule,
  type Rule,
} from "../../../src/protocol/membership/policy.js";
import { FIXTURE_ROLES, ringPolicyData } from "../../helpers/ring-accounts.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const CURATOR = address("CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8");
const AUTHORITY = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const NEXT = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const PAYER = address("29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2");
const RECORDS = address("7BgBvyjrZX1YKz4oh9mjb8ZScatkkwb8DzFx7LoiVkM3");

const READ = 0;
const WRITE = 1;
const SIGN = 2;
const SIGN_WRITE = 3;

beforeAll(initializePoseidon);

const ROLES = FIXTURE_ROLES;
const ROLE_BYTES = RING_ROLES.flatMap((role) => [...addressBytes(ROLES[role])]);

function metas(instruction: Instruction): readonly (readonly [Address, number])[] {
  return (instruction.accounts ?? []).map(({ address: account, role }) => [account, role] as const);
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
  it("creates the ring account and the pool registration in one instruction", async () => {
    const auditor = X25519Keypair.generate().publicKey();
    const table = buildRuleTable({ rules: RULES });
    const [rule] = table.rules;
    if (rule === undefined) throw new Error("table without its rule");
    const head = [
      [PAYER, SIGN_WRITE],
      [AUTHORITY, SIGN],
      [await ringPolicyAddress(RING), WRITE],
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
      roles: ROLES,
      policy: { records: RECORDS, table },
    });
    expect(policy.data).toEqual(
      Uint8Array.of(
        53,
        ...auditor.toBytes(),
        1,
        ...ROLE_BYTES,
        1,
        2,
        ListId.allow,
        0,
        ListId.block,
        0,
        1,
        ...encodeRule(rule),
      ),
    );
    expect(metas(policy)).toEqual([...head, [RECORDS, READ]]);
    const auditOnly = await initializeRingInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      auditorPublicKey: auditor,
      kind: "auditOnly",
      roles: ROLES,
    });
    expect(auditOnly.data).toEqual(Uint8Array.of(53, ...auditor.toBytes(), 0, ...ROLE_BYTES, 0));
    expect(metas(auditOnly)).toEqual(head);
  });

  it("rebinds the records to a registry the trailing account names", async () => {
    const instruction = await updateRingPolicyInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      update: { kind: "records", records: RECORDS },
    });
    expect(instruction.data).toEqual(Uint8Array.of(54, 2));
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
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
      roles: ROLES,
    });
    expect(instruction.programAddress).toBe(RING);
    expect(instruction.data).toEqual(
      Uint8Array.of(53, ...auditor.toBytes(), byte, ...ROLE_BYTES, 0),
    );
  });

  it.each([
    ["a zero key", { pauser: address("11111111111111111111111111111111") }, "ZeroRoleKey"],
    ["one key in two roles", { pauser: FIXTURE_ROLES.admin }, "DuplicateRoleKey"],
  ] as const)("refuses %s like Rust `RingRoles::check`", async (_case, change, reason) => {
    await expect(
      initializeRingInstruction({
        ringProgramId: RING,
        payer: PAYER,
        authority: AUTHORITY,
        auditorPublicKey: X25519Keypair.generate().publicKey(),
        kind: "auditOnly",
        roles: { ...ROLES, ...change },
      }),
    ).rejects.toMatchObject({ code: "RING_CONFIG_INVALID", details: { reason } });
  });

  it("refuses a kind the program does not know", async () => {
    await expect(
      initializeRingInstruction({
        ringProgramId: RING,
        payer: PAYER,
        authority: AUTHORITY,
        auditorPublicKey: X25519Keypair.generate().publicKey(),
        kind: "registry" as RingKind,
        roles: ROLES,
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
        roles: ROLES,
      }),
    ).rejects.toMatchObject({
      code: "RING_CONFIG_INVALID",
      details: { reason: "InvalidAuditorPubkey" },
    });
  });
});

describe("ring account", () => {
  const MODE_OFFSET = 2;
  const CREATED_SLOT_OFFSET = 199;
  const account = () => ringPolicyData({ bump: 254 });

  it("reads the roles and the created slot after the auditor key", () => {
    const data = account();
    const slot = 3n * (1n << 18n) + 7n;
    data.set(u64le(slot), CREATED_SLOT_OFFSET);
    expect(data).toHaveLength(4196);
    expect(decodeRingPolicy(data)).toMatchObject({
      createdSlot: slot,
      roles: ROLES,
      hasPolicy: false,
    });
  });

  it("refuses a short layout, a retired discriminator and an unknown mode like Rust `InvalidRingMode`", () => {
    const data = account();
    expect(() => decodeRingPolicy(data.subarray(0, CREATED_SLOT_OFFSET))).toThrow(
      expect.objectContaining({
        code: "RING_POLICY_INVALID",
        details: { length: CREATED_SLOT_OFFSET, discriminator: 15 },
      }),
    );
    for (const retired of [10, 13]) {
      const stale = account();
      stale[0] = retired;
      expect(() => decodeRingPolicy(stale)).toThrow(
        expect.objectContaining({ code: "RING_POLICY_INVALID" }),
      );
    }
    data[MODE_OFFSET] = 3;
    expect(() => decodeRingPolicy(data)).toThrow(
      expect.objectContaining({
        code: "RING_POLICY_INVALID",
        details: expect.objectContaining({ mode: 3 }),
      }),
    );
  });
});

describe("role writes", () => {
  it.each([
    ["admin", 0],
    ["policy", 1],
    ["pauser", 2],
    ["cosignAdmin", 3],
  ] as const)("hands the %s role over only with both signatures", async (role, byte) => {
    const instruction = await updateRingAuthorityInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      role,
      newAuthority: NEXT,
    });
    expect(instruction.data).toEqual(Uint8Array.of(6, byte));
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
      [NEXT, SIGN],
      [await ringPolicyAddress(RING), WRITE],
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
      [await ringPolicyAddress(RING), READ],
      [await ringAuthAddress(RING), WRITE],
      [SHIELDED_POOL_PROGRAM_ID, READ],
    ]);
  });

  it("writes the co-signer's record and its clearing", async () => {
    const ring = await ringPolicyAddress(RING);
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
      [ring, WRITE],
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
      [ring, WRITE],
      [record, WRITE],
      [PAYER, WRITE],
    ]);
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

  it("appoints the delegate under the admin with the delegate signing", async () => {
    const instruction = await setRingDelegateInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      delegate: NEXT,
    });
    expect(instruction.data).toEqual(Uint8Array.of(24));
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
      [await ringPolicyAddress(RING), WRITE],
      [NEXT, SIGN],
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
        roles: ROLES,
        policy: { records: RECORDS, ...input },
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
        sharedSources: [{ listId: ListId.block, curatorRegistry: CURATOR }],
      },
    });
    expect(instruction.data).toEqual(
      Uint8Array.of(54, 0, 2, ListId.allow, 0, ListId.block, 1, 1, ...encodeRule(rule)),
    );
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
      [await ringPolicyAddress(RING), WRITE],
      [CURATOR, READ],
    ]);
  });

  it.each([
    [
      "a list the table does not reference",
      [{ listId: ListId.frozen, curatorRegistry: CURATOR }],
      "UnreferencedList",
    ],
    [
      "a list shared twice",
      [
        { listId: ListId.block, curatorRegistry: CURATOR },
        { listId: ListId.block, curatorRegistry: CURATOR },
      ],
      "DuplicateList",
    ],
    [
      "two curators",
      [
        { listId: ListId.allow, curatorRegistry: CURATOR },
        { listId: ListId.block, curatorRegistry: NEXT },
      ],
      "MultipleCurators",
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
    const source = (to: { kind: "own" } | { kind: "curator"; registry: Address }) =>
      updateRingPolicyInstruction({
        ringProgramId: RING,
        authority: AUTHORITY,
        update: { kind: "source", listId: ListId.block, source: to },
      });
    const curator = await source({ kind: "curator", registry: CURATOR });
    const own = await source({ kind: "own" });
    const head = [
      [AUTHORITY, SIGN],
      [await ringPolicyAddress(RING), WRITE],
    ];
    expect(curator.data).toEqual(Uint8Array.of(54, 1, ListId.block, 1));
    expect(metas(curator)).toEqual([...head, [CURATOR, READ]]);
    expect(own.data).toEqual(Uint8Array.of(54, 1, ListId.block, 0));
    expect(metas(own)).toEqual(head);
  });

  it("budgets each instruction like Rust `compute_unit_limit`", () => {
    expect(ringComputeUnitLimit(RingInstructionTag.initialize)).toBe(250_000);
    expect(ringComputeUnitLimit(RingInstructionTag.updatePolicy)).toBe(150_000);
    expect(ringComputeUnitLimit(RingInstructionTag.deposit)).toBe(1_400_000);
    expect(ringComputeUnitLimit(RingInstructionTag.syncRoots)).toBe(50_000);
  });
});
