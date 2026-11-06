import type { ShieldedPublicKey } from "@heliuslabs/spr/keypair";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import { hexToBytes } from "@noble/hashes/utils.js";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { bytesKey } from "@heliuslabs/spr/internal";
import type { Address } from "@solana/kit";

import {
  demandRequirement,
  operationDemand,
  publicLegClasses,
  resolveRingCoSigners,
} from "../../src/proof/cosign.js";
import {
  defaultInputBits,
  entryRecord,
  inputClassOf,
  inputMapOf,
  isDefaultRingNote,
  ownerRows,
} from "../../src/proof/audit-proof.js";
import { checkHiddenOwnerSpends } from "../../src/operations/payments/anonymous.js";
import { EMPTY_ENTRY_RECORD, InputClass } from "../../src/protocol/codec/audit-stream.js";
import {
  DisclosureFormat,
  type AuditStreamLayout,
} from "../../src/protocol/codec/ring-disclosure-layout.js";
import { checkInputKeys, checkOutputKeys } from "../../src/proof/policy-proof.js";
import { enrolledSalt } from "../../src/proof/policy-proof.js";
import { anonymousPartyIdentities } from "../../src/protocol/membership/parties.js";
import { ANONYMOUS_PARTIES } from "../../src/protocol/transaction/transact.js";
import { ringCoSignerAccount } from "../helpers/ring-accounts.js";
import { listTagOf } from "../../src/crypto/keys/list-salt.js";
import { selectTransferKey } from "../../src/proof/transfer-proof.js";
import {
  RING_COSIGN_APPROVE_OUTFLOW,
  RING_COSIGN_APPROVE_WITHDRAWAL,
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_TRANSFERS,
} from "../../src/protocol/codec/ring-codecs.js";
import { RingError } from "../../src/protocol/error.js";
import {
  RING_KEYS,
  ringAuthorityExitKeyName,
  ringProvingKey,
} from "../../src/protocol/proof/proving-keys.js";
import { ownerSignerCapacity } from "../../src/protocol/proof/transfer-shapes.js";
import { ApprovalMask } from "../../src/protocol/transaction/transact.js";
import { RING_SOURCE_SLOTS } from "../../src/rpc/prover/types.js";
import { canopyLevels, QUAD_ARITY } from "../../src/protocol/membership/member-registry.js";
import { TRACKING_QUAD_HEIGHT } from "../../src/protocol/membership/tracking.js";
import { unopenedRecordPool } from "../../src/protocol/membership/member-opening.js";
import { transferPoolCapacity } from "../../src/protocol/proof/transfer-shapes.js";
import { ringStreamLayout } from "../../src/protocol/transaction/transact.js";
import { ZERO_NULLIFIER_PK } from "@heliuslabs/spr/internal";
import type { ProofInputUtxo, ProofOutputUtxo } from "@heliuslabs/spr/transaction";
import type { TrackingRecord } from "../../src/protocol/membership/tracking.js";
import {
  ringProofRequestBody,
  type TransferProofRequest,
  type MergeProofRequest,
} from "../../src/rpc/prover/ring.js";

await initializePoseidon();

const field = (text: string): Bytes32 => hexToBytes(text.replace(/^0x/, "")) as Bytes32;
const vector = (path: string): unknown =>
  JSON.parse(readFileSync(new URL(`../../../../test-vectors/${path}`, import.meta.url), "utf8"));
const refusal = (action: () => unknown): RingError => {
  try {
    action();
  } catch (error) {
    if (error instanceof RingError) return error;
    throw error;
  }
  throw new Error("expected a RingError");
};

const SPEND = {
  rail: "confidential",
  inputs: 2,
  outputs: 2,
  spendsDefaultRing: false,
  legs: 0,
  owners: 2,
  pools: { own: 0, curator: 0, tracking: 0 },
  wide: false,
} as const;
const ADDRESSES = { nInputs: 2, coSigners: 0, legs: 0 };

describe("selectTransferKey", () => {
  it("takes the narrowest rows and the wide key past them", () => {
    const small = selectTransferKey({ spend: SPEND, addresses: ADDRESSES, ownerSigners: 2 });
    expect(small.circuit.owners).toBe(4);
    expect(small.wideOwners).toBe(false);
    const wide = selectTransferKey({
      spend: { ...SPEND, inputs: 5, owners: 5 },
      addresses: { ...ADDRESSES, nInputs: 5 },
      ownerSigners: 5,
    });
    expect(wide.circuit.owners).toBe(13);
    expect(wide.wideOwners).toBe(true);
  });

  it("routes by the published inputs, only past 24 reaches the 40 input key", () => {
    const select = (inputs: number, legs = 0, owners = 2) =>
      selectTransferKey({
        spend: { ...SPEND, inputs, legs, owners },
        addresses: { ...ADDRESSES, nInputs: inputs },
        ownerSigners: 0,
      });
    const narrow = select(24);
    expect([narrow.circuit.class, narrow.wideOwners]).toEqual([24, false]);
    expect(select(24, 0, 5).circuit).toMatchObject({ class: 24, outputs: 8, wide: true });
    const widest = select(25);
    expect(widest.circuit).toMatchObject({
      class: 40,
      outputs: 2,
      withdrawals: 4,
      owners: 8,
      wide: true,
    });
    expect(widest.wideOwners).toBe(true);
    expect(transferPoolCapacity(widest.circuit)).toEqual({ own: 67, curator: 67, tracking: 11 });
    expect(select(40, 4, 8).circuit).toEqual(widest.circuit);
    expect(refusal(() => select(25, 5)).code).toBe("RING_CATALOG_KEY_MISSING");
    expect(refusal(() => select(25, 0, 9)).code).toBe("RING_TOO_MANY_OWNERS");
    expect(refusal(() => select(41)).code).toBe("RING_CATALOG_KEY_MISSING");
  });

  it("fits an entry past the small keys on the wide entry key", () => {
    const entered = (inputs: number, outputs: number, legs: number, owners: number) =>
      selectTransferKey({
        spend: {
          ...SPEND,
          rail: "anonymous",
          spendsDefaultRing: true,
          inputs,
          outputs,
          legs,
          owners,
        },
        addresses: { ...ADDRESSES, nInputs: inputs },
        ownerSigners: 0,
      }).circuit;
    expect(entered(8, 2, 4, 8)).toMatchObject({ class: 8, outputs: 4, entry: true });
    expect(entered(2, 8, 4, 2)).toMatchObject({ class: 2, outputs: 8, entry: true });
    expect(entered(5, 8, 4, 4)).toMatchObject({ class: 5, outputs: 8, entry: true });
    const wide = entered(6, 8, 0, 1);
    expect(wide).toMatchObject({ class: 8, outputs: 8, withdrawals: 32, owners: 8, entry: true });
    expect(transferPoolCapacity(wide)).toEqual({ own: 91, curator: 91, tracking: 38 });
    expect(entered(1, 2, 5, 1)).toEqual(wide);
    expect(entered(8, 4, 32, 8)).toEqual(wide);
    expect(refusal(() => entered(9, 2, 0, 1)).code).toBe("RING_CATALOG_KEY_MISSING");
    expect(refusal(() => entered(1, 2, 33, 1)).code).toBe("RING_CATALOG_KEY_MISSING");
  });

  it("seals a tail past the capacity of the key the spend selects", () => {
    const layout = (wideOwners: boolean) =>
      ringStreamLayout({
        rail: "confidential",
        nIn: 2,
        nOut: 2,
        inputs: 2,
        outputs: 2,
        entry: false,
        hasData: true,
        wideOwners,
      });
    expect(layout(false).capacity).toBe(2);
    expect(layout(true).capacity).toBe(8);
  });

  it("refuses past the account bound with the counts", () => {
    const addresses = { nInputs: 24, coSigners: 5, legs: 2 };
    const capacity = ownerSignerCapacity(addresses);
    expect(capacity).toBe(64 - 4 - 6 - 24 - 10 - 2);
    selectTransferKey({ spend: SPEND, addresses, ownerSigners: capacity });
    const refused = refusal(() =>
      selectTransferKey({ spend: SPEND, addresses, ownerSigners: capacity + 1 }),
    );
    expect(refused.code).toBe("RING_TRANSFER_PAST_ACCOUNT_BOUND");
    expect(refused.details).toMatchObject({ ownerSigners: capacity + 1, capacity, coSigners: 5 });
  });

  it("names rows past the widest and an unkeyed shape", () => {
    expect(
      refusal(() =>
        selectTransferKey({
          spend: { ...SPEND, owners: 25 },
          addresses: ADDRESSES,
          ownerSigners: 0,
        }),
      ).code,
    ).toBe("RING_TOO_MANY_OWNERS");
    expect(
      refusal(() =>
        selectTransferKey({
          spend: { ...SPEND, outputs: 17 },
          addresses: ADDRESSES,
          ownerSigners: 0,
        }),
      ).code,
    ).toBe("RING_CATALOG_KEY_MISSING");
  });
});

describe("enrolledSalt", () => {
  const owner = new Uint8Array(32).fill(1) as Bytes32;
  const salt = new Uint8Array(32).fill(2) as Bytes32;
  const salts = new Map([[bytesKey(owner), salt]]);

  it("takes no salt with no row and the row's salt under its tag", () => {
    expect(enrolledSalt(owner, undefined, new Map())).toBeUndefined();
    expect(enrolledSalt(owner, { ...row0(), listTag: listTagOf(salt) }, salts)).toEqual(salt);
  });

  it("refuses a row with no salt and a salt off the row's tag", () => {
    expect(refusal(() => enrolledSalt(owner, row0(), new Map())).code).toBe(
      "RING_LIST_SALT_MISSING",
    );
    expect(refusal(() => enrolledSalt(owner, row0(), salts)).code).toBe("RING_ADDRESS_MISMATCH");
  });
});

describe("the key table", () => {
  it("serves one merge key under its pinned name", () => {
    expect(
      RING_KEYS.filter((key) => key.circuit.family === "merge").map((key) => key.name),
    ).toEqual(["custom-ring-merge"]);
    expect(ringProvingKey({ family: "merge" }).name).toBe("custom_ring_merge.key");
  });

  it("keys the authority exit at two shapes", () => {
    expect(ringAuthorityExitKeyName({ nInputs: 4, nOutputs: 4 })).toBe(
      "transfer_ring_authority_exit_4_4.key",
    );
    expect(refusal(() => ringAuthorityExitKeyName({ nInputs: 2, nOutputs: 4 })).code).toBe(
      "RING_PROVING_KEYS_MISSING",
    );
  });
});

describe("co-sign", () => {
  const demand = (spendsNote: boolean, approval: number, isDeposit?: boolean) =>
    operationDemand({
      spendsNote,
      publicLegs: publicLegClasses(isDeposit === undefined ? [] : [{ isDeposit }]),
      approval,
    });
  const ONE: Address = "11111111111111111111111111111111" as Address;

  it("demands nothing of a ring with no record below its thresholds", () => {
    expect(demandRequirement(demand(true, 0, false), {})).toBeUndefined();
  });

  it("drops transfers under no_spend and adds deposits for a deposit leg", () => {
    const ring = { coSignerClasses: RING_COSIGN_TRANSFERS | RING_COSIGN_DEPOSITS };
    expect(demandRequirement(demand(false, 0, true), ring)?.uncovered).toBe(RING_COSIGN_DEPOSITS);
    expect(demandRequirement(demand(true, 0), ring)?.uncovered).toBe(RING_COSIGN_TRANSFERS);
  });

  it("resolves one approver per class in either order, a missing approver refused", async () => {
    const outflow = "11111111111111111111111111111112" as Address;
    const withdrawal = "11111111111111111111111111111113" as Address;
    const records = new Map<Address, Readonly<{ scope: number; signer: Address }>>([
      [outflow, { scope: RING_COSIGN_APPROVE_OUTFLOW, signer: outflow }],
      [withdrawal, { scope: RING_COSIGN_APPROVE_WITHDRAWAL, signer: withdrawal }],
    ]);
    const accounts = new Map(
      await Promise.all([...records.values()].map((record) => ringCoSignerAccount(ONE, record))),
    );
    const base = {
      client: { getAccount: async (account: Address) => accounts.get(account) },
      ringProgramId: ONE,
      config: {},
      demand: demand(false, ApprovalMask.outflow | ApprovalMask.withdrawal),
      ownerSigners: [],
    };
    const signers = async (supplied: readonly Address[]) =>
      (await resolveRingCoSigners({ ...base, supplied })).map(({ signer }) => signer);
    expect(await signers([outflow, withdrawal])).toEqual([outflow, withdrawal]);
    expect(await signers([withdrawal, outflow])).toEqual([withdrawal, outflow]);
    await expect(signers([outflow])).rejects.toMatchObject({
      code: "RING_COSIGNER_REQUIRED",
      details: { reason: "missing", uncovered: RING_COSIGN_APPROVE_WITHDRAWAL },
    });
    await expect(signers([outflow, outflow])).rejects.toMatchObject({
      code: "RING_COSIGNER_OUT_OF_SCOPE",
    });
  });

  it("binds each co-signer in its party slot, the destination last", () => {
    const parties = anonymousPartyIdentities({
      payer: ONE,
      coSigners: [ONE, ONE],
      exitDestination: ONE,
    });
    expect(parties).toHaveLength(ANONYMOUS_PARTIES);
    expect(parties[3]?.every((byte) => byte === 0)).toBe(true);
    expect(parties.at(-1)?.every((byte) => byte === 0)).toBe(false);
  });

  it("refuses an owner signer as co-signer and a missing approver signature", async () => {
    const client = { getAccount: async () => undefined };
    const base = {
      client,
      ringProgramId: ONE,
      config: { coSignerClasses: RING_COSIGN_TRANSFERS },
      demand: demand(true, 0),
    };
    await expect(
      resolveRingCoSigners({ ...base, supplied: [ONE], ownerSigners: [ONE] }),
    ).rejects.toMatchObject({ code: "RING_COSIGNER_REQUIRED" });
    await expect(
      resolveRingCoSigners({ ...base, supplied: [], ownerSigners: [] }),
    ).rejects.toMatchObject({
      code: "RING_COSIGNER_REQUIRED",
    });
  });
});

describe("merge.json", () => {
  type Request = Readonly<Record<string, unknown>> &
    Readonly<{
      tracking: Readonly<{
        present: boolean;
        record: Readonly<Record<string, string>>;
        path: Readonly<{ index: number; siblings: readonly (readonly string[])[] }>;
      }> | null;
    }>;
  const { cases } = vector("merge/merge.json") as Readonly<{
    cases: readonly Readonly<{ name: string; request: Request }>[];
  }>;

  it.each(cases.map((entry) => [entry.name, entry] as const))("round trips %s", (_, entry) => {
    const { request } = entry;
    const text = (key: string): Bytes32 => field(request[key] as string);
    const opening = (): MergeProofRequest["tracking"] => {
      const { tracking } = request;
      if (tracking === null) return undefined;
      const { record: row, path } = tracking;
      const record = {
        member: field(row["member"] ?? ""),
        next: field(row["next"] ?? ""),
        nullifierPk: field(row["nullifierPk"] ?? ""),
        ctHash: field(row["ctHash"] ?? ""),
        listTag: field(row["listTag"] ?? ""),
      };
      const quad = { index: path.index, siblings: path.siblings.map((level) => level.map(field)) };
      return tracking.present
        ? { kind: "present", record, path: quad }
        : { kind: "absent", low: record, path: quad };
    };
    const tracking = opening();
    expect(
      ringProofRequestBody({
        kind: "merge",
        publicInputHash: text("publicInputHash"),
        outputUtxoHash: text("outputUtxoHash"),
        firstNullifier: text("firstNullifier"),
        ringProgramId: text("ringProgramId"),
        auditorPk: text("auditorPk"),
        payer: text("payer"),
        trackingRoot: text("trackingRoot"),
        ephSk: text("ephSk"),
        ownerKey: text("ownerKey"),
        ownerPkHash: text("ownerPkHash"),
        mintChunks: (request["mintChunks"] as readonly string[]).map(field),
        asset: text("asset"),
        amount: text("amount"),
        nullifierPk: text("nullifierPk"),
        seed: text("seed"),
        outputTreeId: text("outputTreeId"),
        outputRingDataHash: text("outputRingDataHash"),
        ...(tracking === undefined ? {} : { tracking }),
      }),
    ).toEqual(request);
  });
});

const fill = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;
const note = (
  input: Readonly<{
    owner?: Bytes32;
    key?: Bytes32;
    ring?: Address;
    dummy?: boolean;
    address?: boolean;
  }>,
): ProofInputUtxo =>
  ({
    isCompact: () => false,
    isDummy: () => input.dummy === true,
    isAddress: () => input.address === true,
    hash: () => fill(0x0c),
    nullifierPublicKey: input.key ?? fill(9),
    utxo: {
      owner: {
        ownerProofInputHash: () => input.owner ?? fill(1),
        confidentialViewTag: () => fill(7),
      },
      ringProgramId: input.ring,
      asset: RING,
      amount: 5n,
      blinding: fill(8),
    },
  }) as unknown as ProofInputUtxo;
const RING = "11111111111111111111111111111111" as Address;

describe("input evidence", () => {
  const layout = (inputs: number): AuditStreamLayout => ({
    key: { class: 4, entry: true },
    inputs,
    outputs: 1,
    capacity: 2,
    hasData: false,
  });
  const address = note({ address: true });

  it("counts notes alone with addresses interleaved before the dummy suffix", () => {
    const inputs = [note({ ring: RING }), address, note({}), note({ dummy: true })];
    expect(inputs.map(inputClassOf)).toEqual([
      InputClass.note,
      InputClass.address,
      InputClass.note,
      InputClass.dummy,
    ]);
    const map = inputMapOf(inputs, layout(4));
    expect([map.noteCount, map.addressInputBits, map.nonDummyCount]).toEqual([2, 2n, 3]);
    const addresses = inputMapOf([address, address], layout(2));
    expect([addresses.noteCount, addresses.addressInputBits]).toEqual([0, 3n]);
  });

  it("refuses a note or an address past a dummy and a count off the layout", () => {
    for (const inputs of [
      [note({ dummy: true }), note({ ring: RING })],
      [note({ ring: RING }), note({ dummy: true }), address],
    ])
      expect(refusal(() => inputMapOf(inputs, layout(inputs.length))).details).toMatchObject({
        reason: "RingTransactLength",
      });
    expect(refusal(() => inputMapOf([note({})], layout(2))).details).toMatchObject({
      reason: "RingTransactLength",
    });
  });

  it("sets a default bit and an entry on a default-ring note alone, never on an address", () => {
    const inputs = [note({ ring: RING }), note({}), address, note({ dummy: true })];
    expect(defaultInputBits(inputs)).toBe(2n);
    expect(inputs.map(isDefaultRingNote)).toEqual([false, true, false, false]);
    expect(entryRecord(inputs[0] as ProofInputUtxo)).toBe(EMPTY_ENTRY_RECORD);
    expect(entryRecord(inputs[1] as ProofInputUtxo)).toEqual({
      ownerKey: fill(7),
      nullifierPk: fill(9),
      amount: 5n,
      mint: RING,
      inputCommitment: fill(0x0c),
    });
    expect(entryRecord(address)).toBe(EMPTY_ENTRY_RECORD);
    expect(inputMapOf(inputs, layout(4)).validateDefaultInputBits(defaultInputBits(inputs))).toBe(
      undefined,
    );
  });

  it("refuses a hidden owner whose input 0 is an address", () => {
    const owner = fill(1);
    const proofInputs = (inputUtxos: readonly ProofInputUtxo[]) =>
      ({ inputUtxos }) as unknown as Parameters<typeof checkHiddenOwnerSpends>[0];
    const held = (input: ProofInputUtxo): ProofInputUtxo =>
      ({
        ...input,
        isCompact: input.isCompact,
        isDummy: input.isDummy,
        isAddress: input.isAddress,
        utxo: { ...input.utxo, owner: { equals: (key: unknown) => key === owner } },
      }) as unknown as ProofInputUtxo;
    const sender = { signingPublicKey: owner } as unknown as Parameters<
      typeof checkHiddenOwnerSpends
    >[1];
    expect(() =>
      checkHiddenOwnerSpends(proofInputs([held(note({})), held(address)]), sender),
    ).not.toThrow();
    expect(
      refusal(() => checkHiddenOwnerSpends(proofInputs([held(address), held(note({}))]), sender))
        .code,
    ).toBe("RING_NO_HIDDEN_OWNER");
  });

  it("orders rows as field integers, zero rows last, a delegate's zero key taking none", () => {
    const [low, high] = [fill(1), fill(2)];
    const inputs = [
      note({ owner: high, ring: RING }),
      note({ owner: fill(3), address: true }),
      note({ owner: low, ring: RING }),
      note({ owner: high, ring: RING }),
      note({ dummy: true }),
    ];
    expect(ownerRows({ inputs, delegate: false, slots: 4 })).toEqual([
      low,
      high,
      new Uint8Array(32),
      new Uint8Array(32),
    ]);
    const zeroKey = [note({ owner: low, ring: RING, key: ZERO_NULLIFIER_PK as Bytes32 })];
    expect(ownerRows({ inputs: zeroKey, delegate: true })).toEqual([]);
    expect(ownerRows({ inputs: zeroKey, delegate: false })).toEqual([low]);
    expect(refusal(() => ownerRows({ inputs, delegate: false, slots: 1 })).code).toBe(
      "RING_TOO_MANY_OWNERS",
    );
  });
});

describe("tracking predicates", () => {
  const row = (nullifierPk: Bytes32): TrackingRecord => ({
    member: fill(1),
    next: fill(2),
    nullifierPk,
    ctHash: fill(3),
    listTag: fill(5),
  });
  const zero = ZERO_NULLIFIER_PK as Bytes32;
  const check = (input: ProofInputUtxo, rowOf: TrackingRecord | undefined, rail = "confidential") =>
    checkInputKeys({
      inputs: [input],
      rail: rail as "confidential",
      publicOwners: false,
      rowOf: () => rowOf,
    });

  it("holds a nonzero input key to its row and waives only the equality on a zero key", () => {
    check(note({ ring: RING, key: fill(9) }), row(fill(9)));
    check(note({ ring: RING, key: zero }), undefined);
    check(note({ key: fill(6) }), undefined);
    expect(refusal(() => check(note({ ring: RING, key: fill(9) }), undefined)).code).toBe(
      "RING_ADDRESS_NOT_ENROLLED",
    );
    expect(refusal(() => check(note({ ring: RING, key: fill(9) }), row(fill(6)))).code).toBe(
      "RING_ADDRESS_MISMATCH",
    );
  });

  it("refuses a hidden owner's zero key", () => {
    expect(refusal(() => check(note({ ring: RING, key: zero }), undefined, "anonymous")).code).toBe(
      "RING_ZERO_KEY_INPUT_UNNAMED",
    );
  });

  it("holds an output to the rule of its key", () => {
    const output = (key: Bytes32, viewingU = fill(4)): ProofOutputUtxo =>
      ({
        ownerAddress: {
          nullifierPublicKey: key,
          signingPublicKey: { ownerProofInputHash: () => fill(1) },
          viewingPublicKey: { u: () => viewingU },
        },
      }) as unknown as ProofOutputUtxo;
    const checked = (
      outputs: readonly (ProofOutputUtxo | undefined)[],
      served: TrackingRecord | undefined,
    ) =>
      checkOutputKeys({
        outputs,
        rowOf: () => served,
        viewingKeyOf: () => fill(4),
        spenders: [],
      });
    checked([output(fill(9)), undefined], row(fill(9)));
    checked([output(zero)], undefined);
    expect(refusal(() => checked([output(zero)], row(fill(9)))).code).toBe(
      "RING_RECIPIENT_ENROLLED",
    );
    expect(refusal(() => checked([output(fill(9))], undefined)).code).toBe(
      "RING_RECIPIENT_NOT_ENROLLED",
    );
  });

  it("refuses a recipient address sealing to a viewing key its authorization retired", () => {
    const spender = {} as ShieldedPublicKey;
    const output = {
      ownerAddress: {
        nullifierPublicKey: fill(9),
        signingPublicKey: {
          ownerProofInputHash: () => fill(1),
          equals: (other: unknown) => other === spender,
        },
        viewingPublicKey: { u: () => fill(8) },
      },
    } as unknown as ProofOutputUtxo;
    const stale = refusal(() =>
      checkOutputKeys({
        outputs: [output],
        rowOf: () => row(fill(9)),
        viewingKeyOf: () => fill(4),
        spenders: [],
      }),
    );
    expect(stale.code).toBe("RING_RECIPIENT_VIEWING_KEY_STALE");
    checkOutputKeys({
      outputs: [output],
      rowOf: () => row(fill(9)),
      viewingKeyOf: () => undefined,
      spenders: [spender],
    });
  });
});

describe("prover/ring/params.go", () => {
  const source = readFileSync(
    new URL("../../../../prover/ring/params.go", import.meta.url),
    "utf8",
  );
  /** Every JSON name a struct and its embedded structs declare. */
  const tags = (name: string): Readonly<{ required: string[]; optional: string[] }> => {
    const body = new RegExp(`type ${name} struct \\{\\n([\\s\\S]*?)\\n\\}`).exec(source)?.[1];
    if (body === undefined) throw new Error(name);
    const out = { required: [] as string[], optional: [] as string[] };
    for (const line of body.split("\n")) {
      const embedded = /^\s*([A-Z]\w*)\s*$/.exec(line)?.[1];
      if (embedded !== undefined) {
        const inner = tags(embedded);
        out.required.push(...inner.required);
        out.optional.push(...inner.optional);
        continue;
      }
      const tag = /json:"(\w+)(,omitempty)?"/.exec(line);
      if (tag?.[1] !== undefined) (tag[2] === undefined ? out.required : out.optional).push(tag[1]);
    }
    return out;
  };

  it("takes every required key and adds only the wire the circuit's Table reads", () => {
    const circuit = {
      family: "transfer",
      format: DisclosureFormat.Standard,
      outputs: 2,
      class: 24,
      withdrawals: 4,
      owners: 4,
      entry: false,
      wide: false,
    } as const;
    const capacity = transferPoolCapacity(circuit);
    const zero = fill(0);
    const opening = Object.fromEntries(
      [
        "domain",
        "treeId",
        "ownerPkHash",
        "nullifierPk",
        "asset",
        "amount",
        "blinding",
        "dataHash",
        "ringDataHash",
        "ringProgramId",
      ].map((key) => [key, zero]),
    ) as unknown as TransferProofRequest["inputs"][number];
    const repeat = <T>(length: number, value: T): readonly T[] => Array<T>(length).fill(value);
    const entry = { own: 0, curator: 0 };
    const ownerEntry = { ...entry, tracking: 0, listSalt: zero, ownSalted: 0, curatorSalted: 0 };
    const pool = unopenedRecordPool(capacity.tracking);
    const request: TransferProofRequest = {
      kind: "transfer",
      publicInputHash: zero,
      firstNullifier: zero,
      txViewingSk: zero,
      auditorPk: zero,
      salt: new Uint8Array(16) as TransferProofRequest["salt"],
      layout: { hasData: false, entry: false },
      approvalMask: 0,
      outputCount: 2,
      outputs: repeat(2, { output: opening, ownerKey: zero, mintChunks: [zero, zero] }),
      inputCount: 1,
      inputNullifierChain: zero,
      inputNullifiers: repeat(24, zero),
      inputs: repeat(24, opening),
      entries: [],
      signerCount: 0,
      signers: repeat(24, zero),
      rows: repeat(4, zero),
      privateTxHash: zero,
      trackingRoot: zero,
      trackingPool: {
        records: repeat(capacity.tracking, row0()),
        canopy: repeat(QUAD_ARITY ** canopyLevels(capacity.tracking), zero),
        paths: repeat(capacity.tracking, {
          index: 0,
          siblings: repeat(
            TRACKING_QUAD_HEIGHT - canopyLevels(capacity.tracking),
            repeat(QUAD_ARITY - 1, zero),
          ),
        }),
        subjects: pool.subjects,
      },
      rowEntries: repeat(4, 0),
      outputEntries: repeat(2, 0),
      withdrawalCount: 0,
      withdrawalHash: zero,
      withdrawals: repeat(4, { owner: zero, asset: zero, amount: 0n }),
      policyHash: zero,
      ringId: zero,
      ownRoot: zero,
      curatorRoot: zero,
      publicAssets: repeat(3, zero),
      publicAmounts: repeat(3, zero),
      publicGross: repeat(3, zero),
      sources: repeat(RING_SOURCE_SLOTS, { listId: 0, registry: zero }),
      salted: 0,
      policyLen: 0,
      rules: repeat(16, zero),
      ownPool: unopenedRecordPool(capacity.own),
      curatorPool: unopenedRecordPool(capacity.curator),
      senderEntries: repeat(4, ownerEntry),
      ownerEntries: repeat(6, ownerEntry),
      assetEntries: repeat(6 + circuit.class, entry),
      publicAssetEntries: repeat(3, 0),
      inProof: false,
      hidden: false,
      delegate: false,
      sender: zero,
      partyIdentities: repeat(7, zero),
    };
    const keys = Object.keys(ringProofRequestBody(request));
    const go = tags("TransferParams");
    expect(go.required.filter((key) => !keys.includes(key))).toEqual([]);
    expect(keys.filter((key) => !go.required.includes(key) && !go.optional.includes(key))).toEqual(
      [],
    );
  });
});

function row0(): TrackingRecord {
  const zero = new Uint8Array(32) as Bytes32;
  return {
    member: zero,
    next: zero,
    nullifierPk: zero,
    ctHash: zero,
    listTag: zero,
  };
}
