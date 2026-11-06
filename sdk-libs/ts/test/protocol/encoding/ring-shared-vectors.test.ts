import { DisclosureFormat } from "../../../src/protocol/codec/ring-disclosure-layout.js";
import { EMPTY_MINT_POLICY } from "../../../src/protocol/membership/mint-policy.js";
import {
  TRACKING_EMPTY_ROOT,
  trackingEntryChained,
  trackingEntryHash,
} from "../../../src/protocol/membership/tracking.js";
import { describe, expect, it } from "vitest";

import records from "../../../../../test-vectors/registry/ring-records.json" with { type: "json" };
import statements from "../../../../../test-vectors/proof/ring-statements.json" with { type: "json" };
import poolCapacity from "../../../../../test-vectors/policy/pool_capacity.json" with { type: "json" };
import { ZERO_32, encodeBase58 } from "@heliuslabs/spr/internal";
import type { Bytes16, Bytes64, Bytes32, Bytes33 } from "@heliuslabs/spr/interface";
import { packDisclosure, unpackDisclosure } from "../../../src/crypto/audit/audit.js";
import {
  fittedSpend,
  ringTransferCircuit,
  transferCircuitType,
  transferKeys,
  transferPoolCapacity,
} from "../../../src/protocol/proof/transfer-shapes.js";
import {
  APPLY_BATCH,
  QUAD_HEIGHT,
  type MemberRecord,
  type QuadPath,
  type RecordWrite,
  type RecordWriteProofInput,
} from "../../../src/protocol/membership/member-registry.js";
import {
  applyRecordsStatement,
  writeChain,
  recordWriteHash,
  replayRecordWrites,
  verifyRecordOpening,
} from "../../../src/protocol/membership/member-opening.js";
import {
  applyRecordsStatementElements,
  applyRecordsStatementHash,
  registerKeyStatementElements,
  registerKeyStatementHash,
  applyEnrollmentsStatementElements,
  applyEnrollmentsStatementHash,
  ciphertextDigest,
  recordChain,
  tailChain,
  transferStatementElements,
  transferStatementHash,
  type TransferFamily,
  type TransferStatement,
} from "../../../src/protocol/proof/statement.js";
import { RingInstructionTag } from "../../../src/operations/management/admin.js";
import { ringRail, ringRailOf } from "../../../src/protocol/transaction/transact.js";

function bytes<T extends Uint8Array>(value: string, length?: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (length !== undefined && decoded.length !== length)
    throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function hexes(values: readonly Uint8Array[]): string[] {
  return values.map(hex);
}

function field(value: string): Bytes32 {
  return bytes<Bytes32>(value, 32);
}

/** The last byte flipped, still below the modulus for every vector field. */
function flipped(value: Uint8Array): Bytes32 {
  const copy = Uint8Array.from(value);
  copy[31] = (copy[31] ?? 0) ^ 1;
  return field(hex(copy));
}

function ringError(reason: string): unknown {
  return expect.objectContaining({ code: "RING_TRANSACT_DATA_INVALID", details: { reason } });
}

describe("ring-records.json", () => {
  type VectorPath = (typeof records.openings)[number]["path"];
  type VectorRecord = (typeof records.openings)[number]["record"];
  const path = (vector: VectorPath): QuadPath => ({
    index: vector.index,
    siblings: vector.siblings.map((level) => level.map(field)),
  });
  const record = (vector: VectorRecord): MemberRecord => ({
    mintPolicy: EMPTY_MINT_POLICY,
    member: field(vector.member),
    next: field(vector.next),
    lists: BigInt(vector.lists),
  });
  const entry = (write: (typeof records.updates)[number]["writes"][number]): RecordWrite => ({
    member: field(write.member),
    mask: BigInt(write.mask),
    value: BigInt(write.value),
  });

  it("hashes every write of an update and chains it from the update's chain start", () => {
    for (const update of records.updates) {
      let chain = field(update.chain_start);
      for (const write of update.writes) {
        expect(hex(recordWriteHash(entry(write)))).toBe(write.entry_hash);
        chain = writeChain(chain, entry(write));
        expect(hex(chain)).toBe(write.chain);
      }
      expect(hex(chain)).toBe(update.chain_end);
    }
  });

  it("replays every update to the root, next index and statement the apply proof binds", () => {
    for (const update of records.updates) {
      const writes: RecordWriteProofInput[] = update.proof_inputs.map((write) => ({
        oldMintPolicy: EMPTY_MINT_POLICY,
        entry: {
          member: field(write.member),
          mask: BigInt(write.mask),
          value: BigInt(write.value),
        },
        exists: write.exists,
        oldNext: field(write.old_next),
        oldLists: BigInt(write.old_lists),
        slot: path(write.slot),
        low: record(write.low),
        lowPath: path(write.low_path),
      }));
      expect(writes.length).toBeLessThanOrEqual(APPLY_BATCH);
      const inputs = replayRecordWrites({
        oldRoot: field(update.old_root),
        oldNextIndex: update.old_next_index,
        chainStart: field(update.chain_start),
        writes,
      });
      expect(hex(inputs.newRoot)).toBe(update.new_root);
      expect(inputs.newNextIndex).toBe(update.new_next_index);
      expect(hex(inputs.chainEnd)).toBe(update.chain_end);
      const statement = applyRecordsStatement(inputs);
      expect(statement.count).toBe(BigInt(update.count));
      expect(hex(applyRecordsStatementHash(statement))).toBe(update.statement_hash);
    }
  });

  it("verifies a present member and an absent member's low record under the root", () => {
    for (const opening of records.openings) {
      const member = field(opening.member);
      const opened = verifyRecordOpening(
        opening.present
          ? { kind: "present", record: record(opening.record), path: path(opening.path) }
          : { kind: "absent", low: record(opening.record), path: path(opening.path) },
        field(opening.root),
        member,
      );
      expect(opened === undefined).toBe(!opening.present);
      expect(path(opening.path).siblings).toHaveLength(QUAD_HEIGHT);
    }
  });

  it("refuses an opening whose path folds to another root", () => {
    const opening = records.openings[0];
    if (opening === undefined) throw new Error("vector has no opening");
    const honest = path(opening.path);
    const siblings = honest.siblings.map((entries, level) =>
      entries.map((sibling, at) => (level === 3 && at === 1 ? flipped(sibling) : sibling)),
    );
    expect(() =>
      verifyRecordOpening(
        { kind: "present", record: record(opening.record), path: { ...honest, siblings } },
        field(opening.root),
        field(opening.member),
      ),
    ).toThrow(
      expect.objectContaining({
        code: "RING_MEMBER_REGISTRY_INVALID",
        details: { reason: "RootMismatch" },
      }),
    );
  });

  it("refuses a write whose value leaves its mask before the first write", () => {
    const update = records.updates[0];
    const write = update?.proof_inputs[0];
    if (update === undefined || write === undefined) throw new Error("vector has no write");
    expect(() =>
      replayRecordWrites({
        oldRoot: field(update.old_root),
        oldNextIndex: update.old_next_index,
        chainStart: field(update.chain_start),
        writes: [
          {
            oldMintPolicy: EMPTY_MINT_POLICY,
            entry: {
              member: field(write.member),
              mask: BigInt(write.mask),
              value: BigInt(write.value) | (1n << 7n),
            },
            exists: write.exists,
            oldNext: field(write.old_next),
            oldLists: BigInt(write.old_lists),
            slot: path(write.slot),
            low: record(write.low),
            lowPath: path(write.low_path),
          },
        ],
      }),
    ).toThrow(
      expect.objectContaining({
        code: "RING_MEMBER_REGISTRY_INVALID",
        details: { reason: "ValueOutsideMask" },
      }),
    );
  });
});

describe("ring-statements.json", () => {
  type TransferCase = (typeof statements.transfer)[number];

  const family = (vector: TransferCase): TransferFamily =>
    vector.family === "anonymous"
      ? {
          kind: "anonymous",
          partyIdentities: (vector.party_identities ?? []).map(field),
          publicOwners: vector.public_owners === true,
          delegate: vector.delegate === true,
        }
      : {
          kind: "confidential",
          inProof: vector.in_proof === true,
          delegate: vector.delegate === true,
          sender: field(vector.sender ?? "00".repeat(32)),
        };

  const statementOf = (vector: TransferCase, outputs: TransferStatement["outputs"]) => ({
    head: {
      firstNullifier: field(vector.first_nullifier),
      ringId: field(vector.ring_id),
      txViewingU: field(vector.tx_viewing_u),
      auditorPubkey: bytes<Bytes33>(vector.auditor_pubkey, 33),
      envelope: bytes(vector.envelope),
      salt: bytes<Bytes16>(vector.salt, 16),
      layout: {
        hasData: (vector.layout & 1) !== 0,
        entry: (vector.layout & 2) !== 0,
        format:
          (vector.layout & 4) !== 0
            ? DisclosureFormat.SingleAssetPayout
            : DisclosureFormat.Standard,
      },
    },
    family: family(vector),
    approvalMask: vector.approval_mask,
    approvalTotals: ZERO_32,
    signerDataCounts: BigInt((vector as { signer_data_counts?: number }).signer_data_counts ?? 0),
    noSpend: vector.no_spend,
    capacity: vector.output_capacity,
    outputs,
    signers: { count: vector.signer_count, chain: field(vector.signer_chain) },
    inputCount: vector.input_count,
    inputNullifierChain: field(
      (vector as unknown as { input_nullifier_chain: string }).input_nullifier_chain,
    ),
    privateTxHash: field(vector.private_tx_hash),
    roots: {
      policyHash: field(vector.policy_hash),
      ownRoot: field(vector.own_root),
      curatorRoot: field(vector.curator_root),
      trackingRoot: field(vector.tracking_root),
    },
    publicAssets: vector.public_assets.map(field),
    publicAmounts: vector.public_amounts.map(field),
    publicGross: vector.public_gross.map(field),
    withdrawalHash: field(vector.withdrawal_hash),
  });

  it("rebuilds every transfer statement, its element count and its public input", () => {
    for (const vector of statements.transfer) {
      const outputs = vector.outputs.map((slot) => ({
        hash: field(slot.hash),
        record: bytes(slot.record),
        ...(slot.tail === null ? {} : { tail: bytes(slot.tail) }),
      }));
      expect(hex(ciphertextDigest(bytes(vector.envelope))), vector.rail).toBe(
        vector.envelope_digest,
      );
      expect(hex(recordChain(outputs, vector.output_capacity)), vector.rail).toBe(
        vector.record_chain,
      );
      expect(hex(tailChain(outputs, vector.output_capacity)), vector.rail).toBe(vector.tail_chain);
      const statement = statementOf(vector, outputs);
      const elements = transferStatementElements(statement);
      expect(elements, vector.rail).toHaveLength(vector.elements.length);
      expect(hexes(elements), vector.rail).toEqual(vector.elements);
      expect(hex(transferStatementHash(statement))).toBe(vector.public_input_hash);
    }
  });

  it("refuses a transfer statement past its output capacity", () => {
    const vector = statements.transfer.find((entry) => entry.output_capacity === 2);
    if (vector === undefined) throw new Error("vector has no two slot case");
    const outputs = vector.outputs.map((slot) => ({
      hash: field(slot.hash),
      record: bytes(slot.record),
    }));
    expect(() =>
      transferStatementElements({ ...statementOf(vector, outputs), capacity: 1 }),
    ).toThrow(expect.objectContaining({ code: "RING_INVALID_LENGTH" }));
  });

  it("rebuilds the apply records and register key statements", () => {
    const apply = statements.apply_records;
    const applyStatement = {
      oldRoot: field(apply.old_root),
      newRoot: field(apply.new_root),
      oldNextIndex: apply.old_next_index,
      newNextIndex: apply.new_next_index,
      chainStart: field(apply.chain_start),
      chainEnd: field(apply.chain_end),
      count: BigInt(apply.count),
      restrictive: apply.restrictive,
      private: {
        privateWrites: apply.private_writes,
        trackingRoot: field(apply.tracking_root),
      },
    };
    expect(hexes(applyRecordsStatementElements(applyStatement))).toEqual(apply.elements);
    expect(hex(applyRecordsStatementHash(applyStatement))).toBe(apply.public_input_hash);
    const pub = statements.apply_records_public;
    const publicStatement = {
      oldRoot: field(pub.old_root),
      newRoot: field(pub.new_root),
      oldNextIndex: pub.old_next_index,
      newNextIndex: pub.new_next_index,
      chainStart: field(pub.chain_start),
      chainEnd: field(pub.chain_end),
      count: BigInt(pub.count),
      restrictive: pub.restrictive,
    };
    expect(hexes(applyRecordsStatementElements(publicStatement))).toEqual(pub.elements);
    expect(hex(applyRecordsStatementHash(publicStatement))).toBe(pub.public_input_hash);
    const register = statements.register_key;
    const registerStatement = {
      ringId: field(register.ring_id),
      member: field(register.member),
      nullifierPk: field(register.nullifier_pk),
      listTag: field(register.list_tag),
      auditorPubkey: bytes<Bytes33>(register.auditor_pubkey, 33),
      ephU: field(register.eph_u),
      ciphertext: bytes<Bytes64>(register.ciphertext, 64),
    };
    expect(hexes(registerKeyStatementElements(registerStatement))).toEqual(register.elements);
    expect(hex(registerKeyStatementHash(registerStatement))).toBe(register.public_input_hash);
  });

  it("rebuilds the apply enrollments statement, its domain apart from apply records", () => {
    const apply = statements.apply_enrollments;
    const statement = {
      oldRoot: field(apply.old_root),
      newRoot: field(apply.new_root),
      oldNextIndex: BigInt(apply.old_next_index),
      newNextIndex: BigInt(apply.new_next_index),
      chainStart: field(apply.chain_start),
      chainEnd: field(apply.chain_end),
      count: BigInt(apply.count),
    };
    expect(hexes(applyEnrollmentsStatementElements(statement))).toEqual(apply.elements);
    expect(hex(applyEnrollmentsStatementHash(statement))).toBe(apply.public_input_hash);
  });

  it("hashes a tracking entry and chains it as the program does", () => {
    const tracking = statements.tracking;
    const entry = {
      member: field(tracking.member),
      nullifierPk: field(tracking.nullifier_pk),
      ctHash: field(tracking.ct_hash),
      listTag: field(tracking.list_tag),
    };
    expect(hex(trackingEntryHash(entry))).toBe(tracking.entry_hash);
    expect(hex(trackingEntryChained(ZERO_32, entry))).toBe(tracking.chain_from_zero);
    expect(hex(TRACKING_EMPTY_ROOT)).toBe(tracking.empty_root);
  });
});

describe("transfer key selection", () => {
  const spend = {
    format: DisclosureFormat.Standard,
    rail: "confidential",
    inputs: 2,
    outputs: 2,
    spendsDefaultRing: false,
    legs: 0,
    owners: 1,
    pools: { own: 0, curator: 0, tracking: 0 },
    wide: false,
  } as const;

  it("selects one key on every rail", () => {
    expect(ringTransferCircuit(spend)).toEqual(
      ringTransferCircuit({ ...spend, rail: "anonymous" }),
    );
    expect(ringTransferCircuit(spend)?.owners).toBe(4);
  });

  it("names the wide key once a spend leaves the narrow pools", () => {
    const narrow = ringTransferCircuit(spend);
    if (narrow === undefined) throw new Error("no narrow key");
    const width = transferPoolCapacity(narrow).own;
    const own = (records: number) => ({ own: records, curator: 0, tracking: 0 });
    expect(fittedSpend({ ...spend, pools: own(width) }).wide).toBe(false);
    expect(ringTransferCircuit(fittedSpend({ ...spend, pools: own(width + 1) }))).toEqual(
      ringTransferCircuit({ ...spend, wide: true }),
    );
  });

  it("holds forty distinct input assets and their owner subjects", () => {
    const candidate = {
      ...spend,
      inputs: 40,
      pools: { own: 43, curator: 43, tracking: 3 },
    };
    const key = ringTransferCircuit(fittedSpend(candidate));
    expect(key).toMatchObject({ class: 40, outputs: 2, wide: true });
    if (key === undefined) throw new Error("missing key");
    const capacity = transferPoolCapacity(key);
    expect(
      ringTransferCircuit({
        ...fittedSpend(candidate),
        pools: { ...candidate.pools, own: capacity.own + 1 },
      }),
    ).toBeUndefined();
  });

  it("routes payout format only through its confidential profile", () => {
    const payout = {
      ...spend,
      format: DisclosureFormat.SingleAssetPayout,
      inputs: 1,
      outputs: 16,
      pools: { own: 35, curator: 35, tracking: 17 },
    };
    const key = ringTransferCircuit(fittedSpend(payout));
    expect(key).toMatchObject({
      format: DisclosureFormat.SingleAssetPayout,
      class: 1,
      outputs: 16,
    });
    if (key === undefined) throw new Error("missing payout key");
    expect(transferPoolCapacity(key)).toEqual(payout.pools);
    for (const candidate of [
      { ...payout, format: DisclosureFormat.Standard },
      { ...payout, rail: "anonymous" as const },
      { ...payout, inputs: 2 },
      { ...payout, outputs: 15 },
      { ...payout, spendsDefaultRing: true },
      { ...payout, wide: true },
      { ...payout, legs: 1 },
      { ...payout, owners: 2 },
      { ...payout, pools: { ...payout.pools, own: 36 } },
    ])
      expect(ringTransferCircuit(candidate)).toBeUndefined();
  });

  it("holds the pools of pool_capacity.json", () => {
    expect(poolCapacity.keys).toEqual(
      transferKeys().map((circuit) => ({
        key: transferCircuitType(circuit).replaceAll("-", "_"),
        ...transferPoolCapacity(circuit),
      })),
    );
  });

  it("refuses a delegate rail spending a default-ring note", () => {
    expect(ringTransferCircuit({ ...spend, rail: "delegate", spendsDefaultRing: true })).toBe(
      undefined,
    );
  });
});

describe("ring rails", () => {
  const delegate = encodeBase58(new Uint8Array(32).fill(7));

  it("picks the rail of an instruction under the mode and the delegate", () => {
    const { transfer, authorityTransfer, merge } = RingInstructionTag;
    expect(ringRail(transfer, { mode: "confidential" })).toBe("confidential");
    expect(ringRail(transfer, { mode: "anonymous" })).toBe("anonymous");
    expect(ringRail(authorityTransfer, { mode: "confidential", delegate })).toBe("delegate");
    expect(ringRail(authorityTransfer, { mode: "anonymous", delegate })).toBe("anonymousDelegate");
    expect(() => ringRail(authorityTransfer, { mode: "anonymous" })).toThrow(
      ringError("DelegateDisabled"),
    );
    expect(() => ringRailOf(merge, "confidential")).toThrow(ringError("InvalidInstructionData"));
  });
});

describe("disclosure packing", () => {
  it("left-aligns a short tail chunk and zero pads it", () => {
    const plaintext = Uint8Array.from({ length: 40 }, (_, index) => index + 1);
    const fields = packDisclosure(plaintext);
    expect(fields).toHaveLength(2);
    expect(hex(fields[0] ?? new Uint8Array())).toBe(`00${hex(plaintext.subarray(0, 31))}`);
    expect(hex(fields[1] ?? new Uint8Array())).toBe(
      `00${hex(plaintext.subarray(31))}${"00".repeat(22)}`,
    );
    expect(unpackDisclosure(fields, 40)).toEqual(plaintext);
    const padded = fields.map((entry, index) => (index === 1 ? flipped(entry) : entry));
    expect(() => unpackDisclosure(padded, 40)).toThrow("KEYPAIR_DISCLOSURE_PADDING");
  });
});
