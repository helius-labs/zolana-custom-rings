import { policyWithdrawalHash } from "../../src/proof/withdrawals.js";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { basename } from "node:path";

import { describe, expect, it } from "vitest";

import {
  ringProofCircuit,
  ringProofRequestBody,
  ringRequestKey,
  type AnonymousSlotProofInputs,
  type AuditEnvelopeProofInputs,
  type DeliveredSlotProofInputs,
  type PolicyProofInputs,
  type PolicySubjectEntry,
  type PolicyTableProofInputs,
  type RingProofRequest,
  type RingSlotOpening,
} from "../../src/rpc/prover/ring.js";
import { type PresentRecordOpening } from "../../src/rpc/prover/types.js";
import { solanaOwnerIdentity } from "@heliuslabs/zolana/internal";
import { UTXO_DOMAIN } from "@heliuslabs/zolana/interface";
import type { Bytes16, Bytes31, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import {
  NullifierKey,
  outputBlindingSeed,
  poseidon,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import { privateTxHash } from "@heliuslabs/zolana/transaction";
import type {
  MemberRecord,
  QuadPath,
  RecordOpening,
  RecordPool,
  RecordWriteProofInput,
} from "../../src/protocol/membership/member-registry.js";
import {
  RING_KEYS,
  RING_PROVING_KEY_SHA256S,
  ringCircuitType,
  ringProvingKey,
} from "../../src/protocol/proof/proving-keys.js";
import { auditSharedSecret, symmetricAuditApply } from "../../src/crypto/audit/audit.js";
import type { AuditLayout } from "../../src/protocol/codec/ring-disclosure-layout.js";
import {
  anonymousCommitments,
  sealRingDisclosure,
  type AnonymousOutputOpening,
  type DeliveredOutputOpening,
} from "../../src/crypto/audit/ring-disclosure.js";
import { sealDeliveredBody } from "../../src/protocol/transaction/output.js";
import { deliveredSlotSecret, senderCommitment } from "../../src/crypto/derivation/ring-stream.js";
import {
  applyRecordsStatement,
  replayRecordWrites,
  verifyRecordPool,
  type MemberOpeningRead,
} from "../../src/protocol/membership/member-opening.js";
import {
  buildRuleTable,
  decodeRule,
  policyTableHash,
} from "../../src/protocol/membership/policy.js";
import { sealNullifierKeyWith } from "../../src/operations/management/register-key.js";
import {
  applyRecordsStatementHash,
  auditStatementHash,
  policyStatementHash,
  registerKeyStatementHash,
  type AuditHead,
} from "../../src/protocol/proof/statement.js";
import type { RingOutput } from "../../src/protocol/transaction/transact.js";
import { ringBlindingSeed, ringOutputBlinding } from "../../src/crypto/derivation/blinding.js";

const GOLDENS = new URL("../../../../prover/ring/testdata/", import.meta.url);
const HAS_GOLDENS = existsSync(GOLDENS);
const GOLDEN_FILES = HAS_GOLDENS
  ? readdirSync(GOLDENS, { recursive: true }).filter(
      (name): name is string => typeof name === "string" && name.endsWith(".json"),
    )
  : [];
const GOLDEN_BY_CIRCUIT = new Map(
  GOLDEN_FILES.map((file) => [basename(file, ".json"), file] as const),
);
const RUST_FIXTURES = new URL("../../../sdk/tests/fixtures/", import.meta.url);
const RUST_POLICY_FIXTURES = readdirSync(RUST_FIXTURES).filter(
  (name) => name.startsWith("custom-ring-policy-") && name.endsWith(".json"),
);
const ZERO = new Uint8Array(32) as Bytes32;

type Json = Readonly<Record<string, unknown>>;

function golden(circuitType: string): Json {
  const file = GOLDEN_BY_CIRCUIT.get(circuitType);
  if (file === undefined) throw new Error(`missing golden for ${circuitType}`);
  return record(JSON.parse(readFileSync(new URL(file, GOLDENS), "utf8")));
}

function record(value: unknown): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("golden object");
  return value as Json;
}

function list(value: unknown): readonly unknown[] {
  if (!Array.isArray(value)) throw new Error("golden list");
  return value;
}

function text(value: unknown): string {
  if (typeof value !== "string") throw new Error("golden string");
  return value;
}

function count(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Error("golden integer");
  return value;
}

function flag(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Error("golden boolean");
  return value;
}

function bytes<T extends Uint8Array>(value: unknown, length: number): T {
  const hex = text(value);
  if (!hex.startsWith("0x") || hex.length !== 2 + 2 * length) throw new Error("golden hex");
  return Uint8Array.from(Buffer.from(hex.slice(2), "hex")) as T;
}

function field(value: unknown): Bytes32 {
  return bytes<Bytes32>(value, 32);
}

function fields(value: unknown): readonly Bytes32[] {
  return list(value).map(field);
}

function hex(value: Uint8Array): string {
  return `0x${Buffer.from(value).toString("hex")}`;
}

function amountOf(value: Bytes32): bigint {
  return BigInt(hex(value));
}

function opening(value: unknown): RingSlotOpening {
  const item = record(value);
  return {
    domain: field(item["domain"]),
    treeId: field(item["treeId"]),
    ownerPkHash: field(item["ownerPkHash"]),
    nullifierPk: field(item["nullifierPk"]),
    asset: field(item["asset"]),
    amount: field(item["amount"]),
    blinding: field(item["blinding"]),
    dataHash: field(item["dataHash"]),
    ringDataHash: field(item["ringDataHash"]),
    ringProgramId: field(item["ringProgramId"]),
  };
}

function quadPath(index: unknown, flat: unknown): QuadPath {
  const siblings = fields(flat);
  return {
    index: count(index),
    siblings: Array.from({ length: siblings.length / 3 }, (_, level) =>
      siblings.slice(3 * level, 3 * level + 3),
    ),
  };
}

/** Go `RecordOpening` carries no member, the test names the subject it opens. */
function presentRecord(value: unknown, member: Bytes32): PresentRecordOpening {
  const item = record(value);
  return {
    kind: "present",
    record: {
      mintPolicy: mintSettings(
        item["mintPolicy"],
        item["withdrawalThreshold"],
        item["assetLimits"],
      ),
      member,
      next: field(item["next"]),
      lists: BigInt(count(item["lists"])),
      escrowKey: field(item["escrowKey"]),
    },
    path: quadPath(item["index"], item["path"]),
  };
}

function memberOpening(value: unknown, member: Bytes32): RecordOpening | undefined {
  if (value === null) return undefined;
  const item = record(value);
  if (flag(item["present"])) return presentRecord(item, member);
  return {
    kind: "absent",
    low: {
      mintPolicy: mintSettings(
        item["lowMintPolicy"],
        item["lowWithdrawalThreshold"],
        item["lowAssetLimits"],
      ),
      member: field(item["lowMember"]),
      next: field(item["lowNext"]),
      lists: BigInt(count(item["lowLists"])),
      escrowKey: field(item["lowEscrow"]),
    },
    path: quadPath(item["index"], item["path"]),
  };
}

function table(item: Json): PolicyTableProofInputs {
  return {
    sources: list(item["sources"]).map((value) => {
      const source = record(value);
      return { listId: count(source["listId"]), registry: field(source["registry"]) };
    }),
    policyLen: count(item["policyLen"]),
    rules: fields(item["rules"]),
  };
}

function entry(value: unknown): PolicySubjectEntry {
  const item = record(value);
  const [curator, ...rest] = list(item["curator"]);
  if (rest.length !== 0) throw new Error("golden curator entry");
  return { own: count(item["own"]), ...(curator === undefined ? {} : { curator: count(curator) }) };
}

function memberRecord(value: unknown): MemberRecord {
  const item = record(value);
  return {
    mintPolicy: mintSettings(item["mintPolicy"], item["withdrawalThreshold"], item["assetLimits"]),
    member: field(item["member"]),
    next: field(item["next"]),
    lists: BigInt(count(item["lists"])),
    escrowKey: field(item["escrowKey"]),
  };
}

/** Go `PooledRecord`, `SharedRegistryProof` and `PooledSubject` rows, absent when empty. */
function recordPool(records: unknown, proof: unknown, subjects: unknown): RecordPool | undefined {
  const rows = list(records);
  const shared = record(proof);
  if (rows.length === 0) return undefined;
  return {
    records: rows.map(memberRecord),
    canopy: fields(shared["canopy"]),
    paths: list(shared["paths"]).map((value) => {
      const path = record(value);
      return { index: count(path["index"]), siblings: list(path["siblings"]).map(fields) };
    }),
    subjects: list(subjects).map((value) => {
      const subject = record(value);
      return { member: field(subject["member"]), recordIndex: count(subject["recordIndex"]) };
    }),
  };
}

/** `exits | key_escrow << 1 | full_openings << 3`. */
function layout(value: unknown): AuditLayout {
  const flags = count(value);
  return {
    exits: (flags & 1) !== 0,
    keyEscrow: (flags & 2) !== 0,
    fullOpenings: (flags & 8) !== 0,
  };
}

function envelope(item: Json): AuditEnvelopeProofInputs {
  return {
    firstNullifier: field(item["firstNullifier"]),
    ringId: field(item["ringId"]),
    txViewingSk: bytes<Bytes32>(item["txViewingSk"], 32),
    ephSk: bytes<Bytes32>(item["ephSk"], 32),
    auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
    salt: bytes<Bytes16>(item["salt"], 16),
    layout: layout(item["layout"]),
  };
}

function delivered(value: unknown): DeliveredSlotProofInputs {
  const item = record(value);
  return {
    output: opening(item["output"]),
    recipientKey: bytes<Bytes32>(item["recipientKey"], 32),
    ownerKey: bytes<Bytes32>(item["ownerKey"], 32),
    body: bytes(item["body"], 40),
  };
}

function anonymousSlot(value: unknown): AnonymousSlotProofInputs {
  const item = record(value);
  return { output: opening(item["output"]), ownerKey: bytes<Bytes32>(item["ownerKey"], 32) };
}

function policy(item: Json): PolicyProofInputs {
  const outputs = list(item["outputs"]).map((value) => {
    const output = record(value);
    return {
      ...opening(output),
      ...(output["ctHash"] === undefined ? {} : { ctHash: field(output["ctHash"]) }),
    };
  });
  const withdrawals = list(item["withdrawals"]).map((value) => {
    const leg = record(value);
    return {
      owner: field(leg["owner"]),
      asset: field(leg["asset"]),
      amount: BigInt(String(leg["amount"])),
    };
  });
  const ownPool = recordPool(item["ownRecords"], item["ownProof"], item["ownSubjects"]);
  if (ownPool === undefined) throw new Error("golden own pool");
  const curatorPool = recordPool(
    item["curatorRecords"],
    item["curatorProof"],
    item["curatorSubjects"],
  );
  return {
    withdrawalCount: count(item["withdrawalCount"]),
    withdrawalHash: field(item["withdrawalHash"]),
    withdrawals,
    privateTxHash: field(item["privateTxHash"]),
    policyHash: field(item["policyHash"]),
    ringId: field(item["ringId"]),
    ownRoot: field(item["ownRoot"]),
    curatorRoot: field(item["curatorRoot"]),
    publicAssets: fields(item["publicAssets"]),
    publicAmounts: fields(item["publicAmounts"]),
    ...table(item),
    publicAssetEntries: list(item["publicAssetEntries"]).map(count),
    addressChain: field(item["addressChain"]),
    privateTxBlinding: field(item["privateTxBlinding"]),
    outputs,
    recipients: fields(item["recipients"]),
    senderPkHash: field(item["senderPkHash"]),
    ownPool,
    ...(curatorPool === undefined ? {} : { curatorPool }),
    senderEntry: entry(item["senderEntry"]),
    ownerEntries: list(item["ownerEntries"]).map(entry),
    assetEntries: list(item["assetEntries"]).map(entry),
  };
}

function write(value: unknown): RecordWriteProofInput {
  const item = record(value);
  const queued = record(item["entry"]);
  return {
    oldMintPolicy: mintSettings(
      item["oldMintPolicy"],
      item["oldWithdrawalThreshold"],
      item["oldAssetLimits"],
    ),
    entry: {
      member: field(queued["member"]),
      mask: BigInt(count(queued["mask"])),
      value: BigInt(count(queued["value"])),
      escrowKey: field(queued["escrowKey"]),
    },
    exists: flag(item["exists"]),
    oldNext: field(item["oldNext"]),
    oldLists: BigInt(count(item["oldLists"])),
    oldEscrow: field(item["oldEscrow"]),
    slot: quadPath(item["index"], item["path"]),
    low: {
      mintPolicy: mintSettings(
        item["lowMintPolicy"],
        item["lowWithdrawalThreshold"],
        item["lowAssetLimits"],
      ),
      member: field(item["lowMember"]),
      next: field(item["lowNext"]),
      lists: BigInt(count(item["lowLists"])),
      escrowKey: field(item["lowEscrow"]),
    },
    lowPath: quadPath(item["lowIndex"], item["lowPath"]),
  };
}

/** The typed request a golden file holds, built field by field. */
function request(item: Json): RingProofRequest {
  const circuitType = text(item["circuitType"]);
  const publicInputHash = field(item["publicInputHash"]);
  if (circuitType.startsWith("custom-ring-audit-delivered-"))
    return {
      kind: "deliveredAudit",
      publicInputHash,
      ...envelope(item),
      outputs: list(item["outputs"]).map(delivered),
    };
  if (circuitType.startsWith("custom-ring-audit-anonymous-"))
    return {
      kind: "anonymousAudit",
      partyIdentities: fields(item["partyIdentities"]) as [Bytes32, Bytes32, Bytes32],
      publicInputHash,
      ...envelope(item),
      outputs: list(item["outputs"]).map(anonymousSlot),
      privateTxHash: field(item["privateTxHash"]),
      privateTxBlinding: field(item["privateTxBlinding"]),
      ...(item["senderKey"] === undefined
        ? {}
        : { senderKey: bytes<Bytes32>(item["senderKey"], 32) }),
      inputCount: count(item["inputCount"]),
      inputs: list(item["inputs"]).map(opening),
      senderCommitment: field(item["senderCommitment"]),
    };
  if (circuitType.startsWith("custom-ring-policy-member-"))
    return {
      kind: "memberPolicy",
      publicInputHash,
      anonymous: flag(item["anonymous"]),
      approvalRequired: flag(item["approvalRequired"]),
      keyEscrow: flag(item["keyEscrow"]),
      sender: field(item["sender"]),
      inputChain: field(item["inputChain"]),
      ...policy(item),
    };
  if (circuitType.startsWith("custom-ring-policy-delegate-"))
    return {
      kind: "delegatePolicy",
      publicInputHash,
      inputs: list(item["inputs"]).map(opening),
      ...policy(item),
    };
  if (circuitType.startsWith("custom-ring-apply-records-"))
    return {
      kind: "applyRecords",
      publicInputHash,
      oldRoot: field(item["oldRoot"]),
      newRoot: field(item["newRoot"]),
      oldNextIndex: count(item["oldNextIndex"]),
      newNextIndex: count(item["newNextIndex"]),
      chainStart: field(item["chainStart"]),
      chainEnd: field(item["chainEnd"]),
      writes: list(item["writes"]).slice(0, count(item["count"])).map(write),
    };
  if (circuitType === "custom-ring-withdrawal-exemption")
    return {
      kind: "withdrawalExemption",
      publicInputHash,
      root: field(item["root"]),
      assets: fields(item["assets"]),
      amounts: fields(item["amounts"]),
      entries: list(item["entries"]).map((entry, i) =>
        memberOpening(entry, fields(item["assets"])[i] ?? ZERO),
      ),
    };
  if (circuitType === "custom-ring-register-key")
    return {
      kind: "registerKey",
      publicInputHash,
      member: field(item["member"]),
      nullifierSecret: bytes<Bytes32>(item["nullifierSecret"], 32),
      ephSk: bytes<Bytes32>(item["ephSk"], 32),
      auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
    };
  if (circuitType.startsWith("custom-ring-deposit-")) {
    const ownerPkHashes = fields(item["ownerPkHashes"]);
    return {
      kind: "deposit",
      publicInputHash,
      contextHash: field(item["contextHash"]),
      count: count(item["count"]),
      anonymous: item["anonymous"] === undefined ? false : flag(item["anonymous"]),
      ownerPkHashes,
      ...(item["ownerKeys"] === undefined
        ? {}
        : { ownerKeys: list(item["ownerKeys"]).map((key) => bytes<Bytes32>(key, 32)) }),
      nullifierPks: fields(item["nullifierPks"]),
      blindingSecrets: fields(item["blindingSecrets"]),
      ctHashes: fields(item["ctHashes"]),
      members: list(item["members"]).map((member, i) =>
        member === null ? undefined : presentRecord(member, ownerPkHashes[i] ?? ZERO),
      ),
      ephSk: bytes<Bytes32>(item["ephSk"], 32),
      auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
      keyEscrow: flag(item["keyEscrow"]),
      memberRegistryRoot: field(item["memberRegistryRoot"]),
      policyHash: field(item["policyHash"]),
      assets: fields(item["assets"]),
      amounts: fields(item["amounts"]),
      ...(item["table"] === undefined ? {} : { table: table(record(item["table"])) }),
      assetRecords: list(item["assetRecords"]).map((opening, i) =>
        memberOpening(opening, fields(item["assets"])[i] ?? ZERO),
      ),
    };
  }
  if (circuitType.startsWith("custom-ring-merge-v3-")) {
    const ownerKey = bytes<Bytes32>(item["ownerKey"], 32);
    return {
      kind: "merge",
      partyIdentities: fields(item["partyIdentities"]) as [Bytes32, Bytes32, Bytes32],
      publicInputHash,
      privateTxHash: field(item["privateTxHash"]),
      outputUtxoHash: field(item["outputUtxoHash"]),
      firstNullifier: field(item["firstNullifier"]),
      ringProgramId: field(item["ringProgramId"]),
      auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
      salt: field(item["salt"]),
      ephSk: bytes<Bytes32>(item["ephSk"], 32),
      disclosureKey: bytes<Bytes32>(item["disclosureKey"], 32),
      ownerKey,
      nullifierSecret: field(item["nullifierSecret"]),
      mintChunks: fields(item["mintChunks"]),
      inputs: list(item["inputs"]).map((value) => {
        const input = record(value);
        return {
          domain: field(input["domain"]),
          treeId: field(input["treeId"]),
          amount: field(input["amount"]),
          blinding: field(input["blinding"]),
          ringDataHash: field(input["ringDataHash"]),
        };
      }),
      outputTreeId: field(item["outputTreeId"]),
      outputRingDataHash: field(item["outputRingDataHash"]),
      keyEscrow: flag(item["keyEscrow"]),
      memberRegistryRoot: field(item["memberRegistryRoot"]),
      ctHash: field(item["ctHash"]),
      ...(item["member"] === null
        ? {}
        : { member: presentRecord(item["member"], solanaOwnerIdentity(ownerKey) as Bytes32) }),
    };
  }
  throw new Error(`no request for ${circuitType}`);
}

function tagged(u: Uint8Array): Bytes33 {
  return Uint8Array.from([4, ...u]) as Bytes33;
}

function publicKeyOf(secret: Uint8Array): X25519PublicKey {
  const keypair = X25519Keypair.fromBytes(secret);
  try {
    return keypair.publicKey();
  } finally {
    keypair.destroy();
  }
}

function agreement(secret: Uint8Array, peer: X25519PublicKey): Bytes32 {
  const keypair = X25519Keypair.fromBytes(secret);
  try {
    return keypair.ecdh(peer);
  } finally {
    keypair.destroy();
  }
}

/** The envelope the circuit seals, rebuilt from the request's secrets. */
function auditHead(envelope: AuditEnvelopeProofInputs): AuditHead {
  const auditor = X25519PublicKey.fromBytes(tagged(envelope.auditorPk));
  const eph = publicKeyOf(envelope.ephSk);
  const shared = auditSharedSecret(agreement(envelope.ephSk, auditor), eph, auditor);
  return {
    firstNullifier: envelope.firstNullifier,
    ringId: envelope.ringId,
    txViewingU: publicKeyOf(envelope.txViewingSk).u(),
    auditorPubkey: tagged(envelope.auditorPk),
    ephU: eph.u(),
    sealed: symmetricAuditApply(shared, envelope.txViewingSk) as Bytes32,
    salt: envelope.salt,
    layout: envelope.layout,
  };
}

/** Go `UtxoHashCircuit`, a dummy's owner is zero. */
function openingHash(slot: RingSlotOpening): Bytes32 {
  const owner = isUtxo(slot) ? poseidon([slot.ownerPkHash, slot.nullifierPk]) : ZERO;
  return poseidon([
    slot.domain,
    slot.treeId,
    slot.asset,
    slot.amount,
    slot.dataHash,
    poseidon([slot.ringDataHash, slot.ringProgramId]),
    poseidon([owner, slot.blinding]),
  ]) as Bytes32;
}

function isUtxo(slot: RingSlotOpening): boolean {
  return amountOf(slot.domain) === BigInt(UTXO_DOMAIN);
}

function isRingOutput(slot: RingSlotOpening): boolean {
  return isUtxo(slot) && amountOf(slot.ringProgramId) !== 0n;
}

/** The published tag, the circuit reads `low128` so the top 16 bytes are zero. */
/** SPP's TXOB blinding of slot `outputIndex` under the seed the envelope's `tx_viewing_sk` fixes. */
function blindingOf(envelope: AuditEnvelopeProofInputs, outputIndex: number): Bytes32 {
  return ringOutputBlinding({
    firstNullifier: envelope.firstNullifier,
    blindingSeed: ringBlindingSeed(envelope.txViewingSk, envelope.salt),
    outputIndex,
  });
}

function seedOutOf(envelope: AuditEnvelopeProofInputs): Bytes32 {
  return outputBlindingSeed(
    envelope.firstNullifier,
    ringBlindingSeed(envelope.txViewingSk, envelope.salt),
  );
}

function exitOutput(hash: Bytes32): RingOutput {
  return { kind: "exit", hash, ownerTag: ZERO, payload: new Uint8Array(0) };
}

// The Go ring prover goldens live outside the repository.
const CIRCUIT_TYPES = [...GOLDEN_BY_CIRCUIT.keys()].sort();

describe.runIf(HAS_GOLDENS)("ring prover request encoding against the Go goldens", () => {
  it("lists every ring key of ring_keys.rs and names one for each golden", () => {
    const rust = readFileSync(
      new URL("../../../../program-libs/interface/src/proof/ring_keys.rs", import.meta.url),
      "utf8",
    );
    const names = [...rust.matchAll(/name: "([a-z0-9-]+)"/gu)].map((match) => match[1]);
    expect(RING_KEYS.map((key) => key.name)).toEqual(names);
    for (const circuitType of CIRCUIT_TYPES) expect(names).toContain(circuitType);
    for (const key of RING_KEYS) expect(ringCircuitType(key.circuit)).toBe(key.name);
  });

  it.each(CIRCUIT_TYPES)("encodes %s byte for byte", (circuitType) => {
    expectReencoded(golden(circuitType));
  });

  it("encodes the full u64 withdrawal range exactly and rejects overflow", () => {
    const base = request(golden("custom-ring-policy-member-v3-2-w2-own"));
    if (base.kind !== "memberPolicy") throw new Error("member policy fixture");
    const leg = base.withdrawals[0]!;
    const body = ringProofRequestBody({
      ...base,
      withdrawals: [{ ...leg, amount: 0xffff_ffff_ffff_ffffn }, base.withdrawals[1]!],
    });
    expect((body["withdrawals"] as { amount: string }[])[0]?.amount).toBe(
      "0x" + "00".repeat(24) + "ff".repeat(8),
    );
    for (const amount of [-1n, 1n << 64n])
      expect(() =>
        ringProofRequestBody({ ...base, withdrawals: [{ ...leg, amount }, base.withdrawals[1]!] }),
      ).toThrow();
  });

  it("names the deposit key the prover loads and refuses a shape no ring key serves", () => {
    expect(ringProvingKey({ family: "deposit", capacity: 8 })).toEqual({
      name: "custom_ring_deposit_8.key",
      sha256: RING_PROVING_KEY_SHA256S["custom_ring_deposit_8.key"],
    });
    expect(() => ringProvingKey({ family: "deliveredAudit", outputs: 3 })).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_SHAPE" }),
    );
  });

  it("refuses a request no key serves or the strict decoder would refuse", () => {
    const base = request(golden("custom-ring-audit-delivered-8"));
    if (base.kind !== "deliveredAudit") throw new Error("delivered golden");
    const [first, ...rest] = base.outputs;
    if (first === undefined) throw new Error("delivered golden output");
    expect(() => ringProofRequestBody({ ...base, outputs: [...base.outputs, first] })).toThrow(
      expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }),
    );
    const modulus = Uint8Array.from(
      Buffer.from("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", "hex"),
    ) as Bytes32;
    expect(() => ringProofRequestBody({ ...base, firstNullifier: modulus })).toThrow(
      expect.objectContaining({
        code: "CLIENT_INVALID_FIELD",
        details: { field: "firstNullifier" },
      }),
    );
    expect(() =>
      ringProofRequestBody({
        ...base,
        outputs: [{ ...first, body: first.body.slice(1) }, ...rest],
      }),
    ).toThrow(
      expect.objectContaining({
        code: "CLIENT_INVALID_LENGTH",
        details: { field: "outputs[0].body", expected: 40, actual: 39 },
      }),
    );
    const unknown = { ...base };
    Reflect.set(unknown, "kind", "deliveredAuditV2");
    const loose = { ...base };
    Reflect.set(loose, "outputs", { length: base.outputs.length });
    for (const malformed of [unknown, loose]) {
      expect(() => ringProofRequestBody(malformed)).toThrow(
        expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }),
      );
      expect(() => ringRequestKey(malformed)).toThrow(
        expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }),
      );
    }
  });

  it("sends the sender key on the entry key alone", () => {
    const commitment = request(golden("custom-ring-audit-anonymous-v2-4-2"));
    const entry = request(golden("custom-ring-audit-anonymous-entry-v2-8-2"));
    if (commitment.kind !== "anonymousAudit" || entry.kind !== "anonymousAudit")
      throw new Error("anonymous goldens");
    expect(ringProofRequestBody(commitment)).not.toHaveProperty("senderKey");
    expect(ringProofRequestBody(entry)).toHaveProperty("senderKey");
    const { senderKey, ...keyless } = entry;
    if (senderKey === undefined) throw new Error("entry golden without its sender key");
    for (const refused of [{ ...commitment, senderKey }, keyless])
      expect(() => ringProofRequestBody(refused)).toThrow(
        expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }),
      );
  });
});

describe("ring prover request encoding against the Rust fixtures", () => {
  it("finds a Rust policy fixture", () => {
    expect(RUST_POLICY_FIXTURES.length).toBeGreaterThan(0);
  });

  it.each(RUST_POLICY_FIXTURES)("encodes %s byte for byte", (name) => {
    expectReencoded(record(JSON.parse(readFileSync(new URL(name, RUST_FIXTURES), "utf8"))));
  });
});

describe.runIf(HAS_GOLDENS)("ring statements rebuilt from the Go goldens", () => {
  it("rebuilds the register key statement and its sealed key", () => {
    const typed = request(golden("custom-ring-register-key"));
    if (typed.kind !== "registerKey") throw new Error("register key golden");
    expect(typed.nullifierSecret[0]).toBe(0);
    const key = NullifierKey.fromSecret(typed.nullifierSecret.slice(1) as Bytes31);
    const ephemeral = X25519Keypair.fromBytes(typed.ephSk);
    try {
      const envelope = sealNullifierKeyWith(
        ephemeral,
        key,
        X25519PublicKey.fromBytes(tagged(typed.auditorPk)),
      );
      const statement = {
        member: typed.member,
        nullifierPk: envelope.nullifierPublicKey,
        auditorPubkey: tagged(typed.auditorPk),
        ephU: envelope.sealed.ephemeralPublicKey.u(),
        ciphertext: envelope.sealed.ciphertext,
      };
      expect(hex(registerKeyStatementHash(statement))).toBe(hex(typed.publicInputHash));
    } finally {
      ephemeral.destroy();
      key.destroy();
    }
  });

  it.each(["custom-ring-apply-records-1", "custom-ring-apply-records-16"])(
    "replays %s to the golden root, index, chain and statement",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "applyRecords") throw new Error("apply golden");
      const replayed = replayRecordWrites({
        oldRoot: typed.oldRoot,
        oldNextIndex: typed.oldNextIndex,
        chainStart: typed.chainStart,
        writes: typed.writes,
      });
      expect(hex(replayed.newRoot)).toBe(hex(typed.newRoot));
      expect(replayed.newNextIndex).toBe(typed.newNextIndex);
      expect(hex(replayed.chainEnd)).toBe(hex(typed.chainEnd));
      expect(hex(applyRecordsStatementHash(applyRecordsStatement(replayed)))).toBe(
        hex(typed.publicInputHash),
      );
    },
  );

  it.each(CIRCUIT_TYPES.filter((name) => name.startsWith("custom-ring-audit-delivered-")))(
    "rebuilds %s from tx_sk and every recipient key",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "deliveredAudit") throw new Error("delivered golden");
      const key = { txViewingSecret: typed.txViewingSk, salt: typed.salt };
      const { exits, keyEscrow } = typed.layout;
      const outputs = typed.outputs.map((slot, i): DeliveredOutputOpening => {
        const opened = slot.output;
        if (!isUtxo(opened)) return { kind: "dummy" };
        const nullifierPk = keyEscrow ? undefined : opened.nullifierPk;
        expect(hex(blindingOf(typed, i))).toBe(hex(opened.blinding));
        if (!isRingOutput(opened)) {
          return {
            kind: "exit",
            nullifierPk,
            asset: opened.asset,
            amount: amountOf(opened.amount),
          };
        }
        const secret = slotSecret(typed, slot, i);
        expect(
          hex(
            sealDeliveredBody(secret, {
              blinding: opened.blinding,
              amount: amountOf(opened.amount),
            }),
          ),
        ).toBe(hex(slot.body));
        expect(hex(opened.ringDataHash)).toBe(hex(ZERO));
        return { kind: "ring", nullifierPk, ownerKey: slot.ownerKey };
      });
      const disclosure = sealRingDisclosure(key, {
        kind: "delivered",
        layout: { outputs: typed.outputs.length, exits, keyEscrow },
        seedOut: exits ? seedOutOf(typed) : undefined,
        outputs,
      });
      const hash = auditStatementHash({
        head: auditHead(typed),
        outputs: typed.outputs.map((slot) =>
          isUtxo(slot.output) && !isRingOutput(slot.output)
            ? exitOutput(openingHash(slot.output))
            : {
                kind: "delivered",
                hash: openingHash(slot.output),
                u: slot.recipientKey,
                body: slot.body,
              },
        ),
        disclosure,
        kind: { kind: "delivered" },
      });
      expect(hex(hash)).toBe(hex(typed.publicInputHash));
    },
  );

  it.each(CIRCUIT_TYPES.filter((name) => name.startsWith("custom-ring-audit-anonymous-")))(
    "rebuilds %s with its owner keys and its spent inputs",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "anonymousAudit") throw new Error("anonymous golden");
      const key = { txViewingSecret: typed.txViewingSk, salt: typed.salt };
      const spent = typed.inputs.slice(0, typed.inputCount);
      const [first] = spent;
      if (first === undefined) throw new Error("anonymous golden without an input");
      // The circuit proves every spent UTXO under one owner.
      const senderPkHash = first.ownerPkHash;
      expect(typed.senderKey === undefined).toBe(!typed.layout.fullOpenings);
      if (typed.senderKey !== undefined)
        expect(hex(solanaOwnerIdentity(typed.senderKey))).toBe(hex(senderPkHash));
      const outputs = typed.outputs.map((slot, i): AnonymousOutputOpening => {
        const opened = slot.output;
        if (!isUtxo(opened)) return { kind: "dummy" };
        expect(hex(blindingOf(typed, i))).toBe(hex(opened.blinding));
        if (!isRingOutput(opened)) {
          return {
            kind: "exit",
            nullifierPk: opened.nullifierPk,
            asset: opened.asset,
            amount: amountOf(opened.amount),
          };
        }
        // A ring output commits to no ring data, its owner the identity of its disclosed key.
        expect(hex(opened.ringDataHash)).toBe(hex(ZERO));
        expect(hex(solanaOwnerIdentity(slot.ownerKey))).toBe(hex(opened.ownerPkHash));
        return {
          kind: "ring",
          nullifierPk: opened.nullifierPk,
          ownerKey: slot.ownerKey,
          asset: opened.asset,
          amount: amountOf(opened.amount),
        };
      });
      expect(
        hex(senderCommitment({ senderPkHash, privateTxBlinding: typed.privateTxBlinding })),
      ).toBe(hex(typed.senderCommitment));
      expect(
        hex(
          privateTxHash({
            inputHashes: typed.inputs.map((slot) => (isUtxo(slot) ? openingHash(slot) : ZERO)),
            outputHashes: typed.outputs.map((slot) =>
              isUtxo(slot.output) ? openingHash(slot.output) : ZERO,
            ),
            blinding: typed.privateTxBlinding,
          }),
        ),
      ).toBe(hex(typed.privateTxHash));
      const { exits, fullOpenings } = typed.layout;
      const disclosure = sealRingDisclosure(key, {
        kind: "anonymous",
        layout: {
          key: fullOpenings
            ? { kind: "entry" }
            : { kind: "commitment", class: typed.inputs.length },
          inputs: typed.inputCount,
          outputs: typed.outputs.length,
          exits,
        },
        seedOut: exits ? seedOutOf(typed) : undefined,
        outputs,
        inputs:
          typed.senderKey === undefined
            ? anonymousCommitments(
                spent.map((slot) => (isUtxo(slot) ? openingHash(slot) : undefined)),
              )
            : {
                kind: "openings",
                senderKey: typed.senderKey,
                senderNullifierPk: first.nullifierPk,
                inputs: spent.map((slot) =>
                  isUtxo(slot)
                    ? { asset: slot.asset, amount: amountOf(slot.amount), blinding: slot.blinding }
                    : undefined,
                ),
              },
      });
      const hash = auditStatementHash({
        head: auditHead(typed),
        outputs: typed.outputs.map((slot) =>
          isUtxo(slot.output) && !isRingOutput(slot.output)
            ? exitOutput(openingHash(slot.output))
            : {
                // The statement binds no tag and no body.
                kind: "anonymous",
                hash: openingHash(slot.output),
                tag: ZERO,
                body: Uint8Array.of(1),
              },
        ),
        disclosure,
        kind: {
          kind: "anonymous",
          partyIdentities: typed.partyIdentities,
          privateTxHash: typed.privateTxHash,
          senderCommitment: typed.senderCommitment,
        },
      });
      expect(hex(hash)).toBe(hex(typed.publicInputHash));
    },
  );

  it.each(CIRCUIT_TYPES.filter((name) => name.startsWith("custom-ring-policy-")))(
    "rebuilds %s, its table hash and its own-registry openings",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "memberPolicy" && typed.kind !== "delegatePolicy")
        throw new Error("policy golden");
      const table = buildRuleTable({
        rules: typed.rules.slice(0, typed.policyLen).map(decodeRule),
      });
      expect(hex(policyTableHash(table, typed.sources))).toBe(hex(typed.policyHash));
      const ownReads = poolReads(typed.ownPool, typed.ownRoot);
      if (typed.curatorPool !== undefined) poolReads(typed.curatorPool, typed.curatorRoot);
      const own = (entry: PolicySubjectEntry | undefined, member: Bytes32) => {
        const index = entry?.own ?? -1;
        expect(typed.ownPool.subjects[index]?.member).toEqual(member);
        return ownReads[index]?.record();
      };
      own(typed.senderEntry, typed.senderPkHash);
      typed.outputs.forEach((output, i) => {
        if (!isUtxo(output)) return;
        const owner = own(typed.ownerEntries[i], output.ownerPkHash);
        own(typed.assetEntries[i], output.asset);
        if (output.ctHash !== undefined && owner !== undefined)
          expect(hex(owner.escrowKey)).toBe(hex(poseidon([output.nullifierPk, output.ctHash])));
      });
      expect(typed.withdrawalHash).toEqual(
        policyWithdrawalHash(typed.withdrawals.slice(0, typed.withdrawalCount)),
      );
      const statement = {
        withdrawalHash: typed.withdrawalHash,
        privateTxHash: typed.privateTxHash,
        policyHash: typed.policyHash,
        ringId: typed.ringId,
        ownRoot: typed.ownRoot,
        curatorRoot: typed.curatorRoot,
        publicAssets: typed.publicAssets,
        publicAmounts: typed.publicAmounts,
        recipients: typed.recipients,
      };
      const hash =
        typed.kind === "memberPolicy"
          ? policyStatementHash({
              ...statement,
              key: { kind: "member", anonymous: typed.anonymous },
              approvalRequired: typed.approvalRequired,
              keyEscrow: typed.keyEscrow,
              sender: typed.sender,
            })
          : policyStatementHash({
              ...statement,
              key: { kind: "delegate" },
              approvalRequired: false,
              keyEscrow: true,
              sender: ZERO,
            });
      expect(hex(hash)).toBe(hex(typed.publicInputHash));
    },
  );
});

function expectReencoded(item: Json): void {
  const typed = request(item);
  const body = ringProofRequestBody(typed);
  expect(body).toEqual(item);
  expect(JSON.stringify(body)).toBe(JSON.stringify(item));
  expect(ringCircuitType(ringProofCircuit(typed))).toBe(text(item["circuitType"]));
}

/** Every subject's read, the padded pool verified as the indexer would serve it. */
function poolReads(pool: RecordPool, root: Bytes32): readonly MemberOpeningRead[] {
  return verifyRecordPool(
    {
      records: pool.records.map((record, i) => ({ record, path: pool.paths[i] as QuadPath })),
      canopy: pool.canopy,
      subjects: pool.subjects.map((subject) => subject.recordIndex),
    },
    root,
    pool.subjects.map((subject) => subject.member),
    pool.records.length,
  );
}

/** CRDS under `X25519(tx_sk, u)`, the secret the recipient rebuilds from its own key. */
function slotSecret(
  envelope: AuditEnvelopeProofInputs,
  slot: DeliveredSlotProofInputs,
  outputIndex: number,
): Bytes32 {
  const recipient = X25519PublicKey.fromBytes(tagged(slot.recipientKey));
  return deliveredSlotSecret({
    agreement: agreement(envelope.txViewingSk, recipient),
    txViewingKey: publicKeyOf(envelope.txViewingSk),
    recipientViewingKey: recipient,
    salt: envelope.salt,
    outputIndex,
    firstNullifier: envelope.firstNullifier,
  });
}

function mintSettings(packed: unknown, withdrawal: unknown, limits: unknown) {
  const mask = (1n << 64n) - 1n;
  const amounts = (fieldValue: unknown) => {
    const value = amountOf(field(fieldValue));
    return [(value >> 128n) & mask, (value >> 64n) & mask, value & mask] as const;
  };
  const [threshold, cap, cosignAbove] = amounts(packed);
  // The last field holds two amounts below an unused top one.
  const [
    senderCap,
    senderWindowSlots,
    volumeCap,
    volumeWindowSlots,
    depositCap,
    depositWindowSlots,
    ,
    withdrawalCap,
    withdrawalWindowSlots,
  ] = list(limits).flatMap(amounts);
  return {
    threshold,
    cap,
    cosignAbove,
    withdrawalThreshold: amountOf(field(withdrawal)),
    limits: {
      senderCap: senderCap!,
      senderWindowSlots: senderWindowSlots!,
      volumeCap: volumeCap!,
      volumeWindowSlots: volumeWindowSlots!,
      depositCap: depositCap!,
      depositWindowSlots: depositWindowSlots!,
      withdrawalCap: withdrawalCap!,
      withdrawalWindowSlots: withdrawalWindowSlots!,
    },
  };
}
