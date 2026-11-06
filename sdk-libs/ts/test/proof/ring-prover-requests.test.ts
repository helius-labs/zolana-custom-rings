import { initializePoseidon } from "@heliuslabs/spr";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { basename } from "node:path";

import { describe, expect, it } from "vitest";

import {
  ringProofCircuit,
  ringProofRequestBody,
  ringRequestKey,
  type AuditEnvelopeProofInputs,
  type EntryOpeningProofInput,
  type OutputOpeningProofInput,
  type PolicyOwnerEntry,
  type PolicyProofInputs,
  type PolicySubjectEntry,
  type PolicyTableProofInputs,
  type RingProofRequest,
  type RingSlotOpening,
  type TrackingProofInputs,
  type TrackingWriteProofInput,
  type TransferProofRequest,
} from "../../src/rpc/prover/ring.js";
import { ZERO_32, concatBytes, encodeBase58, isZero } from "@heliuslabs/spr/internal";
import { UTXO_DOMAIN } from "@heliuslabs/spr/interface";
import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@heliuslabs/spr/interface";
import {
  NullifierKey,
  poseidon,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/spr/keypair";
import { AssetRegistry, ConfidentialTransfer, SOL_MINT } from "@heliuslabs/spr/transaction";
import type {
  MemberRecord,
  QuadPath,
  RecordPool,
  RecordWriteProofInput,
} from "../../src/protocol/membership/member-registry.js";
import {
  TRACKING_EMPTY_ROOT,
  TRACKING_QUAD_HEIGHT,
  TRACKING_SENTINEL,
  type TrackingEntry,
  type TrackingOpening,
  type TrackingRecord,
} from "../../src/protocol/membership/tracking.js";
import { QUAD_HEIGHT } from "../../src/protocol/membership/member-registry.js";
import { EMPTY_MINT_POLICY } from "../../src/protocol/membership/mint-policy.js";
import {
  RING_KEYS,
  RING_PROVING_KEY_SHA256S,
  ringCircuitType,
  ringProvingKey,
} from "../../src/protocol/proof/proving-keys.js";
import { sealSaltedAuditorStream } from "../../src/crypto/audit/audit.js";
import { listTagOf } from "../../src/crypto/keys/list-salt.js";
import {
  DUMMY_RECORD,
  EMPTY_ENTRY_RECORD,
  encodeAuditEnvelope,
  RecordKind,
} from "../../src/protocol/codec/audit-stream.js";
import {
  recipientKeyRegion,
  type AuditLayout,
  type AuditStreamLayout,
} from "../../src/protocol/codec/ring-disclosure-layout.js";
import { sealOutputSlot } from "../../src/crypto/audit/ring-disclosure.js";
import { txKeySlotSecret } from "../../src/crypto/derivation/ring-stream.js";
import { x25519FromU } from "../../src/crypto/keys/x25519.js";
import {
  applyRecordsStatement,
  replayRecordWrites,
  SENTINEL_RECORD,
} from "../../src/protocol/membership/member-opening.js";
import { buildRuleTable } from "../../src/protocol/membership/policy.js";
import { sealNullifierKeyWith } from "../../src/operations/management/register-key.js";
import {
  applyRecordsStatementHash,
  registerKeyStatementHash,
  signerBinding,
  transferStatementHash,
  type TransferStatement,
} from "../../src/protocol/proof/statement.js";
import { signingKeySpendSigner } from "../../src/operations/payments/anonymous.js";
import { CustomRingTransfer } from "../../src/operations/payments/transfer-rails.js";
import { RingAddress } from "../../src/crypto/keys/ring-address.js";
import { noteInput, ringFixture, walletKeys, type Fixture } from "../helpers/ring-pipeline.js";

await initializePoseidon();

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
const RUST_TRANSFER_FIXTURES = readdirSync(RUST_FIXTURES).filter(
  (name) => name.startsWith("custom-ring-transfer-") && name.endsWith(".json"),
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

function table(item: Json): PolicyTableProofInputs {
  return {
    sources: list(item["sources"]).map((value) => {
      const source = record(value);
      return {
        listId: count(source["listId"]),
        registry: field(source["registry"]),
      };
    }),
    salted: count(item["salted"]),
    policyLen: count(item["policyLen"]),
    rules: fields(item["rules"]),
  };
}

function entry(value: unknown): PolicySubjectEntry {
  const item = record(value);
  const [curator, ...rest] = list(item["curator"]);
  if (curator === undefined || rest.length !== 0) throw new Error("golden curator entry");
  return { own: count(item["own"]), curator: count(curator) };
}

function ownerEntry(value: unknown): PolicyOwnerEntry {
  const item = record(value);
  const [curatorSalted, ...rest] = list(item["curatorSalted"]);
  if (curatorSalted === undefined || rest.length !== 0) throw new Error("golden salted entry");
  return {
    ...entry(item),
    tracking: count(item["tracking"]),
    listSalt: field(item["listSalt"]),
    ownSalted: count(item["ownSalted"]),
    curatorSalted: count(curatorSalted),
  };
}

function memberRecord(value: unknown): MemberRecord {
  const item = record(value);
  return {
    mintPolicy: mintSettings(item["mintPolicy"], item["withdrawalThreshold"], item["assetLimits"]),
    member: field(item["member"]),
    next: field(item["next"]),
    lists: BigInt(count(item["lists"])),
  };
}

/** Go `PooledRecord`, `SharedRegistryProof` and `PooledSubject` rows. */
function recordPool(records: unknown, proof: unknown, subjects: unknown): RecordPool {
  const rows = list(records);
  const shared = record(proof);
  return {
    records: rows.map(memberRecord),
    canopy: fields(shared["canopy"]),
    paths: list(shared["paths"]).map((value) => {
      const path = record(value);
      return {
        index: count(path["index"]),
        siblings: list(path["siblings"]).map(fields),
      };
    }),
    subjects: list(subjects).map((value) => {
      const subject = record(value);
      return {
        member: field(subject["member"]),
        recordIndex: count(subject["recordIndex"]),
      };
    }),
  };
}

/** `entry << 1`, any other bit is refused. */
function layout(value: unknown): AuditLayout {
  const flags = count(value);
  if ((flags & ~2) !== 0) throw new Error(`layout ${flags}`);
  return { entry: (flags & 2) !== 0 };
}

function envelope(item: Json): AuditEnvelopeProofInputs {
  return {
    firstNullifier: field(item["firstNullifier"]),
    txViewingSk: bytes<Bytes32>(item["txViewingSk"], 32),
    auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
    salt: bytes<Bytes16>(item["salt"], 16),
    layout: layout(item["layout"]),
  };
}

function outputOpening(value: unknown): OutputOpeningProofInput {
  const item = record(value);
  return {
    output: opening(item["output"]),
    ownerKey: bytes<Bytes32>(item["ownerKey"], 32),
    mintChunks: fields(item["mintChunks"]),
    recipientKey: bytes<Bytes32>(item["recipientKey"], 32),
  };
}

function entryOpening(value: unknown): EntryOpeningProofInput {
  const item = record(value);
  return {
    ownerKey: bytes<Bytes32>(item["ownerKey"], 32),
    mintChunks: fields(item["mintChunks"]),
  };
}

function trackingRecord(value: unknown): TrackingRecord {
  const item = record(value);
  return {
    member: field(item["member"]),
    next: field(item["next"]),
    ...trackingFields(item),
  };
}

function trackingFields(item: Json): Omit<TrackingEntry, "member"> {
  return {
    nullifierPk: field(item["nullifierPk"]),
    ctHash: field(item["ctHash"]),
    listTag: field(item["listTag"]),
  };
}

function trackingSection(item: Json): TrackingProofInputs {
  const proof = record(item["trackingProof"]);
  return {
    trackingRoot: field(item["trackingRoot"]),
    trackingPool: {
      records: list(item["trackingRecords"]).map(trackingRecord),
      canopy: fields(proof["canopy"]),
      paths: list(proof["paths"]).map((value) => {
        const path = record(value);
        return { index: count(path["index"]), siblings: list(path["siblings"]).map(fields) };
      }),
      subjects: list(item["trackingSubjects"]).map((value) => {
        const subject = record(value);
        return { member: field(subject["member"]), recordIndex: count(subject["recordIndex"]) };
      }),
    },
    rowEntries: list(item["rowEntries"]).map(count),
    outputEntries: list(item["outputEntries"]).map(count),
  };
}

function trackingOpening(value: unknown): TrackingOpening | undefined {
  if (value === null) return undefined;
  const item = record(value);
  const path = record(item["path"]);
  const quad = { index: count(path["index"]), siblings: list(path["siblings"]).map(fields) };
  return flag(item["present"])
    ? { kind: "present", record: trackingRecord(item["record"]), path: quad }
    : { kind: "absent", low: trackingRecord(item["record"]), path: quad };
}

function policy(item: Json): PolicyProofInputs {
  const withdrawals = list(item["withdrawals"]).map((value) => {
    const leg = record(value);
    return {
      owner: field(leg["owner"]),
      asset: field(leg["asset"]),
      amount: BigInt(String(leg["amount"])),
    };
  });
  return {
    withdrawalCount: count(item["withdrawalCount"]),
    withdrawalHash: field(item["withdrawalHash"]),
    withdrawals,
    policyHash: field(item["policyHash"]),
    ringId: field(item["ringId"]),
    ownRoot: field(item["ownRoot"]),
    curatorRoot: field(item["curatorRoot"]),
    publicAssets: fields(item["publicAssets"]),
    publicAmounts: fields(item["publicAmounts"]),
    publicGross: fields(item["publicGross"]),
    ...table(item),
    ownPool: recordPool(item["ownRecords"], item["ownProof"], item["ownSubjects"]),
    curatorPool: recordPool(item["curatorRecords"], item["curatorProof"], item["curatorSubjects"]),
    senderEntries: list(item["senderEntries"]).map(ownerEntry),
    ownerEntries: list(item["ownerEntries"]).map(ownerEntry),
    assetEntries: list(item["assetEntries"]).map(entry),
    publicAssetEntries: list(item["publicAssetEntries"]).map(count),
  };
}

function write(value: unknown): RecordWriteProofInput {
  const item = record(value);
  const queued = record(item["entry"]);
  return {
    entry: {
      member: field(queued["member"]),
      mask: BigInt(count(queued["mask"])),
      value: BigInt(count(queued["value"])),
      ...(amountOf(field(queued["mintPolicy"])) === 0n
        ? {}
        : {
            mintPolicy: mintSettings(
              queued["mintPolicy"],
              queued["withdrawalThreshold"],
              queued["assetLimits"],
            ),
          }),
    },
    exists: flag(item["exists"]),
    oldNext: field(item["oldNext"]),
    oldLists: BigInt(count(item["oldLists"])),
    oldMintPolicy: mintSettings(
      item["oldMintPolicy"],
      item["oldWithdrawalThreshold"],
      item["oldAssetLimits"],
    ),
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
    },
    lowPath: quadPath(item["lowIndex"], item["lowPath"]),
  };
}

function trackingWrite(value: unknown): TrackingWriteProofInput {
  const item = record(value);
  return {
    entry: { member: field(item["member"]), ...trackingFields(item) },
    slot: quadPath(item["index"], item["path"]),
    lowRecord: trackingRecord(item["lowRecord"]),
    lowPath: quadPath(item["lowIndex"], item["lowPath"]),
  };
}

/** The typed request a golden file holds, built field by field. */
function request(item: Json): RingProofRequest {
  const circuitType = text(item["circuitType"]);
  const publicInputHash = field(item["publicInputHash"]);
  const applied = () => ({
    publicInputHash,
    oldRoot: field(item["oldRoot"]),
    newRoot: field(item["newRoot"]),
    oldNextIndex: count(item["oldNextIndex"]),
    newNextIndex: count(item["newNextIndex"]),
    chainStart: field(item["chainStart"]),
    chainEnd: field(item["chainEnd"]),
  });
  if (circuitType.startsWith("custom-ring-transfer-"))
    return {
      kind: "transfer",
      publicInputHash,
      ...envelope(item),
      inProof: flag(item["inProof"]),
      hidden: flag(item["hidden"]),
      delegate: flag(item["delegate"]),
      sender: field(item["sender"]),
      partyIdentities: fields(item["partyIdentities"]),
      approvalMask: count(item["approvalMask"]),
      ...(item["approvalTotals"] === undefined
        ? {}
        : { approvalTotals: field(item["approvalTotals"]) }),
      ...(item["approvalBlinder"] === undefined
        ? {}
        : { approvalBlinder: field(item["approvalBlinder"]) }),
      outputCount: count(item["outputCount"]),
      outputs: list(item["outputs"]).map(outputOpening),
      inputCount: count(item["inputCount"]),
      addressChain: field(item["addressChain"]),
      inputs: list(item["inputs"]).map(opening),
      entries: item["entries"] === undefined ? [] : list(item["entries"]).map(entryOpening),
      signerCount: count(item["signerCount"]),
      signers: fields(item["signers"]),
      rows: fields(item["rows"]),
      privateTxHash: field(item["privateTxHash"]),
      ...trackingSection(item),
      ...policy(item),
    };
  if (circuitType.startsWith("custom-ring-apply-records-"))
    return {
      kind: "applyRecords",
      ...applied(),
      writes: list(item["writes"]).slice(0, count(item["count"])).map(write),
      ...(item["privateWrites"] === undefined
        ? {}
        : {
            private: {
              privateWrites: count(item["privateWrites"]),
              trackingRoot: field(item["trackingRoot"]),
              owners: list(item["owners"]).map((value) => {
                if (value === null) return undefined;
                const owner = record(value);
                return {
                  listSalt: field(owner["listSalt"]),
                  record: trackingRecord(owner["record"]),
                  path: quadPath(owner["index"], owner["path"]),
                };
              }),
            },
          }),
    };
  if (circuitType.startsWith("custom-ring-apply-enrollments-"))
    return {
      kind: "applyEnrollments",
      ...applied(),
      oldNextIndex: BigInt(count(item["oldNextIndex"])),
      newNextIndex: BigInt(count(item["newNextIndex"])),
      writes: list(item["writes"]).slice(0, count(item["count"])).map(trackingWrite),
    };
  if (circuitType === "custom-ring-register-key")
    return {
      kind: "registerKey",
      publicInputHash,
      ringId: field(item["ringId"]),
      member: field(item["member"]),
      nullifierSecret: bytes<Bytes32>(item["nullifierSecret"], 32),
      listSalt: bytes<Bytes32>(item["listSalt"], 32),
      ephSk: bytes<Bytes32>(item["ephSk"], 32),
      auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
    };
  if (circuitType === "custom-ring-merge")
    return {
      kind: "merge",
      publicInputHash,
      outputUtxoHash: field(item["outputUtxoHash"]),
      firstNullifier: field(item["firstNullifier"]),
      ringProgramId: field(item["ringProgramId"]),
      auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
      payer: field(item["payer"]),
      trackingRoot: field(item["trackingRoot"]),
      ephSk: bytes<Bytes32>(item["ephSk"], 32),
      recipientKey: bytes<Bytes32>(item["recipientKey"], 32),
      ownerKey: bytes<Bytes32>(item["ownerKey"], 32),
      ownerPkHash: field(item["ownerPkHash"]),
      mintChunks: fields(item["mintChunks"]),
      asset: field(item["asset"]),
      amount: field(item["amount"]),
      nullifierPk: field(item["nullifierPk"]),
      seed: field(item["seed"]),
      outputTreeId: field(item["outputTreeId"]),
      outputRingDataHash: field(item["outputRingDataHash"]),
      ...(item["tracking"] === null
        ? {}
        : { tracking: trackingOpening(item["tracking"]) as TrackingOpening }),
    };
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
    const item = golden(circuitType);
    expectReencoded(item);
    // Go goldens fix the key order, the strict decoder takes any.
    expect(JSON.stringify(ringProofRequestBody(request(item)))).toBe(JSON.stringify(item));
  });

  it("names the merge key the prover loads and refuses a shape no ring key serves", () => {
    expect(ringProvingKey({ family: "merge" })).toEqual({
      name: "custom_ring_merge.key",
      sha256: RING_PROVING_KEY_SHA256S["custom_ring_merge.key"],
    });
    expect(() =>
      ringProvingKey({
        family: "transfer",
        outputs: 3,
        class: 40,
        withdrawals: 4,
        owners: 4,
        entry: false,
        wide: false,
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_SHAPE" }));
  });
});

function recorded(fixture: Fixture): TransferProofRequest {
  const found = fixture.ringRequests.find((item) => item.kind === "transfer");
  if (found === undefined) throw new Error("no transfer request");
  return found as TransferProofRequest;
}

const assets = new AssetRegistry();

async function confidentialRequest(
  options: Readonly<{ policy?: boolean; inProof?: boolean }> = {},
): Promise<TransferProofRequest> {
  const signing = SigningKey.generate();
  const sender = ShieldedKeypair.fromKeypair(signing);
  const recipient = ShieldedKeypair.generate();
  const fixture = await ringFixture(
    options.policy === true ? { table: buildRuleTable({ rules: [] }), records: [] } : {},
  );
  fixture.enroll(sender.shieldedAddress());
  fixture.enroll(recipient.shieldedAddress());
  const transfer = new ConfidentialTransfer(
    sender.shieldedAddress(),
    [noteInput(sender, 1_000n, fixture.ringProgramId)],
    fixture.authority,
  );
  transfer.send(recipient.shieldedAddress(), SOL_MINT, 400n);
  const rail = CustomRingTransfer.new({
    ringProgramId: fixture.ringProgramId,
    keys: walletKeys(sender),
    transfer,
    assets,
  });
  await (
    options.inProof === true ? rail.withInProofOwner(signingKeySpendSigner(signing)) : rail
  ).prove(fixture.client);
  return recorded(fixture);
}

async function anonymousRequest(
  options: Readonly<{ entry?: boolean; policy?: boolean }> = {},
): Promise<TransferProofRequest> {
  const signing = SigningKey.generate();
  const sender = ShieldedKeypair.fromKeypair(signing);
  const bob = ShieldedKeypair.generate();
  const fixture = await ringFixture({
    mode: "anonymous",
    ...(options.policy === true ? { table: buildRuleTable({ rules: [] }), records: [] } : {}),
  });
  fixture.enroll(sender.shieldedAddress());
  fixture.enroll(bob.shieldedAddress());
  const transfer = new ConfidentialTransfer(
    sender.shieldedAddress(),
    [noteInput(sender, 1_000n, options.entry === true ? undefined : fixture.ringProgramId)],
    fixture.authority,
  );
  await CustomRingTransfer.new({
    ringProgramId: fixture.ringProgramId,
    keys: walletKeys(sender),
    transfer,
    assets,
  })
    .withAnonymousSigner(signingKeySpendSigner(signing))
    .withPayment({
      to: new RingAddress({
        recipient: bob.shieldedAddress(),
        ringProgramId: fixture.ringProgramId,
        listSalt: new Uint8Array(32).fill(1) as Bytes32,
      }),
      asset: SOL_MINT,
      amount: 400n,
      reply: null,
    })
    .prove(fixture.client);
  return recorded(fixture);
}

const GO_PARAMS = readFileSync(
  new URL("../../../../prover/ring/params.go", import.meta.url),
  "utf8",
);

/** The JSON keys of a Go struct in declaration order, embedded structs promoted. */
function goKeys(name: string): readonly string[] {
  const body = new RegExp(`type ${name} struct \\{([\\s\\S]*?)\\n\\}`, "u").exec(GO_PARAMS)?.[1];
  if (body === undefined) throw new Error(`no Go struct ${name}`);
  return body.split("\n").flatMap((line) => {
    if (line.trim().startsWith("//")) return [];
    const tag = /json:"([A-Za-z0-9]+)/u.exec(line)?.[1];
    if (tag !== undefined) return [tag];
    const embedded = /^\s*([A-Z]\w+)\s*$/u.exec(line)?.[1];
    return embedded === undefined ? [] : goKeys(embedded);
  });
}

const CONFIDENTIAL = await confidentialRequest();
const ANONYMOUS = await anonymousRequest();
const ENTRY = await anonymousRequest({ entry: true });

describe("ring prover requests of the rails", () => {
  it("sends the keys of the Go params in declaration order", () => {
    const keys = goKeys("TransferParams");
    expect(Object.keys(ringProofRequestBody(ENTRY))).toEqual(keys);
    const off = keys.filter((key) => key !== "entries");
    expect(Object.keys(ringProofRequestBody(CONFIDENTIAL))).toEqual(off);
    expect(Object.keys(ringProofRequestBody(ANONYMOUS))).toEqual(off);
    const keysOfSlot = (request: RingProofRequest) =>
      Object.keys(record(list(ringProofRequestBody(request)["outputs"])[0]));
    expect(keysOfSlot(CONFIDENTIAL)).toEqual(goKeys("OutputOpening"));
  });

  it("encodes the full u64 withdrawal range exactly and rejects overflow", () => {
    const [leg, ...rest] = CONFIDENTIAL.withdrawals;
    if (leg === undefined) throw new Error("request without a withdrawal slot");
    const body = ringProofRequestBody({
      ...CONFIDENTIAL,
      withdrawals: [{ ...leg, amount: 0xffff_ffff_ffff_ffffn }, ...rest],
    });
    expect((body["withdrawals"] as { amount: string }[])[0]?.amount).toBe(
      "0x" + "00".repeat(24) + "ff".repeat(8),
    );
    for (const amount of [-1n, 1n << 64n])
      expect(() =>
        ringProofRequestBody({
          ...CONFIDENTIAL,
          withdrawals: [{ ...leg, amount }, ...rest],
        }),
      ).toThrow();
  });

  it("refuses a request no key serves or the strict decoder would refuse", () => {
    const base = CONFIDENTIAL;
    const [first, ...rest] = base.outputs;
    if (first === undefined) throw new Error("no delivered output");
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
        outputs: [{ ...first, ownerKey: first.ownerKey.slice(1) as Bytes32 }, ...rest],
      }),
    ).toThrow(
      expect.objectContaining({
        code: "CLIENT_INVALID_LENGTH",
        details: { field: "outputs[0].ownerKey", expected: 32, actual: 31 },
      }),
    );
    const unknown = { ...base };
    Reflect.set(unknown, "kind", "other");
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

  it("sends the entries on the entry key alone", () => {
    expect(ringProofRequestBody(ANONYMOUS)).not.toHaveProperty("entries");
    expect(ringProofRequestBody(ENTRY)).toHaveProperty("entries");
    expect(() => ringProofRequestBody({ ...ENTRY, entries: ENTRY.entries.slice(1) })).toThrow(
      expect.objectContaining({ code: "CLIENT_INVALID_LENGTH" }),
    );
  });

  it("reads every body field back and rebuilds each rail's statement from the request", async () => {
    for (const typed of [
      CONFIDENTIAL,
      await confidentialRequest({ policy: true }),
      await confidentialRequest({ inProof: true }),
    ]) {
      expectReencoded(JSON.parse(JSON.stringify(ringProofRequestBody(typed))));
      checkTransferStatement(typed);
    }
    for (const typed of [ANONYMOUS, ENTRY, await anonymousRequest({ policy: true })]) {
      expectReencoded(JSON.parse(JSON.stringify(ringProofRequestBody(typed))));
      checkTransferStatement(typed);
    }
  });
});

// Go solves every Rust fixture, a TS body equal to it assigns the same witness.
describe("ring prover request encoding against the Rust fixtures", () => {
  it("finds a Rust transfer fixture", () => {
    expect(RUST_TRANSFER_FIXTURES.length).toBeGreaterThan(0);
  });

  it.each(RUST_TRANSFER_FIXTURES)("encodes %s field for field", (name) => {
    expectReencoded(record(JSON.parse(readFileSync(new URL(name, RUST_FIXTURES), "utf8"))));
  });

  it.each(RUST_TRANSFER_FIXTURES)("rebuilds the statement of %s", (name) => {
    const typed = request(record(JSON.parse(readFileSync(new URL(name, RUST_FIXTURES), "utf8"))));
    if (typed.kind !== "transfer") throw new Error("transfer fixture");
    checkTransferStatement(typed);
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
        typed.listSalt,
        X25519PublicKey.fromBytes(tagged(typed.auditorPk)),
      );
      const statement = {
        ringId: typed.ringId,
        member: typed.member,
        nullifierPk: envelope.nullifierPublicKey,
        listTag: listTagOf(typed.listSalt),
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

  it.each(CIRCUIT_TYPES.filter((name) => name.startsWith("custom-ring-transfer-")))(
    "rebuilds %s from its secrets and openings",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "transfer") throw new Error("transfer golden");
      checkTransferStatement(typed);
    },
  );
});

/** Go `assertMint`, the mint's 31 and 1 byte chunks. */
function mintOf(chunks: readonly Bytes32[]): Address {
  const [high, low] = chunks;
  if (high === undefined || low === undefined) throw new Error("mint chunks");
  return encodeBase58(Uint8Array.of(...high.subarray(1), ...low.subarray(31)));
}

/** The stream and every slot's record are deterministic under the transfer's key and salt. */
function checkTransferStatement(typed: TransferProofRequest): void {
  const slots = typed.outputs.slice(0, typed.outputCount);
  // The proof's input slots hold the notes in note order, then dummies.
  const notes = typed.inputs.filter(isUtxo);
  const layout: AuditStreamLayout = {
    key: { class: typed.inputs.length, entry: typed.layout.entry },
    inputs: typed.inputCount,
    outputs: typed.outputCount,
    capacity: typed.outputs.length,
  };
  const evidence = typed.layout.entry
    ? {
        kind: "entry" as const,
        defaultNoteBits: notes.reduce(
          (bits, note, at) =>
            amountOf(note.ringProgramId) === 0n ? bits | (1n << BigInt(at)) : bits,
          0n,
        ),
        inputs: Array.from({ length: typed.inputCount }, (_, at) => {
          const note = notes[at];
          const entry = typed.entries[at];
          // A ring note's and a padding position's evidence stays zero.
          if (note === undefined || entry === undefined || amountOf(note.ringProgramId) !== 0n)
            return EMPTY_ENTRY_RECORD;
          return {
            ownerKey: entry.ownerKey,
            nullifierPk: note.nullifierPk,
            amount: amountOf(note.amount),
            mint: mintOf(entry.mintChunks),
            inputCommitment: openingHash(note),
          };
        }),
      }
    : ({ kind: "none" } as const);
  const auditor = X25519PublicKey.fromBytes(tagged(typed.auditorPk));
  const sealed = sealSaltedAuditorStream({
    txViewingSecret: typed.txViewingSk,
    salt: typed.salt,
    auditorPublicKey: auditor,
    envelope: encodeAuditEnvelope({
      txViewingSecret: typed.txViewingSk,
      realInputs: notes.length,
      evidence,
    }),
    recipientKeys: slots.map((slot, at) => ({
      counter: recipientKeyRegion(layout, at).startCounter,
      bytes: slot.recipientKey,
    })),
  });
  const txKey = ViewingKey.fromBytes(typed.txViewingSk.slice() as Bytes32);
  const records = slots.map((slot, at) => {
    const { output } = slot;
    const record = isUtxo(output)
      ? {
          kind: isRingOutput(output) ? RecordKind.ring : RecordKind.exit,
          amount: amountOf(output.amount),
          ownerKey: slot.ownerKey,
          mint: mintOf(slot.mintChunks),
          nullifierPk: output.nullifierPk,
          blinding: output.blinding,
        }
      : DUMMY_RECORD;
    const secret = txKeySlotSecret({
      txViewingKey: txKey,
      recipientViewingKey: x25519FromU(slot.recipientKey),
      salt: typed.salt,
      outputIndex: at,
      firstNullifier: typed.firstNullifier,
    });
    return sealOutputSlot(secret, { record });
  });
  txKey.destroy();
  const txViewingU = publicKeyOf(typed.txViewingSk).u();
  const parties = typed.partyIdentities.some((party) => !isZero(party));
  const statement: TransferStatement = {
    head: {
      firstNullifier: typed.firstNullifier,
      ringId: typed.ringId,
      txViewingU,
      auditorPubkey: tagged(typed.auditorPk),
      envelope: sealed.envelope,
      recipientKeys: concatBytes(...sealed.recipientKeys),
      salt: typed.salt,
      layout: typed.layout,
    },
    family:
      typed.hidden || parties
        ? {
            kind: "anonymous",
            partyIdentities: typed.partyIdentities,
            publicOwners: !typed.hidden && !typed.delegate,
            delegate: typed.delegate,
          }
        : {
            kind: "confidential",
            inProof: typed.inProof,
            delegate: typed.delegate,
            sender: typed.sender,
          },
    approvalMask: typed.approvalMask,
    approvalTotals: typed.approvalTotals ?? ZERO_32,
    noSpend: notes.length === 0,
    outputs: records.map((record) => ({ record })),
    capacity: typed.outputs.length,
    inputCount: typed.inputCount,
    privateTxHash: typed.privateTxHash,
    signers: signerBinding(typed.signers.slice(0, typed.signerCount), typed.inputs.length),
    roots: {
      policyHash: typed.policyHash,
      ownRoot: typed.ownRoot,
      curatorRoot: typed.curatorRoot,
      trackingRoot: typed.trackingRoot,
    },
    publicAssets: typed.publicAssets,
    publicAmounts: typed.publicAmounts,
    publicGross: typed.publicGross,
    withdrawalHash: typed.withdrawalHash,
  };
  expect(hex(transferStatementHash(statement))).toBe(hex(typed.publicInputHash));
}

function expectReencoded(item: Json): void {
  const typed = request(item);
  const body = ringProofRequestBody(typed);
  expect(body).toEqual(item);
  expect(ringCircuitType(ringProofCircuit(typed))).toBe(text(item["circuitType"]));
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

describe("tracking apply requests", () => {
  const ZERO_PATH = (height: number) => ({
    index: 0,
    siblings: Array.from({ length: height }, () => [ZERO_32, ZERO_32, ZERO_32]),
  });
  const head = {
    publicInputHash: ZERO_32,
    oldRoot: ZERO_32,
    newRoot: ZERO_32,
    chainStart: ZERO_32,
    chainEnd: ZERO_32,
  };
  const WRITE: RecordWriteProofInput = {
    entry: { member: ZERO_32, mask: 1n, value: 1n },
    exists: true,
    oldNext: ZERO_32,
    oldLists: 0n,
    oldMintPolicy: EMPTY_MINT_POLICY,
    slot: ZERO_PATH(QUAD_HEIGHT),
    low: SENTINEL_RECORD,
    lowPath: ZERO_PATH(QUAD_HEIGHT),
  };
  const OWNER = {
    listSalt: ZERO_32,
    record: TRACKING_SENTINEL,
    path: ZERO_PATH(TRACKING_QUAD_HEIGHT),
  };
  const privateApply = (privateWrites: number, owners: readonly (typeof OWNER | undefined)[]) =>
    ({
      kind: "applyRecords",
      ...head,
      oldNextIndex: 1,
      newNextIndex: 2,
      writes: [WRITE, WRITE],
      private: { privateWrites, trackingRoot: TRACKING_EMPTY_ROOT, owners },
    }) satisfies RingProofRequest;

  it("proves a private write's owner row under the tracking root on the private key", () => {
    const request = privateApply(0b10, [undefined, OWNER]);
    expect(ringCircuitType(ringProofCircuit(request))).toBe("custom-ring-apply-records-private-2");
    const body = ringProofRequestBody(request);
    expect(body["privateWrites"]).toBe(2);
    expect(body["trackingRoot"]).toBe(hex(TRACKING_EMPTY_ROOT));
    expect(Object.keys(body).slice(-3)).toEqual(["privateWrites", "trackingRoot", "owners"]);
    const owners = list(body["owners"]);
    expect(owners[0]).toBeNull();
    expect(Object.keys(record(owners[1]))).toEqual(["listSalt", "record", "index", "path"]);
    expect(list(record(owners[1])["path"])).toHaveLength(3 * TRACKING_QUAD_HEIGHT);
    expect(body).not.toHaveProperty("credentialWrites");
  });

  it("refuses an empty private mask and more owners than the key's width", () => {
    expect(() => ringProofRequestBody(privateApply(0, [undefined, OWNER]))).toThrow();
    expect(() => ringProofRequestBody(privateApply(0b10, [undefined, OWNER, OWNER]))).toThrow(
      expect.objectContaining({ details: { field: "owners", expected: 2, actual: 3 } }),
    );
  });

  it("states enrollment indices as u64 up to the tree's capacity", () => {
    const enrollments = (newNextIndex: bigint) =>
      ({
        kind: "applyEnrollments",
        ...head,
        oldNextIndex: newNextIndex - 1n,
        newNextIndex,
        writes: [
          {
            entry: TRACKING_SENTINEL,
            slot: ZERO_PATH(TRACKING_QUAD_HEIGHT),
            lowRecord: TRACKING_SENTINEL,
            lowPath: ZERO_PATH(TRACKING_QUAD_HEIGHT),
          },
        ],
      }) satisfies RingProofRequest;
    const full = ringProofRequestBody(enrollments(1n << 32n));
    expect(ringCircuitType(ringProofCircuit(enrollments(2n)))).toBe(
      "custom-ring-apply-enrollments-1",
    );
    expect(Object.keys(full).slice(2, 8)).toEqual([
      "oldRoot",
      "newRoot",
      "oldNextIndex",
      "newNextIndex",
      "chainStart",
      "chainEnd",
    ]);
    expect(full["newNextIndex"]).toBe(2 ** 32);
    expect(() => ringProofRequestBody(enrollments((1n << 32n) + 1n))).toThrow(
      expect.objectContaining({ details: { field: "newNextIndex", length: 8 } }),
    );
  });
});
