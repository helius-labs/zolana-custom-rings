import { DisclosureFormat } from "../../../src/protocol/codec/ring-disclosure-layout.js";
import { getBase58Decoder, type Signature } from "@solana/kit";
import { hexToBytes } from "@noble/hashes/utils.js";
import { beforeAll, describe, expect, it } from "vitest";

import auditVector from "../../../../../test-vectors/audit/audit-stream.json" with { type: "json" };
import mergeVector from "../../../../../test-vectors/merge/merge.json" with { type: "json" };
import { initializePoseidon, SHIELDED_POOL_PROGRAM_ID } from "@heliuslabs/spr";
import {
  Writer,
  ZERO_32,
  ZERO_NULLIFIER_PK,
  addressBytes,
  encodeBase58,
  encodeMergeOutputData,
  equalBytes,
  hashBytes,
  poseidon,
  treeAddress,
} from "@heliuslabs/spr/internal";
import {
  seededMergeDummyNullifier,
  seededMergeOutputBlinding,
} from "../../../src/crypto/derivation/merge-seed.js";
import { InstructionTag } from "@heliuslabs/spr/interface";
import type { Bytes16, Bytes32, Bytes33 } from "@heliuslabs/spr/interface";
import { ViewingKey, X25519Keypair } from "@heliuslabs/spr/keypair";
import type { IndexedShieldedTransaction } from "@heliuslabs/spr/transaction";

import { readFileSync } from "node:fs";

import { saltedAuditorSchedule } from "../../../src/crypto/audit/audit.js";
import {
  MergeRingAuthority,
  decodeRingMergeRequest,
  forwardedMergeData,
  openMergeRecord,
  sealMergeRecord,
  sppMergeBody,
} from "../../../src/crypto/audit/merge-disclosure.js";
import { ringIdField } from "../../../src/crypto/derivation/ring-stream.js";
import {
  classifyMergeNullifier,
  openRingMerge,
} from "../../../src/operations/audit/audit-merge.js";
import {
  KnownUtxoIndex,
  knownUtxoHash,
  openRingTransfer,
  type KnownUtxo,
  type TransactionAuditInput,
} from "../../../src/operations/audit/audit.js";
import {
  decodeAuditEnvelope,
  decodeAuditRecord,
  decodeCompactAuditRecord,
  EMPTY_ENTRY_RECORD,
  encodeAuditEnvelope,
  RecordKind,
} from "../../../src/protocol/codec/audit-stream.js";
import {
  recordRegion,
  type AuditStreamLayout,
} from "../../../src/protocol/codec/ring-disclosure-layout.js";
import {
  RpcTransactionOrigin,
  ringWithdrawalsOf,
} from "../../../src/protocol/transaction/origin.js";
import { encodeRingTransactInstructionData } from "../../../src/protocol/proof/circuit.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";

const hex = (value: string): Uint8Array => hexToBytes(value.replace(/^0x/u, ""));
const field = (value: string): Bytes32 => hex(value) as Bytes32;
const ring = encodeBase58(new Uint8Array(32).fill(0x90));
const auditor = (): X25519Keypair => X25519Keypair.fromBytes(field(auditVector.auditor_sk));
const SIGNATURE = "5".repeat(87) as Signature;
const SALT = hex(auditVector.salt) as Bytes16;
const TREE_ID = auditVector.output_tree_id;
const SECOND_NULLIFIER = field(`${"00".repeat(31)}77`);

type Case = (typeof auditVector.cases)[number];
const caseNamed = (name: string): Case => {
  const found = auditVector.cases.find((entry) => entry.name === name);
  if (found === undefined) throw new Error(name);
  return found;
};

function layoutOf(entry: Case): AuditStreamLayout {
  return {
    key: {
      class: entry.input_class,
      entry: (entry.layout & 2) !== 0,
      format:
        (entry.layout & 4) !== 0 ? DisclosureFormat.SingleAssetPayout : DisclosureFormat.Standard,
    },
    inputs: entry.input_count,
    outputs: entry.output_count,
    capacity: entry.outputs,
    hasData: (entry.layout & 1) !== 0,
  };
}

interface StreamEdits {
  readonly envelope?: Uint8Array;
  /** Plaintext by slot, resealed at the slot's own counter. */
  readonly records?: ReadonlyMap<number, Uint8Array>;
}

function audited(entry: Case, edits: StreamEdits = {}, rest: Partial<TransactionAuditInput> = {}) {
  const layout = layoutOf(entry);
  const txViewingKey = ViewingKey.fromBytes(field(auditVector.tx_viewing_sk)).publicKey();
  const schedule = saltedAuditorSchedule(auditor(), txViewingKey, SALT);
  const envelope =
    edits.envelope === undefined
      ? hex(entry.envelope_ciphertext)
      : schedule.apply(2, edits.envelope);
  const records = entry.record_ciphertexts.map((record, slot) => {
    const edited = edits.records?.get(slot);
    return edited === undefined
      ? hex(record)
      : schedule.apply(recordRegion(layout, slot).startCounter, edited);
  });
  const tails = (entry.tail_ciphertexts ?? []).map(hex);
  const message = Uint8Array.from([
    ...txViewingKey.toBytes(),
    ...envelope,
    ...records.flatMap((record) => [...record]),
    ...tails.flatMap((tail) => [...tail]),
  ]);
  const transaction: IndexedShieldedTransaction = {
    slot: 7n,
    txSignature: SIGNATURE,
    eventIndex: 0,
    proofless: false,
    ringProgramId: ring,
    txViewingPublicKey: txViewingKey,
    salt: SALT,
    // Only the first nullifier seeds the stream, the rest fill the published count.
    nullifiers: [
      field(auditVector.first_nullifier),
      ...Array.from({ length: entry.input_count - 1 }, (_, slot) =>
        slot === 0 ? SECOND_NULLIFIER : field(`${"00".repeat(31)}${(0x78 + slot).toString(16)}`),
      ),
    ],
    messages: [{ viewTag: auditor().publicKey().u(), data: message }],
    outputSlots: entry.output_hashes.map((hash, index) => ({
      viewTag: new Uint8Array(32).fill(index + 1) as Bytes32,
      payload: new Uint8Array(),
      outputContext: {
        hash: field(hash),
        tree: treeAddress(TREE_ID),
        treeId: TREE_ID,
        leafIndex: BigInt(index),
      },
    })),
  };
  return openRingTransfer({
    auditor: auditor(),
    transaction,
    layout,
    rail: "confidential",
    // The statement's `no_spend` bit, an address input alone sends no note.
    noSpend:
      rest.noSpend ?? decodeAuditEnvelope(hex(entry.envelope_plaintext), layout).realInputs === 0,
    ...rest,
  });
}

function envelopeOf(entry: Case, edit: (bytes: Uint8Array) => void): Uint8Array {
  const bytes = hex(entry.envelope_plaintext);
  edit(bytes);
  return bytes;
}

beforeAll(async () => {
  await initializePoseidon();
});

describe("the transfer reader", () => {
  it("rebuilds every slot of every vector from the stream with no registry", () => {
    expect(equalBytes(ringIdField(ring), field(auditVector.ring_id))).toBe(true);
    for (const entry of auditVector.cases) {
      const { evidence } = decodeAuditEnvelope(hex(entry.envelope_plaintext), layoutOf(entry));
      const { audited: row } = audited(entry);
      expect(row.payloadErrors).toEqual([]);
      expect(row.outputs).toHaveLength(entry.output_count);
      row.outputs.forEach((output, slot) => {
        const plaintext = hex(entry.records[slot] as string);
        const record =
          evidence.kind === "singleAssetPayout"
            ? decodeCompactAuditRecord(plaintext, evidence.mint)
            : decodeAuditRecord(plaintext);
        const expected = ["dummy", "ring", "exit"][record.kind];
        expect(output.opening.kind).toBe(expected);
        if (output.opening.kind === "ring" || output.opening.kind === "exit")
          expect(output.opening.utxo.mint).toBe(record.mint);
      });
    }
  });

  it("reads a record at another slot as a commitment error", () => {
    const entry = caseNamed("plain_with_exit_and_dummy");
    const { audited: row } = audited(entry, {
      records: new Map([[0, hex(entry.records[1] as string)]]),
    });
    expect(row.payloadErrors).toEqual([{ slotIndex: 0, kind: "commitment" }]);
  });

  it("reads a kind off the three and a noncanonical key as a disclosure error", () => {
    const entry = caseNamed("plain_with_exit_and_dummy");
    const badKind = hex(entry.records[0] as string);
    badKind[0] = 3;
    const noncanonical = hex(entry.records[1] as string);
    noncanonical.fill(0xff, 73, 105);
    const { audited: row } = audited(entry, {
      records: new Map([
        [0, badKind],
        [1, noncanonical],
      ]),
    });
    expect(row.payloadErrors).toEqual([
      { slotIndex: 0, kind: "disclosure" },
      { slotIndex: 1, kind: "disclosure" },
    ]);
  });

  it("refuses a dummy record on a live slot by its commitment", () => {
    const entry = caseNamed("plain_with_exit_and_dummy");
    const { audited: row } = audited(entry, { records: new Map([[0, new Uint8Array(105)]]) });
    expect(row.payloadErrors).toEqual([{ slotIndex: 0, kind: "commitment" }]);
  });

  it("refuses R past the frame, a default bit past the notes and a clear noSpend under R zero", () => {
    const entry = caseNamed("entry");
    const refusal = (reason: string) =>
      expect.objectContaining({ code: "RING_AUDIT_MESSAGE", details: { reason } });
    const pastFrame = envelopeOf(entry, (bytes) => {
      bytes[32] = 3;
    });
    expect(() => audited(entry, { envelope: pastFrame })).toThrow(refusal("envelope"));
    const bitPastNotes = envelopeOf(entry, (bytes) => {
      bytes[32] = 1;
    });
    expect(() => audited(entry, { envelope: bitPastNotes })).toThrow(refusal("envelope"));
    const onAddress = envelopeOf(entry, (bytes) => {
      bytes[32] = 1;
      bytes[40] = 2;
    });
    expect(() => audited(entry, { envelope: onAddress })).toThrow(refusal("envelope"));
    const noReal = envelopeOf(entry, (bytes) => {
      bytes[32] = 0;
      bytes.fill(0, 33);
    });
    expect(() => audited(entry, { envelope: noReal })).toThrow(refusal("no spend"));
  });

  it("names the key a forged envelope seals", () => {
    const entry = caseNamed("compact");
    const forged = envelopeOf(entry, (bytes) => {
      bytes.set(ViewingKey.generate().secretBytes(), 0);
    });
    expect(() => audited(entry, { envelope: forged })).toThrow(
      expect.objectContaining({
        code: "RING_AUDIT_KEY_MISMATCH",
        details: { transactionId: expect.any(String) },
      }),
    );
  });

  it("reads padding past the notes, an address apart, a default bit from its evidence and an unknown note as unresolved", () => {
    const entry = caseNamed("entry");
    const { audited: row, realInputs } = audited(entry);
    expect(realInputs).toBe(2);
    expect(row.inputs[0]?.opening).toEqual({ kind: "unresolvedReal" });
    const external = row.inputs[1];
    expect(external?.opening.kind).toBe("external");
    if (external?.opening.kind !== "external") throw new Error("external");
    expect(external.hash).toEqual(external.opening.commitment);
    const padded = envelopeOf(entry, (bytes) => {
      bytes[32] = 1;
      bytes.fill(0, 33);
    });
    expect(
      audited(entry, { envelope: padded }).audited.inputs.map((input) => input.opening.kind),
    ).toEqual(["unresolvedReal", "dummy"]);
    // Input 0 an address, the default note at input 1 still opens from its evidence.
    const address = envelopeOf(entry, (bytes) => {
      bytes[32] = 1;
      bytes[40] = 1;
    });
    expect(
      audited(entry, { envelope: address }).audited.inputs.map((input) => input.opening.kind),
    ).toEqual(["address", "external"]);
  });

  describe("an entry record", () => {
    const entry = caseNamed("entry");
    const mint = encodeBase58(new Uint8Array(32).fill(0x44));
    const record = {
      ownerKey: new Uint8Array(32).fill(0x31) as Bytes32,
      nullifierPk: field(`${"00".repeat(31)}05`),
      amount: 9n,
      mint,
      inputCommitment: field(`${"00".repeat(31)}21`),
    };
    const envelope = (first: typeof record): Uint8Array =>
      encodeAuditEnvelope({
        txViewingSecret: field(auditVector.tx_viewing_sk),
        realInputs: 2,
        addressInputBits: 0n,
        evidence: { kind: "entry", defaultInputBits: 1n, inputs: [first, EMPTY_ENTRY_RECORD] },
      });
    const refusal = (reason: string) =>
      expect.objectContaining({ code: "RING_AUDIT_MESSAGE", details: { reason } });
    const SPENDS = { noSpend: false };

    it("names the sender and the proven commitment", () => {
      const { audited: row } = audited(entry, { envelope: envelope(record) }, SPENDS);
      expect(row.sender).toEqual({ ownerKey: record.ownerKey, nullifierPk: record.nullifierPk });
      expect(row.inputs[0]).toEqual({
        nullifier: field(auditVector.first_nullifier),
        hash: record.inputCommitment,
        opening: {
          kind: "external",
          ownerKey: record.ownerKey,
          nullifierPk: record.nullifierPk,
          asset: hashBytes(addressBytes(mint, "mint")),
          mint,
          amount: 9n,
          commitment: record.inputCommitment,
        },
      });
      expect(row.inputs[1]?.opening).toEqual({ kind: "unresolvedReal" });
    });

    it("refuses a noncanonical commitment and one a known note under the nullifier contradicts", () => {
      const noncanonical = { ...record, inputCommitment: new Uint8Array(32).fill(0xff) as Bytes32 };
      expect(() => audited(entry, { envelope: envelope(noncanonical) }, SPENDS)).toThrow(
        refusal("entry evidence"),
      );
      const other = field(`${"00".repeat(31)}22`);
      const knownUtxos = {
        utxo: () => undefined,
        byNullifier: (nullifier: Bytes32) =>
          equalBytes(nullifier, field(auditVector.first_nullifier))
            ? { commitment: other, utxo: {} as KnownUtxo }
            : undefined,
      };
      expect(() =>
        audited(entry, { envelope: envelope(record) }, { ...SPENDS, knownUtxos }),
      ).toThrow(refusal("entry commitment"));
    });
  });
});

describe("the note index", () => {
  const blinding = field(`${"00".repeat(31)}05`);
  const commitment = field(`${"00".repeat(31)}21`);
  const note = (nullifierPk: Bytes32): KnownUtxo => ({
    ownerKey: new Uint8Array(32).fill(3) as Bytes32,
    owner: { kind: "keyed", nullifierPk },
    asset: ZERO_32,
    amount: 1n,
    blinding,
    dataHash: ZERO_32,
    ringDataHash: ZERO_32,
    treeId: TREE_ID,
  });

  it("resolves a zero key note with no secret", () => {
    const index = new KnownUtxoIndex([{ commitment, utxo: note(ZERO_NULLIFIER_PK as Bytes32) }]);
    const nullifier = poseidon([commitment, blinding, ZERO_32]) as Bytes32;
    expect(index.byNullifier(nullifier)?.commitment).toEqual(commitment);
  });

  it("recomputes an enrolled note once its secret reads", () => {
    const secret = field(`${"00".repeat(31)}09`);
    const key = poseidon([secret]) as Bytes32;
    const readable = { open: false };
    const index = new KnownUtxoIndex([{ commitment, utxo: note(key) }], {
      secrets: { secret: () => (readable.open ? secret : undefined) },
    });
    const nullifier = poseidon([commitment, blinding, secret]) as Bytes32;
    expect(index.byNullifier(nullifier)).toBeUndefined();
    readable.open = true;
    index.reindexSecrets();
    expect(index.byNullifier(nullifier)?.commitment).toEqual(commitment);
  });
});

describe("the merge reader", () => {
  for (const entry of mergeVector.cases) {
    it(`opens the ${entry.name} record and rebuilds its commitment`, () => {
      const record = openMergeRecord(X25519Keypair.fromBytes(field(mergeVector.auditor_sk)), {
        ephemeralPublicKey: hex(mergeVector.eph_pk) as Bytes33,
        ciphertext: hex(entry.ciphertext),
      });
      const { request } = entry;
      expect(record.secret).toEqual(field(request.seed));
      const blinding = seededMergeOutputBlinding(record.secret, field(request.firstNullifier));
      expect(blinding).toEqual(field(entry.output_blinding));
      const rebuilt = knownUtxoHash(
        {
          ownerKey: record.record.ownerKey,
          owner: { kind: "keyed", nullifierPk: record.record.nullifierPk },
          asset: hashBytes(addressBytes(record.record.mint)) as Bytes32,
          amount: record.record.amount,
          blinding,
          dataHash: ZERO_32,
          ringDataHash: field(request.outputRingDataHash),
          treeId: Number(BigInt(request.outputTreeId)),
        },
        field(request.ringProgramId),
      );
      expect(rebuilt).toEqual(field(request.outputUtxoHash));
    });
  }

  const seed = field(`${"00".repeat(31)}13`);
  const firstNullifier = field(`${"00".repeat(31)}1f`);
  const ownerKey = new Uint8Array(32).fill(9) as Bytes32;
  const mint = encodeBase58(new Uint8Array(32).fill(4));
  const ringDataHash = field(`${"00".repeat(31)}d0`);

  function mergeRow(hash: Bytes32) {
    const { sealed } = sealMergeRecord({
      auditorPublicKey: auditor().publicKey(),
      opening: {
        record: {
          kind: RecordKind.ring,
          amount: 12n,
          ownerKey,
          mint,
          nullifierPk: ZERO_NULLIFIER_PK as Bytes32,
        },
        secret: seed,
      },
    });
    const transaction: IndexedShieldedTransaction = {
      slot: 7n,
      txSignature: SIGNATURE,
      eventIndex: 0,
      proofless: false,
      ringProgramId: ring,
      nullifiers: [
        firstNullifier,
        seededMergeDummyNullifier(seed, firstNullifier, 1),
        SECOND_NULLIFIER,
        ...Array.from({ length: 5 }, (_, slot) =>
          seededMergeDummyNullifier(seed, firstNullifier, slot + 3),
        ),
      ],
      messages: [],
      outputSlots: [
        {
          viewTag: new Uint8Array(32) as Bytes32,
          payload: encodeMergeOutputData({
            ringDataHash,
            salt: new Uint8Array(16) as Bytes16,
            ciphertext: [ZERO_32, ZERO_32, ZERO_32],
          }),
          outputContext: {
            hash,
            tree: treeAddress(TREE_ID),
            treeId: TREE_ID,
            leafIndex: 0n,
          },
        },
      ],
    };
    return {
      kind: "merge" as const,
      transaction,
      sealedRecord: sealed,
      authority: MergeRingAuthority.ownerSigned,
    };
  }

  const commitment = (): Bytes32 =>
    knownUtxoHash(
      {
        ownerKey,
        owner: { kind: "keyed", nullifierPk: ZERO_NULLIFIER_PK as Bytes32 },
        asset: hashBytes(addressBytes(mint)) as Bytes32,
        amount: 12n,
        blinding: seededMergeOutputBlinding(seed, firstNullifier),
        dataHash: ZERO_32,
        ringDataHash,
        treeId: TREE_ID,
      },
      ringIdField(ring),
    );

  it("names the output and classifies padding from the seed", () => {
    const opened = openRingMerge({
      confirmed: mergeRow(commitment()),
      eventIndex: 0,
      auditor: auditor(),
    });
    expect(opened.utxo.mint).toBe(mint);
    expect(opened.nullifiers.map(({ state }) => state.kind)).toEqual([
      "unresolvedReal",
      "padding",
      "unresolvedReal",
      "padding",
      "padding",
      "padding",
      "padding",
      "padding",
    ]);
  });

  it("refuses a record off the published commitment", () => {
    expect(() =>
      openRingMerge({
        confirmed: mergeRow(field(`${"00".repeat(31)}01`)),
        eventIndex: 0,
        auditor: auditor(),
      }),
    ).toThrow(expect.objectContaining({ code: "RING_AUDIT_OUTPUT_MISMATCH" }));
  });

  it("never reads a real nullifier as padding", () => {
    expect(
      classifyMergeNullifier({ seed, firstNullifier, nullifier: SECOND_NULLIFIER, position: 2 })
        .kind,
    ).toBe("unresolvedReal");
  });
});

describe("the origin", () => {
  it("parses SPP's delegate exit circuit", () => {
    const data = encodeRingTransactInstructionData({
      expiryUnixTs: 0n,
      txViewingPk: new Uint8Array(33) as Bytes33,
      salt: new Uint8Array(16) as Bytes16,
      interfaceTransfers: [],
      outputs: [],
      messages: [],
      privateTxHash: ZERO_32,
      circuit: { kind: "ringAuthorityExit", inputs: 1, outputs: 2, publicAssetSlots: 2 },
      proof: { a: ZERO_32, b: new Uint8Array(128) as never, c: ZERO_32 },
      inputs: [{ nullifierHash: ZERO_32, treeIndex: 0 }],
      treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
    });
    expect(
      ringWithdrawalsOf([
        {
          programId: SHIELDED_POOL_PROGRAM_ID,
          accounts: [],
          data: Uint8Array.of(InstructionTag.ringAuthorityTransact, ...data),
        },
      ]),
    ).toEqual([]);
  });

  it("binds a tag 57 merge to its forwarded data and refuses another record", async () => {
    const frame = hex(
      readFileSync(
        new URL("../../../../../test-vectors/merge/merge_frame.hex", import.meta.url),
        "utf8",
      ).trim(),
    );
    const request = decodeRingMergeRequest(frame);
    const forwarded = forwardedMergeData(
      request,
      sppMergeBody(request.compactBody),
      InstructionTag.ringMergeTransact,
    );
    const tree = new Uint8Array(addressBytes(treeAddress(TREE_ID)));
    const event = new Writer()
      .u32(1, "trees")
      .bytes(tree)
      .u64(0n, "queue")
      .bytes(tree)
      .u64(4n, "leaf")
      .bytes(new Uint8Array(32).fill(6))
      .finish();
    const encode = getBase58Decoder();
    const confirmed = (wrapper: Uint8Array) => ({
      slot: 7,
      transaction: {
        signatures: [SIGNATURE],
        message: {
          accountKeys: [ring, SHIELDED_POOL_PROGRAM_ID],
          instructions: [{ programIdIndex: 0, accounts: [], data: encode.decode(wrapper) }],
        },
      },
      meta: {
        err: null,
        innerInstructions: [
          {
            index: 0,
            instructions: [
              { programIdIndex: 1, accounts: [], data: encode.decode(forwarded), stackHeight: 2 },
              {
                programIdIndex: 1,
                accounts: [],
                data: encode.decode(Uint8Array.of(InstructionTag.emitEvent, 3, ...event)),
                stackHeight: 3,
              },
            ],
          },
        ],
      },
    });
    const indexed: IndexedShieldedTransaction = {
      slot: 7n,
      txSignature: SIGNATURE,
      eventIndex: 0,
      proofless: false,
      ringProgramId: ring,
      nullifiers: [new Uint8Array(32).fill(5) as Bytes32],
      messages: [],
      outputSlots: [
        {
          viewTag: new Uint8Array(32).fill(6) as Bytes32,
          payload: encodeMergeOutputData({
            ringDataHash: request.outputRingDataHash,
            salt: new Uint8Array(16).fill(2) as Bytes16,
            ciphertext: [
              new Uint8Array(32).fill(3) as Bytes32,
              new Uint8Array(32).fill(3) as Bytes32,
              new Uint8Array(32).fill(3) as Bytes32,
            ],
          }),
          outputContext: {
            hash: new Uint8Array(32).fill(1) as Bytes32,
            tree: treeAddress(TREE_ID),
            treeId: TREE_ID,
            leafIndex: 4n,
          },
        },
      ],
    };
    const originOver = (wrapper: Uint8Array) =>
      new RpcTransactionOrigin({
        getTransaction: () => ({ send: async () => confirmed(wrapper) }),
      } as never);
    const wrapper = Uint8Array.of(RingInstructionTag.merge, ...frame);
    const bound = await originOver(wrapper).confirmedTransaction(indexed, ring);
    if (bound?.kind !== "merge") throw new Error(bound?.kind);
    expect(bound.authority).toBe(request.authority);
    expect(bound.sealedRecord.ciphertext).toEqual(request.sealed.ciphertext);
    const forged = wrapper.slice();
    forged[8 + 1] = (forged[8 + 1] ?? 0) ^ 1;
    await expect(originOver(forged).confirmedTransaction(indexed, ring)).rejects.toMatchObject({
      code: "RING_ORIGIN_DECODE",
    });
  });
});
