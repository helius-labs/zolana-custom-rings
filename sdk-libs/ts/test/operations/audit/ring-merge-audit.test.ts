import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it, vi } from "vitest";

import mergeVector from "../../../../../test-vectors/merge/merge.json" with { type: "json" };
import {
  treeAddress,
  encodeMergeOutputData,
  encodeBase58,
  addressBytes,
  equalBytes,
  hashBytes,
  ZERO_32,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import {
  seededMergeDummyNullifier,
  seededMergeOutputBlinding,
} from "../../../src/crypto/derivation/merge-seed.js";
import { initializePoseidon } from "@heliuslabs/spr";
import type { Bytes16, Bytes32, Bytes33, Signature } from "@heliuslabs/spr/interface";
import { X25519Keypair } from "@heliuslabs/spr/keypair";
import type { IndexedShieldedTransaction } from "@heliuslabs/spr/transaction";
import {
  auditRingMerges,
  classifyMergeNullifier,
  openRingMerge,
} from "../../../src/operations/audit/audit-merge.js";
import { knownUtxoHash, type KnownUtxos } from "../../../src/operations/audit/audit.js";
import {
  MergeRingAuthority,
  sealMergeRecord,
  type SealedMergeRecord,
} from "../../../src/crypto/audit/merge-disclosure.js";
import { ringIdField } from "../../../src/crypto/derivation/ring-stream.js";
import { RecordKind, type AuditRecord } from "../../../src/protocol/codec/audit-stream.js";
import {
  kitReads,
  solanaRpcReads,
  transactionsPage,
} from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { transactionItems } from "../../../../../zolana/sdk-libs/ts/test/helpers/pages.js";

await initializePoseidon();

const SIGNATURE = "5".repeat(87) as Signature;

function memberOf(index: number): Bytes32 {
  const value = new Uint8Array(32);
  value[30] = index >> 8;
  value[31] = index & 0xff;
  return value as Bytes32;
}

function scanClient(input: Readonly<{ transactions: readonly IndexedShieldedTransaction[][] }>) {
  const transactionPages = vi.fn(async (request: { paginationToken?: string }) => {
    const at = request.paginationToken === undefined ? 0 : Number(request.paginationToken);
    const last = at + 1 === input.transactions.length;
    return transactionsPage({
      data: transactionItems(input.transactions[at] ?? []),
      paginationToken: last ? null : String(at + 1),
    });
  });
  return {
    client: {
      ...kitReads({ solanaRpc: solanaRpcReads({}) }),
      getShieldedTransactionsByTags: transactionPages,
    },
    transactionPages,
  };
}

describe("the tag 57 reader", () => {
  const hex = (value: string): Uint8Array => hexToBytes(value.replace(/^0x/u, ""));
  const vectorAuditor = (): X25519Keypair =>
    X25519Keypair.fromBytes(hex(mergeVector.auditor_sk) as Bytes32);
  const vectorRing = encodeBase58(new Uint8Array(32).fill(0x90));
  const TREE = 9;
  const REAL = memberOf(0x77);
  type Case = (typeof mergeVector.cases)[number];

  /** The vector's record over `vectorRing`, position 2 real and every other past the first padding. */
  function row(entry: Case, overrides: Readonly<{ hash?: Bytes32; sealed?: SealedRecord }> = {}) {
    const { request } = entry;
    const seed = hex(request.seed) as Bytes32;
    const firstNullifier = hex(request.firstNullifier) as Bytes32;
    const ringDataHash = hex(request.outputRingDataHash) as Bytes32;
    const record = hex(entry.record);
    const mint = encodeBase58(record.subarray(41, 73));
    const hash =
      overrides.hash ??
      knownUtxoHash(
        {
          ownerKey: record.slice(9, 41) as Bytes32,
          owner: { kind: "keyed", nullifierPk: hex(request.nullifierPk) as Bytes32 },
          asset: hashBytes(addressBytes(mint)) as Bytes32,
          amount: BigInt(request.amount),
          blinding: seededMergeOutputBlinding(seed, firstNullifier),
          dataHash: ZERO_32,
          ringDataHash,
          treeId: TREE,
        },
        ringIdField(vectorRing),
      );
    const transaction: IndexedShieldedTransaction = {
      slot: 7n,
      txSignature: SIGNATURE,
      eventIndex: 0,
      proofless: false,
      ringProgramId: vectorRing,
      nullifiers: [
        firstNullifier,
        seededMergeDummyNullifier(seed, firstNullifier, 1),
        REAL,
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
          outputContext: { hash, tree: treeAddress(TREE), treeId: TREE, leafIndex: 0n },
        },
      ],
    };
    return {
      kind: "merge" as const,
      transaction,
      sealedRecord: overrides.sealed ?? {
        ephemeralPublicKey: hex(mergeVector.eph_pk) as Bytes33,
        ciphertext: hex(entry.ciphertext),
      },
      authority: MergeRingAuthority.ownerSigned,
    };
  }

  type SealedRecord = Pick<SealedMergeRecord, "ephemeralPublicKey" | "ciphertext">;

  /** The first vector's opening with `edit` applied, sealed to the vector's auditor. */
  function resealed(edit: Partial<AuditRecord>, seed = hex(mergeVector.cases[0]!.request.seed)) {
    const record = hex(mergeVector.cases[0]!.record);
    return sealMergeRecord({
      auditorPublicKey: vectorAuditor().publicKey(),
      opening: {
        record: {
          kind: RecordKind.ring,
          amount: 12n,
          ownerKey: record.slice(9, 41) as Bytes32,
          mint: encodeBase58(record.subarray(41, 73)),
          nullifierPk: record.slice(73, 105) as Bytes32,
          ...edit,
        },
        secret: seed as Bytes32,
      },
    }).sealed;
  }

  it.each(mergeVector.cases)("rebuilds the $name output from its record alone", (entry) => {
    const opened = openRingMerge({
      confirmed: row(entry),
      eventIndex: 0,
      auditor: vectorAuditor(),
    });
    const record = hex(entry.record);
    expect(opened.utxo).toEqual({
      ownerKey: record.slice(9, 41),
      nullifierPk: hex(entry.request.nullifierPk),
      asset: hashBytes(record.subarray(41, 73)),
      mint: encodeBase58(record.subarray(41, 73)),
      amount: 12n,
      blinding: hex(entry.output_blinding),
      dataHash: ZERO_32,
      ringDataHash: hex(entry.request.outputRingDataHash),
    });
    expect(opened.authority).toBe(MergeRingAuthority.ownerSigned);
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

  it("identifies the zero key and the enrolled key from each record", () => {
    const [enrolled, zero] = mergeVector.cases;
    const keyOf = (entry: Case) =>
      openRingMerge({ confirmed: row(entry), eventIndex: 0, auditor: vectorAuditor() }).utxo
        .nullifierPk;
    expect(keyOf(zero!)).toEqual(ZERO_NULLIFIER_PK);
    expect(keyOf(enrolled!)).not.toEqual(ZERO_NULLIFIER_PK);
  });

  it("resolves a nullifier through the known notes and never a padding position", () => {
    const entry = mergeVector.cases[0]!;
    const commitment = memberOf(0x33);
    const utxo = {
      ownerKey: memberOf(1),
      owner: { kind: "keyed" as const, nullifierPk: memberOf(2) },
      asset: memberOf(3),
      amount: 1n,
      blinding: memberOf(4),
      dataHash: ZERO_32,
      ringDataHash: ZERO_32,
      treeId: TREE,
    };
    const known: KnownUtxos = {
      utxo: () => undefined,
      byNullifier: (nullifier) => (equalBytes(nullifier, REAL) ? { commitment, utxo } : undefined),
    };
    const opened = openRingMerge({
      confirmed: row(entry),
      eventIndex: 0,
      auditor: vectorAuditor(),
      known,
    });
    expect(opened.nullifiers[2]?.state).toEqual({
      kind: "resolved",
      note: { commitment, utxo },
    });
    expect(opened.nullifiers[1]?.state).toEqual({ kind: "padding" });
  });

  it.each(mergeVector.cases)(
    "classifies the $name padding from its seed at its position",
    (entry) => {
      const seed = hex(entry.request.seed) as Bytes32;
      const firstNullifier = hex(entry.request.firstNullifier) as Bytes32;
      const nullifier = seededMergeDummyNullifier(seed, firstNullifier, 3);
      const kindOf = (fields: Readonly<{ seed: Bytes32; position: number }>) =>
        classifyMergeNullifier({ firstNullifier, nullifier, ...fields }).kind;
      expect(kindOf({ seed, position: 3 })).toBe("padding");
      expect(kindOf({ seed, position: 4 })).toBe("unresolvedReal");
      expect(kindOf({ seed: memberOf(0x99), position: 3 })).toBe("unresolvedReal");
    },
  );

  it("refuses a record off the commitment, a dummy kind and a noncanonical key or seed", () => {
    const entry = mergeVector.cases[0]!;
    const open = (confirmed: ReturnType<typeof row>) => () =>
      openRingMerge({ confirmed, eventIndex: 0, auditor: vectorAuditor() });
    expect(open(row(entry, { hash: memberOf(1) }))).toThrow(
      expect.objectContaining({ code: "RING_AUDIT_OUTPUT_MISMATCH" }),
    );
    expect(open(row(entry, { sealed: resealed({ amount: 13n }) }))).toThrow(
      expect.objectContaining({ code: "RING_AUDIT_OUTPUT_MISMATCH" }),
    );
    expect(open(row(entry, { sealed: resealed({ kind: RecordKind.exit }) }))).toThrow(
      expect.objectContaining({ code: "RING_AUDIT_MESSAGE", details: { reason: "merge record" } }),
    );
    const noncanonical = new Uint8Array(32).fill(0xff) as Bytes32;
    expect(open(row(entry, { sealed: resealed({ nullifierPk: noncanonical }) }))).toThrow(
      expect.objectContaining({ code: "RING_AUDIT_MESSAGE", details: { reason: "merge record" } }),
    );
    expect(open(row(entry, { sealed: resealed({}, noncanonical) }))).toThrow(
      expect.objectContaining({ code: "RING_AUDIT_MESSAGE", details: { reason: "merge record" } }),
    );
  });

  it("refuses a row of two outputs, a count off every width and no ring", () => {
    const confirmed = row(mergeVector.cases[0]!);
    const { transaction } = confirmed;
    const open = (edited: IndexedShieldedTransaction) => () =>
      openRingMerge({
        confirmed: { ...confirmed, transaction: edited },
        eventIndex: 0,
        auditor: vectorAuditor(),
      });
    const { ringProgramId: _ring, ...ringless } = transaction;
    for (const edited of [
      { ...transaction, outputSlots: [...transaction.outputSlots, ...transaction.outputSlots] },
      { ...transaction, nullifiers: [] },
      ringless,
    ])
      expect(open(edited)).toThrow(expect.objectContaining({ code: "RING_ORIGIN_DECODE" }));
  });

  it("lists a record of another auditor and a tampered record, and reads a good row", async () => {
    const entry = mergeVector.cases[0]!;
    const good = row(entry);
    const bad = {
      ...row(entry),
      transaction: { ...good.transaction, txSignature: "6".repeat(87) as Signature },
    };
    const tampered = bad.sealedRecord.ciphertext.slice();
    tampered[8] = (tampered[8] ?? 0) ^ 1;
    const { client } = scanClient({ transactions: [[good.transaction, bad.transaction]] });
    const page = await auditRingMerges({
      client,
      ringProgramId: vectorRing,
      auditor: vectorAuditor(),
      origin: {
        confirmedTransaction: async (transaction) =>
          transaction === good.transaction
            ? good
            : {
                ...bad,
                transaction,
                sealedRecord: { ...bad.sealedRecord, ciphertext: tampered },
              },
      },
    });
    expect(page.merges.map(({ signature }) => signature)).toEqual([SIGNATURE]);
    expect(page.skipped.map(({ signature }) => signature)).toEqual([bad.transaction.txSignature]);
    const { client: other } = scanClient({ transactions: [[good.transaction]] });
    const foreign = await auditRingMerges({
      client: other,
      ringProgramId: vectorRing,
      auditor: X25519Keypair.generate(),
      origin: { confirmedTransaction: async () => good },
    });
    expect(foreign.merges).toEqual([]);
    expect(foreign.skipped).toHaveLength(1);
  });

  it("refuses a tag 57 row read twice", async () => {
    const good = row(mergeVector.cases[0]!);
    const { client } = scanClient({ transactions: [[good.transaction], [good.transaction]] });
    await expect(
      auditRingMerges({
        client,
        ringProgramId: vectorRing,
        auditor: vectorAuditor(),
        origin: { confirmedTransaction: async () => good },
      }),
    ).rejects.toMatchObject({ code: "RING_RPC", details: { reason: "duplicate merge" } });
  });
});
