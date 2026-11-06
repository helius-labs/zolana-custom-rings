import { type Address, type Signature } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import {
  ZERO_32,
  ZERO_NULLIFIER_PK,
  encodeBase58,
  rightAlign,
  treeAddress,
  mergeOutputBlinding,
  mergeOutputKey,
  hashBytes,
  addressBytes,
  poseidon,
  encodeMergeOutputData,
  encryptMergeOutput,
} from "@heliuslabs/spr/internal";
import { seededMergeOutputBlinding } from "../../../src/crypto/derivation/merge-seed.js";
import { initializePoseidon } from "@heliuslabs/spr";
import type { Bytes16, Bytes32, Bytes33 } from "@heliuslabs/spr/interface";
import { ShieldedKeypair, X25519Keypair, X25519PublicKey } from "@heliuslabs/spr/keypair";
import { AssetRegistry, SOL_MINT, ownerUtxoHash } from "@heliuslabs/spr/transaction";
import type { IndexedShieldedTransaction, OutputSlot } from "@heliuslabs/spr/transaction";
import { STREAM_FIRST_COUNTER } from "../../../src/protocol/codec/ring-disclosure-layout.js";
import {
  auditSharedSecret,
  auditorMessageData,
  AUDIT_ENC_INFO,
  AuditSchedule,
} from "../../../src/crypto/audit/audit.js";
import { ringBlindingSeed, ringOutputBlinding } from "../../../src/crypto/derivation/blinding.js";
import { sealRingDisclosure as sealStream } from "../../../src/crypto/audit/ring-disclosure.js";
import { MergeRingAuthority, sealMergeRecord } from "../../../src/crypto/audit/merge-disclosure.js";
import { ringIdField } from "../../../src/crypto/derivation/ring-stream.js";
import { RecordKind, type AuditRecord } from "../../../src/protocol/codec/audit-stream.js";
import type { AuditStreamLayout as StreamLayout } from "../../../src/protocol/codec/ring-disclosure-layout.js";
import { frameKeyShape } from "../../../src/protocol/proof/transfer-shapes.js";
import type { RingRail } from "../../../src/protocol/transaction/transact.js";
import { zeroKeyNullifier } from "../../../src/state/exposed-notes.js";
import {
  KnownUtxoIndex,
  auditRing,
  knownUtxoHash,
  openedUtxo,
  type KnownUtxos,
} from "../../../src/operations/audit/audit.js";
import {
  type ConfirmedRingTransaction,
  type TransactionOrigin,
} from "../../../src/protocol/transaction/origin.js";
import { RingError } from "../../../src/protocol/error.js";
import {
  recoverRingMemberNotes,
  retainedRecovery,
  type RingRecoveryStep,
} from "../../../src/operations/workflow/recover.js";
import { ringAuditReader } from "../../helpers/clients.js";
import { transactionsPage } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { x25519FromU } from "../../../src/crypto/keys/x25519.js";
import { transactionItems } from "../../../../../zolana/sdk-libs/ts/test/helpers/pages.js";
import { historyCursor } from "../../../src/rpc/history.js";

await initializePoseidon();

function hex<T extends Uint8Array>(value: string, length?: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (length !== undefined && decoded.length !== length)
    throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function field(value: string): Bytes32 {
  return hex<Bytes32>(value, 32);
}

const SIGNATURE = "1".repeat(64) as Signature;
/** A mint no default registry names, the exit of the pair vector settles it. */
const FOREIGN_MINT = encodeBase58(new Uint8Array(32).fill(0x0a));
const OTHER_RING = encodeBase58(new Uint8Array(32).fill(0x0b));

function withSlot(
  index: number,
  change: (slot: OutputSlot) => OutputSlot,
): (transaction: IndexedShieldedTransaction) => IndexedShieldedTransaction {
  return (transaction) => ({
    ...transaction,
    outputSlots: transaction.outputSlots.map((slot, at) => (at === index ? change(slot) : slot)),
  });
}

function ringError(code: string, details?: Readonly<Record<string, unknown>>): unknown {
  return expect.objectContaining({
    code,
    ...(details === undefined ? {} : { details: expect.objectContaining(details) }),
  });
}

describe("auditor envelope", () => {
  // Pinned by prover/ringtest/ringaudit/kdf_test.go and sdk-libs/client/src/crypto/encryption/mod.rs.
  const auditor = X25519Keypair.fromBytes(
    hex("01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c", 32),
  );
  const ephemeralPublicKey = X25519PublicKey.fromBytes(
    hex<Bytes33>("048ea960e4e1b72cdec9a6e7d86ae28cd04edb4b5c07266d3c32d9133c8ebaa966", 33),
  );

  it("matches the circuit vector", () => {
    expect(auditor.publicKey().toBytes()).toEqual(
      hex("04708c2645c705baaf44f2ab947574174f9280df58be6fc2f6f2e8881b78a3115a", 33),
    );
    const dh = auditor.ecdh(ephemeralPublicKey);
    expect(dh).toEqual(field("464b33b122dc1346a6012199742d7e14b2ee6436589c454a579fdda24feec92c"));
    expect(auditSharedSecret(dh, ephemeralPublicKey, auditor.publicKey())).toEqual(
      field("2590b2b949a2f87b9201e4d065167ea9282c4bd06a32e888e24e33c5bddae54f"),
    );
    const envelope = field("48537b94c6262ed3b45768a5d0f065edbb25515039bef17bacf99386f7f55e6a");
    const schedule = AuditSchedule.derive(
      auditSharedSecret(dh, ephemeralPublicKey, auditor.publicKey()),
      AUDIT_ENC_INFO,
    );
    expect(schedule.apply(STREAM_FIRST_COUNTER, envelope)).toEqual(
      field("001013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f4e"),
    );
    schedule.destroy();
  });
});

const RING = encodeBase58(
  field("9090909090909090909090909090909090909090909090909090909090909090"),
);

const TX_SECRET = field("001013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f4e");
const TX_SALT = hex<Bytes16>("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", 16);
const TREE_ID = 9;
const FIRST_NULLIFIER = field(`${"00".repeat(31)}70`);
const OTHER_NULLIFIER = field(`${"00".repeat(31)}71`);
const OTHER_OWNER = new Uint8Array(32).fill(0xb2) as Bytes32;
const OTHER_NULLIFIER_PK = field(`${"00".repeat(31)}21`);

const otherRecords: readonly AuditRecord[] = [
  {
    kind: RecordKind.ring,
    amount: 100n,
    ownerKey: OTHER_OWNER,
    mint: FOREIGN_MINT,
    nullifierPk: OTHER_NULLIFIER_PK,
  },
  {
    kind: RecordKind.exit,
    amount: 30n,
    ownerKey: OTHER_OWNER,
    mint: FOREIGN_MINT,
    nullifierPk: OTHER_NULLIFIER_PK,
  },
];

function streamLayout(inputs: number, outputs: number): StreamLayout {
  const shape = frameKeyShape({
    rail: "confidential",
    inputs,
    outputs,
    spendsDefaultRing: false,
    wide: false,
  });
  if (shape === undefined) throw new Error("no key at the slot count");
  return {
    key: { class: shape.inputs, entry: false },
    inputs,
    outputs,
    capacity: shape.outputs,
    hasData: false,
  };
}

function noteHash(record: AuditRecord, blinding: Bytes32, ringDataHash = ZERO_32): Bytes32 {
  const utxo = openedUtxo(
    {
      ownerKey: record.ownerKey,
      nullifierPk: record.nullifierPk,
      asset: hashBytes(addressBytes(record.mint)) as Bytes32,
      mint: record.mint,
      amount: record.amount,
      blinding,
      dataHash: ZERO_32,
      ringDataHash,
    },
    TREE_ID,
  );
  return knownUtxoHash(utxo, record.kind === RecordKind.ring ? ringIdField(RING) : ZERO_32);
}

const leaf = (hash: Bytes32, leafIndex: bigint) => ({
  hash,
  tree: treeAddress(TREE_ID),
  treeId: TREE_ID,
  leafIndex,
});

function sealedTransfer(
  input: Readonly<{
    auditor: X25519PublicKey;
    records?: readonly AuditRecord[];
    nullifiers?: readonly Bytes32[];
    addressInputBits?: bigint;
    txSignature?: Signature;
  }>,
) {
  const records = input.records ?? otherRecords;
  const nullifiers = input.nullifiers ?? [FIRST_NULLIFIER];
  const addressInputBits = input.addressInputBits ?? 0n;
  const addresses = nullifiers.filter((_, slot) => (addressInputBits >> BigInt(slot)) & 1n).length;
  const blindingSeed = ringBlindingSeed(TX_SECRET, TX_SALT);
  const blindings = records.map((_, outputIndex) =>
    ringOutputBlinding({ firstNullifier: nullifiers[0]!, blindingSeed, outputIndex }),
  );
  const message = auditorMessageData(
    sealStream({
      layout: streamLayout(nullifiers.length, records.length),
      auditorPublicKey: input.auditor,
      salt: TX_SALT,
      disclosure: {
        envelope: {
          txViewingSecret: TX_SECRET,
          realInputs: nullifiers.length - addresses,
          addressInputBits,
          evidence: { kind: "none" },
        },
        records,
      },
    }),
    input.auditor,
  );
  const transaction: IndexedShieldedTransaction = {
    slot: 7n,
    txSignature: input.txSignature ?? SIGNATURE,
    eventIndex: 0,
    txViewingPublicKey: x25519FromU(
      field("3632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63"),
    ),
    salt: TX_SALT,
    outputSlots: records.map((record, slot) => ({
      viewTag: new Uint8Array(32).fill(slot + 1) as Bytes32,
      outputContext: leaf(noteHash(record, blindings[slot]!), BigInt(slot)),
      payload: new Uint8Array(),
    })),
    messages: [message],
    nullifiers,
    proofless: false,
    ringProgramId: RING,
  };
  return { transaction, blindings };
}

const transferRows = (rail: RingRail): TransactionOrigin => ({
  confirmedTransaction: async (transaction) => ({
    kind: "transfer",
    transaction,
    inputTreeIds: transaction.nullifiers.map(() => undefined),
    layout: streamLayout(transaction.nullifiers.length, transaction.outputSlots.length),
    rail,
    noSpend: false,
    hasData: false,
    entry: false,
  }),
});
const TRANSFERS = transferRows("confidential");

describe("auditRing", () => {
  const ring = RING;
  const transfers = TRANSFERS;

  function scan(
    transactions: readonly IndexedShieldedTransaction[],
    origin: TransactionOrigin,
    extra: Readonly<{ auditor: X25519Keypair; knownUtxos?: KnownUtxos }>,
  ) {
    return auditRing({
      client: ringAuditReader({
        getShieldedTransactionsByTags: async () =>
          transactionsPage({
            data: transactionItems([...transactions]),
          }),
      }),
      auditor: extra.auditor,
      ringProgramId: ring,
      origin,
      ...(extra.knownUtxos === undefined ? {} : { knownUtxos: extra.knownUtxos }),
    });
  }

  it("opens a spend of a note an earlier call opened through the caller's known notes", async () => {
    const auditor = X25519Keypair.generate();
    const blinding = field(`${"00".repeat(31)}05`);
    const record = { ...otherRecords[0]!, nullifierPk: ZERO_NULLIFIER_PK as Bytes32 };
    const commitment = noteHash(record, blinding);
    const nullifier = zeroKeyNullifier(commitment, blinding);
    const { transaction } = sealedTransfer({
      auditor: auditor.publicKey(),
      nullifiers: [nullifier],
    });
    const origin = transferRows("anonymous");
    const unseen = await scan([transaction], origin, { auditor });
    expect(unseen.transactions[0]?.sender).toBeUndefined();
    expect(unseen.transactions[0]?.inputs[0]?.opening).toEqual({ kind: "unresolvedReal" });
    expect(unseen.transactions[0]?.outputs).toHaveLength(otherRecords.length);
    const page = await scan([transaction], origin, {
      auditor,
      knownUtxos: new KnownUtxoIndex([
        {
          commitment,
          utxo: openedUtxo(
            {
              ownerKey: record.ownerKey,
              nullifierPk: record.nullifierPk,
              asset: hashBytes(addressBytes(record.mint)) as Bytes32,
              mint: record.mint,
              amount: record.amount,
              blinding,
              dataHash: ZERO_32,
              ringDataHash: ZERO_32,
            },
            TREE_ID,
          ),
        },
      ]),
    });
    expect(page.transactions[0]?.sender).toEqual({
      ownerKey: record.ownerKey,
      nullifierPk: ZERO_NULLIFIER_PK,
    });
    expect(page.transactions[0]?.inputs[0]?.opening).toMatchObject({
      kind: "opened",
      amount: record.amount,
    });
    expect(page.transactions[0]?.inputs[0]?.hash).toEqual(commitment);
  });

  it("reads an address input apart from the note it follows", async () => {
    const auditor = X25519Keypair.generate();
    const { transaction } = sealedTransfer({
      auditor: auditor.publicKey(),
      nullifiers: [FIRST_NULLIFIER, field(`${"00".repeat(31)}77`)],
      addressInputBits: 2n,
    });
    const page = await scan([transaction], TRANSFERS, { auditor });
    expect(page.transactions[0]?.inputs.map((input) => input.opening)).toEqual([
      { kind: "unresolvedReal" },
      { kind: "address" },
    ]);
  });

  it("resolves a merged input before tracing its later transfer in either history order", async () => {
    const auditor = X25519Keypair.generate();
    const seed = field(`${"00".repeat(31)}13`);
    const firstNullifier = field(`${"00".repeat(31)}1f`);
    const record = { ...otherRecords[0]!, nullifierPk: ZERO_NULLIFIER_PK as Bytes32 };
    const blinding = seededMergeOutputBlinding(seed, firstNullifier);
    const commitment = noteHash(record, blinding);
    const { sealed } = sealMergeRecord({
      auditorPublicKey: auditor.publicKey(),
      opening: { record, secret: seed },
    });
    const merge: IndexedShieldedTransaction = {
      slot: 6n,
      txSignature: "6".repeat(87) as Signature,
      eventIndex: 0,
      proofless: false,
      ringProgramId: RING,
      nullifiers: [firstNullifier, OTHER_NULLIFIER],
      messages: [],
      outputSlots: [
        {
          viewTag: firstNullifier,
          payload: encodeMergeOutputData({
            salt: new Uint8Array(16).fill(3) as Bytes16,
            ciphertext: [ZERO_32, ZERO_32, ZERO_32],
            ringDataHash: ZERO_32,
          }),
          outputContext: leaf(commitment, 9n),
        },
      ],
    };
    const { transaction: transfer } = sealedTransfer({
      auditor: auditor.publicKey(),
      nullifiers: [zeroKeyNullifier(commitment, blinding)],
    });
    const origin: TransactionOrigin = {
      confirmedTransaction: async (transaction, read) =>
        transaction.txSignature === merge.txSignature
          ? {
              kind: "merge",
              transaction,
              sealedRecord: sealed,
              authority: MergeRingAuthority.ownerSigned,
            }
          : transferRows("anonymous").confirmedTransaction(transaction, read),
    };
    for (const history of [
      [merge, transfer],
      [transfer, merge],
    ]) {
      const page = await scan(history, origin, { auditor });
      expect(page.skipped).toEqual([]);
      expect(page.transactions[0]?.sender).toEqual({
        ownerKey: record.ownerKey,
        nullifierPk: ZERO_NULLIFIER_PK,
      });
      expect(page.transactions[0]?.inputs[0]?.opening).toMatchObject({
        kind: "opened",
        amount: record.amount,
      });
      expect(page.transactions[0]?.inputs[0]?.hash).toEqual(commitment);
    }
  });

  it("audits the ring's confirmed transfers and skips every other event", async () => {
    const auditor = X25519Keypair.generate();
    const { transaction: transfer } = sealedTransfer({ auditor: auditor.publicKey() });
    const foreign = { ...transfer, txSignature: "3".repeat(64) as Signature };
    const origin: TransactionOrigin = {
      confirmedTransaction: async (transaction): Promise<ConfirmedRingTransaction | undefined> => {
        if (transaction.txSignature === foreign.txSignature) return undefined;
        return transfers.confirmedTransaction(transaction, ring);
      },
    };
    const page = await scan([transfer, foreign], origin, { auditor });
    expect(page.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(page.nextCursor).toBeUndefined();
  });

  it("skips a row that does not decode, reports it and stops on a transport failure", async () => {
    const auditor = X25519Keypair.generate();
    const { transaction: transfer } = sealedTransfer({ auditor: auditor.publicKey() });
    for (const code of ["RING_ORIGIN_DECODE", "RING_TRANSACT_DATA_INVALID"] as const) {
      const bad = {
        ...transfer,
        slot: 9n,
        txSignature: "2".repeat(64) as Signature,
      };
      const origin: TransactionOrigin = {
        confirmedTransaction: async (transaction) => {
          if (transaction.txSignature === bad.txSignature) throw new RingError(code);
          return transfers.confirmedTransaction(transaction, ring);
        },
      };
      const page = await scan([bad, transfer], origin, { auditor });
      expect(page.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
      expect(page.skipped).toEqual([
        {
          slot: 9n,
          signature: bad.txSignature,
          eventIndex: bad.eventIndex,
          reason: "invalidAuditData",
        },
      ]);
    }
    for (const code of ["RING_ORIGIN_UNAVAILABLE", "RING_ORIGIN_STACK"] as const) {
      const origin: TransactionOrigin = {
        confirmedTransaction: async () => {
          throw new RingError(code);
        },
      };
      await expect(scan([transfer], origin, { auditor })).rejects.toThrow(ringError(code));
    }
  });

  it("lists a row that fails its audit, opens the rest and keeps its stops", async () => {
    const auditor = X25519Keypair.generate();
    const { transaction: transfer } = sealedTransfer({ auditor: auditor.publicKey() });
    const sealed = transfer.messages.at(-1)!;
    const malformed = {
      ...transfer,
      slot: 9n,
      txSignature: "2".repeat(64) as Signature,
      messages: [{ viewTag: sealed.viewTag, data: Uint8Array.of(1) }],
    };
    const page = await scan([malformed, transfer], transfers, { auditor });
    expect(page.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(page.skipped).toEqual([
      {
        slot: 9n,
        signature: malformed.txSignature,
        eventIndex: malformed.eventIndex,
        reason: "invalidAuditData",
      },
    ]);
    await expect(scan([{ ...transfer, messages: [] }], transfers, { auditor })).rejects.toThrow(
      ringError("RING_AUDIT_MESSAGE", { reason: "missing" }),
    );
  });

  it("never reads the origin of a row another ring or the default ring indexed", async () => {
    const auditor = X25519Keypair.generate();
    const { transaction: transfer } = sealedTransfer({ auditor: auditor.publicKey() });
    const { ringProgramId: _ring, ...defaultRing } = {
      ...transfer,
      txSignature: "7".repeat(64) as Signature,
    };
    const otherRing = {
      ...transfer,
      txSignature: "8".repeat(64) as Signature,
      ringProgramId: OTHER_RING,
    };
    const read = vi.fn(async (transaction: IndexedShieldedTransaction) => {
      if (transaction.txSignature !== SIGNATURE) throw new Error("origin read of a foreign row");
      return transfers.confirmedTransaction(transaction, ring);
    });
    const page = await scan(
      [defaultRing, otherRing, transfer],
      { confirmedTransaction: read },
      {
        auditor,
      },
    );
    expect(page.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("refuses a confirmed transfer without its auditor message", async () => {
    const auditor = X25519Keypair.generate();
    const { transaction: transfer } = sealedTransfer({ auditor: auditor.publicKey() });
    await expect(scan([{ ...transfer, messages: [] }], transfers, { auditor })).rejects.toThrow(
      ringError("RING_AUDIT_MESSAGE", { reason: "missing" }),
    );
  });

  it("opens a row under one agreement and one schedule", async () => {
    const auditor = X25519Keypair.generate();
    const { transaction: transfer } = sealedTransfer({ auditor: auditor.publicKey() });
    const ecdh = vi.spyOn(auditor, "ecdh");
    const derive = vi.spyOn(AuditSchedule, "derive");
    try {
      const page = await scan([transfer], transfers, { auditor });
      expect(page.transactions).toHaveLength(1);
      expect(ecdh).toHaveBeenCalledTimes(1);
      expect(derive.mock.calls.filter(([, label]) => label === AUDIT_ENC_INFO)).toHaveLength(1);
    } finally {
      vi.restoreAllMocks();
    }
  });

  it("opens a row on a retry once the RPC serves its auditor message", async () => {
    const auditor = X25519Keypair.generate();
    const { transaction: transfer } = sealedTransfer({ auditor: auditor.publicKey() });
    let served = false;
    const origin: TransactionOrigin = {
      confirmedTransaction: async (transaction, read) =>
        transfers.confirmedTransaction(
          served ? transaction : { ...transaction, messages: [] },
          read,
        ),
    };
    await expect(scan([transfer], origin, { auditor })).rejects.toThrow(
      ringError("RING_AUDIT_MESSAGE", { reason: "missing" }),
    );
    served = true;
    const page = await scan([transfer], origin, { auditor });
    expect(page.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(page.skipped).toEqual([]);
  });

  it("follows the cursor to the page that states its frontier and stops at the page cap", async () => {
    const auditor = X25519Keypair.generate();
    const { transaction: first } = sealedTransfer({ auditor: auditor.publicKey() });
    const second = { ...first, txSignature: "4".repeat(64) as Signature };
    const pages = [
      transactionsPage({
        data: transactionItems([first]),
        paginationToken: "t1",
      }),
      transactionsPage({ data: transactionItems([second]) }),
    ];
    const read = vi.fn(
      async (request: { paginationToken?: string }) =>
        pages[request.paginationToken === undefined ? 0 : 1]!,
    );
    const audit = (maxPages?: number) =>
      auditRing({
        client: ringAuditReader({ getShieldedTransactionsByTags: read }),
        auditor,
        ringProgramId: ring,
        origin: transfers,
        ...(maxPages === undefined ? {} : { maxPages }),
      });
    const capped = await audit(1);
    expect(capped.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(capped.nextCursor).toEqual(historyCursor(ring, "ring", "t1"));
    const complete = await audit();
    expect(complete.transactions.map((audited) => audited.signature)).toEqual([
      SIGNATURE,
      second.txSignature,
    ]);
    expect(complete.nextCursor).toBeUndefined();
    expect(read.mock.calls.map(([request]) => request.paginationToken)).toEqual([
      undefined,
      undefined,
      "t1",
    ]);
  });

  it("refuses a token that does not advance, a cursor of another query and a zero limit", async () => {
    const auditor = X25519Keypair.generate();
    const audit = (
      pages: readonly ReturnType<typeof transactionsPage>[],
      limits: Readonly<{ pageSize?: number; maxPages?: number }> = {},
    ) => {
      const read = vi.fn(
        async (request: { paginationToken?: string }) =>
          pages[request.paginationToken === undefined ? 0 : 1]!,
      );
      return {
        read,
        result: auditRing({
          client: ringAuditReader({ getShieldedTransactionsByTags: read }),
          auditor,
          ringProgramId: ring,
          origin: transfers,
          ...limits,
        }),
      };
    };
    const stuck = [
      transactionsPage({ paginationToken: "t1" }),
      transactionsPage({ paginationToken: "t1" }),
    ];
    await expect(audit(stuck).result).rejects.toThrow(ringError("RING_HISTORY_PAGE_INVALID"));
    for (const cursor of [
      historyCursor(ring, "tags", "t1"),
      historyCursor("11111111111111111111111111111111" as Address, "ring", "t1"),
      "t1",
      Uint8Array.of(2, 1) as unknown as string,
    ]) {
      const read = vi.fn(async () => transactionsPage());
      await expect(
        auditRing({
          client: ringAuditReader({ getShieldedTransactionsByTags: read }),
          auditor,
          ringProgramId: ring,
          origin: transfers,
          cursor,
        }),
      ).rejects.toThrow(ringError("RING_HISTORY_CURSOR_INVALID"));
      expect(read).not.toHaveBeenCalled();
    }
    for (const limits of [{ pageSize: 0 }, { maxPages: 0 }, { pageSize: 1.5 }]) {
      const { read, result } = audit([transactionsPage()], limits);
      await expect(result).rejects.toThrow(ringError("RING_RPC", { reason: "invalid scan limit" }));
      expect(read).not.toHaveBeenCalled();
    }
  });
});

describe("recoverRingMemberNotes", () => {
  const AMOUNT = 100n;

  const ownedRecord = (owner: ShieldedKeypair, mint: Address = SOL_MINT): AuditRecord => {
    const address = owner.shieldedAddress();
    return {
      kind: RecordKind.ring,
      amount: AMOUNT,
      ownerKey: address.signingPublicKey.ed25519(),
      mint,
      nullifierPk: address.nullifierPublicKey,
    };
  };

  function ownedTransfer(owner: ShieldedKeypair, auditor: X25519PublicKey, mint?: Address) {
    const record = ownedRecord(owner, mint);
    const { transaction, blindings } = sealedTransfer({
      auditor,
      records: [record, ...otherRecords],
    });
    const commitment = transaction.outputSlots[0]!.outputContext.hash;
    return { transaction, commitment, blinding: blindings[0]!, amount: AMOUNT };
  }

  async function recover(input: Parameters<typeof recoverStep>[0]) {
    const step = await recoverStep(input);
    if (step.kind !== "complete") throw new Error("the recovery paused");
    return step.notes;
  }

  function recoverStep(
    input: Readonly<{
      owner: ShieldedKeypair;
      auditor: X25519Keypair;
      transaction: IndexedShieldedTransaction;
      spends?: readonly IndexedShieldedTransaction[];
      nullifierKey?: ShieldedKeypair;
      assets?: AssetRegistry;
      tags?: () => ReturnType<typeof transactionsPage>;
      /** The ring's history, else the audited page. */
      history?: readonly IndexedShieldedTransaction[];
      origin?: TransactionOrigin;
    }>,
  ) {
    const page = () =>
      transactionsPage({
        data: transactionItems([input.transaction]),
      });
    const { history } = input;
    return recoverRingMemberNotes({
      client: {
        ...ringAuditReader({
          getShieldedTransactionsByTags: async (request) =>
            request.tags.length === 0 && (history !== undefined || input.spends !== undefined)
              ? transactionsPage({
                  data: transactionItems([
                    ...(history ?? []),
                    input.transaction,
                    ...(input.spends ?? []),
                  ]),
                })
              : (input.tags ?? page)(),
          solanaRpc: { getProgramAccounts: () => ({ send: async () => [] }) },
        }),
      },
      ringProgramId: RING,
      auditor: input.auditor,
      source: input.owner.shieldedAddress(),
      nullifierKey: (input.nullifierKey ?? input.owner).nullifierKey(),
      assets: input.assets ?? new AssetRegistry([[2n, FOREIGN_MINT]]),
      origin: input.origin ?? TRANSFERS,
    });
  }

  /** A ring merge spending `nullifier` first, its output encrypted for `owner`. */
  function mergeOf(
    owner: ShieldedKeypair,
    auditor: X25519PublicKey,
    nullifier: Bytes32,
    mint: Address = SOL_MINT,
  ) {
    const key = owner.nullifierKey();
    const salt = new Uint8Array(16).fill(3) as Bytes16;
    const ringDataHash = new Uint8Array(32).fill(5) as Bytes32;
    const blinding = mergeOutputBlinding(key, nullifier);
    const record: AuditRecord = ownedRecord(owner, mint);
    const commitment = ownerUtxoHash({
      owner: poseidon([
        owner.shieldedAddress().signingPublicKey.ownerProofInputHash(),
        key.publicKey(),
      ]),
      asset: mint,
      amount: AMOUNT,
      blinding,
      treeId: TREE_ID,
      ringDataHash,
      ringProgramId: RING,
    });
    const secret = key.secretBytes();
    const { sealed } = sealMergeRecord({
      auditorPublicKey: auditor,
      opening: { record, secret: rightAlign(secret) as Bytes32 },
    });
    secret.fill(0);
    const ciphertext = encryptMergeOutput(
      { amount: AMOUNT, mint },
      mergeOutputKey(key, nullifier),
      salt,
    );
    const transaction: IndexedShieldedTransaction = {
      slot: 8n,
      txSignature: "6".repeat(64) as Signature,
      eventIndex: 0,
      proofless: false,
      ringProgramId: RING,
      nullifiers: [nullifier, new Uint8Array(32).fill(7) as Bytes32],
      messages: [],
      outputSlots: [
        {
          viewTag: nullifier,
          payload: encodeMergeOutputData({ salt, ciphertext, ringDataHash }),
          outputContext: leaf(commitment, 9n),
        },
      ],
    };
    const unreadable: IndexedShieldedTransaction = {
      ...transaction,
      outputSlots: transaction.outputSlots.map((slot) => ({
        ...slot,
        payload: encodeMergeOutputData({
          salt,
          ciphertext: [new Uint8Array(32).fill(255) as Bytes32, ZERO_32, ZERO_32],
          ringDataHash,
        }),
      })),
    };
    const row = (indexed: IndexedShieldedTransaction): ConfirmedRingTransaction => ({
      kind: "merge",
      transaction: indexed,
      sealedRecord: sealed,
      authority: MergeRingAuthority.ownerSigned,
    });
    return { transaction, unreadable, commitment, row };
  }

  it("records a note whose mint no registry names as unopened and goes on", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction, commitment } = ownedTransfer(owner, auditor.publicKey(), FOREIGN_MINT);
    const recovered = await recover({ owner, auditor, transaction, assets: new AssetRegistry() });
    expect(recovered.notes).toEqual([]);
    expect(recovered.unopened).toEqual([commitment]);
    expect(recovered.unknownMints).toEqual([FOREIGN_MINT]);
  });

  it("refuses a result past a row it could not read and stops at a failed read", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction } = ownedTransfer(owner, auditor.publicKey());
    const sealed = transaction.messages.at(-1)!;
    await expect(
      recover({
        owner,
        auditor,
        transaction: {
          ...transaction,
          messages: [{ viewTag: sealed.viewTag, data: Uint8Array.of(1) }],
        },
      }),
    ).rejects.toThrow(ringError("RING_RECOVERY_INCOMPLETE", { reason: "skipped row" }));
    const nullifier = (await recover({ owner, auditor, transaction })).notes[0]!.nullifier;
    const spend = {
      ...transaction,
      txSignature: "5".repeat(64) as Signature,
      nullifiers: [nullifier],
    };
    const spending = (code: "RING_ORIGIN_DECODE" | "RING_ORIGIN_UNAVAILABLE") =>
      recover({
        owner,
        auditor,
        transaction,
        spends: [spend],
        origin: {
          confirmedTransaction: async (row, ring) => {
            if (row.txSignature === spend.txSignature) throw new RingError(code);
            return TRANSFERS.confirmedTransaction(row, ring);
          },
        },
      });
    await expect(spending("RING_ORIGIN_DECODE")).rejects.toThrow(
      ringError("RING_RECOVERY_INCOMPLETE", {
        reason: "skipped row",
        transactionId: spend.txSignature,
      }),
    );
    await expect(spending("RING_ORIGIN_UNAVAILABLE")).rejects.toThrow(
      ringError("RING_ORIGIN_UNAVAILABLE"),
    );
  });

  it("never reads the origin of a spend another ring indexed", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction, commitment } = ownedTransfer(owner, auditor.publicKey());
    const unspent = await recover({ owner, auditor, transaction });
    const foreign = {
      ...transaction,
      txSignature: "5".repeat(64) as Signature,
      nullifiers: [unspent.notes[0]!.nullifier],
      ringProgramId: OTHER_RING,
    };
    const recovered = await recover({
      owner,
      auditor,
      transaction,
      spends: [foreign],
      origin: {
        confirmedTransaction: async (indexed, ring) => {
          if (indexed.ringProgramId !== ring) throw new Error("origin read of a foreign row");
          return TRANSFERS.confirmedTransaction(indexed, ring);
        },
      },
    });
    expect(recovered.notes.map((note) => note.outputContext.hash)).toEqual([commitment]);
  });

  it("follows a spend into the merge that folded the note and recovers the merged output", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction } = ownedTransfer(owner, auditor.publicKey());
    const unspent = await recover({ owner, auditor, transaction });
    const merge = mergeOf(owner, auditor.publicKey(), unspent.notes[0]!.nullifier);
    const merged = await recover({
      owner,
      auditor,
      transaction,
      spends: [merge.transaction],
      origin: {
        confirmedTransaction: async (indexed, ring) =>
          indexed.txSignature === merge.transaction.txSignature
            ? merge.row(indexed)
            : TRANSFERS.confirmedTransaction(indexed, ring),
      },
    });
    expect(merged.notes.map((note) => [note.outputContext.hash, note.utxo.amount])).toEqual([
      [merge.commitment, AMOUNT],
    ]);
    expect(merged.unopened).toEqual([]);
  });

  it("recovers a merge from its record when the native ciphertext is invalid", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const source = ownedTransfer(owner, auditor.publicKey());
    const nullifier = owner.nullifierKey().nullifier(source.commitment, source.blinding);
    const merge = mergeOf(owner, auditor.publicKey(), nullifier);
    const result = await recover({
      owner,
      auditor,
      transaction: source.transaction,
      history: [merge.unreadable],
      origin: {
        confirmedTransaction: async (row, ring) =>
          row.txSignature === merge.unreadable.txSignature
            ? merge.row(row)
            : TRANSFERS.confirmedTransaction(row, ring),
      },
    });
    expect(result.notes.map((note) => [note.outputContext.hash, note.utxo.amount])).toEqual([
      [merge.commitment, AMOUNT],
    ]);
    expect(result.unopened).toEqual([]);
  });

  /** An owner-signed zero-key merge under a private seed, its native body opens under no key. */
  function zeroKeyMergeOf(owner: ShieldedKeypair, auditor: X25519PublicKey) {
    const seed = field(`00${"5a".repeat(31)}`);
    const firstNullifier = field(`${"00".repeat(31)}61`);
    const ringDataHash = new Uint8Array(32).fill(5) as Bytes32;
    const blinding = seededMergeOutputBlinding(seed, firstNullifier);
    const commitment = ownerUtxoHash({
      owner: poseidon([
        owner.shieldedAddress().signingPublicKey.ownerProofInputHash(),
        ZERO_NULLIFIER_PK,
      ]),
      asset: SOL_MINT,
      amount: AMOUNT,
      blinding,
      treeId: TREE_ID,
      ringDataHash,
      ringProgramId: RING,
    });
    const { sealed } = sealMergeRecord({
      auditorPublicKey: auditor,
      opening: {
        record: { ...ownedRecord(owner), nullifierPk: ZERO_NULLIFIER_PK as Bytes32 },
        secret: seed,
      },
    });
    const transaction: IndexedShieldedTransaction = {
      slot: 8n,
      txSignature: "7".repeat(64) as Signature,
      eventIndex: 0,
      proofless: false,
      ringProgramId: RING,
      nullifiers: [firstNullifier, new Uint8Array(32).fill(7) as Bytes32],
      messages: [],
      outputSlots: [
        {
          viewTag: owner.shieldedAddress().signingPublicKey.ownerProofInputHash(),
          payload: encodeMergeOutputData({
            salt: new Uint8Array(16).fill(3) as Bytes16,
            ciphertext: [new Uint8Array(32).fill(255) as Bytes32, ZERO_32, ZERO_32],
            ringDataHash,
          }),
          outputContext: leaf(commitment, 9n),
        },
      ],
    };
    const origin: TransactionOrigin = {
      confirmedTransaction: async (indexed, ring) =>
        indexed.txSignature === transaction.txSignature
          ? {
              kind: "merge",
              transaction: indexed,
              sealedRecord: sealed,
              authority: MergeRingAuthority.ownerSigned,
            }
          : TRANSFERS.confirmedTransaction(indexed, ring),
    };
    return { transaction, commitment, blinding, origin };
  }

  it("recovers a zero-key merge from its record alone, with no input history or nullifier-key seed", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const merge = zeroKeyMergeOf(owner, auditor.publicKey());
    const result = await recover({
      owner,
      auditor,
      transaction: merge.transaction,
      origin: merge.origin,
    });
    expect(
      result.notes.map((note) => [note.outputContext.hash, note.utxo.amount, note.nullifier]),
    ).toEqual([[merge.commitment, AMOUNT, zeroKeyNullifier(merge.commitment, merge.blinding)]]);
    expect(result.unopened).toEqual([]);
    // Another member's recovery reads the same record and keeps nothing.
    const stranger = await recover({
      owner: ShieldedKeypair.generate(),
      auditor,
      transaction: merge.transaction,
      origin: merge.origin,
    });
    expect(stranger.notes).toEqual([]);
    expect(stranger.unopened).toEqual([]);
  });

  it("keeps one note for a merge event the history repeats", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const merge = zeroKeyMergeOf(owner, auditor.publicKey());
    const result = await recover({
      owner,
      auditor,
      transaction: merge.transaction,
      history: [merge.transaction],
      origin: merge.origin,
    });
    expect(result.notes.map((note) => note.outputContext.hash)).toEqual([merge.commitment]);
  });

  it("refuses a merge record off the confirmed output", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const source = ownedTransfer(owner, auditor.publicKey());
    const nullifier = owner.nullifierKey().nullifier(source.commitment, source.blinding);
    const merge = mergeOf(owner, auditor.publicKey(), nullifier);
    const wrong = withSlot(0, (slot) => ({
      ...slot,
      outputContext: { ...slot.outputContext, hash: field("01".repeat(32)) },
    }))(merge.transaction);
    await expect(
      recover({
        owner,
        auditor,
        transaction: source.transaction,
        history: [wrong],
        origin: {
          confirmedTransaction: async (row, ring) =>
            row.txSignature === wrong.txSignature
              ? merge.row(row)
              : TRANSFERS.confirmedTransaction(row, ring),
        },
      }),
    ).rejects.toThrow(ringError("RING_RECOVERY_INCOMPLETE", { reason: "skipped row" }));
  });

  it.each([
    ["valid", true],
    ["invalid", false],
  ] as const)(
    "reads an unknown merge mint from its record under a %s native ciphertext",
    async (_, validBody) => {
      const auditor = X25519Keypair.generate();
      const owner = ShieldedKeypair.generate();
      const source = ownedTransfer(owner, auditor.publicKey());
      const nullifier = owner.nullifierKey().nullifier(source.commitment, source.blinding);
      const merge = mergeOf(owner, auditor.publicKey(), nullifier, FOREIGN_MINT);
      const transaction = validBody ? merge.transaction : merge.unreadable;
      const result = await recover({
        owner,
        auditor,
        transaction: source.transaction,
        history: [transaction],
        assets: new AssetRegistry(),
        origin: {
          confirmedTransaction: async (row, ring) =>
            row.txSignature === transaction.txSignature
              ? merge.row(row)
              : TRANSFERS.confirmedTransaction(row, ring),
        },
      });
      expect(result.notes).toEqual([]);
      expect(result.unopened).toEqual([merge.commitment]);
      expect(result.unknownMints).toEqual([FOREIGN_MINT]);
    },
  );

  it("refuses another nullifier key, an output the auditor cannot open and a scan the page cap cuts", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction, commitment } = ownedTransfer(owner, auditor.publicKey());
    await expect(
      recover({
        owner,
        auditor,
        transaction,
        nullifierKey: ShieldedKeypair.generate(),
      }),
    ).rejects.toThrow(ringError("RING_NULLIFIER_KEY_MISMATCH"));
    const moved = withSlot(1, (slot) => ({
      ...slot,
      outputContext: { ...slot.outputContext, hash: commitment },
    }))(transaction);
    await expect(recover({ owner, auditor, transaction: moved })).rejects.toThrow(
      ringError("RING_AUDIT_OUTPUT_MISMATCH", {
        reason: "unopened",
        slotIndex: 1,
      }),
    );
    let page = 0;
    const endless = () => transactionsPage({ paginationToken: `t${++page}` });
    await expect(
      recoverStep({ owner, auditor, transaction, tags: endless }),
    ).resolves.toMatchObject({
      kind: "paused",
      progress: { cursor: historyCursor(RING, "ring", "t32") },
    });
  });

  describe("paged", () => {
    /** Serves `rows` `limit` at a time behind tokens `p<offset>`. */
    function pagedRecovery(
      input: Readonly<{
        owner: ShieldedKeypair;
        auditor: X25519Keypair;
        rows: readonly IndexedShieldedTransaction[];
        pageSize?: number;
        maxPages?: number;
        progress?: Extract<RingRecoveryStep, { kind: "paused" }>["progress"];
        origin?: TransactionOrigin;
      }>,
    ) {
      return recoverRingMemberNotes({
        client: ringAuditReader({
          getShieldedTransactionsByTags: async (request) => {
            const start = Number(request.paginationToken?.slice(1) ?? 0);
            const end = start + Number(request.limit);
            return transactionsPage({
              data: transactionItems(input.rows.slice(start, end)),
              ...(end < input.rows.length ? { paginationToken: `p${end}` } : {}),
            });
          },
        }),
        ringProgramId: RING,
        auditor: input.auditor,
        source: input.owner.shieldedAddress(),
        nullifierKey: input.owner.nullifierKey(),
        assets: new AssetRegistry([[2n, FOREIGN_MINT]]),
        origin: input.origin ?? TRANSFERS,
        ...(input.pageSize === undefined ? {} : { pageSize: input.pageSize }),
        ...(input.maxPages === undefined ? {} : { maxPages: input.maxPages }),
        ...(input.progress === undefined ? {} : { progress: input.progress }),
      });
    }

    /** A spend that sorts ahead of the note it spends inside one slot, then a note one slot later. */
    async function slotSplitHistory(owner: ShieldedKeypair, auditor: X25519Keypair) {
      const { transaction: spent } = ownedTransfer(owner, auditor.publicKey());
      const nullifier = (await recover({ owner, auditor, transaction: spent })).notes[0]!.nullifier;
      const spend = sealedTransfer({
        auditor: auditor.publicKey(),
        nullifiers: [nullifier],
        txSignature: "5".repeat(64) as Signature,
      }).transaction;
      const kept = {
        ...sealedTransfer({
          auditor: auditor.publicKey(),
          records: [ownedRecord(owner), ...otherRecords],
          nullifiers: [OTHER_NULLIFIER],
          txSignature: "4".repeat(64) as Signature,
        }).transaction,
        slot: spent.slot + 1n,
      };
      return { rows: [spend, spent, kept], kept: kept.outputSlots[0]!.outputContext.hash };
    }

    function paused(step: RingRecoveryStep) {
      if (step.kind !== "paused") throw new Error("the recovery completed");
      return step.progress;
    }

    it("splits over three calls into the result of one full recovery", async () => {
      const auditor = X25519Keypair.generate();
      const owner = ShieldedKeypair.generate();
      const { rows, kept } = await slotSplitHistory(owner, auditor);
      const full = await pagedRecovery({ owner, auditor, rows });
      expect(
        full.kind === "complete" && full.notes.notes.map((note) => note.outputContext.hash),
      ).toEqual([kept]);
      const page = { owner, auditor, rows, pageSize: 1, maxPages: 1 };
      const first = paused(await pagedRecovery(page));
      expect(first.cursor).toBe(historyCursor(RING, "ring", "p1"));
      const second = paused(await pagedRecovery({ ...page, progress: first }));
      expect(await pagedRecovery({ ...page, progress: second })).toEqual(full);
    });

    it("resumes past every row its progress read and retries the same progress after an error", async () => {
      const auditor = X25519Keypair.generate();
      const owner = ShieldedKeypair.generate();
      const { rows } = await slotSplitHistory(owner, auditor);
      const [spend, , kept] = rows;
      const full = await pagedRecovery({ owner, auditor, rows });
      const page = { owner, auditor, rows, pageSize: 1, maxPages: 1 };
      const progress = paused(await pagedRecovery(page));
      // A read of the row the progress already holds fails, the failing attempt reads one page more.
      const origin = (failing: ReadonlySet<Signature>): TransactionOrigin => ({
        confirmedTransaction: async (row, ring) => {
          if (failing.has(row.txSignature)) throw new RingError("RING_ORIGIN_UNAVAILABLE");
          return TRANSFERS.confirmedTransaction(row, ring);
        },
      });
      const resume = { ...page, maxPages: 4, progress };
      await expect(
        pagedRecovery({
          ...resume,
          origin: origin(new Set([spend!.txSignature, kept!.txSignature])),
        }),
      ).rejects.toThrow(ringError("RING_ORIGIN_UNAVAILABLE"));
      for (const _ of [0, 1])
        expect(
          await pagedRecovery({ ...resume, origin: origin(new Set([spend!.txSignature])) }),
        ).toEqual(full);
    });

    it("holds the member's notes alone across pages of other members' traffic", async () => {
      const auditor = X25519Keypair.generate();
      const owner = ShieldedKeypair.generate();
      const mine = { ...ownedTransfer(owner, auditor.publicKey()).transaction, slot: 10n };
      const spent = (await recover({ owner, auditor, transaction: mine })).notes[0]!.nullifier;
      const transfer = (index: number, nullifier: Bytes32, records?: readonly AuditRecord[]) => ({
        ...sealedTransfer({
          auditor: auditor.publicKey(),
          nullifiers: [nullifier],
          txSignature:
            `${"3".repeat(62)}${"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[Math.floor(index / 58)]!}${"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[index % 58]!}` as Signature,
          ...(records === undefined ? {} : { records }),
        }).transaction,
        slot: 11n + BigInt(index),
      });
      const others = Array.from({ length: 70 }, (_, index) =>
        transfer(index, field(`${"00".repeat(30)}c0${index.toString(16).padStart(2, "0")}`)),
      );
      const respend = transfer(70, spent, [ownedRecord(owner), ...otherRecords]);
      const rows = [mine, ...others.slice(0, 6), respend, ...others.slice(6)];
      const full = await pagedRecovery({ owner, auditor, rows });
      const page = { owner, auditor, rows, pageSize: 1, maxPages: 1 };
      let step = await pagedRecovery(page);
      let pauses = 0;
      while (step.kind === "paused") {
        const held = retainedRecovery(step.progress);
        expect(held.notes).toBeLessThanOrEqual(1);
        expect(held.claimed).toBeLessThanOrEqual(2);
        expect(held.openSlot).toBe(1);
        expect(held.unseenInputs).toBeLessThanOrEqual(64);
        pauses += 1;
        step = await pagedRecovery({ ...page, progress: step.progress });
      }
      expect(pauses).toBe(rows.length - 1);
      expect(step).toEqual(full);
      expect(step.notes.notes.map((note) => note.outputContext.hash)).toEqual([
        respend.outputSlots[0]!.outputContext.hash,
      ]);
      expect(step.notes.unseenInputs).toEqual(
        [FIRST_NULLIFIER, ...others.map(({ nullifiers }) => nullifiers[0])].slice(0, 64),
      );
      expect(step.notes.unseenInputCount).toBe(71n);
    });

    it("refuses a progress another member started", async () => {
      const auditor = X25519Keypair.generate();
      const owner = ShieldedKeypair.generate();
      const { rows } = await slotSplitHistory(owner, auditor);
      const page = { owner, auditor, rows, pageSize: 1, maxPages: 1 };
      const progress = paused(await pagedRecovery(page));
      await expect(
        pagedRecovery({ ...page, owner: ShieldedKeypair.generate(), progress }),
      ).rejects.toThrow(ringError("RING_RECOVERY_PROGRESS_MISMATCH"));
    });
  });
});
