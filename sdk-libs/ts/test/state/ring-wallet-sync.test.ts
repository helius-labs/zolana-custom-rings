import { equalBytes } from "@heliuslabs/spr/internal";
import type { Address } from "@heliuslabs/spr/interface";
import { address, type Signature } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";
import {
  Data,
  LocalShieldedKeys,
  SOL_MINT,
  ShieldedKeypair,
  Utxo,
  ViewingKey,
  syncWallet,
  type Bytes16,
  type Bytes32,
} from "@heliuslabs/spr";
import { DEFAULT_TREE_ID, type Bytes33 } from "@heliuslabs/spr/interface";
import { X25519PublicKey } from "@heliuslabs/spr/keypair";
import {
  bytesKey,
  ZERO_NULLIFIER_PK,
  encodeBase58,
  encodeMergeOutputData,
  encryptMergeOutput,
  mergeOutputBlinding,
  mergeOutputKey,
  poseidon,
} from "@heliuslabs/spr/internal";
import {
  AssetRegistry,
  Wallet,
  ownerUtxoHash,
  type IndexedShieldedTransaction,
} from "@heliuslabs/spr/transaction";

import {
  encodeRingBodyOutput,
  encodeRingOutput,
  RingScheme,
} from "../../src/protocol/transaction/output.js";
import { sealRecipientBody } from "../../src/protocol/codec/anonymous-delivery.js";
import { deliveredSlotSecret, slotTag } from "../../src/crypto/derivation/ring-stream.js";
import { noteState } from "../../src/state/exposed-notes.js";
import { LocalRingKeys } from "../../src/state/ring-keys.js";
import { openRingNotes, syncRingWallet, type RingSyncClient } from "../../src/state/ring-sync.js";
import { AnonymousWallet } from "../../src/state/anonymous-wallet.js";
import { ViewingHistory } from "../../src/state/viewing-history.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const SALT = new Uint8Array(16).fill(7) as Bytes16;
const FIRST_NULLIFIER = new Uint8Array(32).fill(9) as Bytes32;
const AMOUNT = 25_000n;

/** Below the field modulus, a commitment binds it. */
function blinding(fill = 3): Bytes32 {
  const bytes = new Uint8Array(32).fill(fill);
  bytes[0] = 0;
  return bytes as Bytes32;
}

function note(
  owner: ShieldedKeypair,
  asset: Address = SOL_MINT,
  fill?: number,
): Readonly<{ utxo: Utxo; hash: Bytes32 }> {
  const utxo = new Utxo({
    owner: owner.shieldedAddress().signingPublicKey,
    asset,
    amount: AMOUNT,
    blinding: blinding(fill),
    data: new Data(),
    ringProgramId: RING,
  });
  return { utxo, hash: utxo.hash(owner.nullifierPublicKey(), DEFAULT_TREE_ID) };
}

function transaction(
  txKey: ViewingKey,
  viewTag: Bytes32,
  hash: Bytes32,
  payload: Uint8Array,
): IndexedShieldedTransaction {
  return {
    slot: 1n,
    txSignature: "1".repeat(64) as Signature,
    txViewingPublicKey: txKey.publicKey(),
    salt: SALT,
    outputSlots: [
      {
        viewTag,
        outputContext: { hash, tree: TREE, treeId: DEFAULT_TREE_ID, leafIndex: 0n },
        payload,
      },
    ],
    messages: [],
    nullifiers: [FIRST_NULLIFIER],
    proofless: false,
    ringProgramId: RING,
  };
}

async function opened(
  keys: Parameters<typeof openRingNotes>[0]["keys"],
  transactions: readonly IndexedShieldedTransaction[],
) {
  return openRingNotes({ keys, assets: new AssetRegistry(), transactions });
}

describe("openRingNotes", () => {
  it("opens a delivered note under ring keys by trial over the registered mints", async () => {
    const recipient = ShieldedKeypair.generate();
    const tx = ringBody(recipient);
    const notes = await opened(LocalRingKeys.fromKeypair(recipient), [tx]);
    expect(notes.utxos.map((entry) => [entry.utxo.amount, entry.utxo.asset])).toEqual([
      [AMOUNT, SOL_MINT],
    ]);
    expect(notes.utxos[0]?.outputContext.hash).toEqual(note(recipient).hash);
    expect(notes.utxos[0]?.outputContext.tree).toBe(TREE);
    expect(notes.utxos[0]?.spent).toBe(false);
    expect(notes.pendingOpenings).toEqual([]);
    const plain = await opened(LocalShieldedKeys.fromKeypair(recipient), [tx]);
    expect(plain.utxos).toEqual([]);
    const stranger = await opened(LocalRingKeys.fromKeypair(ShieldedKeypair.generate()), [tx]);
    expect(stranger).toEqual({ utxos: [], pendingOpenings: [] });
  });
});

/** `rows` answer tag reads and `spends` nullifier reads, every page snapshots `tip`. */
function syncClient(
  transactions: readonly IndexedShieldedTransaction[],
  spends: readonly IndexedShieldedTransaction[] = [],
) {
  const rows = [...transactions];
  const spent = [...spends];
  const tip = { slot: 20n };
  const page = <T>(data: readonly T[]) => ({
    context: { slot: tip.slot, blockTime: 0n },
    data,
    paginationToken: null,
  });
  return {
    rows,
    spent,
    tip,
    getEncryptedUtxosByTags: vi.fn<RingSyncClient["getEncryptedUtxosByTags"]>(async () => page([])),
    getShieldedTransactionsByTags: vi.fn<RingSyncClient["getShieldedTransactionsByTags"]>(
      async (request) =>
        page(
          rows
            .filter((tx) => tx.slot > (request.filters?.slot?.gt ?? 0n))
            // An indexer serves only a row publishing a requested tag.
            .filter((tx) =>
              [...tx.outputSlots, ...tx.messages].some(({ viewTag }) =>
                request.tags.some((tag) => equalBytes(tag, viewTag)),
              ),
            )
            .map((tx) => ({ slot: tx.slot, signature: tx.txSignature, events: [tx] })),
        ),
    ),
    getShieldedTransactionsByNullifiers: vi.fn<
      RingSyncClient["getShieldedTransactionsByNullifiers"]
    >(async (request) =>
      page(
        spent
          .filter((tx) => tx.slot > (request.filters?.slot?.gt ?? 0n))
          .filter((tx) =>
            tx.nullifiers.some((nullifier) =>
              request.nullifiers.some((asked) => equalBytes(asked, nullifier)),
            ),
          )
          .map((tx) => ({ slot: tx.slot, signature: tx.txSignature, events: [tx] })),
      ),
    ),
  };
}

function ringWallet(owner: ShieldedKeypair): AnonymousWallet {
  const identity = owner.shieldedAddress();
  return AnonymousWallet.create(
    new Wallet({ identity }),
    ViewingHistory.create(identity.viewingPublicKey, 0n),
  );
}

/** Ring body under the sender's agreement with the recipient key. */
function ringBody(
  recipient: ShieldedKeypair,
  hash: Bytes32 = note(recipient).hash,
  mint: Address = SOL_MINT,
  fill?: number,
): IndexedShieldedTransaction {
  const txKey = ViewingKey.generate();
  const viewing = recipient.shieldedAddress().viewingPublicKey;
  const slotSecret = deliveredSlotSecret({
    agreement: txKey.ecdh(viewing),
    txViewingKey: txKey.publicKey(),
    recipientViewingKey: viewing,
    salt: SALT,
    outputIndex: 0,
    firstNullifier: FIRST_NULLIFIER,
  });
  const body = sealRecipientBody(slotSecret, {
    blinding: blinding(fill),
    amount: AMOUNT,
    mint,
  });
  return transaction(
    txKey,
    slotTag(viewing.u()),
    hash,
    encodeRingBodyOutput(body, new Uint8Array()),
  );
}

describe("ring bodies", () => {
  it("opens a note under the ring key with its mint from the body", async () => {
    const recipient = ShieldedKeypair.generate();
    const notes = await opened(LocalRingKeys.fromKeypair(recipient), [
      ringBody(recipient, note(recipient).hash),
    ]);
    expect(notes.utxos.map((entry) => [entry.utxo.amount, entry.utxo.asset])).toEqual([
      [AMOUNT, SOL_MINT],
    ]);
    const [held] = notes.utxos;
    if (held === undefined) throw new Error("no note");
    expect(noteState(held)).toBe("spendable");
  });

  it("opens a note under the zero key as exposed", async () => {
    const recipient = ShieldedKeypair.generate();
    const hash = note(recipient).utxo.hash(ZERO_NULLIFIER_PK as Bytes32, DEFAULT_TREE_ID);
    const notes = await opened(LocalRingKeys.fromKeypair(recipient), [ringBody(recipient, hash)]);
    const [held] = notes.utxos;
    if (held === undefined) throw new Error("no note");
    expect(noteState(held)).toBe("exposedIfSpent");
  });

  it("skips a commitment neither candidate rebuilds", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const other = new Uint8Array(32).fill(1) as Bytes32;
    expect(await opened(keys, [ringBody(recipient, other)])).toEqual({
      utxos: [],
      pendingOpenings: [],
    });
  });

  it("refuses the sync when the holder fails on a ring body slot", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const failure = new Error("holder offline");
    vi.spyOn(keys, "ringTagMatches").mockRejectedValue(failure);
    await expect(opened(keys, [ringBody(recipient, note(recipient).hash)])).rejects.toBe(failure);
  });
});

/** A ring merge spending `nullifier`, its output encrypted under the owner's nullifier key. */
function mergeOf(owner: ShieldedKeypair, nullifier: Bytes32, mint: Address) {
  const key = owner.nullifierKey();
  const salt = new Uint8Array(16).fill(3) as Bytes16;
  const ringDataHash = new Uint8Array(32).fill(5) as Bytes32;
  const commitment = ownerUtxoHash({
    owner: poseidon([
      owner.shieldedAddress().signingPublicKey.ownerProofInputHash(),
      key.publicKey(),
    ]),
    asset: mint,
    amount: AMOUNT,
    blinding: mergeOutputBlinding(key, nullifier),
    treeId: DEFAULT_TREE_ID,
    ringDataHash,
    ringProgramId: RING,
  });
  const transaction: IndexedShieldedTransaction = {
    slot: 25n,
    txSignature: "6".repeat(64) as Signature,
    eventIndex: 0,
    proofless: false,
    ringProgramId: RING,
    nullifiers: [nullifier, new Uint8Array(32).fill(7) as Bytes32],
    messages: [],
    outputSlots: [
      {
        viewTag: nullifier,
        payload: encodeMergeOutputData({
          salt,
          ciphertext: encryptMergeOutput(
            { amount: AMOUNT, mint },
            mergeOutputKey(key, nullifier),
            salt,
          ),
          ringDataHash,
        }),
        outputContext: { hash: commitment, tree: TREE, treeId: DEFAULT_TREE_ID, leafIndex: 4n },
      },
    ],
  };
  return { transaction, commitment };
}

describe("syncRingWallet", () => {
  it("reads a confidential payment under the slot tag it publishes", async () => {
    const recipient = ShieldedKeypair.generate();
    const ring = ringWallet(recipient);
    const { wallet } = ring;
    const client = syncClient([ringBody(recipient)]);
    await syncRingWallet({ wallet: ring, keys: LocalRingKeys.fromKeypair(recipient), client });
    expect(wallet.utxos().map((entry) => entry.utxo.amount)).toEqual([AMOUNT]);
  });

  it("counts ring notes and reads no completed history on a second sync", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const ring = ringWallet(recipient);
    const { wallet } = ring;
    const client = syncClient([ringBody(recipient)]);
    const retry = { numRetries: 2, delayMs: 1n, maxDelayMs: 2n };
    const context = { signal: new AbortController().signal };
    const input = {
      wallet: ring,
      keys,
      client,
      config: { requireSlot: 7n, retry, queryChunk: 3, pageLimit: 5 },
    };

    const report = await syncRingWallet(input, context);

    expect(report.storedUtxos).toBe(1);
    expect(wallet.utxos().map((entry) => entry.utxo.amount)).toEqual([AMOUNT]);
    // The core tags, then the slot tag a delivery publishes beside the owner tag a zero-key merge carries.
    const viewing = keys.viewingPublicKeys()[0]!;
    const owner = recipient.shieldedAddress().signingPublicKey.ownerProofInputHash();
    expect(
      client.getShieldedTransactionsByTags.mock.calls.map(([request]) => request.tags),
    ).toEqual([expect.anything(), [slotTag(viewing.u()), owner]]);
    expect(client.getEncryptedUtxosByTags.mock.calls.map(([request]) => request.tags)).toEqual([
      expect.anything(),
      [viewing.u()],
    ]);
    expect(client.getShieldedTransactionsByTags.mock.calls[1]).toEqual([
      expect.objectContaining({ limit: 5 }),
      { poll: retry, requireSlot: 7n },
      context,
    ]);
    expect(client.getShieldedTransactionsByNullifiers.mock.calls[0]).toEqual([
      expect.objectContaining({ limit: 5, nullifiers: [wallet.utxos()[0]?.nullifier] }),
      { poll: retry, requireSlot: 7n },
      context,
    ]);
    for (const stream of ["transactions", "proofless"] as const)
      expect(wallet._syncCheckpoint(stream, bytesKey(viewing.u()))).toBe(20n);
    expect(ring.history().current().tagPosition).toBe(20n);
    expect(ring.toJson()).toContain('"tagPosition":20}');

    const tagged = client.getShieldedTransactionsByTags.mock.calls.length;
    const deposits = client.getEncryptedUtxosByTags.mock.calls.length;
    const second = await syncRingWallet(input, context);

    expect(second.storedUtxos).toBe(0);
    expect(wallet.utxos()).toHaveLength(1);
    const reads = [
      ...client.getShieldedTransactionsByTags.mock.calls.slice(tagged),
      ...client.getEncryptedUtxosByTags.mock.calls.slice(deposits),
    ];
    expect(reads).toHaveLength(4);
    for (const [request] of reads) expect(request.filters).toEqual({ slot: { gt: 20n } });
  });

  it("opens a later payment and a spend once above the cursors", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const ring = ringWallet(recipient);
    const { wallet } = ring;
    const client = syncClient([ringBody(recipient)]);
    await syncRingWallet({ wallet: ring, keys, client });
    const [first] = wallet.utxos();
    if (first === undefined) throw new Error("no note");
    const later = {
      ...ringBody(recipient, note(recipient, SOL_MINT, 2).hash, SOL_MINT, 2),
      slot: 25n,
    };
    client.rows.push(later);
    client.spent.push({
      ...later,
      txSignature: "3".repeat(64) as Signature,
      nullifiers: [first.nullifier],
      outputSlots: [],
    });
    client.tip.slot = 30n;

    const report = await syncRingWallet({ wallet: ring, keys, client });

    expect(report.storedUtxos).toBe(1);
    expect(wallet.utxos().map((entry) => [entry.utxo.amount, entry.spent])).toEqual([
      [AMOUNT, true],
      [AMOUNT, false],
    ]);
    const third = await syncRingWallet({ wallet: ring, keys, client });
    expect(third.storedUtxos).toBe(0);
    expect(wallet.utxos()).toHaveLength(2);
  });

  it("reads ring notes below an existing core checkpoint", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const ring = ringWallet(recipient);
    const { wallet } = ring;
    const client = syncClient([ringBody(recipient)]);
    await syncWallet({ wallet, keys, client });
    const tag = bytesKey(keys.viewingPublicKeys()[0]!.u());
    expect(wallet._syncCheckpoint("transactions", tag)).toBe(20n);
    expect(wallet.utxos()).toEqual([]);

    const report = await syncRingWallet({ wallet: ring, keys, client });

    expect(report.storedUtxos).toBe(1);
    expect(wallet.utxos().map((entry) => entry.utxo.amount)).toEqual([AMOUNT]);
    const slotRead = client.getShieldedTransactionsByTags.mock.calls.find(([request]) =>
      equalBytes(request.tags[0]!, slotTag(keys.viewingPublicKeys()[0]!.u())),
    );
    expect(slotRead?.[0].filters).toBeUndefined();
  });

  it("reads delivered history after ring derivation keys become available", async () => {
    const recipient = ShieldedKeypair.generate();
    const ring = ringWallet(recipient);
    const { wallet } = ring;
    const client = syncClient([ringBody(recipient)]);
    await syncRingWallet({ wallet: ring, keys: LocalShieldedKeys.fromKeypair(recipient), client });
    expect(wallet.utxos()).toEqual([]);

    const report = await syncRingWallet({
      wallet: ring,
      keys: LocalRingKeys.fromKeypair(recipient),
      client,
    });

    expect(report.storedUtxos).toBe(1);
    expect(wallet.utxos().map((entry) => entry.utxo.amount)).toEqual([AMOUNT]);
  });

  it("keeps the wallet unchanged when a ring spend read fails", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const ring = ringWallet(recipient);
    const { wallet } = ring;
    const client = syncClient([ringBody(recipient)]);
    const failure = new Error("unavailable");
    client.getShieldedTransactionsByNullifiers.mockRejectedValueOnce(failure);
    const before = wallet._state();
    const revision = wallet._revision;

    await expect(syncRingWallet({ wallet: ring, keys, client })).rejects.toBe(failure);

    expect(wallet._state()).toEqual(before);
    expect(wallet._revision).toBe(revision);
    expect(wallet.lastSynced).toBe(0n);
    expect(wallet._checkpointEntries("transactions")).toEqual([]);
    expect(wallet._checkpointEntries("proofless")).toEqual([]);
  });

  it("keeps the wallet unchanged when ring nullifier derivation fails", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const ring = ringWallet(recipient);
    const { wallet } = ring;
    const client = syncClient([ringBody(recipient)]);
    vi.spyOn(keys, "derive").mockResolvedValue([]);
    const before = wallet._state();

    await expect(syncRingWallet({ wallet: ring, keys, client })).rejects.toMatchObject({
      code: "WALLET_KEYS_BATCH_MISMATCH",
    });

    expect(wallet._state()).toEqual(before);
    expect(wallet._checkpointEntries("transactions")).toEqual([]);
    expect(client.getShieldedTransactionsByNullifiers).not.toHaveBeenCalled();
  });

  it("refuses the sync and moves nothing when the key holder fails on a delivered slot", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const ring = ringWallet(recipient);
    const { wallet } = ring;
    const client = syncClient([ringBody(recipient)]);
    const failure = new Error("holder offline");
    vi.spyOn(keys, "ringTagMatches").mockRejectedValue(failure);
    const before = wallet._state();

    await expect(syncRingWallet({ wallet: ring, keys, client })).rejects.toBe(failure);

    expect(wallet._state()).toEqual(before);
    expect(wallet.lastSynced).toBe(0n);
    expect(wallet._checkpointEntries("transactions")).toEqual([]);
  });

  it("refuses a holder that answers no secret for a delivered slot", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    vi.spyOn(keys, "ringTagMatches").mockResolvedValue([]);
    await expect(opened(keys, [ringBody(recipient)])).rejects.toMatchObject({
      code: "WALLET_KEYS_BATCH_MISMATCH",
    });
  });

  it("skips a body off its length and keeps the note beside it", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const good = ringBody(recipient);
    const [slot] = good.outputSlots;
    if (slot === undefined) throw new Error("no slot");
    const short = {
      ...good,
      txSignature: "2".repeat(64) as Signature,
      outputSlots: [
        {
          ...slot,
          payload: encodeRingOutput(RingScheme.ringBody, new Uint8Array(5)),
        },
      ],
    };
    const notes = await opened(keys, [short, good]);
    expect(notes.utxos.map((entry) => entry.utxo.amount)).toEqual([AMOUNT]);
  });

  it("asks the holder nothing for a published key or first nullifier no agreement accepts", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const asked = vi.spyOn(keys, "ringTagMatches");
    const good = ringBody(recipient);
    const smallOrder = X25519PublicKey.fromBytes(
      new Uint8Array([4, ...new Uint8Array(32)]) as Bytes33,
    );
    const notes = await opened(keys, [
      { ...good, txViewingPublicKey: smallOrder },
      { ...good, nullifiers: [new Uint8Array(32).fill(0xff) as Bytes32] },
    ]);
    expect(notes).toEqual({ utxos: [], pendingOpenings: [] });
    expect(asked).not.toHaveBeenCalled();
  });

  it("keeps an unknown-mint note pending beside a payment, then promotes it on registration", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const ring = ringWallet(recipient);
    const unknownMint = encodeBase58(new Uint8Array(32).fill(1));
    const pending = {
      ...ringBody(recipient, note(recipient, unknownMint).hash, unknownMint),
      txSignature: "2".repeat(64) as Signature,
    };
    const client = syncClient([pending, ringBody(recipient)]);

    await syncRingWallet({ wallet: ring, keys, client });

    // The payment stays visible, the pending note waits outside every balance and selection.
    expect(ring.wallet.utxos().map((entry) => entry.utxo.asset)).toEqual([SOL_MINT]);
    expect(ring.wallet.ringBalances()).toHaveLength(1);
    expect(ring.pendingOpenings().map((entry) => entry.utxo.asset)).toEqual([unknownMint]);
    const restored = AnonymousWallet.fromJson(ring.toJson());
    expect(restored.pendingOpenings().map((entry) => entry.outputContext.hash)).toEqual([
      pending.outputSlots[0]!.outputContext.hash,
    ]);

    const calls = client.getShieldedTransactionsByTags.mock.calls.length;
    restored.wallet.ensureAsset(9n, unknownMint);
    const report = await syncRingWallet({ wallet: restored, keys, client });

    expect(report.storedUtxos).toBe(1);
    expect(restored.pendingOpenings()).toEqual([]);
    expect(
      restored.wallet
        .utxos()
        .map((entry) => entry.utxo.asset)
        .sort(),
    ).toEqual([SOL_MINT, unknownMint].sort());
    for (const [request] of client.getShieldedTransactionsByTags.mock.calls.slice(calls))
      expect(request.filters).toEqual({ slot: { gt: 20n } });
  });

  it("refuses a held key the history lists no entry for and moves nothing", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const identity = recipient.shieldedAddress();
    const ring = AnonymousWallet.create(
      new Wallet({ identity }),
      ViewingHistory.create(ShieldedKeypair.generate().shieldedAddress().viewingPublicKey, 0n),
    );
    const client = syncClient([ringBody(recipient)]);
    const before = ring.toJson();

    await expect(syncRingWallet({ wallet: ring, keys, client })).rejects.toMatchObject({
      code: "RING_HELD_KEY_NOT_IN_HISTORY",
    });

    expect(ring.toJson()).toBe(before);
    expect(client.getShieldedTransactionsByTags.mock.calls).toHaveLength(1);
  });

  it("refuses a stored document whose pending notes name another identity", () => {
    const document = JSON.parse(ringWallet(ShieldedKeypair.generate()).toJson()) as Record<
      string,
      unknown
    >;
    const other = JSON.parse(ringWallet(ShieldedKeypair.generate()).toJson()) as Record<
      string,
      unknown
    >;
    expect(() =>
      AnonymousWallet.fromJson(JSON.stringify({ ...document, pending: other["pending"] })),
    ).toThrow(expect.objectContaining({ code: "RING_WALLET_DOCUMENT" }));
  });

  it("stores a merge output of an unregistered mint as pending and spendable once the mint registers", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const ring = ringWallet(recipient);
    const { hash } = note(recipient);
    const nullifier = recipient.nullifierKey().nullifier(hash, blinding());
    const unknownMint = encodeBase58(new Uint8Array(32).fill(1));
    const merge = mergeOf(recipient, nullifier, unknownMint);
    const client = syncClient([ringBody(recipient)], [merge.transaction]);

    await syncRingWallet({ wallet: ring, keys, client });

    expect(ring.wallet.utxos().map((entry) => [entry.outputContext.hash, entry.spent])).toEqual([
      [hash, true],
    ]);
    expect(ring.pendingOpenings().map((entry) => entry.outputContext.hash)).toEqual([
      merge.commitment,
    ]);
    expect(ring._mergeRetries()).toEqual([]);
    ring.wallet.ensureAsset(9n, unknownMint);
    await syncRingWallet({ wallet: ring, keys, client });
    expect(ring.pendingOpenings()).toEqual([]);
    expect(ring.wallet.utxos().map((entry) => entry.outputContext.hash)).toEqual([
      hash,
      merge.commitment,
    ]);
  });

  it("rereads a stored merge retry until the indexer returns its spend row", async () => {
    const recipient = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(recipient);
    const { hash } = note(recipient);
    const nullifier = recipient.nullifierKey().nullifier(hash, blinding());
    const merge = mergeOf(recipient, nullifier, SOL_MINT);
    const client = syncClient([ringBody(recipient)], [{ ...merge.transaction, outputSlots: [] }]);
    const synced = ringWallet(recipient);
    await syncRingWallet({ wallet: synced, keys, client });
    // A Rust sync whose registry lacked the merge mint stored the spend as a retry.
    const document = JSON.parse(synced.toJson()) as Record<string, unknown>;
    expect(document["mergeRetries"]).toEqual([]);
    const ring = AnonymousWallet.fromJson(
      JSON.stringify({ ...document, mergeRetries: [bytesKey(nullifier)] }),
    );

    // A lagging indexer returns no spend row, the retry stays.
    client.spent.length = 0;
    await syncRingWallet({ wallet: ring, keys, client });
    expect(ring._mergeRetries()).toEqual([nullifier]);
    expect(ring.wallet.utxos()).toHaveLength(1);

    client.spent.push(merge.transaction);
    await syncRingWallet({ wallet: ring, keys, client });
    expect(ring._mergeRetries()).toEqual([]);
    expect(ring.wallet.utxos().map((entry) => [entry.outputContext.hash, entry.spent])).toEqual([
      [hash, true],
      [merge.commitment, false],
    ]);
    expect(JSON.parse(ring.toJson())).toMatchObject({ mergeRetries: [] });
  });
});
