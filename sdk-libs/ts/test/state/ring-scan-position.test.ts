import { encodeRingBodyOutput } from "../../src/protocol/transaction/output.js";
import { describe, expect, it, vi } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import type { Address } from "@solana/kit";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { randomSalt, ShieldedAddress, ViewingKey } from "@heliuslabs/spr/keypair";
import {
  AssetRegistry,
  deserializeWallet,
  serializeWallet,
  Utxo,
  Wallet,
} from "@heliuslabs/spr/transaction";

import { recipientTag, txKeySlotSecret, slotTag } from "../../src/crypto/derivation/ring-stream.js";

import { AnonymousSync } from "../../src/state/anonymous-sync.js";
import { AnonymousWallet } from "../../src/state/anonymous-wallet.js";
import { LocalRingKeys } from "../../src/state/ring-keys.js";
import { StreamCounter, ViewingHistory } from "../../src/state/viewing-history.js";
import { ClientError } from "@heliuslabs/spr/client";
import {
  ASSETS,
  found,
  hex,
  keypair,
  output,
  RING,
  ScanIndexer,
  ScanWallet,
  sealedNote,
  signature,
} from "../helpers/ring-scan.js";
import { randomAddress, TREE, TREE_ID } from "../helpers/ring-pipeline.js";

await initializePoseidon();

/** A body under `mint`, published at slot 4, its hash returned. */
function unknownMintPayment(indexer: ScanIndexer, reader: ScanWallet, mint: Address): string {
  const txKey = ViewingKey.generate();
  const salt = randomSalt();
  const firstNullifier = new Uint8Array(32).fill(0x0f) as Bytes32;
  const blinding = new Uint8Array(32).fill(0x12) as Bytes32;
  const { address: owner } = reader;
  const secret = (): Bytes32 =>
    txKeySlotSecret({
      txViewingKey: txKey,
      recipientViewingKey: owner.viewingPublicKey,
      salt,
      outputIndex: 0,
      firstNullifier,
    });
  const utxoHash = new Utxo({
    owner: owner.signingPublicKey,
    asset: mint,
    amount: 7n,
    blinding,
    ringProgramId: RING,
  }).hash(owner.nullifierPublicKey, TREE_ID);
  indexer.publish({
    slot: 4n,
    txSignature: signature(77n),
    eventIndex: 0,
    txViewingPublicKey: txKey.publicKey(),
    salt,
    outputSlots: [
      {
        viewTag: slotTag(recipientTag(secret())),
        outputContext: { hash: utxoHash, tree: TREE, treeId: TREE_ID, leafIndex: 0n },
        payload: encodeRingBodyOutput(
          sealedNote(secret(), { owner, blinding, amount: 7n, mint }),
          new Uint8Array(),
        ),
      },
    ],
    messages: [],
    nullifiers: [firstNullifier],
    proofless: false,
    ringProgramId: RING,
  });
  return hex(utxoHash);
}

function anonymousWallet(owner: ScanWallet, history: ViewingHistory): AnonymousWallet {
  return AnonymousWallet.create(new Wallet({ identity: owner.address, registry: ASSETS }), history);
}

function position(history: ViewingHistory): bigint | null | undefined {
  return history.current().ringPosition(RING);
}

/** Three transfers to `bob`, the two later ones in one slot. */
async function slotSplit(indexer: ScanIndexer, bob: ScanWallet, alice: ScanWallet) {
  return [
    await alice.pay(indexer, [{ to: bob.address, amount: 1n }], { slot: 10n }),
    await alice.pay(indexer, [{ to: bob.address, amount: 2n }], { slot: 20n }),
    await alice.pay(indexer, [{ to: bob.address, amount: 3n }], { slot: 20n }),
  ] as const;
}

describe("ring scan position", () => {
  it("loses and repeats no row across a page split inside one slot", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await slotSplit(indexer, bob, alice);
    indexer.contexts.push(20n, 20n, 25n);
    const scan = await AnonymousSync.create(bob.keys, ASSETS)
      .withScanLimits({ pageSize: 1 })
      .fetch(indexer.client(), bob.fresh());
    expect(scan.utxos.map((note) => note.utxo.amount).sort()).toEqual([1n, 2n, 3n]);
    expect(indexer.ringReads).toHaveLength(3);
    expect(position(scan.history)).toBe(25n);
  });

  it("reads strictly past the terminal context on the next run, with no token", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 1n }], { slot: 10n });
    indexer.contexts.push(40n);
    const first = await bob.sync(indexer, bob.fresh());
    expect(position(first.history)).toBe(40n);
    const late = await alice.pay(indexer, [{ to: bob.address, amount: 2n }], { slot: 41n });
    const next = await bob.sync(indexer, first.history);
    expect(indexer.ringReads.at(-1)?.filters).toEqual({ slot: { gt: 40n } });
    expect(indexer.ringReads.at(-1)?.paginationToken).toBeUndefined();
    expect(found(next)).toEqual([hex(output(late, 1))]);
  });

  it("keeps a final page's context below an earlier page's, and never lowers a stored position", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await slotSplit(indexer, bob, alice);
    indexer.contexts.push(50n, 50n, 30n);
    const limited = AnonymousSync.create(bob.keys, ASSETS).withScanLimits({ pageSize: 1 });
    const scan = await limited.fetch(indexer.client(), bob.fresh());
    expect(position(scan.history)).toBe(30n);

    const replica = new ScanIndexer();
    replica.contexts.push(12n);
    const raised = bob.fresh()._withRingCheckpoint(RING, bob.viewingKey, 30n);
    const lower = await limited.fetch(replica.client(), raised);
    expect(position(lower.history)).toBe(30n);
  });

  it("moves no position from a capped read and refuses a repeating token", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await slotSplit(indexer, bob, alice);
    const capped = await AnonymousSync.create(bob.keys, ASSETS)
      .withScanLimits({ pageSize: 1, maxPages: 1 })
      .fetch(indexer.client(), bob.fresh());
    expect(capped.utxos).toHaveLength(1);
    expect(position(capped.history)).toBeNull();
    const looping = {
      ...indexer.client(),
      getShieldedTransactionsByTags: async () => ({
        context: { slot: 9n, blockTime: 0n },
        paginationToken: "9:same",
        data: [],
      }),
    };
    await expect(
      bob.sync({ client: () => looping } as unknown as ScanIndexer, bob.fresh()),
    ).rejects.toThrow("RING_HISTORY_PAGE_INVALID");
  });

  it("keeps the position through a refused page, the next run finds the same notes once", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await slotSplit(indexer, bob, alice);
    const history = bob.fresh();
    const wallet = anonymousWallet(bob, history);
    const limited = AnonymousSync.create(bob.keys, ASSETS).withScanLimits({ pageSize: 1 });
    indexer.refuseAt = { read: 2, error: new Error("-32016") };
    await expect(limited.fetch(indexer.client(), history)).rejects.toThrow("-32016");
    expect(position(history)).toBeNull();
    indexer.refuseAt = undefined;
    const scan = await limited.fetch(indexer.client(), history);
    await wallet.absorb(scan);
    expect(wallet.notes()).toHaveLength(3);
    expect(position(wallet.history())).toBe(20n);
  });

  it("reads from the enrollment floor, keeping the whole enrollment slot", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 1n }], { slot: 10n });
    const paid = await alice.pay(indexer, [{ to: bob.address, amount: 2n }], { slot: 11n });
    const history = ViewingHistory.create(bob.viewingKey, 0n).withRing(RING, 10n);
    const scan = await bob.sync(indexer, history);
    expect(indexer.ringReads[0]?.filters).toEqual({ slot: { gt: 10n } });
    expect(found(scan)).toEqual([hex(output(paid, 1))]);
  });

  it("restarts from stored state with the same notes and no repeat", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const [, , last] = await slotSplit(indexer, bob, alice);
    const wallet = anonymousWallet(bob, bob.fresh());
    await wallet.absorb(await bob.sync(indexer, bob.fresh()));
    const back = AnonymousWallet.fromJson(wallet.toJson());
    expect(back.notes()).toHaveLength(3);
    expect(position(back.history())).toBe(last.slot);
    const again = await bob.sync(indexer, back.history());
    expect(again.found).toEqual([]);
    expect(indexer.ringReads.at(-1)?.filters).toEqual({ slot: { gt: last.slot } });
  });
});

describe("atomic progress", () => {
  it("keeps a counter taken during a scan, the next deposit tag never repeats", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 7n }], { slot: 9n });
    const wallet = anonymousWallet(bob, bob.fresh());
    const scan = await bob.sync(indexer, wallet.history());
    const during = await wallet.history().senderTag(bob.keys);
    wallet.updateHistory(during.history);
    await wallet.absorb(scan);
    expect(wallet.history().current().txCount).toBe(1n);
    expect(position(wallet.history())).toBe(9n);
    expect(wallet.notes().map((note) => note.utxo.amount)).toEqual([7n]);
    const after = await wallet.history().senderTag(bob.keys);
    expect(hex(after.tag)).not.toBe(hex(during.tag));
  });

  it("keeps a key added during a scan, unread for the next sync", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 7n }], { slot: 9n });
    const wallet = anonymousWallet(bob, bob.fresh());
    const scan = await bob.sync(indexer, wallet.history());
    const added = ViewingKey.generate().publicKey();
    wallet.updateHistory(wallet.history().withRotatedKey(added, 5n));
    await wallet.absorb(scan);
    expect(wallet.history().current().viewingPublicKey.equals(added)).toBe(true);
    expect(wallet.history().entry(added)?.ringPosition(RING)).toBeNull();
    expect(wallet.history().entry(bob.viewingKey)?.ringPosition(RING)).toBe(9n);
  });

  it("keeps a sender confirmed and a ring added during a scan", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 7n }], { slot: 9n });
    const wallet = anonymousWallet(bob, bob.fresh());
    const scan = await bob.sync(indexer, wallet.history());
    const ring = randomAddress();
    wallet.updateHistory(wallet.history().withConfirmedSender(alice.viewingKey).withRing(ring));
    await wallet.absorb(scan);
    const entry = wallet.history().current();
    expect(entry.knownSenders().some((key) => key.equals(alice.viewingKey))).toBe(true);
    expect(entry.ringPosition(ring)).toBeNull();
    expect(entry.ringPosition(RING)).toBe(9n);
  });

  it("refuses a scan once another scan moved the progress, without consuming it", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 7n }], { slot: 9n });
    const original = bob.fresh();
    const wallet = anonymousWallet(bob, original);
    const late = await bob.sync(indexer, original);
    await wallet.absorb(await bob.sync(indexer, original));
    const stored = wallet.toJson();
    await expect(wallet.absorb(late)).rejects.toThrow("RING_SCAN_HISTORY_CHANGED");
    expect(wallet.toJson()).toBe(stored);
    const unchanged = anonymousWallet(bob, ViewingHistory.fromJson(original.toJson()));
    await unchanged.absorb(late);
    expect(unchanged.notes().map((note) => note.utxo.amount)).toEqual([7n]);
  });

  it("refuses a history whose tag counter falls, the tag would repeat", async () => {
    const bob = new ScanWallet(2);
    const base = bob.fresh();
    const wallet = anonymousWallet(bob, base);
    wallet.updateHistory((await base.senderTag(bob.keys)).history);
    expect(() => wallet.updateHistory(base)).toThrow("RING_SCAN_PROGRESS_MOVED");
    expect(wallet.history().current().txCount).toBe(1n);
  });

  it("gives concurrent callers distinct tags and burns the index of a failed holder", async () => {
    const bob = new ScanWallet(2);
    const wallet = anonymousWallet(bob, bob.fresh());
    const tags = await Promise.all([
      wallet.takeSenderTag(bob.keys),
      wallet.takeSenderTag(bob.keys),
    ]);
    expect(new Set(tags.map(hex)).size).toBe(2);
    expect(wallet.history().current().txCount).toBe(2n);
    const failing = {
      ...bob.keys,
      viewTags: () => Promise.reject(new Error("holder offline")),
    } as unknown as typeof bob.keys;
    await expect(wallet.takeSenderTag(failing)).rejects.toThrow("holder offline");
    expect(wallet.history().current().txCount).toBe(3n);
  });

  it("stores notes, spends, claims and the position in one document", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 7n, reply: alice.replyTo() }], {
      slot: 9n,
    });
    const wallet = anonymousWallet(bob, bob.fresh());
    await wallet.absorb(await bob.sync(indexer, bob.fresh()));
    const back = AnonymousWallet.fromJson(wallet.toJson());
    expect(back.notes().map((note) => note.utxo.amount)).toEqual([7n]);
    expect(position(back.history())).toBe(9n);
    expect(back.pendingClaims()).toHaveLength(1);
    expect(back.toJson()).toBe(wallet.toJson());
  });

  it("skips no funds when notes persist and the crash lands before the position", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 7n }], { slot: 9n });
    const history = bob.fresh();
    const scan = await bob.sync(indexer, history);
    const absorbed = anonymousWallet(bob, history);
    await absorbed.absorb(scan);
    // A store of two writes crashed after the first, the notes stored beside the old position.
    const back = AnonymousWallet.create(
      deserializeWallet(serializeWallet(absorbed.wallet)),
      history,
    );
    expect(back.notes()).toHaveLength(1);
    expect(position(back.history())).toBeNull();
    await back.absorb(await bob.sync(indexer, back.history()));
    expect(back.notes().map((note) => note.utxo.amount)).toEqual([7n]);
    expect(position(back.history())).toBe(9n);
  });

  it("skips no funds when the position is attempted before the notes", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 7n }], { slot: 9n });
    const history = bob.fresh();
    const scan = await bob.sync(indexer, history);
    const wallet = anonymousWallet(bob, history);
    expect(() => wallet.updateHistory(scan.history)).toThrow("RING_SCAN_PROGRESS_MOVED");
    expect(position(wallet.history())).toBeNull();
    // A position written alone reads as no document, the wallet keeps its stored one.
    expect(() => AnonymousWallet.fromJson(scan.history.toJson())).toThrow("RING_WALLET_DOCUMENT");
    await wallet.absorb(await bob.sync(indexer, wallet.history()));
    expect(wallet.notes().map((note) => note.utxo.amount)).toEqual([7n]);
  });

  it("takes a counter or an added key through updateHistory and refuses a moved watermark", async () => {
    const bob = new ScanWallet(2);
    const wallet = anonymousWallet(bob, bob.fresh());
    const { history: counted } = await wallet.history().senderTag(bob.keys);
    wallet.updateHistory(counted);
    expect(wallet.history().current().txCount).toBe(1n);
    const added = ViewingKey.generate().publicKey();
    wallet.updateHistory(wallet.history().withRotatedKey(added, 5n));
    expect(wallet.history().entry(added)?.ringPosition(RING)).toBeNull();
    const entry = wallet.history().current();
    const watermark = wallet
      .history()
      .withEntry(
        wallet.history().entries.length - 1,
        entry.withTxCounter(StreamCounter.restore({ next: 4n, scanned: 4n, pending: [] })),
      );
    expect(() => wallet.updateHistory(watermark)).toThrow("RING_SCAN_PROGRESS_MOVED");
  });

  it("persists a note under an unknown mint as pending with progress advanced, spendable once it registers with no rescan", async () => {
    const indexer = new ScanIndexer();
    const bob = new ScanWallet(2);
    const mint = randomAddress();
    const hash = unknownMintPayment(indexer, bob, mint);
    const scan = await bob.sync(indexer, bob.fresh());
    expect(scan.unknownMints).toEqual([mint]);
    expect(position(scan.history)).toBe(4n);
    const registry = new AssetRegistry();
    const wallet = AnonymousWallet.create(
      new Wallet({ identity: bob.address, registry }),
      bob.fresh(),
    );
    await wallet.absorb(scan);
    expect(wallet.notes()).toEqual([]);
    expect(wallet.pendingOpenings().map((note) => hex(note.outputContext.hash))).toEqual([hash]);
    expect(await wallet.promotePending()).toEqual([]);
    const back = AnonymousWallet.fromJson(wallet.toJson());
    expect(back.pendingOpenings()).toHaveLength(1);
    expect(position(back.history())).toBe(4n);
    back.wallet.ensureAsset(99n, mint);
    const reads = indexer.ringReads.length;
    expect((await back.promotePending()).map((note) => note.utxo.amount)).toEqual([7n]);
    expect(back.pendingOpenings()).toEqual([]);
    expect(back.notes().map((note) => hex(note.outputContext.hash))).toEqual([hash]);
    expect(indexer.ringReads).toHaveLength(reads);
  });

  it("refuses another field and a malformed claim", async () => {
    const bob = new ScanWallet(2);
    const wallet = anonymousWallet(bob, bob.fresh());
    const text = wallet.toJson();
    expect(() =>
      AnonymousWallet.fromJson(text.replace('"history"', '"other":2,"history"')),
    ).toThrow("RING_WALLET_DOCUMENT");
    expect(() =>
      AnonymousWallet.fromJson(text.replace('"claims":[]', '"claims":[{"utxoHash":"zz"}]')),
    ).toThrow("RING_WALLET_DOCUMENT");
  });
});

describe("viewing keys", () => {
  function rotatedHolder(bob: ScanWallet, added: ViewingKey): LocalRingKeys {
    return LocalRingKeys.fromKeys({
      address: bob.address,
      viewingKeys: [bob.keypair.viewingKey(), added],
      listRoot: bob.keypair.viewingKey(),
      nullifierKey: bob.keypair.nullifierKey(),
    });
  }

  it("reads a newly watched ring under every retained key", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const added = keypair(5).viewingKey();
    const history = ViewingHistory.create(bob.viewingKey, 0n)
      .withRotatedKey(added.publicKey(), 5n)
      .withRing(RING);
    const paid = await alice.pay(indexer, [{ to: bob.address, amount: 7n }], { slot: 10n });
    const scan = await AnonymousSync.create(rotatedHolder(bob, added), ASSETS).fetch(
      indexer.client(),
      history,
    );
    expect(found(scan)).toEqual([hex(output(paid, 1))]);
    expect(indexer.ringReads).toHaveLength(1);
    expect(history.withRing(RING, 20n).entries.map((entry) => entry.ringPosition(RING))).toEqual([
      null,
      null,
    ]);
  });

  it("adds missing ring positions without changing an existing checkpoint", () => {
    const bob = new ScanWallet(2);
    const added = keypair(5).viewingKey();
    const history = ViewingHistory.create(bob.viewingKey, 0n)
      .withRotatedKey(added.publicKey(), 5n)
      ._withRingCheckpoint(RING, added.publicKey(), 30n)
      .withRing(RING, 10n);
    expect(history.entries.map((entry) => entry.ringPosition(RING))).toEqual([10n, 30n]);
  });

  it("scans a rotated key as its own query from its own start, the old key from its position", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const added = keypair(5).viewingKey();
    await alice.pay(indexer, [{ to: bob.address, amount: 1n }], { slot: 30n });
    const before = await bob.sync(indexer, bob.fresh());
    const history = before.history.withRotatedKey(added.publicKey(), 5n);
    expect(history.entry(added.publicKey())?.ringPosition(RING)).toBeNull();
    expect(history.entry(bob.viewingKey)?.ringPosition(RING)).toBe(30n);
    const toAdded = ShieldedAddress.fromPublicKeys(
      bob.address.signingPublicKey,
      bob.address.nullifierPublicKey,
      added.publicKey(),
    );
    // Below the old key's position.
    const paid = await alice.pay(indexer, [{ to: toAdded, amount: 2n }], { slot: 25n });
    indexer.ringReads.length = 0;
    indexer.contexts.push(35n, 35n);
    const scan = await AnonymousSync.create(rotatedHolder(bob, added), ASSETS).fetch(
      indexer.client(),
      history,
    );
    expect(indexer.ringReads.map((read) => read.filters?.slot?.gt)).toEqual(
      expect.arrayContaining([undefined, 30n]),
    );
    expect(found(scan)).toContain(hex(output(paid, 1)));
    expect(scan.history.entry(added.publicKey())?.ringPosition(RING)).toBe(35n);
    expect(scan.history.entry(bob.viewingKey)?.ringPosition(RING)).toBe(35n);
  });

  it("scans an imported older key from the ring's start, the current key stays last", async () => {
    const bob = new ScanWallet(2);
    const imported = ViewingKey.generate();
    const synced = ViewingHistory.create(bob.viewingKey, 9n)
      .withRing(RING)
      ._withRingCheckpoint(RING, bob.viewingKey, 50n);
    const history = synced.withImportedKey(imported.publicKey(), 2n);
    expect(history.entry(imported.publicKey())?.ringPosition(RING)).toBeNull();
    expect(history.current().viewingPublicKey.equals(bob.viewingKey)).toBe(true);
    expect(() => synced.withImportedKey(imported.publicKey(), 9n)).toThrow(
      "RING_IMPORTED_KEY_NOT_OLDER",
    );
  });

  it("receives under the old key, rotates, receives under the new key, restarts and recovers both", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const added = keypair(5).viewingKey();
    const rotatedAddress = ShieldedAddress.fromPublicKeys(
      bob.address.signingPublicKey,
      bob.address.nullifierPublicKey,
      added.publicKey(),
    );
    await alice.pay(indexer, [{ to: bob.address, amount: 1n }], { slot: 10n });
    const wallet = anonymousWallet(bob, bob.fresh());
    await wallet.absorb(await bob.sync(indexer, wallet.history()));
    wallet.updateHistory(wallet.history().withRotatedKey(added.publicKey(), 5n));
    await alice.pay(indexer, [{ to: rotatedAddress, amount: 2n }], { slot: 20n });
    const holder = LocalRingKeys.fromKeys({
      address: rotatedAddress,
      viewingKeys: [added, bob.keypair.viewingKey()],
      listRoot: bob.keypair.viewingKey(),
      nullifierKey: bob.keypair.nullifierKey(),
    });
    expect(holder.viewingPublicKeys()).toHaveLength(2);
    const sync = AnonymousSync.create(holder, ASSETS);
    await wallet.absorb(await sync.fetch(indexer.client(), wallet.history()));
    expect(wallet.notes().map((note) => note.utxo.amount)).toEqual([1n, 2n]);
    const restarted = AnonymousWallet.fromJson(wallet.toJson());
    expect(restarted.notes().map((note) => note.utxo.amount)).toEqual([1n, 2n]);
    const recovered = await sync.fullScan(
      indexer.client(),
      ViewingHistory.create(bob.viewingKey, 0n).withRotatedKey(added.publicKey(), 5n),
      RING,
    );
    expect(recovered.utxos.map((note) => note.utxo.amount)).toEqual([1n, 2n]);
    expect(recovered.found.map((note) => hex(note.viewingPublicKey.toBytes()))).toEqual([
      hex(bob.viewingKey.toBytes()),
      hex(added.publicKey().toBytes()),
    ]);
  });

  it("refuses a holder key the history does not name, an import scans once added", async () => {
    const indexer = new ScanIndexer();
    const bob = new ScanWallet(2);
    const imported = ViewingKey.generate();
    const holder = rotatedHolder(bob, imported);
    await expect(
      AnonymousSync.create(holder, ASSETS).fetch(indexer.client(), bob.fresh()),
    ).rejects.toThrow("RING_VIEWING_HISTORY_INVALID");
    const added = bob.fresh().withRotatedKey(imported.publicKey(), 5n);
    await AnonymousSync.create(holder, ASSETS).fetch(indexer.client(), added);
    expect(indexer.ringReads).toHaveLength(1);
  });

  it("runs one agreement per transaction and key across every slot and the bundle", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const carol = new ScanWallet(3);
    const added = keypair(5).viewingKey();
    for (const amount of [1n, 2n, 3n])
      await alice.pay(indexer, [
        { to: carol.address, amount },
        { to: carol.address, amount },
      ]);
    const history = bob.fresh().withRotatedKey(added.publicKey(), 5n);
    const holder = rotatedHolder(bob, added);
    const agreements = vi.spyOn(ViewingKey.prototype, "ecdh");
    await AnonymousSync.create(holder, ASSETS).fetch(indexer.client(), history);
    expect(agreements).toHaveBeenCalledTimes(3 * 2);
    agreements.mockRestore();
    expect(found(await bob.sync(indexer, bob.fresh()))).toEqual([]);
  });
});

describe("page too large", () => {
  it("halves the limit from the same token and loses no row", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const paid = [
      await alice.pay(indexer, [{ to: bob.address, amount: 10n }]),
      await alice.pay(indexer, [{ to: bob.address, amount: 11n }]),
    ];
    indexer.responseLimit = 1;
    const scan = await bob.sync(indexer, bob.fresh());
    expect(found(scan)).toEqual(paid.map((tx) => hex(output(tx, 1))));
    const asked = indexer.ringReads.map((read) => read.limit);
    expect(asked.slice(0, 2)).toEqual([1000, 500]);
    expect(asked.filter((limit) => limit === 1)).toHaveLength(2);
    expect(position(scan.history)).toBe(paid[1]?.slot);
  });

  it("fails the read at limit one and moves nothing", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 10n }]);
    indexer.responseLimit = 0;
    await expect(bob.sync(indexer, bob.fresh())).rejects.toMatchObject({
      code: "CLIENT_INDEXER_RESPONSE_TOO_LARGE",
    });
    expect(indexer.ringReads.at(-1)?.limit).toBe(1);
  });

  it("keeps every other refusal at the first ask", async () => {
    const indexer = new ScanIndexer();
    const bob = new ScanWallet(2);
    indexer.refuseAt = {
      read: 1,
      error: new ClientError("CLIENT_INDEXER", {
        details: { method: "getShieldedTransactionsByTags", retryable: false },
      }),
    };
    await expect(bob.sync(indexer, bob.fresh())).rejects.toMatchObject({ code: "CLIENT_INDEXER" });
    expect(indexer.ringReads).toHaveLength(1);
  });
});
