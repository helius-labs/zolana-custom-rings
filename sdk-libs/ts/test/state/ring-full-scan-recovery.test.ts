import { encodeRingBodyOutput } from "../../src/protocol/transaction/output.js";
import { getBase58Decoder, type Signature } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import type { Bytes16, Bytes32 } from "@heliuslabs/spr/interface";
import { randomSalt, ShieldedAddress, ViewingKey, type ViewTag } from "@heliuslabs/spr/keypair";
import {
  encodeMergeOutputData,
  encryptMergeOutput,
  mergeOutputBlinding,
  mergeOutputKey,
} from "@heliuslabs/spr/internal";
import {
  SOL_MINT,
  Utxo,
  type IndexedShieldedTransaction,
  type OutputSlot,
} from "@heliuslabs/spr/transaction";

import { deliveredSlotSecret, slotTag } from "../../src/crypto/derivation/ring-stream.js";
import { AnonymousSync, TAGS_PER_REQUEST, ringFullScan } from "../../src/state/anonymous-sync.js";
import { openRingNotes } from "../../src/state/ring-sync.js";
import { LocalRingKeys } from "../../src/state/ring-keys.js";
import { ViewingHistory } from "../../src/state/viewing-history.js";
import { TREE, TREE_ID, randomAddress } from "../helpers/ring-pipeline.js";
import {
  ASSETS,
  found,
  hex,
  keypair,
  output,
  RING,
  SCAN_USDC,
  ScanIndexer,
  ScanWallet,
  sealedNote,
} from "../helpers/ring-scan.js";

await initializePoseidon();

function randomTag(): ViewTag {
  return globalThis.crypto.getRandomValues(new Uint8Array(32)) as ViewTag;
}

/** A sender chooses its tags. */
function underWrongTags(tx: IndexedShieldedTransaction): IndexedShieldedTransaction {
  return {
    ...tx,
    outputSlots: tx.outputSlots.map((slot) => ({ ...slot, viewTag: randomTag() })),
    messages: tx.messages.map((message) => ({ ...message, viewTag: randomTag() })),
  };
}

function recover(
  wallet: ScanWallet,
  indexer: ScanIndexer,
  options: Readonly<{ pageSize?: number; maxPages?: number }> = {},
) {
  return AnonymousSync.create(wallet.keys, ASSETS)
    .withScanLimits(options)
    .fullScan(indexer.client(), ViewingHistory.create(wallet.viewingKey, 0n), RING);
}

describe("full scan recovery", () => {
  it("finds a note under a wrong tag only in recovery", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const wrong = underWrongTags(alice.seal(indexer, [{ to: bob.address, amount: 30n }]));
    indexer.publish(wrong);
    expect((await bob.sync(indexer, bob.fresh())).utxos).toEqual([]);
    expect((await alice.sync(indexer, alice.fresh())).utxos).toEqual([]);
    const byTag = vi.fn(async () => {
      throw new Error("tag reads unavailable");
    });
    const byNullifier = vi.fn(indexer.client().getShieldedTransactionsByNullifiers);
    const history = (await ViewingHistory.create(bob.viewingKey, 0n).senderTag(bob.keys)).history;
    const recovered = await AnonymousSync.create(bob.keys, ASSETS).fullScan(
      {
        ...indexer.client(),
        getEncryptedUtxosByTags: byTag,
        getShieldedTransactionsByNullifiers: byNullifier,
      },
      history,
      RING,
    );
    expect(byTag).not.toHaveBeenCalled();
    expect(byNullifier).toHaveBeenCalledTimes(1);
    expect(byNullifier.mock.calls.flatMap(([request]) => request.nullifiers).map(hex)).toEqual(
      recovered.utxos.map((note) => hex(note.nullifier)),
    );
    expect(
      byNullifier.mock.calls.every(([request]) => request.nullifiers.length <= TAGS_PER_REQUEST),
    ).toBe(true);
    expect(recovered.spentNullifiers).toEqual([]);
    expect(recovered.status).toBe("Complete");
    expect(recovered.history.current().tx).toEqual(history.current().tx);
    expect(found(recovered)).toEqual([hex(output(wrong, 1))]);
    expect(recovered.found[0]?.stream).toEqual({ kind: "fullScan" });
    expect((await recover(alice, indexer)).utxos.map((note) => note.utxo.amount)).toEqual([70n]);
  });

  it("recovers a body and a bundle under wrong tags, under a retired key too", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = keypair(2);
    const retired = keypair(3);
    const bobRetired = ShieldedAddress.fromPublicKeys(
      bob.shieldedAddress().signingPublicKey,
      bob.shieldedAddress().nullifierPublicKey,
      retired.shieldedAddress().viewingPublicKey,
    );
    const tx = underWrongTags(
      alice.seal(indexer, [
        { to: bob.shieldedAddress(), amount: 30n },
        { to: bobRetired, amount: 20n },
      ]),
    );
    indexer.publish(tx);

    const sender = await recover(alice, indexer);
    expect(sender.found.map(({ utxoHash, stream }) => [hex(utxoHash), stream])).toEqual([
      [hex(output(tx, 0)), { kind: "fullScan" }],
    ]);
    expect(sender.utxos.map((note) => note.utxo.amount)).toEqual([50n]);
    expect(sender.sent.map((row) => [row.position, row.amount, row.check])).toEqual([
      [1, 30n, { kind: "unverified" }],
      [2, 20n, { kind: "unverified" }],
    ]);

    const holder = LocalRingKeys.fromKeys({
      address: bob.shieldedAddress(),
      viewingKeys: [bob.viewingKey(), retired.viewingKey()],
      listRoot: bob.viewingKey(),
      nullifierKey: bob.nullifierKey(),
    });
    const recipient = await AnonymousSync.create(holder, ASSETS).fullScan(
      indexer.client(),
      ViewingHistory.create(bob.viewingKey().publicKey(), 0n).withRotatedKey(
        retired.viewingKey().publicKey(),
        1n,
      ),
      RING,
    );
    expect(recipient.utxos.map((note) => note.utxo.amount)).toEqual([30n, 20n]);
    expect(recipient.found.map(({ viewingPublicKey }) => viewingPublicKey.u())).toEqual([
      bob.viewingKey().publicKey().u(),
      retired.viewingKey().publicKey().u(),
    ]);
    expect(recipient.sent).toEqual([]);

    const stranger = await recover(new ScanWallet(4), indexer);
    expect(stranger.utxos).toEqual([]);
    expect(stranger.spentNullifiers).toEqual([]);
  });

  it("takes every row once across a page split inside one slot and a repeated row", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const rows = [
      await alice.pay(indexer, [{ to: bob.address, amount: 1n }], { slot: 10n }),
      await alice.pay(indexer, [{ to: bob.address, amount: 2n }], { slot: 10n }),
      await alice.pay(indexer, [{ to: bob.address, amount: 3n }], { slot: 10n }),
    ];
    indexer.contexts.push(10n, 10n, 12n);
    const recovered = await recover(bob, indexer, { pageSize: 1 });
    expect(indexer.ringReads).toHaveLength(3);
    expect([...found(recovered)].sort()).toEqual(rows.map((row) => hex(output(row, 1))).sort());
    expect(recovered.history.entry(bob.viewingKey)?.ringPosition(RING)).toBe(12n);
  });

  it("reads from the start and leaves the position alone past a capped read, a restart finds the rest", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    for (const amount of [1n, 2n])
      await alice.pay(indexer, [{ to: bob.address, amount }], { slot: 10n + amount });
    const capped = await recover(bob, indexer, { pageSize: 1, maxPages: 1 });
    expect(capped.utxos.map((note) => note.utxo.amount)).toEqual([1n]);
    expect(capped.history.current().ringPosition(RING)).toBeUndefined();
    const restarted = await recover(bob, indexer);
    expect(restarted.utxos.map((note) => note.utxo.amount)).toEqual([1n, 2n]);
    expect(indexer.ringReads.at(-1)?.filters).toBeUndefined();
  });

  it("recovers change and no-change bundles", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 100n }]);
    await alice.pay(indexer, [{ to: bob.address, amount: 40n }]);
    const recovered = await recover(alice, indexer);
    expect(recovered.utxos.map((note) => note.utxo.amount)).toEqual([0n, 60n]);
    expect(recovered.sent.map((row) => row.amount)).toEqual([100n, 40n]);
  });

  it("recovers two SPL change outputs, each from its own record", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    alice.fundFirst(SCAN_USDC, 40n);
    const paid = await alice.pay(indexer, [{ to: alice.address, amount: 25n }]);
    expect(paid.outputSlots.slice(0, 2).map((slot) => slot.viewTag)).toEqual([
      new Uint8Array(32),
      new Uint8Array(32),
    ]);
    const recovered = await recover(alice, indexer);
    expect(recovered.utxos.map((note) => [note.utxo.asset, note.utxo.amount]).toSorted()).toEqual([
      [SCAN_USDC, 15n],
      [SCAN_USDC, 25n],
    ]);
  });

  it("opens same-page merges and checks only recovered nullifiers", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 70n }], { slot: 5n });
    await alice.pay(indexer, [{ to: bob.address, amount: 30n }], { slot: 6n });
    const held = await recover(bob, indexer);
    const nullifiers = held.utxos.map((utxo) => utxo.nullifier);
    const [first] = nullifiers;
    if (first === undefined) throw new Error("no notes");
    const nullifierKey = bob.keypair.nullifierKey();
    const merged = new Utxo({
      owner: bob.address.signingPublicKey,
      asset: SOL_MINT,
      amount: 100n,
      blinding: mergeOutputBlinding(nullifierKey, first),
      ringProgramId: RING,
    });
    const mergedHash = merged.hash(bob.address.nullifierPublicKey, TREE_ID);
    const salt = new Uint8Array(16).fill(8) as Bytes16;
    indexer.publish({
      slot: 7n,
      txSignature: getBase58Decoder().decode(new Uint8Array(64).fill(0x99)) as Signature,
      eventIndex: 0,
      outputSlots: [
        {
          viewTag: first,
          outputContext: {
            hash: mergedHash,
            tree: TREE,
            treeId: TREE_ID,
            leafIndex: indexer.leaves(1),
          },
          payload: encodeMergeOutputData({
            salt,
            ciphertext: encryptMergeOutput(
              { amount: 100n, mint: SOL_MINT },
              mergeOutputKey(nullifierKey, first),
              salt,
            ),
            ringDataHash: new Uint8Array(32) as Bytes32,
          }),
        },
      ],
      messages: [],
      nullifiers,
      proofless: false,
      ringProgramId: RING,
    });
    const byNullifier = vi.fn(indexer.client().getShieldedTransactionsByNullifiers);
    const pagesBefore = indexer.ringReads.length;
    const recovered = await AnonymousSync.create(bob.keys, ASSETS).fullScan(
      { ...indexer.client(), getShieldedTransactionsByNullifiers: byNullifier },
      ViewingHistory.create(bob.viewingKey, 0n),
      RING,
    );
    expect(indexer.ringReads.length - pagesBefore).toBe(1);
    expect(byNullifier).toHaveBeenCalledTimes(1);
    const queried = byNullifier.mock.calls.flatMap(([request]) => request.nullifiers).map(hex);
    expect(queried.sort()).toEqual(
      [...nullifiers, merged.nullifier(mergedHash, nullifierKey)].map(hex).sort(),
    );
    expect(new Set(queried).size).toBe(queried.length);
    expect(
      byNullifier.mock.calls.every(([request]) => request.nullifiers.length <= TAGS_PER_REQUEST),
    ).toBe(true);
    expect(recovered.utxos).toHaveLength(3);
    expect(recovered.status).toBe("Complete");
    expect(recovered.found.at(-1)?.stream).toEqual({ kind: "merge", firstNullifier: first });
    expect(recovered.utxos.filter((utxo) => !utxo.spent).map((utxo) => utxo.utxo.amount)).toEqual([
      100n,
    ]);
    expect(recovered.spentNullifiers.map(hex).sort()).toEqual(nullifiers.map(hex).sort());
  });

  it("finds what a tag scan finds on one history", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    for (const amount of [11n, 12n, 13n]) await alice.pay(indexer, [{ to: bob.address, amount }]);
    const scan = await bob.sync(indexer, bob.fresh());
    const recovered = await recover(bob, indexer);
    expect(found(recovered)).toEqual(found(scan));
    const change = await alice.sync(indexer, alice.fresh());
    expect(found(await recover(alice, indexer))).toEqual(found(change));
  });

  it("names a rebuilt mint the registry lacks and leaves its note out", async () => {
    const bob = new ScanWallet(2);
    const indexer = new ScanIndexer();
    const mint = randomAddress();
    const txKey = ViewingKey.generate();
    const salt = randomSalt();
    const firstNullifier = new Uint8Array(32).fill(0x0f) as Bytes32;
    const blinding = new Uint8Array(32).fill(0x12) as Bytes32;
    const { address } = bob;
    const agreement = txKey.ecdh(address.viewingPublicKey);
    const body = sealedNote(
      deliveredSlotSecret({
        agreement,
        txViewingKey: txKey.publicKey(),
        recipientViewingKey: address.viewingPublicKey,
        salt,
        outputIndex: 0,
        firstNullifier,
      }),
      { owner: address, blinding, amount: 7n, mint },
    );
    const hash = new Utxo({
      owner: address.signingPublicKey,
      asset: mint,
      amount: 7n,
      blinding,
      ringProgramId: RING,
    }).hash(address.nullifierPublicKey, TREE_ID);
    indexer.publish({
      slot: 1n,
      txSignature: getBase58Decoder().decode(new Uint8Array(64).fill(0x5b)) as Signature,
      eventIndex: 0,
      txViewingPublicKey: txKey.publicKey(),
      salt,
      outputSlots: [
        {
          viewTag: randomTag(),
          outputContext: { hash, tree: TREE, treeId: TREE_ID, leafIndex: 0n },
          payload: encodeRingBodyOutput(body, new Uint8Array()),
        },
      ],
      messages: [],
      nullifiers: [firstNullifier],
      proofless: false,
      ringProgramId: RING,
    });
    const recovered = await recover(bob, indexer);
    expect(recovered.utxos).toEqual([]);
    expect(recovered.pendingOpenings.map((note) => note.utxo.amount)).toEqual([7n]);
    expect(recovered.unknownMints).toEqual([mint]);
    expect(recovered.unmatched.map(hex)).toEqual([hex(hash)]);
  });

  describe("a confidential slot", () => {
    const deliver = (
      indexer: ScanIndexer,
      to: ScanWallet,
      published: (slot: OutputSlot) => OutputSlot,
    ): Bytes32 => {
      const txKey = ViewingKey.generate();
      const salt = randomSalt();
      const firstNullifier = new Uint8Array(32).fill(0x2f) as Bytes32;
      const blinding = new Uint8Array(32).fill(0x12) as Bytes32;
      const { address } = to;
      const body = sealedNote(
        deliveredSlotSecret({
          agreement: txKey.ecdh(address.viewingPublicKey),
          txViewingKey: txKey.publicKey(),
          recipientViewingKey: address.viewingPublicKey,
          salt,
          outputIndex: 0,
          firstNullifier,
        }),
        { owner: address, blinding, amount: 30n, mint: SOL_MINT },
      );
      const hash = new Utxo({
        owner: address.signingPublicKey,
        asset: SOL_MINT,
        amount: 30n,
        blinding,
        ringProgramId: RING,
      }).hash(address.nullifierPublicKey, TREE_ID);
      const leafIndex = indexer.leaves(1);
      const tx = {
        slot: leafIndex + 1n,
        txSignature: getBase58Decoder().decode(
          new Uint8Array(64).fill(Number(leafIndex) + 0x60),
        ) as Signature,
        eventIndex: 0,
        txViewingPublicKey: txKey.publicKey(),
        salt,
        outputSlots: [
          published({
            viewTag: slotTag(address.viewingPublicKey.u()),
            outputContext: { hash, tree: TREE, treeId: TREE_ID, leafIndex },
            payload: encodeRingBodyOutput(body, new Uint8Array()),
          }),
        ],
        messages: [],
        nullifiers: [firstNullifier],
        proofless: false,
        ringProgramId: RING,
      };
      indexer.publish(tx);
      txKey.destroy();
      return hash;
    };
    const scan = (reader: ScanWallet, indexer: ScanIndexer) =>
      ringFullScan({ keys: reader.keys, assets: ASSETS, client: indexer.client(), ring: RING });

    it("finds a note under a wrong tag, the tag read misses it", async () => {
      const indexer = new ScanIndexer();
      const bob = new ScanWallet(2);
      const hash = deliver(indexer, bob, (slot) => ({
        ...slot,
        viewTag: new Uint8Array(32).fill(0x55) as Bytes32,
      }));
      const tagged = await openRingNotes({
        keys: bob.keys,
        assets: ASSETS,
        transactions: indexer.transactions,
      });
      expect(tagged.utxos).toEqual([]);
      const recovered = await scan(bob, indexer);
      expect(recovered.utxos.map((note) => hex(note.outputContext.hash))).toEqual([hex(hash)]);
      expect(recovered.auditorRecovery.unopened.map(hex)).not.toContain(hex(hash));
    });

    it("reports a commitment published twice once", async () => {
      const indexer = new ScanIndexer();
      const bob = new ScanWallet(2);
      const hash = deliver(indexer, bob, (slot) => slot);
      const [first] = indexer.transactions;
      if (first === undefined) throw new Error("no row");
      indexer.publish({
        ...first,
        slot: first.slot + 1n,
        txSignature: getBase58Decoder().decode(new Uint8Array(64).fill(0x7e)) as Signature,
      });
      const recovered = await scan(bob, indexer);
      expect(recovered.utxos.map((note) => hex(note.outputContext.hash))).toEqual([hex(hash)]);
    });

    it("opens nothing from a bad body and leaves it and a foreign slot to the auditor", async () => {
      const indexer = new ScanIndexer();
      const bob = new ScanWallet(2);
      const bad = deliver(indexer, bob, (slot) => {
        const payload = slot.payload.slice();
        payload[payload.length - 1] = (payload[payload.length - 1] ?? 0) ^ 1;
        return { ...slot, payload };
      });
      const foreign = deliver(indexer, new ScanWallet(3), (slot) => slot);
      const recovered = await scan(bob, indexer);
      expect(recovered.utxos).toEqual([]);
      expect(recovered.auditorRecovery.unopened.map(hex)).toEqual(
        expect.arrayContaining([hex(bad), hex(foreign)]),
      );
    });
  });
});
