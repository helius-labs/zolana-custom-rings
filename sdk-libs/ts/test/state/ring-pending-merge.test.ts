import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import {
  encodeMergeOutputData,
  encryptMergeOutput,
  mergeOutputBlinding,
  mergeOutputKey,
  ZERO_32,
} from "@heliuslabs/spr/internal";
import type { Address, Bytes16 } from "@heliuslabs/spr/interface";
import { AssetRegistry, Utxo, Wallet, type WalletUtxo } from "@heliuslabs/spr/transaction";

import { AnonymousSync } from "../../src/state/anonymous-sync.js";
import { AnonymousWallet } from "../../src/state/anonymous-wallet.js";
import { TREE, TREE_ID, randomAddress } from "../helpers/ring-pipeline.js";
import { field, hex, RING, ScanIndexer, ScanWallet, signature } from "../helpers/ring-scan.js";

await initializePoseidon();

function heldNote(owner: ScanWallet, mint: Address): WalletUtxo {
  const utxo = new Utxo({
    owner: owner.address.signingPublicKey,
    asset: mint,
    amount: 7n,
    blinding: field(1, 1),
    ringProgramId: RING,
  });
  const hash = utxo.hash(owner.address.nullifierPublicKey, TREE_ID);
  return {
    utxo,
    outputContext: { hash, tree: TREE, leafIndex: 0n },
    nullifier: utxo.nullifier(hash, owner.keypair.nullifierKey()),
    spent: false,
  };
}

function publishMerge(
  input: Readonly<{
    indexer: ScanIndexer;
    owner: ScanWallet;
    spent: WalletUtxo;
    slot: bigint;
  }>,
): WalletUtxo {
  const { indexer, owner, spent, slot } = input;
  const key = owner.keypair.nullifierKey();
  const firstNullifier = spent.nullifier;
  const utxo = new Utxo({
    owner: owner.address.signingPublicKey,
    asset: spent.utxo.asset,
    amount: spent.utxo.amount,
    blinding: mergeOutputBlinding(key, firstNullifier),
    ringProgramId: RING,
  });
  const hash = utxo.hash(owner.address.nullifierPublicKey, TREE_ID);
  const outputContext = { hash, tree: TREE, treeId: TREE_ID, leafIndex: slot };
  const salt = new Uint8Array(16).fill(Number(slot)) as Bytes16;
  indexer.publish({
    slot,
    txSignature: signature(slot),
    eventIndex: 0,
    outputSlots: [
      {
        viewTag: firstNullifier,
        outputContext,
        payload: encodeMergeOutputData({
          salt,
          ciphertext: encryptMergeOutput(
            { amount: utxo.amount, mint: utxo.asset },
            mergeOutputKey(key, firstNullifier),
            salt,
          ),
          ringDataHash: ZERO_32,
        }),
      },
    ],
    messages: [],
    nullifiers: [firstNullifier, field(2, Number(slot))],
    proofless: false,
    ringProgramId: RING,
  });
  return {
    utxo,
    outputContext,
    nullifier: utxo.nullifier(hash, key),
    spent: false,
  };
}

describe("pending merge notes", () => {
  it.each(["fetch", "fullScan"] as const)(
    "%s keeps an unknown mint pending through restart and a later spend",
    async (method) => {
      const owner = new ScanWallet(2);
      const mint = randomAddress();
      const indexer = new ScanIndexer();
      const seed = heldNote(owner, mint);
      const first = publishMerge({ indexer, owner, spent: seed, slot: 2n });
      const wallet = AnonymousWallet.create(
        new Wallet({ identity: owner.address, registry: new AssetRegistry() }),
        owner.fresh(),
      );
      const read = (stored: AnonymousWallet, held: readonly WalletUtxo[]) => {
        const sync = AnonymousSync.create(owner.keys, stored.wallet.registry).withHeldNotes(held);
        return method === "fetch"
          ? sync.fetch(indexer.client(), stored.history())
          : sync.fullScan(indexer.client(), stored.history(), RING);
      };
      const initial = await read(wallet, [seed]);
      expect(initial.utxos).toEqual([]);
      expect(initial.unknownMints).toEqual([mint]);
      expect(initial.unmatched.map(hex)).toEqual([hex(first.outputContext.hash)]);
      expect(initial.spentNullifiers.map(hex)).toEqual([hex(seed.nullifier)]);
      await wallet.absorb(initial);

      const restored = AnonymousWallet.fromJson(wallet.toJson());
      const second = publishMerge({ indexer, owner, spent: first, slot: 3n });
      const next = await read(restored, [...restored.notes(), ...restored.pendingOpenings()]);
      expect(next.utxos).toEqual([]);
      expect(next.pendingOpenings.map((note) => hex(note.outputContext.hash))).toEqual([
        hex(second.outputContext.hash),
      ]);
      expect(next.spentNullifiers.map(hex)).toEqual([hex(first.nullifier)]);
      await restored.absorb(next);
      expect(restored.notes()).toEqual([]);

      const persisted = AnonymousWallet.fromJson(restored.toJson());
      expect(persisted.pendingOpenings().map((note) => note.spent)).toEqual([true, false]);
      const reads = indexer.ringReads.length;
      persisted.wallet.ensureAsset(9n, mint);
      expect(await persisted.promotePending()).toHaveLength(2);
      expect(persisted.pendingOpenings()).toEqual([]);
      expect(
        persisted
          .notes()
          .filter((note) => !note.spent)
          .map((note) => hex(note.outputContext.hash)),
      ).toEqual([hex(second.outputContext.hash)]);
      expect(indexer.ringReads).toHaveLength(reads);
    },
  );
  it("tracks a stored pending note through bounded recovery before promotion", async () => {
    const owner = new ScanWallet(2);
    const mint = randomAddress();
    const indexer = new ScanIndexer();
    const seed = heldNote(owner, mint);
    const first = publishMerge({ indexer, owner, spent: seed, slot: 2n });
    let wallet = AnonymousWallet.create(
      new Wallet({ identity: owner.address, registry: new AssetRegistry() }),
      owner.fresh(),
    );
    const initial = await AnonymousSync.create(owner.keys, wallet.wallet.registry)
      .withHeldNotes([seed])
      .fetch(indexer.client(), wallet.history());
    await wallet.absorb(initial);
    const second = publishMerge({ indexer, owner, spent: first, slot: 3n });
    const source = indexer.client();
    const client = {
      getEncryptedUtxosByTags: async (
        ...args: Parameters<typeof source.getEncryptedUtxosByTags>
      ) => ({
        ...(await source.getEncryptedUtxosByTags(...args)),
        context: { slot: 100n, blockTime: 0n },
      }),
      getShieldedTransactionsByTags: async (
        ...args: Parameters<typeof source.getShieldedTransactionsByTags>
      ) => ({
        ...(await source.getShieldedTransactionsByTags(...args)),
        context: { slot: 100n, blockTime: 0n },
      }),
      getShieldedTransactionsByNullifiers: async (
        ...args: Parameters<typeof source.getShieldedTransactionsByNullifiers>
      ) => ({
        ...(await source.getShieldedTransactionsByNullifiers(...args)),
        context: { slot: 100n, blockTime: 0n },
      }),
    };
    const sync = AnonymousSync.create(owner.keys, wallet.wallet.registry).withScanLimits({
      maxPages: 1,
    });
    let status: "Paused" | "Complete" = "Paused";
    for (let attempt = 0; attempt < 20 && status === "Paused"; attempt++) {
      const scan = await sync.fetchWallet(client, wallet);
      status = scan.status;
      await wallet.absorb(scan);
      wallet = AnonymousWallet.fromJson(wallet.toJson());
    }
    expect(status).toBe("Complete");
    expect(wallet.pendingOpenings().map((note) => note.spent)).toEqual([true, false]);
    const reads = indexer.ringReads.length;
    wallet.wallet.ensureAsset(9n, mint);
    await wallet.promotePending();
    expect(
      wallet
        .notes()
        .filter((note) => !note.spent)
        .map((note) => hex(note.outputContext.hash)),
    ).toEqual([hex(second.outputContext.hash)]);
    expect(indexer.ringReads).toHaveLength(reads);
  });
});
