import { describe, expect, it, vi } from "vitest";
import { initializePoseidon } from "@heliuslabs/spr";
import { type GetByTagsRequest, type GetByNullifiersRequest } from "@heliuslabs/spr/client";
import type { Bytes32, PageOptions } from "@heliuslabs/spr/interface";
import { SOL_MINT, Wallet, type IndexedShieldedTransaction } from "@heliuslabs/spr/transaction";
import { AnonymousSync, type AnonymousSyncClient } from "../../src/state/anonymous-sync.js";
import { AnonymousWallet } from "../../src/state/anonymous-wallet.js";
import { RECOVERY_DIAGNOSTIC_SAMPLES } from "../../src/state/recovery-session.js";
import { extended } from "../../src/operations/workflow/extended.js";
import { selectRingInputs } from "../../src/operations/payments/transfer.js";
import {
  ASSETS,
  RING,
  ScanIndexer,
  ScanWallet,
  field,
  hex,
  signature,
} from "../helpers/ring-scan.js";

await initializePoseidon();

class RecoverySource {
  readonly indexer = new ScanIndexer();
  readonly ringQueries: GetByTagsRequest[] = [];
  readonly spendQueries: GetByNullifiersRequest[] = [];
  readonly tagQueries: GetByTagsRequest[] = [];
  contextSlot = 100n;

  client(): AnonymousSyncClient {
    return {
      getEncryptedUtxosByTags: async (request) => {
        this.tagQueries.push(request);
        return { ...this.page([], request), data: [] };
      },
      getShieldedTransactionsByTags: async (request) => {
        this.ringQueries.push(request);
        const rows = this.indexer.transactions.filter(
          (row) => row.ringProgramId === request.ringProgramId,
        );
        return this.transactions(rows, request);
      },
      getShieldedTransactionsByNullifiers: async (request) => {
        this.spendQueries.push(request);
        const wanted = new Set(request.nullifiers.map(hex));
        return this.transactions(
          this.indexer.transactions.filter((row) =>
            row.nullifiers.some((value) => wanted.has(hex(value))),
          ),
          request,
        );
      },
    };
  }

  transactions(rows: readonly IndexedShieldedTransaction[], request: PageOptions) {
    const page = this.page(rows, request);
    return {
      ...page,
      data: page.data.map((row) => ({ slot: row.slot, signature: row.txSignature, events: [row] })),
    };
  }

  page<T extends { slot: bigint; txSignature: string }>(rows: readonly T[], request: PageOptions) {
    const lower = request.filters?.slot?.gt;
    const upper = request.filters?.slot?.lte;
    const ordered = rows
      .filter(
        (row) =>
          (lower === undefined || row.slot > lower) && (upper === undefined || row.slot <= upper),
      )
      .toSorted((left, right) =>
        left.slot === right.slot
          ? left.txSignature < right.txSignature
            ? -1
            : left.txSignature > right.txSignature
              ? 1
              : 0
          : left.slot < right.slot
            ? -1
            : 1,
      );
    const offset = Number(request.paginationToken ?? "0");
    const data = ordered.slice(offset, offset + (request.limit ?? 1000));
    return {
      context: { slot: this.contextSlot, blockTime: 0n },
      data,
      paginationToken: offset + data.length < ordered.length ? String(offset + data.length) : null,
    };
  }
}

function wallet(owner: ScanWallet): AnonymousWallet {
  return AnonymousWallet.create(
    new Wallet({ identity: owner.address, registry: ASSETS }),
    owner.fresh(),
  );
}

async function complete(
  sync: AnonymousSync,
  source: RecoverySource,
  original: AnonymousWallet,
  full = false,
): Promise<AnonymousWallet> {
  let held = original;
  for (let attempt = 0; attempt < 100; attempt++) {
    const scan = full
      ? await sync.fullScanWallet(source.client(), held, RING)
      : await sync.fetchWallet(source.client(), held);
    await held.absorb(scan);
    held = AnonymousWallet.fromJson(held.toJson());
    if (scan.status === "Complete") return held;
  }
  throw new Error("recovery did not complete");
}

describe("durable recovery", () => {
  it("resumes a capped page after restart and keeps the fixed target", async () => {
    const source = new RecoverySource();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    for (const slot of [10n, 20n, 30n])
      await alice.pay(source.indexer, [{ to: bob.address, amount: slot }], { slot });
    const sync = AnonymousSync.create(bob.keys, ASSETS).withScanLimits({
      pageSize: 1,
      maxPages: 1,
    });
    const held = wallet(bob);
    const first = await sync.fetchWallet(source.client(), held);
    expect(first.status).toBe("Paused");
    expect(first.targetSlot).toBe(100n);
    await held.absorb(first);
    source.contextSlot = 200n;
    await alice.pay(source.indexer, [{ to: bob.address, amount: 40n }], { slot: 150n });
    const restored = await complete(sync, source, AnonymousWallet.fromJson(held.toJson()));
    expect(restored.notes().map((note) => note.utxo.amount)).toEqual([10n, 20n, 30n]);
    expect(restored.history().current().ringPosition(RING)).toBe(100n);
    expect(source.ringQueries.map((query) => query.paginationToken)).toEqual([undefined, "1", "2"]);
    for (const query of [
      ...source.ringQueries,
      ...source.spendQueries,
      ...source.tagQueries.slice(1),
    ]) {
      expect(query.filters?.slot?.lte).toBe(100n);
      expect(query.minContextSlot).toBe(100n);
    }
    expect(restored.recoveryCoverage().status).toBe("Complete");
  });

  it("refuses a scan after a wallet revision changes", async () => {
    const source = new RecoverySource();
    const bob = new ScanWallet(2);
    const held = wallet(bob);
    const sync = AnonymousSync.create(bob.keys, ASSETS).withScanLimits({ maxPages: 1 });
    const scan = await sync.fetchWallet(source.client(), held);
    await held.takeSenderTag(bob.keys);
    await expect(held.absorb(scan)).rejects.toThrow("RING_SCAN_HISTORY_CHANGED");
    expect(held.recoveryCoverage().status).toBe("Complete");
    expect(held.history().current().tx.next).toBe(1n);
  });

  it("refuses a changed recovery scope and another wallet instance", async () => {
    const source = new RecoverySource();
    const bob = new ScanWallet(2);
    const held = wallet(bob);
    const sync = AnonymousSync.create(bob.keys, ASSETS).withScanLimits({ maxPages: 1 });
    const scan = await sync.fetchWallet(source.client(), held);
    await expect(wallet(bob).absorb(scan)).rejects.toThrow("RING_SCAN_HISTORY_CHANGED");
    await held.absorb(scan);
    const document = held.toJson();
    await expect(sync.withFullRescan().fetchWallet(source.client(), held)).rejects.toThrow(
      "RING_SCAN_HISTORY_CHANGED",
    );
    await expect(sync.fullScanWallet(source.client(), held, RING)).rejects.toThrow(
      "RING_SCAN_HISTORY_CHANGED",
    );
    expect(held.toJson()).toBe(document);
  });

  it("excludes an unchecked opening from funding and reports incomplete coverage", async () => {
    const source = new RecoverySource();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(source.indexer, [{ to: bob.address, amount: 7n }]);
    const sync = AnonymousSync.create(bob.keys, ASSETS).withScanLimits({
      pageSize: 1,
      maxPages: 1,
    });
    const held = wallet(bob);
    for (let attempt = 0; held.notes().length === 0 && attempt < 10; attempt++)
      await held.absorb(await sync.fetchWallet(source.client(), held));
    expect(held.notes()).toHaveLength(1);
    const select = (stored: AnonymousWallet) =>
      selectRingInputs({
        wallet: stored.wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 1n,
        inputs: "ring",
        maxInputs: 1,
      });
    expect(() => select(held)).toThrow("RING_SYNC_INCOMPLETE");
    const restored = AnonymousWallet.fromJson(held.toJson());
    expect(() => select(restored)).toThrow("RING_SYNC_INCOMPLETE");
    const checked = await complete(sync, source, restored);
    expect(select(checked)).toHaveLength(1);
    expect(source.spendQueries.flatMap((query) => query.nullifiers).map(hex)).toEqual([
      hex(checked.notes()[0]!.nullifier),
    ]);
  });

  it("checks an owned nullifier when its spend precedes its creation in the same slot", async () => {
    const source = new RecoverySource();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const paid = await alice.pay(source.indexer, [{ to: bob.address, amount: 7n }], { slot: 10n });
    const initial = await bob.sync(source.indexer, bob.fresh());
    const owned = initial.utxos[0]!;
    const [before, after] = [signature(1n), signature(2n)].sort();
    source.indexer.transactions.splice(0, 1, { ...paid, txSignature: after! });
    source.indexer.publish({
      ...paid,
      txSignature: before!,
      outputSlots: [],
      messages: [],
      nullifiers: [owned.nullifier],
    });
    const sync = AnonymousSync.create(bob.keys, ASSETS).withScanLimits({
      pageSize: 1,
      maxPages: 1,
    });
    const held = await complete(sync, source, wallet(bob), true);
    expect(held.notes()).toHaveLength(1);
    expect(held.notes()[0]?.spent).toBe(true);
    expect(source.spendQueries).toHaveLength(1);
  });

  it("bounds foreign diagnostics and retains no foreign nullifier queue", async () => {
    const source = new RecoverySource();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const carol = new ScanWallet(3);
    const first = await alice.pay(source.indexer, [{ to: carol.address, amount: 1n }]);
    source.indexer.transactions.length = 0;
    for (let at = 0; at < 40; at++)
      source.indexer.publish({
        ...first,
        txSignature: signature(BigInt(at)),
        outputSlots: first.outputSlots.map((slot, position) => ({
          ...slot,
          outputContext: { ...slot.outputContext, hash: field(at, position) },
        })),
        nullifiers: [field(at, 8)],
      });
    const sync = AnonymousSync.create(bob.keys, ASSETS).withScanLimits({
      pageSize: 8,
      maxPages: 1,
    });
    let held = wallet(bob);
    let count = 0n;
    for (let attempt = 0; attempt < 10; attempt++) {
      const scan = await sync.fullScanWallet(source.client(), held, RING);
      count = scan.auditorRecovery.unopenedCount;
      expect(scan.auditorRecovery.unopened.length).toBeLessThanOrEqual(RECOVERY_DIAGNOSTIC_SAMPLES);
      await held.absorb(scan);
      const session = held._recoveryState().session;
      expect(session?.queue ?? []).toEqual([]);
      expect(session?.checked ?? []).toEqual([]);
      expect(session?.active ?? null).toBeNull();
      const stored = JSON.parse(held.toJson());
      if (stored.recovery?.unopenedSamples.length > 0) {
        stored.recovery.unopenedCount = "0";
        expect(() => AnonymousWallet.fromJson(JSON.stringify(stored))).toThrow(
          "RING_WALLET_DOCUMENT",
        );
      }
      held = AnonymousWallet.fromJson(held.toJson());
      if (scan.status === "Complete") break;
    }
    // Each transaction's change and payment both carry a record, neither opens under bob's key.
    expect(count).toBe(80n);
    expect(source.spendQueries).toEqual([]);
  });
  it("wipes opened recipient secrets when transaction key derivation fails", async () => {
    const source = new RecoverySource();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(source.indexer, [{ to: bob.address, amount: 7n }]);
    const retained: Bytes32[] = [];
    const delivery = vi.fn<typeof bob.keys.ringDeliverySecrets>(async (requests, context) => {
      const secrets = await bob.keys.ringDeliverySecrets(requests, context);
      retained.push(...secrets);
      return secrets;
    });
    const transaction = vi.fn<typeof bob.keys.transactionKeys>(async () => {
      expect(retained.length).toBeGreaterThan(0);
      expect(retained.every((secret) => secret.some((byte) => byte !== 0))).toBe(true);
      throw new Error("key holder unavailable");
    });
    const keys = extended(bob.keys, {
      ringDeliverySecrets: delivery,
      transactionKeys: transaction,
    });
    await expect(
      AnonymousSync.create(keys, ASSETS).fullScan(source.client(), bob.fresh(), RING),
    ).rejects.toThrow("key holder unavailable");
    expect(delivery).toHaveBeenCalledTimes(1);
    expect(transaction).toHaveBeenCalledTimes(1);
    expect(retained.length).toBeGreaterThan(0);
    expect(retained.every((secret) => secret.every((byte) => byte === 0))).toBe(true);
    expect(source.spendQueries).toEqual([]);
  });

  it("retains a completed target through reload and refuses an older source", async () => {
    const source = new RecoverySource();
    source.contextSlot = 200n;
    const bob = new ScanWallet(2);
    const sync = AnonymousSync.create(bob.keys, ASSETS);
    const held = wallet(bob);
    const scan = await sync.fetchWallet(source.client(), held);
    expect(scan.status).toBe("Complete");
    await held.absorb(scan);
    const restored = AnonymousWallet.fromJson(held.toJson());
    expect(restored._recoveryMinimumSlot()).toBe(200n);
    expect(JSON.parse(restored.toJson()).recoveryFloor).toBe("200");
    const document = restored.toJson();
    source.contextSlot = 100n;
    await expect(sync.fetchWallet(source.client(), restored)).rejects.toThrow(
      "RING_HISTORY_PAGE_INVALID",
    );
    expect(source.tagQueries.at(-1)?.minContextSlot).toBe(200n);
    expect(restored.toJson()).toBe(document);
    const old = JSON.parse(document);
    delete old.recoveryFloor;
    expect(AnonymousWallet.fromJson(JSON.stringify(old))._recoveryMinimumSlot()).toBe(200n);
  });

  it("uses the highest ring, tag and core checkpoint as the target floor", async () => {
    const source = new RecoverySource();
    const bob = new ScanWallet(2);
    const history = bob
      .fresh()
      ._withRingCheckpoint(RING, bob.viewingKey, 200n)
      ._withTagPosition([bob.viewingKey], 250n);
    const held = AnonymousWallet.create(
      new Wallet({ identity: bob.address, registry: ASSETS }),
      history,
    );
    held.wallet._setSyncCheckpoint("nullifiers", hex(field(1, 1)), 300n);
    await expect(
      AnonymousSync.create(bob.keys, ASSETS).fetchWallet(source.client(), held),
    ).rejects.toThrow("RING_HISTORY_PAGE_INVALID");
    expect(source.tagQueries.at(-1)?.minContextSlot).toBe(300n);
    expect(source.ringQueries).toEqual([]);
  });
});
