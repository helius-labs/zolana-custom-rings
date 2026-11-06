import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import {
  addressBytes,
  encodeMergeOutputData,
  encryptMergeOutput,
  ZERO_32,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import {
  seededMergeOutputBlinding,
  seededMergeOutputKey,
} from "../../src/crypto/derivation/merge-seed.js";
import type { Bytes16, Bytes32 } from "@heliuslabs/spr/interface";
import { ViewingKey } from "@heliuslabs/spr/keypair";
import { SOL_MINT, Utxo } from "@heliuslabs/spr/transaction";

import { isZeroKeyNote } from "../../src/state/exposed-notes.js";
import { LocalRingKeys } from "../../src/state/ring-keys.js";
import { openZeroKeyMerges } from "../../src/state/zero-key-merge.js";
import {
  ASSETS,
  field,
  hex,
  RING,
  ScanIndexer,
  ScanWallet,
  signature,
} from "../helpers/ring-scan.js";
import { TREE, TREE_ID } from "../helpers/ring-pipeline.js";
import { AnonymousSync } from "../../src/state/anonymous-sync.js";

beforeAll(initializePoseidon);

const FIRST_NULLIFIER = field(9, 9);
const SALT = new Uint8Array(16).fill(4) as Bytes16;

/** A merge row sealed under `seed`, tagged by `tag` as `merge_ring` tags it. */
function zeroKeyMergeRow(
  input: Readonly<{ owner: ScanWallet; seed: Bytes32; tag?: Bytes32; amount?: bigint }>,
) {
  const { owner, seed } = input;
  const amount = input.amount ?? 60n;
  const utxo = new Utxo({
    owner: owner.address.signingPublicKey,
    asset: SOL_MINT,
    amount,
    blinding: seededMergeOutputBlinding(seed, FIRST_NULLIFIER),
    ringProgramId: RING,
  });
  const hash = utxo.hash(ZERO_NULLIFIER_PK as Bytes32, TREE_ID);
  return {
    hash,
    row: {
      slot: 5n,
      txSignature: signature(5n),
      eventIndex: 0,
      outputSlots: [
        {
          viewTag: input.tag ?? owner.address.signingPublicKey.ownerProofInputHash(),
          outputContext: { hash, tree: TREE, treeId: TREE_ID, leafIndex: 3n },
          payload: encodeMergeOutputData({
            salt: SALT,
            ciphertext: encryptMergeOutput(
              { amount, mint: SOL_MINT },
              seededMergeOutputKey(seed, FIRST_NULLIFIER),
              SALT,
            ),
            ringDataHash: ZERO_32,
          }),
        },
      ],
      messages: [],
      nullifiers: [FIRST_NULLIFIER, field(9, 10)],
      proofless: false,
      ringProgramId: RING,
    },
  };
}

const seedOf = (key: ViewingKey): Bytes32 =>
  key.mergeSeed(addressBytes(RING, "ring") as Bytes32, FIRST_NULLIFIER);

describe("openZeroKeyMerges", () => {
  it("opens a merge from the viewing key with no input history", async () => {
    const owner = new ScanWallet(2);
    const { row, hash } = zeroKeyMergeRow({
      owner,
      seed: seedOf(owner.keypair.viewingKey()),
    });
    const [opened] = await openZeroKeyMerges({
      keys: owner.keys,
      owner: owner.address,
      rows: [row],
    });
    expect(hex(opened?.utxo.outputContext.hash ?? ZERO_32)).toBe(hex(hash));
    expect(opened?.utxo.utxo.amount).toBe(60n);
    if (opened === undefined) throw new Error("no note");
    expect(isZeroKeyNote(opened.utxo)).toBe(true);
  });

  it("tries a rotated viewing key in turn", async () => {
    const owner = new ScanWallet(2);
    const retired = ViewingKey.generate();
    const keys = LocalRingKeys.fromKeys({
      address: owner.address,
      viewingKeys: [owner.keypair.viewingKey(), retired],
      listRoot: owner.keypair.viewingKey(),
      nullifierKey: owner.keypair.nullifierKey(),
    });
    const { row } = zeroKeyMergeRow({ owner, seed: seedOf(retired) });
    const [opened] = await openZeroKeyMerges({ keys, owner: owner.address, rows: [row] });
    expect(opened?.viewingPublicKey.equals(retired.publicKey())).toBe(true);
  });

  it("leaves a merge under a keeper's seed unopened, the ciphertext decodes to no match", async () => {
    const owner = new ScanWallet(2);
    const { row } = zeroKeyMergeRow({ owner, seed: field(3, 3) });
    expect(
      await openZeroKeyMerges({ keys: owner.keys, owner: owner.address, rows: [row] }),
    ).toEqual([]);
  });

  it("reads only the rows tagged by the owner's identity and asks the holder nothing else", async () => {
    const owner = new ScanWallet(2);
    const { row } = zeroKeyMergeRow({
      owner,
      seed: seedOf(owner.keypair.viewingKey()),
      tag: FIRST_NULLIFIER,
    });
    let asked = 0;
    const keys = {
      viewingPublicKeys: () => owner.keys.viewingPublicKeys(),
      mergeSeeds: async () => {
        asked += 1;
        return [];
      },
    };
    expect(await openZeroKeyMerges({ keys, owner: owner.address, rows: [row] })).toEqual([]);
    expect(asked).toBe(0);
  });
});

describe("a scan", () => {
  it.each(["fetch", "fullScan"] as const)(
    "%s keeps a zero-key merge with its input history gone",
    async (method) => {
      const indexer = new ScanIndexer();
      const owner = new ScanWallet(2);
      const { row, hash } = zeroKeyMergeRow({
        owner,
        seed: seedOf(owner.keypair.viewingKey()),
      });
      indexer.publish(row);
      const sync = AnonymousSync.create(owner.keys, ASSETS);
      const scan =
        method === "fetch"
          ? await sync.fetch(indexer.client(), owner.fresh())
          : await sync.fullScan(indexer.client(), owner.fresh(), RING);
      expect(scan.utxos.map((note) => hex(note.outputContext.hash))).toEqual([hex(hash)]);
      expect(scan.found[0]?.nullifierPublicKey).toEqual(ZERO_NULLIFIER_PK);
      expect(scan.found[0]?.stream.kind).toBe("merge");
    },
  );
});

describe("an every-site recovery", () => {
  it("opens each page's zero-key merges before it reads the next page", async () => {
    const indexer = new ScanIndexer();
    const owner = new ScanWallet(3);
    const seed = seedOf(owner.keypair.viewingKey());
    const hashes = [1n, 2n, 3n].map((page) => {
      const { row, hash } = zeroKeyMergeRow({ owner, seed, amount: 60n + page });
      indexer.publish({ ...row, slot: 5n + page, txSignature: signature(5n + page) });
      return hash;
    });
    const events: string[] = [];
    const served = indexer.client();
    const client = {
      ...served,
      getShieldedTransactionsByTags: (
        request: Parameters<typeof served.getShieldedTransactionsByTags>[0],
      ) => {
        events.push("page");
        return served.getShieldedTransactionsByTags(request);
      },
    };
    const keys = new Proxy(owner.keys, {
      get(target, property) {
        if (property === "mergeSeeds")
          return (...args: Parameters<typeof target.mergeSeeds>) => {
            events.push("seeds");
            return target.mergeSeeds(...args);
          };
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });

    const scan = await AnonymousSync.create(keys, ASSETS)
      .withScanLimits({ pageSize: 1 })
      .fullScan(client, owner.fresh(), RING);

    // A row leaves the scan with its page, no later read reopens the history.
    expect(events.slice(0, 6)).toEqual(["page", "seeds", "page", "seeds", "page", "seeds"]);
    expect(events.filter((event) => event === "seeds")).toHaveLength(3);
    expect(scan.utxos.map((note) => hex(note.outputContext.hash))).toEqual(hashes.map(hex));
  });
});
