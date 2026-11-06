import { getBase58Decoder, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import {
  concatBytes,
  encodeMergeOutputData,
  encryptMergeOutput,
  mergeOutputBlinding,
  mergeOutputKey,
  poseidon,
  ZERO_32,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import type { Bytes16, Bytes32 } from "@heliuslabs/spr/interface";
import { randomSalt, ShieldedAddress, ViewingKey, X25519Keypair } from "@heliuslabs/spr/keypair";
import { SOL_MINT, Utxo, Wallet } from "@heliuslabs/spr/transaction";

import {
  AnonymousSync,
  type AnonymousScan,
  type AnonymousStream,
} from "../../src/state/anonymous-sync.js";
import { AnonymousWallet } from "../../src/state/anonymous-wallet.js";
import {
  PENDING_RETENTION,
  StreamCounter,
  ViewingHistory,
} from "../../src/state/viewing-history.js";
import {
  RECIPIENT_BODY_LEN,
  sealRecipientBody,
  sealSenderBundle,
  senderBundleLen,
} from "../../src/protocol/codec/anonymous-delivery.js";
import {
  deliveredSlotSecret,
  recipientTag,
  slotTag,
} from "../../src/crypto/derivation/ring-stream.js";
import {
  encodeRingOutput,
  RingScheme,
  senderBundleOutputBody,
  encodeRingBodyOutput,
} from "../../src/protocol/transaction/output.js";
import { TREE, TREE_ID } from "../helpers/ring-pipeline.js";
import {
  ASSETS,
  field,
  found,
  hex,
  keypair,
  output,
  RING,
  ScanIndexer,
  ScanWallet,
} from "../helpers/ring-scan.js";

await initializePoseidon();

const ZERO = new Uint8Array(32) as Bytes32;

function stream(scan: AnonymousScan, utxoHash: Bytes32): AnonymousStream {
  const entry = scan.found.find((utxo) => hex(utxo.utxoHash) === hex(utxoHash));
  if (entry === undefined) throw new Error(`note ${hex(utxoHash)} not found`);
  return entry.stream;
}

describe("anonymous sync", () => {
  it("finds a payment under its recipient tag and the change under the bundle tag", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const paid = await alice.pay(indexer, [{ to: bob.address, amount: 30n }]);
    const received = await bob.sync(indexer, bob.fresh());
    expect(stream(received, output(paid, 1))).toEqual({ kind: "tagHint" });
    expect(received.utxos.map((note) => note.utxo.amount)).toEqual([30n]);
    const change = await alice.sync(indexer, alice.fresh());
    expect(stream(change, output(paid, 0))).toEqual({ kind: "tagHint" });
    expect(change.utxos.map((note) => note.utxo.amount)).toEqual([70n]);
    expect(indexer.transactionTagReads).toBe(0);
  });

  it("skips a body sealed to another key and goes on", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const stranger = ShieldedAddress.fromPublicKeys(
      bob.address.signingPublicKey,
      bob.address.nullifierPublicKey,
      keypair(9).shieldedAddress().viewingPublicKey,
    );
    await alice.pay(indexer, [{ to: stranger, amount: 9n }]);
    const paid = await alice.pay(indexer, [{ to: bob.address, amount: 30n }]);
    const scanned = await bob.sync(indexer, bob.fresh());
    expect(found(scanned)).toEqual([hex(output(paid, 1))]);
    expect(scanned.unmatched).toEqual([]);
  });

  it("finds change on no-change and two-output frames through one bundle test", async () => {
    const indexer = new ScanIndexer();
    const carol = new ScanWallet(3);
    const bob = new ScanWallet(4);
    const noChange = await carol.pay(indexer, [{ to: bob.address, amount: 100n }]);
    const withChange = await carol.pay(indexer, [{ to: bob.address, amount: 40n }]);
    const scan = await carol.sync(indexer, carol.fresh());
    expect(scan.utxos.map((note) => note.utxo.amount)).toEqual([0n, 60n]);
    expect(found(scan)).toEqual([hex(output(noChange, 0)), hex(output(withChange, 0))]);
    expect(scan.sent.map((row) => row.amount)).toEqual([100n, 40n]);
  });

  it("lists a sent payment and its change once when the indexer repeats the row", async () => {
    const indexer = new ScanIndexer();
    const carol = new ScanWallet(3);
    const bob = new ScanWallet(4);
    const paid = await carol.pay(indexer, [{ to: bob.address, amount: 40n }]);
    indexer.publish(paid);
    const scan = await carol.sync(indexer, carol.fresh());
    expect(scan.utxos.map((note) => note.utxo.amount)).toEqual([60n]);
    expect(scan.sent.map((row) => [hex(row.utxoHash), row.amount])).toEqual([
      [hex(output(paid, 1)), 40n],
    ]);
  });

  it("lists every payment in the change and verifies a row only under a held address", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2).address;
    const carol = new ScanWallet(3).address;
    const paid = await alice.pay(indexer, [
      { to: bob, amount: 30n },
      { to: carol, amount: 20n },
    ]);
    const forged = ShieldedAddress.fromPublicKeys(
      carol.signingPublicKey,
      new ScanWallet(4).address.nullifierPublicKey,
      carol.viewingPublicKey,
    );
    const scan = await AnonymousSync.create(alice.keys, ASSETS)
      .withRecipientAddresses([bob, forged])
      .fetch(indexer.client(), alice.fresh());
    expect(
      scan.sent.map((row) => [
        row.position,
        hex(row.recipientViewingPublicKey.toBytes()),
        row.ownerPublicKey === undefined ? undefined : hex(row.ownerPublicKey.toBytes()),
        row.amount,
        row.check,
        hex(row.utxoHash),
        row.txSignature,
      ]),
    ).toEqual([
      [
        1,
        hex(bob.viewingPublicKey.toBytes()),
        hex(bob.signingPublicKey.toBytes()),
        30n,
        { kind: "verified", mint: SOL_MINT },
        hex(output(paid, 1)),
        paid.txSignature,
      ],
      [
        2,
        hex(carol.viewingPublicKey.toBytes()),
        undefined,
        20n,
        { kind: "unverified" },
        hex(output(paid, 2)),
        paid.txSignature,
      ],
    ]);
    const unheld = await alice.sync(indexer, alice.fresh());
    expect(unheld.sent.map((row) => row.check)).toEqual([
      { kind: "unverified" },
      { kind: "unverified" },
    ]);
  });

  it("finds change under another transaction key by the bundle tag, listing no sent row", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const relayed = alice.seal(indexer, [{ to: bob.address, amount: 30n }]);
    const keys = {
      ...alice.keys,
      address: () => alice.keys.address(),
      viewingPublicKeys: () => alice.keys.viewingPublicKeys(),
      decrypt: alice.keys.decrypt.bind(alice.keys),
      derive: alice.keys.derive.bind(alice.keys),
      mergeSeeds: alice.keys.mergeSeeds.bind(alice.keys),
      ringDeliverySecrets: alice.keys.ringDeliverySecrets.bind(alice.keys),
      ringTagMatches: alice.keys.ringTagMatches.bind(alice.keys),
      viewTags: alice.keys.viewTags.bind(alice.keys),
      // A relayer drew the frame's key, the wallet's own derivation names another.
      transactionKeys: async (requests: readonly unknown[]) =>
        requests.map(() => ViewingKey.generate()),
    };
    indexer.publish(relayed);
    const scan = await AnonymousSync.create(keys, ASSETS).fetch(indexer.client(), alice.fresh());
    expect(stream(scan, output(relayed, 0))).toEqual({ kind: "tagHint" });
    expect(scan.sent).toEqual([]);
  });

  it("leaves no row for a listed body that fails to open, the change still found", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2).address;
    const paid = alice.seal(indexer, [{ to: bob, amount: 30n }]);
    const slot = paid.outputSlots[1];
    if (slot === undefined) throw new Error("no payment");
    const payload = slot.payload.slice(0, -1);
    new DataView(payload.buffer).setUint32(1, payload.length - 5, true);
    indexer.publish({ ...paid, outputSlots: paid.outputSlots.with(1, { ...slot, payload }) });
    const scan = await alice.sync(indexer, alice.fresh());
    expect(scan.sent).toEqual([]);
    expect(stream(scan, output(paid, 0))).toEqual({ kind: "tagHint" });
  });

  it("never fails on sender-chosen garbage under a matching tag", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const txKey = ViewingKey.generate();
    const salt = randomSalt();
    const firstNullifier = field(9, 9);
    const secret = (outputIndex: number) =>
      deliveredSlotSecret({
        agreement: txKey.ecdh(bob.viewingKey),
        txViewingKey: txKey.publicKey(),
        recipientViewingKey: bob.viewingKey,
        salt,
        outputIndex,
        firstNullifier,
      });
    const noise = new Uint8Array(RECIPIENT_BODY_LEN).fill(0x5c);
    // Opens under bob's key, its blinding outside the field fails the hash rebuild.
    const named = sealRecipientBody(secret(2), {
      blinding: new Uint8Array(32).fill(0xff) as Bytes32,
      amount: 5n,
      mint: SOL_MINT,
    });
    // Opens under bob's key, its change rebuilds no published hash.
    const bundle = sealSenderBundle(secret(3), {
      outputSeed: new Uint8Array(32).fill(0x0b) as Bytes32,
      change: [{ mint: SOL_MINT, amount: 5n }],
      recipientKeys: [ZERO, keypair(8).shieldedAddress().viewingPublicKey.u()],
    });
    const payloads = [
      new Uint8Array(),
      encodeRingBodyOutput(noise, new Uint8Array()),
      encodeRingBodyOutput(named, new Uint8Array()),
    ];
    const leaf = indexer.leaves(payloads.length);
    const unmatched = new Uint8Array(32).fill(0x0c) as Bytes32;
    indexer.publish({
      slot: 1n,
      txSignature: getBase58Decoder().decode(new Uint8Array(64).fill(0x77)) as Signature,
      eventIndex: 0,
      txViewingPublicKey: txKey.publicKey(),
      salt,
      outputSlots: payloads.map((payload, position) => ({
        viewTag: slotTag(recipientTag(secret(position))),
        outputContext: {
          hash: unmatched,
          tree: TREE,
          treeId: TREE_ID,
          leafIndex: leaf + BigInt(position),
        },
        payload,
      })),
      messages: [
        {
          viewTag: ZERO,
          data: encodeRingOutput(RingScheme.ringSenderBundle, bundle),
        },
      ],
      nullifiers: [firstNullifier],
      proofless: false,
      ringProgramId: RING,
    });
    const paid = await alice.pay(indexer, [{ to: bob.address, amount: 30n }]);
    const scanned = await bob.sync(indexer, bob.fresh());
    expect(found(scanned)).toEqual([hex(output(paid, 1))]);
    expect(scanned.unmatched).toEqual([]);
    expect(scanned.history.current().knownSenders()).toEqual([]);
  });

  it("finds a merge of the wallet's notes and marks them spent", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    for (const amount of [70n, 30n]) await alice.pay(indexer, [{ to: bob.address, amount }]);
    const held = await bob.sync(indexer, bob.fresh());
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
      slot: 99n,
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
            ringDataHash: ZERO,
          }),
        },
      ],
      messages: [],
      nullifiers,
      proofless: false,
      ringProgramId: RING,
    });
    const next = await bob.sync(indexer, held.history, held.utxos);
    expect(stream(next, mergedHash)).toEqual({ kind: "merge", firstNullifier: first });
    expect(next.spentNullifiers.map(hex)).toEqual(expect.arrayContaining(nullifiers.map(hex)));
    expect(
      next.utxos.filter((utxo) => !utxo.spent).map((utxo) => hex(utxo.outputContext.hash)),
    ).toEqual([hex(mergedHash)]);
    const wallet = AnonymousWallet.create(
      new Wallet({ identity: bob.address, registry: ASSETS }),
      bob.fresh(),
    );
    await wallet.absorb(held);
    await wallet.absorb(next);
    await expect(wallet.absorb(next)).rejects.toThrow("RING_SCAN_CONSUMED");
    await expect(wallet.absorb({ ...next })).rejects.toThrow("RING_SCAN_CONSUMED");
    const repeated = await bob.sync(indexer, wallet.history(), wallet.notes());
    await wallet.absorb(repeated);
    expect(wallet.notes().map((utxo) => [hex(utxo.outputContext.hash), utxo.spent])).toEqual([
      ...held.utxos.map((utxo) => [hex(utxo.outputContext.hash), true]),
      [hex(mergedHash), false],
    ]);
  });

  it("reports only the wallet's own spends out of a whole ring's rows", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const carol = new ScanWallet(3);
    const strangers = await alice.pay(indexer, [{ to: carol.address, amount: 5n }]);
    await alice.pay(indexer, [{ to: bob.address, amount: 5n }]);
    const scan = await bob.sync(indexer, bob.fresh());
    expect(scan.spentNullifiers).toEqual([]);
    expect(strangers.nullifiers.length).toBeGreaterThan(0);
  });

  it("derives a zero nullifier key note's nullifier with no holder", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const zeroKeyed = ShieldedAddress.fromPublicKeys(
      bob.address.signingPublicKey,
      ZERO_NULLIFIER_PK as Bytes32,
      bob.viewingKey,
    );
    const paid = await alice.pay(indexer, [{ to: zeroKeyed, amount: 30n }]);
    const scan = await bob.sync(indexer, bob.fresh());
    const [note] = scan.utxos;
    if (note === undefined) throw new Error("no note");
    const hash = output(paid, 1);
    expect(hex(note.outputContext.hash)).toBe(hex(hash));
    expect(scan.found[0]?.nullifierPublicKey).toEqual(ZERO_NULLIFIER_PK);
    expect(note.nullifier).toEqual(poseidon([hash, note.utxo.blinding, ZERO_32]));
  });

  it("rebuilds an entry's moved note and its change from the two SOL cells", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const entered = await alice.pay(indexer, [{ to: alice.address, amount: 25n }]);
    expect(entered.outputSlots.slice(0, 2).map((slot) => slot.payload.length)).toEqual([0, 0]);
    const scan = await alice.sync(indexer, alice.fresh());
    expect(found(scan)).toEqual([hex(output(entered, 0)), hex(output(entered, 1))]);
    expect(scan.utxos.map((note) => note.utxo.amount).sort()).toEqual([25n, 75n]);
    expect(scan.utxos.every((note) => note.utxo.ringProgramId !== undefined)).toBe(true);
  });

  it("rebuilds a zero amount change slot", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2).address;
    const paid = await alice.pay(indexer, [{ to: bob, amount: 100n }]);
    expect(paid.outputSlots[0]?.payload).toHaveLength(0);
    expect(paid.outputSlots[0]?.viewTag).toEqual(ZERO);
    const scan = await alice.sync(indexer, alice.fresh());
    expect(found(scan)).toEqual([hex(output(paid, 0))]);
    expect(scan.utxos[0]?.utxo.amount).toBe(0n);
  });

  it("holds a reply as a claim the wallet confirms and learns nothing without one", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const carol = new ScanWallet(3);
    await carol.pay(indexer, [{ to: bob.address, amount: 5n }]);
    const bare = await bob.sync(indexer, bob.fresh());
    expect(bare.senderClaims).toEqual([]);
    expect(bare.history.current().knownSenders()).toEqual([]);

    const paid = await alice.pay(indexer, [
      { to: bob.address, amount: 30n, reply: alice.replyTo() },
    ]);
    const scan = await bob.sync(indexer, bob.fresh());
    expect(scan.history.current().knownSenders()).toEqual([]);
    const claim = scan.senderClaims[0];
    if (claim === undefined) throw new Error("no claim");
    expect(hex(claim.utxoHash)).toBe(hex(output(paid, 1)));

    const wallet = AnonymousWallet.create(
      new Wallet({ identity: bob.address, registry: ASSETS }),
      bob.fresh(),
    );
    await wallet.absorb(scan);
    expect(Object.isFrozen(scan)).toBe(true);
    expect(wallet.pendingClaims().map((pending) => hex2(pending.claimedViewingKey))).toEqual([
      hex2(alice.viewingKey),
    ]);
    expect(wallet.history().current().knownSenders()).toEqual([]);
    expect(() => wallet.confirmClaim(carol.viewingKey)).toThrow("RING_UNKNOWN_SENDER_CLAIM");
    wallet.confirmClaim(alice.viewingKey);
    expect(wallet.history().current().knownSenders().map(hex2)).toEqual([hex2(alice.viewingKey)]);
    expect(wallet.pendingClaims()).toEqual([]);
    expect(() => wallet.confirmClaim(alice.viewingKey)).toThrow("RING_UNKNOWN_SENDER_CLAIM");
  });

  it("reads a decoded reply as a claim and an undecodable one as none, the note kept", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const carol = new ScanWallet(3);
    const paid = await alice.pay(indexer, [
      { to: bob.address, amount: 30n, reply: alice.replyTo() },
      { to: carol.address, amount: 20n },
    ]);
    const decodes = await bob.sync(indexer, bob.fresh());
    expect(found(decodes)).toEqual([hex(output(paid, 1))]);
    expect(decodes.senderClaims.map(({ claim }) => claim.claimed.viewingKey.u())).toEqual([
      alice.viewingKey.u(),
    ]);
    expect(decodes.senderClaims[0]?.claim.claimed.ownerKey).toEqual(
      alice.address.signingPublicKey.confidentialViewTag(),
    );
    const undecodable = await carol.sync(indexer, carol.fresh());
    expect(found(undecodable)).toEqual([hex(output(paid, 2))]);
    expect(undecodable.senderClaims).toEqual([]);
  });

  it("opens the bundle under its published count and skips a bundle of another length", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2).address;
    const paid = alice.seal(indexer, [{ to: bob, amount: 30n }], { compact: true });
    expect(paid.outputSlots).toHaveLength(2);
    const [message] = paid.messages;
    if (message === undefined) throw new Error("no bundle");
    expect(senderBundleOutputBody(message.data)).toHaveLength(
      senderBundleLen({ outputs: 2, change: 1 }),
    );

    indexer.publish(paid);
    const opened = await alice.sync(indexer, alice.fresh());
    expect(found(opened)).toEqual([hex(output(paid, 0))]);

    const stretched = new ScanIndexer();
    const body = senderBundleOutputBody(message.data);
    if (body === undefined) throw new Error("no bundle");
    stretched.publish({
      ...paid,
      messages: [
        {
          ...message,
          data: encodeRingOutput(
            RingScheme.ringSenderBundle,
            concatBytes(body, new Uint8Array(32)),
          ),
        },
      ],
    });
    const skipped = await alice.sync(stretched, alice.fresh());
    expect(skipped.utxos).toEqual([]);
    expect(skipped.unmatched).toEqual([]);
    expect(skipped.sent).toEqual([]);
  });

  it("takes the fast path on the wallet's own bundle and keeps the tag test for every other candidate", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const own = await alice.pay(indexer, [{ to: bob.address, amount: 5n }]);
    const paid = await bob.pay(indexer, [{ to: alice.address, amount: 6n }]);
    const scan = await AnonymousSync.create(alice.keys, ASSETS)
      .withSenderFastPath()
      .fetch(indexer.client(), alice.fresh());
    expect([...found(scan)].sort()).toEqual([hex(output(own, 0)), hex(output(paid, 1))].sort());
  });
});

function hex2(key: Readonly<{ toBytes(): Uint8Array }>): string {
  return hex(key.toBytes());
}

describe("viewing history", () => {
  const key = () => X25519Keypair.generate().publicKey();

  it("writes the form sorted by key text", () => {
    const ringB = "So11111111111111111111111111111111111111112" as typeof RING;
    const ringA = "11111111111111111111111111111111" as typeof RING;
    const viewingPublicKey = key();
    const senders = [key(), key()];
    const history = senders.reduce(
      (held, sender) => held.withEntry(0, held.current().withKnownSender(sender)),
      ViewingHistory.create(viewingPublicKey, 3n).withRing(ringB, 8n).withRing(ringA),
    );
    const sorted = senders.map(hex2).sort();
    const counter = '{"next":0,"scanned":0,"pending":[]}';
    expect(history.toJson()).toBe(
      `{"viewingHistory":[{"viewingPubkey":"${hex2(viewingPublicKey)}","createdAt":3,` +
        `"tx":${counter},"knownSenders":["${sorted[0]}","${sorted[1]}"],` +
        `"ringPositions":[{"ring":"${ringA}","afterSlot":null},{"ring":"${ringB}","afterSlot":8}],"tagPosition":null}]}`,
    );
    expect(ViewingHistory.fromJson(history.toJson()).toJson()).toBe(history.toJson());
  });

  it("refuses another field, a stale rotation, a malformed counter and a repeated ring", () => {
    const history = ViewingHistory.create(key(), 0n);
    const stored = JSON.parse(history.toJson()) as object;
    expect(() => ViewingHistory.fromJson(JSON.stringify({ ...stored, other: 7 }))).toThrow(
      "RING_VIEWING_HISTORY_INVALID",
    );
    const rotated = history.withRotatedKey(key(), 5n);
    expect(() => rotated.withRotatedKey(key(), 5n)).toThrow("RING_ROTATED_KEY_NOT_NEWER");
    const counter = StreamCounter.restore({
      next: PENDING_RETENTION + 2n,
      scanned: PENDING_RETENTION + 2n,
      pending: [2n, 3n],
    });
    const withCounter = history.withEntry(0, history.current().withTxCounter(counter));
    expect(ViewingHistory.fromJson(withCounter.toJson()).toJson()).toBe(withCounter.toJson());
    const parsed = JSON.parse(withCounter.toJson()) as {
      viewingHistory: { tx: { pending: number[] } }[];
    };
    for (const pending of [[0], [2, 2], [3, 2], [Number(PENDING_RETENTION) + 2]]) {
      const refused = structuredClone(parsed);
      const [first] = refused.viewingHistory;
      if (first === undefined) throw new Error("no entry");
      first.tx.pending = pending;
      expect(() => ViewingHistory.fromJson(JSON.stringify(refused)), String(pending)).toThrow(
        "RING_VIEWING_HISTORY_INVALID",
      );
    }
    const enrolled = history.withRing(RING);
    const row = `{"ring":"${RING}","afterSlot":null}`;
    expect(() => ViewingHistory.fromJson(enrolled.toJson().replace(row, `${row},${row}`))).toThrow(
      "RING_VIEWING_HISTORY_INVALID",
    );
    expect(() =>
      ViewingHistory.fromJson(enrolled.toJson().replace(`"ring":"${RING}"`, `"ring":"nope"`)),
    ).toThrow("RING_VIEWING_HISTORY_INVALID");
  });

  it("reads a u64 counter past 2^53 exactly", () => {
    const history = ViewingHistory.create(key(), 0n);
    const json = history.toJson().replace('"tx":{"next":0', `"tx":{"next":${(1n << 64n) - 2n}`);
    expect(ViewingHistory.fromJson(json).current().txCount).toBe((1n << 64n) - 2n);
  });
});
