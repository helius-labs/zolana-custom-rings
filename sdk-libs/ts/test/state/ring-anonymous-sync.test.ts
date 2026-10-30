import { getBase58Decoder, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import type { GetByNullifiersRequest, GetByTagsRequest } from "@heliuslabs/zolana/client";
import {
  addressBytes,
  concatBytes,
  encodeMergeOutputData,
  encodeOutputData,
  encryptMergeOutput,
  mergeOutputBlinding,
  mergeOutputKey,
} from "@heliuslabs/zolana/internal";
import {
  InstructionTag,
  type Bytes16,
  type Bytes32,
  type Bytes33,
} from "@heliuslabs/zolana/interface";
import type { Bytes96 } from "@heliuslabs/zolana";
import {
  randomSalt,
  ShieldedAddress,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  X25519Keypair,
  type ViewTag,
} from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  ConfidentialTransfer,
  Data,
  EncryptedScheme,
  ownerUtxoHash,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  type IndexedShieldedTransaction,
  type OutputSlot,
  type WalletUtxo,
} from "@heliuslabs/zolana/transaction";

import {
  AnonymousSync,
  type AnonymousScan,
  type AnonymousStream,
  type AnonymousSyncClient,
  TAGS_PER_REQUEST,
} from "../../src/state/anonymous-sync.js";
import {
  GapScan,
  PENDING_RETENTION,
  StreamCounter,
  TAG_GAP,
  TransferTagging,
  VIEWING_HISTORY_VERSION,
  ViewingHistory,
  ViewingKeyEntry,
  type PaymentRecipient,
} from "../../src/state/viewing-history.js";
import { AnonymousPlan, RingOutputRail } from "../../src/operations/payments/output-rail.js";
import { RECIPIENT_BODY_LEN } from "../../src/protocol/codec/anonymous-body.js";
import {
  encodeAnonymousRecipient,
  encodeAnonymousSender,
} from "../../src/protocol/codec/anonymous-plaintext.js";
import { encodeRingDepositPlaintext } from "../../src/protocol/codec/ring-deposit-plaintext.js";
import { encodeRingDepositCapsule } from "../../src/protocol/codec/ring-deposit-capsule.js";
import { encodeRingOutput, RingScheme } from "../../src/protocol/transaction/output.js";
import type { RingKeys } from "../../src/state/ring-keys.js";
import { TREE, TREE_ID, randomAddress, walletKeys } from "../helpers/ring-pipeline.js";

await initializePoseidon();

const RING = randomAddress();
const PAYER = randomAddress();
const ASSETS = new AssetRegistry();
const CONTEXT = Object.freeze({ slot: 1n << 62n, blockTime: 0n });
const ZERO = new Uint8Array(32) as Bytes32;

function keypair(seed: number): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );
}

/** A canonical field value distinct per pair. */
function field(seed: number, index: number): Bytes32 {
  const value = new Uint8Array(32).fill(0x11);
  value[30] = seed;
  value[31] = index;
  return value as Bytes32;
}

function signature(leaf: bigint): Signature {
  const bytes = new Uint8Array(64).fill(0x5a);
  new DataView(bytes.buffer).setBigUint64(0, leaf);
  return getBase58Decoder().decode(bytes) as Signature;
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

/** Every tag lookup is exact, as the indexer's is. */
class Indexer {
  readonly transactions: IndexedShieldedTransaction[] = [];
  readonly deposits: Readonly<{ slot: bigint; txSignature: Signature; outputSlot: OutputSlot }>[] =
    [];
  #nextLeaf = 0n;
  #tagReads = 0;
  #tagsRead = 0;

  publish(transaction: IndexedShieldedTransaction): void {
    this.transactions.push(transaction);
  }

  leaves(count: number): bigint {
    const first = this.#nextLeaf;
    this.#nextLeaf += BigInt(count);
    return first;
  }

  /** The tag reads and the tags they named since the last call. */
  takeTagReads(): readonly [number, number] {
    const taken = [this.#tagReads, this.#tagsRead] as const;
    this.#tagReads = 0;
    this.#tagsRead = 0;
    return taken;
  }

  client(): AnonymousSyncClient {
    const tagged = (request: GetByTagsRequest) => {
      const tags = new Set(request.tags.map(hex));
      return (slot: Readonly<{ viewTag: Bytes32 }>) => tags.has(hex(slot.viewTag));
    };
    const terminal = { context: CONTEXT, scannedThrough: Uint8Array.of(0) };
    return {
      getShieldedTransactionsByTags: async (request: GetByTagsRequest) => {
        this.#tagReads += 1;
        this.#tagsRead += request.tags.length;
        return {
          ...terminal,
          transactions: this.transactions.filter(
            (tx) => tx.outputSlots.some(tagged(request)) || tx.messages.some(tagged(request)),
          ),
        };
      },
      getEncryptedUtxosByTags: async (request: GetByTagsRequest) => ({
        ...terminal,
        matches: this.deposits.filter((deposit) => tagged(request)(deposit.outputSlot)),
      }),
      getShieldedTransactionsByNullifiers: async (request: GetByNullifiersRequest) => {
        const wanted = new Set(request.nullifiers.map(hex));
        return {
          ...terminal,
          transactions: this.transactions.filter((tx) =>
            tx.nullifiers.some((nullifier) => wanted.has(hex(nullifier))),
          ),
        };
      },
    };
  }
}

interface Pay {
  readonly to: ShieldedAddress;
  readonly request?: ViewTag;
  readonly amount: bigint;
}

/** A wallet whose viewing history is stored before every send. */
class Wallet {
  readonly keypair: ShieldedKeypair;
  readonly keys: ReturnType<typeof walletKeys>;
  history: ViewingHistory;
  readonly #funding: ProofInputUtxo[];

  constructor(seed: number) {
    this.keypair = keypair(seed);
    this.keys = walletKeys(this.keypair);
    this.history = fresh(this);
    this.#funding = Array.from({ length: 4 }, (_, index) =>
      ProofInputUtxo.fromKeypair(
        new Utxo({
          owner: this.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 100n,
          blinding: field(seed, index),
          ringProgramId: RING,
        }),
        this.keypair,
        {},
        TREE_ID,
      ),
    );
  }

  get address(): ShieldedAddress {
    return this.keypair.shieldedAddress();
  }

  get viewingKey(): ShieldedAddress["viewingPublicKey"] {
    return this.address.viewingPublicKey;
  }

  async pay(indexer: Indexer, payments: readonly Pay[]): Promise<IndexedShieldedTransaction> {
    const tx = await this.seal(indexer, payments);
    indexer.publish(tx);
    return tx;
  }

  /** Seals one anonymous transfer from the next funding note, its leaves taken, unpublished. */
  async seal(indexer: Indexer, payments: readonly Pay[]): Promise<IndexedShieldedTransaction> {
    const recipients: PaymentRecipient[] = payments.map((pay) => ({
      viewingPublicKey: pay.to.viewingPublicKey,
      firstContact:
        pay.request === undefined ? { kind: "bootstrap" } : { kind: "request", tag: pay.request },
    }));
    const tags = await new TransferTagging({
      keys: this.keys,
      history: this.history,
      recipients,
    }).plan();
    this.history = tags.history;
    const plan = tags.payments.reduce(
      (planned, tag) => planned.withPayment(tag.payment),
      AnonymousPlan.create(tags.senderTag),
    );
    const input = this.#funding.shift();
    if (input === undefined) throw new Error("no funding left");
    const transfer = new ConfidentialTransfer(this.address, [input], PAYER)
      .withRingProgramId(RING)
      .withOutputTreeId(TREE_ID);
    for (const pay of payments) transfer.sendToRing(pay.to, SOL_MINT, pay.amount, RING);
    const prepared = transfer.prepare();
    const rail = new RingOutputRail(
      this.keypair.transactionViewingKey(prepared.firstNullifier),
      prepared.firstNullifier,
      { kind: "anonymous", plan },
    );
    const proof = rail.encrypt({
      prepared,
      sender: this.address,
      assets: ASSETS,
      instructionDiscriminator: InstructionTag.ringTransact,
    });
    const { outputs, resolvedOwnerTags, messages } = proof.externalData;
    const leaf = indexer.leaves(outputs.length);
    return {
      slot: leaf + 1n,
      txSignature: signature(leaf),
      eventIndex: 0,
      txViewingPublicKey: rail.txViewingKey.publicKey(),
      salt: rail.salt,
      outputSlots: outputs.map((output, index) => ({
        viewTag: resolvedOwnerTags[index] ?? ZERO,
        outputContext: {
          hash: output.utxoHash,
          tree: TREE,
          treeId: TREE_ID,
          leafIndex: leaf + BigInt(index),
        },
        payload: output.data ?? new Uint8Array(),
      })),
      messages,
      nullifiers: proof.inputUtxos.map((spent) => spent.nullifier()),
      proofless: false,
      ringProgramId: RING,
    };
  }

  sync(indexer: Indexer, history: ViewingHistory, held: readonly WalletUtxo[] = []) {
    return AnonymousSync.create(this.keys, ASSETS)
      .withHeldNotes(held)
      .fetch(indexer.client(), history);
  }
}

function fresh(wallet: Wallet): ViewingHistory {
  return ViewingHistory.create(wallet.address.viewingPublicKey, 0n);
}

function output(tx: IndexedShieldedTransaction, position: number): Bytes32 {
  const slot = tx.outputSlots[position];
  if (slot === undefined) throw new Error("no output");
  return slot.outputContext.hash;
}

function stream(scan: AnonymousScan, utxoHash: Bytes32): AnonymousStream {
  const found = scan.found.find((utxo) => hex(utxo.utxoHash) === hex(utxoHash));
  if (found === undefined) throw new Error(`note ${hex(utxoHash)} not found`);
  return found.stream;
}

function found(scan: AnonymousScan): readonly string[] {
  return scan.found.map((utxo) => hex(utxo.utxoHash));
}

function sent(wallet: Wallet, recipient: Wallet) {
  return wallet.history
    .current()
    .counter({ kind: "toRecipient", counterparty: recipient.viewingKey });
}

function receivedFrom(history: ViewingHistory, sender: Wallet) {
  return history.current().counter({ kind: "fromSender", counterparty: sender.viewingKey });
}

describe("anonymous sync", () => {
  it("pairs a bootstrap payment and finds the next one under the shared tag", async () => {
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const bob = new Wallet(2);
    const first = await alice.pay(indexer, [{ to: bob.address, amount: 30n }]);
    expect(first.outputSlots[1]?.viewTag).toEqual(bob.viewingKey.u());

    const scanned = await bob.sync(indexer, fresh(bob));
    expect(stream(scanned, output(first, 1))).toEqual({ kind: "bootstrap" });
    expect(receivedFrom(scanned.history, alice)?.next).toBe(0n);

    const second = await alice.pay(indexer, [{ to: bob.address, amount: 40n }]);
    const bobKey = bob.keypair.viewingKey();
    expect(second.outputSlots[1]?.viewTag).toEqual(
      bobKey.recipientSharedViewTags(alice.viewingKey).tag(0n),
    );
    bobKey.destroy();
    const rescanned = await bob.sync(indexer, scanned.history);
    expect(stream(rescanned, output(second, 1))).toMatchObject({ kind: "shared", index: 0n });
    expect(receivedFrom(rescanned.history, alice)?.next).toBe(1n);
    expect(sent(alice, bob)?.next).toBe(1n);
  });

  it("finds a request payment under its request tag", async () => {
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const bob = new Wallet(2);
    const minted = await bob.history.requestTag(bob.keys);
    bob.history = minted.history;
    const viewing = bob.keypair.viewingKey();
    expect(minted.tag).toEqual(viewing.recipientRequestViewTag(0n));
    viewing.destroy();
    const paid = await alice.pay(indexer, [{ to: bob.address, request: minted.tag, amount: 25n }]);
    expect(paid.outputSlots[1]?.viewTag).toEqual(minted.tag);
    const scanned = await bob.sync(indexer, fresh(bob));
    expect(stream(scanned, output(paid, 1))).toEqual({ kind: "request", index: 0n });
    expect(scanned.history.current().requestCount).toBe(1n);
    expect(receivedFrom(scanned.history, alice)?.next).toBe(0n);
  });

  it("finds the change under the sender tag", async () => {
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const bob = new Wallet(2);
    const paid = await alice.pay(indexer, [{ to: bob.address, amount: 30n }]);
    const viewing = alice.keypair.viewingKey();
    expect(paid.outputSlots[0]?.viewTag).toEqual(viewing.senderViewTag(0n));
    viewing.destroy();
    const scanned = await alice.sync(indexer, fresh(alice));
    expect(stream(scanned, output(paid, 0))).toEqual({ kind: "sender", index: 0n });
    const change = scanned.utxos[0];
    expect([change?.utxo.amount, change?.utxo.ringProgramId]).toEqual([70n, RING]);
    expect(scanned.history.current().txCount).toBe(1n);
    expect(
      scanned.history.current().counter({ kind: "toRecipient", counterparty: bob.viewingKey })
        ?.next,
    ).toBe(0n);
  });

  it("rebuilds the counters and both counterparty maps from index 0", async () => {
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const bob = new Wallet(2);
    for (const amount of [10n, 11n, 12n]) await alice.pay(indexer, [{ to: bob.address, amount }]);
    bob.history = (await bob.sync(indexer, bob.history)).history;
    await bob.pay(indexer, [{ to: alice.address, amount: 5n }]);
    const aliceRestored = await alice.sync(indexer, fresh(alice));
    const bobRestored = await bob.sync(indexer, fresh(bob));
    const restored = aliceRestored.history.current();
    expect(restored.txCount).toBe(3n);
    expect(restored.txCount).toBe(alice.history.current().txCount);
    expect(restored.counter({ kind: "toRecipient", counterparty: bob.viewingKey })?.next).toBe(
      sent(alice, bob)?.next,
    );
    expect(receivedFrom(aliceRestored.history, bob)?.next).toBe(0n);
    expect(bobRestored.history.current().txCount).toBe(1n);
    expect(receivedFrom(bobRestored.history, alice)?.next).toBe(2n);
    expect(
      bobRestored.history.current().counter({ kind: "toRecipient", counterparty: alice.viewingKey })
        ?.next,
    ).toBe(0n);
    const unspent = bobRestored.utxos.filter((utxo) => !utxo.spent);
    expect(unspent.reduce((sum, utxo) => sum + utxo.utxo.amount, 0n)).toBe(10n + 11n + 12n + 95n);
  });

  it("skips a body sealed to another key and goes on", async () => {
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const bob = new Wallet(2);
    const stranger = ShieldedAddress.fromPublicKeys(
      bob.address.signingPublicKey,
      bob.address.nullifierPublicKey,
      keypair(9).shieldedAddress().viewingPublicKey,
    );
    const misrouted = await alice.pay(indexer, [
      { to: stranger, request: bob.viewingKey.u(), amount: 9n },
    ]);
    expect(misrouted.outputSlots[1]?.viewTag).toEqual(bob.viewingKey.u());
    const paid = await alice.pay(indexer, [{ to: bob.address, amount: 30n }]);
    const scanned = await bob.sync(indexer, fresh(bob));
    expect(found(scanned)).toEqual([hex(output(paid, 1))]);
    expect(receivedFrom(scanned.history, alice)?.next).toBe(0n);
  });

  it("resumes from each watermark and a full rescan reads from index 0", async () => {
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const bob = new Wallet(2);
    const pay = (amount: bigint) => alice.pay(indexer, [{ to: bob.address, amount }]);
    const first = await pay(10n);
    const second = await pay(11n);
    const own = alice.history.current();
    expect([own.txCount, own.tx.scanned]).toEqual([2n, 0n]);

    const held = await bob.sync(indexer, fresh(bob));
    const counter = receivedFrom(held.history, alice);
    expect([counter?.next, counter?.scanned]).toEqual([1n, 1n]);
    const third = await pay(12n);

    const resumed = await bob.sync(indexer, held.history);
    expect(found(resumed)).toContain(hex(output(third, 1)));
    expect(found(resumed)).not.toContain(hex(output(second, 1)));
    expect(receivedFrom(resumed.history, alice)?.next).toBe(2n);

    const rescanned = await AnonymousSync.create(bob.keys, ASSETS)
      .withFullRescan()
      .fetch(indexer.client(), resumed.history);
    expect([...found(rescanned)].sort()).toEqual(
      [first, second, third].map((tx) => hex(output(tx, 1))).sort(),
    );
  });

  it("costs every forged sender one gap of tags, batched across streams, and still pairs a real one", async () => {
    const forged = 4096;
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const bob = new Wallet(2);
    const entry = ViewingKeyEntry.restore({
      viewingPublicKey: bob.viewingKey,
      createdAt: 0n,
      tx: StreamCounter.EMPTY,
      request: StreamCounter.EMPTY,
      knownSenders: Array.from({ length: forged }, () => ({
        key: X25519Keypair.generate().publicKey(),
        counter: StreamCounter.EMPTY,
      })),
      knownRecipients: [],
    });
    const firstRound = (forged + 3) * Number(TAG_GAP) + 1;
    const withinBound = ([reads, tags]: readonly [number, number]) => {
      expect(tags).toBeLessThanOrEqual(firstRound + 2 * Number(TAG_GAP));
      expect(reads).toBeLessThanOrEqual(Math.ceil(firstRound / TAGS_PER_REQUEST) + 1);
    };

    await alice.pay(indexer, [{ to: bob.address, amount: 30n }]);
    const paired = await bob.sync(indexer, fresh(bob).withEntry(0, entry));
    withinBound(indexer.takeTagReads());
    expect(paired.history.current().knownSenders()).toHaveLength(forged + 1);
    expect(receivedFrom(paired.history, alice)?.next).toBe(0n);

    const shared = await alice.pay(indexer, [{ to: bob.address, amount: 40n }]);
    const found = await bob.sync(indexer, paired.history);
    withinBound(indexer.takeTagReads());
    expect(stream(found, output(shared, 1))).toMatchObject({ kind: "shared", index: 0n });
  }, 60_000);

  it("finds a transfer landing behind the watermark on the next sync", async () => {
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const bob = new Wallet(2);
    const pay = (amount: bigint): readonly Pay[] => [{ to: bob.address, amount }];
    await alice.pay(indexer, pay(10n));
    const paired = await bob.sync(indexer, fresh(bob));
    const late = await alice.seal(indexer, pay(11n));
    const landed = await alice.pay(indexer, pay(12n));
    const pending = (counter: StreamCounter | undefined) => [counter?.scanned, counter?.pending];

    const passed = await bob.sync(indexer, paired.history);
    expect(pending(receivedFrom(passed.history, alice))).toEqual([2n, [0n]]);
    expect(stream(passed, output(landed, 1))).toMatchObject({ kind: "shared", index: 1n });
    const own = await alice.sync(indexer, alice.history);
    expect(pending(own.history.current().tx)).toEqual([3n, [1n]]);

    indexer.publish(late);
    const caught = await bob.sync(indexer, passed.history);
    expect(stream(caught, output(late, 1))).toMatchObject({ kind: "shared", index: 0n });
    expect(pending(receivedFrom(caught.history, alice))).toEqual([2n, []]);
    const ownCaught = await alice.sync(indexer, own.history);
    expect(stream(ownCaught, output(late, 0))).toEqual({ kind: "sender", index: 1n });
    expect(pending(ownCaught.history.current().tx)).toEqual([3n, []]);
  });

  it("lists every payment in the change and verifies a row only under a held address", async () => {
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const bob = new Wallet(2).address;
    const carol = new Wallet(3).address;
    const paid = await alice.pay(indexer, [
      { to: bob, amount: 30n },
      { to: carol, amount: 20n },
    ]);
    const forged = ShieldedAddress.fromPublicKeys(
      carol.signingPublicKey,
      new Wallet(4).address.nullifierPublicKey,
      carol.viewingPublicKey,
    );
    const scan = await AnonymousSync.create(alice.keys, ASSETS)
      .withRecipientAddresses([bob, forged])
      .fetch(indexer.client(), fresh(alice));
    expect(
      scan.sent.map((row) => [
        row.position,
        hex(row.recipientViewingPublicKey.toBytes()),
        hex(row.ownerPublicKey.toBytes()),
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
        hex(carol.signingPublicKey.toBytes()),
        20n,
        { kind: "unverified" },
        hex(output(paid, 2)),
        paid.txSignature,
      ],
    ]);
    const unheld = await alice.sync(indexer, fresh(alice));
    expect(unheld.sent.map((row) => row.check)).toEqual([
      { kind: "unverified" },
      { kind: "unverified" },
    ]);
  });

  it("leaves no row for a listed body that fails to open, the change still found", async () => {
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const bob = new Wallet(2).address;
    const paid = await alice.seal(indexer, [{ to: bob, amount: 30n }]);
    const slot = paid.outputSlots[1];
    if (slot === undefined) throw new Error("no payment");
    const payload = slot.payload.slice(0, -1);
    new DataView(payload.buffer).setUint32(1, payload.length - 5, true);
    const truncated = { ...paid, outputSlots: paid.outputSlots.with(1, { ...slot, payload }) };
    indexer.publish(truncated);
    const scan = await alice.sync(indexer, fresh(alice));
    expect(scan.sent).toEqual([]);
    expect(stream(scan, output(paid, 0))).toEqual({ kind: "sender", index: 0n });
  });

  it("never fails on sender-chosen garbage under a tag", async () => {
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const bob = new Wallet(2);
    const txKey = ViewingKey.generate();
    const salt = randomSalt();
    const noise = new Uint8Array(RECIPIENT_BODY_LEN).fill(0x5c);
    noise[0] = 1;
    // Names bob, its blinding outside the field fails the hash rebuild.
    const named = encodeAnonymousRecipient({
      verified: { ownerPublicKey: bob.address.signingPublicKey, mint: SOL_MINT, amount: 5n },
      unverified: {
        senderPublicKey: keypair(7).shieldedAddress().viewingPublicKey,
        blinding: new Uint8Array(32).fill(0xff) as Bytes32,
        data: new Data(),
      },
    });
    // Names bob, its change rebuilds no published hash.
    const bundle = encodeAnonymousSender({
      verified: {
        ownerPublicKey: bob.address.signingPublicKey,
        splMint: SOL_MINT,
        splAmount: 0n,
        solAmount: 5n,
        recipientViewingPublicKeys: [keypair(8).shieldedAddress().viewingPublicKey],
      },
      unverified: {
        blindingSeed: new Uint8Array(32).fill(0x0b) as Bytes32,
        splData: new Data(),
        solData: new Data(),
      },
    });
    const bodies = [noise, named];
    const leaf = indexer.leaves(bodies.length);
    const unmatched = new Uint8Array(32).fill(0x0c) as Bytes32;
    indexer.publish({
      slot: 1n,
      txSignature: getBase58Decoder().decode(new Uint8Array(64).fill(0x77)) as Signature,
      eventIndex: 0,
      txViewingPublicKey: txKey.publicKey(),
      salt,
      outputSlots: bodies.map((body, position) => ({
        viewTag: bob.viewingKey.u(),
        outputContext: {
          hash: unmatched,
          tree: TREE,
          treeId: TREE_ID,
          leafIndex: leaf + BigInt(position),
        },
        payload: encodeRingOutput(
          RingScheme.anonymousRecipient,
          txKey.encryptSlot(bob.viewingKey, body, salt, position),
        ),
      })),
      messages: [
        {
          viewTag: bob.viewingKey.u(),
          data: encodeRingOutput(
            RingScheme.anonymousSender,
            txKey.encryptSlot(bob.viewingKey, bundle, salt, bodies.length),
          ),
        },
      ],
      nullifiers: [field(9, 9)],
      proofless: false,
      ringProgramId: RING,
    });
    const paid = await alice.pay(indexer, [{ to: bob.address, amount: 30n }]);
    const scanned = await bob.sync(indexer, fresh(bob));
    expect(found(scanned)).toEqual([hex(output(paid, 1))]);
    expect(scanned.unmatched.map(hex)).toEqual([hex(unmatched), hex(unmatched)]);
    expect(scanned.history.current().knownSenders()).toHaveLength(1);
    expect(scanned.history.current().knownRecipients()).toEqual([]);
  });

  it("finds a merge of the wallet's notes and marks them spent", async () => {
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const bob = new Wallet(2);
    for (const amount of [70n, 30n]) await alice.pay(indexer, [{ to: bob.address, amount }]);
    const held = await bob.sync(indexer, fresh(bob));
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
  });

  it("finds an own deposit on the sender tag and moves tx_count, a malformed capsule opens to nothing", async () => {
    const indexer = new Indexer();
    const alice = new Wallet(1);
    const truncated = await alice.history.senderTag(alice.keys);
    alice.history = truncated.history;
    const kept = await alice.history.senderTag(alice.keys);
    alice.history = kept.history;
    for (const [tag, capsule, blinding] of [
      [truncated.tag, false, field(7, 1)],
      [kept.tag, true, field(7, 2)],
    ] as const)
      indexer.deposits.push(depositRow(alice.address, tag, capsule, blinding));
    const scanned = await alice.sync(indexer, fresh(alice));
    expect(scanned.found.map((utxo) => utxo.stream)).toEqual([{ kind: "sender", index: 1n }]);
    expect(scanned.history.current().txCount).toBe(2n);
    expect(scanned.utxos.map((utxo) => utxo.utxo.amount)).toEqual([25n]);
  });
});

/** `ownerUtxoHash ‖ asset ‖ u64le(amount) ‖ no data hash ‖ ring ‖ ring data hash ‖ envelope`. */
function depositRow(owner: ShieldedAddress, tag: ViewTag, capsule: boolean, blinding: Bytes32) {
  const envelope = ViewingKey.generate();
  const salt = randomSalt();
  const recipientCiphertext = envelope.encryptRingDeposit(
    owner.viewingPublicKey,
    encodeRingDepositPlaintext({ blinding, ringData: new Uint8Array() }),
    salt,
  );
  const ciphertext = capsule
    ? encodeRingDepositCapsule({
        slotIndex: 0,
        ephemeralPublicKey: new Uint8Array(33).fill(2) as Bytes33,
        ciphertext: new Uint8Array(96) as Bytes96,
        recipientCiphertext,
      })
    : new TextEncoder().encode("CRDEP001");
  const amount = new Uint8Array(8);
  new DataView(amount.buffer).setBigUint64(0, 25n, true);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, ciphertext.length, true);
  const body = concatBytes(
    ownerUtxoHash(owner.ownerHash(), blinding),
    new Uint8Array(32),
    amount,
    Uint8Array.of(0),
    addressBytes(RING),
    new Uint8Array(32),
    envelope.publicKey().toBytes(),
    salt,
    length,
    ciphertext,
  );
  envelope.destroy();
  const hash = new Utxo({
    owner: owner.signingPublicKey,
    asset: SOL_MINT,
    amount: 25n,
    blinding,
    ringProgramId: RING,
  }).hash(owner.nullifierPublicKey, TREE_ID);
  return {
    slot: 1n,
    txSignature: getBase58Decoder().decode(new Uint8Array(64).fill(blinding[31] ?? 0)) as Signature,
    outputSlot: {
      viewTag: tag,
      outputContext: {
        hash,
        tree: TREE,
        treeId: TREE_ID,
        leafIndex: 500n + BigInt(blinding[31] ?? 0),
      },
      payload: encodeOutputData(EncryptedScheme.ringDeposit, body),
    },
  };
}

describe("viewing history", () => {
  const key = () => X25519Keypair.generate().publicKey();

  it("reads at most one request after a round that finds its last index", () => {
    const scan = new GapScan(0n, StreamCounter.EMPTY);
    for (let round = 0; round < 64; round++) {
      const indices = scan.round();
      expect(indices.length).toBeLessThanOrEqual(TAGS_PER_REQUEST);
      expect(scan.advance(indices.slice(-1))).toBe(true);
    }
  });

  it("keeps an unseen index pending until it trails past the retention", () => {
    let counter = StreamCounter.EMPTY.observe(0n, new Set([1n, 3n]));
    expect([counter.scanned, counter.next]).toEqual([4n, 4n]);
    expect(counter.pending).toEqual([0n, 2n]);
    counter = counter.observe(4n, new Set([2n]));
    expect(counter.pending).toEqual([0n]);
    counter = counter.observe(4n, new Set([PENDING_RETENTION]));
    expect(counter.scanned).toBe(PENDING_RETENTION + 1n);
    expect(counter.pending).toEqual(
      Array.from({ length: Number(PENDING_RETENTION) - 4 }, (_, at) => BigInt(at) + 4n),
    );
  });

  it("keeps the watermark and the pending index a full rescan passes unseen", () => {
    const counter = StreamCounter.EMPTY.observe(0n, new Set([1n, 3n])).observe(
      0n,
      new Set([0n, 1n]),
    );
    expect(counter.scanned).toBe(4n);
    expect(counter.pending).toEqual([2n]);
  });

  it("round trips its JSON and refuses another version, a stale rotation and a malformed counter", async () => {
    const alice = new Wallet(1);
    const bob = keypair(2).shieldedAddress().viewingPublicKey;
    const tags = await new TransferTagging({
      keys: alice.keys,
      history: alice.history,
      recipients: [{ viewingPublicKey: bob, firstContact: { kind: "bootstrap" } }],
    }).plan();
    const rotated = tags.history.withRotatedKey(keypair(3).shieldedAddress().viewingPublicKey, 5n);
    const json = rotated.toJson();
    expect(ViewingHistory.fromJson(json).toJson()).toBe(json);
    const stored = JSON.parse(json) as { version: number; viewingHistory: { tx: unknown }[] };
    expect(stored.version).toBe(VIEWING_HISTORY_VERSION);
    expect(() => ViewingHistory.fromJson(JSON.stringify({ ...stored, version: 6 }))).toThrow(
      expect.objectContaining({ code: "RING_VIEWING_HISTORY_VERSION", details: { version: "6" } }),
    );
    expect(() => rotated.withRotatedKey(keypair(4).shieldedAddress().viewingPublicKey, 5n)).toThrow(
      "RING_ROTATED_KEY_NOT_NEWER",
    );
    const counter = StreamCounter.EMPTY.observe(0n, new Set([PENDING_RETENTION + 1n]));
    const history = ViewingHistory.create(key(), 0n);
    const entry = history.current().withCounter("tx", counter);
    const withCounter = history.withEntry(0, entry);
    expect(ViewingHistory.fromJson(withCounter.toJson()).toJson()).toBe(withCounter.toJson());
    const parsed = JSON.parse(withCounter.toJson()) as {
      viewingHistory: { tx: { pending: number[]; scanned: number } }[];
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
    const past = JSON.parse(history.toJson()) as { viewingHistory: { tx: { scanned: number } }[] };
    const [entryJson] = past.viewingHistory;
    if (entryJson === undefined) throw new Error("no entry");
    entryJson.tx.scanned = 1;
    expect(() => ViewingHistory.fromJson(JSON.stringify(past))).toThrow(
      "RING_VIEWING_HISTORY_INVALID",
    );
  });

  it("reads a u64 counter past 2^53 exactly", () => {
    const history = ViewingHistory.create(key(), 0n);
    const json = history.toJson().replace('"tx":{"next":0', `"tx":{"next":${(1n << 64n) - 2n}`);
    expect(ViewingHistory.fromJson(json).current().txCount).toBe((1n << 64n) - 2n);
  });

  it("takes shared, then request, then bootstrap tags in one transfer", async () => {
    const alice = new Wallet(1);
    const bob = keypair(2).shieldedAddress().viewingPublicKey;
    const carol = keypair(3).shieldedAddress().viewingPublicKey;
    const request = new Uint8Array(32).fill(3) as ViewTag;
    const tags = await new TransferTagging({
      keys: alice.keys,
      history: alice.history,
      recipients: [
        { viewingPublicKey: bob, firstContact: { kind: "bootstrap" } },
        { viewingPublicKey: bob, firstContact: { kind: "request", tag: request } },
        { viewingPublicKey: carol, firstContact: { kind: "request", tag: request } },
      ],
    }).plan();
    expect(tags.payments.map((tag) => tag.selection)).toEqual([
      { kind: "bootstrap" },
      { kind: "shared", index: 0n },
      { kind: "request" },
    ]);
    expect(tags.payments[0]?.payment.tag).toEqual(bob.u());
    expect(tags.payments[2]?.payment.tag).toEqual(request);
    const entry = tags.history.current();
    expect(entry.txCount).toBe(1n);
    expect(entry.counter({ kind: "toRecipient", counterparty: bob })?.next).toBe(1n);
    expect(entry.counter({ kind: "toRecipient", counterparty: carol })?.next).toBe(0n);
    expect(alice.history.current().txCount).toBe(0n);
  });

  it("pairs nothing on a deposit's first contact and pairs on a transfer's", async () => {
    const alice = new Wallet(1);
    const bob: PaymentRecipient = {
      viewingPublicKey: keypair(2).shieldedAddress().viewingPublicKey,
      firstContact: { kind: "bootstrap" },
    };
    const deposit = await alice.history.depositTag(alice.keys, bob);
    expect(deposit.tag.selection).toEqual({ kind: "bootstrap" });
    expect(deposit.history.current().knownRecipients()).toEqual([]);
    const again = await deposit.history.depositTag(alice.keys, bob);
    expect(again.tag.selection).toEqual({ kind: "bootstrap" });
    const transfer = await new TransferTagging({
      keys: alice.keys,
      history: again.history,
      recipients: [bob],
    }).plan();
    expect(
      transfer.history
        .current()
        .counter({ kind: "toRecipient", counterparty: bob.viewingPublicKey }),
    ).toBeDefined();
  });

  it("takes disjoint tags in the two directions of a pair", () => {
    const alice = keypair(1);
    const bob = keypair(2);
    const toBob = alice.viewingKey().sendSharedViewTags(bob.viewingPublicKey()).tag(0n);
    const toAlice = bob.viewingKey().sendSharedViewTags(alice.viewingPublicKey()).tag(0n);
    expect(hex(toBob)).not.toBe(hex(toAlice));
    expect(bob.viewingKey().recipientSharedViewTags(alice.viewingPublicKey()).tag(0n)).toEqual(
      toBob,
    );
  });

  it("refuses a history whose current key the keys do not hold", async () => {
    const keys: RingKeys = walletKeys(keypair(1));
    await expect(
      new TransferTagging({
        keys,
        history: ViewingHistory.create(key(), 0n),
        recipients: [],
      }).plan(),
    ).rejects.toThrow("RING_VIEWING_KEY_NOT_CURRENT");
  });
});
