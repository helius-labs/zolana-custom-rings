import { getBase58Decoder, type Address, type Signature } from "@solana/kit";

import {
  ClientError,
  type GetByNullifiersRequest,
  type GetByTagsRequest,
} from "@heliuslabs/spr/client";
import { InstructionTag, type Bytes32 } from "@heliuslabs/spr/interface";
import {
  ShieldedKeypair,
  SigningKey,
  X25519Keypair,
  type ShieldedAddress,
} from "@heliuslabs/spr/keypair";
import {
  AssetRegistry,
  ConfidentialTransfer,
  Data,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  type IndexedShieldedTransaction,
  type WalletUtxo,
} from "@heliuslabs/spr/transaction";

import { AnonymousPlan, RingOutputRail } from "../../src/operations/payments/output-rail.js";
import { sealOutputSlot } from "../../src/crypto/audit/ring-disclosure.js";
import { RecordKind } from "../../src/protocol/codec/audit-stream.js";
import type { ReplyMetadata } from "../../src/protocol/codec/anonymous-delivery.js";
import {
  AnonymousSync,
  type AnonymousScan,
  type AnonymousSyncClient,
} from "../../src/state/anonymous-sync.js";
import { ViewingHistory } from "../../src/state/viewing-history.js";
import { transactionItems } from "../../../../zolana/sdk-libs/ts/test/helpers/pages.js";
import { TREE, TREE_ID, randomAddress, walletKeys } from "./ring-pipeline.js";

/** An exit's record seals to it, no scan reads the auditor stream. */
const SCAN_AUDITOR = X25519Keypair.generate();

export const RING = randomAddress();
export const PAYER = randomAddress();
export const SCAN_USDC = randomAddress();
export const ASSETS = new AssetRegistry([[2n, SCAN_USDC]]);

const CONTEXT_FLOOR = 1n << 40n;
const ZERO = new Uint8Array(32) as Bytes32;

export function keypair(seed: number): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );
}

/** A canonical field value distinct per pair. */
export function field(seed: number, index: number): Bytes32 {
  const value = new Uint8Array(32).fill(0x11);
  value[30] = seed;
  value[31] = index;
  return value as Bytes32;
}

export function signature(leaf: bigint): Signature {
  const bytes = new Uint8Array(64).fill(0x5a);
  new DataView(bytes.buffer).setBigUint64(0, leaf);
  return getBase58Decoder().decode(bytes) as Signature;
}

export function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

/** Serves the by-ring read as Photon does, ordered by `(slot, signature)`, `limit` counting transactions. */
export class ScanIndexer {
  readonly transactions: IndexedShieldedTransaction[] = [];
  readonly ringReads: GetByTagsRequest[] = [];
  /** Tags named on the by-tags read, zero for a wallet that scans. */
  transactionTagReads = 0;
  /** Snapshot slot of each next page, past them the highest row or the floor. */
  readonly contexts: bigint[] = [];
  /** Answers the next by-ring read with the refusal. */
  refuseAt: Readonly<{ read: number; error: Error }> | undefined;
  responseLimit: number | undefined;
  #nextLeaf = 0n;

  publish(transaction: IndexedShieldedTransaction): void {
    this.transactions.push(transaction);
  }

  leaves(count: number): bigint {
    const first = this.#nextLeaf;
    this.#nextLeaf += BigInt(count);
    return first;
  }

  client(): AnonymousSyncClient {
    const context = { slot: CONTEXT_FLOOR, blockTime: 0n };
    return {
      getShieldedTransactionsByTags: async (request: GetByTagsRequest) => {
        if (request.ringProgramId === undefined) {
          this.transactionTagReads += request.tags.length;
          return { context, paginationToken: null, data: [] };
        }
        this.ringReads.push(request);
        if (this.refuseAt?.read === this.ringReads.length) throw this.refuseAt.error;
        if (this.responseLimit !== undefined && (request.limit ?? 1000) > this.responseLimit)
          throw new ClientError("CLIENT_INDEXER_RESPONSE_TOO_LARGE", {
            details: { method: "getShieldedTransactionsByTags" },
          });
        return this.#ringPage(request);
      },
      getEncryptedUtxosByTags: async () => ({ context, paginationToken: null, data: [] }),
      getShieldedTransactionsByNullifiers: async (request: GetByNullifiersRequest) => {
        const wanted = new Set(request.nullifiers.map(hex));
        return {
          context,
          paginationToken: null,
          data: transactionItems(
            this.transactions.filter((tx) =>
              tx.nullifiers.some((nullifier) => wanted.has(hex(nullifier))),
            ),
          ),
        };
      },
    };
  }

  #ringPage(request: GetByTagsRequest) {
    const limit = request.limit ?? 1000;
    const floor = request.filters?.slot?.gt;
    const [tokenSlot, tokenSignature] = request.paginationToken?.split(":") ?? [];
    const ordered = this.transactions
      .filter(
        (tx) =>
          tx.ringProgramId === request.ringProgramId && (floor === undefined || tx.slot > floor),
      )
      .sort((left, right) =>
        left.slot === right.slot
          ? left.txSignature < right.txSignature
            ? -1
            : 1
          : left.slot < right.slot
            ? -1
            : 1,
      )
      .filter(
        (tx) =>
          tokenSlot === undefined ||
          tx.slot > BigInt(tokenSlot) ||
          (tx.slot === BigInt(tokenSlot) && tx.txSignature > (tokenSignature ?? "")),
      );
    const page = ordered.slice(0, limit);
    const last = page.at(-1);
    const highest = this.transactions.reduce(
      (high, tx) => (tx.slot > high ? tx.slot : high),
      floor ?? 0n,
    );
    return {
      context: { slot: this.contexts.shift() ?? highest, blockTime: 0n },
      paginationToken:
        ordered.length > page.length && last !== undefined
          ? `${last.slot}:${last.txSignature}`
          : null,
      data: transactionItems(page),
    };
  }
}

export interface Pay {
  readonly to: ShieldedAddress;
  readonly amount: bigint;
  readonly reply?: ReplyMetadata;
}

export type SealedTransfer = IndexedShieldedTransaction;

/** A wallet enrolled on `RING` that pays through the real rail. */
export class ScanWallet {
  readonly keypair: ShieldedKeypair;
  readonly keys: ReturnType<typeof walletKeys>;
  readonly #funding: ProofInputUtxo[];

  constructor(seed: number) {
    this.keypair = keypair(seed);
    this.keys = walletKeys(this.keypair);
    this.#funding = Array.from({ length: 8 }, (_, index) =>
      this.#note(SOL_MINT, 100n, field(seed, index)),
    );
  }

  /** The next transfer spends a note of `asset` and pays every payment in it. */
  fundFirst(asset: Address, amount: bigint): void {
    this.#funding.unshift(this.#note(asset, amount, field(0xf0, this.#funding.length)));
  }

  #note(asset: Address, amount: bigint, blinding: Bytes32): ProofInputUtxo {
    return ProofInputUtxo.fromKeypair(
      new Utxo({
        owner: this.keypair.signingPublicKey(),
        asset,
        amount,
        blinding,
        ringProgramId: RING,
      }),
      this.keypair,
      {},
      TREE_ID,
    );
  }

  get address(): ShieldedAddress {
    return this.keypair.shieldedAddress();
  }

  get viewingKey(): ShieldedAddress["viewingPublicKey"] {
    return this.address.viewingPublicKey;
  }

  /** A history that reads `RING` from its start. */
  fresh(): ViewingHistory {
    return ViewingHistory.create(this.viewingKey, 0n).withRing(RING);
  }

  async pay(
    indexer: ScanIndexer,
    payments: readonly Pay[],
    options: Readonly<{ compact?: boolean; slot?: bigint }> = {},
  ): Promise<SealedTransfer> {
    const tx = this.seal(indexer, payments, options);
    indexer.publish(tx);
    return tx;
  }

  /** Seals one anonymous transfer from the next funding note, its leaves taken, unpublished. */
  seal(
    indexer: ScanIndexer,
    payments: readonly Pay[],
    options: Readonly<{ compact?: boolean; slot?: bigint }> = {},
  ): SealedTransfer {
    // An output to the sender is a bundle cell, not a payment.
    const plan = payments
      .filter((pay) => !pay.to.viewingPublicKey.equals(this.address.viewingPublicKey))
      .reduce(
        (planned, pay) =>
          planned.withPayment({ recipient: pay.to.viewingPublicKey, reply: pay.reply ?? null }),
        AnonymousPlan.create(),
      );
    const input = this.#funding.shift();
    if (input === undefined) throw new Error("no funding left");
    const transfer = (
      options.compact === true
        ? ConfidentialTransfer.compact(this.address, [input], PAYER)
        : new ConfidentialTransfer(this.address, [input], PAYER)
    )
      .withRingProgramId(RING)
      .withOutputTreeId(TREE_ID);
    for (const pay of payments) transfer.sendToRing(pay.to, input.utxo.asset, pay.amount, RING);
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
      auditor: SCAN_AUDITOR.publicKey(),
      instructionDiscriminator: InstructionTag.ringTransact,
    });
    const { outputs, resolvedOwnerTags, messages } = proof.externalData;
    const leaf = indexer.leaves(outputs.length);
    return {
      slot: options.slot ?? leaf + 1n,
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

  sync(indexer: ScanIndexer, history: ViewingHistory, held: readonly WalletUtxo[] = []) {
    return AnonymousSync.create(this.keys, ASSETS)
      .withHeldNotes(held)
      .fetch(indexer.client(), history);
  }

  fullScan(indexer: ScanIndexer, history: ViewingHistory = this.fresh()) {
    return AnonymousSync.create(this.keys, ASSETS).fullScan(indexer.client(), history, RING);
  }

  /** The claim the wallet confirms, its own viewing key the sender's. */
  replyTo(): ReplyMetadata {
    return {
      viewingKey: this.viewingKey,
      ownerKey: this.address.signingPublicKey.confidentialViewTag(),
      nullifierPk: this.address.nullifierPublicKey,
      data: new Data(),
    };
  }
}

export function output(tx: IndexedShieldedTransaction, position: number): Bytes32 {
  const slot = tx.outputSlots[position];
  if (slot === undefined) throw new Error("no output");
  return slot.outputContext.hash;
}

export function found(scan: Pick<AnonymousScan, "found">): readonly string[] {
  return scan.found.map((utxo) => hex(utxo.utxoHash));
}

/** A ring note's record sealed to `owner` under `slotSecret`, the body a reader opens. */
export function sealedNote(
  slotSecret: Bytes32,
  note: Readonly<{
    owner: ShieldedAddress;
    mint: Address;
    amount: bigint;
    blinding: Bytes32;
    /** The owner's own key unless a zero-key note names `ZERO_NULLIFIER_PK`. */
    nullifierPk?: Bytes32;
  }>,
): Uint8Array {
  return sealOutputSlot(slotSecret, {
    record: {
      kind: RecordKind.ring,
      amount: note.amount,
      ownerKey: note.owner.signingPublicKey.confidentialViewTag() as Bytes32,
      mint: note.mint,
      nullifierPk: note.nullifierPk ?? note.owner.nullifierPublicKey,
      blinding: note.blinding,
    },
  });
}
