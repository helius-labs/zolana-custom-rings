/** Transfers found by scanning each ring's history, Rust `zolana_ring_client::anonymous`. */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { getBase58Encoder, type ReadonlyUint8Array } from "@solana/kit";

import {
  ClientError,
  DEFAULT_INDEXER_POLL_CONFIG,
  type IndexerReader,
  type IndexerRpcConfig,
  type KitRpcAccess,
} from "@heliuslabs/spr/client";
import {
  bytesKey,
  equalBytes,
  isCanonicalField,
  isZero,
  PAGE_LIMIT,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import type { Address, Bytes16, Bytes32, RequestContext } from "@heliuslabs/spr/interface";
import {
  X25519PublicKey,
  type ShieldedAddress,
  type ShieldedPublicKey,
  type ViewingKey,
} from "@heliuslabs/spr/keypair";
import {
  transactOutputBlinding,
  SOL_ASSET_ID,
  SOL_MINT,
  type AssetRegistry,
  type IndexedShieldedTransaction,
  type OutputSlot,
  type ShieldedKeys,
  type Utxo,
  type WalletUtxo,
} from "@heliuslabs/spr/transaction";

import { txKeySlotSecret } from "../crypto/derivation/ring-stream.js";
import { isSmallOrder, x25519FromU } from "../crypto/keys/x25519.js";
import {
  openRecipientBody,
  openCompactRecipientBody,
  openReply,
  openSenderBundle,
  senderBundleLen,
  type BundleLayout,
  type ChangeCell,
  type RecipientBody,
  type ReplyClaim,
} from "../protocol/codec/anonymous-delivery.js";
import { CompactAssetResolver } from "../rpc/compact-assets.js";
import { DisclosureFormat } from "../protocol/codec/ring-disclosure-layout.js";
import { ringBodyOutput, senderBundleOutputBody } from "../protocol/transaction/output.js";
import { openRecipientNote } from "../crypto/derivation/blinding.js";
import { HalvingPageLimit, readRingPages, scanLimits, type ScanLimits } from "../rpc/history.js";
import type { AnonymousWallet } from "./anonymous-wallet.js";
import {
  RECOVERY_DIAGNOSTIC_SAMPLES,
  type RecoverySession,
  type RecoveryTask,
  type RecoveryPage,
} from "./recovery-session.js";
import { answered, decoded, unseen } from "./batch.js";
import { isZeroKeyNote as isExposedNote, zeroKeyNullifier } from "./exposed-notes.js";
import { openZeroKeyMerges, type OpenedZeroKeyMerge } from "./zero-key-merge.js";
import { registeredMint } from "../operations/workflow/recover.js";
import { openRingMerges } from "./ring-sync.js";
import type { RingKeys, RingTagFrame } from "./ring-keys.js";
import { RingError } from "../protocol/error.js";
import { ViewingHistory, type ViewingKeyEntry } from "./viewing-history.js";

/** The indexer's cap on the tags or nullifiers one request names. */
export const TAGS_PER_REQUEST = Number(PAGE_LIMIT);

/** How a sync found a note. */
export type AnonymousStream =
  /** A transfer's slot or bundle whose tag matched. */
  | Readonly<{ kind: "tagHint" }>
  | Readonly<{ kind: "merge"; firstNullifier: Bytes32 }>
  /** Tried with no use of its tag. */
  | Readonly<{ kind: "fullScan" }>;

export interface AnonymousRingUtxo {
  readonly utxoHash: Bytes32;
  readonly viewingPublicKey: X25519PublicKey;
  /** The registered key or `ZERO_NULLIFIER_PK`, whichever rebuilt. */
  readonly nullifierPublicKey: Bytes32;
  readonly stream: AnonymousStream;
}

export type SentCheck =
  /** A held recipient address rebuilt the published hash under `mint`. */
  | Readonly<{ kind: "verified"; mint: Address }>
  /** No held address names the viewing key and rebuilds the hash. */
  | Readonly<{ kind: "unverified" }>;

/** One payment the wallet's sender bundle lists, its body opened with the transaction key. */
export interface SentPayment {
  readonly txSignature: IndexedShieldedTransaction["txSignature"];
  readonly utxoHash: Bytes32;
  readonly position: number;
  readonly recipientViewingPublicKey: X25519PublicKey;
  /** The held address that rebuilt the hash, `undefined` under an unverified check. */
  readonly ownerPublicKey: ShieldedPublicKey | undefined;
  readonly amount: bigint;
  readonly check: SentCheck;
}

/** An unauthenticated sender claim, `AnonymousWallet.confirmClaim` alone learns from it. */
export interface SenderClaim {
  readonly utxoHash: Bytes32;
  readonly claim: ReplyClaim;
}

export interface AnonymousRecovery {
  /** The notes found, spent once a fetched transaction spends them. */
  readonly utxos: readonly WalletUtxo[];
  readonly spentNullifiers: readonly Bytes32[];
  readonly found: readonly AnonymousRingUtxo[];
  /** The replies on found notes, a frame without one adds none. */
  readonly senderClaims: readonly SenderClaim[];
  /** The wallet's payments in the transfers it sent, a body that fails to open left out. */
  readonly sent: readonly SentPayment[];
  /** Notes under a mint the registry lacks, stored and unspendable until it registers, no rescan needed. */
  readonly pendingOpenings: readonly WalletUtxo[];
  /** Rebuilt mints missing from the asset registry. */
  readonly unknownMints: readonly Address[];
  /** The output hash of each note in `pendingOpenings`. */
  readonly unmatched: readonly Bytes32[];
}

/** Bodies no held key rebuilt, an owner's note under a bad body opens only through an auditor read. */
export interface AuditorRecovery {
  /** Commitments, foreign notes and dummies among them. */
  readonly unopened: readonly Bytes32[];
  readonly unopenedCount: bigint;
}

export interface AnonymousScan extends AnonymousRecovery {
  readonly status: "Paused" | "Complete";
  readonly pauseReason: "pageBudget" | "assetLookup" | null;
  readonly targetSlot: bigint | null;
  readonly observedSlot: bigint;
  /** Filled by a full scan alone. */
  readonly auditorRecovery: AuditorRecovery;
  /** Counters, watermarks and ring positions as read, `AnonymousWallet.absorb` stores them with the notes. */
  readonly history: ViewingHistory;
}

/** A scan a sync issued and no absorb took, no copy carries a position past its notes. */
interface IssuedScan {
  readonly history: ViewingHistory;
  readonly wallet?: AnonymousWallet;
  readonly revision?: bigint;
  readonly coreRevision?: number;
  readonly session?: RecoverySession | null;
}
const issuedScans = new WeakMap<AnonymousScan, IssuedScan>();

/** @internal `AnonymousWallet.absorb` alone. */
export function consumeScan(
  scan: AnonymousScan,
  history: ViewingHistory,
  wallet: AnonymousWallet,
): RecoverySession | null | undefined {
  const original = issuedScans.get(scan);
  if (original === undefined) throw new RingError("RING_SCAN_CONSUMED");
  if (!history._progressMatches(original.history)) throw new RingError("RING_SCAN_HISTORY_CHANGED");
  if (original.wallet === undefined && scan.status === "Paused")
    throw new RingError("RING_SYNC_INCOMPLETE");
  if (original.wallet !== undefined) {
    const current = wallet._recoveryState();
    if (
      original.wallet !== wallet ||
      current.revision !== original.revision ||
      current.coreRevision !== original.coreRevision
    )
      throw new RingError("RING_SCAN_HISTORY_CHANGED");
  }
  issuedScans.delete(scan);
  return original.session;
}

export type AnonymousSyncClient = Pick<
  IndexerReader,
  | "getShieldedTransactionsByTags"
  | "getEncryptedUtxosByTags"
  | "getShieldedTransactionsByNullifiers"
>;

type SyncKeys = ShieldedKeys & RingKeys;

/** What opens a body, every secret stays with `keys`. */
interface BodyReads {
  readonly keys: SyncKeys;
  readonly assets: AssetRegistry;
  readonly recipients: readonly ShieldedAddress[];
  readonly resolveCompactAsset?: (assetId: bigint) => Promise<Address | undefined>;
}

interface SyncFields extends BodyReads {
  readonly config: IndexerRpcConfig | undefined;
  readonly minimumSlot?: bigint;
  readonly fullRescan: boolean;
  readonly held: readonly WalletUtxo[];
  readonly limits: ScanLimits;
  readonly senderFastPath: boolean;
  readonly tagMatcher: Pick<RingKeys, "ringTagMatches">;
  readonly compactAssetClient?: Pick<KitRpcAccess, "solanaRpc">;
}

/** Scans each ring of the history. */
export class AnonymousSync {
  readonly #fields: SyncFields;

  private constructor(fields: SyncFields) {
    this.#fields = fields;
    Object.freeze(this);
  }

  static create(keys: ShieldedKeys & RingKeys, assets: AssetRegistry): AnonymousSync {
    return new AnonymousSync({
      keys,
      assets,
      config: undefined,
      fullRescan: false,
      held: [],
      recipients: [],
      limits: scanLimits({}),
      senderFastPath: false,
      tagMatcher: keys,
    });
  }

  withCompactAssetClient(client: Pick<KitRpcAccess, "solanaRpc">): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, compactAssetClient: client });
  }

  withIndexerConfig(config: IndexerRpcConfig): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, config });
  }

  /** Every stream from index 0 and every ring from its start, for a wallet that keeps no notes between syncs. */
  withFullRescan(): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, fullRescan: true });
  }

  /** Include pending openings to retain their later spends. */
  withHeldNotes(held: readonly WalletUtxo[]): AnonymousSync {
    return new AnonymousSync({
      ...this.#fields,
      held: Object.freeze([...held]),
    });
  }

  /** The recipients' addresses the wallet holds, a sent payment verifies only against one. */
  withRecipientAddresses(recipients: readonly ShieldedAddress[]): AnonymousSync {
    return new AnonymousSync({
      ...this.#fields,
      recipients: Object.freeze([...recipients]),
    });
  }

  withScanLimits(input: Readonly<{ pageSize?: number; maxPages?: number }>): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, limits: scanLimits(input) });
  }

  /** Moves the tag test off the main thread, the matcher's worker is the key's holder. */
  withTagMatcher(tagMatcher: Pick<RingKeys, "ringTagMatches">): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, tagMatcher });
  }

  /** A bundle under the wallet's own transaction key skips its tag test, every other candidate keeps it. */
  withSenderFastPath(): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, senderFastPath: true });
  }

  /** An entry whose key the holder lacks stays as stored, a held key without an entry is refused until the history adds it. */
  async fetch(
    client: AnonymousSyncClient,
    history: ViewingHistory,
    context?: RequestContext,
  ): Promise<AnonymousScan> {
    const scan = this.#scan(client, history, context);
    try {
      await scan.rings();
      await scan.merges();
    } catch (error) {
      if (!(error instanceof RecoveryPaused)) throw error;
      scan.pause();
    }
    return scan.result();
  }

  async fetchWallet(
    client: AnonymousSyncClient,
    wallet: AnonymousWallet,
    context?: RequestContext,
  ): Promise<AnonymousScan> {
    return this.#fetchWallet(client, wallet, undefined, context);
  }

  async fullScanWallet(
    client: AnonymousSyncClient,
    wallet: AnonymousWallet,
    ring: Address,
    context?: RequestContext,
  ): Promise<AnonymousScan> {
    return this.#fetchWallet(client, wallet, ring, context);
  }

  async #fetchWallet(
    client: AnonymousSyncClient,
    wallet: AnonymousWallet,
    ring: Address | undefined,
    context: RequestContext | undefined,
  ): Promise<AnonymousScan> {
    const original = wallet._recoveryState();
    const history = wallet.history();
    const fields = {
      ...this.#fields,
      minimumSlot: wallet._recoveryMinimumSlot(),
      held: [...wallet.notes(), ...wallet.pendingOpenings()],
    };
    if (!equalBytes(fields.keys.address().toBytes(), wallet.wallet.identity.toBytes()))
      throw new RingError("RING_SCAN_HISTORY_CHANGED");
    if (fields.keys.viewingPublicKeys().some((key) => history.entry(key) === undefined))
      throw new RingError("RING_VIEWING_HISTORY_INVALID", {
        details: { reason: "a held viewing key has no entry" },
      });
    const scan = new Scan(fields, client, history, context);
    const session = await scan.resume(original.session, ring);
    const result = await scan.result();
    issuedScans.set(result, {
      history,
      wallet,
      revision: original.revision,
      coreRevision: original.coreRevision,
      session,
    });
    return result;
  }

  /** Tries every slot and bundle of `ring` from its start with no use of a tag, spends resolve from the same pages. */
  async fullScan(
    client: AnonymousSyncClient,
    history: ViewingHistory,
    ring: Address,
    context?: RequestContext,
  ): Promise<AnonymousScan> {
    const scan = this.#scan(client, history, context);
    try {
      await scan.recover(ring);
      await scan.merges();
    } catch (error) {
      if (!(error instanceof RecoveryPaused)) throw error;
      scan.pause();
    }
    return scan.result();
  }

  #scan(
    client: AnonymousSyncClient,
    history: ViewingHistory,
    context: RequestContext | undefined,
  ): Scan {
    if (this.#fields.keys.viewingPublicKeys().some((key) => history.entry(key) === undefined))
      throw new RingError("RING_VIEWING_HISTORY_INVALID", {
        details: { reason: "a held viewing key has no entry" },
      });
    return new Scan(this.#fields, client, history, context);
  }
}

export interface RingFullScan {
  readonly status: "Paused" | "Complete";
  readonly pauseReason: "pageBudget" | "assetLookup" | null;
  readonly targetSlot: bigint | null;
  /** Under the wallet's own nullifier key. */
  readonly utxos: readonly WalletUtxo[];
  /** Unspent zero-key notes in publication order. */
  readonly exposedIfSpent: readonly WalletUtxo[];
  /** The nullifiers of the spent zero-key notes. */
  readonly spentExposed: readonly Bytes32[];
  readonly pending: readonly WalletUtxo[];
  readonly auditorRecovery: AuditorRecovery;
}

/** A wrong tag hides nothing here, every held key tries every site of `ring`. */
export async function ringFullScan(
  input: Readonly<{
    keys: SyncKeys;
    assets: AssetRegistry;
    client: AnonymousSyncClient;
    ring: Address;
    config?: IndexerRpcConfig;
  }>,
  context?: RequestContext,
): Promise<RingFullScan> {
  const [current, ...retired] = [...input.keys.viewingPublicKeys()].reverse();
  if (current === undefined)
    throw new RingError("RING_VIEWING_HISTORY_INVALID", {
      details: { reason: "no held viewing key" },
    });
  const history = retired
    .reduce(
      (held, key, index) => held.withRotatedKey(key, BigInt(index + 1)),
      ViewingHistory.create(current, 0n),
    )
    .withRing(input.ring);
  const sync = AnonymousSync.create(input.keys, input.assets);
  const scan = await (
    input.config === undefined ? sync : sync.withIndexerConfig(input.config)
  ).fullScan(input.client, history, input.ring, context);
  const zeroKey = scan.utxos.filter(isExposedNote);
  return Object.freeze({
    utxos: Object.freeze(scan.utxos.filter((note) => !isExposedNote(note))),
    exposedIfSpent: Object.freeze(zeroKey.filter((note) => !note.spent)),
    spentExposed: Object.freeze(zeroKey.filter((note) => note.spent).map((note) => note.nullifier)),
    pending: scan.pendingOpenings,
    auditorRecovery: scan.auditorRecovery,
    status: scan.status,
    pauseReason: scan.pauseReason,
    targetSlot: scan.targetSlot,
  });
}

/** Rust `RingDeliveryContext`. */
interface SlotContext {
  readonly ring: Address;
  readonly txViewingPublicKey: X25519PublicKey;
  readonly salt: Bytes16;
  readonly firstNullifier: Bytes32;
}

/** A recipient body at an output, a sender bundle in a message. */
type Site =
  | Readonly<{ kind: "output"; position: number }>
  | Readonly<{ kind: "message"; message: number }>;

/** A ring body or a sender bundle a held key may open. */
interface Body {
  readonly tx: IndexedShieldedTransaction;
  readonly site: Site;
  readonly ciphertext: Uint8Array;
  readonly reply: Uint8Array;
  readonly context: SlotContext;
  readonly found: AnonymousStream;
  readonly format: DisclosureFormat;
}

/** A note whose rebuilt hash matched, before its nullifier. */
interface Found {
  readonly utxo: Utxo;
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
  readonly outputContext: WalletUtxo["outputContext"];
  readonly nullifierPublicKey: Bytes32;
  readonly order: Publication;
  /** Under a mint the registry lacks. */
  readonly pending?: boolean;
}

/** Where a note was published, the order a scan returns its notes in. */
interface Publication {
  readonly slot: bigint;
  readonly signature: ReadonlyUint8Array;
  readonly position: number;
}

interface Decrypted {
  readonly utxo: WalletUtxo;
  readonly order: Publication;
}

type Rebuilt = Readonly<{
  utxo: Utxo;
  nullifierPublicKey: Bytes32;
  dataHash?: Bytes32;
  ringDataHash?: Bytes32;
}>;

/** A body the reader's own keys rebuilt. */
interface RebuiltNote extends Rebuilt {
  readonly body: Body;
  readonly position: number;
  readonly claim: ReplyClaim | undefined;
  readonly pending: boolean;
}

class Scan {
  readonly #unopened = new Map<string, Bytes32>();
  readonly #sync: SyncFields;
  readonly #client: AnonymousSyncClient;
  readonly #context: RequestContext | undefined;
  readonly #address: ShieldedAddress;
  readonly #ledger: NoteLedger;
  /** Held notes stay out of the ledger, a merge output among them is not found again. */
  readonly #heldHashes: ReadonlySet<string>;
  readonly #originalHistory: ViewingHistory;
  readonly #pageLimit = new HalvingPageLimit(TAGS_PER_REQUEST);
  #history: ViewingHistory;
  #status: "Paused" | "Complete" = "Complete";
  #pauseReason: "pageBudget" | "assetLookup" | null = null;
  #session: RecoverySession | undefined;
  #page: RecoveryPage | undefined;
  #workOffset = 0;
  #unopenedCount = 0n;
  #queueHead = 0;
  #queued = new Set<string>();
  #compactResolver: CompactAssetResolver | undefined;

  constructor(
    sync: SyncFields,
    client: AnonymousSyncClient,
    history: ViewingHistory,
    context: RequestContext | undefined,
  ) {
    this.#sync = sync;
    this.#client = client;
    this.#context = context;
    this.#address = sync.keys.address();
    this.#ledger = new NoteLedger(sync.keys, sync.held);
    this.#heldHashes = new Set(sync.held.map(({ outputContext }) => bytesKey(outputContext.hash)));
    this.#originalHistory = history;
    this.#history = history;
  }

  async resume(
    stored: RecoverySession | null,
    ring: Address | undefined,
  ): Promise<RecoverySession | null> {
    const mode = ring === undefined ? "tagHints" : "everySite";
    const keys = this.#sync.keys.viewingPublicKeys().map(keyHex).sort();
    const owner = bytesToHex(this.#address.toBytes());
    const session = stored ?? this.#newSession({ owner, keys, mode, ring });
    if (
      session.owner !== owner ||
      session.mode !== mode ||
      session.ring !== (ring ?? null) ||
      session.rescan !== this.#sync.fullRescan ||
      session.senderFastPath !== this.#sync.senderFastPath ||
      session.keys.length !== keys.length ||
      session.keys.some((key) => !keys.includes(key))
    )
      throw new RingError("RING_SCAN_HISTORY_CHANGED");
    this.#session = session;
    this.#history = ViewingHistory.fromJson(session.history);
    this.#unopenedCount = session.unopenedCount;
    for (const hash of session.unopenedSamples)
      this.#unopened.set(hash, hexToBytes(hash) as Bytes32);
    this.#queued = new Set([
      ...session.queue,
      ...session.checked,
      ...(session.active?.nullifiers ?? []),
    ]);
    this.#enqueue(this.#sync.held.filter((note) => !note.spent).map((note) => note.nullifier));
    let remaining = this.#sync.limits.maxPages;
    if (session.targetSlot === null) {
      const first = this.#history.entries.find((entry) =>
        session.keys.includes(keyHex(entry.viewingPublicKey)),
      );
      if (first === undefined) throw new RingError("RING_SCAN_HISTORY_CHANGED");
      const minimumSlot = this.#history.entries.reduce(
        (floor, entry) =>
          entry
            .ringPositions()
            .reduce(
              (highest, position) => maxSlot(highest, position.afterSlot ?? 0n),
              maxSlot(floor, entry.tagPosition ?? 0n),
            ),
        maxSlot(this.#sync.minimumSlot ?? 0n, this.#sync.config?.requireSlot ?? 0n),
      );
      const probe = await this.#client.getEncryptedUtxosByTags(
        { tags: [first.viewingPublicKey.u()], limit: 1, minContextSlot: minimumSlot },
        { poll: this.#sync.config?.poll ?? DEFAULT_INDEXER_POLL_CONFIG, requireSlot: minimumSlot },
        this.#context,
      );
      if (probe.context.slot < minimumSlot) throw new RingError("RING_HISTORY_PAGE_INVALID");
      session.targetSlot = probe.context.slot;
      remaining--;
    }
    if (session.targetSlot < (this.#sync.minimumSlot ?? 0n))
      throw new RingError("RING_SYNC_INCOMPLETE");
    while (remaining > 0) {
      await this.#ledger.assignNullifiers(this.#context);
      this.#enqueue(this.#ledger.takeNullifiers());
      if (session.active === null && this.#queueHead < session.queue.length) {
        session.active = {
          nullifiers: session.queue.slice(this.#queueHead, this.#queueHead + TAGS_PER_REQUEST),
          limit: this.#sync.limits.pageSize,
          token: null,
          workOffset: 0,
        };
        this.#queueHead += session.active.nullifiers.length;
      }
      try {
        if (session.active !== null) {
          remaining--;
          await this.#spendPage(session.active);
          continue;
        }
        const task = session.tasks[session.task];
        if (task === undefined) break;
        remaining--;
        await this.#discoveryPage(task);
      } catch (error) {
        if (
          error instanceof ClientError &&
          error.code === "CLIENT_INDEXER_RESPONSE_TOO_LARGE" &&
          this.#page !== undefined &&
          this.#page.workOffset === 0 &&
          this.#page.limit > 1
        ) {
          this.#page.limit = Math.floor(this.#page.limit / 2);
          continue;
        }
        if (!(error instanceof RecoveryPaused)) throw error;
        this.#pauseReason = "assetLookup";
        break;
      }
    }
    await this.#ledger.assignNullifiers(this.#context);
    this.#enqueue(this.#ledger.takeNullifiers());
    session.queue = session.queue.slice(this.#queueHead);
    this.#queueHead = 0;
    session.history = this.#history.toJson();
    session.unopenedCount = this.#unopenedCount;
    session.unopenedSamples = [...this.#unopened.keys()];
    const complete =
      session.task === session.tasks.length &&
      session.active === null &&
      session.queue.length === 0;
    this.#status = complete ? "Complete" : "Paused";
    this.#pauseReason = complete ? null : (this.#pauseReason ?? "pageBudget");
    if (!complete) this.#history = this.#originalHistory;
    return complete ? null : session;
  }

  #newSession(
    input: Readonly<{
      owner: string;
      keys: string[];
      mode: "tagHints" | "everySite";
      ring: Address | undefined;
    }>,
  ): RecoverySession {
    const tasks: RecoveryTask[] = [];
    for (const entry of this.#history.entries.filter((candidate) =>
      input.keys.includes(keyHex(candidate.viewingPublicKey)),
    )) {
      const key = keyHex(entry.viewingPublicKey);
      const rings =
        input.ring === undefined ? entry.ringPositions() : [{ ring: input.ring, afterSlot: null }];
      for (const position of rings)
        tasks.push({
          kind: "ring",
          ring: position.ring,
          keys: [key],
          afterSlot: this.#sync.fullRescan ? null : position.afterSlot,
          limit: this.#sync.limits.pageSize,
          token: null,
          workOffset: 0,
        });
    }
    const ringTasks = new Map<string, Extract<RecoveryTask, { kind: "ring" }>>();
    const combined = tasks.filter((task) => {
      if (task.kind !== "ring") return true;
      const key = `${task.ring}:${task.afterSlot}`;
      const previous = ringTasks.get(key);
      if (previous === undefined) {
        ringTasks.set(key, task);
        return true;
      }
      previous.keys.push(...task.keys);
      return false;
    });
    return {
      version: 1,
      ...input,
      ring: input.ring ?? null,
      rescan: this.#sync.fullRescan,
      senderFastPath: this.#sync.senderFastPath,
      history: this.#history.toJson(),
      targetSlot: null,
      tasks: combined,
      task: 0,
      queue: [],
      checked: [],
      active: null,
      unopenedCount: 0n,
      unopenedSamples: [],
    };
  }

  #enqueue(nullifiers: readonly Bytes32[]): void {
    const session = this.#session;
    if (session === undefined) return;
    for (const nullifier of nullifiers) {
      const key = bytesToHex(nullifier);
      if (unseen(this.#queued, key)) session.queue.push(key);
    }
  }

  #query(page: RecoveryPage, afterSlot?: bigint | null) {
    const target = this.#session?.targetSlot;
    if (target === undefined || target === null) throw new RingError("RING_HISTORY_PAGE_INVALID");
    this.#page = page;
    return {
      limit: page.limit,
      ...(page.token === null ? {} : { paginationToken: page.token }),
      filters: {
        slot: {
          lte: target,
          ...(afterSlot === undefined || afterSlot === null ? {} : { gt: afterSlot }),
        },
      },
      minContextSlot: target,
    };
  }

  #queryConfig(): IndexerRpcConfig {
    const target = this.#session?.targetSlot ?? 0n;
    return { poll: this.#sync.config?.poll ?? DEFAULT_INDEXER_POLL_CONFIG, requireSlot: target };
  }

  #validatePage(
    page: Readonly<{
      context: Readonly<{ slot: bigint }>;
      data: readonly Readonly<{ slot: bigint }>[];
      paginationToken: string | null;
    }>,
    cursor: RecoveryPage,
    afterSlot?: bigint | null,
  ): void {
    const target = this.#session?.targetSlot;
    if (
      target === undefined ||
      target === null ||
      page.context.slot < target ||
      page.data.length > cursor.limit ||
      page.data.some(
        (row) =>
          row.slot > target ||
          (afterSlot !== undefined && afterSlot !== null && row.slot <= afterSlot),
      ) ||
      (page.paginationToken !== null && page.paginationToken === cursor.token)
    )
      throw new RingError("RING_HISTORY_PAGE_INVALID");
    this.#page = cursor;
    this.#workOffset = 0;
  }

  async #spendPage(active: RecoveryPage & { nullifiers: string[] }): Promise<void> {
    const response = await this.#client.getShieldedTransactionsByNullifiers(
      {
        ...this.#query(active),
        nullifiers: active.nullifiers.map((key) => hexToBytes(key) as Bytes32),
      },
      this.#queryConfig(),
      this.#context,
    );
    this.#validatePage(response, active);
    const rows = response.data.flatMap((item) => item.events);
    await keepRingMerges(this.#mergeReads(), rows);
    this.#ledger.keepZeroKeyMerges(
      await openZeroKeyMerges({ keys: this.#sync.keys, owner: this.#address, rows }, this.#context),
      this.#sync.assets,
    );
    await this.#ledger.assignNullifiers(this.#context);
    this.#ledger.noteSpends(rows);
    active.token = response.paginationToken;
    active.workOffset = 0;
    const session = this.#session;
    if (active.token === null && session !== undefined) {
      session.checked.push(...active.nullifiers);
      session.active = null;
    }
  }

  async #discoveryPage(task: RecoveryTask): Promise<void> {
    const session = this.#session;
    if (session === undefined) throw new RingError("RING_HISTORY_PAGE_INVALID");
    const response = await this.#client.getShieldedTransactionsByTags(
      { ...this.#query(task, task.afterSlot), tags: [], ringProgramId: task.ring as Address },
      this.#queryConfig(),
      this.#context,
    );
    this.#validatePage(response, task, task.afterSlot);
    const rows = response.data.flatMap((item) => item.events);
    if (rows.some((row) => row.ringProgramId !== task.ring))
      throw new RingError("RING_HISTORY_PAGE_INVALID");
    for (const key of task.keys) {
      const viewingPublicKey = X25519PublicKey.fromBytes(hexToBytes(key));
      if (session.mode === "everySite") await this.#tryEverySite(viewingPublicKey, rows);
      else await this.#testTags(viewingPublicKey, rows);
    }
    if (this.#workOffset !== task.workOffset) throw new RingError("RING_HISTORY_PAGE_INVALID");
    this.#ledger.keepZeroKeyMerges(
      await openZeroKeyMerges({ keys: this.#sync.keys, owner: this.#address, rows }, this.#context),
      this.#sync.assets,
    );
    if (session.mode === "everySite") await keepRingMerges(this.#mergeReads(), rows);
    await this.#ledger.assignNullifiers(this.#context);
    this.#ledger.noteSpends(rows);
    if (session.mode === "everySite") this.#diagnostics(rows);
    task.token = response.paginationToken;
    task.workOffset = 0;
    if (task.token === null) {
      for (const key of task.keys)
        this.#history = this.#history._withRingCheckpoint(
          task.ring as Address,
          X25519PublicKey.fromBytes(hexToBytes(key)),
          session.targetSlot ?? 0n,
        );
      session.task++;
    }
  }

  #diagnostics(rows: readonly IndexedShieldedTransaction[]): void {
    for (const slot of rows.flatMap((row) => row.outputSlots)) {
      if (
        ringBodyOutput(slot.payload) === undefined ||
        this.#ledger.isFound(slot.outputContext.hash)
      )
        continue;
      this.#unopenedCount++;
      if (this.#unopened.size < RECOVERY_DIAGNOSTIC_SAMPLES)
        this.#unopened.set(bytesToHex(slot.outputContext.hash), slot.outputContext.hash);
    }
  }

  pause(): void {
    this.#status = "Paused";
    this.#pauseReason = "assetLookup";
    this.#history = this.#originalHistory;
  }

  /** Entries at one position of one ring share a read, a key added later is its own query. */
  async rings(): Promise<void> {
    const reads = new Map<
      string,
      Readonly<{ ring: Address; afterSlot: bigint | null; keys: X25519PublicKey[] }>
    >();
    for (const entry of this.#history.entries.filter((held) => this.#holds(held)))
      for (const { ring, afterSlot } of entry.ringPositions()) {
        const position = this.#sync.fullRescan ? null : afterSlot;
        const key = `${ring}:${String(position)}`;
        const read = reads.get(key) ?? { ring, afterSlot: position, keys: [] };
        read.keys.push(entry.viewingPublicKey);
        reads.set(key, read);
      }
    for (const { ring, afterSlot, keys } of reads.values())
      await this.#readRing({ ring, afterSlot, keys, trial: "tagHints" });
  }

  /** Recovery, every site tried under every held key from the ring's start. */
  async recover(ring: Address): Promise<void> {
    const keys = this.#history.entries
      .filter((held) => this.#holds(held))
      .map((entry) => entry.viewingPublicKey);
    await this.#readRing({ ring, afterSlot: null, keys, trial: "everySite" });
  }

  /** The spends of every found or held ring note, round after round, open the ring merges among them. */
  merges(): Promise<void> {
    return openMerges(
      this.#mergeReads(),
      (frontier) =>
        this.#paged(frontier, (nullifiers, token, limit) =>
          this.#client
            .getShieldedTransactionsByNullifiers(
              { nullifiers, ...token, limit },
              this.#sync.config,
              this.#context,
            )
            .then((page) => ({ ...page, items: page.data.flatMap((item) => item.events) })),
        ),
      this.#sync.held.flatMap((utxo) => (utxo.spent ? [] : [utxo.nullifier])),
    );
  }

  async result(): Promise<AnonymousScan> {
    const recovery = await this.#ledger.recovery(this.#context);
    for (const note of [...recovery.utxos, ...recovery.pendingOpenings])
      this.#unopened.delete(bytesKey(note.outputContext.hash));
    if (this.#session !== undefined) this.#session.unopenedSamples = [...this.#unopened.keys()];
    const scan: AnonymousScan = Object.freeze({
      ...recovery,
      auditorRecovery: Object.freeze({
        unopenedCount: this.#unopenedCount,
        unopened: Object.freeze(
          [...this.#unopened.entries()]
            .sort(([left], [right]) => (left < right ? -1 : 1))
            .map(([, hash]) => hash),
        ),
      }),
      history: this.#history,
      status: this.#status,
      pauseReason: this.#pauseReason,
      targetSlot: this.#session?.targetSlot ?? null,
      observedSlot: this.#ledger.observedSlot,
    });
    issuedScans.set(scan, { history: this.#originalHistory });
    return scan;
  }

  #holds(entry: ViewingKeyEntry): boolean {
    return this.#sync.keys.viewingPublicKeys().some((key) => key.equals(entry.viewingPublicKey));
  }

  #mergeReads(): MergeReads {
    return {
      keys: this.#sync.keys,
      owner: this.#address,
      assets: this.#sync.assets,
      ledger: this.#ledger,
      held: this.#heldHashes,
      context: this.#context,
    };
  }

  /** Reads to a terminal page, only its `context.slot` becomes a position. */
  async #readRing(
    read: Readonly<{
      ring: Address;
      afterSlot: bigint | null;
      keys: readonly X25519PublicKey[];
      trial: "tagHints" | "everySite";
    }>,
  ): Promise<void> {
    const { ring, afterSlot, keys, trial } = read;
    const reach = await readRingPages(
      {
        client: this.#client,
        ringProgramId: ring,
        limits: this.#sync.limits,
        ...(afterSlot === null ? {} : { afterSlot }),
        ...(this.#sync.config === undefined ? {} : { config: this.#sync.config }),
      },
      async (rows) => {
        // 1. Each page opens before the next arrives, the scan keeps no ring row past its page.
        for (const viewingPublicKey of keys)
          if (trial === "tagHints") await this.#testTags(viewingPublicKey, rows);
          else await this.#tryEverySite(viewingPublicKey, rows);
        // 2. A recovery reads every merge in its pages, a tag sync finds ring merges by nullifier.
        if (trial === "everySite") await keepRingMerges(this.#mergeReads(), rows);
        // 3. A zero-key merge tags its owner's identity and opens under the viewing key alone.
        this.#ledger.keepZeroKeyMerges(
          await openZeroKeyMerges(
            { keys: this.#sync.keys, owner: this.#address, rows },
            this.#context,
          ),
          this.#sync.assets,
        );
        await this.#ledger.assignNullifiers(this.#context);
        this.#ledger.noteSpends(rows);
        if (trial === "everySite") this.#diagnostics(rows);
      },
      this.#context,
    );
    if (reach.checkpoint === undefined) {
      this.#status = "Paused";
      this.#pauseReason = "pageBudget";
      return;
    }
    const { checkpoint } = reach;
    this.#history = keys.reduce(
      (history, key) => history._withRingCheckpoint(ring, key, checkpoint),
      this.#history,
    );
  }

  /** One agreement per candidate per key inside the holder, only a matching tag opens a body. */
  async #testTags(
    viewingPublicKey: X25519PublicKey,
    rows: readonly IndexedShieldedTransaction[],
  ): Promise<void> {
    const candidates = rows
      .map((tx) => sitesOf(tx).flatMap((site) => bodyAt(tx, site, TAG_HINT) ?? []))
      .filter((bodies) => bodies.length > 0);
    if (candidates.length === 0) return;
    const recognized = await this.#ownBundles(viewingPublicKey, candidates.flat());
    const tested = candidates
      .map((bodies) => bodies.filter((body) => !recognized.has(body)))
      .filter((bodies) => bodies.length > 0);
    const frames = tested.flatMap((bodies): RingTagFrame[] => {
      const [first] = bodies;
      if (first === undefined) return [];
      const { txViewingPublicKey, salt, firstNullifier } = first.context;
      return [
        {
          viewingPublicKey,
          txViewingPublicKey,
          salt,
          firstNullifier,
          probes: bodies.map(bodyProbe),
        },
      ];
    });
    const answers =
      frames.length === 0 ? [] : await this.#sync.tagMatcher.ringTagMatches(frames, this.#context);
    const matched = answered(tested, answers).flatMap(([bodies, frameAnswers]) =>
      answered(bodies, frameAnswers).flatMap(([body, secret]) =>
        secret === undefined ? [] : [[body, secret] as const],
      ),
    );
    await this.#read(viewingPublicKey, [
      ...matched,
      ...(await bodySecrets(this.#sync.keys, viewingPublicKey, [...recognized], this.#context)),
    ]);
  }

  /** The fast path's bundles, a proof under another transaction key keeps its tag test. */
  async #ownBundles(
    viewingPublicKey: X25519PublicKey,
    bodies: readonly Body[],
  ): Promise<ReadonlySet<Body>> {
    if (!this.#sync.senderFastPath) return new Set();
    const own = await ownTransactions(this.#sync.keys, viewingPublicKey, bodies, this.#context);
    for (const key of own.values()) key.destroy();
    return new Set(
      bodies.filter(
        (body) => body.site.kind === "message" && own.has(bytesKey(body.context.firstNullifier)),
      ),
    );
  }

  /** Recovers every rail without reading a tag, tags are unproved hints. */
  async #tryEverySite(
    viewingPublicKey: X25519PublicKey,
    rows: readonly IndexedShieldedTransaction[],
  ): Promise<void> {
    const bodies = rows.flatMap((tx) =>
      sitesOf(tx).flatMap((site) => bodyAt(tx, site, FULL_SCAN) ?? []),
    );
    await this.#read(
      viewingPublicKey,
      await bodySecrets(this.#sync.keys, viewingPublicKey, bodies, this.#context),
    );
  }

  async #read(
    viewingPublicKey: X25519PublicKey,
    opened: readonly (readonly [Body, Bytes32])[],
  ): Promise<void> {
    const reads: BodyReads = {
      ...this.#sync,
      resolveCompactAsset: (id) => this.#resolveCompact(id),
    };
    await readBodies(reads, viewingPublicKey, opened, this.#context, async (open) => {
      const step = this.#workOffset++;
      if (this.#page !== undefined && step < this.#page.workOffset) return;
      this.#ledger.absorb(viewingPublicKey, await open());
      if (this.#page !== undefined) this.#page.workOffset = step + 1;
    });
  }

  async #resolveCompact(assetId: bigint): Promise<Address | undefined> {
    if (assetId === 0n) return undefined;
    if (assetId === SOL_ASSET_ID) return SOL_MINT;
    const source = this.#sync.compactAssetClient;
    const targetSlot = this.#session?.targetSlot;
    if (targetSlot === undefined || targetSlot === null)
      throw new RingError("RING_SYNC_INCOMPLETE", {
        details: { reason: "compact asset recovery requires fetchWallet or fullScanWallet" },
      });
    if (source === undefined)
      throw new RingError("RING_SYNC_INCOMPLETE", {
        details: { reason: "compact asset recovery requires withCompactAssetClient" },
      });
    try {
      this.#compactResolver ??= await CompactAssetResolver.open(
        { client: source, targetSlot },
        this.#context,
      );
      const resolved = await this.#compactResolver.resolve(assetId, this.#context);
      if (resolved.kind === "paused") throw new RecoveryPaused();
      return resolved.kind === "foreign" ? undefined : resolved.mint.asset;
    } catch (error) {
      if (
        error instanceof ClientError &&
        ["CLIENT_REQUEST", "CLIENT_RPC", "CLIENT_TIMEOUT", "CLIENT_INDEXER_TIMEOUT"].includes(
          error.code,
        ) &&
        (error.details as { retryable?: boolean } | undefined)?.retryable !== false
      )
        throw new RecoveryPaused();
      throw error;
    }
  }

  /** Every page of every chunk, a null token ends a chunk's read. */
  async #paged<T>(
    queried: readonly Bytes32[],
    fetch: (
      chunk: Bytes32[],
      token: Readonly<{ paginationToken?: string }>,
      limit: number,
    ) => Promise<Readonly<{ items: readonly T[]; paginationToken: string | null }>>,
  ): Promise<readonly T[]> {
    const items: T[] = [];
    for (let start = 0; start < queried.length; start += TAGS_PER_REQUEST) {
      const chunk = queried.slice(start, start + TAGS_PER_REQUEST);
      const followed = new Set<string>();
      let token: string | undefined;
      for (;;) {
        const asked = token === undefined ? {} : { paginationToken: token };
        const page = await this.#pageLimit.read((limit) => fetch(chunk, asked, limit));
        items.push(...page.items);
        token = page.paginationToken ?? undefined;
        if (token === undefined) break;
        if (followed.has(token))
          throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
            details: { path: "$.paginationToken" },
          });
        followed.add(token);
      }
    }
    return items;
  }
}

interface MergeReads {
  readonly keys: ShieldedKeys;
  readonly owner: ShieldedAddress;
  readonly assets: AssetRegistry;
  readonly ledger: NoteLedger;
  /** Output hash keys of the held notes. */
  readonly held: ReadonlySet<string>;
  readonly context: RequestContext | undefined;
}

/** The merges spending the found and held ring notes, round after round. */
async function openMerges(
  input: MergeReads,
  spendsOf: (frontier: readonly Bytes32[]) => Promise<readonly IndexedShieldedTransaction[]>,
  heldRing: readonly Bytes32[],
): Promise<void> {
  const queried = new Set<string>();
  let seed = heldRing;
  for (;;) {
    await input.ledger.assignNullifiers(input.context);
    const frontier = [...input.ledger.takeNullifiers(), ...seed].filter((nullifier) =>
      unseen(queried, bytesKey(nullifier)),
    );
    seed = [];
    if (frontier.length === 0) return;
    const spends = await spendsOf(frontier);
    await keepRingMerges(input, spends);
    await input.ledger.assignNullifiers(input.context);
    input.ledger.noteSpends(spends);
  }
}

/** Keeps each merge output of `rows` the owner's keys open and no held or found note holds. */
async function keepRingMerges(
  input: MergeReads,
  rows: readonly IndexedShieldedTransaction[],
): Promise<void> {
  const { ledger, owner, context } = input;
  const { merges, utxos } = await openRingMerges(
    { keys: input.keys, owner, assets: input.assets, spends: rows },
    context,
  );
  const opened = new Map(utxos.map((utxo) => [bytesKey(utxo.outputContext.hash), utxo]));
  for (const merge of merges) {
    const firstNullifier = merge.nullifiers[0];
    if (firstNullifier === undefined) continue;
    for (const [position, slot] of merge.outputSlots.entries()) {
      const hash = slot.outputContext.hash;
      const key = bytesKey(hash);
      const utxo = opened.get(key);
      if (utxo === undefined || input.held.has(key) || ledger.isFound(hash)) continue;
      const pending = registeredMint(input.assets, utxo.utxo.asset) === undefined;
      if (pending) ledger.unknownMint(utxo.utxo.asset);
      ledger.keep(
        {
          utxo: utxo.utxo,
          pending,
          outputContext: utxo.outputContext,
          nullifierPublicKey: owner.nullifierPublicKey,
          order: publication(merge, position),
        },
        owner.viewingPublicKey,
        Object.freeze({ kind: "merge", firstNullifier }),
      );
    }
  }
}

/** @internal The notes one sync or recovery keeps, each once, under the stream that found it. */
export class NoteLedger {
  readonly #keys: ShieldedKeys;
  /** Only a spend of these or of a found note leaves the ledger, a ring's other spends are not the wallet's. */
  readonly #held: readonly WalletUtxo[];
  #found: Found[] = [];
  readonly #decrypted: Decrypted[] = [];
  readonly #pending: Decrypted[] = [];
  /** Output hash keys of every kept note, one lookup per candidate. */
  readonly #known = new Set<string>();
  readonly #streams: AnonymousRingUtxo[] = [];
  /** Kept apart from `#streams`, a recovery opens merges page by page yet lists them after every body. */
  readonly #mergeStreams: AnonymousRingUtxo[] = [];
  /** Each beside its key's index, the list stays ordered by held key. */
  readonly #zeroKeyStreams: (readonly [number, AnonymousRingUtxo])[] = [];
  readonly #spent = new Map<string, Bytes32>();
  readonly #ownedNullifiers = new Set<string>();
  #newNullifiers: Bytes32[] = [];
  readonly #senderClaims: SenderClaim[] = [];
  readonly #sent: SentPayment[] = [];
  readonly #sentKeys = new Set<string>();
  readonly #unknownMints = new Set<Address>();
  #observedSlot = 0n;

  constructor(keys: ShieldedKeys, held: readonly WalletUtxo[]) {
    this.#keys = keys;
    this.#held = held;
    for (const note of held) {
      this.#known.add(bytesKey(note.outputContext.hash));
      this.#ownedNullifiers.add(bytesKey(note.nullifier));
    }
  }

  /** A claim stays with its note, a note found twice adds none. */
  absorb(viewingPublicKey: X25519PublicKey, read: BodyRead): void {
    for (const { utxo, nullifierPublicKey, body, position, claim, pending } of read.notes) {
      const slot = body.tx.outputSlots[position];
      if (slot === undefined || this.isFound(slot.outputContext.hash)) continue;
      this.keep(
        {
          utxo,
          nullifierPublicKey,
          pending,
          outputContext: walletContext(slot),
          order: publication(body.tx, position),
        },
        viewingPublicKey,
        body.found,
      );
      if (claim !== undefined)
        this.#senderClaims.push(Object.freeze({ utxoHash: slot.outputContext.hash, claim }));
    }
    // A repeated row lists its payments again, the published output names each once.
    for (const payment of read.sent)
      if (unseen(this.#sentKeys, `${payment.txSignature}:${bytesKey(payment.utxoHash)}`))
        this.#sent.push(payment);
    for (const mint of read.unknownMints) this.unknownMint(mint);
  }

  get observedSlot(): bigint {
    return this.#observedSlot;
  }

  keep(note: Found, viewingPublicKey: X25519PublicKey, stream: AnonymousStream): void {
    this.#observedSlot = maxSlot(this.#observedSlot, note.order.slot);
    this.#known.add(bytesKey(note.outputContext.hash));
    this.#found.push(note);
    (stream.kind === "merge" ? this.#mergeStreams : this.#streams).push(
      Object.freeze({
        utxoHash: note.outputContext.hash,
        viewingPublicKey,
        nullifierPublicKey: note.nullifierPublicKey,
        stream,
      }),
    );
  }

  unknownMint(mint: Address): void {
    this.#unknownMints.add(mint);
  }

  keepZeroKeyMerges(opened: readonly OpenedZeroKeyMerge[], assets: AssetRegistry): void {
    const held = this.#keys.viewingPublicKeys();
    for (const { utxo, row, position, viewingPublicKey } of opened) {
      const hash = utxo.outputContext.hash;
      if (this.isFound(hash)) continue;
      const firstNullifier = row.nullifiers[0];
      if (firstNullifier === undefined) continue;
      this.#known.add(bytesKey(hash));
      this.#observedSlot = maxSlot(this.#observedSlot, row.slot);
      const pending = registeredMint(assets, utxo.utxo.asset) === undefined;
      if (pending) this.unknownMint(utxo.utxo.asset);
      this.#ownedNullifiers.add(bytesKey(utxo.nullifier));
      if (!utxo.spent) this.#newNullifiers.push(utxo.nullifier);
      (pending ? this.#pending : this.#decrypted).push({
        utxo,
        order: publication(row, position),
      });
      this.#zeroKeyStreams.push([
        held.findIndex((key) => key.equals(viewingPublicKey)),
        Object.freeze({
          utxoHash: hash,
          viewingPublicKey,
          nullifierPublicKey: ZERO_NULLIFIER_PK as Bytes32,
          stream: Object.freeze({ kind: "merge" as const, firstNullifier }),
        }),
      ]);
    }
  }

  isFound(hash: Bytes32): boolean {
    return this.#known.has(bytesKey(hash));
  }

  noteSpends(transactions: readonly IndexedShieldedTransaction[]): void {
    for (const tx of transactions)
      for (const nullifier of tx.nullifiers)
        if (this.#ownedNullifiers.has(bytesKey(nullifier)))
          this.#spent.set(bytesKey(nullifier), nullifier);
  }

  /** Derives the nullifiers of the found notes in publication order. */
  async assignNullifiers(context: RequestContext | undefined): Promise<void> {
    const found = this.#found;
    this.#found = [];
    const registered = found.filter((note) => !isZeroKeyNote(note));
    const derived =
      registered.length === 0
        ? []
        : await this.#keys.derive(
            registered.map(({ utxo, outputContext }) => ({
              kind: "nullifier" as const,
              utxoHash: outputContext.hash,
              blinding: utxo.blinding,
            })),
            context,
          );
    const nullifiers = new Map(answered(registered, derived));
    for (const note of found) {
      const { order, nullifierPublicKey: _nullifierPublicKey, ...fields } = note;
      const nullifier =
        nullifiers.get(note) ?? zeroKeyNullifier(fields.outputContext.hash, fields.utxo.blinding);
      const { pending, ...kept } = fields;
      this.#ownedNullifiers.add(bytesKey(nullifier));
      this.#newNullifiers.push(nullifier);
      (pending === true ? this.#pending : this.#decrypted).push({
        utxo: Object.freeze({ ...kept, nullifier, spent: false }),
        order,
      });
    }
  }

  takeNullifiers(): readonly Bytes32[] {
    const nullifiers = this.#newNullifiers;
    this.#newNullifiers = [];
    return nullifiers;
  }

  async recovery(context: RequestContext | undefined): Promise<AnonymousRecovery> {
    await this.assignNullifiers(context);
    this.#decrypted.sort((left, right) => compareOrder(left.order, right.order));
    this.#pending.sort((left, right) => compareOrder(left.order, right.order));
    return Object.freeze({
      utxos: this.#marked(this.#decrypted),
      pendingOpenings: this.#marked(this.#pending),
      spentNullifiers: Object.freeze(
        [...this.#decrypted, ...this.#pending, ...this.#held.map((utxo) => ({ utxo }))].flatMap(
          ({ utxo: { nullifier } }) => (this.#spent.has(bytesKey(nullifier)) ? [nullifier] : []),
        ),
      ),
      found: Object.freeze([
        ...this.#streams,
        ...this.#mergeStreams,
        ...this.#zeroKeyStreams
          .toSorted(([left], [right]) => left - right)
          .map(([, stream]) => stream),
      ]),
      senderClaims: Object.freeze([...this.#senderClaims]),
      sent: Object.freeze([...this.#sent]),
      unknownMints: Object.freeze([...this.#unknownMints]),
      unmatched: Object.freeze(this.#pending.map(({ utxo }) => utxo.outputContext.hash)),
    });
  }

  #marked(notes: readonly Decrypted[]): readonly WalletUtxo[] {
    return Object.freeze(
      notes.map(({ utxo }) =>
        Object.freeze({ ...utxo, spent: this.#spent.has(bytesKey(utxo.nullifier)) }),
      ),
    );
  }
}

/** One viewing key's reading of a batch of bodies. */
class BodyRead {
  readonly notes: RebuiltNote[] = [];
  readonly unknownMints: Address[] = [];
  readonly sent: SentPayment[] = [];
  readonly #reads: BodyReads;
  readonly #owner: ShieldedAddress;

  constructor(reads: BodyReads) {
    this.#reads = reads;
    this.#owner = reads.keys.address();
  }

  async recipientBody(body: Body, position: number, secret: Bytes32): Promise<void> {
    const opening = await this.#opening(body.format, secret, body.ciphertext);
    if (opening === undefined) return;
    this.#note(body, position, opening, claimOf(body.reply, secret));
  }

  /** Each change slot the bundle rebuilds from the seed and retained chain history with no auditor read, then the payments only the sender's own key proves. */
  async senderBundle(
    body: Body,
    secret: Bytes32,
    txViewingKey: ViewingKey | undefined,
  ): Promise<void> {
    const slots = bundleSlots(body.tx);
    const bundle = decoded(() => openSenderBundle(secret, body.ciphertext, slots.layout));
    if (bundle === undefined) return;
    try {
      for (const [index, position] of slots.bodiless.entries()) {
        const cell = bundle.change[index];
        const opening =
          cell === undefined
            ? undefined
            : decoded(() =>
                changeOpening(
                  cell,
                  transactOutputBlinding(body.context.firstNullifier, bundle.outputSeed, position),
                ),
              );
        this.#note(body, position, opening, undefined);
      }
    } finally {
      bundle.outputSeed.fill(0);
    }
    if (txViewingKey === undefined) return;
    for (const [position, recipient] of listedRecipients(bundle.recipientKeys, slots.bearing)) {
      const sent = await this.#sentPayment(body, position, recipient, txViewingKey);
      if (sent !== undefined) this.sent.push(sent);
    }
  }

  async #opening(
    format: DisclosureFormat,
    secret: Bytes32,
    ciphertext: Uint8Array,
  ): Promise<RecipientBody | undefined> {
    if (format === DisclosureFormat.Standard)
      return decoded(() => openRecipientBody(secret, ciphertext));
    const compact = decoded(() => openCompactRecipientBody(secret, ciphertext));
    if (compact === undefined) return undefined;
    const mint = await this.#reads.resolveCompactAsset?.(compact.assetId);
    if (mint === undefined) return undefined;
    return { blinding: compact.blinding, amount: compact.amount, mint };
  }

  /** Only a rebuilt commitment counts, the cipher authenticates nothing. */
  #note(
    body: Body,
    position: number,
    opening: RecipientBody | undefined,
    claim: ReplyClaim | undefined,
  ): void {
    const slot = body.tx.outputSlots[position];
    if (slot === undefined || opening === undefined) return;
    const rebuilt = rebuild(this.#reads.assets, this.#owner, slot, body.context.ring, opening);
    if (rebuilt !== undefined) this.#keep(body, position, rebuilt, claim);
  }

  /** A mint the registry lacks holds the note back, the scan still moves past it. */
  #keep(body: Body, position: number, rebuilt: Rebuilt, claim: ReplyClaim | undefined): void {
    const slot = body.tx.outputSlots[position];
    if (slot === undefined) return;
    const mint = rebuilt.utxo.asset;
    const pending = registeredMint(this.#reads.assets, mint) === undefined;
    if (pending) this.unknownMints.push(mint);
    this.notes.push({ ...rebuilt, body, position, claim, pending });
  }

  /** `undefined` when the body at `position` fails to open under the recipient's key. */
  async #sentPayment(
    body: Body,
    position: number,
    recipient: X25519PublicKey,
    txViewingKey: ViewingKey,
  ): Promise<SentPayment | undefined> {
    const slot = body.tx.outputSlots[position];
    const parts = slot === undefined ? undefined : ringBodyOutput(slot.payload);
    if (slot === undefined || parts === undefined) return undefined;
    const secret = txKeySlotSecret({
      txViewingKey,
      recipientViewingKey: recipient,
      salt: body.context.salt,
      outputIndex: position,
      firstNullifier: body.context.firstNullifier,
    });
    let opening: RecipientBody | undefined;
    try {
      opening = await this.#opening(parts.format, secret, parts.body);
    } finally {
      secret.fill(0);
    }
    if (opening === undefined) return undefined;
    const verified = this.#reads.recipients.find(
      (address) =>
        address.viewingPublicKey.equals(recipient) &&
        rebuild(this.#reads.assets, address, slot, body.context.ring, opening) !== undefined,
    );
    return Object.freeze({
      txSignature: body.tx.txSignature,
      utxoHash: slot.outputContext.hash,
      position,
      recipientViewingPublicKey: recipient,
      ownerPublicKey: verified?.signingPublicKey,
      amount: opening.amount,
      check: Object.freeze(
        verified === undefined
          ? { kind: "unverified" as const }
          : { kind: "verified" as const, mint: opening.mint },
      ),
    });
  }
}

/** Each body's slot secret, one agreement per transaction inside the holder. */
async function bodySecrets(
  keys: RingKeys,
  viewingPublicKey: X25519PublicKey,
  bodies: readonly Body[],
  context: RequestContext | undefined,
): Promise<readonly (readonly [Body, Bytes32])[]> {
  if (bodies.length === 0) return [];
  return answered(
    bodies,
    await keys.ringDeliverySecrets(
      bodies.map((body) => ({
        viewingPublicKey,
        txViewingPublicKey: body.context.txViewingPublicKey,
        salt: body.context.salt,
        outputIndex: outputIndex(body),
        firstNullifier: body.context.firstNullifier,
      })),
      context,
    ),
  );
}

/** Wipes every secret it reads. */
async function readBodies(
  reads: BodyReads,
  viewingPublicKey: X25519PublicKey,
  opened: readonly (readonly [Body, Bytes32])[],
  context: RequestContext | undefined,
  visit: (open: () => Promise<BodyRead>) => Promise<void>,
): Promise<void> {
  let own: ReadonlyMap<string, ViewingKey> = new Map();
  try {
    own = await ownTransactions(
      reads.keys,
      viewingPublicKey,
      opened.map(([body]) => body),
      context,
    );
    for (const [body, secret] of opened)
      await visit(async () => {
        const read = new BodyRead(reads);
        if (body.site.kind === "output") await read.recipientBody(body, body.site.position, secret);
        else await read.senderBundle(body, secret, own.get(bytesKey(body.context.firstNullifier)));
        return read;
      });
  } finally {
    for (const [, secret] of opened) secret.fill(0);
    for (const txViewingKey of own.values()) txViewingKey.destroy();
  }
}

/** The transaction key of each transaction the entry's key sent, keyed by its first nullifier. */
async function ownTransactions(
  keys: ShieldedKeys,
  viewingPublicKey: X25519PublicKey,
  bodies: readonly Body[],
  context: RequestContext | undefined,
): Promise<ReadonlyMap<string, ViewingKey>> {
  const contexts = new Map<string, SlotContext>();
  for (const body of bodies)
    if (body.site.kind === "message")
      contexts.set(bytesKey(body.context.firstNullifier), body.context);
  if (contexts.size === 0) return new Map();
  const held = [...contexts.values()];
  const derived = answered(
    held,
    await keys.transactionKeys(
      held.map((slot) => ({
        viewingPublicKey,
        firstNullifier: slot.firstNullifier,
      })),
      context,
    ),
  );
  const own = new Map<string, ViewingKey>();
  derived.forEach(([slot, txViewingKey]) => {
    // Another viewing key sent the transaction.
    if (!txViewingKey.publicKey().equals(slot.txViewingPublicKey)) {
      txViewingKey.destroy();
      return;
    }
    own.set(bytesKey(slot.firstNullifier), txViewingKey);
  });
  return own;
}

/** Tries the registered key then the zero key, a third key misses. */
function rebuild(
  assets: AssetRegistry,
  owner: ShieldedAddress,
  slot: OutputSlot,
  ring: Address,
  opening: RecipientBody,
): Rebuilt | undefined {
  const { hash, treeId } = slot.outputContext;
  if (treeId === undefined) return undefined;
  return decoded(() =>
    openRecipientNote({ owner, ring, treeId, commitment: hash, assets }, opening),
  );
}

function changeOpening(cell: ChangeCell, blinding: Bytes32): RecipientBody {
  return Object.freeze({ mint: cell.mint, amount: cell.amount, blinding });
}

/** A row's slots in the bundle's order, the k-th bodiless slot takes the k-th change cell. */
function bundleSlots(tx: IndexedShieldedTransaction): {
  readonly bodiless: readonly number[];
  readonly bearing: readonly number[];
  readonly layout: BundleLayout;
} {
  const bodiless: number[] = [];
  const bearing: number[] = [];
  for (const [position, slot] of tx.outputSlots.entries())
    (slot.payload.length === 0 ? bodiless : bearing).push(position);
  return { bodiless, bearing, layout: { outputs: tx.outputSlots.length, change: bodiless.length } };
}

/** Zero keys and keys no ECDH accepts left out, each key beside its slot. */
function listedRecipients(
  keys: readonly Bytes32[],
  bearing: readonly number[],
): readonly (readonly [number, X25519PublicKey])[] {
  return keys.flatMap((key, index) => {
    const position = bearing[index];
    if (position === undefined || isZero(key)) return [];
    const recipient = decoded(() => x25519FromU(key));
    return recipient === undefined || isSmallOrder(recipient)
      ? []
      : [[position, recipient] as const];
  });
}

function sitesOf(tx: IndexedShieldedTransaction): readonly Site[] {
  return [
    ...tx.outputSlots.map((_, position): Site => ({ kind: "output", position })),
    ...tx.messages.map((_, message): Site => ({ kind: "message", message })),
  ];
}

/** `undefined` for a site that holds no well formed body or bundle. */
function bodyAt(
  tx: IndexedShieldedTransaction,
  site: Site,
  found: AnonymousStream,
): Body | undefined {
  const context = slotContext(tx);
  if (context === undefined) return undefined;
  if (site.kind === "output") {
    const slot = tx.outputSlots[site.position];
    const parts = slot === undefined ? undefined : ringBodyOutput(slot.payload);
    return parts === undefined
      ? undefined
      : {
          tx,
          site,
          ciphertext: parts.body,
          reply: parts.reply,
          context,
          found,
          format: parts.format,
        };
  }
  const message = tx.messages[site.message];
  const bundle = message === undefined ? undefined : senderBundleOutputBody(message.data);
  // Compact slots never reach the event, a bundle of any other `m` opens under another secret.
  return bundle?.length === senderBundleLen(bundleSlots(tx).layout)
    ? {
        tx,
        site,
        ciphertext: bundle,
        reply: new Uint8Array(),
        context,
        found,
        format: DisclosureFormat.Standard,
      }
    : undefined;
}

/** `undefined` without a reply or on bytes that never decode. */
function claimOf(reply: Uint8Array, secret: Bytes32): ReplyClaim | undefined {
  return reply.length === 0 ? undefined : decoded(() => openReply(secret, reply));
}

/** A body at its position, a bundle at `m`, past every body's index. */
function outputIndex(body: Body): number {
  return body.site.kind === "output" ? body.site.position : body.tx.outputSlots.length;
}

const FULL_SCAN: AnonymousStream = Object.freeze({ kind: "fullScan" });
const TAG_HINT: AnonymousStream = Object.freeze({ kind: "tagHint" });
const base58 = getBase58Encoder();

function isZeroKeyNote(note: Found): boolean {
  return equalBytes(note.nullifierPublicKey, ZERO_NULLIFIER_PK);
}

/** `undefined` without a ring, a contributory key, a salt or a canonical first nullifier. */
function slotContext(tx: IndexedShieldedTransaction): SlotContext | undefined {
  const { ringProgramId: ring, txViewingPublicKey, salt } = tx;
  const firstNullifier = tx.nullifiers[0];
  if (
    ring === undefined ||
    txViewingPublicKey === undefined ||
    salt === undefined ||
    firstNullifier === undefined ||
    isSmallOrder(txViewingPublicKey) ||
    !isCanonicalField(firstNullifier)
  )
    return undefined;
  return { ring, txViewingPublicKey, salt, firstNullifier };
}

function walletContext(slot: OutputSlot): WalletUtxo["outputContext"] {
  return Object.freeze({
    hash: slot.outputContext.hash,
    tree: slot.outputContext.tree,
    leafIndex: slot.outputContext.leafIndex,
  });
}

/** A slot answers under the recipient domain, a bundle under the sender's at index `m`. */
function bodyProbe(body: Body): RingTagFrame["probes"][number] {
  const { site, tx } = body;
  const published =
    site.kind === "output" ? tx.outputSlots[site.position] : tx.messages[site.message];
  if (published === undefined)
    throw new RingError("RING_VIEWING_HISTORY_INVALID", { details: { reason: "no such site" } });
  return {
    kind: site.kind === "output" ? "recipient" : "senderBundle",
    outputIndex: outputIndex(body),
    tag: published.viewTag,
  };
}

function publication(tx: IndexedShieldedTransaction, position: number): Publication {
  return { slot: tx.slot, signature: base58.encode(tx.txSignature), position };
}

/** Slot, then signature bytes, then output position. */
function compareOrder(left: Publication, right: Publication): number {
  if (left.slot !== right.slot) return left.slot < right.slot ? -1 : 1;
  const length = Math.min(left.signature.length, right.signature.length);
  for (let at = 0; at < length; at++) {
    const difference = (left.signature[at] ?? 0) - (right.signature[at] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.signature.length - right.signature.length || left.position - right.position;
}

function keyHex(key: X25519PublicKey): string {
  return bytesToHex(key.toBytes());
}

class RecoveryPaused extends Error {}

function maxSlot(left: bigint, right: bigint): bigint {
  return left > right ? left : right;
}
