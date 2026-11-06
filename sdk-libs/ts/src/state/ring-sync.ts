/**
 * Ring notes opened into a wallet, the pinned zolana sync drops them, Rust `zolana_ring_client::confidential`.
 *
 * Read `syncRingWallet` first. Each held key's `tagPosition` resumes the ring tag reads beside the core sync's checkpoints, `AnonymousWallet._absorbConfidential` stores both with the notes.
 */
import { syncWallet, type SyncReport, type SyncWalletInput } from "@heliuslabs/spr";
import type { IndexerReader, IndexerRpcConfig } from "@heliuslabs/spr/client";
import {
  bytesKey,
  equalBytes,
  fetchSplAssetRegistrations,
  createIndexerRpcConfig,
  isCanonicalField,
  ZERO_NULLIFIER_PK,
  type CheckpointStream,
  type SyncCheckpointAdvances,
} from "@heliuslabs/spr/internal";
import { confidentialSlotTag } from "../crypto/derivation/ring-stream.js";
import type { Bytes32, RequestContext } from "@heliuslabs/spr/interface";
import type { ShieldedAddress, X25519PublicKey } from "@heliuslabs/spr/keypair";
import {
  decryptTransactions,
  Wallet,
  type AssetRegistry,
  type IndexedShieldedTransaction,
  type ShieldedKeys,
  type WalletUtxo,
} from "@heliuslabs/spr/transaction";

import { ringBodyOutput, readRingOutput, RingScheme } from "../protocol/transaction/output.js";
import { openRecipientNote } from "../crypto/derivation/blinding.js";
import { openOutputSlot } from "../crypto/audit/ring-disclosure.js";
import { spendingTransactions } from "../operations/workflow/recover.js";
import { outputTreeId } from "../protocol/membership/trees.js";
import { isRingKeys, type RingKeys, type RingTagFrame } from "./ring-keys.js";
import { isSmallOrder } from "../crypto/keys/x25519.js";
import { answered, decoded, exactlyOne, unseen } from "./batch.js";
import { zeroKeyNullifier } from "./exposed-notes.js";
import { openZeroKeyMerges } from "./zero-key-merge.js";
import { HalvingPageLimit, nextHistoryToken } from "../rpc/history.js";
import { isPendingNote } from "./ring-wallet.js";
import type { AnonymousWallet } from "./anonymous-wallet.js";
import type { ViewingHistory } from "./viewing-history.js";
import { RingError } from "../protocol/error.js";

export interface RingNotes {
  readonly utxos: readonly WalletUtxo[];
  /** Notes sent to a held key under a mint the registry lacks, a transfer never selects one. */
  readonly pendingOpenings: readonly WalletUtxo[];
}

/** Every note is unspent, a ring body opens only under keys that are also `RingKeys`. */
export async function openRingNotes(
  input: Readonly<{
    keys: ShieldedKeys;
    assets: AssetRegistry;
    transactions: readonly IndexedShieldedTransaction[];
  }>,
  context?: RequestContext,
): Promise<RingNotes> {
  const notes: Note[] = [];
  for (const tx of input.transactions) {
    const { ringProgramId: ring, txViewingPublicKey, salt } = tx;
    if (ring === undefined || txViewingPublicKey === undefined || salt === undefined) continue;
    for (const [slotIndex, slot] of tx.outputSlots.entries()) {
      const site: Site = {
        tx,
        ring,
        txViewingPublicKey,
        salt,
        slotIndex,
        slot,
      };
      const opened = await openSlot(input, site, context);
      if (opened !== undefined) notes.push(opened);
    }
  }
  const keyed = notes.filter(
    ({ nullifierPublicKey }) => !equalBytes(nullifierPublicKey, ZERO_NULLIFIER_PK),
  );
  const derived =
    keyed.length === 0
      ? []
      : await input.keys.derive(
          keyed.map(({ utxo, utxoHash }) => ({
            kind: "nullifier",
            utxoHash,
            blinding: utxo.blinding,
          })),
          context,
        );
  const nullifiers = new Map(answered(keyed, derived));
  const opened = notes.map((note): WalletUtxo => {
    const { utxoHash, slot, nullifierPublicKey: _key, ...fields } = note;
    return Object.freeze({
      ...fields,
      outputContext: Object.freeze({
        hash: utxoHash,
        tree: slot.outputContext.tree,
        leafIndex: slot.outputContext.leafIndex,
      }),
      nullifier: nullifiers.get(note) ?? zeroKeyNullifier(utxoHash, note.utxo.blinding),
      spent: false,
    });
  });
  return Object.freeze({
    utxos: Object.freeze(opened.filter((note) => !isPendingNote(input.assets, note))),
    pendingOpenings: Object.freeze(opened.filter((note) => isPendingNote(input.assets, note))),
  });
}

export type RingSyncInput = Omit<SyncWalletInput, "wallet"> &
  Readonly<{ wallet: AnonymousWallet; client: RingSyncClient }>;

/** Notes, pending notes, tag positions and merge retries commit together after every read succeeds, Rust `RingConfidentialScan::sync`. */
export async function syncRingWallet(
  input: RingSyncInput,
  context?: RequestContext,
): Promise<SyncReport> {
  const { wallet: ring, keys, client } = input;
  const { wallet } = ring;
  return wallet._withSyncLock(async () => {
    const revision = wallet._revision;
    // 1. The core sync resumes from its checkpoints on a copy, nothing reaches the wallet before step 5.
    const staging = wallet._clone();
    const reads = new RingReads(input, staging, context);
    const report = await syncWallet({ ...input, wallet: staging, client: reads.client }, context);
    // 2. Ring outputs publish tags the core sync never reads, each held key resumes at its tag position.
    // Only ring keys open a body, a sync without them leaves every position for one with them.
    const tagged = isRingKeys(keys) ? await reads.tagged(keys, ring.history()) : undefined;
    const rows = tagged?.rows ?? [];
    const opened = await openRingNotes(
      { keys, assets: staging.registry, transactions: rows },
      context,
    );
    const notes = [...opened.utxos, ...opened.pendingOpenings];
    if (isRingKeys(keys))
      notes.push(
        ...(await openZeroKeyMerges({ keys, owner: keys.address(), rows }, context)).map(
          ({ utxo }) => utxo,
        ),
      );
    // 3. One registry refresh per sync, a note the refresh leaves unnamed is stored pending and its position still advances.
    const { solanaRpc, commitment } = client;
    if (
      [...notes, ...ring.pendingOpenings()].some((note) => isPendingNote(staging.registry, note)) &&
      solanaRpc !== undefined &&
      commitment !== undefined
    )
      for (const { assetId, mint } of await fetchSplAssetRegistrations(
        { solanaRpc, commitment },
        context,
      ))
        staging.ensureAsset(assetId, mint);
    // 4. The core sync read the spends of held notes. A note new to the wallet or promoted and a stored retry still need theirs.
    // A merge output under an unregistered mint opens and waits as pending, a TS sync adds no retry and rereads a stored one until the spend row returns.
    const held = new Set(
      [...staging.utxos(), ...ring.pendingOpenings()].map((note) =>
        bytesKey(note.outputContext.hash),
      ),
    );
    const fresh = notes.filter((note) => unseen(held, bytesKey(note.outputContext.hash)));
    const promoted = ring
      .pendingOpenings()
      .filter((note) => !isPendingNote(staging.registry, note));
    const retries = ring._mergeRetries();
    const read = new Set<string>();
    const owner = keys.address();
    const budget = { remaining: Number.MAX_SAFE_INTEGER };
    const chunkSize = input.config?.queryChunk ?? 64;
    let spends = reads.spendRows();
    let unread = [...[...fresh, ...promoted].map((note) => note.nullifier), ...retries];
    for (;;) {
      for (let offset = 0; offset < unread.length; offset += chunkSize)
        spends = [
          ...spends,
          ...(await spendingTransactions(
            reads.client,
            unread.slice(offset, offset + chunkSize),
            budget,
            context,
          )),
        ];
      const merges = spends.filter(
        (row) =>
          isRingMergeRow(row) && unseen(read, `${row.txSignature}:${String(row.eventIndex)}`),
      );
      const merged = await openRingMerges(
        { keys, owner, assets: staging.registry, spends: merges },
        context,
      );
      const next = merged.utxos.filter((note) => unseen(held, bytesKey(note.outputContext.hash)));
      if (next.length === 0) break;
      fresh.push(...next);
      spends = [];
      unread = next.map((note) => note.nullifier);
    }
    // 5. The core rows, the ring notes, the positions and the retries land in one commit.
    const published = new Set(reads.spentNullifiers().map(bytesKey));
    const initial = new Set(wallet.utxos().map((note) => bytesKey(note.outputContext.hash)));
    let storedUtxos = 0;
    ring._absorbConfidential(
      {
        notes: fresh,
        spentNullifiers: reads.spentNullifiers(),
        ...(tagged?.position === undefined ? {} : { tagPosition: tagged.position }),
        retried: retries.filter((nullifier) => published.has(bytesKey(nullifier))),
      },
      staging,
      (commit) => {
        wallet._commitSync(
          {
            ...staging._state(),
            ...commit,
            lastSynced: staging.lastSynced,
            checkpoints: reads.checkpoints(),
            registryAdditions: staging.registry
              .entries()
              .map(([assetId, mint]) => ({ assetId, mint })),
          },
          revision,
        );
        storedUtxos = commit.utxos.filter(
          (note) => !initial.has(bytesKey(note.outputContext.hash)),
        ).length;
      },
    );
    return Object.freeze({ ...report, storedUtxos });
  });
}

export type RingSyncClient = SyncWalletInput["client"] &
  Pick<IndexerReader, "getShieldedTransactionsByNullifiers" | "getShieldedTransactionsByTags">;

interface Site {
  readonly tx: IndexedShieldedTransaction;
  readonly ring: NonNullable<IndexedShieldedTransaction["ringProgramId"]>;
  readonly txViewingPublicKey: X25519PublicKey;
  readonly salt: NonNullable<IndexedShieldedTransaction["salt"]>;
  readonly slotIndex: number;
  readonly slot: IndexedShieldedTransaction["outputSlots"][number];
}

type Note = Readonly<{
  utxo: WalletUtxo["utxo"];
  /** The registered key or the zero key, whichever rebuilt. */
  nullifierPublicKey: Bytes32;
  dataHash?: Bytes32;
  ringDataHash?: Bytes32;
  utxoHash: Bytes32;
  slot: Site["slot"];
}>;

/** The ring merges among `spends` and the notes they open to `owner`, Rust `RingMerges`. */
/** A merge publishes no transaction key or salt. */
export function isRingMergeRow(tx: IndexedShieldedTransaction): boolean {
  return (
    tx.ringProgramId !== undefined &&
    !tx.proofless &&
    tx.txViewingPublicKey === undefined &&
    tx.salt === undefined
  );
}

export async function openRingMerges(
  input: Readonly<{
    keys: ShieldedKeys;
    owner: ShieldedAddress;
    assets: AssetRegistry;
    spends: readonly IndexedShieldedTransaction[];
  }>,
  context: RequestContext | undefined,
): Promise<
  Readonly<{
    merges: readonly IndexedShieldedTransaction[];
    utxos: readonly WalletUtxo[];
  }>
> {
  const merges = input.spends.filter(isRingMergeRow);
  if (merges.length === 0) return { merges, utxos: [] };
  const opened = new Wallet({ identity: input.owner, registry: input.assets });
  await decryptTransactions({
    wallet: opened,
    keys: input.keys,
    transactions: merges,
    context,
  });
  return { merges, utxos: opened._state().utxos };
}

/** `undefined` for a slot sent to no held key. */
async function openSlot(
  input: Readonly<{ keys: ShieldedKeys; assets: AssetRegistry }>,
  site: Site,
  context: RequestContext | undefined,
): Promise<Note | undefined> {
  let frame: ReturnType<typeof readRingOutput>;
  try {
    frame = readRingOutput(site.slot.payload);
  } catch {
    return undefined;
  }
  if (frame.encoding !== "encrypted") return undefined;
  if (!isRingKeys(input.keys)) return undefined;
  const reads = { keys: input.keys, assets: input.assets };
  return frame.scheme === RingScheme.ringBody ? recipientNote(reads, site, context) : undefined;
}

/** The record names its mint, a commitment under the wallet's key or zero proves the note. */
async function recipientNote(
  input: Readonly<{ keys: RingKeys; assets: AssetRegistry }>,
  site: Site,
  context: RequestContext | undefined,
): Promise<Note | undefined> {
  const parts = ringBodyOutput(site.slot.payload);
  if (parts === undefined) return undefined;
  const slotSecret = await heldSlotSecret(input.keys, site, context);
  if (slotSecret === undefined) return undefined;
  const owner = input.keys.address();
  try {
    const note = decoded(() =>
      openRecipientNote(
        {
          owner,
          ring: site.ring,
          treeId: outputTreeId(site.slot.outputContext),
          commitment: site.slot.outputContext.hash,
          assets: input.assets,
        },
        openOutputSlot(slotSecret, parts.body),
      ),
    );
    if (note === undefined) return undefined;
    const { registered: _registered, ...opened } = note;
    return Object.freeze({ ...opened, slot: site.slot });
  } finally {
    slotSecret.fill(0);
  }
}

/** Malformed published bytes skip the slot, a holder failure refuses the sync. */
async function heldSlotSecret(
  keys: RingKeys,
  site: Site,
  context: RequestContext | undefined,
): Promise<Bytes32 | undefined> {
  // The holder is asked only under the key whose public tag the slot carries.
  const viewingPublicKey = keys
    .viewingPublicKeys()
    .find((key) => equalBytes(confidentialSlotTag(key.u()), site.slot.viewTag));
  const firstNullifier = site.tx.nullifiers[0];
  if (
    viewingPublicKey === undefined ||
    firstNullifier === undefined ||
    isSmallOrder(site.txViewingPublicKey) ||
    !isCanonicalField(firstNullifier)
  )
    return undefined;
  const frame: RingTagFrame = {
    viewingPublicKey,
    txViewingPublicKey: site.txViewingPublicKey,
    salt: site.salt,
    firstNullifier,
    probes: [{ kind: "confidential", outputIndex: site.slotIndex, tag: site.slot.viewTag }],
  };
  const answers = exactlyOne(await keys.ringTagMatches([frame], context));
  return answered(frame.probes, answers)[0]?.[1];
}

/** The reads one sync makes, the spends they returned and the tag positions they reached. */
class RingReads {
  readonly client: RingSyncClient;
  readonly #staging: Wallet;
  readonly #context: RequestContext | undefined;
  readonly #rpcConfig: IndexerRpcConfig;
  readonly #pageLimit: HalvingPageLimit;
  readonly #spends: IndexedShieldedTransaction[] = [];

  constructor(input: RingSyncInput, staging: Wallet, context: RequestContext | undefined) {
    const { client, config } = input;
    this.#staging = staging;
    this.#context = context;
    this.#rpcConfig = createIndexerRpcConfig(
      config?.retry ?? client.indexerConfig?.poll,
      config?.requireSlot ?? client.indexerConfig?.requireSlot,
    );
    const limit = config?.pageLimit ?? 1_000;
    this.#pageLimit = new HalvingPageLimit(limit);
    this.client = {
      ...(client.solanaRpc === undefined ? {} : { solanaRpc: client.solanaRpc }),
      ...(client.commitment === undefined ? {} : { commitment: client.commitment }),
      ...(client.indexerConfig === undefined ? {} : { indexerConfig: client.indexerConfig }),
      getEncryptedUtxosByTags: (request, rpcConfig, context) =>
        client.getEncryptedUtxosByTags(request, rpcConfig, context),
      getShieldedTransactionsByTags: (request, rpcConfig, context) =>
        client.getShieldedTransactionsByTags(request, rpcConfig, context),
      // Every spend read, the core sync's and the ring's, marks the notes it names.
      getShieldedTransactionsByNullifiers: async (request, rpcConfig, context) => {
        const page = await client.getShieldedTransactionsByNullifiers(
          { limit, ...request },
          rpcConfig ?? this.#rpcConfig,
          context,
        );
        this.#spends.push(...page.data.flatMap((item) => item.events));
        return page;
      },
    };
  }

  /**
   * Each held key's slot tag, deposits and the owner tag above the key's tag position, Rust `read_tags`.
   *
   * Keys at one position share a read, an unread key reads from the first indexed block.
   * The owner tag rides the lowest group, and every read key moves to the lowest terminal slot, so the owner tag's next read leaves no gap.
   */
  async tagged(
    keys: RingKeys,
    history: ViewingHistory,
  ): Promise<
    Readonly<{
      rows: readonly IndexedShieldedTransaction[];
      position?: Readonly<{ keys: readonly X25519PublicKey[]; afterSlot: bigint }>;
    }>
  > {
    // 1. A held key with no entry would read nothing and report nothing missed.
    const held = keys.viewingPublicKeys();
    const groups = new Map<bigint | null, X25519PublicKey[]>();
    for (const key of held) {
      const entry = history.entry(key);
      if (entry === undefined) throw new RingError("RING_HELD_KEY_NOT_IN_HISTORY");
      groups.set(entry.tagPosition, [...(groups.get(entry.tagPosition) ?? []), key]);
    }
    // 2. One read per group and stream, an unread group first.
    const ordered = [...groups].sort(([left], [right]) =>
      left === null ? -1 : right === null ? 1 : left < right ? -1 : left > right ? 1 : 0,
    );
    const ownerTag = keys.address().signingPublicKey.ownerProofInputHash();
    const rows: IndexedShieldedTransaction[] = [];
    let covered: bigint | undefined;
    for (const [at, [position, members]] of ordered.entries()) {
      const slotTags = members.map((key) => confidentialSlotTag(key.u()));
      const reached = [
        await this.#read(
          "transactions",
          [...slotTags, ...(at === 0 ? [ownerTag] : [])],
          position,
          rows,
        ),
        await this.#read(
          "proofless",
          members.map((key) => key.u()),
          position,
          rows,
        ),
      ];
      for (const slot of reached)
        covered = covered === undefined || slot < covered ? slot : covered;
    }
    return covered === undefined
      ? { rows }
      : { rows, position: { keys: held, afterSlot: covered } };
  }

  /** Every row a spend read returned so far. */
  spendRows(): readonly IndexedShieldedTransaction[] {
    return [...this.#spends];
  }

  spentNullifiers(): readonly Bytes32[] {
    return this.#spends.flatMap((transaction) => transaction.nullifiers);
  }

  checkpoints(): SyncCheckpointAdvances {
    const staged = (stream: CheckpointStream) => new Map(this.#staging._checkpointEntries(stream));
    return {
      transactions: staged("transactions"),
      proofless: staged("proofless"),
      nullifiers: staged("nullifiers"),
    };
  }

  /** Every row of `tags` above `after`, the terminal page's snapshot slot covers every match at or below it. */
  async #read(
    stream: "transactions" | "proofless",
    tags: readonly Bytes32[],
    after: bigint | null,
    rows: IndexedShieldedTransaction[],
  ): Promise<bigint> {
    let token: string | undefined;
    for (;;) {
      const asked = {
        tags,
        ...(after === null ? {} : { filters: { slot: { gt: after } } }),
        ...(token === undefined ? {} : { paginationToken: token }),
      };
      const page =
        stream === "transactions"
          ? await this.#pageLimit.read(async (limit) => {
              const read = await this.client.getShieldedTransactionsByTags(
                { ...asked, limit },
                this.#rpcConfig,
                this.#context,
              );
              rows.push(...read.data.flatMap((item) => item.events));
              return read;
            })
          : await this.#pageLimit.read(async (limit) => {
              const read = await this.client.getEncryptedUtxosByTags(
                { ...asked, limit },
                this.#rpcConfig,
                this.#context,
              );
              rows.push(...prooflessRows(read));
              return read;
            });
      const next = nextHistoryToken(token, page);
      if (next === undefined) return page.context.slot;
      token = next;
    }
  }
}

/** A match carrying a transaction key or salt is a transfer slot, not a deposit. */
function prooflessRows(
  page: Awaited<ReturnType<RingSyncClient["getEncryptedUtxosByTags"]>>,
): readonly IndexedShieldedTransaction[] {
  return page.data
    .flatMap((item) => item.outputs)
    .filter((match) => match.txViewingPk === undefined && match.salt === undefined)
    .map((match) => ({
      slot: match.slot,
      txSignature: match.txSignature,
      outputSlots: [match.outputSlot],
      messages: [],
      nullifiers: [],
      proofless: true,
    }));
}
