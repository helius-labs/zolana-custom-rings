/**
 * Anonymous ring sync, spec First Time Sync Wallet, every stream resumed from its scan watermark,
 * Rust `zolana_ring_client::anonymous`.
 */
import { getBase58Encoder, type ReadonlyUint8Array } from "@solana/kit";

import { ClientError, type IndexerReader, type IndexerRpcConfig } from "@heliuslabs/zolana/client";
import { bytesKey, equalBytes, isCanonicalField, PAGE_LIMIT } from "@heliuslabs/zolana/internal";
import type { Address, Bytes16, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import {
  X25519PublicKey,
  type SharedViewTags,
  type ShieldedAddress,
  type ShieldedPublicKey,
  type ViewingKey,
  type ViewTag,
} from "@heliuslabs/zolana/keypair";
import {
  type AssetRegistry,
  type DepositPayloadDecoder,
  type IndexedShieldedTransaction,
  type OutputSlot,
  type ShieldedKeys,
  type Utxo,
  type WalletUtxo,
} from "@heliuslabs/zolana/transaction";

import { isSmallOrder } from "../crypto/keys/x25519.js";
import {
  isDummyRecipient,
  listedRecipients,
  openRecipient,
  rebuilds,
  senderChange,
  type AnonymousOutput,
} from "../protocol/codec/anonymous-body.js";
import {
  decodeAnonymousRecipient,
  decodeAnonymousSender,
  type AnonymousRecipientPlaintext,
} from "../protocol/codec/anonymous-plaintext.js";
import { customRingDepositPayload } from "../protocol/transaction/deposit-payload.js";
import {
  anonymousRecipientOutputBody,
  anonymousSenderOutputBody,
} from "../protocol/transaction/output.js";
import { answered, unseen } from "./batch.js";
import { decoded, openRingDeposit, type RingDepositNote } from "./ring-deposit.js";
import { registeredMint } from "../operations/workflow/recover.js";
import { openRingMerges } from "./ring-sync.js";
import type { RingKeys, SharedTagPair } from "./ring-keys.js";
import { RingError } from "../protocol/error.js";
import {
  GapScan,
  type EntryStream,
  type ViewingHistory,
  type ViewingKeyEntry,
  viewTagStream,
} from "./viewing-history.js";

/** The indexer's cap on the tags or nullifiers one request names. */
export const TAGS_PER_REQUEST = Number(PAGE_LIMIT);

/** How a sync found a note. */
export type AnonymousStream =
  /** A change output or a deposit under `senderViewTag(index)`. */
  | Readonly<{ kind: "sender"; index: bigint }>
  | Readonly<{ kind: "request"; index: bigint }>
  | Readonly<{ kind: "bootstrap" }>
  /** Under `recipientSharedViewTag(sender, index)`. */
  | Readonly<{ kind: "shared"; sender: X25519PublicKey; index: bigint }>
  | Readonly<{ kind: "merge"; firstNullifier: Bytes32 }>;

export interface AnonymousRingUtxo {
  readonly utxoHash: Bytes32;
  readonly viewingPublicKey: X25519PublicKey;
  readonly stream: AnonymousStream;
}

export type SentCheck =
  /** A held recipient address rebuilt the published hash under `mint`. */
  | Readonly<{ kind: "verified"; mint: Address }>
  /** No held address names the owner and viewing key, or the body rebuilds no hash. */
  | Readonly<{ kind: "unverified" }>;

/** One payment the wallet's sender bundle lists, its body opened with the transaction key. */
export interface SentPayment {
  readonly txSignature: IndexedShieldedTransaction["txSignature"];
  readonly utxoHash: Bytes32;
  readonly position: number;
  readonly recipientViewingPublicKey: X25519PublicKey;
  readonly ownerPublicKey: ShieldedPublicKey;
  readonly amount: bigint;
  readonly check: SentCheck;
}

export interface AnonymousScan {
  /** Counters, watermarks and counterparties raised to what the indexer holds, never lowered. */
  readonly history: ViewingHistory;
  /** The notes found past each watermark, spent once a fetched transaction spends them. */
  readonly utxos: readonly WalletUtxo[];
  readonly spentNullifiers: readonly Bytes32[];
  readonly found: readonly AnonymousRingUtxo[];
  /** The output hash of each body that decoded as the wallet's but did not rebuild. */
  readonly unmatched: readonly Bytes32[];
  /** The wallet's payments in the transfers whose change it found, a body that fails to open left out. */
  readonly sent: readonly SentPayment[];
  /** Deposit mints missing from the asset registry, their notes left out until registered. */
  readonly unknownMints: readonly Address[];
}

export type AnonymousSyncClient = Pick<
  IndexerReader,
  | "getShieldedTransactionsByTags"
  | "getEncryptedUtxosByTags"
  | "getShieldedTransactionsByNullifiers"
>;

type SyncKeys = ShieldedKeys & RingKeys;

interface SyncFields {
  readonly keys: SyncKeys;
  readonly assets: AssetRegistry;
  readonly config: IndexerRpcConfig | undefined;
  readonly depositPayload: DepositPayloadDecoder;
  readonly fullRescan: boolean;
  readonly held: readonly WalletUtxo[];
  readonly recipients: readonly ShieldedAddress[];
}

/** Reads every anonymous stream of each held viewing key, each tag derived by `keys`, Rust `AnonymousSync`. */
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
      depositPayload: customRingDepositPayload,
      fullRescan: false,
      held: [],
      recipients: [],
    });
  }

  withIndexerConfig(config: IndexerRpcConfig): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, config });
  }

  /** A framing of the deposit ciphertexts other than the audit capsule. */
  withDepositPayload(depositPayload: DepositPayloadDecoder): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, depositPayload });
  }

  /** Every stream from index 0, for a wallet that keeps no notes between syncs. */
  withFullRescan(): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, fullRescan: true });
  }

  /** Notes found by earlier syncs, a merge spending them is found from their nullifiers. */
  withHeldNotes(held: readonly WalletUtxo[]): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, held: Object.freeze([...held]) });
  }

  /** The recipients' addresses the wallet holds, a sent payment verifies only against one. */
  withRecipientAddresses(recipients: readonly ShieldedAddress[]): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, recipients: Object.freeze([...recipients]) });
  }

  /** An entry whose key the holder lacks stays as stored. */
  async fetch(
    client: AnonymousSyncClient,
    history: ViewingHistory,
    context?: RequestContext,
  ): Promise<AnonymousScan> {
    const held = this.#fields.keys.viewingPublicKeys();
    const scan = new Scan(this.#fields, client, history, context);
    for (const [index, entry] of history.entries.entries())
      if (held.some((key) => key.equals(entry.viewingPublicKey))) await scan.entry(index);
    await scan.merges();
    return scan.result();
  }
}

class TagWindow<T> {
  readonly #byTag = new Map<string, T>();
  readonly tags: readonly ViewTag[];

  constructor(tags: readonly (readonly [T, ViewTag])[]) {
    for (const [index, tag] of tags) this.#byTag.set(bytesKey(tag), index);
    this.tags = tags.map(([, tag]) => tag);
  }

  indexOf(tag: Bytes32): T | undefined {
    return this.#byTag.get(bytesKey(tag));
  }
}

type StreamSource =
  | Readonly<{ stream: "tx" | "request"; shared?: undefined }>
  | Readonly<{ stream: SharedTagPair; shared: SharedViewTags }>;

type ActiveStream = StreamSource & { readonly scan: GapScan };

type RoundTag = Readonly<{ kind: "bootstrap" }> | Readonly<{ slot: number; index: bigint }>;

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

interface Hit {
  readonly tx: IndexedShieldedTransaction;
  readonly site: Site;
  readonly found: AnonymousStream | undefined;
}

/** A scheme 1 or 2 body the entry's key may open. */
interface Body {
  readonly tx: IndexedShieldedTransaction;
  readonly site: Site;
  readonly ciphertext: Uint8Array;
  readonly context: SlotContext;
  readonly found: AnonymousStream;
}

/** A note whose rebuilt hash matched, before its nullifier. */
interface Found extends RingDepositNote {
  readonly outputContext: WalletUtxo["outputContext"];
  readonly order: Publication;
}

/** Where a note was published, the order a scan returns its notes in. */
interface Publication {
  readonly slot: bigint;
  readonly signature: ReadonlyUint8Array;
  readonly position: number;
}

type Deposit = Readonly<{
  slot: bigint;
  txSignature: IndexedShieldedTransaction["txSignature"];
  outputSlot: OutputSlot;
}>;

interface Decrypted {
  readonly utxo: WalletUtxo;
  readonly order: Publication;
}

class Scan {
  readonly #sync: SyncFields;
  readonly #client: AnonymousSyncClient;
  readonly #context: RequestContext | undefined;
  readonly #address: ShieldedAddress;
  #history: ViewingHistory;
  #found: Found[] = [];
  readonly #decrypted: Decrypted[] = [];
  readonly #streams: AnonymousRingUtxo[] = [];
  /** Sites already read, a body under two tags opens once. */
  readonly #opened = new Set<string>();
  readonly #spends = new Set<string>();
  readonly #spent = new Map<string, Bytes32>();
  readonly #unmatched: Bytes32[] = [];
  readonly #sent: SentPayment[] = [];
  readonly #unknownMints = new Set<Address>();

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
    this.#history = history;
  }

  /** All streams share each round's reads, a counterparty learned in a round joins the next. */
  async entry(index: number): Promise<void> {
    const viewingPublicKey = this.#entry(index).viewingPublicKey;
    const started = new Set<string>();
    const opened: SharedViewTags[] = [];
    let active: ActiveStream[] = [];
    let bootstrap: ViewTag | undefined = viewingPublicKey.u();
    try {
      for (;;) {
        const fresh = await this.#startStreams(index, started);
        for (const { shared } of fresh) if (shared !== undefined) opened.push(shared);
        active = [...active, ...fresh];
        if (active.length === 0) return;
        const tagged: (readonly [RoundTag, ViewTag])[] =
          bootstrap === undefined ? [] : [[BOOTSTRAP_TAG, bootstrap]];
        bootstrap = undefined;
        for (const [slot, source] of active.entries()) {
          const indices = source.scan.round();
          const tags = await this.#tags(viewingPublicKey, source, indices);
          for (const [at, tag] of answered(indices, tags)) tagged.push([{ slot, index: at }, tag]);
        }
        const round = active;
        const seen = await this.#window(index, new TagWindow(tagged), (tag) => {
          if (!("slot" in tag)) return BOOTSTRAP;
          const stream = round[tag.slot]?.stream;
          return stream === undefined ? undefined : foundIn(stream, tag.index);
        });
        active = round.filter(({ stream, scan }, slot) => {
          const found = [...seen].flatMap((tag) =>
            "slot" in tag && tag.slot === slot ? [tag.index] : [],
          );
          if (scan.advance(found)) return true;
          const current = this.#entry(index);
          const counter = current.counter(stream);
          if (counter !== undefined)
            this.#withEntry(index, current.withCounter(stream, scan.finish(counter)));
          return false;
        });
      }
    } finally {
      for (const shared of opened) shared.destroy();
    }
  }

  /** The spends of every found or held ring note, round after round, open the ring merges among them. */
  async merges(): Promise<void> {
    const queried = new Set<string>();
    const held = this.#sync.held
      .filter((utxo) => utxo.utxo.ringProgramId !== undefined)
      .map((utxo) => utxo.nullifier);
    for (;;) {
      await this.#assignNullifiers();
      const frontier = [
        ...this.#decrypted
          .filter(({ utxo }) => utxo.utxo.ringProgramId !== undefined)
          .map(({ utxo }) => utxo.nullifier),
        ...held,
      ].filter((nullifier) => unseen(queried, bytesKey(nullifier)));
      if (frontier.length === 0) return;
      const spends = await this.#paged(frontier, (nullifiers, cursor) =>
        this.#client
          .getShieldedTransactionsByNullifiers(
            { nullifiers, ...cursor, limit: TAGS_PER_REQUEST },
            this.#sync.config,
            this.#context,
          )
          .then((page) => ({ ...page, items: page.transactions })),
      );
      this.#noteSpends(spends);
      const { merges, utxos } = await openRingMerges(
        { keys: this.#sync.keys, owner: this.#address, assets: this.#sync.assets, spends },
        this.#context,
      );
      for (const merge of merges) {
        const firstNullifier = merge.nullifiers[0];
        if (firstNullifier === undefined) continue;
        for (const [position, slot] of merge.outputSlots.entries()) {
          const hash = slot.outputContext.hash;
          const utxo = utxos.find((entry) => equalBytes(entry.outputContext.hash, hash));
          if (utxo === undefined || this.#held(hash)) continue;
          this.#keep(
            {
              utxo: utxo.utxo,
              outputContext: utxo.outputContext,
              order: publication(merge, position),
            },
            this.#address.viewingPublicKey,
            Object.freeze({ kind: "merge", firstNullifier }),
          );
        }
      }
    }
  }

  async result(): Promise<AnonymousScan> {
    await this.#assignNullifiers();
    return Object.freeze({
      history: this.#history,
      utxos: Object.freeze(
        this.#decrypted.map(({ utxo }) =>
          Object.freeze({ ...utxo, spent: this.#spent.has(bytesKey(utxo.nullifier)) }),
        ),
      ),
      spentNullifiers: Object.freeze([...this.#spent.values()]),
      found: Object.freeze([...this.#streams]),
      unmatched: Object.freeze([...this.#unmatched]),
      sent: Object.freeze([...this.#sent]),
      unknownMints: Object.freeze([...this.#unknownMints]),
    });
  }

  /** Every new pair's ECDH in one request. */
  async #startStreams(index: number, started: Set<string>): Promise<readonly ActiveStream[]> {
    const entry = this.#entry(index);
    const fresh = (stream: EntryStream): boolean => unseen(started, streamKey(stream));
    const pairs = [
      ...entry.knownSenders().map((known) => pairOf("fromSender", known.key)),
      ...entry.knownRecipients().map((known) => pairOf("toRecipient", known.key)),
    ].filter(fresh);
    const derived =
      pairs.length === 0
        ? []
        : await this.#sync.keys.sharedViewTags(
            pairs.map((pair) => ({ viewingPublicKey: entry.viewingPublicKey, pair })),
            this.#context,
          );
    let shared: readonly (readonly [(typeof pairs)[number], SharedViewTags])[];
    try {
      shared = answered(pairs, derived);
    } catch (error) {
      for (const tags of derived) tags.destroy();
      throw error;
    }
    const sources: readonly StreamSource[] = [
      ...(["tx", "request"] as const).filter(fresh).map((stream) => ({ stream })),
      ...shared.map(([stream, tags]) => ({ stream, shared: tags })),
    ];
    return sources.flatMap((source) => {
      const counter = entry.counter(source.stream);
      if (counter === undefined) return [];
      const from = this.#sync.fullRescan ? 0n : counter.scanned;
      return [{ ...source, scan: new GapScan(from, counter) }];
    });
  }

  async #tags(
    viewingPublicKey: X25519PublicKey,
    source: StreamSource,
    counters: readonly bigint[],
  ): Promise<readonly ViewTag[]> {
    if (source.shared !== undefined) {
      const { shared } = source;
      return counters.map((at) => shared.tag(at));
    }
    const requests = counters.map((at) => ({
      viewingPublicKey,
      stream: viewTagStream(source.stream, at),
    }));
    return answered(requests, await this.#sync.keys.viewTags(requests, this.#context)).map(
      ([, tag]) => tag,
    );
  }

  /** Opens every output under a tag of `window`, the tags any output holds. */
  async #window<T>(
    index: number,
    window: TagWindow<T>,
    found: (at: T) => AnonymousStream | undefined,
  ): Promise<ReadonlySet<T>> {
    const transactions = await this.#transactions(window.tags);
    const deposits = await this.#deposits(window.tags);
    const observed = new Set<T>();
    const hits: Hit[] = [];
    for (const tx of transactions) {
      const sites: (readonly [Site, Bytes32])[] = [
        ...tx.outputSlots.map(
          (slot, position) => [{ kind: "output", position }, slot.viewTag] as const,
        ),
        ...tx.messages.map(
          (message, index) => [{ kind: "message", message: index }, message.viewTag] as const,
        ),
      ];
      for (const [site, tag] of sites) {
        const at = window.indexOf(tag);
        if (at === undefined) continue;
        observed.add(at);
        hits.push({ tx, site, found: found(at) });
      }
    }
    this.#noteSpends(transactions);
    await this.#open(index, hits);
    for (const deposit of deposits) {
      const at = window.indexOf(deposit.outputSlot.viewTag);
      if (at === undefined) continue;
      observed.add(at);
      const stream = found(at);
      if (stream !== undefined) await this.#openDeposit(index, deposit, stream);
    }
    return observed;
  }

  /** Decrypts every scheme 1 and 2 body of `hits` under its slot index in one request. */
  async #open(index: number, hits: readonly Hit[]): Promise<void> {
    const viewingPublicKey = this.#entry(index).viewingPublicKey;
    const bodies: Body[] = [];
    for (const { tx, site, found } of hits) {
      if (found === undefined) continue;
      if (!unseen(this.#opened, `${txKey(tx)}:${site.kind}:${siteIndex(site)}`)) continue;
      const context = slotContext(tx);
      const ciphertext = siteBody(tx, site);
      if (context === undefined || ciphertext === undefined) continue;
      bodies.push({ tx, site, ciphertext, context, found });
    }
    if (bodies.length === 0) return;
    const opened = answered(
      bodies,
      await this.#sync.keys.decrypt(
        bodies.map((body) => ({
          ciphertext: body.ciphertext,
          viewingPublicKey,
          txViewingPublicKey: body.context.txViewingPublicKey,
          salt: body.context.salt,
          slotIndex: slotIndex(body),
          label: "transfer" as const,
        })),
        this.#context,
      ),
    );
    const own = await this.#ownTransactions(viewingPublicKey, bodies);
    try {
      opened.forEach(([body, plaintext]) => {
        try {
          if (body.site.kind === "output")
            this.#openRecipient(index, body, body.site.position, plaintext);
          else
            this.#openBundle(
              index,
              body,
              plaintext,
              own.get(bytesKey(body.context.firstNullifier)),
            );
        } finally {
          plaintext.fill(0);
        }
      });
    } finally {
      for (const txViewingKey of own.values()) txViewingKey.destroy();
    }
  }

  /** The transaction key of each transaction the entry's key sent, keyed by its first nullifier. */
  async #ownTransactions(
    viewingPublicKey: X25519PublicKey,
    bodies: readonly Body[],
  ): Promise<ReadonlyMap<string, ViewingKey>> {
    const contexts = new Map<string, SlotContext>();
    for (const body of bodies)
      if (body.site.kind === "message")
        contexts.set(bytesKey(body.context.firstNullifier), body.context);
    if (contexts.size === 0) return new Map();
    const held = [...contexts.values()];
    const keys = answered(
      held,
      await this.#sync.keys.transactionKeys(
        held.map((context) => ({ viewingPublicKey, firstNullifier: context.firstNullifier })),
        this.#context,
      ),
    );
    const own = new Map<string, ViewingKey>();
    keys.forEach(([context, txViewingKey]) => {
      // Another viewing key sent the transaction.
      if (!txViewingKey.publicKey().equals(context.txViewingPublicKey)) {
        txViewingKey.destroy();
        return;
      }
      own.set(bytesKey(context.firstNullifier), txViewingKey);
    });
    return own;
  }

  /** A body that rebuilds no hash is unmatched, one that fails to decode or names another owner skipped. */
  #openRecipient(index: number, body: Body, position: number, plaintext: Uint8Array): void {
    const note = decoded(() => decodeAnonymousRecipient(plaintext));
    if (note === undefined) return;
    if (!note.verified.ownerPublicKey.equals(this.#address.signingPublicKey)) return;
    const output = this.#output(body, this.#address, position);
    const utxo = output === undefined ? undefined : decoded(() => openRecipient(output, note));
    if (utxo === undefined) {
      this.#unmatch(body, position);
      return;
    }
    this.#accept(index, body, position, utxo);
    this.#learn(index, pairOf("fromSender", note.unverified.senderPublicKey));
  }

  /** Each change output the bundle rebuilds, the change leading at output 0. */
  #openBundle(
    index: number,
    body: Body,
    plaintext: Uint8Array,
    txViewingKey: ViewingKey | undefined,
  ): void {
    const bundle = decoded(() => decodeAnonymousSender(plaintext));
    if (bundle === undefined) return;
    if (!bundle.verified.ownerPublicKey.equals(this.#address.signingPublicKey)) return;
    const outputs = body.tx.outputSlots.length;
    if (outputs === 0) return;
    const { firstNullifier, ring } = body.context;
    const change = decoded(() =>
      senderChange({ assets: this.#sync.assets, ring }, bundle, firstNullifier),
    );
    if (change === undefined) {
      this.#unmatch(body, 0);
      return;
    }
    change.slice(0, outputs).forEach((utxo, position) => {
      const output = this.#output(body, this.#address, position);
      if (output !== undefined && rebuilds(output, utxo)) this.#accept(index, body, position, utxo);
      else this.#unmatch(body, position);
    });
    // Only the wallet's own transaction key proves the listed payments its own.
    if (txViewingKey === undefined) return;
    this.#recordSent(body, bundle.verified.recipientViewingPublicKeys, txViewingKey);
    for (const recipient of listedRecipients(bundle))
      this.#learn(index, pairOf("toRecipient", recipient));
  }

  /** The bundle lists one key per output after the change, in output order. */
  #recordSent(body: Body, listed: readonly X25519PublicKey[], txViewingKey: ViewingKey): void {
    const first = body.tx.outputSlots.length - listed.length;
    if (first < 0) return;
    listed.forEach((recipient, offset) => {
      if (isDummyRecipient(recipient) || isSmallOrder(recipient)) return;
      const sent = this.#sentPayment(body, first + offset, recipient, txViewingKey);
      if (sent !== undefined) this.#sent.push(sent);
    });
  }

  /** `undefined` when the body at `position` fails to open under the recipient's key. */
  #sentPayment(
    body: Body,
    position: number,
    recipient: X25519PublicKey,
    txViewingKey: ViewingKey,
  ): SentPayment | undefined {
    const slot = body.tx.outputSlots[position];
    const sealed = slot === undefined ? undefined : anonymousRecipientOutputBody(slot.payload);
    if (slot === undefined || sealed === undefined) return undefined;
    let note: AnonymousRecipientPlaintext | undefined;
    let plaintext: Uint8Array | undefined;
    try {
      plaintext = txViewingKey.decryptSlotEphemeral(recipient, sealed, body.context.salt, position);
      note = decodeAnonymousRecipient(plaintext);
    } catch {
      return undefined;
    } finally {
      plaintext?.fill(0);
    }
    const opened = note;
    const { ownerPublicKey, amount } = opened.verified;
    const verified = this.#sync.recipients
      .filter(
        (address) =>
          address.viewingPublicKey.equals(recipient) &&
          address.signingPublicKey.equals(ownerPublicKey),
      )
      .map((address) => {
        const output = this.#output(body, address, position);
        return output === undefined ? undefined : decoded(() => openRecipient(output, opened));
      })
      .find((utxo): utxo is Utxo => utxo !== undefined);
    return Object.freeze({
      txSignature: body.tx.txSignature,
      utxoHash: slot.outputContext.hash,
      position,
      recipientViewingPublicKey: recipient,
      ownerPublicKey,
      amount,
      check: Object.freeze(
        verified === undefined
          ? { kind: "unverified" as const }
          : { kind: "verified" as const, mint: verified.asset },
      ),
    });
  }

  /** `undefined` for a slot the indexer reported without its tree id, it rebuilds nothing. */
  #output(body: Body, owner: ShieldedAddress, position: number): AnonymousOutput | undefined {
    const context = body.tx.outputSlots[position]?.outputContext;
    if (context?.treeId === undefined) return undefined;
    return {
      owner,
      assets: this.#sync.assets,
      ring: body.context.ring,
      treeId: context.treeId,
      utxoHash: context.hash,
    };
  }

  /** A key no ECDH accepts never enters the map. */
  #learn(index: number, pair: SharedTagPair): void {
    if (isSmallOrder(pair.counterparty)) return;
    this.#withEntry(index, this.#entry(index).learn(pair));
  }

  /** Keeps a rebuilt note once, under the stream that found it. */
  #accept(index: number, body: Body, position: number, utxo: Utxo): void {
    const slot = body.tx.outputSlots[position];
    if (slot === undefined || this.#isFound(slot.outputContext.hash)) return;
    this.#keep(
      { utxo, outputContext: walletContext(slot), order: publication(body.tx, position) },
      this.#entry(index).viewingPublicKey,
      body.found,
    );
  }

  #unmatch(body: Body, position: number): void {
    const slot = body.tx.outputSlots[position];
    if (slot !== undefined) this.#unmatched.push(slot.outputContext.hash);
  }

  async #openDeposit(index: number, deposit: Deposit, found: AnonymousStream): Promise<void> {
    const slot = deposit.outputSlot;
    if (this.#isFound(slot.outputContext.hash)) return;
    const entry = this.#entry(index);
    const opened = await openRingDeposit(
      {
        keys: this.#sync.keys,
        owner: this.#address,
        viewingPublicKey: entry.viewingPublicKey,
        outputSlot: slot,
        depositPayload: this.#sync.depositPayload,
      },
      this.#context,
    );
    if (opened === undefined) return;
    if (registeredMint(this.#sync.assets, opened.utxo.asset) === undefined) {
      this.#unknownMints.add(opened.utxo.asset);
      return;
    }
    this.#keep(
      {
        ...opened,
        outputContext: walletContext(slot),
        order: { slot: deposit.slot, signature: base58.encode(deposit.txSignature), position: 0 },
      },
      entry.viewingPublicKey,
      found,
    );
  }

  #keep(note: Found, viewingPublicKey: X25519PublicKey, stream: AnonymousStream): void {
    this.#found.push(note);
    this.#streams.push(
      Object.freeze({ utxoHash: note.outputContext.hash, viewingPublicKey, stream }),
    );
  }

  /** Derives the nullifiers of the found notes in publication order. */
  async #assignNullifiers(): Promise<void> {
    const found = this.#found;
    this.#found = [];
    if (found.length === 0) return;
    const nullifiers = answered(
      found,
      await this.#sync.keys.derive(
        found.map(({ utxo, outputContext }) => ({
          kind: "nullifier" as const,
          utxoHash: outputContext.hash,
          blinding: utxo.blinding,
        })),
        this.#context,
      ),
    );
    for (const [{ order, ...note }, nullifier] of nullifiers)
      this.#decrypted.push({ utxo: Object.freeze({ ...note, nullifier, spent: false }), order });
    this.#decrypted.sort((left, right) => compareOrder(left.order, right.order));
  }

  #noteSpends(transactions: readonly IndexedShieldedTransaction[]): void {
    for (const tx of transactions) {
      if (!unseen(this.#spends, txKey(tx))) continue;
      for (const nullifier of tx.nullifiers) this.#spent.set(bytesKey(nullifier), nullifier);
    }
  }

  #isFound(hash: Bytes32): boolean {
    return this.#found.some((entry) => equalBytes(entry.outputContext.hash, hash));
  }

  /** A note the current sync opened or an earlier one holds. */
  #held(hash: Bytes32): boolean {
    const same = (entry: WalletUtxo) => equalBytes(entry.outputContext.hash, hash);
    return this.#decrypted.some(({ utxo }) => same(utxo)) || this.#sync.held.some(same);
  }

  /** Every transaction published under one of `tags`, each once. */
  async #transactions(tags: readonly ViewTag[]): Promise<readonly IndexedShieldedTransaction[]> {
    const transactions = await this.#paged(tags, (chunk, cursor) =>
      this.#client
        .getShieldedTransactionsByTags(
          { tags: chunk, ...cursor, limit: TAGS_PER_REQUEST },
          this.#sync.config,
          this.#context,
        )
        .then((page) => ({ ...page, items: page.transactions })),
    );
    const seen = new Set<string>();
    return transactions.filter((tx) => unseen(seen, txKey(tx)));
  }

  /** The deposits published under one of `tags`, one per deposited output. */
  #deposits(tags: readonly ViewTag[]): Promise<readonly Deposit[]> {
    return this.#paged(tags, (chunk, cursor) =>
      this.#client
        .getEncryptedUtxosByTags(
          { tags: chunk, ...cursor, limit: TAGS_PER_REQUEST },
          this.#sync.config,
          this.#context,
        )
        .then((page) => ({ ...page, items: page.matches })),
    );
  }

  /** Every page of every chunk, a terminal page names a scan frontier or no next cursor. */
  async #paged<T>(
    queried: readonly Bytes32[],
    fetch: (
      chunk: Bytes32[],
      cursor: Readonly<{ cursor?: Uint8Array }>,
    ) => Promise<
      Readonly<{ items: readonly T[]; nextCursor?: Uint8Array; scannedThrough?: Uint8Array }>
    >,
  ): Promise<readonly T[]> {
    const items: T[] = [];
    for (let start = 0; start < queried.length; start += TAGS_PER_REQUEST) {
      const chunk = queried.slice(start, start + TAGS_PER_REQUEST);
      const followed = new Set<string>();
      let cursor: Uint8Array | undefined;
      for (;;) {
        const page = await fetch(chunk, cursor === undefined ? {} : { cursor });
        items.push(...page.items);
        const next = page.scannedThrough === undefined ? page.nextCursor : undefined;
        if (next === undefined) break;
        if (followed.has(bytesKey(next)))
          throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
            details: { path: "$.nextCursor" },
          });
        followed.add(bytesKey(next));
        cursor = next;
      }
    }
    return items;
  }

  #entry(index: number): ViewingKeyEntry {
    const entry = this.#history.entries[index];
    if (entry === undefined)
      throw new RingError("RING_VIEWING_HISTORY_INVALID", {
        details: { reason: "names no viewing key at the index" },
      });
    return entry;
  }

  #withEntry(index: number, entry: ViewingKeyEntry): void {
    this.#history = this.#history.withEntry(index, entry);
  }
}

const BOOTSTRAP: AnonymousStream = Object.freeze({ kind: "bootstrap" });
const BOOTSTRAP_TAG: RoundTag = BOOTSTRAP;
const base58 = getBase58Encoder();

function pairOf(kind: SharedTagPair["kind"], counterparty: X25519PublicKey): SharedTagPair {
  return Object.freeze({ kind, counterparty });
}

/** A `toRecipient` stream holds the wallet's own payments, observed and never opened. */
function foundIn(stream: EntryStream, index: bigint): AnonymousStream | undefined {
  if (stream === "tx") return Object.freeze({ kind: "sender", index });
  if (stream === "request") return Object.freeze({ kind: "request", index });
  return stream.kind === "fromSender"
    ? Object.freeze({ kind: "shared", sender: stream.counterparty, index })
    : undefined;
}

function txKey(tx: IndexedShieldedTransaction): string {
  return `${tx.txSignature}:${String(tx.eventIndex)}`;
}

function streamKey(stream: EntryStream): string {
  return typeof stream === "string"
    ? stream
    : `${stream.kind}:${bytesKey(stream.counterparty.toBytes())}`;
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

function siteIndex(site: Site): number {
  return site.kind === "output" ? site.position : site.message;
}

function siteBody(tx: IndexedShieldedTransaction, site: Site): Uint8Array | undefined {
  if (site.kind === "output") {
    const slot = tx.outputSlots[site.position];
    return slot === undefined ? undefined : anonymousRecipientOutputBody(slot.payload);
  }
  const message = tx.messages[site.message];
  return message === undefined ? undefined : anonymousSenderOutputBody(message.data);
}

/** Messages follow the outputs. */
function slotIndex(body: Body): number {
  return body.site.kind === "output"
    ? body.site.position
    : body.tx.outputSlots.length + body.site.message;
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
