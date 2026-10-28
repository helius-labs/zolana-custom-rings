/**
 * The anonymous rail's wallet state, spec `ViewingKeyEntry` per retained viewing key, and the spec
 * view tag selection over it, Rust `zolana_ring_client::viewing_history`.
 */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { RequestContext } from "@heliuslabs/zolana";
import { PAGE_LIMIT, U64_MAX } from "@heliuslabs/zolana/internal";
import { X25519PublicKey, type ViewTag } from "@heliuslabs/zolana/keypair";

import { isSmallOrder } from "../crypto/keys/x25519.js";
import type { TaggedPayment } from "../operations/payments/output-rail.js";
import { RingError } from "../protocol/error.js";
import { exactlyOne } from "./batch.js";
import type { RingKeys, SharedTagPair, ViewTagStream } from "./ring-keys.js";

export const VIEWING_HISTORY_VERSION = 7;

/** How far below its watermark a sync still reads an unobserved index. */
export const PENDING_RETENTION = 256n;

/** Indices a stream's first round reads past its next index, doubled up to `PAGE_LIMIT` after every round that finds one. */
export const TAG_GAP = 20n;

/** One tag stream's next index to use and the index its sync resumes from, never above `next`. */
export class StreamCounter {
  readonly next: bigint;
  readonly scanned: bigint;
  /** Ascending, unobserved, below `scanned` by at most `PENDING_RETENTION`. */
  readonly pending: readonly bigint[];

  private constructor(next: bigint, scanned: bigint, pending: readonly bigint[]) {
    this.next = next;
    this.scanned = scanned;
    this.pending = Object.freeze([...pending]);
    Object.freeze(this);
  }

  static readonly EMPTY: StreamCounter = new StreamCounter(0n, 0n, []);

  /** A scan from `from` saw `observed`, an index it passed unseen stays pending. */
  observe(from: bigint, observed: ReadonlySet<bigint>): StreamCounter {
    const highest = [...observed].filter((index) => index >= from).reduce(max, -1n);
    const reached = highest < 0n ? from : saturatingIncrement(highest);
    const scanned = max(this.scanned, reached);
    const floor = retentionFloor(scanned);
    const pending = new Set(this.pending);
    for (let index = max(from, floor); index < reached; index++) pending.add(index);
    return new StreamCounter(
      max(this.next, scanned),
      scanned,
      [...pending].filter((index) => index >= floor && !observed.has(index)).sort(ascending),
    );
  }

  /** The index a new tag takes and the counter past it. */
  takeNext(): Readonly<{ index: bigint; counter: StreamCounter }> {
    if (this.next >= U64_MAX) throw new RingError("RING_COUNTER_OVERFLOW");
    return Object.freeze({
      index: this.next,
      counter: new StreamCounter(this.next + 1n, this.scanned, this.pending),
    });
  }

  /** Refuses a watermark past `next` and a pending index outside its retention window. */
  static restore(stored: Readonly<{ next: bigint; scanned: bigint; pending: readonly bigint[] }>) {
    const { next, scanned, pending } = stored;
    if (scanned > next) throw invalid("a scan watermark passes its next index");
    const floor = retentionFloor(scanned);
    const ascendingOrder = pending.every(
      (index, at) => at === 0 || (pending[at - 1] ?? 0n) < index,
    );
    if (!ascendingOrder || pending.some((index) => index < floor || index >= scanned))
      throw invalid("a pending index repeats or lies outside its retention window");
    return new StreamCounter(next, scanned, pending);
  }
}

export class GapScan {
  readonly #from: bigint;
  #start: bigint;
  #end: bigint;
  #gap = TAG_GAP;
  #late: readonly bigint[];
  readonly #observed = new Set<bigint>();

  constructor(from: bigint, counter: StreamCounter) {
    this.#from = from;
    this.#start = from;
    this.#end = saturatingAdd(max(counter.next, from), TAG_GAP);
    this.#late = counter.pending;
  }

  round(): readonly bigint[] {
    const late = this.#late;
    this.#late = [];
    const length = Number(this.#end - this.#start);
    return [...late, ...Array.from({ length }, (_, offset) => this.#start + BigInt(offset))];
  }

  /** `false` once a round finds nothing in its range. */
  advance(seen: Iterable<bigint>): boolean {
    let found = false;
    for (const at of seen) {
      this.#observed.add(at);
      found ||= at >= this.#start && at < this.#end;
    }
    if (!found) return false;
    this.#gap = min(this.#gap * 2n, PAGE_LIMIT);
    this.#start = this.#end;
    this.#end = saturatingAdd(this.#start, this.#gap);
    return true;
  }

  finish(counter: StreamCounter): StreamCounter {
    return counter.observe(this.#from, this.#observed);
  }
}

export class ViewingKeyEntry {
  readonly viewingPublicKey: X25519PublicKey;
  readonly createdAt: bigint;
  readonly tx: StreamCounter;
  readonly request: StreamCounter;
  /** Keyed by the viewing key a sender's recipient bodies name. */
  readonly #knownSenders: ReadonlyMap<string, Counterparty>;
  readonly #knownRecipients: ReadonlyMap<string, Counterparty>;

  private constructor(fields: EntryFields) {
    this.viewingPublicKey = fields.viewingPublicKey;
    this.createdAt = fields.createdAt;
    this.tx = fields.tx;
    this.request = fields.request;
    this.#knownSenders = new Map(fields.knownSenders);
    this.#knownRecipients = new Map(fields.knownRecipients);
    Object.freeze(this);
  }

  static create(viewingPublicKey: X25519PublicKey, createdAt: bigint): ViewingKeyEntry {
    return new ViewingKeyEntry({
      viewingPublicKey,
      createdAt: checkedI64(createdAt, "createdAt"),
      tx: StreamCounter.EMPTY,
      request: StreamCounter.EMPTY,
      knownSenders: new Map(),
      knownRecipients: new Map(),
    });
  }

  get txCount(): bigint {
    return this.tx.next;
  }

  get requestCount(): bigint {
    return this.request.next;
  }

  knownSenders(): readonly Counterparty[] {
    return [...this.#knownSenders.values()];
  }

  knownRecipients(): readonly Counterparty[] {
    return [...this.#knownRecipients.values()];
  }

  /** `undefined` for an unknown counterparty. */
  counter(stream: EntryStream): StreamCounter | undefined {
    if (stream === "tx" || stream === "request") return this[stream];
    return this.#known(stream.kind).get(keyOf(stream.counterparty))?.counter;
  }

  /** An unknown counterparty keeps the entry as it is. */
  withCounter(stream: EntryStream, counter: StreamCounter): ViewingKeyEntry {
    if (stream === "tx" || stream === "request")
      return new ViewingKeyEntry({ ...this.#fields(), [stream]: counter });
    const known = this.#known(stream.kind);
    const key = keyOf(stream.counterparty);
    if (!known.has(key)) return this;
    const counterparty: Counterparty = Object.freeze({ key: stream.counterparty, counter });
    return this.#withKnown(stream.kind, new Map([...known, [key, counterparty]]));
  }

  /** Refuses a counterparty map naming a key twice or a small-order key. */
  static restore(
    fields: Readonly<{
      viewingPublicKey: X25519PublicKey;
      createdAt: bigint;
      tx: StreamCounter;
      request: StreamCounter;
      knownSenders: readonly Counterparty[];
      knownRecipients: readonly Counterparty[];
    }>,
  ): ViewingKeyEntry {
    const counterparties = (rows: readonly Counterparty[], name: string) => {
      if (rows.some((row) => isSmallOrder(row.key)))
        throw invalid(`${name} holds a small-order key`);
      const known = new Map(rows.map((row) => [keyOf(row.key), Object.freeze({ ...row })]));
      if (known.size !== rows.length) throw invalid(`${name} repeats a key`);
      return known;
    };
    return new ViewingKeyEntry({
      viewingPublicKey: fields.viewingPublicKey,
      createdAt: checkedI64(fields.createdAt, "createdAt"),
      tx: fields.tx,
      request: fields.request,
      knownSenders: counterparties(fields.knownSenders, "knownSenders"),
      knownRecipients: counterparties(fields.knownRecipients, "knownRecipients"),
    });
  }

  /** A known counterparty keeps the entry as it is. */
  learn(pair: SharedTagPair): ViewingKeyEntry {
    const known = this.#known(pair.kind);
    const key = keyOf(pair.counterparty);
    if (known.has(key)) return this;
    const counterparty: Counterparty = { key: pair.counterparty, counter: StreamCounter.EMPTY };
    return this.#withKnown(pair.kind, new Map([...known, [key, counterparty]]));
  }

  /** Shared once known, else the caller's first contact tag. */
  async select(
    keys: RingKeys,
    recipient: PaymentRecipient,
    pairing: FirstContactPairing,
    context: RequestContext | undefined,
  ): Promise<Readonly<{ tag: PaymentTag; entry: ViewingKeyEntry }>> {
    const pair: SharedTagPair = { kind: "toRecipient", counterparty: recipient.viewingPublicKey };
    const counter = this.counter(pair);
    if (counter !== undefined) {
      const { index, counter: advanced } = counter.takeNext();
      const shared = exactlyOne(
        await keys.sharedViewTags([{ viewingPublicKey: this.viewingPublicKey, pair }], context),
      );
      let tag: ViewTag;
      try {
        tag = shared.tag(index);
      } finally {
        shared.destroy();
      }
      return {
        tag: paymentTag(recipient, tag, Object.freeze({ kind: "shared", index })),
        entry: this.withCounter(pair, advanced),
      };
    }
    if (isSmallOrder(recipient.viewingPublicKey))
      throw new RingError("RING_RECIPIENT_KEY_NOT_CONTRIBUTORY");
    const entry = pairing === "pairs" ? this.learn(pair) : this;
    const first = recipient.firstContact;
    const tag =
      first.kind === "request"
        ? paymentTag(recipient, first.tag, Object.freeze({ kind: "request" }))
        : paymentTag(
            recipient,
            recipient.viewingPublicKey.u(),
            Object.freeze({ kind: "bootstrap" }),
          );
    return { tag, entry };
  }

  #known(kind: SharedTagPair["kind"]): ReadonlyMap<string, Counterparty> {
    return kind === "fromSender" ? this.#knownSenders : this.#knownRecipients;
  }

  #withKnown(kind: SharedTagPair["kind"], known: ReadonlyMap<string, Counterparty>) {
    return new ViewingKeyEntry({
      ...this.#fields(),
      ...(kind === "fromSender" ? { knownSenders: known } : { knownRecipients: known }),
    });
  }

  #fields(): EntryFields {
    return {
      viewingPublicKey: this.viewingPublicKey,
      createdAt: this.createdAt,
      tx: this.tx,
      request: this.request,
      knownSenders: this.#knownSenders,
      knownRecipients: this.#knownRecipients,
    };
  }
}

export type Counterparty = Readonly<{ key: X25519PublicKey; counter: StreamCounter }>;

export type EntryStream = "tx" | "request" | SharedTagPair;

/** A first contact pairs only when its body names the sender. */
export type FirstContactPairing = "pairs" | "unpaired";

/** The tag a first payment to a recipient takes, chosen by the caller. */
export type FirstContact =
  /** The tag of a payment request the recipient minted. */
  | Readonly<{ kind: "request"; tag: ViewTag }>
  /** The recipient's `recipientBootstrapViewTag`, readable by anyone who knows its address. */
  | Readonly<{ kind: "bootstrap" }>;

/** A recipient of an anonymous payment, `firstContact` taken until the pair is known. */
export interface PaymentRecipient {
  readonly viewingPublicKey: X25519PublicKey;
  readonly firstContact: FirstContact;
}

/** The spec view tag selection a payment took. */
export type TagSelection =
  | Readonly<{ kind: "shared"; index: bigint }>
  | Readonly<{ kind: "request" }>
  | Readonly<{ kind: "bootstrap" }>;

export interface PaymentTag {
  readonly payment: TaggedPayment;
  readonly selection: TagSelection;
}

/** One transfer's tags, `history` advanced past them and stored before the transfer is sent. */
export interface TransferTags {
  readonly senderTag: ViewTag;
  readonly payments: readonly PaymentTag[];
  readonly history: ViewingHistory;
}

/** A tag for one output, `history` advanced past it. */
export interface AdvancedTag<T> {
  readonly tag: T;
  readonly history: ViewingHistory;
}

/** Every retained viewing key, oldest first, the last one current. */
export class ViewingHistory {
  readonly entries: readonly ViewingKeyEntry[];

  private constructor(entries: readonly ViewingKeyEntry[]) {
    this.entries = Object.freeze([...entries]);
    Object.freeze(this);
  }

  /** A wallet whose one viewing key never paid or was paid. */
  static create(viewingPublicKey: X25519PublicKey, createdAt: bigint): ViewingHistory {
    return new ViewingHistory([ViewingKeyEntry.create(viewingPublicKey, createdAt)]);
  }

  /** The rotated key becomes current, the earlier keys keep reading what was sent to them. */
  withRotatedKey(viewingPublicKey: X25519PublicKey, createdAt: bigint): ViewingHistory {
    if (createdAt <= this.current().createdAt || this.entry(viewingPublicKey) !== undefined)
      throw new RingError("RING_ROTATED_KEY_NOT_NEWER");
    return new ViewingHistory([
      ...this.entries,
      ViewingKeyEntry.create(viewingPublicKey, createdAt),
    ]);
  }

  current(): ViewingKeyEntry {
    const current = this.entries.at(-1);
    // Every constructor and `fromJson` holds at least one entry.
    if (current === undefined) throw invalid("holds no viewing key");
    return current;
  }

  entry(viewingPublicKey: X25519PublicKey): ViewingKeyEntry | undefined {
    return this.entries.find((entry) => entry.viewingPublicKey.equals(viewingPublicKey));
  }

  withEntry(index: number, entry: ViewingKeyEntry): ViewingHistory {
    if (this.entries[index] === undefined) throw invalid("names no viewing key at the index");
    return new ViewingHistory(this.entries.map((held, at) => (at === index ? entry : held)));
  }

  /** The next sender tag of the current key, the tag of a deposit to the wallet's own note. */
  async senderTag(keys: RingKeys, context?: RequestContext): Promise<AdvancedTag<ViewTag>> {
    return this.#ownTag(keys, "tx", context);
  }

  /** A deposit's tag, a first contact pairs nothing since a deposit names no sender. */
  async depositTag(
    keys: RingKeys,
    recipient: PaymentRecipient,
    context?: RequestContext,
  ): Promise<AdvancedTag<PaymentTag>> {
    const { tag, entry } = await this.current().select(keys, recipient, "unpaired", context);
    return Object.freeze({ tag, history: this.#withCurrent(entry) });
  }

  /** A fresh `recipientRequestViewTag` for a payment request. */
  async requestTag(keys: RingKeys, context?: RequestContext): Promise<AdvancedTag<ViewTag>> {
    return this.#ownTag(keys, "request", context);
  }

  /** Its counterparties link the wallet's payments, store it as key material. */
  toJson(): string {
    const counter = (value: StreamCounter): string =>
      `"next":${value.next},"scanned":${value.scanned},"pending":[${value.pending.join(",")}]`;
    const counterparties = (known: readonly Counterparty[]): string =>
      known
        .map(({ key, counter: held }) => ({ pubkey: bytesToHex(key.toBytes()), held }))
        .sort((left, right) =>
          left.pubkey < right.pubkey ? -1 : left.pubkey > right.pubkey ? 1 : 0,
        )
        .map(({ pubkey, held }) => `{"pubkey":"${pubkey}",${counter(held)}}`)
        .join(",");
    const entries = this.entries.map(
      (entry) =>
        `{"viewingPubkey":"${bytesToHex(entry.viewingPublicKey.toBytes())}","createdAt":${entry.createdAt},` +
        `"tx":{${counter(entry.tx)}},"request":{${counter(entry.request)}},` +
        `"knownSenders":[${counterparties(entry.knownSenders())}],` +
        `"knownRecipients":[${counterparties(entry.knownRecipients())}]}`,
    );
    return `{"version":${VIEWING_HISTORY_VERSION},"viewingHistory":[${entries.join(",")}]}`;
  }

  /** Another version fails with `RING_VIEWING_HISTORY_VERSION`, a sync from index 0 rebuilds it. */
  static fromJson(text: string): ViewingHistory {
    const stored = record(parseExact(text), "history");
    const version = stored["version"];
    if (typeof version !== "bigint" || version < 0n || version > 0xffff_ffffn)
      throw invalid("version is not a u32");
    if (version !== BigInt(VIEWING_HISTORY_VERSION))
      throw new RingError("RING_VIEWING_HISTORY_VERSION", {
        details: { version: version.toString() },
      });
    known(stored, "history", ["version", "viewingHistory"]);
    const entries: ViewingKeyEntry[] = [];
    for (const value of list(stored["viewingHistory"], "viewingHistory")) {
      const entry = storedEntry(value);
      const last = entries.at(-1);
      if (
        (last !== undefined && last.createdAt >= entry.createdAt) ||
        entries.some((earlier) => earlier.viewingPublicKey.equals(entry.viewingPublicKey))
      )
        throw invalid("viewing keys repeat or are not oldest first");
      entries.push(entry);
    }
    if (entries.length === 0) throw invalid("holds no viewing key");
    return new ViewingHistory(entries);
  }

  async #ownTag(
    keys: RingKeys,
    stream: "tx" | "request",
    context?: RequestContext,
  ): Promise<AdvancedTag<ViewTag>> {
    const current = this.current();
    const { index, counter } = current[stream].takeNext();
    const tag = exactlyOne(
      await keys.viewTags(
        [{ viewingPublicKey: current.viewingPublicKey, stream: viewTagStream(stream, index) }],
        context,
      ),
    );
    return Object.freeze({ tag, history: this.#withCurrent(current.withCounter(stream, counter)) });
  }

  #withCurrent(entry: ViewingKeyEntry): ViewingHistory {
    return this.withEntry(this.entries.length - 1, entry);
  }
}

/** The tags of a transfer from the current viewing key, payments in declared order. */
export class TransferTagging {
  readonly keys: RingKeys;
  readonly history: ViewingHistory;
  readonly recipients: readonly PaymentRecipient[];

  constructor(
    fields: Readonly<{
      keys: RingKeys;
      history: ViewingHistory;
      recipients: readonly PaymentRecipient[];
    }>,
  ) {
    this.keys = fields.keys;
    this.history = fields.history;
    this.recipients = Object.freeze([...fields.recipients]);
    Object.freeze(this);
  }

  /** The change outputs' sender tag and one tag per recipient, the current key the wallet's. */
  async plan(context?: RequestContext): Promise<TransferTags> {
    if (!this.history.current().viewingPublicKey.equals(this.keys.address().viewingPublicKey))
      throw new RingError("RING_VIEWING_KEY_NOT_CURRENT");
    const { tag: senderTag, history } = await this.history.senderTag(this.keys, context);
    let entry = history.current();
    const payments: PaymentTag[] = [];
    for (const recipient of this.recipients) {
      const selected = await entry.select(this.keys, recipient, "pairs", context);
      payments.push(selected.tag);
      entry = selected.entry;
    }
    return Object.freeze({
      senderTag,
      payments: Object.freeze(payments),
      history: history.withEntry(history.entries.length - 1, entry),
    });
  }
}

interface EntryFields {
  readonly viewingPublicKey: X25519PublicKey;
  readonly createdAt: bigint;
  readonly tx: StreamCounter;
  readonly request: StreamCounter;
  readonly knownSenders: ReadonlyMap<string, Counterparty>;
  readonly knownRecipients: ReadonlyMap<string, Counterparty>;
}

export function viewTagStream(stream: "tx" | "request", index: bigint): ViewTagStream {
  return stream === "tx"
    ? { kind: "sender", txCount: index }
    : { kind: "request", requestCount: index };
}

const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;

function paymentTag(
  recipient: PaymentRecipient,
  tag: ViewTag,
  selection: TagSelection,
): PaymentTag {
  return Object.freeze({
    payment: Object.freeze({ recipient: recipient.viewingPublicKey, tag }),
    selection,
  });
}

function storedEntry(value: unknown): ViewingKeyEntry {
  const stored = record(value, "entry");
  known(stored, "entry", [
    "viewingPubkey",
    "createdAt",
    "tx",
    "request",
    "knownSenders",
    "knownRecipients",
  ]);
  const counterparties = (name: string): readonly Counterparty[] =>
    list(stored[name], name).map((row) =>
      Object.freeze({
        key: pubkey(record(row, name)["pubkey"], name),
        counter: storedCounter(row, name, ["pubkey"]),
      }),
    );
  return ViewingKeyEntry.restore({
    viewingPublicKey: pubkey(stored["viewingPubkey"], "viewingPubkey"),
    createdAt: integer(stored["createdAt"], "createdAt"),
    tx: storedCounter(stored["tx"], "tx", []),
    request: storedCounter(stored["request"], "request", []),
    knownSenders: counterparties("knownSenders"),
    knownRecipients: counterparties("knownRecipients"),
  });
}

function storedCounter(value: unknown, name: string, extra: readonly string[]): StreamCounter {
  const stored = record(value, name);
  known(stored, name, ["next", "scanned", "pending", ...extra]);
  return StreamCounter.restore({
    next: u64(stored["next"], name),
    scanned: u64(stored["scanned"], name),
    pending: list(stored["pending"], name).map((index) => u64(index, name)),
  });
}

/** Integer literals parse to exact bigints, a runtime without source access refuses an unsafe one. */
function parseExact(text: string): unknown {
  if (typeof text !== "string") throw invalid("is not JSON text");
  try {
    return JSON.parse(text, (_key: string, value: unknown, context?: { source?: string }) => {
      if (typeof value !== "number") return value;
      const source = context?.source;
      if (source !== undefined && /^-?[0-9]+$/.test(source)) return BigInt(source);
      return Number.isSafeInteger(value) ? BigInt(value) : value;
    });
  } catch (cause) {
    throw new RingError("RING_VIEWING_HISTORY_INVALID", {
      details: { reason: "does not parse as JSON" },
      cause,
    });
  }
}

function record(value: unknown, name: string): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw invalid(`${name} is not an object`);
  return value as Readonly<Record<string, unknown>>;
}

function list(value: unknown, name: string): readonly unknown[] {
  if (!Array.isArray(value)) throw invalid(`${name} is not a list`);
  return value;
}

function known(value: Readonly<Record<string, unknown>>, name: string, keys: readonly string[]) {
  const missing = keys.some((key) => !(key in value));
  const unknown = Object.keys(value).some((key) => !keys.includes(key));
  if (missing || unknown) throw invalid(`${name} names other fields`);
}

function integer(value: unknown, name: string): bigint {
  if (typeof value !== "bigint") throw invalid(`${name} is not an integer`);
  return value;
}

function u64(value: unknown, name: string): bigint {
  const parsed = integer(value, name);
  if (parsed < 0n || parsed > U64_MAX) throw invalid(`${name} is outside u64`);
  return parsed;
}

function checkedI64(value: bigint, name: string): bigint {
  if (typeof value !== "bigint" || value < I64_MIN || value > I64_MAX)
    throw invalid(`${name} is outside i64`);
  return value;
}

/** An error names the field alone. */
function pubkey(value: unknown, name: string): X25519PublicKey {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{66}$/.test(value))
    throw invalid(`${name} holds a key that is not a tagged X25519 key`);
  try {
    return X25519PublicKey.fromBytes(hexToBytes(value));
  } catch {
    throw invalid(`${name} holds a key that is not a tagged X25519 key`);
  }
}

function keyOf(key: X25519PublicKey): string {
  return bytesToHex(key.toBytes());
}

function invalid(reason: string): RingError {
  return new RingError("RING_VIEWING_HISTORY_INVALID", { details: { reason } });
}

function retentionFloor(scanned: bigint): bigint {
  return scanned > PENDING_RETENTION ? scanned - PENDING_RETENTION : 0n;
}

function max(left: bigint, right: bigint): bigint {
  return left > right ? left : right;
}

function min(left: bigint, right: bigint): bigint {
  return left < right ? left : right;
}

function ascending(left: bigint, right: bigint): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function saturatingIncrement(value: bigint): bigint {
  return saturatingAdd(value, 1n);
}

function saturatingAdd(value: bigint, added: bigint): bigint {
  return value > U64_MAX - added ? U64_MAX : value + added;
}
