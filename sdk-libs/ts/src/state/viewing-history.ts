/** Rust `zolana_ring_client::viewing_history`. */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { address as checkedRing, type Address } from "@solana/kit";
import type { RequestContext } from "@heliuslabs/spr";
import { U64_MAX } from "@heliuslabs/spr/internal";
import { X25519PublicKey, type ViewTag } from "@heliuslabs/spr/keypair";

import { isSmallOrder } from "../crypto/keys/x25519.js";
import { RingError } from "../protocol/error.js";
import { exactlyOne } from "./batch.js";
import type { RingKeys, ViewTagStream } from "./ring-keys.js";

/** How far below its watermark a sync still reads an unobserved index. */
export const PENDING_RETENTION = 256n;

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

  /** The index a new tag takes and the counter past it. */
  takeNext(): Readonly<{ index: bigint; counter: StreamCounter }> {
    if (this.next >= U64_MAX) throw new RingError("RING_COUNTER_OVERFLOW");
    return Object.freeze({
      index: this.next,
      counter: new StreamCounter(this.next + 1n, this.scanned, this.pending),
    });
  }

  /** @internal `next` never falls below a taken tag. */
  _scannedUnder(next: bigint): StreamCounter {
    return new StreamCounter(max(this.next, next), this.scanned, this.pending);
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

export class ViewingKeyEntry {
  readonly viewingPublicKey: X25519PublicKey;
  readonly createdAt: bigint;
  readonly tx: StreamCounter;
  /** Confirmed reply claims, keyed by the viewing key a sender's replies name. */
  readonly #knownSenders: ReadonlyMap<string, X25519PublicKey>;
  /** `null` reads the ring from its start. */
  readonly #ringPositions: ReadonlyMap<Address, bigint | null>;
  /** The confidential sync's slot and owner tag reads are complete through it, `null` reads from the start. */
  readonly tagPosition: bigint | null;

  private constructor(fields: EntryFields) {
    this.viewingPublicKey = fields.viewingPublicKey;
    this.createdAt = fields.createdAt;
    this.tx = fields.tx;
    this.#knownSenders = new Map(fields.knownSenders);
    this.#ringPositions = new Map(fields.ringPositions);
    this.tagPosition = fields.tagPosition;
    Object.freeze(this);
  }

  static create(viewingPublicKey: X25519PublicKey, createdAt: bigint): ViewingKeyEntry {
    return new ViewingKeyEntry({
      viewingPublicKey,
      createdAt: checkedI64(createdAt, "createdAt"),
      tx: StreamCounter.EMPTY,
      knownSenders: new Map(),
      ringPositions: new Map(),
      tagPosition: null,
    });
  }

  get txCount(): bigint {
    return this.tx.next;
  }

  knownSenders(): readonly X25519PublicKey[] {
    return [...this.#knownSenders.values()];
  }

  ringPositions(): readonly RingPosition[] {
    return [...this.#ringPositions].map(([ring, afterSlot]) => Object.freeze({ ring, afterSlot }));
  }

  /** `undefined` for a ring the key does not read. */
  ringPosition(ring: Address): bigint | null | undefined {
    return this.#ringPositions.get(ring);
  }

  withTxCounter(counter: StreamCounter): ViewingKeyEntry {
    return new ViewingKeyEntry({ ...this.#fields(), tx: counter });
  }

  /** A known sender keeps the entry as it is. */
  withKnownSender(sender: X25519PublicKey): ViewingKeyEntry {
    const key = keyOf(sender);
    if (this.#knownSenders.has(key)) return this;
    return new ViewingKeyEntry({
      ...this.#fields(),
      knownSenders: new Map([...this.#knownSenders, [key, sender]]),
    });
  }

  /** Refuses a counterparty list naming a key twice or a small-order key, and a ring named twice. */
  static restore(
    fields: Readonly<{
      viewingPublicKey: X25519PublicKey;
      createdAt: bigint;
      tx: StreamCounter;
      knownSenders: readonly X25519PublicKey[];
      ringPositions: readonly RingPosition[];
      tagPosition: bigint | null;
    }>,
  ): ViewingKeyEntry {
    if (fields.knownSenders.some(isSmallOrder))
      throw invalid("knownSenders holds a small-order key");
    const knownSenders = new Map(fields.knownSenders.map((key) => [keyOf(key), key]));
    if (knownSenders.size !== fields.knownSenders.length)
      throw invalid("knownSenders repeats a key");
    const ringPositions = new Map(fields.ringPositions.map((row) => [row.ring, row.afterSlot]));
    if (ringPositions.size !== fields.ringPositions.length)
      throw invalid("ringPositions repeats a ring");
    return new ViewingKeyEntry({
      viewingPublicKey: fields.viewingPublicKey,
      createdAt: checkedI64(fields.createdAt, "createdAt"),
      tx: fields.tx,
      knownSenders,
      ringPositions,
      tagPosition: fields.tagPosition,
    });
  }

  /** @internal */
  _withRingPosition(ring: Address, afterSlot: bigint | null): ViewingKeyEntry {
    return new ViewingKeyEntry({
      ...this.#fields(),
      ringPositions: new Map([...this.#ringPositions, [ring, afterSlot]]),
    });
  }

  /** @internal */
  _withTagPosition(afterSlot: bigint): ViewingKeyEntry {
    return new ViewingKeyEntry({ ...this.#fields(), tagPosition: afterSlot });
  }

  /** @internal A lower `next` would issue a tag again. */
  _progressMatches(stored: ViewingKeyEntry): boolean {
    const counters =
      this.tx.next >= stored.tx.next &&
      this.tx.scanned === stored.tx.scanned &&
      this.tx.pending.join() === stored.tx.pending.join();
    const keptEvery = stored
      .ringPositions()
      .every(({ ring, afterSlot }) => this.ringPosition(ring) === afterSlot);
    const addedUnread = this.ringPositions().every(
      ({ ring, afterSlot }) => stored.ringPosition(ring) !== undefined || afterSlot === null,
    );
    return counters && keptEvery && addedUnread && this.tagPosition === stored.tagPosition;
  }

  /** @internal `read` is the same key after a scan, a ring added since keeps its unread position. */
  _withScanProgress(read: ViewingKeyEntry): ViewingKeyEntry {
    return new ViewingKeyEntry({
      ...this.#fields(),
      tx: read.tx._scannedUnder(this.tx.next),
      ringPositions: new Map([...this.#ringPositions, ...read.#ringPositions]),
    });
  }

  #fields(): EntryFields {
    return {
      viewingPublicKey: this.viewingPublicKey,
      createdAt: this.createdAt,
      tx: this.tx,
      knownSenders: this.#knownSenders,
      ringPositions: this.#ringPositions,
      tagPosition: this.tagPosition,
    };
  }
}

/** One ring a key reads, `afterSlot` the terminal page's `context.slot` of its last read. */
export type RingPosition = Readonly<{ ring: Address; afterSlot: bigint | null }>;

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

  /** The rotated key becomes current, its next sync reads every ring of the wallet from its start. */
  withRotatedKey(viewingPublicKey: X25519PublicKey, createdAt: bigint): ViewingHistory {
    if (createdAt <= this.current().createdAt || this.entry(viewingPublicKey) !== undefined)
      throw new RingError("RING_ROTATED_KEY_NOT_NEWER");
    return new ViewingHistory([...this.entries, this.#unreadEntry(viewingPublicKey, createdAt)]);
  }

  /** A key the wallet held before its current one, its next sync reads every ring from its start. */
  withImportedKey(viewingPublicKey: X25519PublicKey, createdAt: bigint): ViewingHistory {
    if (
      createdAt >= this.current().createdAt ||
      this.entries.some((entry) => entry.createdAt === createdAt) ||
      this.entry(viewingPublicKey) !== undefined
    )
      throw new RingError("RING_IMPORTED_KEY_NOT_OLDER");
    return new ViewingHistory(
      [...this.entries, this.#unreadEntry(viewingPublicKey, createdAt)].sort((left, right) =>
        ascending(left.createdAt, right.createdAt),
      ),
    );
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

  /** Every ring any key reads, by address text. */
  rings(): readonly Address[] {
    return [
      ...new Set(this.entries.flatMap((entry) => entry.ringPositions().map(({ ring }) => ring))),
    ].sort();
  }

  withRing(ring: Address, afterSlot: bigint | null = null): ViewingHistory {
    return new ViewingHistory(
      this.entries.map((entry) =>
        entry.ringPosition(ring) === undefined ? entry._withRingPosition(ring, afterSlot) : entry,
      ),
    );
  }

  /** The wallet's own decision to trust a claimed sender under its current key. */
  withConfirmedSender(sender: X25519PublicKey): ViewingHistory {
    if (isSmallOrder(sender)) throw new RingError("RING_RECIPIENT_KEY_NOT_CONTRIBUTORY");
    return this.withEntry(this.entries.length - 1, this.current().withKnownSender(sender));
  }

  /** @internal Only a terminal page's `context.slot` reaches here, a lower one leaves the position in place. */
  _withRingCheckpoint(
    ring: Address,
    viewingPublicKey: X25519PublicKey,
    checkpoint: bigint,
  ): ViewingHistory {
    const index = this.entries.findIndex((entry) =>
      entry.viewingPublicKey.equals(viewingPublicKey),
    );
    const entry = this.entries[index];
    if (entry === undefined) throw invalid("names no entry for the viewing key");
    const stored = entry.ringPosition(ring);
    if (typeof stored === "bigint" && stored >= checkpoint) return this;
    return this.withEntry(index, entry._withRingPosition(ring, checkpoint));
  }

  /** @internal Each named key's confidential tag reads are complete through `afterSlot`. */
  _withTagPosition(keys: readonly X25519PublicKey[], afterSlot: bigint): ViewingHistory {
    return new ViewingHistory(
      this.entries.map((entry) =>
        keys.some((key) => key.equals(entry.viewingPublicKey))
          ? entry._withTagPosition(afterSlot)
          : entry,
      ),
    );
  }

  /** @internal Every stored key's progress unmoved, an added key starts with none. */
  _progressMatches(stored: ViewingHistory): boolean {
    return (
      stored.entries.every((held) => {
        const entry = this.entry(held.viewingPublicKey);
        return entry !== undefined && entry._progressMatches(held);
      }) &&
      this.entries.every(
        (entry) =>
          stored.entry(entry.viewingPublicKey) !== undefined ||
          (entry.tx.scanned === 0n &&
            entry.ringPositions().every(({ afterSlot }) => afterSlot === null) &&
            entry.tagPosition === null),
      )
    );
  }

  /** @internal A counter, key, sender or ring added during the scan stays. */
  _withScanProgress(scanned: ViewingHistory): ViewingHistory {
    return new ViewingHistory(
      this.entries.map((entry) => {
        const read = scanned.entry(entry.viewingPublicKey);
        return read === undefined ? entry : entry._withScanProgress(read);
      }),
    );
  }

  /** The next sender tag of the current key, the tag of a deposit to the wallet's own note. */
  async senderTag(keys: RingKeys, context?: RequestContext): Promise<AdvancedTag<ViewTag>> {
    return this.#ownTag(keys, context);
  }

  /** Its positions and counters decide what a sync skips, store it as key material. */
  toJson(): string {
    const counter = (value: StreamCounter): string =>
      `{"next":${value.next},"scanned":${value.scanned},"pending":[${value.pending.join(",")}]}`;
    const entries = this.entries.map((entry) => {
      const senders = entry.knownSenders().map(keyOf).sort();
      const positions = [...entry.ringPositions()]
        .sort((left, right) => (left.ring < right.ring ? -1 : 1))
        .map(({ ring, afterSlot }) => `{"ring":"${ring}","afterSlot":${afterSlot ?? "null"}}`);
      return (
        `{"viewingPubkey":"${keyOf(entry.viewingPublicKey)}","createdAt":${entry.createdAt},` +
        `"tx":${counter(entry.tx)},` +
        `"knownSenders":[${senders.map((sender) => `"${sender}"`).join(",")}],` +
        `"ringPositions":[${positions.join(",")}],` +
        `"tagPosition":${entry.tagPosition ?? "null"}}`
      );
    });
    return `{"viewingHistory":[${entries.join(",")}]}`;
  }

  static fromJson(text: string): ViewingHistory {
    return ViewingHistory._fromValue(parseExact(text));
  }

  /** @internal Integers already exact bigints. */
  static _fromValue(value: unknown): ViewingHistory {
    const stored = record(value, "history");
    known(stored, "history", ["viewingHistory"]);
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

  async #ownTag(keys: RingKeys, context?: RequestContext): Promise<AdvancedTag<ViewTag>> {
    const current = this.current();
    const { index, counter } = current.tx.takeNext();
    const tag = exactlyOne(
      await keys.viewTags(
        [{ viewingPublicKey: current.viewingPublicKey, stream: senderStream(index) }],
        context,
      ),
    );
    return Object.freeze({
      tag,
      history: this.withEntry(this.entries.length - 1, current.withTxCounter(counter)),
    });
  }

  /** Every ring the wallet reads is unread under an added key. */
  #unreadEntry(viewingPublicKey: X25519PublicKey, createdAt: bigint): ViewingKeyEntry {
    return this.rings().reduce(
      (entry, ring) => entry._withRingPosition(ring, null),
      ViewingKeyEntry.create(viewingPublicKey, createdAt),
    );
  }
}

interface EntryFields {
  readonly viewingPublicKey: X25519PublicKey;
  readonly createdAt: bigint;
  readonly tx: StreamCounter;
  readonly knownSenders: ReadonlyMap<string, X25519PublicKey>;
  readonly ringPositions: ReadonlyMap<Address, bigint | null>;
  readonly tagPosition: bigint | null;
}

export function senderStream(txCount: bigint): ViewTagStream {
  return { kind: "sender", txCount };
}

const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;

function storedEntry(value: unknown): ViewingKeyEntry {
  const stored = record(value, "entry");
  known(stored, "entry", [
    "viewingPubkey",
    "createdAt",
    "tx",
    "knownSenders",
    "ringPositions",
    "tagPosition",
  ]);
  return ViewingKeyEntry.restore({
    viewingPublicKey: pubkey(stored["viewingPubkey"], "viewingPubkey"),
    createdAt: integer(stored["createdAt"], "createdAt"),
    tx: storedCounter(stored["tx"], "tx"),
    knownSenders: list(stored["knownSenders"], "knownSenders").map((key) =>
      pubkey(key, "knownSenders"),
    ),
    ringPositions: list(stored["ringPositions"], "ringPositions").map(storedPosition),
    tagPosition: stored["tagPosition"] === null ? null : u64(stored["tagPosition"], "tagPosition"),
  });
}

function storedPosition(value: unknown): RingPosition {
  const stored = record(value, "ringPosition");
  known(stored, "ringPosition", ["ring", "afterSlot"]);
  const afterSlot = stored["afterSlot"];
  return Object.freeze({
    ring: storedRing(stored["ring"]),
    afterSlot: afterSlot === null ? null : u64(afterSlot, "afterSlot"),
  });
}

function storedRing(value: unknown): Address {
  if (typeof value !== "string") throw invalid("ring is not an address");
  try {
    return checkedRing(value);
  } catch {
    throw invalid("ring is not an address");
  }
}

function storedCounter(value: unknown, name: string): StreamCounter {
  const stored = record(value, name);
  known(stored, name, ["next", "scanned", "pending"]);
  return StreamCounter.restore({
    next: u64(stored["next"], name),
    scanned: u64(stored["scanned"], name),
    pending: list(stored["pending"], name).map((index) => u64(index, name)),
  });
}

/** Integer literals parse to exact bigints, a runtime without source access refuses an unsafe one. */
export function parseExact(text: string): unknown {
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

function ascending(left: bigint, right: bigint): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
