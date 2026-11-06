/**
 * Every plaintext of the ring auditor stream and its input map, Rust
 * `custom_ring_interface::audit_stream`.
 * Read after `ring-disclosure-layout.ts`. Read before `proof/audit-proof.ts` and the audit readers.
 */
import {
  addressBytes,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  encodeBase58,
  equalBytes,
  u64be,
} from "@heliuslabs/spr/internal";
import type { Address, Bytes32 } from "@heliuslabs/spr/interface";

import { checkedCounter } from "../../crypto/error.js";
import {
  ADDRESS_INPUT_BITS_LEN,
  AUDIT_RECORD_LEN,
  COMPACT_AUDIT_RECORD_LEN,
  DisclosureFormat,
  SINGLE_ASSET_PAYOUT_INPUTS,
  disclosureFormat,
  DATA_TAIL_LEN,
  DEFAULT_INPUT_BITS_LEN,
  ENTRY_RECORD_LEN,
  ENVELOPE_HEAD_LEN,
  ENVELOPE_KEY_LEN,
  MAX_INPUT_CLASS,
  OPENING_RECORD_LEN,
  RECORD_STRIDE,
  checkedStreamLayout,
  envelopeRegion,
  type AuditStreamLayout,
} from "./ring-disclosure-layout.js";
import { RingError } from "../error.js";

const FIELD_LEN = 32;
const AMOUNT_LEN = 8;
const ZERO = new Uint8Array(FIELD_LEN) as Bytes32;
const ZERO_MINT = encodeBase58(ZERO);
const NO_EVIDENCE: AuditEvidence = Object.freeze({ kind: "none" });

/** A record's first byte, the circuit derives it from the slot's domain and ring id, Rust `RecordKind`. */
export const RecordKind = Object.freeze({ dummy: 0, ring: 1, exit: 2 } as const);
export type RecordKind = (typeof RecordKind)[keyof typeof RecordKind];

/** One published slot, the proof holds a dummy's plaintext to zero, Rust `AuditRecord`. */
export interface AuditRecord {
  readonly kind: RecordKind;
  readonly amount: bigint;
  readonly ownerKey: Bytes32;
  readonly mint: Address;
  readonly nullifierPk: Bytes32;
}

/** A deposit or merge record, `secret` the deposit's blinding or the merge's seed, Rust `OpeningRecord`. */
export interface OpeningRecord {
  readonly record: AuditRecord;
  readonly secret: Bytes32;
}

/** Zero fields while `hasData` is clear and on a dummy, Rust `DataTail`. */
export interface DataTail {
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
}

/** Zero on any slot but a default-ring note, Rust `EntryRecord`. */
export interface EntryRecord {
  readonly ownerKey: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly amount: bigint;
  readonly mint: Address;
  /** SPP's spent UTXO hash, the value `private_tx_hash` chains. */
  readonly inputCommitment: Bytes32;
}

/** The envelope past its sealed key and count, Rust `AuditEvidence`. */
export type AuditEvidence =
  | Readonly<{ kind: "none" }>
  | Readonly<{ kind: "singleAssetPayout"; mint: Address }>
  | Readonly<{
      kind: "entry";
      /** Bit `i` set when input `i` is a live default-ring note. */
      defaultInputBits: bigint;
      /** One per published input. */
      inputs: readonly EntryRecord[];
    }>;

/** `tx_viewing_sk ‖ R ‖ A ‖ default_input_bits ‖ entries`, Rust `AuditEnvelope`. */
export interface AuditEnvelope {
  readonly txViewingSecret: Bytes32;
  /** `R`, the spent notes, addresses excluded. */
  readonly realInputs: number;
  /** `A`, bit `i` set when published input `i` is an address. */
  readonly addressInputBits: bigint;
  readonly evidence: AuditEvidence;
}

/** One input slot, Rust `InputClass`. */
export const InputClass = Object.freeze({
  note: "note",
  address: "address",
  dummy: "dummy",
} as const);
export type InputClass = (typeof InputClass)[keyof typeof InputClass];

/** Rust `InputClassification`, unchecked until `InputMap.check`. */
export interface InputClassification {
  /** `n`, the published nullifiers. */
  readonly publishedInputs: number;
  /** `C`, the key's input class. */
  readonly capacity: number;
  /** `R`. */
  readonly noteCount: number;
  /** `A` in absolute published input order. */
  readonly addressInputBits: bigint;
}

/** Rust `InputMap`, notes and addresses interleave below `L = R + popcount(A)`, dummies from `L`. */
export class InputMap {
  readonly #classification: InputClassification;
  /** `L`. */
  readonly nonDummyCount: number;

  private constructor(classification: InputClassification, nonDummyCount: number) {
    this.#classification = Object.freeze({ ...classification });
    this.nonDummyCount = nonDummyCount;
  }

  /** Refuses counts past the capacity, a capacity past the bitmap and an address bit at or past `L`. */
  static check(classification: InputClassification): InputMap {
    const { publishedInputs, capacity, noteCount, addressInputBits } = classification;
    // 1. Range every count first, a bigint shift accepts any count and would hide one past the bitmap.
    if (
      !Number.isInteger(publishedInputs) ||
      !Number.isInteger(capacity) ||
      !Number.isInteger(noteCount) ||
      typeof addressInputBits !== "bigint" ||
      publishedInputs < 1 ||
      publishedInputs > capacity ||
      capacity > MAX_INPUT_CLASS ||
      noteCount < 0 ||
      noteCount > 0xff ||
      addressInputBits < 0n ||
      addressInputBits >> BigInt(MAX_INPUT_CLASS) !== 0n
    )
      throw refused();
    // 2. `L` counts notes and addresses alike, an address bit at or past it would sit in padding.
    const nonDummyCount = noteCount + popcount(addressInputBits);
    if (nonDummyCount > publishedInputs || addressInputBits >> BigInt(nonDummyCount) !== 0n)
      throw refused();
    return new InputMap(classification, nonDummyCount);
  }

  /** `classes` spans the capacity, a note or address past a dummy or past `n` is refused. */
  static fromClasses(classes: readonly InputClass[], publishedInputs: number): InputMap {
    if (classes.length > MAX_INPUT_CLASS) throw refused();
    let noteCount = 0;
    let addressInputBits = 0n;
    let padding = false;
    classes.forEach((inputClass, slot) => {
      if ((padding || slot >= publishedInputs) && inputClass !== InputClass.dummy) throw refused();
      if (inputClass === InputClass.note) noteCount += 1;
      else if (inputClass === InputClass.address) addressInputBits |= 1n << BigInt(slot);
      else padding = true;
    });
    return InputMap.check({
      publishedInputs,
      capacity: classes.length,
      noteCount,
      addressInputBits,
    });
  }

  get noteCount(): number {
    return this.#classification.noteCount;
  }

  get addressInputBits(): bigint {
    return this.#classification.addressInputBits;
  }

  get publishedInputs(): number {
    return this.#classification.publishedInputs;
  }

  get capacity(): number {
    return this.#classification.capacity;
  }

  /** `undefined` at or past the capacity. */
  slot(slot: number): InputClass | undefined {
    if (!Number.isInteger(slot) || slot < 0 || slot >= this.capacity) return undefined;
    if (slot >= this.nonDummyCount) return InputClass.dummy;
    return ((this.addressInputBits >> BigInt(slot)) & 1n) === 1n
      ? InputClass.address
      : InputClass.note;
  }

  classes(): readonly InputClass[] {
    return Object.freeze(
      Array.from({ length: this.capacity }, (_, slot) => this.slot(slot) as InputClass),
    );
  }

  /** Default bits name note positions alone, never an address or a dummy. */
  validateDefaultInputBits(bits: bigint): void {
    if (
      typeof bits !== "bigint" ||
      (bits & this.addressInputBits) !== 0n ||
      bits >> BigInt(this.nonDummyCount) !== 0n
    )
      throw refused();
  }
}

/** The envelope's map under `layout`, Rust `AuditEnvelope::input_map`. */
export function envelopeInputMap(
  envelope: Pick<AuditEnvelope, "realInputs" | "addressInputBits">,
  layout: Pick<AuditStreamLayout, "inputs" | "key">,
): InputMap {
  const map = InputMap.check({
    publishedInputs: layout.inputs,
    capacity: layout.key.class,
    noteCount: envelope.realInputs,
    addressInputBits: envelope.addressInputBits,
  });
  if (
    disclosureFormat(layout.key.format) === DisclosureFormat.SingleAssetPayout &&
    (map.noteCount !== SINGLE_ASSET_PAYOUT_INPUTS || map.addressInputBits !== 0n)
  )
    throw refused();
  return map;
}

export const DUMMY_RECORD: AuditRecord = Object.freeze({
  kind: RecordKind.dummy,
  amount: 0n,
  ownerKey: ZERO,
  mint: ZERO_MINT,
  nullifierPk: ZERO,
});

export const EMPTY_TAIL: DataTail = Object.freeze({ dataHash: ZERO, ringDataHash: ZERO });

export const EMPTY_ENTRY_RECORD: EntryRecord = Object.freeze({
  ownerKey: ZERO,
  nullifierPk: ZERO,
  amount: 0n,
  mint: ZERO_MINT,
  inputCommitment: ZERO,
});

export function encodeAuditRecord(record: AuditRecord): Uint8Array {
  const out = new Uint8Array(AUDIT_RECORD_LEN);
  out[0] = record.kind;
  out.set(u64be(checkedCounter(record.amount, "amount")), 1);
  out.set(checkedBytes<Bytes32>(record.ownerKey, FIELD_LEN, "owner key"), 9);
  out.set(addressBytes(record.mint, "mint"), 41);
  out.set(checkedBytes<Bytes32>(record.nullifierPk, FIELD_LEN, "nullifier pk"), 73);
  return out;
}

/** Refuses a kind off the three and a dummy that carries a value. */
export function decodeAuditRecord(plaintext: Uint8Array): AuditRecord {
  if (plaintext.length !== AUDIT_RECORD_LEN) throw refused();
  const kind = plaintext[0];
  if (kind !== RecordKind.dummy && kind !== RecordKind.ring && kind !== RecordKind.exit)
    throw refused();
  const body = plaintext.subarray(1);
  if (kind === RecordKind.dummy && body.some((byte) => byte !== 0)) throw refused();
  return Object.freeze({
    kind,
    amount: bytesToBigInt(plaintext.subarray(1, 9)),
    ownerKey: plaintext.slice(9, 41) as Bytes32,
    mint: encodeBase58(plaintext.subarray(41, 73)),
    nullifierPk: plaintext.slice(73, 105) as Bytes32,
  });
}

export function encodeCompactAuditRecord(record: AuditRecord): Uint8Array {
  if (record.kind !== RecordKind.ring) throw refused();
  return concatBytes(
    Uint8Array.of(record.kind),
    u64be(checkedCounter(record.amount, "amount")),
    checkedBytes<Bytes32>(record.ownerKey, FIELD_LEN, "owner key"),
    checkedBytes<Bytes32>(record.nullifierPk, FIELD_LEN, "nullifier pk"),
  );
}

export function decodeCompactAuditRecord(plaintext: Uint8Array, mint: Address): AuditRecord {
  if (plaintext.length !== COMPACT_AUDIT_RECORD_LEN || plaintext[0] !== RecordKind.ring)
    throw refused();
  return Object.freeze({
    kind: RecordKind.ring,
    amount: bytesToBigInt(plaintext.subarray(1, 9)),
    ownerKey: plaintext.slice(9, 41) as Bytes32,
    mint,
    nullifierPk: plaintext.slice(41) as Bytes32,
  });
}

export function encodeOpeningRecord(opening: OpeningRecord): Uint8Array {
  const out = new Uint8Array(OPENING_RECORD_LEN);
  out.set(encodeAuditRecord(opening.record));
  out.set(checkedBytes<Bytes32>(opening.secret, FIELD_LEN, "secret"), RECORD_STRIDE);
  return out;
}

export function decodeOpeningRecord(plaintext: Uint8Array): OpeningRecord {
  if (plaintext.length !== OPENING_RECORD_LEN) throw refused();
  if (plaintext.subarray(AUDIT_RECORD_LEN, RECORD_STRIDE).some((byte) => byte !== 0))
    throw refused();
  return Object.freeze({
    record: decodeAuditRecord(plaintext.subarray(0, AUDIT_RECORD_LEN)),
    secret: plaintext.slice(RECORD_STRIDE) as Bytes32,
  });
}

export function encodeDataTail(tail: DataTail): Uint8Array {
  return concatBytes(
    checkedBytes<Bytes32>(tail.dataHash, FIELD_LEN, "data hash"),
    checkedBytes<Bytes32>(tail.ringDataHash, FIELD_LEN, "ring data hash"),
  );
}

export function decodeDataTail(plaintext: Uint8Array): DataTail {
  if (plaintext.length !== DATA_TAIL_LEN) throw refused();
  return Object.freeze({
    dataHash: plaintext.slice(0, FIELD_LEN) as Bytes32,
    ringDataHash: plaintext.slice(FIELD_LEN) as Bytes32,
  });
}

export function encodeAuditEnvelope(envelope: AuditEnvelope): Uint8Array {
  const { evidence, realInputs, addressInputBits } = envelope;
  if (!Number.isInteger(realInputs) || realInputs < 0 || realInputs > 0xff) throw refused();
  const head = concatBytes(
    checkedBytes<Bytes32>(envelope.txViewingSecret, ENVELOPE_KEY_LEN, "tx viewing secret"),
    Uint8Array.of(realInputs),
    u64be(checkedCounter(addressInputBits, "address input bits")),
  );
  if (evidence.kind === "none") return head;
  if (evidence.kind === "singleAssetPayout")
    return concatBytes(head, addressBytes(evidence.mint, "mint"));
  return concatBytes(
    head,
    u64be(checkedCounter(evidence.defaultInputBits, "default input bits")),
    ...evidence.inputs.map(encodeEntryRecord),
  );
}

/** Refuses any length other than `layout`'s, counts off the input map, a default bit off a note and a nonzero record off a default bit. */
export function decodeAuditEnvelope(
  plaintext: Uint8Array,
  layout: AuditStreamLayout,
): AuditEnvelope {
  checkedStreamLayout(layout);
  if (plaintext.length !== envelopeRegion(layout).length) throw refused();
  // 1. The head sits at fixed offsets on every key.
  const txViewingSecret = plaintext.slice(0, ENVELOPE_KEY_LEN) as Bytes32;
  const realInputs = plaintext[ENVELOPE_KEY_LEN] ?? 0;
  const bitsAt = ENVELOPE_HEAD_LEN - ADDRESS_INPUT_BITS_LEN;
  const addressInputBits = bytesToBigInt(plaintext.subarray(bitsAt, ENVELOPE_HEAD_LEN));
  // 2. `R` and `A` must form a canonical map before any evidence reads a position.
  const head = { txViewingSecret, realInputs, addressInputBits };
  const inputs = envelopeInputMap(head, layout);
  if (disclosureFormat(layout.key.format) === DisclosureFormat.SingleAssetPayout) {
    return Object.freeze({
      ...head,
      evidence: Object.freeze({
        kind: "singleAssetPayout",
        mint: encodeBase58(plaintext.subarray(ENVELOPE_HEAD_LEN)),
      }),
    });
  }
  if (!layout.key.entry) return Object.freeze({ ...head, evidence: NO_EVIDENCE });
  // 3. Entry evidence names default-ring notes alone, every other published position stays zero.
  const entriesAt = ENVELOPE_HEAD_LEN + DEFAULT_INPUT_BITS_LEN;
  const defaultInputBits = bytesToBigInt(plaintext.subarray(ENVELOPE_HEAD_LEN, entriesAt));
  inputs.validateDefaultInputBits(defaultInputBits);
  const records = Array.from({ length: layout.inputs }, (_, slot) =>
    decodeEntryRecord(
      plaintext.subarray(
        entriesAt + slot * ENTRY_RECORD_LEN,
        entriesAt + (slot + 1) * ENTRY_RECORD_LEN,
      ),
    ),
  );
  if (
    records.some(
      (record, slot) =>
        ((defaultInputBits >> BigInt(slot)) & 1n) === 0n && !isEmptyEntryRecord(record),
    )
  )
    throw refused();
  return Object.freeze({
    ...head,
    evidence: Object.freeze({
      kind: "entry",
      defaultInputBits,
      inputs: Object.freeze(records),
    }),
  });
}

/** True on the all-zero record a ring note, an address or a dummy carries. */
export function isEmptyEntryRecord(record: EntryRecord): boolean {
  return equalBytes(encodeEntryRecord(record), encodeEntryRecord(EMPTY_ENTRY_RECORD));
}

function encodeEntryRecord(record: EntryRecord): Uint8Array {
  return concatBytes(
    checkedBytes<Bytes32>(record.ownerKey, FIELD_LEN, "owner key"),
    checkedBytes<Bytes32>(record.nullifierPk, FIELD_LEN, "nullifier pk"),
    u64be(checkedCounter(record.amount, "amount")),
    addressBytes(record.mint, "mint"),
    checkedBytes<Bytes32>(record.inputCommitment, FIELD_LEN, "input commitment"),
  );
}

function decodeEntryRecord(bytes: Uint8Array): EntryRecord {
  const mintAt = 2 * FIELD_LEN + AMOUNT_LEN;
  const commitmentAt = mintAt + FIELD_LEN;
  const field = (at: number): Bytes32 => bytes.slice(at, at + FIELD_LEN) as Bytes32;
  return Object.freeze({
    ownerKey: field(0),
    nullifierPk: field(FIELD_LEN),
    amount: bytesToBigInt(bytes.subarray(2 * FIELD_LEN, mintAt)),
    mint: encodeBase58(bytes.subarray(mintAt, commitmentAt)),
    inputCommitment: field(commitmentAt),
  });
}

function popcount(bits: bigint): number {
  let count = 0;
  for (let rest = bits; rest !== 0n; rest >>= 1n) count += Number(rest & 1n);
  return count;
}

function refused(): RingError {
  return new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason: "RingTransactLength" } });
}
