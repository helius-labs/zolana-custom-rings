/**
 * Every plaintext of the ring auditor stream and of an output slot, Rust
 * `custom_ring_interface::audit_stream`.
 * Read after `ring-disclosure-layout.ts`. Read before `crypto/audit/ring-disclosure.ts` and the audit readers.
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
  DEFAULT_NOTE_BITS_LEN,
  ENTRY_RECORD_LEN,
  ENVELOPE_HEAD_LEN,
  ENVELOPE_KEY_LEN,
  MERGE_RECORD_LEN,
  OUTPUT_RECORD_LEN,
  PAYLOAD_LENGTH_LEN,
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

/** One published slot's opening, the proof holds every field to the slot's commitment, Rust `OutputRecord`. */
export interface OutputRecord {
  readonly kind: RecordKind;
  readonly amount: bigint;
  readonly ownerKey: Bytes32;
  readonly mint: Address;
  readonly nullifierPk: Bytes32;
  readonly blinding: Bytes32;
}

/** A merge's output record and the seed its blinding derives from, Rust `MergeRecord`. */
export interface MergeRecord {
  readonly record: OutputRecord;
  readonly seed: Bytes32;
}

/** The unproven bytes past a record, Rust `RecipientPayload`. */
export interface RecipientPayload {
  /** The commitment covers it, a nonzero value travels with the note. */
  readonly ringDataHash?: Bytes32;
  /** The `data_hash` then the application data under it, empty on a plain note. */
  readonly data: Uint8Array;
}

/** Zero on any note but a default-ring note, Rust `EntryRecord`. */
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
  | Readonly<{
      kind: "entry";
      /** Bit `k` set when note `k` is a default-ring note. */
      defaultNoteBits: bigint;
      /** One per published input, by note order. */
      inputs: readonly EntryRecord[];
    }>;

/** `tx_viewing_sk ‖ R ‖ default_note_bits ‖ entries`, Rust `AuditEnvelope`. */
export interface AuditEnvelope {
  readonly txViewingSecret: Bytes32;
  /** `R`, the spent notes. */
  readonly realInputs: number;
  readonly evidence: AuditEvidence;
}

/** One input slot of a proof, the auditor's own index classifies a published nullifier, Rust `InputClass`. */
export const InputClass = Object.freeze({
  note: "note",
  address: "address",
  dummy: "dummy",
} as const);
export type InputClass = (typeof InputClass)[keyof typeof InputClass];

export const DUMMY_RECORD: OutputRecord = Object.freeze({
  kind: RecordKind.dummy,
  amount: 0n,
  ownerKey: ZERO,
  mint: ZERO_MINT,
  nullifierPk: ZERO,
  blinding: ZERO,
});

export const EMPTY_ENTRY_RECORD: EntryRecord = Object.freeze({
  ownerKey: ZERO,
  nullifierPk: ZERO,
  amount: 0n,
  mint: ZERO_MINT,
  inputCommitment: ZERO,
});

export function encodeOutputRecord(record: OutputRecord): Uint8Array {
  const out = new Uint8Array(OUTPUT_RECORD_LEN);
  out[0] = record.kind;
  out.set(u64be(checkedCounter(record.amount, "amount")), 1);
  out.set(checkedBytes<Bytes32>(record.ownerKey, FIELD_LEN, "owner key"), 9);
  out.set(addressBytes(record.mint, "mint"), 41);
  out.set(checkedBytes<Bytes32>(record.nullifierPk, FIELD_LEN, "nullifier pk"), 73);
  out.set(checkedBytes<Bytes32>(record.blinding, FIELD_LEN, "blinding"), 105);
  return out;
}

/** Refuses a kind off the three and a dummy that carries a value. */
export function decodeOutputRecord(plaintext: Uint8Array): OutputRecord {
  if (plaintext.length !== OUTPUT_RECORD_LEN) throw refused();
  const kind = plaintext[0];
  if (kind !== RecordKind.dummy && kind !== RecordKind.ring && kind !== RecordKind.exit)
    throw refused();
  if (kind === RecordKind.dummy && plaintext.some((byte) => byte !== 0)) throw refused();
  return Object.freeze({
    kind,
    amount: bytesToBigInt(plaintext.subarray(1, 9)),
    ownerKey: plaintext.slice(9, 41) as Bytes32,
    mint: encodeBase58(plaintext.subarray(41, 73)),
    nullifierPk: plaintext.slice(73, 105) as Bytes32,
    blinding: plaintext.slice(105, OUTPUT_RECORD_LEN) as Bytes32,
  });
}

export function encodeMergeRecord(merge: MergeRecord): Uint8Array {
  return concatBytes(
    encodeOutputRecord(merge.record),
    checkedBytes<Bytes32>(merge.seed, FIELD_LEN, "seed"),
  );
}

/** Rust `MergeRecord::decode`, the merge reader refuses a kind other than a ring note. */
export function decodeMergeRecord(plaintext: Uint8Array): MergeRecord {
  if (plaintext.length !== MERGE_RECORD_LEN) throw refused();
  const record = decodeOutputRecord(plaintext.subarray(0, OUTPUT_RECORD_LEN));
  return Object.freeze({ record, seed: plaintext.slice(OUTPUT_RECORD_LEN) as Bytes32 });
}

/** `u16be(len) ‖ u8(has_ring_data) ‖ ring_data_hash? ‖ data ‖ zero padding`, `paddedLength` counts the prefix, Rust `RecipientPayload::encode_padded`. */
export function encodeRecipientPayload(
  payload: RecipientPayload,
  paddedLength?: number,
): Uint8Array {
  const { ringDataHash, data } = payload;
  const content = concatBytes(
    Uint8Array.of(ringDataHash === undefined ? 0 : 1),
    ...(ringDataHash === undefined
      ? []
      : [checkedBytes<Bytes32>(ringDataHash, FIELD_LEN, "ring data hash")]),
    data,
  );
  const length = paddedLength ?? PAYLOAD_LENGTH_LEN + content.length;
  if (
    !Number.isSafeInteger(length) ||
    length > 0xffff ||
    length < PAYLOAD_LENGTH_LEN + content.length
  )
    throw refused();
  const encoded = new Uint8Array(length);
  new DataView(encoded.buffer).setUint16(0, content.length, false);
  encoded.set(content, PAYLOAD_LENGTH_LEN);
  return encoded;
}

/** Refuses a short prefix, a length past the bytes, nonzero padding and a presence byte off 0 or 1, Rust `RecipientPayload::decode`. */
export function decodeRecipientPayload(plaintext: Uint8Array): RecipientPayload {
  if (plaintext.length < PAYLOAD_LENGTH_LEN) throw refused();
  const length = new DataView(plaintext.buffer, plaintext.byteOffset, 2).getUint16(0, false);
  const end = PAYLOAD_LENGTH_LEN + length;
  if (length === 0 || end > plaintext.length || plaintext.subarray(end).some((byte) => byte !== 0))
    throw refused();
  const presence = plaintext[PAYLOAD_LENGTH_LEN];
  const rest = plaintext.subarray(PAYLOAD_LENGTH_LEN + 1, end);
  if (presence === 0) return Object.freeze({ data: rest.slice() });
  if (presence !== 1 || rest.length < FIELD_LEN) throw refused();
  return Object.freeze({
    ringDataHash: rest.slice(0, FIELD_LEN) as Bytes32,
    data: rest.slice(FIELD_LEN),
  });
}

export const EMPTY_PAYLOAD: RecipientPayload = Object.freeze({ data: new Uint8Array() });

export function encodeAuditEnvelope(envelope: AuditEnvelope): Uint8Array {
  const { evidence, realInputs } = envelope;
  if (!Number.isInteger(realInputs) || realInputs < 0 || realInputs > 0xff) throw refused();
  const head = concatBytes(
    checkedBytes<Bytes32>(envelope.txViewingSecret, ENVELOPE_KEY_LEN, "tx viewing secret"),
    Uint8Array.of(realInputs),
  );
  if (evidence.kind === "none") return head;
  return concatBytes(
    head,
    u64be(checkedCounter(evidence.defaultNoteBits, "default note bits")),
    ...evidence.inputs.map(encodeEntryRecord),
  );
}

/** Refuses any length other than `layout`'s, `R` past `n`, a default bit at or past `R` and a nonzero record off a default bit. */
export function decodeAuditEnvelope(
  plaintext: Uint8Array,
  layout: AuditStreamLayout,
): AuditEnvelope {
  checkedStreamLayout(layout);
  if (plaintext.length !== envelopeRegion(layout).length) throw refused();
  const txViewingSecret = plaintext.slice(0, ENVELOPE_KEY_LEN) as Bytes32;
  const realInputs = plaintext[ENVELOPE_KEY_LEN] ?? 0;
  // 1. `R` counts notes among the published inputs, every note takes one nullifier.
  if (realInputs > layout.inputs) throw refused();
  const head = { txViewingSecret, realInputs };
  if (!layout.key.entry) return Object.freeze({ ...head, evidence: NO_EVIDENCE });
  // 2. Records sit by note order, a bit or a record past `R` would name a note the proof never opened.
  const entriesAt = ENVELOPE_HEAD_LEN + DEFAULT_NOTE_BITS_LEN;
  const defaultNoteBits = bytesToBigInt(plaintext.subarray(ENVELOPE_HEAD_LEN, entriesAt));
  if (defaultNoteBits >> BigInt(realInputs) !== 0n) throw refused();
  const records = Array.from({ length: layout.inputs }, (_, note) =>
    decodeEntryRecord(
      plaintext.subarray(
        entriesAt + note * ENTRY_RECORD_LEN,
        entriesAt + (note + 1) * ENTRY_RECORD_LEN,
      ),
    ),
  );
  if (
    records.some(
      (record, note) =>
        ((defaultNoteBits >> BigInt(note)) & 1n) === 0n && !isEmptyEntryRecord(record),
    )
  )
    throw refused();
  return Object.freeze({
    ...head,
    evidence: Object.freeze({ kind: "entry", defaultNoteBits, inputs: Object.freeze(records) }),
  });
}

/** True on the all-zero record a ring note or a padding position carries. */
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

function refused(): RingError {
  return new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason: "RingTransactLength" } });
}
