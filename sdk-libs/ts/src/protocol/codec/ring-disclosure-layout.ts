/** Regions of the ring auditor stream and the output record, Rust `custom_ring_interface::audit_stream`. */
import { InterfaceError } from "@heliuslabs/spr/interface";

/** Rust `TRANSFER_OUTPUT_CAPACITIES`, the output counts of the confidential keys. */
export const TRANSFER_OUTPUT_CAPACITIES: readonly number[] = Object.freeze([2, 4, 8]);
/** Rust `PACK_BE_CHUNK_BYTES`, the bytes of one packed field. */
export const DISCLOSURE_CHUNK_BYTES = 31;
export const STREAM_BLOCK_LEN = 16;
export const STREAM_FIRST_COUNTER = 2;
/** The sealed `tx_viewing_sk`, the envelope's first bytes. */
export const ENVELOPE_KEY_LEN = 32;
/** `R`, the spent notes. */
export const REAL_INPUT_COUNT_LEN = 1;
/** `tx_viewing_sk ‖ R`, the same on every key. */
export const ENVELOPE_HEAD_LEN = ENVELOPE_KEY_LEN + REAL_INPUT_COUNT_LEN;
/** The default note bitmap is u64, a wider input class needs a new layout. */
export const MAX_INPUT_CLASS = 64;
/** Keys with entry capacity alone, bit `k` set when note `k` is a default-ring note. */
export const DEFAULT_NOTE_BITS_LEN = 8;
/** `kind ‖ u64be(amount) ‖ owner_key ‖ mint ‖ be32(nullifier_pk) ‖ be32(blinding)`. */
export const OUTPUT_RECORD_LEN = 137;
/** The output record then `be32(seed)`. */
export const MERGE_RECORD_LEN = OUTPUT_RECORD_LEN + 32;
/** `eph_sk ‖ V`, sealed to the auditor. */
export const MERGE_ENVELOPE_LEN = 64;
/** `owner_key ‖ be32(nullifier_pk) ‖ u64be(amount) ‖ mint ‖ be32(input_commitment)`. */
export const ENTRY_RECORD_LEN = 136;
/** `0x04 ‖ eph_u` ahead of the auditor ciphertexts. */
export const TAGGED_KEY_LEN = 33;
/** One slot's sealed recipient key `V_i`, the raw `u`. */
export const RECIPIENT_KEY_LEN = 32;
/** Each recipient key keeps its own counters, no slot shares a block with the next. */
export const RECIPIENT_KEY_BLOCKS = 2;
/** `u16be(len)` ahead of a payload. */
export const PAYLOAD_LENGTH_LEN = 2;

/** Rust `pack_be_chunks`, the fields `length` bytes pack into. */
export function packedChunks(length: number): number {
  return Math.ceil(length / DISCLOSURE_CHUNK_BYTES);
}

/** The statement's layout element, Rust `AuditLayout`. */
export interface AuditLayout {
  /** The key carries default bits and one evidence entry per published input. */
  readonly entry: boolean;
}

/** `entry << 1`. */
export function auditLayoutValue(layout: AuditLayout): number {
  if (typeof layout.entry !== "boolean") throw shapeError("layout");
  return layout.entry ? 2 : 0;
}

/** One key's envelope, every rail of a key shares one circuit, Rust `AuditKey`. */
export interface AuditKey {
  /** `C`, the widest published input count. */
  readonly class: number;
  /** Default bits and one evidence entry per published input. */
  readonly entry: boolean;
}

/** One stretch of the auditor keystream, no counter serves two regions, Rust `StreamRegion`. */
export interface AuditStreamRegion {
  readonly startCounter: number;
  readonly maxBlocks: number;
  /** Transmitted bytes, padding and unused blocks never leave the prover. */
  readonly length: number;
}

/** Every length of one transfer's auditor stream, a frame of any other length is refused, Rust `AuditStreamLayout`. */
export interface AuditStreamLayout {
  readonly key: AuditKey;
  /** `n`, the frame's nullifier count, never the key capacity or a private live count. */
  readonly inputs: number;
  /** `m`, the published slots. */
  readonly outputs: number;
  /** `N`, the key's output capacity, the recipient keys span every slot of it. */
  readonly capacity: number;
}

/** Refuses an input count off the key, a key past the bitmap and an output count off the capacity. */
export function checkedStreamLayout(layout: AuditStreamLayout): AuditStreamLayout {
  const { key, inputs, outputs, capacity } = layout;
  const counted =
    Number.isInteger(inputs) &&
    inputs >= 1 &&
    inputs <= key.class &&
    key.class <= MAX_INPUT_CLASS &&
    typeof key.entry === "boolean" &&
    Number.isInteger(capacity) &&
    Number.isInteger(outputs) &&
    outputs >= 1 &&
    outputs <= capacity;
  if (!counted) throw shapeError("layout");
  return layout;
}

function headLen(key: AuditKey): number {
  return ENVELOPE_HEAD_LEN + (key.entry ? DEFAULT_NOTE_BITS_LEN : 0);
}

function entryLen(key: AuditKey): number {
  return key.entry ? ENTRY_RECORD_LEN : 0;
}

/** `E`, the same at every published input count, no recipient key's counter moves. */
export function envelopeBlocks(key: AuditKey): number {
  return Math.ceil((headLen(key) + entryLen(key) * key.class) / STREAM_BLOCK_LEN);
}

/** `K0`. */
export function firstRecipientKeyCounter(key: AuditKey): number {
  return STREAM_FIRST_COUNTER + envelopeBlocks(key);
}

/** Slots at or past `n` stay absent from the evidence. */
export function envelopeRegion(layout: AuditStreamLayout): AuditStreamRegion {
  return Object.freeze({
    startCounter: STREAM_FIRST_COUNTER,
    maxBlocks: envelopeBlocks(layout.key),
    length: headLen(layout.key) + entryLen(layout.key) * layout.inputs,
  });
}

/** Its counter fixed by the slot index alone, omission moves no region. */
export function recipientKeyRegion(layout: AuditStreamLayout, slot: number): AuditStreamRegion {
  return Object.freeze({
    startCounter: firstRecipientKeyCounter(layout.key) + slot * RECIPIENT_KEY_BLOCKS,
    maxBlocks: RECIPIENT_KEY_BLOCKS,
    length: slot < layout.outputs ? RECIPIENT_KEY_LEN : 0,
  });
}

/** `32 m`, the transmitted key region. */
export function recipientKeysLen(layout: Pick<AuditStreamLayout, "outputs">): number {
  return RECIPIENT_KEY_LEN * layout.outputs;
}

/** `0x04 ‖ eph_u ‖ envelope_ct ‖ keys_ct ‖ record_ct of each exit`. */
export function auditorMessageLen(layout: AuditStreamLayout, exits: number): number {
  return (
    TAGGED_KEY_LEN +
    envelopeRegion(layout).length +
    recipientKeysLen(layout) +
    OUTPUT_RECORD_LEN * exits
  );
}

/** The blocks a reader decrypts. */
export function capacityBlocks(layout: Pick<AuditStreamLayout, "key" | "capacity">): number {
  return envelopeBlocks(layout.key) + layout.capacity * RECIPIENT_KEY_BLOCKS;
}

function shapeError(name: string): InterfaceError {
  return new InterfaceError("INTERFACE_INVALID_SHAPE", { name });
}
