/** Regions of the ring auditor stream, Rust `custom_ring_interface::audit_stream`. */
import { InterfaceError } from "@heliuslabs/spr/interface";

export const SINGLE_ASSET_PAYOUT_INPUTS = 1;
export const SINGLE_ASSET_PAYOUT_OUTPUTS = 16;

/** Rust `TRANSFER_OUTPUT_CAPACITIES`, the output counts of the confidential keys. */
export const TRANSFER_OUTPUT_CAPACITIES: readonly number[] = Object.freeze([
  2,
  4,
  8,
  SINGLE_ASSET_PAYOUT_OUTPUTS,
]);
/** Rust `PACK_BE_CHUNK_BYTES`, the bytes of one packed field. */
export const DISCLOSURE_CHUNK_BYTES = 31;
export const STREAM_BLOCK_LEN = 16;
export const STREAM_FIRST_COUNTER = 2;
/** The sealed `tx_viewing_sk`, the envelope's first bytes. */
export const ENVELOPE_KEY_LEN = 32;
/** `R`, spent notes among the published inputs, addresses excluded. */
export const REAL_INPUT_COUNT_LEN = 1;
/** `A` as a big-endian u64, bit `i` set when published input `i` is an address. */
export const ADDRESS_INPUT_BITS_LEN = 8;
/** `tx_viewing_sk ‖ R ‖ A`, the same on every key. */
export const ENVELOPE_HEAD_LEN = ENVELOPE_KEY_LEN + REAL_INPUT_COUNT_LEN + ADDRESS_INPUT_BITS_LEN;
/** The address and default bitmaps are u64, a wider input class needs a new layout. */
export const MAX_INPUT_CLASS = 64;
/** Keys with entry capacity alone, bit `i` set when input `i` is a default-ring note. */
export const DEFAULT_INPUT_BITS_LEN = 8;
/** `kind ‖ u64be(amount) ‖ owner_key ‖ mint ‖ be32(nullifier_pk)`. */
export const AUDIT_RECORD_LEN = 105;
export const COMPACT_AUDIT_RECORD_LEN = 73;
export const RECIPIENT_BODY_LEN = 72;
export const COMPACT_RECIPIENT_BODY_LEN = 48;

export enum DisclosureFormat {
  Standard = 0,
  SingleAssetPayout = 1,
}

export function disclosureFormat(format: DisclosureFormat | undefined): DisclosureFormat {
  if (format === undefined || format === DisclosureFormat.Standard)
    return DisclosureFormat.Standard;
  if (format === DisclosureFormat.SingleAssetPayout) return format;
  throw shapeError("format");
}

export function auditRecordLength(key: Pick<AuditKey, "format">): number {
  return disclosureFormat(key.format) === DisclosureFormat.SingleAssetPayout
    ? COMPACT_AUDIT_RECORD_LEN
    : AUDIT_RECORD_LEN;
}

function recordBlocks(key: AuditKey): number {
  return Math.ceil(auditRecordLength(key) / STREAM_BLOCK_LEN);
}
/** `be32(data_hash) ‖ be32(ring_data_hash)`. */
export const DATA_TAIL_LEN = 64;
/** `owner_key ‖ be32(nullifier_pk) ‖ u64be(amount) ‖ mint ‖ be32(input_commitment)`. */
export const ENTRY_RECORD_LEN = 136;
/** `0x04 ‖ eph_u` ahead of the auditor ciphertexts. */
export const TAGGED_KEY_LEN = 33;

export const RECORD_BLOCKS = Math.ceil(AUDIT_RECORD_LEN / STREAM_BLOCK_LEN);
/** The padding past a record keeps slot `i` at its counter, a transfer frame omits it. */
export const RECORD_STRIDE = RECORD_BLOCKS * STREAM_BLOCK_LEN;
/** The secret is the deposit's blinding or the merge's seed. */
export const OPENING_RECORD_LEN = RECORD_STRIDE + 32;
export const TAIL_BLOCKS = DATA_TAIL_LEN / STREAM_BLOCK_LEN;

/** Rust `pack_be_chunks`, the fields `length` bytes pack into. */
export function packedChunks(length: number): number {
  return Math.ceil(length / DISCLOSURE_CHUNK_BYTES);
}

/** The statement's layout element, Rust `AuditLayout`. */
export interface AuditLayout {
  readonly format?: DisclosureFormat;
  /** One tail per published slot, the proof holds every data hash to zero while clear. */
  readonly hasData: boolean;
  /** The key carries default bits and one evidence entry per published input. */
  readonly entry: boolean;
}

/** `has_data | entry << 1`. */
export function auditLayoutValue(layout: AuditLayout): number {
  if (typeof layout.hasData !== "boolean" || typeof layout.entry !== "boolean")
    throw shapeError("layout");
  return (layout.hasData ? 1 : 0) | (layout.entry ? 2 : 0) | (disclosureFormat(layout.format) << 2);
}

/** One key's envelope, every rail of a key shares one circuit, Rust `AuditKey`. */
export interface AuditKey {
  readonly format?: DisclosureFormat;
  /** The widest published input count, also `S`. */
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
  /** `N`, the key's output capacity, records and tails span every slot of it. */
  readonly capacity: number;
  /** The statement's bit, one tail per published slot. */
  readonly hasData: boolean;
}

/** Refuses an input count off the key, a key past the bitmaps and an output count off the capacity. */
export function checkedStreamLayout(layout: AuditStreamLayout): AuditStreamLayout {
  const { key, inputs, outputs, capacity } = layout;
  const counted =
    Number.isInteger(inputs) &&
    inputs >= 1 &&
    inputs <= key.class &&
    key.class <= MAX_INPUT_CLASS &&
    Number.isInteger(capacity) &&
    Number.isInteger(outputs) &&
    outputs >= 1 &&
    outputs <= capacity;
  if (!counted || typeof layout.hasData !== "boolean") throw shapeError("layout");
  if (
    disclosureFormat(key.format) === DisclosureFormat.SingleAssetPayout &&
    (key.entry ||
      layout.hasData ||
      inputs !== SINGLE_ASSET_PAYOUT_INPUTS ||
      key.class !== SINGLE_ASSET_PAYOUT_INPUTS ||
      outputs !== SINGLE_ASSET_PAYOUT_OUTPUTS ||
      capacity !== SINGLE_ASSET_PAYOUT_OUTPUTS)
  )
    throw shapeError("payout");
  return layout;
}

function headLen(key: AuditKey): number {
  return (
    ENVELOPE_HEAD_LEN +
    (key.entry ? DEFAULT_INPUT_BITS_LEN : 0) +
    (disclosureFormat(key.format) === DisclosureFormat.SingleAssetPayout ? 32 : 0)
  );
}

function entryLen(key: AuditKey): number {
  return key.entry ? ENTRY_RECORD_LEN : 0;
}

/** `E`, the same at every published input count, no record's counter moves. */
export function envelopeBlocks(key: AuditKey): number {
  return Math.ceil((headLen(key) + entryLen(key) * key.class) / STREAM_BLOCK_LEN);
}

/** `R0`. */
export function firstRecordCounter(key: AuditKey): number {
  return STREAM_FIRST_COUNTER + envelopeBlocks(key);
}

/** `T0`, past every record of `N` slots. */
export function firstTailCounter(layout: Pick<AuditStreamLayout, "key" | "capacity">): number {
  return firstRecordCounter(layout.key) + layout.capacity * recordBlocks(layout.key);
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
export function recordRegion(layout: AuditStreamLayout, slot: number): AuditStreamRegion {
  return Object.freeze({
    startCounter: firstRecordCounter(layout.key) + slot * recordBlocks(layout.key),
    maxBlocks: recordBlocks(layout.key),
    length: recordLen(layout, slot),
  });
}

/** Transmits nothing past the outputs or while `hasData` is clear. */
export function tailRegion(layout: AuditStreamLayout, slot: number): AuditStreamRegion {
  return Object.freeze({
    startCounter: firstTailCounter(layout) + slot * TAIL_BLOCKS,
    maxBlocks: TAIL_BLOCKS,
    length: tailLen(layout, slot),
  });
}

export function recordLen(
  layout: Pick<AuditStreamLayout, "outputs" | "key">,
  slot: number,
): number {
  return slot < layout.outputs ? auditRecordLength(layout.key) : 0;
}

export function tailLen(
  layout: Pick<AuditStreamLayout, "outputs" | "hasData">,
  slot: number,
): number {
  return layout.hasData && slot < layout.outputs ? DATA_TAIL_LEN : 0;
}

export function recordsLen(layout: Pick<AuditStreamLayout, "outputs" | "key">): number {
  return auditRecordLength(layout.key) * layout.outputs;
}

export function tailsLen(layout: Pick<AuditStreamLayout, "outputs" | "hasData">): number {
  return layout.hasData ? DATA_TAIL_LEN * layout.outputs : 0;
}

/** `0x04 ‖ eph_u ‖ envelope_ct ‖ record_ct... ‖ tail_ct...`. */
export function auditorMessageLen(layout: AuditStreamLayout): number {
  return TAGGED_KEY_LEN + envelopeRegion(layout).length + recordsLen(layout) + tailsLen(layout);
}

/** The blocks a reader decrypts, a clear `hasData` reaches no tail. */
export function capacityBlocks(
  layout: Pick<AuditStreamLayout, "key" | "capacity" | "hasData">,
): number {
  const tails = layout.hasData ? layout.capacity * TAIL_BLOCKS : 0;
  return envelopeBlocks(layout.key) + layout.capacity * recordBlocks(layout.key) + tails;
}

function shapeError(name: string): InterfaceError {
  return new InterfaceError("INTERFACE_INVALID_SHAPE", { name });
}
