/** The transfer key catalog, Rust `key_catalog.rs` and `Shapes` in `prover/circuits/transfer`. */
import {
  DisclosureFormat,
  SINGLE_ASSET_PAYOUT_INPUTS,
  SINGLE_ASSET_PAYOUT_OUTPUTS,
} from "../codec/ring-disclosure-layout.js";
import type { RingRail } from "../transaction/transact.js";
import { N_PUBLIC_SLOTS } from "../transaction/spp.js";

/** One transfer key, Rust `TransferShape`. */
export interface TransferShape {
  readonly format: DisclosureFormat;
  readonly outputs: number;
  /** The widest published input count the key serves. */
  readonly inputs: number;
  readonly withdrawals: number;
  /** Owner rows the key opens. */
  readonly owners: number;
  /** One evidence slot per input, the key also spends default-ring notes. */
  readonly entry: boolean;
  /** A salted and a public record per owner fit. */
  readonly wide: boolean;
  /** The most tracking rows one inline transaction on the key opens. */
  readonly tracking: number;
  /** Standard format excludes input and public slot assets. */
  readonly records: number;
}

/** Rust `narrow`, `wide` and `entry`. */
const shape = (
  outputs: number,
  inputs: number,
  withdrawals: number,
  owners: number,
  family: Readonly<{ entry: boolean; wide: boolean }>,
  [tracking, records]: readonly [number, number],
): TransferShape =>
  Object.freeze({
    format: DisclosureFormat.Standard,
    outputs,
    inputs,
    withdrawals,
    owners,
    ...family,
    tracking,
    records,
  });

const NARROW = Object.freeze({ entry: false, wide: false });
const WIDE = Object.freeze({ entry: false, wide: true });
const ENTRY = Object.freeze({ entry: true, wide: true });

/** Ascending outputs, a frame takes the first that holds its SPP width. */
const NARROW_SHAPES: readonly TransferShape[] = Object.freeze([
  shape(2, 24, 4, 4, NARROW, [6, 12]),
  shape(4, 24, 4, 4, NARROW, [8, 16]),
  shape(8, 16, 4, 4, NARROW, [12, 24]),
]);
/** The wide flag takes the first row holding the frame, the last only past 24 inputs. */
const WIDE_SHAPES: readonly TransferShape[] = Object.freeze([
  shape(8, 24, 32, 13, WIDE, [42, 88]),
  shape(2, 40, 4, 8, WIDE, [11, 24]),
]);
/** A frame takes the first row holding its width. */
const ENTRY_SHAPES: readonly TransferShape[] = Object.freeze([
  shape(4, 8, 4, 8, ENTRY, [14, 32]),
  shape(8, 2, 4, 2, ENTRY, [14, 36]),
  shape(8, 5, 4, 4, ENTRY, [15, 38]),
]);
const WIDE_ENTRY_SHAPE = shape(8, 8, 32, 8, ENTRY, [38, 80]);

const PAYOUT_SHAPE: TransferShape = Object.freeze({
  format: DisclosureFormat.SingleAssetPayout,
  outputs: SINGLE_ASSET_PAYOUT_OUTPUTS,
  inputs: SINGLE_ASSET_PAYOUT_INPUTS,
  withdrawals: 0,
  owners: 1,
  entry: false,
  wide: false,
  tracking: 17,
  records: 35,
});

/** Rust `RingRail::disclosure_format`. */
export function railDisclosureFormat(
  rail: RingRail,
  shape: Readonly<{ inputs: number; outputs: number }>,
): DisclosureFormat {
  return rail === "confidential" &&
    shape.inputs === PAYOUT_SHAPE.inputs &&
    shape.outputs === PAYOUT_SHAPE.outputs
    ? DisclosureFormat.SingleAssetPayout
    : DisclosureFormat.Standard;
}

export const TRANSFER_SHAPES: readonly TransferShape[] = Object.freeze([
  ...NARROW_SHAPES,
  ...WIDE_SHAPES,
  ...ENTRY_SHAPES,
  WIDE_ENTRY_SHAPE,
  PAYOUT_SHAPE,
]);

/** What names a frame's key, nothing else moves a record's counter, Rust `FrameKey`. */
export interface FrameKey {
  readonly format?: DisclosureFormat;
  readonly rail: RingRail;
  /** `n`, the frame's nullifier count. */
  readonly inputs: number;
  readonly outputs: number;
  readonly spendsDefaultRing: boolean;
  readonly wide: boolean;
}

/** `undefined` when the catalog keys none, Rust `FrameKey::shape`. */
export function frameKeyShape(key: FrameKey): TransferShape | undefined {
  if (key.format === DisclosureFormat.SingleAssetPayout) {
    return key.rail === "confidential" &&
      key.inputs === PAYOUT_SHAPE.inputs &&
      key.outputs === PAYOUT_SHAPE.outputs &&
      !key.spendsDefaultRing &&
      !key.wide
      ? PAYOUT_SHAPE
      : undefined;
  }
  if (key.format !== undefined && key.format !== DisclosureFormat.Standard) return undefined;
  const holds = (entry: TransferShape): boolean =>
    key.outputs <= entry.outputs && key.inputs <= entry.inputs;
  // SPP's authority rail holds every input to the ring.
  if (key.spendsDefaultRing) {
    if (key.rail === "delegate" || key.rail === "anonymousDelegate") return undefined;
    return (key.wide ? [WIDE_ENTRY_SHAPE] : ENTRY_SHAPES).find(holds);
  }
  return (key.wide ? WIDE_SHAPES : NARROW_SHAPES).find(holds);
}

/** A transfer key, Rust `RingCircuit::Transfer`. */
export interface TransferKeyCircuit {
  readonly format: DisclosureFormat;
  readonly family: "transfer";
  readonly outputs: number;
  /** The widest published input count. */
  readonly class: number;
  readonly withdrawals: number;
  readonly owners: number;
  readonly entry: boolean;
  /** A salted and a public record per owner fit. */
  readonly wide: boolean;
}

/** A key's record pool widths, Rust `RecordPools`. */
export interface PolicyPoolCapacity {
  readonly own: number;
  readonly curator: number;
  /** Tracking openings, Rust `RecordPools::tracking`. */
  readonly tracking: number;
}

/** What selects a transfer key, Rust `TransferSpend`. */
export interface TransferSpend {
  readonly format?: DisclosureFormat;
  readonly rail: RingRail;
  /** Published inputs, the spent notes. */
  readonly inputs: number;
  readonly outputs: number;
  readonly spendsDefaultRing: boolean;
  /** Public withdrawal legs. */
  readonly legs: number;
  /** Distinct live input owners. */
  readonly owners: number;
  /** Distinct records the spend opens in each pool, a salted read takes a row beside the public one. */
  readonly pools: PolicyPoolCapacity;
  readonly wide: boolean;
}

/** The wide flag follows the narrow key failing to hold the spend, Rust `TransferSpend::fitted`. */
export function fittedSpend(spend: TransferSpend): TransferSpend {
  const narrow = frameKeyShape({ ...spend, wide: false });
  return { ...spend, wide: narrow === undefined || !shapeHolds(narrow, spend) };
}

/** The one transfer key serving the spend, `undefined` when the catalog keys none. */
export function ringTransferCircuit(spend: TransferSpend): TransferKeyCircuit | undefined {
  const found = frameKeyShape(spend);
  return found === undefined || !shapeHolds(found, spend) ? undefined : shapeCircuit(found);
}

/** `S`, the owner signer slots of a key's statement chain, Go `Sections.Signers`. */
export function signerSlots(circuit: TransferKeyCircuit): number {
  return circuit.class;
}

/** Rust `RingCircuit::record_pools`, each pool takes as many subjects as records. */
export function transferPoolCapacity(circuit: TransferKeyCircuit): PolicyPoolCapacity {
  const row = TRANSFER_SHAPES.find((entry) => sameCircuit(shapeCircuit(entry), circuit));
  if (row === undefined) throw new RangeError(`no catalog key ${transferCircuitType(circuit)}`);
  if (row.format === DisclosureFormat.SingleAssetPayout) {
    return Object.freeze({ own: row.records, curator: row.records, tracking: row.tracking });
  }
  const records = row.records + row.inputs;
  // Withdrawals settle through the public slots, their assets are at most N_PUBLIC_SLOTS.
  const withdrawalAssets = Math.min(row.withdrawals, N_PUBLIC_SLOTS);
  return Object.freeze({
    own: records + Math.max(withdrawalAssets, N_PUBLIC_SLOTS),
    curator: records + withdrawalAssets,
    tracking: row.tracking,
  });
}

function sameCircuit(left: TransferKeyCircuit, right: TransferKeyCircuit): boolean {
  return (
    left.format === right.format &&
    left.outputs === right.outputs &&
    left.class === right.class &&
    left.withdrawals === right.withdrawals &&
    left.owners === right.owners &&
    left.entry === right.entry &&
    left.wide === right.wide
  );
}

/** The circuit type the prover serves the key under, Go `Key.circuitType`. */
export function transferCircuitType(circuit: TransferKeyCircuit): string {
  const family =
    circuit.format === DisclosureFormat.SingleAssetPayout
      ? "transfer-payout"
      : circuit.entry
        ? "transfer-entry"
        : circuit.wide
          ? "transfer-wide"
          : "transfer";
  return `custom-ring-${family}-${circuit.outputs}-in${circuit.class}-w${circuit.withdrawals}-s${circuit.owners}`;
}

/** Every transfer key in the catalog's order, Go `keys`. */
export function transferKeys(): readonly TransferKeyCircuit[] {
  return TRANSFER_SHAPES.map(shapeCircuit);
}

/** Rust `SPP_ADDRESSES`, the addresses SPP takes beside its nullifier PDAs. */
const SPP_ADDRESSES = 4;
/** Rust `RING_ADDRESSES`, ring program, policy, config, own, curator and tracking registries. */
const RING_ADDRESSES = 6;
/** Rust `MAX_TRANSACTION_ADDRESSES`, the v1 ceiling. */
export const MAX_TRANSACTION_ADDRESSES = 64;

/** What takes a v1 transaction's addresses beside its owner signers, Rust `TransferAddresses`. */
export interface TransferAddresses {
  /** The shape's nullifier PDAs. */
  readonly nInputs: number;
  readonly coSigners: number;
  readonly legs: number;
}

/** Rust `TransferAddresses::owner_signers`, a co-signer takes its record too. */
export function ownerSignerCapacity(addresses: TransferAddresses): number {
  const taken =
    SPP_ADDRESSES + RING_ADDRESSES + addresses.nInputs + 2 * addresses.coSigners + addresses.legs;
  return Math.max(0, MAX_TRANSACTION_ADDRESSES - taken);
}

function shapeCircuit(entry: TransferShape): TransferKeyCircuit {
  return Object.freeze({
    family: "transfer",
    format: entry.format,
    outputs: entry.outputs,
    class: entry.inputs,
    withdrawals: entry.withdrawals,
    owners: entry.owners,
    entry: entry.entry,
    wide: entry.wide,
  });
}

/** Rust `TransferShape::holds`. */
function shapeHolds(entry: TransferShape, spend: TransferSpend): boolean {
  const pools = transferPoolCapacity(shapeCircuit(entry));
  return (
    Number.isInteger(spend.inputs) &&
    spend.inputs >= 1 &&
    spend.inputs <= entry.inputs &&
    spend.legs <= entry.withdrawals &&
    spend.owners <= entry.owners &&
    spend.pools.own <= pools.own &&
    spend.pools.curator <= pools.curator &&
    spend.pools.tracking <= pools.tracking
  );
}
