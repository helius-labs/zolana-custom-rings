/** The totals a transfer proof binds for a co-signer, Rust `zolana_ring_policy::ApprovalTotals`. */
import { bigIntBytes, equalBytes, hashChain4, ZERO_32 } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";

import { assetFlows, orderedOwners, type DebitTransfer, type PublicGross } from "./owner-debits.js";

const U128_MAX = (1n << 128n) - 1n;

/** "CRAO". */
export const APPROVAL_TOTALS_DOMAIN = 0x4352_414fn;

/** `peak` is one owner's largest charged outflow of the asset, the value `cosignAbove` compares. */
export interface OutputTotals {
  /** Zero on a dummy slot. */
  readonly asset: Bytes32;
  readonly peak: bigint;
  readonly chargedOutflow: bigint;
}

/** `peak` and `outflow` read debits alone, a charged asset reads whole under its live output. */
export interface PublicTotals {
  readonly asset: Bytes32;
  readonly peak: bigint;
  readonly outflow: bigint;
  readonly gross: bigint;
}

/** Amounts are decimal text, a `u128` does not survive every JSON reader. */
export interface OutputTotalsOpening {
  readonly asset: Bytes32;
  readonly peak: string;
  readonly chargedOutflow: string;
}

export interface PublicTotalsOpening {
  readonly asset: Bytes32;
  readonly peak: string;
  readonly outflow: string;
  readonly gross: string;
}

/** The totals and blinder a frame's digest commits, no transaction secret and no slot, Rust `ApprovalOpening`. */
export interface ApprovalOpening {
  readonly blinder: Bytes32;
  readonly outputs: readonly OutputTotalsOpening[];
  readonly public: readonly PublicTotalsOpening[];
}

/** The layout every key commits, a slot past the live ones reads zeros. */
export class ApprovalTotals {
  readonly outputs: readonly OutputTotals[];
  readonly publicSlots: readonly PublicTotals[];

  constructor(
    layout: Readonly<{ outputs: readonly OutputTotals[]; publicSlots: readonly PublicTotals[] }>,
  ) {
    this.outputs = Object.freeze([...layout.outputs]);
    this.publicSlots = Object.freeze([...layout.publicSlots]);
    Object.freeze(this);
  }

  /** `slotAssets` holds `undefined` on a dummy slot, `publicSlots` follows the statement's order. */
  static new(
    input: Readonly<{
      transfer: DebitTransfer;
      slotAssets: readonly (Bytes32 | undefined)[];
      publicSlots: readonly PublicGross[];
    }>,
  ): ApprovalTotals {
    const { transfer } = input;
    const owners = orderedOwners(transfer);
    return new ApprovalTotals({
      outputs: input.slotAssets.map((asset) => {
        if (asset === undefined)
          return Object.freeze({ asset: ZERO_32, peak: 0n, chargedOutflow: 0n });
        const { peak, sum } = peakAndSum(
          assetFlows(transfer, owners, asset).map((row) => row.chargedOutflow),
        );
        return Object.freeze({ asset, peak, chargedOutflow: sum });
      }),
      publicSlots: input.publicSlots.map(({ asset, gross }) => {
        const { peak, sum } = peakAndSum(
          assetFlows(transfer, owners, asset).map((row) => row.debit),
        );
        return Object.freeze({ asset, peak, outflow: sum, gross });
      }),
    });
  }

  /** Zero when no slot names `asset`. */
  peakOf(asset: Bytes32): bigint {
    return this.#largest(asset, (peak) => peak);
  }

  /** Zero when no slot names `asset`. */
  outflowOf(asset: Bytes32): bigint {
    return this.#largest(asset, (_, total) => total);
  }

  /** The frame's `approvalTotals` extension, the blinder fresh per transaction. */
  commitment(blinder: Bytes32): Bytes32 {
    return hashChain4([
      amountField(APPROVAL_TOTALS_DOMAIN),
      blinder,
      ...this.outputs.flatMap((slot) => [
        slot.asset,
        amountField(slot.peak),
        amountField(slot.chargedOutflow),
      ]),
      ...this.publicSlots.flatMap((slot) => [
        slot.asset,
        amountField(slot.peak),
        amountField(slot.outflow),
        amountField(slot.gross),
      ]),
    ]) as Bytes32;
  }

  /** `total` is an output's charged outflow and a public slot's debits. */
  #largest(asset: Bytes32, read: (peak: bigint, total: bigint) => bigint): bigint {
    return [
      ...this.outputs.map((slot) => [slot.asset, slot.peak, slot.chargedOutflow] as const),
      ...this.publicSlots.map((slot) => [slot.asset, slot.peak, slot.outflow] as const),
    ]
      .filter(([slotAsset]) => equalBytes(slotAsset, asset))
      .map(([, peak, total]) => read(peak, total))
      .reduce((largest, value) => (value > largest ? value : largest), 0n);
  }
}

export function approvalOpeningOf(totals: ApprovalTotals, blinder: Bytes32): ApprovalOpening {
  return Object.freeze({
    blinder,
    outputs: Object.freeze(
      totals.outputs.map((slot) =>
        Object.freeze({
          asset: slot.asset,
          peak: slot.peak.toString(),
          chargedOutflow: slot.chargedOutflow.toString(),
        }),
      ),
    ),
    public: Object.freeze(
      totals.publicSlots.map((slot) =>
        Object.freeze({
          asset: slot.asset,
          peak: slot.peak.toString(),
          outflow: slot.outflow.toString(),
          gross: slot.gross.toString(),
        }),
      ),
    ),
  });
}

/** `undefined` on an amount Rust `u128::from_str` refuses, the digest check then reads a false opening. */
export function openingTotals(opening: ApprovalOpening): ApprovalTotals | undefined {
  const outputs: OutputTotals[] = [];
  for (const slot of opening.outputs) {
    const [peak, chargedOutflow] = [parseAmount(slot.peak), parseAmount(slot.chargedOutflow)];
    if (peak === undefined || chargedOutflow === undefined) return undefined;
    outputs.push({ asset: slot.asset, peak, chargedOutflow });
  }
  const publicSlots: PublicTotals[] = [];
  for (const slot of opening.public) {
    const [peak, outflow, gross] = [
      parseAmount(slot.peak),
      parseAmount(slot.outflow),
      parseAmount(slot.gross),
    ];
    if (peak === undefined || outflow === undefined || gross === undefined) return undefined;
    publicSlots.push({ asset: slot.asset, peak, outflow, gross });
  }
  return new ApprovalTotals({ outputs, publicSlots });
}

/** Rust `u128::from_str`, bare `BigInt` also reads "", " 4 " and "0x10". */
function parseAmount(text: string): bigint | undefined {
  if (!/^\+?[0-9]+$/.test(text)) return undefined;
  const amount = BigInt(text);
  return amount > U128_MAX ? undefined : amount;
}

function peakAndSum(values: readonly bigint[]): Readonly<{ peak: bigint; sum: bigint }> {
  return values.reduce(
    ({ peak, sum }, value) => ({
      peak: value > peak ? value : peak,
      sum: sum + value,
    }),
    { peak: 0n, sum: 0n },
  );
}

function amountField(value: bigint): Bytes32 {
  return bigIntBytes(value) as Bytes32;
}
