/** Each owner's guard, debit and charged outflow per asset, Rust `zolana_ring_policy::quantities`. */
import { bytesKey, bytesToBigInt, equalBytes, isZero } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";

import { ApprovalMask } from "../transaction/transact.js";
import type { MintPolicy } from "./mint-policy.js";

/** A live input, keyed by owner identity so one owner's notes aggregate across nullifier keys. */
export interface DebitInput {
  readonly owner: Bytes32;
  readonly asset: Bytes32;
  readonly amount: bigint;
}

/** A live output, an exit leaves the ring even when it pays its own owner. */
export interface DebitOutput extends DebitInput {
  readonly ring: boolean;
}

/** A public slot's statement-bound gross withdrawal, no deposit subtracted. */
export interface PublicGross {
  readonly asset: Bytes32;
  readonly gross: bigint;
}

/** One row's quantities of one asset, `held = debit + kept`, `debit` is the owner's net outflow. */
export interface OwnerDebit {
  readonly owner: Bytes32;
  readonly asset: Bytes32;
  readonly debit: bigint;
  readonly kept: bigint;
  readonly charge: bigint;
  /** `debit + charge`, the value the cap and `cosignAbove` read. */
  readonly chargedOutflow: bigint;
}

/** One transfer's parties, the assets are its output and public assets. */
export interface DebitTransfer {
  readonly senders: readonly Bytes32[];
  readonly assets: readonly Bytes32[];
  readonly inputs: readonly DebitInput[];
  readonly outputs: readonly DebitOutput[];
  readonly publicGross: readonly PublicGross[];
}

/** Nonzero charged outflow rows by ascending owner then assets order, no caller input selects a share. */
export function ownerDebits(transfer: DebitTransfer): readonly OwnerDebit[] {
  const owners = orderedOwners(transfer);
  const flows = distinct(transfer.assets)
    .flatMap((asset) => assetFlows(transfer, owners, asset))
    .filter((flow) => flow.chargedOutflow !== 0n);
  // Array sort is stable, each owner keeps its assets' order.
  return Object.freeze(flows.sort((left, right) => compareField(left.owner, right.owner)));
}

/** Big-endian bytes order as the field integers the circuit's rows ascend by. */
export function compareField(left: Bytes32, right: Bytes32): number {
  const [a, b] = [bytesToBigInt(left), bytesToBigInt(right)];
  return a < b ? -1 : a > b ? 1 : 0;
}

/** The order every asset's flows share. */
export function orderedOwners(transfer: DebitTransfer): Bytes32[] {
  return distinct(transfer.senders.filter((owner) => !isZero(owner))).sort(compareField);
}

/** One row per owner, zero rows kept. */
export function assetFlows(
  transfer: DebitTransfer,
  owners: readonly Bytes32[],
  asset: Bytes32,
): readonly OwnerDebit[] {
  const rows = owners.map((owner) => {
    const held = sum(
      transfer.inputs.filter(
        (input) => equalBytes(input.owner, owner) && equalBytes(input.asset, asset),
      ),
    );
    const returned = sum(
      transfer.outputs.filter(
        (output) =>
          output.ring && equalBytes(output.owner, owner) && equalBytes(output.asset, asset),
      ),
    );
    const debit = held > returned ? held - returned : 0n;
    return { owner, asset, debit, kept: held - debit };
  });
  const exits = sum(
    transfer.outputs.filter((output) => !output.ring && equalBytes(output.asset, asset)),
  );
  const gross = transfer.publicGross
    .filter((slot) => equalBytes(slot.asset, asset))
    .reduce((total, slot) => total + slot.gross, 0n);
  const leaving = exits + gross;
  const sumDebit = rows.reduce((total, row) => total + row.debit, 0n);
  const sumKept = rows.reduce((total, row) => total + row.kept, 0n);
  const displaced = min(leaving, sumDebit + sumKept) - min(leaving, sumDebit);
  let running = 0n;
  let previous = 0n;
  return rows.map((row) => {
    running += row.kept;
    // `displaced` is zero whenever `sumKept` is, the charge telescopes to `displaced`.
    const share = displaced === 0n ? 0n : (displaced * running) / sumKept;
    const charge = share - previous;
    previous = share;
    return Object.freeze({ ...row, charge, chargedOutflow: row.debit + charge });
  });
}

/** Compared with amount guards, `receipt + exit + paid`, Rust `GuardScope`. */
export class GuardScope {
  /** Default-ring notes stay out, entry funding is a receipt. */
  readonly #ringInputs: readonly DebitInput[];
  /** Outputs and withdrawals, `ring` clear on an exit or a withdrawal. */
  readonly #payments: readonly DebitOutput[];

  constructor(
    input: Readonly<{ ringInputs: readonly DebitInput[]; payments: readonly DebitOutput[] }>,
  ) {
    this.#ringInputs = input.ringInputs;
    this.#payments = input.payments;
  }

  owner(owner: Bytes32, asset: Bytes32): bigint {
    const held = (slot: DebitInput): boolean =>
      equalBytes(slot.owner, owner) && equalBytes(slot.asset, asset);
    const paid = (ring: boolean): bigint =>
      sum(this.#payments.filter((pay) => pay.ring === ring && held(pay)));
    const spent = sum(this.#ringInputs.filter(held));
    const receipts = paid(true);
    return (receipts > spent ? receipts - spent : 0n) + paid(false);
  }

  /** Over the asset's distinct owners. */
  asset(asset: Bytes32): bigint {
    const owners = distinct(
      this.#payments.filter((pay) => equalBytes(pay.asset, asset)).map((pay) => pay.owner),
    );
    return owners.reduce((total, owner) => total + this.owner(owner, asset), 0n);
  }
}

/** The statement's proven bits, zero and an asset with no record both mean no threshold, Rust `ApprovalInputs::mask`. */
export function approvalMask(
  input: Readonly<{
    flows: readonly OwnerDebit[];
    publicGross: readonly PublicGross[];
    policyOf: (asset: Bytes32) => MintPolicy;
  }>,
): number {
  const { flows, publicGross, policyOf } = input;
  const overOutflow = flows.some((flow) => {
    const above = policyOf(flow.asset).cosignAbove;
    return above !== 0n && flow.chargedOutflow > above;
  });
  const overWithdrawal = publicGross.some((slot) => {
    const threshold = policyOf(slot.asset).withdrawalThreshold;
    return threshold !== 0n && slot.gross > threshold;
  });
  return (overOutflow ? ApprovalMask.outflow : 0) | (overWithdrawal ? ApprovalMask.withdrawal : 0);
}

function sum(slots: readonly Pick<DebitInput, "amount">[]): bigint {
  return slots.reduce((total, slot) => total + slot.amount, 0n);
}

function min(left: bigint, right: bigint): bigint {
  return left < right ? left : right;
}

function distinct(values: readonly Bytes32[]): Bytes32[] {
  return [...new Map(values.map((value) => [bytesKey(value), value])).values()];
}
