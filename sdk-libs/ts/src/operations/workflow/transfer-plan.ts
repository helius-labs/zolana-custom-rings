/**
 * One planned key per transfer, Rust `pipeline::plan`. The key fixes every counter of the auditor
 * stream, so sealing, the proof request, the relay terms and the fit check read one
 * `PlannedTransfer`. Ring RPC keeps a relayed seal only where its read's key opens the same stream,
 * otherwise it refuses with `resealNarrow` or `resealWide` and the owner seals again under `sealRow`.
 *
 * Read after `protocol/proof/transfer-shapes.ts`. Read before `pipeline.ts`.
 */
import type { AuditStreamLayout } from "../../protocol/codec/ring-disclosure-layout.js";
import {
  fittedSpend,
  type PolicyPoolCapacity,
  type TransferKeyCircuit,
  type TransferSpend,
} from "../../protocol/proof/transfer-shapes.js";
import { transferKeyCircuit } from "../../proof/transfer-proof.js";

/** One of the two rows a transfer's counts select between, the frame header's wide flag, Rust `SealRow`. */
export type SealRow = "narrow" | "wide";

export const NO_RECORD_POOLS: PolicyPoolCapacity = Object.freeze({
  own: 0,
  curator: 0,
  tracking: 0,
});

/** Rust `PlannedTransfer`. */
export interface PlannedTransfer {
  readonly circuit: TransferKeyCircuit;
  readonly wideOwners: boolean;
  readonly layout: AuditStreamLayout;
}

/** What a planner adds to a key, every value public before any record read. */
export interface PlanFrame {
  /** `pools` empty and `wide` clear, a plan fills them. */
  readonly subjects: TransferSpend;
  /** The stream layout of a frame under the header's wide flag. */
  layoutUnder(wideOwners: boolean): AuditStreamLayout;
}

/** The narrowest key holding the counts and `pools`, empty pools ahead of every record read. */
export function planTransfer(frame: PlanFrame, pools: PolicyPoolCapacity): PlannedTransfer {
  return keyedPlan(frame, fittedSpend({ ...frame.subjects, pools }));
}

/** The key of `row` whatever the reads, the row a reseal names. */
export function planTransferAt(frame: PlanFrame, row: SealRow): PlannedTransfer {
  return keyedPlan(frame, { ...frame.subjects, wide: row === "wide" });
}

function keyedPlan(frame: PlanFrame, spend: TransferSpend): PlannedTransfer {
  return Object.freeze({
    circuit: transferKeyCircuit(spend),
    wideOwners: spend.wide,
    layout: frame.layoutUnder(spend.wide),
  });
}
