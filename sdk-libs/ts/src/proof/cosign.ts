import type { Address } from "@solana/kit";

import type { ChainReader } from "@heliuslabs/zolana/client";
import type { RequestContext } from "@heliuslabs/zolana/interface";
import { SOL_MINT } from "@heliuslabs/zolana/transaction";
import type { SettlementTransfer } from "@heliuslabs/zolana/transaction";

import {
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  type RingCoSigner,
  type RingPolicy,
} from "../protocol/codec/ring-codecs.js";
import { RingError } from "../protocol/error.js";
import { fetchRingCoSignerRecord } from "../protocol/membership/config.js";

/** Describes the operation classes and withdrawal amounts requiring approval. */
export interface CoSignDemand {
  readonly classes: number;
  /** Each withdrawn mint once, SOL under the zero address. */
  readonly withdrawals: readonly Readonly<{ mint: Address; amount: bigint }>[];
}

export const TRANSFER_DEMAND: CoSignDemand = Object.freeze({
  classes: RING_COSIGN_TRANSFERS,
  withdrawals: Object.freeze([]),
});
export const DEPOSIT_DEMAND: CoSignDemand = Object.freeze({
  classes: RING_COSIGN_DEPOSITS,
  withdrawals: Object.freeze([]),
});

/** Rust `CoSignDemand::transact`, a transfer plus each public leg's class and withdrawal. */
export function transactDemand(transfers: readonly SettlementTransfer[]): CoSignDemand {
  let classes = RING_COSIGN_TRANSFERS;
  const totals = new Map<Address, bigint>();
  for (const transfer of transfers) {
    classes |= transfer.isDeposit ? RING_COSIGN_DEPOSITS : RING_COSIGN_WITHDRAWALS;
    if (transfer.isDeposit) continue;
    const mint = transfer.kind === "sol" ? SOL_MINT : transfer.mint;
    totals.set(mint, (totals.get(mint) ?? 0n) + transfer.amount);
  }
  return Object.freeze({
    classes,
    withdrawals: Object.freeze(
      [...totals].map(([mint, amount]) => Object.freeze({ mint, amount })),
    ),
  });
}

/** Rust `CoSignRequirement`, one `CoSigner` record must satisfy it. */
export type CoSignRequirement =
  | Readonly<{ kind: "any" }>
  | Readonly<{ kind: "covering"; classes: number }>;

type RequirementInput = Readonly<{
  ringProgramId: Address;
  config: RingPolicy;
  demand: CoSignDemand;
  approvalRequired: boolean;
  /** Only a verified exemption proof waives the withdrawal class. */
  withdrawalExempt?: boolean;
}>;

/** Rust `CoSignDemand::requirement`, `undefined` when no record covers a class and no approval is demanded. */
export function coSignRequirement(input: RequirementInput): CoSignRequirement | undefined {
  const covered = input.config.coSignerClasses ?? 0;
  let shared = covered & input.demand.classes;
  if (input.withdrawalExempt === true || input.demand.withdrawals.length === 0)
    shared &= ~RING_COSIGN_WITHDRAWALS;
  if (shared !== 0) return Object.freeze({ kind: "covering", classes: shared });
  if (!input.approvalRequired) return undefined;
  if (covered === 0) throw coSignerRequired(input.ringProgramId, "approvalWithoutCoSigner");
  return Object.freeze({ kind: "any" });
}

/** Rust `CoSignRequirement::check`, the record's signer signs. */
export function checkCoSignRecord(
  ringProgramId: Address,
  requirement: CoSignRequirement,
  record: RingCoSigner,
): Address {
  if (
    requirement.kind === "covering" &&
    (record.scope & requirement.classes) !== requirement.classes
  )
    throw coSignerRequired(ringProgramId, "outOfScope", record.signer);
  return record.signer;
}

/** Rust `CoSignerChoice::resolve`, the supplied signer once its record covers the demand. */
export async function resolveRingCoSigner(
  input: RequirementInput &
    Readonly<{ client: Pick<ChainReader, "getAccount">; supplied: Address | undefined }>,
  context?: RequestContext,
): Promise<Address | undefined> {
  const requirement = coSignRequirement(input);
  if (requirement === undefined) return undefined;
  if (input.supplied === undefined) throw coSignerRequired(input.ringProgramId, "missing");
  const record = await fetchRingCoSignerRecord(
    input.client,
    input.ringProgramId,
    input.supplied,
    context,
  );
  if (record === undefined) throw coSignerRequired(input.ringProgramId, "noRecord", input.supplied);
  return checkCoSignRecord(input.ringProgramId, requirement, record);
}

/** The transfer's co-signer, never one of its owner signers or its delegate. */
export async function demandedCoSigner(
  input: Omit<RequirementInput, "demand"> &
    Readonly<{
      client: Pick<ChainReader, "getAccount">;
      supplied: Address | undefined;
      transfers: readonly SettlementTransfer[];
      /** Empty on the anonymous and delegate rails. */
      ownerSigners: readonly Address[];
      delegate?: Address;
    }>,
  context?: RequestContext,
): Promise<Address | undefined> {
  const demanded = await resolveRingCoSigner(
    { ...input, demand: transactDemand(input.transfers) },
    context,
  );
  // Rust `CoSignerIsOwner` and `CoSignerIsDelegate`, dual control needs a second key.
  if (demanded !== undefined && input.ownerSigners.includes(demanded))
    throw new RingError("RING_COSIGNER_REQUIRED", {
      details: { reason: "coSignerIsOwner", expected: demanded },
    });
  if (demanded !== undefined && demanded === input.delegate)
    throw new RingError("RING_COSIGNER_REQUIRED", {
      details: { reason: "coSignerIsDelegate", expected: demanded },
    });
  return demanded;
}

function coSignerRequired(
  ringProgramId: Address,
  reason: "approvalWithoutCoSigner" | "missing" | "noRecord" | "outOfScope",
  signer?: Address,
): RingError {
  return new RingError("RING_COSIGNER_REQUIRED", {
    details: { ringProgramId, reason, ...(signer === undefined ? {} : { signer }) },
  });
}
