/** One co-sign rule for the program and the SDKs, Rust `instructions::cosign`. */
import type { Address } from "@solana/kit";

import type { ChainReader } from "@heliuslabs/spr/client";
import type { RequestContext } from "@heliuslabs/spr/interface";

import {
  RING_COSIGN_APPROVE_OUTFLOW,
  RING_COSIGN_APPROVE_WITHDRAWAL,
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  type RingCoSigner,
  type RingPolicy,
} from "../protocol/codec/ring-codecs.js";
import { RingError } from "../protocol/error.js";
import { fetchRingCoSignerRecord } from "../protocol/membership/config.js";
import { ringCoSignerAddress } from "../protocol/pda/index.js";
import { ApprovalMask } from "../protocol/transaction/transact.js";
import { PendingRelaySignature } from "../rpc/relay.js";
import {
  expectedCoSigner,
  expectedFunder,
  type CoSignerRule,
  type RelayFunderTerms,
  type TokenAccountCreate,
} from "../rpc/relay-message.js";

const APPROVALS = RING_COSIGN_APPROVE_OUTFLOW | RING_COSIGN_APPROVE_WITHDRAWAL;

/** A transfer's economic operation, merge and delegate demand nothing. */
export interface CoSignOperation {
  /** Clear under the statement's `no_spend`. */
  readonly spendsNote: boolean;
  /** `RING_COSIGN_DEPOSITS` and `RING_COSIGN_WITHDRAWALS` of its public legs. */
  readonly publicLegs: number;
  /** The statement's proven bits. */
  readonly approval: number;
}

export interface CoSignDemand {
  /** `RING_COSIGN_*` bits. */
  readonly classes: number;
}

export interface CoSignRequirement {
  /** `RING_COSIGN_*` bits no record covered yet. */
  readonly uncovered: number;
}

/** A demanded signer and its `CoSigner` record, the pair ahead of the SPP accounts. */
export interface RingCoSignerAccounts {
  readonly signer: Address;
  readonly record: Address;
}

export const NO_DEMAND: CoSignDemand = Object.freeze({ classes: 0 });

/** Rust `ApprovalMask::classes`. */
export function approvalClasses(approval: number): number {
  return (
    ((approval & ApprovalMask.outflow) !== 0 ? RING_COSIGN_APPROVE_OUTFLOW : 0) |
    ((approval & ApprovalMask.withdrawal) !== 0 ? RING_COSIGN_APPROVE_WITHDRAWAL : 0)
  );
}

/** Rust `CoSignOperation::demand`. */
export function operationDemand(operation: CoSignOperation): CoSignDemand {
  return Object.freeze({
    classes:
      (operation.spendsNote ? RING_COSIGN_TRANSFERS : 0) |
      operation.publicLegs |
      approvalClasses(operation.approval),
  });
}

/** The public leg classes of `transfers`, a deposit leg adds `DEPOSITS`, a withdrawal `WITHDRAWALS`. */
export function publicLegClasses(transfers: readonly Readonly<{ isDeposit: boolean }>[]): number {
  return transfers.reduce(
    (classes, transfer) =>
      classes | (transfer.isDeposit ? RING_COSIGN_DEPOSITS : RING_COSIGN_WITHDRAWALS),
    0,
  );
}

/** Rust `CoSignDemand::requirement`, a class with no record drops out, an approval class never does. */
export function demandRequirement(
  demand: CoSignDemand,
  ring: Pick<RingPolicy, "coSignerClasses">,
): CoSignRequirement | undefined {
  const classes = demand.classes & ((ring.coSignerClasses ?? 0) | APPROVALS);
  return classes === 0 ? undefined : Object.freeze({ uncovered: classes });
}

/** Rust `CoSignRequirement::cover`, a record covering no new class is refused. */
export function coverRequirement(
  requirement: CoSignRequirement,
  record: Pick<RingCoSigner, "scope" | "signer">,
): CoSignRequirement | undefined {
  if ((record.scope & requirement.uncovered) === 0)
    throw new RingError("RING_COSIGNER_OUT_OF_SCOPE", {
      details: { signer: record.signer, scope: record.scope, uncovered: requirement.uncovered },
    });
  const uncovered = requirement.uncovered & ~record.scope;
  return uncovered === 0 ? undefined : Object.freeze({ uncovered });
}

/** Reads `supplied` in order while a demanded class stays uncovered, Rust `CoSignerChoice::resolve`. */
export async function resolveRingCoSigners(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount">;
    ringProgramId: Address;
    config: Pick<RingPolicy, "coSignerClasses">;
    demand: CoSignDemand;
    supplied: readonly Address[];
    /** Empty on the anonymous and delegate rails. */
    ownerSigners: readonly Address[];
  }>,
  context?: RequestContext,
): Promise<readonly RingCoSignerAccounts[]> {
  const { client, ringProgramId, ownerSigners } = input;
  const supplied = input.supplied[Symbol.iterator]();
  const resolved: RingCoSignerAccounts[] = [];
  let requirement = demandRequirement(input.demand, input.config);
  while (requirement !== undefined) {
    const { value: signer } = supplied.next() as IteratorResult<Address, undefined>;
    if (signer === undefined)
      throw new RingError("RING_COSIGNER_REQUIRED", {
        details: { reason: "missing", ringProgramId, uncovered: requirement.uncovered },
      });
    // Rust `CoSignerIsOwner`, dual control needs a second key.
    if (ownerSigners.includes(signer)) throw coSignerRequired("coSignerIsOwner", signer);
    const record = await fetchRingCoSignerRecord(client, ringProgramId, signer, context);
    if (record === undefined) throw coSignerRequired("noRecord", signer);
    requirement = coverRequirement(requirement, record);
    resolved.push(
      Object.freeze({ signer, record: await ringCoSignerAddress(ringProgramId, signer) }),
    );
  }
  return Object.freeze(resolved);
}

function coSignerRequired(reason: string, signer: Address): RingError {
  return new RingError("RING_COSIGNER_REQUIRED", { details: { reason, signer } });
}

/** A co-signer the frame names, what it signs is the rule it holds, Rust `CoSignerApproval`. */
export class CoSignerApproval {
  readonly #input: CoSignerApprovalInput;

  constructor(input: CoSignerApprovalInput) {
    this.#input = input;
    Object.freeze(this);
  }

  async pending(): Promise<PendingRelaySignature> {
    const { relayId, message } = this.#input;
    return new PendingRelaySignature(relayId, message, await expectedCoSigner(this.#input));
  }
}

/** A funder's approval, its signature moves the legs it names and nothing else of its, Rust `FunderApproval`. */
export class FunderApproval {
  readonly #input: FunderApprovalInput;

  constructor(input: FunderApprovalInput) {
    this.#input = input;
    Object.freeze(this);
  }

  async pending(): Promise<PendingRelaySignature> {
    const { relayId, message, terms, config } = this.#input;
    return new PendingRelaySignature(relayId, message, await expectedFunder({ terms, config }));
  }
}

export interface FunderApprovalInput {
  readonly relayId: ConstructorParameters<typeof PendingRelaySignature>[0];
  readonly message: Uint8Array;
  readonly terms: RelayFunderTerms;
  readonly config: Pick<RingPolicy, "mode">;
}

export interface CoSignerApprovalInput {
  readonly relayId: ConstructorParameters<typeof PendingRelaySignature>[0];
  readonly message: Uint8Array;
  readonly ring: Address;
  readonly feePayer: Address;
  readonly signer: Address;
  readonly config: Pick<RingPolicy, "mode">;
  /** The public creates a relay puts ahead of the ring instruction. */
  readonly setup: readonly TokenAccountCreate[];
  readonly rule: CoSignerRule;
}
