/** The one ring proof of a transfer, one request over the audit and policy sections. */
import { ZERO_32 } from "@heliuslabs/spr/internal";
import { NO_CACHE_WRITES, type Bytes32, type CacheAccess } from "@heliuslabs/spr/interface";
import type { X25519PublicKey } from "@heliuslabs/spr/keypair";
import type { ProofInputUtxo, ProofOutputUtxo, SppProofInputs } from "@heliuslabs/spr/transaction";

import type { TransferProofRequest } from "../rpc/prover/ring.js";
import type { RingOutputRail } from "../operations/payments/output-rail.js";
import {
  fittedSpend,
  frameKeyShape,
  ownerSignerCapacity,
  ringTransferCircuit,
  signerSlots,
  type TransferAddresses,
  type TransferKeyCircuit,
  type TransferSpend,
} from "../protocol/proof/transfer-shapes.js";
import { ANONYMOUS_PARTIES, type RingRail } from "../protocol/transaction/transact.js";
import { inputNullifierChain, inputNullifierSlots } from "../protocol/proof/statement.js";
import { RingError } from "../protocol/error.js";
import {
  auditEnvelope,
  entryOpenings,
  inputOpenings,
  outputOpenings,
  type SealedAudit,
} from "./audit-proof.js";
import {
  approvalTotalsOf,
  policyParams,
  type PolicyInputs,
  type PolicyProving,
} from "./policy-proof.js";
import { approvalOpeningOf, type ApprovalOpening } from "../protocol/membership/approval-totals.js";
import { signerDataCountsOf } from "../protocol/membership/signer-data-counts.js";

/** The key a transfer proves under, `wideOwners` the frame flag naming its rows. */
export interface TransferKeySelection {
  readonly circuit: TransferKeyCircuit;
  readonly wideOwners: boolean;
}

/** Refuses a transaction past the account bound before proving, picks the narrowest rows holding every owner. */
export function selectTransferKey(
  input: Readonly<{
    spend: TransferSpend;
    addresses: TransferAddresses;
    /** The published owner signers, hidden and in-proof owners take no address. */
    ownerSigners: number;
  }>,
): TransferKeySelection {
  const { spend, addresses, ownerSigners } = input;
  checkOwnerSignerBound(addresses, ownerSigners);
  const fitted = fittedSpend(spend);
  return Object.freeze({ circuit: transferKeyCircuit(fitted), wideOwners: fitted.wide });
}

/** Refuses a transaction past the account bound, the published owner signers alone take addresses. */
export function checkOwnerSignerBound(addresses: TransferAddresses, ownerSigners: number): void {
  const capacity = ownerSignerCapacity(addresses);
  if (ownerSigners > capacity)
    throw new RingError("RING_TRANSFER_PAST_ACCOUNT_BOUND", {
      details: { ownerSigners, capacity, ...addresses },
    });
}

/** The key of `spend` as its wide flag stands, refused when the catalog keys none. */
export function transferKeyCircuit(spend: TransferSpend): TransferKeyCircuit {
  const circuit = ringTransferCircuit(spend);
  if (circuit === undefined) throw unkeyed(spend);
  return circuit;
}

function unkeyed(spend: TransferSpend): RingError {
  const maximum = frameKeyShape(spend)?.owners;
  if (maximum !== undefined && spend.owners > maximum)
    return new RingError("RING_TOO_MANY_OWNERS", {
      details: { owners: spend.owners, maximum },
    });
  return new RingError("RING_CATALOG_KEY_MISSING", {
    details: {
      rail: spend.rail,
      inputs: spend.inputs,
      outputs: spend.outputs,
      legs: spend.legs,
    },
  });
}

export type { TransferProofRequest };

/** A frame's digest and what opens it, Rust `Frame::approval_opening`. */
export interface TransferApproval {
  readonly digest: Bytes32;
  readonly opening: ApprovalOpening;
}

/**
 * The digest over every slot of the selected key, `capacity` its `N`. A compact shape's `m` would
 * leave the rows short of what the circuit commits. The rail draws the blinder once per attempt,
 * 31 bytes below the field, the digest hides the totals only under a fresh one.
 */
export function transferApprovalOf(
  proofInputs: SppProofInputs,
  capacity: number,
  blinder: Bytes32,
): TransferApproval {
  const totals = approvalTotalsOf(proofInputs, capacity);
  return Object.freeze({
    digest: totals.commitment(blinder),
    opening: approvalOpeningOf(totals, blinder),
  });
}

/** The statement's element over the run `signers` binds and the slots SPP publishes, refused where the circuit has no solution. */
export function ownerDataCounts(
  run: readonly Bytes32[],
  outputs: readonly ProofOutputUtxo[],
): bigint {
  const counts = signerDataCountsOf(
    run,
    outputs.flatMap((output) =>
      output.isDummy() || output.ownerAddress === undefined || output.dataHash === undefined
        ? []
        : [
            {
              ownerIdentity: output.ownerAddress.signingPublicKey.ownerProofInputHash(),
              dataHash: output.dataHash,
            },
          ],
    ),
  );
  if (counts === undefined)
    throw new RingError("RING_TRANSACT_DATA_INVALID", {
      details: { reason: "InvalidSignerDataCounts" },
    });
  return counts;
}

/** Reads alone, a cached write refuses at staging. */
export function cacheAccessOf(proofInputs: SppProofInputs): CacheAccess | undefined {
  const readBitmap = proofInputs.inputUtxos.reduce(
    (bits, input) =>
      input.cacheSlot === undefined ? bits : bits | (1n << BigInt(input.cacheSlot)),
    0n,
  );
  return readBitmap === 0n ? undefined : Object.freeze({ readBitmap, writeSlots: NO_CACHE_WRITES });
}

/** The request of the key the frame selects, every section over the same slots. */
export function transferProofRequest(
  input: Readonly<{
    rail: RingOutputRail;
    ringRail: RingRail;
    sealed: SealedAudit;
    /** `m`. */
    outputCount: number;
    /** The published inputs in SPP order, compact padding left out. */
    inputs: readonly ProofInputUtxo[];
    proofInputs: SppProofInputs;
    auditor: X25519PublicKey;
    policy: PolicyInputs;
    proving: PolicyProving;
    publicInputHash: Bytes32;
    privateTxHash: Bytes32;
    /** The in-proof owner, zero on every other rail. */
    sender: Bytes32;
    inProof: boolean;
    publicOwners: boolean;
    /** Payer, each co-signer and exit destination, zero when absent, unread off the anonymous frame. */
    partyIdentities: readonly Bytes32[];
    /** SPP's owner signer run by owner identity, in-proof and authority bind none. */
    signers: readonly Bytes32[];
    /** Zeros when the frame discloses no totals, a zero digest opens nothing. */
    approval?: TransferApproval;
  }>,
): TransferProofRequest {
  const { policy, proofInputs, inputs, signers } = input;
  const { circuit } = policy;
  const inputClass = circuit.class;
  const entry = input.sealed.audit.entry;
  const anonymousFrame = input.ringRail === "anonymous" || input.ringRail === "anonymousDelegate";
  // The proof derives its address chain from these nullifiers and the chain binds them to the frame.
  const nullifiers = inputs.map((spent) => spent.nullifier());
  return Object.freeze({
    kind: "transfer",
    publicInputHash: input.publicInputHash,
    ...auditEnvelope({
      rail: input.rail,
      sealed: input.sealed,
      firstNullifier: proofInputs.firstNullifier(),
      auditor: input.auditor,
    }),
    approvalMask: policy.approvalMask,
    approvalTotals: input.approval?.digest ?? ZERO_32,
    approvalBlinder: input.approval?.opening.blinder ?? ZERO_32,
    outputCount: input.outputCount,
    // Every slot of the key's capacity, an omitted suffix runs its gadgets over its own proof output.
    outputs: outputOpenings(proofInputs.outputs, proofInputs.outputTreeId, circuit.outputs),
    inputCount: inputs.length,
    inputNullifierChain: inputNullifierChain(nullifiers, inputClass),
    inputNullifiers: inputNullifierSlots(nullifiers, inputClass),
    inputs: inputOpenings(inputs, inputClass),
    entries: entry ? entryOpenings(inputs, inputClass) : [],
    signerCount: signers.length,
    signerDataCounts: ownerDataCounts(signers, proofInputs.outputs),
    signers: [
      ...signers,
      ...Array.from({ length: Math.max(0, signerSlots(circuit) - signers.length) }, () => ZERO_32),
    ],
    rows: policy.rows,
    privateTxHash: input.privateTxHash,
    ...policy.tracking,
    ...policyParams(policy, input.proving),
    inProof: input.inProof,
    hidden: input.ringRail === "anonymous" && !input.publicOwners,
    delegate: input.ringRail === "delegate" || input.ringRail === "anonymousDelegate",
    sender: input.sender,
    partyIdentities: anonymousFrame
      ? [
          ...input.partyIdentities,
          ...Array.from(
            { length: Math.max(0, ANONYMOUS_PARTIES - input.partyIdentities.length) },
            () => ZERO_32,
          ),
        ]
      : Array.from({ length: ANONYMOUS_PARTIES }, () => ZERO_32),
  });
}
