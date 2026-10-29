import { anonymousPartyIdentities } from "../../protocol/membership/parties.js";
import type { Instruction } from "@solana/kit";

import type {
  PreparedMergeInputs,
  ProofDataSourceContext,
  WalletKeys,
} from "@heliuslabs/zolana/client";
import type { LatestBlockhash } from "@heliuslabs/zolana/internal";
import {
  prepareProverMerge,
  compressG2,
  withProofDataRetry,
  compileUnsignedTransaction,
  prepareMerge,
  reserveEntries,
  reservedUtxoKeys,
  unreserved,
  selectUtxos,
  encodeMergeTransactInstructionData,
  mergePaddedInputCount,
  SYSTEM_PROGRAM,
  instruction,
  meta,
  signerAddress,
  type SignerAccount,
  Writer,
  nullifierPdaAddress,
  ZERO_32,
  checkIntentApproval,
  ownerSolanaAccount,
  equalBytes,
} from "@heliuslabs/zolana/internal";
import { customRingProof } from "../../rpc/prover/proof.js";
import { initializePoseidon } from "@heliuslabs/zolana";
import {
  MERGE_INPUT_COUNT,
  InstructionTag,
  SHIELDED_POOL_PROGRAM_ID,
} from "@heliuslabs/zolana/interface";
import type {
  Address,
  Bytes32,
  Bytes128,
  MergeTransactInstructionData,
  RequestContext,
  Transaction,
} from "@heliuslabs/zolana/interface";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  SOL_MINT,
  approveUnattended,
  intentHash,
  type ApprovalHandler,
  type TransactionIntent,
  checkKeysIdentity,
} from "@heliuslabs/zolana/transaction";
import type { PreparedMerge, Wallet } from "@heliuslabs/zolana/transaction";
import type { RingMergeClient, RingSecretProver } from "../../rpc/ports.js";
import { ringAuthAddress, ringConfigAddress, ringPolicyAddress } from "../../protocol/pda/index.js";

import { checkSignersHideOwner } from "./anonymous.js";
import { fetchRingProgramConfig } from "../../protocol/membership/config.js";
import { TRANSFER_DEMAND, checkRingCoSigner } from "../../proof/cosign.js";
import { RingError, RingProgramError, wrapRingError } from "../../protocol/error.js";
import {
  checkAnonymousMergeWidth,
  emptyRingMergeDisclosure,
  ringMergeDisclosureRequest,
  wipeRingMergeDisclosureRequest,
  writeRingMergeDisclosure,
  type RingMergeDisclosure,
} from "../../crypto/audit/merge-disclosure.js";
import {
  RingTransactionSubmission,
  checkRetainedEntries,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "../workflow/submission.js";
import { ringIntentMismatch, ringProofInput, ringSelectionErrors } from "../workflow/selection.js";
import { resolveRingOutputTree } from "../../protocol/membership/trees.js";
import { SIZE_PROBE_LIFETIME } from "../workflow/compile.js";

/** Rust `MAX_MERGE_INPUTS`. */
export const MAX_RING_MERGE_INPUTS = 50;
/** Rust `compute_unit_limit(Merge)`. */
export const RING_MERGE_COMPUTE_UNIT_LIMIT = 1_400_000;
/** `expiry_unix_ts u64 ‖ proof.a` ahead of `proof.b` in the SPP merge body, Rust `MERGE_B_OFFSET`. */
const MERGE_B_OFFSET = 8 + 32;

export interface RingMergeTransactionParams {
  readonly client: RingMergeClient & ProofDataSourceContext;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  /** An anonymous ring's disclosure proof reaches the nullifier secret only through `proveRingWithSecret`. */
  readonly keys: WalletKeys & Partial<RingSecretProver>;
  readonly feePayer: Address;
  readonly asset?: Address;
  /** The most notes merged, smallest first, from 2 through `MAX_RING_MERGE_INPUTS`, default `MERGE_INPUT_COUNT`. */
  readonly maxInputs?: number;
  readonly outputTree?: Address;
  /** Signs when the config's scope covers transfers. */
  readonly cosigner?: SignerAccount;
  readonly approve?: ApprovalHandler;
}

export async function buildRingMergeTransaction(
  params: RingMergeTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (await buildRingMerge(params, {}, context)).transaction;
}

/** A rebuild proves the same notes again under the registry's newest root. */
export function createRingMergeSubmission(
  params: RingMergeTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: params.wallet,
      build: (retry, context) => buildRingMerge(params, retry, context),
      registry: params.client,
    },
    context,
  );
}

/**
 * `MERGE ‖ own_revision ‖ output_ring_data_hash ‖ disclosure? ‖ body` with the body's
 * `proof.b` compressed, the accounts `[config, policy?, co_signer?]` ahead of SPP's merge list.
 */
export async function ringMergeInstruction(
  input: Readonly<{
    ringProgramId: Address;
    inputTree: Address;
    outputTree: Address;
    payer: SignerAccount;
    data: MergeTransactInstructionData;
    outputRingDataHash: Bytes32;
    /** The co-signer the config demands for transfers. */
    cosigner?: SignerAccount;
  }> &
    (
      | Readonly<{ ownRevision: bigint; disclosure?: undefined }>
      /** An anonymous ring reads no records, its disclosure proves the owner instead. */
      | Readonly<{ disclosure: RingMergeDisclosure; ownRevision?: undefined }>
    ),
): Promise<Instruction> {
  const [config, policy, auth, nullifiers] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    input.disclosure === undefined ? ringPolicyAddress(input.ringProgramId) : undefined,
    ringAuthAddress(input.ringProgramId),
    Promise.all(input.data.nullifiers.map((value) => nullifierPdaAddress(input.inputTree, value))),
  ]);
  const body = encodeMergeTransactInstructionData(input.data);
  return instruction(
    writeRingMergeDisclosure(
      new Writer()
        .u8(InstructionTag.ringMergeTransact, "instructionTag")
        .u64(input.ownRevision ?? 0n, "ownRevision")
        .bytes(input.outputRingDataHash, 32, "outputRingDataHash"),
      input.disclosure,
    )
      .bytes(body.subarray(0, MERGE_B_OFFSET))
      .bytes(compressG2(body.slice(MERGE_B_OFFSET, MERGE_B_OFFSET + 128) as Bytes128), 64)
      .bytes(body.subarray(MERGE_B_OFFSET + 128))
      .finish(),
    [
      meta(config, false, false),
      ...(policy === undefined ? [] : [meta(policy, false, false)]),
      ...(input.cosigner === undefined ? [] : [meta(input.cosigner, true, false)]),
      meta(input.inputTree, false, true),
      meta(input.outputTree, false, true),
      meta(auth, false, false),
      meta(input.payer, true, true),
      meta(SYSTEM_PROGRAM, false, false),
      meta(SHIELDED_POOL_PROGRAM_ID, false, false),
      ...nullifiers.map((key) => meta(key, false, true)),
    ],
    input.ringProgramId,
  );
}

async function buildRingMerge(
  params: RingMergeTransactionParams,
  retry: RingSubmissionBuildState,
  context?: RequestContext,
): Promise<RingSubmissionAttempt> {
  try {
    await initializePoseidon();
    checkKeysIdentity(params.keys, params.wallet.identity);
    const maxInputs = mergeWidth(params.maxInputs);
    const [config, outputTree] = await Promise.all([
      fetchRingProgramConfig(params.client, params.ringProgramId, context),
      resolveRingOutputTree(params.client, params.outputTree, context),
    ]);
    if (config.mode !== "anonymous") return escrowMerge(params.ringProgramId);
    const cosigner = checkRingCoSigner({
      ringProgramId: params.ringProgramId,
      configured: config.coSigner,
      supplied: params.cosigner,
      demand: TRANSFER_DEMAND,
      approvalRequired: false,
    });
    const owner = params.keys.address();
    checkSignersHideOwner(owner.signingPublicKey.ed25519(), [
      params.feePayer,
      cosigner === undefined ? undefined : signerAddress(cosigner),
    ]);
    const asset = params.asset ?? SOL_MINT;
    const reserved = reservedUtxoKeys(params.wallet);
    if (retry.entries !== undefined) checkRetainedEntries(params.wallet, retry.entries);
    const entries =
      retry.entries ??
      selectUtxos({
        wallet: params.wallet,
        asset,
        target: { kind: "consolidate", minInputs: 2 },
        policy: {
          eligible: (entry) =>
            unreserved(reserved)(entry) &&
            entry.utxo.ringProgramId === params.ringProgramId &&
            entry.dataHash === undefined &&
            entry.utxo.data.records().every((record) => record.kind !== "utxoData"),
          ordering: "smallestFirst",
          maxInputs,
          tree: { kind: "fixed", tree: params.client.tree },
          errors: {
            ...ringSelectionErrors,
            tooFewUtxos: () => new RingError("RING_NOTHING_TO_MERGE"),
          },
        },
      }).entries;
    checkAnonymousMergeWidth(mergePaddedInputCount(entries.length) ?? entries.length);
    retry.entries = entries;
    retry.reservation ??= reserveEntries(params.wallet, entries, retry.lifetime);
    const inputs = entries.map((entry) => ringProofInput(entry, owner, params.client));
    const prepared = await prepareMerge(
      {
        keys: params.keys,
        inputs,
        outputTreeId: outputTree.treeId,
        ring: { programId: params.ringProgramId },
        invalidAnswers: () => ringIntentMismatch("keyAnswers"),
      },
      context,
    );
    const expectedHash = prepared.outputHash();
    const compile = async (
      data: MergeTransactInstructionData,
      lifetime: LatestBlockhash,
      disclosure: RingMergeDisclosure,
    ): Promise<Transaction> =>
      compileUnsignedTransaction({
        feePayer: params.feePayer,
        lifetime,
        instructions: [
          await ringMergeInstruction({
            ringProgramId: params.ringProgramId,
            inputTree: params.client.tree,
            outputTree: outputTree.tree,
            payer: params.feePayer,
            data,
            // An anonymous ring merge output carries no ring data, Rust `AnonymousRingDataNotZero`.
            outputRingDataHash: ZERO_32,
            disclosure,
            ...(cosigner === undefined ? {} : { cosigner }),
          }),
        ],
        computeUnitLimit: RING_MERGE_COMPUTE_UNIT_LIMIT,
      });
    // Zeroed proofs over the real accounts size the transaction before any proof request.
    const proofInputs = prepareProverMerge(prepared, params.client.tree);
    const preview = proofInputs.finish({
      slot: { id: prepared.inputTreeId, utxoRoot: ZERO_32, nullifierRoot: ZERO_32 },
      utxoRootIndex: 0,
      nullifierRootIndex: 0,
    });
    await compile(
      preview.instructionData({ a: ZERO_32, b: new Uint8Array(128) as Bytes128, c: ZERO_32 }),
      SIZE_PROBE_LIFETIME,
      emptyRingMergeDisclosure(prepared.inputs.length),
    );
    const intent: TransactionIntent = {
      kind: "ringMerge",
      ringProgramId: params.ringProgramId,
      outputTree: outputTree.tree,
      asset,
      numInputs: inputs.length,
      mergedAmount: prepared.output.amount,
    };
    const planned = intentHash(intent);
    if (retry.intent !== undefined && !equalBytes(retry.intent, planned))
      throw ringIntentMismatch("retryIntent");
    retry.intent = planned;
    const approval = await (params.approve ?? approveUnattended)({
      solanaPublicKey: ownerSolanaAccount(owner, params.feePayer),
      intent,
      summary: `merge ${String(inputs.length)} inputs in ring ${params.ringProgramId}`,
    });
    checkIntentApproval(approval, intent, ringIntentMismatch);
    const { data } = await withProofDataRetry(
      params.client.proofDataSource,
      (attempt) => params.client.proveMerge({ prepared, keys: params.keys }, attempt),
      context,
    );
    if (!equalBytes(data.outputUtxoHash, expectedHash)) throw ringIntentMismatch("output");
    const disclosure = await proveMergeDisclosure(
      {
        partyIdentities: anonymousPartyIdentities(params.feePayer, config.coSigner?.signer),
        keys: params.keys,
        ringProgramId: params.ringProgramId,
        auditor: config.auditorPublicKey,
        prepared,
        slots: proofInputs.inputs.payload,
        spp: data,
      },
      context,
    );
    const lifetime = await params.client.getLatestBlockhash(context);
    return {
      transaction: await compile(data, lifetime, disclosure),
      lastValidBlockHeight: lifetime.lastValidBlockHeight,
      intentHash: planned,
      ringInstructionIndex: 0,
      roots: [],
    };
  } catch (cause) {
    if (retry.reservation !== undefined) params.wallet._releaseReservation(retry.reservation.id);
    throw wrapRingError("RING_BUILD_MERGE", cause);
  }
}

/** The program refuses an escrow-mode merge without a ring merge proof, Rust `verify_escrow_merge`. */
function escrowMerge(ringProgramId: Address): never {
  throw new RingError("RING_ESCROW_MERGE_UNVERIFIED", {
    details: { ringProgramId, programError: RingProgramError.escrowMergeUnverified },
  });
}

/** Only the key holder adds the nullifier secret. */
async function proveMergeDisclosure(
  input: Readonly<{
    partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
    keys: Partial<RingSecretProver>;
    ringProgramId: Address;
    auditor: X25519PublicKey;
    prepared: PreparedMerge;
    slots: PreparedMergeInputs;
    spp: MergeTransactInstructionData;
  }>,
  context: RequestContext | undefined,
): Promise<RingMergeDisclosure> {
  const prover = input.keys.proveRingWithSecret?.bind(input.keys);
  if (prover === undefined) throw new RingError("RING_KEYS_REQUIRED");
  const { request, disclosure } = ringMergeDisclosureRequest(input);
  try {
    const proof = await prover(request, context);
    return Object.freeze({ ...disclosure, proof: customRingProof(proof) });
  } finally {
    wipeRingMergeDisclosureRequest(request);
  }
}

function mergeWidth(maxInputs = MERGE_INPUT_COUNT): number {
  if (maxInputs > MAX_RING_MERGE_INPUTS) {
    throw new RingError("RING_TOO_MANY_INPUTS", {
      details: { selected: maxInputs, maximum: MAX_RING_MERGE_INPUTS },
    });
  }
  if (!Number.isSafeInteger(maxInputs) || maxInputs < 2) {
    throw new RingError("RING_NOTHING_TO_MERGE");
  }
  return maxInputs;
}
