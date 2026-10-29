import { anonymousPartyIdentities } from "../../protocol/membership/parties.js";
import { getBase64Decoder, type Instruction } from "@solana/kit";

import type {
  PreparedMergeInputs,
  ProofDataSourceContext,
  TreeContext,
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
import { MERGE_WIDTHS } from "../../protocol/codec/ring-disclosure-layout.js";
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
import type { NullifierKey, ShieldedAddress, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  SOL_MINT,
  approveUnattended,
  intentHash,
  type ApprovalHandler,
  type TransactionIntent,
  checkKeysIdentity,
} from "@heliuslabs/zolana/transaction";
import type {
  AssetRegistry,
  PreparedMerge,
  Wallet,
  WalletUtxo,
} from "@heliuslabs/zolana/transaction";
import { encodeRelayMergeInputs } from "../../protocol/ring-rpc/relay-proof-inputs.js";
import type { RelayIntent, RelayQuote } from "../../protocol/ring-rpc/ring-rpc-types.js";
import { PreparedRelay } from "../../rpc/relay.js";
import type { RingMergeClient, RingSecretProver } from "../../rpc/ports.js";
import {
  ringAuthAddress,
  ringCoSignerMetas,
  ringConfigAddress,
  ringPolicyAddress,
} from "../../protocol/pda/index.js";

import { checkSignersHideOwner } from "./anonymous.js";
import { fetchRingProgramConfig } from "../../protocol/membership/config.js";
import { TRANSFER_DEMAND, resolveRingCoSigner } from "../../proof/cosign.js";
import { RingError, wrapRingError } from "../../protocol/error.js";
import {
  checkMergeWidth,
  emptyRingMergeDisclosure,
  ringMergeDisclosureRequest,
  wipeRingMergeDisclosureRequest,
  writeRingMergeDisclosure,
  type RingMergeDisclosure,
  type RingMergeEscrow,
} from "../../crypto/audit/merge-disclosure.js";
import { readRegisteredRecord } from "../../rpc/registered-record.js";
import {
  RingTransactionSubmission,
  checkRetainedEntries,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "../workflow/submission.js";
import { ringIntentMismatch, ringProofInput, ringSelectionErrors } from "../workflow/selection.js";
import { resolveRingOutputTree } from "../../protocol/membership/trees.js";
import { SIZE_PROBE_LIFETIME } from "../workflow/compile.js";

const base64 = getBase64Decoder();

/** Rust `MAX_RING_MERGE_INPUTS`, the widest merge whose disclosure fits one v1 transaction. */
export const MAX_RING_MERGE_INPUTS = Math.max(...MERGE_WIDTHS);
/** Rust `compute_unit_limit(Merge)`. */
export const RING_MERGE_COMPUTE_UNIT_LIMIT = 1_400_000;
/** `expiry_unix_ts u64 ‖ proof.a` ahead of `proof.b` in the SPP merge body, Rust `MERGE_B_OFFSET`. */
const MERGE_B_OFFSET = 8 + 32;

export interface RingMergeTransactionParams {
  readonly client: RingMergeClient & ProofDataSourceContext;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  /** The disclosure proof reaches the nullifier secret only through `proveRingWithSecret`. */
  readonly keys: WalletKeys & Partial<RingSecretProver>;
  readonly feePayer: Address;
  readonly asset?: Address;
  /** The most notes merged, smallest first, from 2 through `MAX_RING_MERGE_INPUTS`, default `MERGE_INPUT_COUNT`. */
  readonly maxInputs?: number;
  readonly outputTree?: Address;
  /** Signs when a record covers transfers, the record must be its own. */
  readonly cosigner?: SignerAccount;
  readonly approve?: ApprovalHandler;
}

export interface RingMergeRelayParams {
  readonly client: TreeContext;
  readonly ringProgramId: Address;
  /** Owns every note. */
  readonly sender: ShieldedAddress;
  /** Ring RPC proves with it and so links every spend of the owner. */
  readonly nullifierKey: NullifierKey;
  readonly notes: readonly WalletUtxo[];
  readonly assets: AssetRegistry;
  readonly quote: RelayQuote;
}

/** Rust `MergeRelay::prepare`, Ring RPC derives the merged note and no wallet signature follows. */
export function prepareRingMergeRelay(params: RingMergeRelayParams): PreparedRelay {
  let payload: Uint8Array | undefined;
  try {
    payload = encodeRelayMergeInputs({
      ringProgramId: params.ringProgramId,
      sender: params.sender,
      nullifierKey: params.nullifierKey,
      inputs: params.notes.map((note) => ringProofInput(note, params.sender, params.client)),
      leafIndexes: params.notes.map((note) => note.outputContext.leafIndex),
      assets: params.assets,
    });
    return new PreparedRelay({
      ring: params.ringProgramId,
      quote: params.quote,
      intent: {
        operation: "merge",
        proofInputs: base64.decode(payload) as RelayIntent["proofInputs"],
      },
    });
  } finally {
    payload?.fill(0);
  }
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
 * `MERGE ‖ own_revision ‖ output_ring_data_hash ‖ disclosure ‖ body` with the body's
 * `proof.b` compressed, the accounts `[config, policy?, co-signer record and signer?]` ahead of SPP's merge list.
 */
export async function ringMergeInstruction(
  input: Readonly<{
    ringProgramId: Address;
    inputTree: Address;
    outputTree: Address;
    payer: SignerAccount;
    data: MergeTransactInstructionData;
    outputRingDataHash: Bytes32;
    disclosure: RingMergeDisclosure;
    /** Key escrow rings only, the policy account then follows the config. */
    ownRevision?: bigint;
    /** The supplied co-signer when a record covers transfers. */
    cosigner?: SignerAccount;
  }>,
): Promise<Instruction> {
  const [config, policy, auth, nullifiers, cosigner] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    input.ownRevision === undefined ? undefined : ringPolicyAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
    Promise.all(input.data.nullifiers.map((value) => nullifierPdaAddress(input.inputTree, value))),
    input.cosigner === undefined ? [] : ringCoSignerMetas(input.ringProgramId, input.cosigner),
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
      ...cosigner,
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
    const demanded = await resolveRingCoSigner(
      {
        client: params.client,
        ringProgramId: params.ringProgramId,
        config,
        demand: TRANSFER_DEMAND,
        approvalRequired: false,
        supplied: params.cosigner === undefined ? undefined : signerAddress(params.cosigner),
      },
      context,
    );
    const cosigner = demanded === undefined ? undefined : params.cosigner;
    const owner = params.keys.address();
    if (config.mode === "anonymous")
      checkSignersHideOwner(owner.signingPublicKey.ed25519(), [params.feePayer, demanded]);
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
    checkMergeWidth(mergePaddedInputCount(entries.length) ?? entries.length);
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
    const escrow =
      config.mode === "confidentialEscrow"
        ? await readRegisteredRecord(
            {
              client: params.client,
              ringProgramId: params.ringProgramId,
              member: owner.signingPublicKey.ownerProofInputHash(),
              escrowed: prepared.nullifierPublicKey,
            },
            context,
          )
        : undefined;
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
            // Rust `AnonymousRingDataNotZero` refuses ring data on an anonymous ring.
            outputRingDataHash: ZERO_32,
            disclosure,
            ...(escrow === undefined ? {} : { ownRevision: escrow.root.revision }),
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
        partyIdentities: anonymousPartyIdentities(params.feePayer, demanded),
        keys: params.keys,
        ringProgramId: params.ringProgramId,
        auditor: config.auditorPublicKey,
        prepared,
        slots: proofInputs.inputs.payload,
        spp: data,
        ...(escrow === undefined
          ? {}
          : { escrow: { root: escrow.root.root, record: escrow.record, ctHash: escrow.ctHash } }),
      },
      context,
    );
    const lifetime = await params.client.getLatestBlockhash(context);
    return {
      transaction: await compile(data, lifetime, disclosure),
      lastValidBlockHeight: lifetime.lastValidBlockHeight,
      intentHash: planned,
      ringInstructionIndex: 0,
      roots: escrow === undefined ? [] : [escrow.root],
    };
  } catch (cause) {
    if (retry.reservation !== undefined) params.wallet._releaseReservation(retry.reservation.id);
    throw wrapRingError("RING_BUILD_MERGE", cause);
  }
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
    escrow?: RingMergeEscrow;
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
