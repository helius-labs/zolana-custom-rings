import { bytesKey } from "@heliuslabs/spr/internal";
import {
  assertIsFullySignedTransaction,
  assertIsTransactionWithinSizeLimit,
  getSignatureFromTransaction,
  isSolanaError,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  SOLANA_ERROR__TRANSACTION_ERROR__BLOCKHASH_NOT_FOUND,
  type Address,
  type Signature,
  type TransactionPartialSigner,
} from "@solana/kit";
import {
  isClientError,
  runKitRpc,
  type UtxoReservation,
  equalBytes,
  assertVersion1Transaction,
  compileUnsignedTransaction,
} from "@heliuslabs/spr/internal";
import type { BlockhashProvider, ChainReader, KitRpcAccess } from "@heliuslabs/spr/client";
import type { ViewingHistory } from "../../state/viewing-history.js";
import { savePersistedWallet, type WalletPersistence } from "@heliuslabs/spr/wallet";
import type { Bytes32, RequestContext, Transaction } from "@heliuslabs/spr/interface";
import {
  type Wallet,
  type WalletUtxo,
  type PendingWalletSubmission,
} from "@heliuslabs/spr/transaction";
import type {
  RingSubmissionPending,
  RingSubmissionStatus,
  RingSubmissionTransport,
} from "../../rpc/ports.js";
import { fetchRingPolicy, fetchStorageRegistry } from "../../protocol/membership/config.js";
import { RingError, RingProgramError } from "../../protocol/error.js";
import { fetchTrackingRegistry } from "../../rpc/tracking-resolver.js";
import { ringComputeUnitLimit } from "../management/admin.js";
import type { OwnerDebit } from "../../protocol/membership/owner-debits.js";
import { checkSpendCoverage } from "./selection.js";
import { TransactionFit } from "./address-ceiling.js";
import {
  boundState,
  fitBudget,
  fitSigners,
  transactTag,
  type ProvenRingTransfer,
  type RingBoundState,
  type RingTransactionFrame,
} from "./pipeline.js";

/** Keeps the signed intent and validity bounds of one transaction attempt. */
export interface RingSubmissionAttempt extends RingBoundState {
  readonly transaction: Transaction;
  readonly lastValidBlockHeight: bigint;
  readonly intentHash: Bytes32;
  readonly ringInstructionIndex: number;
  /** The anonymous depositor's viewing history past the attempt's tag, every attempt the same. */
  readonly viewingHistory?: ViewingHistory;
  /** Absent off a transfer. */
  readonly chargedOutflows?: readonly OwnerDebit[];
}

export type RingSubmissionResult =
  | Readonly<{
      kind: "confirmed";
      signature: Signature;
      slot: bigint;
      attempts: number;
    }>
  | Readonly<{ kind: "unknown"; signature: Signature; attempts: number }>
  | Readonly<{
      kind: "failed";
      signature: Signature;
      attempts: number;
      instructionIndex?: number;
      customCode?: number;
    }>;

/** @internal Retains the same notes and intent across proof rebuilds. */
export interface RingSubmissionBuildState {
  lifetime?: "submission";
  entries?: readonly WalletUtxo[];
  reservation?: UtxoReservation;
  intent?: Bytes32;
}

/** Keeps selected notes unavailable until submission resolves. */
export interface ReservationHold {
  release(): void;
  extend(): void;
}

export type RingSubmissionBuild = (context?: RequestContext) => Promise<RingSubmissionAttempt>;

const MAX_ATTEMPTS = 3;

/** @internal Rust `REPROOF`, pinned row for row by the parity test. */
export const REPROOF: ReadonlyMap<number, "fixes" | "ifMoved"> = new Map([
  [RingProgramError.rootNotServed, "fixes"],
  [RingProgramError.trackingRootBelowFloor, "fixes"],
  [RingProgramError.unboundRegistry, "fixes"],
  [RingProgramError.proofVerificationFailed, "ifMoved"],
]);
const NO_RESERVATION: ReservationHold = Object.freeze({ release() {}, extend() {} });

/** One proven transfer as an attempt, the fit refuses it over the complete transaction, setup included. */
export async function provenRingAttempt(
  input: Readonly<{
    proven: ProvenRingTransfer;
    feePayer: Address;
    chain: BlockhashProvider;
    transaction: RingTransactionFrame;
    intentHash: Bytes32;
  }>,
  context?: RequestContext,
): Promise<RingSubmissionAttempt> {
  const { proven, feePayer, chain, transaction: frame } = input;
  const [instruction, lifetime] = await Promise.all([
    proven.instruction(),
    chain.getLatestBlockhash(context),
  ]);
  const computeUnitLimit = ringComputeUnitLimit(transactTag(proven.data.rail));
  TransactionFit.of(instruction, fitSigners(feePayer, frame), {
    ...fitBudget(frame),
    computeUnitLimit,
  });
  return Object.freeze({
    transaction: compileUnsignedTransaction({
      ...frame,
      feePayer,
      lifetime,
      computeUnitLimit,
      instructions: [instruction],
    }),
    lastValidBlockHeight: lifetime.lastValidBlockHeight,
    intentHash: input.intentHash,
    ringInstructionIndex: frame.setupInstructions?.length ?? 0,
    chargedOutflows: proven.chargedOutflows,
    ...boundState(proven),
  });
}

interface HeldTransaction extends RingSubmissionPending {
  unsent: Transaction | undefined;
}

/** Resolves each broadcast before retrying an unchanged payment intent. */
export class RingTransactionSubmission {
  readonly #intent: Bytes32;
  readonly #build: RingSubmissionBuild;
  readonly #reservation: ReservationHold;
  readonly #registry: Pick<ChainReader, "getAccount"> | undefined;
  readonly #wallet: Wallet | undefined;
  readonly #id: string;
  readonly #utxoHashes: readonly Bytes32[];
  #persistence: WalletPersistence | undefined;
  #attempt: RingSubmissionAttempt;
  /** `undefined` until the attempt signs and its record saves. */
  #signed: HeldTransaction | undefined;
  #record: (RingSubmissionPending & { saved: boolean }) | undefined;
  /** A record the wallet held and no longer lists was settled by `reconcileRingSubmissions`. */
  #held = false;
  #attempts = 0;
  #proved = false;
  #terminal = false;
  #busy = false;

  constructor(
    input: Readonly<{
      first: RingSubmissionAttempt;
      build: RingSubmissionBuild;
      reservation?: ReservationHold;
      /** Reads the bound registries when a proof fails. */
      registry?: Pick<ChainReader, "getAccount">;
      wallet?: Wallet;
      reservationId?: string;
      utxoHashes?: readonly Bytes32[];
    }>,
  ) {
    this.#attempt = input.first;
    this.#intent = new Uint8Array(input.first.intentHash) as Bytes32;
    this.#build = input.build;
    this.#reservation = input.reservation ?? NO_RESERVATION;
    this.#registry = input.registry;
    this.#wallet = input.wallet;
    this.#id = input.reservationId ?? bytesKey(crypto.getRandomValues(new Uint8Array(16)));
    this.#utxoHashes = (input.utxoHashes ?? []).map((hash) => new Uint8Array(hash) as Bytes32);
  }

  /** An anonymous depositor stores it before the first `send`. */
  get viewingHistory(): ViewingHistory | undefined {
    return this.#attempt.viewingHistory;
  }

  /** @internal The reservation `build` records outlives every attempt. */
  static async fromBuilder(
    input: Readonly<{
      wallet: Wallet;
      build: (
        retry: RingSubmissionBuildState,
        context?: RequestContext,
      ) => Promise<RingSubmissionAttempt>;
      registry?: Pick<ChainReader, "getAccount">;
    }>,
    context?: RequestContext,
  ): Promise<RingTransactionSubmission> {
    const retry: RingSubmissionBuildState = { lifetime: "submission" };
    const build: RingSubmissionBuild = (context) => input.build(retry, context);
    let first: RingSubmissionAttempt;
    try {
      first = await build(context);
    } catch (cause) {
      if (retry.reservation !== undefined) input.wallet._releaseReservation(retry.reservation.id);
      throw cause;
    }
    return new RingTransactionSubmission({
      first,
      build,
      wallet: input.wallet,
      ...(input.registry === undefined ? {} : { registry: input.registry }),
      ...(retry.reservation === undefined
        ? {}
        : {
            reservationId: retry.reservation.id,
            utxoHashes: retry.reservation.utxoHashes,
          }),
      reservation: {
        release: () => {
          if (retry.reservation !== undefined) {
            input.wallet._releaseReservation(retry.reservation.id);
          }
        },
        extend: () => {
          if (retry.entries !== undefined) checkRetainedEntries(input.wallet, retry.entries);
        },
      },
    });
  }

  async sendPersisted(
    input: WalletPersistence & Readonly<{ transport: RingSubmissionTransport }>,
    context?: RequestContext,
  ): Promise<RingSubmissionResult> {
    if (
      this.#busy ||
      (this.#wallet !== undefined && this.#wallet !== input.wallet) ||
      (this.#persistence !== undefined &&
        (this.#persistence.wallet !== input.wallet ||
          this.#persistence.store !== input.store ||
          this.#persistence.cipher !== input.cipher))
    )
      throw new RingError("RING_SUBMISSION_PENDING");
    this.#persistence = input;
    return this.send(input.transport, context);
  }

  /** Rust `RingSubmission::prove`, `send` signs only after the charges were read here. */
  prove(): readonly OwnerDebit[] {
    this.#proved = true;
    return this.#attempt.chargedOutflows ?? [];
  }

  cancel(): void {
    if (this.#busy || this.#signed !== undefined) throw new RingError("RING_SUBMISSION_PENDING");
    this.#terminal = true;
    this.#reservation.release();
  }

  /** Unknown submissions must resolve before another broadcast. */
  async send(
    transport: RingSubmissionTransport,
    context?: RequestContext,
  ): Promise<RingSubmissionResult> {
    if (this.#busy || this.#terminal) throw new RingError("RING_SUBMISSION_PENDING");
    // A reproof keeps the operation's amounts, so its charges are the ones `prove` showed.
    if (!this.#proved) throw new RingError("RING_SUBMISSION_UNPROVED");
    this.#busy = true;
    try {
      await this.#save();
      for (;;) {
        // 1. The transaction signs and its record saves ahead of the broadcast. The record holds the notes until the
        // signature resolves.
        const signed = this.#signed ?? (await this.#sign(transport, context));
        // 2. One broadcast per signature, a later call only reads its status.
        const { signature } = signed;
        const status: RingSubmissionStatus = this.#withheld(signed)
          ? { kind: "expired" }
          : await land(signed, transport, context);
        if (status.kind === "unknown") return this.#unknown(signature);
        if (status.kind === "confirmed") {
          this.#terminal = true;
          return { kind: "confirmed", signature, slot: status.slot, attempts: this.#attempts };
        }
        // 3. The retry decision reads the bound registries, a failed read throws with the signature held to read again.
        const retry = await this.#retries(status, context);
        // 4. The record leaves before any rebuild. A record reconcile already settled released its notes, so no
        // rebuild follows.
        const reconciled = this.#reconciled();
        this.#signed = undefined;
        await this.#dropRecord();
        if (reconciled || !retry || this.#attempts >= MAX_ATTEMPTS) {
          this.#terminal = true;
          this.#reservation.release();
          return failedSubmission({ signature, attempts: this.#attempts }, status);
        }
        this.#attempt = await this.#build(context);
      }
    } catch (cause) {
      if (this.#signed === undefined) {
        this.#holder()?._removePendingSubmission(this.#id);
        this.#record = undefined;
        this.#held = false;
        this.#terminal = true;
        this.#reservation.release();
      }
      throw cause;
    } finally {
      this.#busy = false;
    }
  }

  async #sign(
    transport: RingSubmissionTransport,
    context: RequestContext | undefined,
  ): Promise<HeldTransaction> {
    if (!equalBytes(this.#intent, this.#attempt.intentHash))
      throw new RingError("RING_INTENT_MISMATCH");
    this.#reservation.extend();
    const { signed, signature } = await signUnchanged(
      transport,
      this.#attempt.transaction,
      context,
    );
    this.#attempts += 1;
    const { lastValidBlockHeight } = this.#attempt;
    this.#record = { signature, lastValidBlockHeight, saved: false };
    await this.#save();
    this.#signed = { signature, lastValidBlockHeight, unsent: signed };
    return this.#signed;
  }

  async #retries(
    status: Extract<RingSubmissionStatus, { kind: "failed" | "expired" }>,
    context: RequestContext | undefined,
  ): Promise<boolean> {
    if (status.kind === "expired") return true;
    const ringCode =
      status.instructionIndex === this.#attempt.ringInstructionIndex
        ? status.customCode
        : undefined;
    const reproof = ringCode === undefined ? undefined : REPROOF.get(ringCode);
    return reproof === "fixes" || (reproof === "ifMoved" && (await this.#moved(context)));
  }

  #unknown(signature: Signature): RingSubmissionResult {
    return { kind: "unknown", signature, attempts: this.#attempts };
  }

  #holder(): Wallet | undefined {
    return this.#wallet ?? this.#persistence?.wallet;
  }

  /** A transaction never sent stays unsent once reconcile freed its notes. */
  #withheld(signed: HeldTransaction): boolean {
    if (signed.unsent === undefined || !this.#reconciled()) return false;
    signed.unsent = undefined;
    return true;
  }

  #reconciled(): boolean {
    const holder = this.#holder();
    return (
      this.#held &&
      holder !== undefined &&
      !holder.pendingSubmissions().some((pending) => pending.id === this.#id)
    );
  }

  async #save(): Promise<void> {
    const record = this.#record;
    if (record === undefined || record.saved) return;
    // A record written back after its reservation was released leaves a snapshot that no longer loads.
    if (this.#reconciled()) {
      this.#terminal = true;
      throw new RingError("RING_SUBMISSION_PENDING", { details: { reason: "reconciled" } });
    }
    const holder = this.#holder();
    if (holder !== undefined) {
      holder._setPendingSubmission({
        id: this.#id,
        intentHash: this.#intent,
        utxoHashes: this.#utxoHashes,
        attempts: this.#attempts,
        signature: record.signature,
        lastValidBlockHeight: record.lastValidBlockHeight,
      });
      this.#held = true;
    }
    if (this.#persistence === undefined) return;
    await savePersistedWallet(this.#persistence);
    record.saved = true;
  }

  async #dropRecord(): Promise<void> {
    this.#record = undefined;
    this.#held = false;
    this.#holder()?._removePendingSubmission(this.#id);
    if (this.#persistence !== undefined) await savePersistedWallet(this.#persistence);
  }

  /** Rust `BoundState::moved`. */
  async #moved(context?: RequestContext): Promise<boolean> {
    const { roots = [], trackingRoot, policy } = this.#attempt;
    const chain = this.#registry;
    if (chain === undefined) return false;
    if (trackingRoot !== undefined) {
      const tracking = await fetchTrackingRegistry(chain, trackingRoot.registry, context);
      const held = tracking.roots.some(
        (root) =>
          root?.revision === trackingRoot.revision && equalBytes(root.hash, trackingRoot.root),
      );
      if (!held) return true;
    }
    for (const bound of roots) {
      // Expiry is not checked here, an expired root fails on chain as `rootNotServed` and a reproof follows.
      const registry = await fetchStorageRegistry(chain, bound.registry, context);
      const held = registry.roots.some(
        (root) => root?.revision === bound.revision && equalBytes(root.hash, bound.root),
      );
      if (!held) return true;
    }
    if (policy === undefined) return false;
    const ringPolicy = await fetchRingPolicy(chain, policy.ringProgramId, context);
    return !equalBytes(ringPolicy.policyHash, policy.policyHash);
  }
}

/** Settles each record whose signature resolved, an unknown signature or a confirmed record with unspent notes stays held. */
export async function reconcileRingSubmissions(
  input: WalletPersistence & Readonly<{ transport: Pick<RingSubmissionTransport, "status"> }>,
  context?: RequestContext,
): Promise<readonly RingSubmissionResult[]> {
  const results: RingSubmissionResult[] = [];
  for (const pending of input.wallet.pendingSubmissions()) {
    const status = await input.transport.status(pending, context);
    const current = input.wallet.pendingSubmissions().find((entry) => entry.id === pending.id);
    if (current?.signature !== pending.signature) continue;
    if (status.kind === "unknown") {
      results.push({ kind: "unknown", signature: pending.signature, attempts: pending.attempts });
      continue;
    }
    if (status.kind === "confirmed") {
      const unspent = new Set(
        input.wallet
          .utxos()
          .filter((entry) => !entry.spent)
          .map((entry) => bytesKey(entry.outputContext.hash)),
      );
      if (!pending.utxoHashes.some((hash) => unspent.has(bytesKey(hash)))) {
        input.wallet._releaseReservation(pending.id);
        input.wallet._removePendingSubmission(pending.id);
      }
      results.push({
        kind: "confirmed",
        signature: pending.signature,
        attempts: pending.attempts,
        slot: status.slot,
      });
    } else {
      input.wallet._releaseReservation(pending.id);
      input.wallet._removePendingSubmission(pending.id);
      results.push(failedSubmission(pending, status));
    }
  }
  await savePersistedWallet(input);
  return results;
}

/** A signer that changes the message would sign a transaction the wallet never approved. */
async function signUnchanged(
  transport: RingSubmissionTransport,
  transaction: Transaction,
  context: RequestContext | undefined,
): Promise<Readonly<{ signed: Transaction; signature: Signature }>> {
  const approvedMessage = new Uint8Array(transaction.messageBytes);
  const signed = await transport.sign(transaction, context);
  if (!equalBytes(new Uint8Array(signed.messageBytes), approvedMessage))
    throw new RingError("RING_INTENT_MISMATCH");
  assertIsFullySignedTransaction(signed);
  return { signed, signature: getSignatureFromTransaction(signed) };
}

async function broadcast(
  transport: RingSubmissionTransport,
  signed: Transaction,
  context: RequestContext | undefined,
): Promise<RingSubmissionStatus | undefined> {
  try {
    return await transport.send(signed, context);
  } catch (cause) {
    // A send error leaves the signature pending.
    if (isClientError(cause) && cause.code === "CLIENT_ABORTED") throw cause;
    return undefined;
  }
}

async function land(
  held: HeldTransaction,
  transport: RingSubmissionTransport,
  context: RequestContext | undefined,
): Promise<RingSubmissionStatus> {
  const { signature, lastValidBlockHeight, unsent } = held;
  // Cleared first, an aborted broadcast stays held and never sends again.
  held.unsent = undefined;
  const status = unsent === undefined ? undefined : await broadcast(transport, unsent, context);
  return status ?? (await readStatus(transport, { signature, lastValidBlockHeight }, context));
}

async function readStatus(
  transport: RingSubmissionTransport,
  pending: RingSubmissionPending,
  context: RequestContext | undefined,
): Promise<RingSubmissionStatus> {
  try {
    return await transport.status(pending, context);
  } catch {
    return { kind: "unknown" };
  }
}

function failedSubmission(
  pending: Pick<PendingWalletSubmission, "signature" | "attempts">,
  status: Extract<RingSubmissionStatus, { kind: "failed" | "expired" }>,
): RingSubmissionResult {
  return {
    kind: "failed",
    signature: pending.signature,
    attempts: pending.attempts,
    ...(status.kind !== "failed" || status.instructionIndex === undefined
      ? {}
      : { instructionIndex: status.instructionIndex }),
    ...(status.kind !== "failed" || status.customCode === undefined
      ? {}
      : { customCode: status.customCode }),
  };
}

/** @internal */
export function checkRetainedEntries(wallet: Wallet, entries: readonly WalletUtxo[]): void {
  const current = wallet.utxos();
  for (const entry of entries) {
    const unspent = current.some(
      (known) => !known.spent && equalBytes(known.outputContext.hash, entry.outputContext.hash),
    );
    if (!unspent) {
      throw new RingError("RING_RESERVED_INPUT_SPENT", {
        details: { utxoHash: bytesKey(entry.outputContext.hash) },
      });
    }
  }
  checkSpendCoverage(wallet, entries);
}

export function createKitRingSubmissionTransport(
  client: KitRpcAccess,
  signers: readonly TransactionPartialSigner[],
): RingSubmissionTransport {
  const heldSigners = [...signers];
  const send = sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc });
  return {
    // The kit refuses a signer the message does not name.
    sign: async (transaction, context) =>
      runKitRpc("signTransaction", context, (abortSignal) =>
        signTransactionWithSigners(
          heldSigners.filter((signer) => signer.address in transaction.signatures),
          transaction,
          { abortSignal },
        ),
      ),
    send: async (transaction, context) => {
      assertIsFullySignedTransaction(transaction);
      assertIsTransactionWithinSizeLimit(transaction);
      assertVersion1Transaction(transaction);
      return runKitRpc("sendTransaction", context, async (abortSignal) => {
        try {
          await send(transaction, { commitment: client.commitment, abortSignal });
          return undefined;
        } catch (cause) {
          const refusal = preflightRefusal(cause);
          if (refusal === undefined) throw cause;
          return refusal;
        }
      });
    },
    status: async (pending, context) => {
      const status = await readSignatureStatus(client, pending.signature, context);
      if (status !== null) return status;
      const height = await runKitRpc("getBlockHeight", context, (abortSignal) =>
        client.solanaRpc.getBlockHeight({ commitment: client.commitment }).send({ abortSignal }),
      );
      if (height <= pending.lastValidBlockHeight) return { kind: "unknown" };
      // Expiry cannot settle an absence observed before the last valid block.
      return (
        (await readSignatureStatus(client, pending.signature, context)) ?? {
          kind: "expired",
        }
      );
    },
  };
}

async function readSignatureStatus(
  client: KitRpcAccess,
  signature: Signature,
  context?: RequestContext,
): Promise<RingSubmissionStatus | null> {
  const response = await runKitRpc("getSignatureStatuses", context, (abortSignal) =>
    client.solanaRpc
      .getSignatureStatuses([signature], { searchTransactionHistory: true })
      .send({ abortSignal }),
  );
  if (response.value.length !== 1) return { kind: "unknown" };
  const status = response.value[0];
  if (status === undefined) return { kind: "unknown" };
  if (status === null) return null;
  if (status.confirmationStatus !== "confirmed" && status.confirmationStatus !== "finalized")
    return { kind: "unknown" };
  if (status.err === null) return { kind: "confirmed", slot: status.slot };
  return failedStatus(status.err);
}

/** The node's simulation refused the transaction, nothing was broadcast. */
function preflightRefusal(cause: unknown): RingSubmissionStatus | undefined {
  if (
    !isSolanaError(cause, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE)
  )
    return undefined;
  const refusal: unknown = cause.cause;
  // A blockhash past its window rebuilds as Rust `reproof_fixes` does.
  if (isSolanaError(refusal, SOLANA_ERROR__TRANSACTION_ERROR__BLOCKHASH_NOT_FOUND))
    return { kind: "expired" };
  if (isSolanaError(refusal, SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM)) {
    return {
      kind: "failed",
      instructionIndex: refusal.context.index,
      customCode: refusal.context.code,
    };
  }
  return { kind: "failed" };
}

/** Only `InstructionError: [index, { Custom }]` carries a program code. */
function failedStatus(error: unknown): RingSubmissionStatus {
  if (
    typeof error !== "object" ||
    error === null ||
    !("InstructionError" in error) ||
    !Array.isArray(error.InstructionError)
  )
    return { kind: "failed" };
  const [index, detail] = error.InstructionError;
  if (
    typeof index !== "number" ||
    !Number.isSafeInteger(index) ||
    index < 0 ||
    typeof detail !== "object" ||
    detail === null ||
    !("Custom" in detail) ||
    typeof detail.Custom !== "number" ||
    !Number.isSafeInteger(detail.Custom)
  )
    return { kind: "failed" };
  return { kind: "failed", instructionIndex: index, customCode: detail.Custom };
}
