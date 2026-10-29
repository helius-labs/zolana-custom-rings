/** Ring transfers from a wallet, every flow selects, reserves, approves, proves and compiles through one driver. */
import type { Instruction } from "@solana/kit";

import type { BlockhashProvider, WalletKeys } from "@heliuslabs/zolana/client";
import {
  compileUnsignedTransaction,
  reserveEntries,
  reservedUtxoKeys,
  unreserved,
  selectUtxos,
  resolveWithdrawalSettlement,
  withdrawalSetupInstructions,
  signerAddress,
  type SignerAccount,
  MAX_TRANSACT_INPUTS,
  ownerSolanaAccount,
  withdrawalIntentRecipient,
  equalBytes,
  resolveShieldedRecipient,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import { SPP_SUPPORTED_SHAPES } from "@heliuslabs/zolana/interface";
import type {
  Address,
  Bytes32,
  RequestContext,
  Transaction,
  TransactWithdrawal,
} from "@heliuslabs/zolana/interface";
import { ShieldedAddress, type NullifierKey } from "@heliuslabs/zolana/keypair";
import {
  SOL_MINT,
  ConfidentialTransfer,
  type PreparedTransfer,
} from "@heliuslabs/zolana/transaction";
import {
  approveRingUnattended,
  checkRingIntentApproval,
  checkRingPreparedTransfer,
  ringIntentHash,
  type RingApprovalHandler,
  type RingTransactionIntent,
} from "../../protocol/transaction/intent.js";
import type { Wallet, WalletUtxo } from "@heliuslabs/zolana/transaction";
import { anonymousAuditKey } from "../../protocol/codec/ring-disclosure-layout.js";
import { RingAddress, RingPaymentRequest } from "../../crypto/keys/ring-address.js";

import { RingInstructionTag, ringComputeUnitLimit } from "../management/admin.js";
import { carriesNoData, type AnonymousPayment, type AnonymousSpendSigner } from "./anonymous.js";
import { fetchRingProgramConfig } from "../../protocol/membership/config.js";
import { RingError, wrapRingError } from "../../protocol/error.js";
import { boundState } from "../workflow/pipeline.js";
import {
  CustomRingTransfer,
  type CustomRingTransferClient,
  type PreparedRingRelay,
  type RingTransferApproval,
} from "./transfer-rails.js";
import type { RelayQuote, TokenAccountSetup } from "../../protocol/ring-rpc/ring-rpc-types.js";
import type { PreparedRelay } from "../../rpc/relay.js";
import { ringIntentMismatch, ringProofInput, ringSelectionErrors } from "../workflow/selection.js";
import {
  RingTransactionSubmission,
  checkRetainedEntries,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "../workflow/submission.js";
import { resolveRingOutputTree } from "../../protocol/membership/trees.js";
import type { FirstContact, ViewingHistory } from "../../state/viewing-history.js";

export type RingTransferClient = CustomRingTransferClient & BlockhashProvider;

/** The owner signs the message hash inside the proof. */
export interface RingRelaySpend {
  /** Names the fee payer the transfer pays from. */
  readonly quote: RelayQuote;
  /** Ring RPC proves with it and so links every spend of the owner. */
  readonly nullifierKey: NullifierKey;
  /** Must hold the sender's signing key. */
  readonly signer: AnonymousSpendSigner;
}

/** The only spend of an anonymous ring. */
export interface AnonymousRingSpend extends RingRelaySpend {
  /** Store `PreparedRingRelay.viewingHistory` in its place before `relay.send`. */
  readonly history: ViewingHistory;
  /** The tag a payment to a `RingAddress` takes until the pair is known, chosen by the caller. */
  readonly firstContact?: FirstContact;
  /** A missing SPL exit token account must be the owner's associated token account. */
  readonly exitTokenOwner?: Address;
}

/** What every ring spend names, each flow adds its recipient. */
export interface RingSpendParams {
  readonly client: RingTransferClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  readonly keys: WalletKeys;
  readonly feePayer: Address;
  readonly approve?: RingApprovalHandler;
  readonly asset?: Address;
  readonly amount: bigint;
  /** Receives every private output, defaults to `client.tree`. */
  readonly outputTree?: Address;
  /** Signs when the ring demands a co-signer, its record must cover the demand. */
  readonly cosigner?: SignerAccount;
  readonly priorityFeeLamports?: bigint;
}

/** `anonymous` on an anonymous ring, `confidential` on any other. */
export type RingRelayRail =
  | Readonly<{ anonymous: AnonymousRingSpend; confidential?: never }>
  | Readonly<{ confidential: RingRelaySpend; anonymous?: never }>;

/** Ring RPC pays and co-signs a relayed spend. */
export type RingRelaySpendParams<
  P extends RingSpendParams = RingSpendParams,
  R extends RingRelayRail = RingRelayRail,
> = Omit<P, "feePayer" | "cosigner" | "priorityFeeLamports"> & R;

export type PreparedSpendRelay<R extends RingRelayRail> =
  R extends Readonly<{
    anonymous: AnonymousRingSpend;
  }>
    ? PreparedRingRelay
    : Readonly<{ relay: PreparedRelay }>;

export interface RingTransferTransactionParams extends RingSpendParams {
  /** A ring address or payment request on an anonymous ring, a shielded address or a registered owner on any other. */
  readonly recipient: Address | ShieldedAddress | RingAddress | RingPaymentRequest;
  /** `"default"` funds only from default UTXOs. `"ring-or-default"` mixes both pools, an anonymous ring funds from one pool alone. */
  readonly inputs?: "ring" | "ring-or-default" | "default";
}

export type RingEntryTransactionParams = RingSpendParams;

export interface RingExitTransactionParams extends RingSpendParams {
  readonly recipient: Address | ShieldedAddress;
}

export interface RingWithdrawalTransactionParams extends RingSpendParams {
  /** Any Solana account. It needs no registry record and need not exist yet. */
  readonly recipient: Address;
  /** SPL Token or Token-2022 for non-SOL assets, the settlement lands in the recipient's ATA. */
  readonly splTokenProgram?: Address;
}

/** Unsigned, the fee payer and any co-signer sign. */
export async function buildRingTransferTransaction(
  input: RingTransferTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (await buildRingSend({ params: input, destination: "ring", retry: {} }, context))
    .transaction;
}

export function createRingTransferSubmission(
  input: RingTransferTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: input.wallet,
      registry: input.client,
      build: (retry, buildContext) =>
        buildRingSend({ params: input, destination: "ring", retry }, buildContext),
    },
    context,
  );
}

/**
 * Value leaves the ring to a default-ring UTXO of the recipient, and the audit proof still covers
 * the exit. Only ring-bound UTXOs fund it.
 */
export async function buildRingExitTransaction(
  input: RingExitTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (await buildRingSend({ params: input, destination: "default", retry: {} }, context))
    .transaction;
}

export function createRingExitSubmission(
  input: RingExitTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: input.wallet,
      registry: input.client,
      build: (retry, buildContext) =>
        buildRingSend({ params: input, destination: "default", retry }, buildContext),
    },
    context,
  );
}

/** Default UTXOs of the sender enter the ring as its own ring notes. */
export async function buildRingEntryTransaction(
  input: RingEntryTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (await buildRingEntry({ params: input, retry: {} }, context)).transaction;
}

export function createRingEntrySubmission(
  input: RingEntryTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: input.wallet,
      registry: input.client,
      build: (retry, buildContext) => buildRingEntry({ params: input, retry }, buildContext),
    },
    context,
  );
}

/**
 * Value leaves the ring to a plain Solana account. The recipient, the amount and the asset are
 * public, and the audit proof still covers the exit.
 */
export async function buildRingWithdrawalTransaction(
  input: RingWithdrawalTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (await buildRingWithdrawal({ params: input, retry: {} }, context)).transaction;
}

export function createRingWithdrawalSubmission(
  input: RingWithdrawalTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: input.wallet,
      registry: input.client,
      build: (retry, buildContext) => buildRingWithdrawal({ params: input, retry }, buildContext),
    },
    context,
  );
}

/** Ring RPC reads the paths and records, proves and sends. */
export function prepareRingTransferRelay<R extends RingRelayRail>(
  input: RingRelaySpendParams<RingTransferTransactionParams, R>,
  context?: RequestContext,
): Promise<PreparedSpendRelay<R>> {
  return relayRingSpend({ params: input, strategy: sendStrategy(input, "ring") }, context);
}

export function prepareRingExitRelay<R extends RingRelayRail>(
  input: RingRelaySpendParams<RingExitTransactionParams, R>,
  context?: RequestContext,
): Promise<PreparedSpendRelay<R>> {
  return relayRingSpend({ params: input, strategy: sendStrategy(input, "default") }, context);
}

export function prepareRingEntryRelay<R extends RingRelayRail>(
  input: RingRelaySpendParams<RingEntryTransactionParams, R>,
  context?: RequestContext,
): Promise<PreparedSpendRelay<R>> {
  return relayRingSpend({ params: input, strategy: entryStrategy(input) }, context);
}

export function prepareRingWithdrawalRelay<R extends RingRelayRail>(
  input: RingRelaySpendParams<RingWithdrawalTransactionParams, R>,
  context?: RequestContext,
): Promise<PreparedSpendRelay<R>> {
  return relayRingSpend(
    {
      params: input,
      strategy: withdrawalStrategy({ ...input, feePayer: relaySpend(input).quote.feePayer }),
    },
    context,
  );
}

/** UTXOs on `tree` the mode admits, largest first, at most `maxInputs`. */
export function selectRingInputs(
  input: Readonly<{
    wallet: Wallet;
    ringProgramId: Address;
    asset: Address;
    amount: bigint;
    inputs: "ring" | "ring-or-default" | "default" | "entry";
    tree: Address;
    maxInputs: number;
  }>,
): readonly WalletUtxo[] {
  const { wallet, ringProgramId, asset, amount, inputs } = input;
  // Zero selects a UTXO whose whole change would cross the ring boundary.
  if (amount <= 0n) throw new RingError("RING_ZERO_AMOUNT", { details: { asset } });
  const reserved = reservedUtxoKeys(wallet);
  return selectUtxos({
    wallet,
    asset,
    target: { kind: "cover", amount },
    policy: {
      eligible: (entry) => {
        if (!unreserved(reserved)(entry)) return false;
        if (entry.utxo.ringProgramId === ringProgramId)
          return inputs === "ring" || inputs === "ring-or-default";
        return (
          inputs !== "ring" &&
          entry.utxo.ringProgramId === undefined &&
          entry.ringDataHash === undefined &&
          (inputs !== "entry" || carriesNoData([entry.dataHash]))
        );
      },
      ordering: "largestFirst",
      allowWideBalance: true,
      maxInputs: input.maxInputs,
      tree: { kind: "fixed", tree: input.tree },
      errors: ringSelectionErrors,
    },
  }).entries;
}

function buildRingSend(
  input: Readonly<{
    params: RingTransferTransactionParams | RingExitTransactionParams;
    destination: "ring" | "default";
    retry: RingSubmissionBuildState;
  }>,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const { params, destination, retry } = input;
  return buildRingSpend({ params, strategy: sendStrategy(params, destination), retry }, context);
}

function buildRingEntry(
  input: Readonly<{ params: RingEntryTransactionParams; retry: RingSubmissionBuildState }>,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const { params, retry } = input;
  return buildRingSpend({ params, strategy: entryStrategy(params), retry }, context);
}

function buildRingWithdrawal(
  input: Readonly<{ params: RingWithdrawalTransactionParams; retry: RingSubmissionBuildState }>,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const { params, retry } = input;
  return buildRingSpend({ params, strategy: withdrawalStrategy(params), retry }, context);
}

type SendParams = SpendBase &
  Pick<RingTransferTransactionParams, "recipient"> &
  Partial<Pick<RingTransferTransactionParams, "inputs">> &
  Readonly<{ anonymous?: AnonymousRingSpend }>;

function sendStrategy(
  params: SendParams,
  destination: "ring" | "default",
): RingSpendStrategy<ShieldedAddress | AnonymousRecipient> {
  return {
    errorCode: "RING_BUILD_TRANSFER",
    relay: destination === "ring" ? "prepareRingTransferRelay" : "prepareRingExitRelay",
    selection: destination === "ring" ? (params.inputs ?? "ring") : "ring",
    resolve: (context) => resolveSendRecipient(params, destination, context),
    configure: ({ transfer, resolved, selected, asset, payment }) => {
      // Change of a default UTXO becomes ring bound.
      const defaultFunding = selected
        .filter((entry) => entry.utxo.ringProgramId === undefined)
        .reduce((sum, entry) => sum + entry.utxo.amount, 0n);
      const crossing =
        defaultFunding === 0n
          ? ""
          : `, moves ${String(defaultFunding)} ${assetLabel(asset)} of default UTXOs into the ring`;
      if (!(resolved instanceof ShieldedAddress)) {
        payment(resolved.to, resolved.firstContact, asset, params.amount);
        return {
          intent: {
            kind: "ringAnonymousTransfer",
            ringProgramId: params.ringProgramId,
            asset,
            amount: params.amount,
            recipient: resolved.to,
            defaultFunding,
          },
          summary: `anonymous ring payment of ${String(params.amount)} ${assetLabel(asset)} in ring ${params.ringProgramId}${crossing}`,
        };
      }
      if (destination === "ring") transfer.send(resolved, asset, params.amount);
      else transfer.sendDefaultRing(resolved, asset, params.amount);
      const boundary =
        destination === "default" ? "exit" : defaultFunding > 0n ? "entry" : "transfer";
      return {
        intent: {
          kind: "ringTransfer",
          ringProgramId: params.ringProgramId,
          asset,
          amount: params.amount,
          recipient: resolved,
          boundary,
          defaultFunding,
        },
        summary: `ring ${boundary} of ${String(params.amount)} ${assetLabel(asset)} in ring ${params.ringProgramId} to a shielded address${crossing}`,
      };
    },
  };
}

function entryStrategy(params: SpendBase): RingSpendStrategy<undefined> {
  return {
    errorCode: "RING_BUILD_ENTRY",
    relay: "prepareRingEntryRelay",
    selection: "default",
    resolve: () => Promise.resolve(undefined),
    configure: ({ transfer, owner, asset }) => {
      transfer.sendToRing(owner, asset, params.amount, params.ringProgramId);
      return {
        intent: {
          kind: "ringEntry",
          ringProgramId: params.ringProgramId,
          asset,
          amount: params.amount,
        },
        summary: `ring entry of ${String(params.amount)} ${assetLabel(asset)} into ring ${params.ringProgramId}`,
      };
    },
  };
}

type WithdrawalParams = SpendBase &
  Pick<RingWithdrawalTransactionParams, "recipient" | "splTokenProgram" | "feePayer">;

function withdrawalStrategy(params: WithdrawalParams): RingSpendStrategy<
  Readonly<{
    settlement: Awaited<ReturnType<typeof resolveWithdrawalSettlement>>;
    setupInstructions: readonly Instruction[];
  }>
> {
  return {
    errorCode: "RING_BUILD_WITHDRAWAL",
    relay: "prepareRingWithdrawalRelay",
    selection: "ring",
    resolve: async () => {
      const asset = params.asset ?? SOL_MINT;
      const [settlement, setupInstructions] = await Promise.all([
        resolveWithdrawalSettlement(params.recipient, asset, params.splTokenProgram),
        withdrawalSetupInstructions({
          payer: params.feePayer,
          recipient: params.recipient,
          asset,
          ...(params.splTokenProgram === undefined
            ? {}
            : { splTokenProgram: params.splTokenProgram }),
        }),
      ]);
      return { settlement, setupInstructions };
    },
    configure: ({ transfer, resolved, asset }) => {
      transfer.withdraw(asset, params.amount, resolved.settlement.target);
      return {
        intent: {
          kind: "ringWithdrawal",
          ringProgramId: params.ringProgramId,
          asset,
          amount: params.amount,
          recipient: withdrawalIntentRecipient(resolved.settlement.target),
        },
        summary: `public withdrawal of ${String(params.amount)} ${assetLabel(asset)} from ring ${params.ringProgramId} to ${params.recipient}`,
        withdrawal: resolved.settlement.accounts,
        setupInstructions: resolved.setupInstructions,
        ...(resolved.setupInstructions.length === 0
          ? {}
          : { tokenAccountSetup: [{ owner: params.recipient, mint: asset }] }),
      };
    },
  };
}

interface RingSpendPlan {
  readonly intent: RingTransactionIntent;
  readonly summary: string;
  readonly withdrawal?: TransactWithdrawal;
  readonly setupInstructions?: readonly Instruction[];
  /** The accounts Ring RPC creates in place of `setupInstructions`. */
  readonly tokenAccountSetup?: readonly TokenAccountSetup[];
}

interface RingSpendStrategy<R> {
  readonly errorCode: "RING_BUILD_ENTRY" | "RING_BUILD_TRANSFER" | "RING_BUILD_WITHDRAWAL";
  /** The flow an anonymous ring relays through. */
  readonly relay:
    | "prepareRingEntryRelay"
    | "prepareRingExitRelay"
    | "prepareRingTransferRelay"
    | "prepareRingWithdrawalRelay";
  readonly selection: "ring" | "ring-or-default" | "default";
  resolve(context: RequestContext | undefined): Promise<R>;
  configure(
    input: Readonly<{
      transfer: ConfidentialTransfer;
      resolved: R;
      selected: readonly WalletUtxo[];
      asset: Address;
      owner: ShieldedAddress;
      /** Pays a ring address on the anonymous rail. */
      payment: (
        to: RingAddress,
        firstContact: FirstContact,
        asset: Address,
        amount: bigint,
      ) => void;
    }>,
  ): RingSpendPlan;
}

type SpendBase = Omit<RingSpendParams, "feePayer" | "cosigner" | "priorityFeeLamports">;

/** The spend selected, reserved and configured, before its rail proves or relays it. */
interface StagedSpend {
  readonly selected: readonly WalletUtxo[];
  readonly rail: CustomRingTransfer;
  readonly plan: RingSpendPlan;
  readonly planned: Bytes32;
  readonly anonymousPayment: AnonymousPayment | undefined;
  readonly owner: ShieldedAddress;
}

/** One build attempt, the reservation `retry` holds survives every rebuild of a submission. */
async function buildRingSpend<R>(
  input: Readonly<{
    params: RingSpendParams;
    strategy: RingSpendStrategy<R>;
    retry: RingSubmissionBuildState;
  }>,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const { params, strategy, retry } = input;
  try {
    const staged = await stageRingSpend(
      {
        params,
        feePayer: params.feePayer,
        strategy,
        retry,
        route: "direct",
        ...(params.cosigner === undefined ? {} : { coSigner: signerAddress(params.cosigner) }),
      },
      context,
    );
    const { plan, owner } = staged;
    const approval: RingTransferApproval = {
      transaction: {
        ...(params.priorityFeeLamports === undefined
          ? {}
          : { priorityFeeLamports: params.priorityFeeLamports }),
        ...(plan.setupInstructions === undefined
          ? {}
          : { setupInstructions: plan.setupInstructions }),
      },
      approve: async ({ prepared }) => {
        await approveSpend({ params, feePayer: params.feePayer, plan, owner, prepared });
      },
    };
    const proven = await staged.rail.proveApproved(params.client, approval, context);
    const [instruction, lifetime] = await Promise.all([
      proven.instruction(),
      params.client.getLatestBlockhash(context),
    ]);
    const transaction = compileUnsignedTransaction({
      ...approval.transaction,
      feePayer: params.feePayer,
      lifetime,
      computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.transfer),
      instructions: [instruction],
    });
    return Object.freeze({
      transaction,
      lastValidBlockHeight: lifetime.lastValidBlockHeight,
      intentHash: staged.planned,
      ringInstructionIndex: plan.setupInstructions?.length ?? 0,
      ...boundState(proven),
    });
  } catch (cause) {
    if (retry.reservation !== undefined) params.wallet._releaseReservation(retry.reservation.id);
    throw wrapRingError(strategy.errorCode, cause);
  }
}

/** The relayed terminal, the selected notes stay leased for `DEFAULT_RESERVATION_TTL_MS`. */
async function relayRingSpend<S, R extends RingRelayRail>(
  input: Readonly<{
    params: SpendBase & R;
    strategy: RingSpendStrategy<S>;
  }>,
  context: RequestContext | undefined,
): Promise<PreparedSpendRelay<R>> {
  const { params, strategy } = input;
  const spend = relaySpend(params);
  const { anonymous } = params;
  const retry: RingSubmissionBuildState = {};
  try {
    const staged = await stageRingSpend(
      {
        params,
        feePayer: spend.quote.feePayer,
        strategy,
        retry,
        route: anonymous === undefined ? "confidentialRelay" : "anonymousRelay",
      },
      context,
    );
    const { plan, owner } = staged;
    const relayInput = {
      quote: spend.quote,
      nullifierKey: spend.nullifierKey,
      notes: staged.selected,
      ...(plan.tokenAccountSetup === undefined
        ? {}
        : { tokenAccountSetup: plan.tokenAccountSetup }),
    };
    const approval: RingTransferApproval = {
      transaction: {},
      approve: ({ prepared }) =>
        approveSpend({ params, feePayer: spend.quote.feePayer, plan, owner, prepared }),
    };
    // `R` holds `anonymous` exactly when the spend returns a viewing history.
    if (anonymous === undefined)
      return Object.freeze({
        relay: await staged.rail
          .withInProofOwner(spend.signer)
          .prepareRelayApproved(params.client, relayInput, approval, context),
      }) as PreparedSpendRelay<R>;
    let transfer = staged.rail.withAnonymousSigner(anonymous.signer, anonymous.history);
    if (staged.anonymousPayment !== undefined)
      transfer = transfer.withPayment(staged.anonymousPayment);
    if (anonymous.exitTokenOwner !== undefined)
      transfer = transfer.withExitTokenOwner(anonymous.exitTokenOwner);
    return (await transfer.prepareRelayApproved(
      params.client,
      relayInput,
      approval,
      context,
    )) as PreparedSpendRelay<R>;
  } catch (cause) {
    if (retry.reservation !== undefined) params.wallet._releaseReservation(retry.reservation.id);
    throw wrapRingError(strategy.errorCode, cause);
  }
}

function relaySpend(rail: RingRelayRail): RingRelaySpend {
  return rail.anonymous === undefined ? rail.confidential : rail.anonymous;
}

/** Each route's refusal on a ring whose mode it does not serve. */
const MODE_REFUSALS = Object.freeze({
  direct: "RING_ANONYMOUS_RELAY_REQUIRED",
  anonymousRelay: "RING_NOT_ANONYMOUS",
  confidentialRelay: "RING_ANONYMOUS_SIGNER_REQUIRED",
} as const);

/** `retry` keeps the reservation for the caller to release. */
async function stageRingSpend<R>(
  input: Readonly<{
    params: SpendBase;
    feePayer: Address;
    strategy: RingSpendStrategy<R>;
    retry: RingSubmissionBuildState;
    route: keyof typeof MODE_REFUSALS;
    coSigner?: Address;
  }>,
  context: RequestContext | undefined,
): Promise<StagedSpend> {
  const { params, strategy, retry, route } = input;
  const anonymousRing = route === "anonymousRelay";
  await initializePoseidon();
  const asset = params.asset ?? SOL_MINT;
  const owner = params.keys.address();
  const [resolved, config, outputTree] = await Promise.all([
    strategy.resolve(context),
    fetchRingProgramConfig(params.client, params.ringProgramId, context),
    resolveRingOutputTree(params.client, params.outputTree, context),
  ]);
  if (anonymousRing !== (config.mode === "anonymous"))
    throw new RingError(MODE_REFUSALS[route], {
      details: {
        ringProgramId: params.ringProgramId,
        ...(route === "direct" ? { use: strategy.relay } : {}),
      },
    });
  if (retry.entries !== undefined) checkRetainedEntries(params.wallet, retry.entries);
  const pool = {
    wallet: params.wallet,
    ringProgramId: params.ringProgramId,
    asset,
    amount: params.amount,
    tree: params.client.tree,
  };
  const selected =
    retry.entries ??
    (anonymousRing
      ? selectAnonymousInputs(pool, strategy.selection)
      : selectRingInputs({
          ...pool,
          inputs: strategy.selection,
          maxInputs: MAX_TRANSACT_INPUTS,
        }));
  retry.reservation = retry.reservation ?? reserveEntries(params.wallet, selected, retry.lifetime);
  retry.entries = selected;
  const transfer = new ConfidentialTransfer(
    owner,
    selected.map((entry) => ringProofInput(entry, owner, params.client)),
    input.feePayer,
  ).withOutputTreeId(outputTree.treeId);
  let anonymousPayment: AnonymousPayment | undefined;
  const plan = strategy.configure({
    transfer,
    resolved,
    selected,
    asset,
    owner,
    payment: (to, firstContact, paidAsset, amount) => {
      if (!anonymousRing || anonymousPayment !== undefined)
        throw new RingError("RING_NOT_ANONYMOUS", {
          details: { ringProgramId: params.ringProgramId },
        });
      anonymousPayment = { to, firstContact, asset: paidAsset, amount };
    },
  });
  const planned = ringIntentHash(plan.intent);
  if (retry.intent !== undefined && !equalBytes(retry.intent, planned))
    throw ringIntentMismatch("retryIntent");
  retry.intent = planned;
  const ownerRail = CustomRingTransfer.new({
    ringProgramId: params.ringProgramId,
    keys: params.keys,
    transfer,
    assets: params.wallet.registry,
    ...(input.coSigner === undefined ? {} : { coSigner: input.coSigner }),
  });
  return Object.freeze({
    selected,
    rail:
      plan.withdrawal === undefined ? ownerRail : ownerRail.withWithdrawalAccounts(plan.withdrawal),
    plan,
    planned,
    anonymousPayment,
    owner,
  });
}

async function approveSpend(
  input: Readonly<{
    params: SpendBase;
    feePayer: Address;
    plan: RingSpendPlan;
    owner: ShieldedAddress;
    prepared: PreparedTransfer;
  }>,
): Promise<void> {
  const { params, plan } = input;
  const approved = await (params.approve ?? approveRingUnattended)({
    solanaPublicKey: ownerSolanaAccount(input.owner, input.feePayer),
    intent: plan.intent,
    summary: plan.summary,
  });
  checkRingIntentApproval(approved, plan.intent, ringIntentMismatch);
  checkRingPreparedTransfer(input.prepared, plan.intent, ringIntentMismatch);
}

/** A spend pays its recipient or exit and returns change. */
const SPEND_OUTPUTS = 2;

/** The prover refuses a spend mixing ring and default-ring UTXOs, ring UTXOs alone fund it first. */
function selectAnonymousInputs(
  pool: Omit<Parameters<typeof selectRingInputs>[0], "inputs" | "maxInputs">,
  selection: "ring" | "ring-or-default" | "default",
): readonly WalletUtxo[] {
  const select = (inputs: "ring" | "entry") =>
    selectRingInputs({ ...pool, inputs, maxInputs: anonymousInputCap(inputs) });
  if (selection !== "ring-or-default") return select(selection === "ring" ? "ring" : "entry");
  try {
    return select("ring");
  } catch (ringAlone) {
    if (!unfunded(ringAlone)) throw ringAlone;
    try {
      return select("entry");
    } catch (defaultAlone) {
      if (!unfunded(defaultAlone)) throw defaultAlone;
      throw ringAlone;
    }
  }
}

function unfunded(cause: unknown): boolean {
  return (
    cause instanceof RingError &&
    (cause.code === "RING_INSUFFICIENT_BALANCE" || cause.code === "RING_TOO_MANY_INPUTS")
  );
}

/** Padded inputs are published, the widest two-output shape an anonymous key serves bounds a spend. */
function anonymousInputCap(selection: "ring" | "entry"): number {
  const spendsDefaultRing = selection === "entry";
  return Math.max(
    ...SPP_SUPPORTED_SHAPES.filter(
      (shape) =>
        shape.outputs === SPEND_OUTPUTS &&
        anonymousAuditKey({ inputs: shape.inputs, outputs: shape.outputs, spendsDefaultRing }) !==
          undefined,
    ).map((shape) => shape.inputs),
  );
}

type AnonymousRecipient = Readonly<{ to: RingAddress; firstContact: FirstContact }>;

/** A ring address or request pays on the anonymous rail, any other recipient resolves to its shielded address. */
async function resolveSendRecipient(
  params: SendParams,
  destination: "ring" | "default",
  context: RequestContext | undefined,
): Promise<ShieldedAddress | AnonymousRecipient> {
  const { recipient } = params;
  if (recipient instanceof RingAddress || recipient instanceof RingPaymentRequest) {
    const to = recipient instanceof RingAddress ? recipient : recipient.address;
    if (destination !== "ring" || to.ringProgramId !== params.ringProgramId)
      throw new RingError("RING_FOREIGN_RING", {
        details: { address: to.ringProgramId, ring: params.ringProgramId },
      });
    return Object.freeze({ to, firstContact: firstContactOf(params, recipient) });
  }
  return resolveShieldedRecipient(
    { rpc: params.client, recipient },
    (unregistered) =>
      new RingError("RING_BUILD_TRANSFER", {
        details: { reason: "recipient not registered", recipient: unregistered },
      }),
    context,
  );
}

/** A request names its tag, amount and mint, a bare address takes the caller's explicit choice. */
function firstContactOf(
  params: SendParams,
  recipient: RingAddress | RingPaymentRequest,
): FirstContact {
  const chosen = params.anonymous?.firstContact;
  if (recipient instanceof RingAddress) {
    if (chosen === undefined) throw new RingError("RING_FIRST_CONTACT_REQUIRED");
    return chosen;
  }
  const asset = params.asset ?? SOL_MINT;
  if (chosen !== undefined) throw ringIntentMismatch("firstContact");
  if (recipient.amount !== undefined && recipient.amount !== params.amount)
    throw ringIntentMismatch("amount");
  if (recipient.mint !== undefined && recipient.mint !== asset) throw ringIntentMismatch("asset");
  return Object.freeze({ kind: "request", tag: recipient.requestViewTag });
}

export function assetLabel(asset: Address): string {
  return asset === SOL_MINT ? "SOL" : asset;
}
