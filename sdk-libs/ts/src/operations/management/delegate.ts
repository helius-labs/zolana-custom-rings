/** Delegate moves from a wallet, the configured delegate signs and the member does not. */
import { NullifierKeyProofAuthority } from "@heliuslabs/spr/client";
import type {
  BlockhashProvider,
  KitRpcAccess,
  ProofAuthority,
  ProofService,
  WalletKeys,
} from "@heliuslabs/spr/client";
import {
  reserveEntries,
  reservedUtxoKeys,
  unreserved,
  signerAddress,
  type SignerAccount,
  checkIntentApproval,
  checkPreparedTransfer,
  checkTransactionIntent,
  ownerSolanaAccount,
  type UtxoReservation,
  bytesKey,
  encodeBase58,
  equalBytes,
  fetchSplAssetRegistrations,
} from "@heliuslabs/spr/internal";
import type { Address, Bytes32, RequestContext, Transaction } from "@heliuslabs/spr/interface";
import type { NullifierKey, ShieldedAddress } from "@heliuslabs/spr/keypair";
import {
  approveUnattended,
  intentHash,
  type ApprovalHandler,
  type TransactionIntent,
  Wallet,
  type WalletUtxo,
} from "@heliuslabs/spr/transaction";

import { RingError, wrapRingError } from "../../protocol/error.js";
import {
  DelegateTransfer,
  type DelegateOutput,
  type DelegateTransferClient,
  type DelegateWithdrawal,
  type RingTransferApproval,
} from "../payments/transfer-rails.js";
import { standIn, type CoOwner } from "../payments/ring-spend.js";
import {
  ringIntentMismatch,
  ringProofInputs,
  ringSelectionErrors,
  selectFunding,
  type Cover,
} from "../workflow/selection.js";
import {
  RingTransactionSubmission,
  checkRetainedEntries,
  provenRingAttempt,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "../workflow/submission.js";
import { RING_AUTHORITY_SHAPES } from "../../protocol/transaction/spp.js";

export type RingDelegateTransferClient = DelegateTransferClient & BlockhashProvider & KitRpcAccess;

/** Builds a move authorized by the configured Solana delegate. */
export interface RingDelegateTransferParams {
  readonly client: RingDelegateTransferClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  /** The source is not a required Solana signer. */
  readonly source: WalletKeys;
  readonly approve?: ApprovalHandler;
  readonly delegate: SignerAccount;
  readonly feePayer: Address;
  readonly outputs: readonly DelegateOutput[];
  /** A public withdrawal, a delegate takes no deposit leg. */
  readonly withdrawal?: DelegateWithdrawal;
  readonly priorityFeeLamports?: bigint;
  /** The key the signed request names, fresh unless named. */
  readonly txViewingKey?: Bytes32;
}

/** The opened member key proves through the client's proof service. */
export type RingDelegateRecoveredClient = RingDelegateTransferClient &
  Readonly<{ proofService: ProofService }>;

/** Recovered openings still require the configured delegate's signature. */
export type RingDelegateRecoveredParams = Omit<
  RingDelegateTransferParams,
  "wallet" | "source" | "approve" | "client"
> &
  Readonly<{
    client: RingDelegateRecoveredClient;
    /** Change returns to the owner of the last note spent. */
    sources: readonly DelegateSource[];
  }>;

export interface DelegateSource {
  readonly address: ShieldedAddress;
  /** Recovered from escrow, the proof spends the member's notes with it. */
  readonly nullifierKey: NullifierKey;
  readonly notes: readonly WalletUtxo[];
}

type DelegateMove = Omit<RingDelegateTransferParams, "wallet" | "source" | "approve">;

type MoveAuthority =
  | Readonly<{ kind: "keys"; keys: WalletKeys; approve: ApprovalHandler }>
  | Readonly<{ kind: "recovered"; sources: readonly DelegateSource[]; proofs: ProofService }>;

export function createRingDelegateSubmission(
  input: RingDelegateTransferParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const source = keysSource(input);
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: input.wallet,
      registry: input.client,
      build: (retry, buildContext) =>
        buildDelegateTransaction(
          { move: input, wallet: input.wallet, source, retry },
          buildContext,
        ),
    },
    context,
  );
}

export async function buildRingDelegateTransferTransaction(
  input: RingDelegateTransferParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (
    await buildDelegateTransaction(
      { move: input, wallet: input.wallet, source: keysSource(input), retry: {} },
      context,
    )
  ).transaction;
}

export function createRingDelegateRecoveredSubmission(
  input: RingDelegateRecoveredParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const wallet = recoveredWallet(input);
  const source = recoveredSource(input);
  return RingTransactionSubmission.fromBuilder(
    {
      wallet,
      registry: input.client,
      build: (retry, buildContext) =>
        buildDelegateTransaction({ move: input, wallet, source, retry }, buildContext),
    },
    context,
  );
}

export async function buildRingDelegateRecoveredTransaction(
  input: RingDelegateRecoveredParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (
    await buildDelegateTransaction(
      { move: input, wallet: recoveredWallet(input), source: recoveredSource(input), retry: {} },
      context,
    )
  ).transaction;
}

function keysSource(input: RingDelegateTransferParams): MoveAuthority {
  return { kind: "keys", keys: input.source, approve: input.approve ?? approveUnattended };
}

function recoveredWallet(input: RingDelegateRecoveredParams): Wallet {
  const [first] = input.sources;
  if (first === undefined)
    throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "inputs" } });
  const named = new Set(input.sources.map((source) => encodeBase58(source.address.toBytes())));
  if (named.size !== input.sources.length)
    throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "repeatedSource" } });
  if (
    !input.sources.every(({ address, nullifierKey }) =>
      equalBytes(nullifierKey.publicKey(), address.nullifierPublicKey),
    )
  )
    throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
  const wallet = new Wallet({ identity: first.address });
  wallet._replace({
    utxos: input.sources.flatMap((source) => source.notes),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

function recoveredSource(input: RingDelegateRecoveredParams): MoveAuthority {
  return { kind: "recovered", sources: input.sources, proofs: input.client.proofService };
}

function movableOwners(authority: MoveAuthority): readonly ShieldedAddress[] {
  return authority.kind === "keys"
    ? [authority.keys.address()]
    : authority.sources.map((source) => source.address);
}

/** The authority completing the change owner's inputs, released when the attempt ends. */
function delegateProofs(
  authority: MoveAuthority,
  changeOwner: ShieldedAddress,
): Readonly<{ proofs: ProofAuthority; release(): void }> {
  if (authority.kind === "keys") return { proofs: authority.keys, release: () => {} };
  const source = authority.sources.find(({ address }) =>
    equalBytes(address.toBytes(), changeOwner.toBytes()),
  );
  if (source === undefined)
    throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "inputs" } });
  const proofs = new NullifierKeyProofAuthority(source.nullifierKey, authority.proofs);
  return { proofs, release: () => proofs.destroy() };
}

async function buildDelegateTransaction(
  input: Readonly<{
    move: DelegateMove;
    wallet: Wallet;
    source: MoveAuthority;
    retry: RingSubmissionBuildState;
  }>,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const { move, wallet, source, retry } = input;
  const outputs = Object.freeze(move.outputs.map((output) => Object.freeze({ ...output })));
  const owners = movableOwners(source);
  let spender: ReturnType<typeof delegateProofs> | undefined;
  let reservation: UtxoReservation | undefined;
  try {
    if (
      source.kind === "keys" &&
      !owners.every((owner) => equalBytes(owner.toBytes(), wallet.identity.toBytes()))
    )
      throw ringIntentMismatch("source");
    const assets = wallet.registry.clone();
    for (const { assetId, mint } of await fetchSplAssetRegistrations(move.client, context))
      assets.register(assetId, mint);
    const amounts = new Map<Address, bigint>();
    for (const output of outputs) {
      assets.assetId(output.asset);
      amounts.set(output.asset, (amounts.get(output.asset) ?? 0n) + output.amount);
    }
    const { withdrawal } = move;
    if (withdrawal !== undefined)
      amounts.set(withdrawal.asset, (amounts.get(withdrawal.asset) ?? 0n) + withdrawal.amount);
    if (retry.entries !== undefined) checkRetainedEntries(wallet, retry.entries);
    const selected = retry.entries ?? selectSourceNotes(move, wallet, owners, amounts);
    reservation = retry.reservation ?? reserveEntries(wallet, selected, retry.lifetime);
    retry.entries = selected;
    retry.reservation = reservation;
    const ownerOf = (entry: WalletUtxo): ShieldedAddress => {
      const found = owners.find((candidate) => entry.utxo.owner.equals(candidate.signingPublicKey));
      if (found === undefined)
        throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "inputs" } });
      return found;
    };
    // Every note of a mint but the last in largest first order is spent whole, its change is
    // that note's owner's, also after selection regroups the notes by tree.
    const walletOrder = new Map(
      wallet.utxos().map((entry, index) => [bytesKey(entry.nullifier), index]),
    );
    const orderOf = (entry: WalletUtxo) => walletOrder.get(bytesKey(entry.nullifier)) ?? -1;
    const spentMints = [...amounts].map(([asset, amount]) => {
      const notes = selected.filter((entry) => entry.utxo.asset === asset);
      const last = notes.reduce<WalletUtxo | undefined>(
        (found, entry) =>
          found === undefined ||
          entry.utxo.amount < found.utxo.amount ||
          (entry.utxo.amount === found.utxo.amount && orderOf(entry) > orderOf(found))
            ? entry
            : found,
        undefined,
      );
      if (last === undefined)
        throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "inputs" } });
      const spent = notes.reduce((total, entry) => total + entry.utxo.amount, 0n);
      return { asset, owner: ownerOf(last), change: spent - amount };
    });
    const [firstMint] = spentMints;
    if (firstMint === undefined)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "inputs" } });
    const owner = firstMint.owner;
    const coSources = delegateCoSources(source, selected.map(ownerOf), owner);
    // The sender's change pads in, another owner's is a slot of its own.
    const moved = [
      ...outputs,
      ...spentMints
        .filter((mint) => mint.change > 0n && !equalBytes(mint.owner.toBytes(), owner.toBytes()))
        .map((mint) =>
          Object.freeze({ recipient: mint.owner, asset: mint.asset, amount: mint.change }),
        ),
    ];
    const intent: TransactionIntent = Object.freeze({
      kind: "ringDelegate",
      ringProgramId: move.ringProgramId,
      delegate: signerAddress(move.delegate),
      source: owner,
      outputs: moved.map(({ recipient, asset, amount }) =>
        Object.freeze({ recipient, asset, amount }),
      ),
    });
    checkTransactionIntent(intent, ringIntentMismatch);
    const planned = intentHash(intent);
    if (retry.intent !== undefined && !equalBytes(retry.intent, planned))
      throw ringIntentMismatch("retryIntent");
    retry.intent = planned;
    spender = delegateProofs(source, owner);
    const transfer = DelegateTransfer.new({
      ringProgramId: move.ringProgramId,
      delegate: intent.delegate,
      payer: move.feePayer,
      source: owner,
      sourceProofs: spender.proofs,
      inputs: await ringProofInputs(selected, ownerOf, move.client, context),
      coSources,
      outputs: moved,
      assets,
      outputTreeId: move.client.treeId,
      ...(move.txViewingKey === undefined ? {} : { txViewingKey: move.txViewingKey }),
      ...(withdrawal === undefined ? {} : { withdrawal }),
    });
    const approval: RingTransferApproval = {
      transaction:
        move.priorityFeeLamports === undefined
          ? {}
          : { priorityFeeLamports: move.priorityFeeLamports },
      approve: async ({ prepared }) => {
        if (source.kind === "keys") {
          const approved = await source.approve({
            solanaPublicKey: ownerSolanaAccount(owner, move.feePayer),
            intent,
            summary: `Delegate ${intent.delegate} moves ${String(outputs.length)} payment(s)${withdrawal === undefined ? "" : " and a public withdrawal"}, change stays with the source.`,
          });
          checkIntentApproval(approved, intent, ringIntentMismatch);
        }
        // SPP's delegate intent names ring outputs alone.
        if (withdrawal === undefined && outputs.every((output) => output.exit !== true))
          checkPreparedTransfer(
            {
              ...prepared,
              inputs: prepared.inputs.map((spent) => standIn(spent, owner)),
            },
            intent,
            ringIntentMismatch,
          );
      },
    };
    const proven = await transfer.proveApproved(move.client, approval, context);
    return await provenRingAttempt(
      {
        proven,
        feePayer: move.feePayer,
        chain: move.client,
        transaction: approval.transaction,
        intentHash: planned,
      },
      context,
    );
  } catch (cause) {
    if (reservation !== undefined) wallet._releaseReservation(reservation.id);
    throw wrapRingError("RING_BUILD_TRANSFER", cause);
  } finally {
    spender?.release();
  }
}

function delegateCoSources(
  authority: MoveAuthority,
  spent: readonly ShieldedAddress[],
  changeOwner: ShieldedAddress,
): readonly CoOwner[] {
  if (authority.kind === "keys") return [];
  return authority.sources.flatMap(({ address, nullifierKey }) =>
    !equalBytes(address.toBytes(), changeOwner.toBytes()) &&
    spent.some((owner) => equalBytes(owner.toBytes(), address.toBytes()))
      ? [{ owner: address.solanaAddress(), nullifierKey }]
      : [],
  );
}

/** Plain ring notes of the source, one cover per mint. */
function selectSourceNotes(
  move: DelegateMove,
  wallet: Wallet,
  owners: readonly ShieldedAddress[],
  amounts: ReadonlyMap<Address, bigint>,
): readonly WalletUtxo[] {
  const reserved = reservedUtxoKeys(wallet);
  return selectAuthorityNotes({
    wallet,
    covers: [...amounts].map(([asset, amount]) => ({ asset, amount })),
    // A withdrawal holds a slot of SPP's authority builder.
    outputs: move.outputs.length + (move.withdrawal === undefined ? 0 : 1),
    eligible: (entry) =>
      unreserved(reserved)(entry) &&
      entry.utxo.ringProgramId === move.ringProgramId &&
      owners.some((owner) =>
        equalBytes(
          entry.utxo.owner.ownerProofInputHash(),
          owner.signingPublicKey.ownerProofInputHash(),
        ),
      ),
  });
}

export function selectAuthorityNotes(
  input: Readonly<{
    wallet: Wallet;
    covers: readonly Cover[];
    outputs: number;
    eligible: (entry: WalletUtxo) => boolean;
  }>,
): readonly WalletUtxo[] {
  const { covers, outputs } = input;
  const maxInputs = Math.max(
    0,
    ...RING_AUTHORITY_SHAPES.filter((shape) => shape.outputs >= outputs).map(
      (shape) => shape.inputs,
    ),
  );
  return selectFunding({
    wallet: input.wallet,
    covers,
    policy: {
      eligible: input.eligible,
      ordering: "largestFirst",
      allowWideBalance: true,
      maxInputs,
      errors: ringSelectionErrors,
    },
  });
}
