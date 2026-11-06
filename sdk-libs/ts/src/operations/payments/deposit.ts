/**
 * A ring deposit is a ring transfer that spends no note, one public leg funds its one ring output.
 * The frame's sender is a fresh zero-key address per attempt, the recipient finds the note as any payment.
 */
import {
  getBase58Decoder,
  getBase64Decoder,
  type Instruction,
  type MessagePartialSigner,
  type Signature,
} from "@solana/kit";

import { initializePoseidon } from "@heliuslabs/spr";
import type { ProofService } from "@heliuslabs/spr/client";
import { LocalKeys } from "@heliuslabs/spr/client";
import {
  checkIntentApproval,
  isZero,
  resolveDepositSettlement,
  resolveShieldedRecipient,
  signerAddress,
  splAssetRegistryAddress,
  splInterfaceWithBump,
  type SignerAccount,
} from "@heliuslabs/spr/internal";
import { decodeSplAssetRegistry } from "@heliuslabs/spr/interface";
import type { Address, Bytes32, RequestContext, Transaction } from "@heliuslabs/spr/interface";
import {
  NullifierKey,
  ShieldedAddress,
  ShieldedKeypair,
  type Bytes31,
} from "@heliuslabs/spr/keypair";
import {
  AssetRegistry,
  ConfidentialTransfer,
  Data,
  SOL_MINT,
  Utxo,
  approveUnattended,
  intentHash,
  type ApprovalHandler,
  type DepositSource,
  type ProofOutputUtxo,
  type TransactionIntent,
} from "@heliuslabs/spr/transaction";

import { RingAddress, type RingPaymentRequest } from "../../crypto/keys/ring-address.js";
import { RingError, wrapRingError } from "../../protocol/error.js";
import { fetchRingPolicy } from "../../protocol/membership/config.js";
import { resolveRingOutputTree } from "../../protocol/membership/trees.js";
import { RingInstructionTag } from "../../protocol/transaction/instruction-tag.js";
import { depositRequestDigest } from "../../protocol/ring-rpc/relay-proof-inputs.js";
import type { RelayIntent, RelayQuote } from "../../protocol/ring-rpc/ring-rpc-types.js";
import type { RingListSalt } from "../../proof/policy-proof.js";
import { PreparedRelay } from "../../rpc/relay.js";
import { mismatch } from "../../rpc/relay-message.js";
import { signMessage } from "../../rpc/ring-rpc.js";
import type { RingKeys } from "../../state/ring-keys.js";
import { ringComputeUnitLimit } from "../management/admin.js";
import {
  boundState,
  type ProvenRingTransfer,
  type RingBoundState,
  type TransactDeposit,
} from "../workflow/pipeline.js";
import { ringIntentMismatch } from "../workflow/selection.js";
import {
  provenRingAttempt,
  RingTransactionSubmission,
  type RingSubmissionAttempt,
} from "../workflow/submission.js";
import {
  CustomRingTransfer,
  type CustomRingTransferInput,
  type PublicOwnerTransfer,
} from "./transfer-rails.js";
import { assetLabel, type RingTransferClient } from "./transfer.js";

const base58 = getBase58Decoder();
const base64 = getBase64Decoder();

/** The transfer limit, a deposit lands through `TRANSFER`. */
export const RING_DEPOSIT_COMPUTE_UNIT_LIMIT = ringComputeUnitLimit(RingInstructionTag.transfer);

/** Who a deposit pays. */
export type RingDepositRecipient =
  /** A confidential ring member, found under its viewing key's tag. */
  | Readonly<{ kind: "confidential"; address: Address | ShieldedAddress; listSalt?: Bytes32 }>
  /** The depositor's own hidden identity on an anonymous ring, `listSalt` its enrollment's. */
  | Readonly<{ kind: "anonymous"; keys: RingKeys; listSalt: Bytes32 }>
  /** Another member of an anonymous ring. */
  | Readonly<{ kind: "anonymousPayment"; to: RingAddress | RingPaymentRequest }>;

/** The frame's fresh sender proves through `proofService`. */
export type RingDepositClient = RingTransferClient & Readonly<{ proofService: ProofService }>;

export interface RingDepositParams {
  readonly client: RingDepositClient;
  readonly ringProgramId: Address;
  readonly feePayer: Address;
  /** Funds the deposit, the fee payer when absent. */
  readonly depositor?: SignerAccount;
  /** The output tree, the client's when absent. */
  readonly tree?: Address;
  readonly recipient: RingDepositRecipient;
  readonly asset?: Address;
  readonly amount: bigint;
  readonly splTokenAccount?: Address;
  readonly splTokenProgram?: Address | null;
  /** Signs when a record covers deposits, the record must be its own. */
  readonly cosigner?: SignerAccount;
}

/** Rust `RingDeposit::prepare_relay`. */
export interface RingDepositRelayParams extends Omit<
  RingDepositParams,
  "feePayer" | "depositor" | "cosigner"
> {
  /** Funds the deposit and signs its request and message. */
  readonly depositor: SignerAccount;
  readonly depositorSigner: MessagePartialSigner;
  readonly quote: RelayQuote;
  readonly approve?: ApprovalHandler;
}

export interface PreparedRingDepositRelay {
  readonly relay: PreparedRelay;
}

/** A proven deposit and the chain values its proofs bind. */
export interface ProvenRingDeposit extends RingBoundState {
  readonly instruction: Instruction;
  /** The note the deposit creates, as SPP appends it. */
  readonly utxo: Utxo;
}

type DepositRail = CustomRingTransfer | PublicOwnerTransfer;

/** One attempt's frame, its sender drawn fresh. */
export class PreparedRingDeposit {
  readonly #ringProgramId: Address;
  readonly #recipient: ShieldedAddress;
  readonly #asset: Address;
  readonly #amount: bigint;
  readonly #rail: DepositRail;
  /** The fresh sender's, Ring RPC proves a relayed frame with it. */
  readonly #nullifierKey: NullifierKey;
  #proved = false;

  private constructor(
    fields: Readonly<{
      ringProgramId: Address;
      recipient: ShieldedAddress;
      asset: Address;
      amount: bigint;
      rail: DepositRail;
      nullifierKey: NullifierKey;
    }>,
  ) {
    this.#ringProgramId = fields.ringProgramId;
    this.#recipient = fields.recipient;
    this.#asset = fields.asset;
    this.#amount = fields.amount;
    this.#rail = fields.rail;
    this.#nullifierKey = fields.nullifierKey;
  }

  /** Builds the frame against the ring's mode, nothing is proven. */
  static async prepare(
    params: RingDepositParams,
    context?: RequestContext,
  ): Promise<PreparedRingDeposit> {
    try {
      return await PreparedRingDeposit.#frame(
        {
          ...params,
          depositor: params.depositor ?? params.feePayer,
          ...(params.cosigner === undefined ? {} : { coSigners: [signerAddress(params.cosigner)] }),
        },
        context,
      );
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    }
  }

  /** Ring RPC proves and pays, the depositor signs the request now and its legs on the returned message. */
  static async prepareRelay(
    params: RingDepositRelayParams,
    context?: RequestContext,
  ): Promise<PreparedRingDepositRelay> {
    let payload: Uint8Array | undefined;
    try {
      if (params.depositorSigner.address !== signerAddress(params.depositor))
        throw mismatch("Signer");
      const { quote } = params;
      const prepared = await PreparedRingDeposit.#frame(
        { ...params, feePayer: quote.feePayer },
        context,
      );
      const intent = prepared.intent();
      const approval = await (params.approve ?? approveUnattended)({
        solanaPublicKey: signerAddress(params.depositor),
        intent,
        summary: `ring deposit of ${String(params.amount)} ${assetLabel(prepared.#asset)} into ring ${params.ringProgramId}`,
      });
      checkIntentApproval(approval, intent, ringIntentMismatch);
      const frame = await prepared.#rail.depositRelay(
        params.client,
        { quote, nullifierKey: prepared.#nullifierKey },
        context,
      );
      payload = frame.payload;
      const depositorSignature = base58.decode(
        await signMessage(params.depositorSigner, depositRequestDigest(payload)),
      ) as Signature;
      return Object.freeze({
        relay: new PreparedRelay(
          {
            ring: params.ringProgramId,
            quote,
            intent: {
              operation: "deposit",
              proofInputs: base64.decode(payload) as RelayIntent["proofInputs"],
              depositorSignature,
            },
          },
          frame.expected,
        ),
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    } finally {
      payload?.fill(0);
    }
  }

  async prove(client: RingDepositClient, context?: RequestContext): Promise<ProvenRingDeposit> {
    try {
      const proven = await this.proveTransfer(client, context);
      const output = proven.outputs.find((slot) => !slot.isDummy() && !slot.isCompact());
      if (output === undefined) throw new RingError("RING_BUILD_DEPOSIT");
      return Object.freeze({
        instruction: await proven.instruction(),
        utxo: outputUtxo(output, this.#ringProgramId),
        ...boundState(proven),
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    }
  }

  /** @internal A second proof is refused, a retry prepares a new frame. */
  proveTransfer(client: RingDepositClient, context?: RequestContext): Promise<ProvenRingTransfer> {
    if (this.#proved) throw new RingError("RING_DEPOSIT_FRAME_REUSED");
    this.#proved = true;
    return this.#rail.prove(client, context);
  }

  /** @internal */
  intent(): TransactionIntent {
    return {
      kind: "ringDeposit",
      ringProgramId: this.#ringProgramId,
      asset: this.#asset,
      amount: this.#amount,
      recipient: this.#recipient,
    };
  }

  static async #frame(
    params: Omit<RingDepositParams, "depositor" | "cosigner"> &
      Readonly<{ depositor: SignerAccount; coSigners?: readonly Address[] }>,
    context: RequestContext | undefined,
  ): Promise<PreparedRingDeposit> {
    await initializePoseidon();
    const { client, ringProgramId } = params;
    const asset = params.asset ?? SOL_MINT;
    const funder = signerAddress(params.depositor);
    const [config, outputTree, settlement] = await Promise.all([
      fetchRingPolicy(client, ringProgramId, context),
      resolveRingOutputTree(client, params.tree, context),
      resolveDepositSettlement(
        {
          asset,
          depositor: funder,
          ...(params.splTokenAccount === undefined
            ? {}
            : { splTokenAccount: params.splTokenAccount }),
          ...(params.splTokenProgram === undefined
            ? {}
            : { splTokenProgram: params.splTokenProgram }),
        },
        () => new RingError("RING_BUILD_DEPOSIT", { details: { reason: "missing token account" } }),
      ),
    ]);
    const anonymous = config.mode === "anonymous";
    const paid = await depositPayee(params, anonymous, context);
    // 1. The sender spends nothing and seeds the transaction key. Its zero key keeps the anonymous
    //    rail's zero change out of the tracking rows a keyed owner needs.
    const fresh = ShieldedKeypair.generate();
    const nullifierKey = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);
    const sender = ShieldedAddress.fromPublicKeys(
      fresh.signingPublicKey(),
      nullifierKey.publicKey(),
      fresh.viewingKey().publicKey(),
    );
    const transfer = ConfidentialTransfer.newDeposit(sender, outputTree.treeId, params.feePayer);
    // 2. One public leg funds the output, the funder signs the leg's accounts.
    let deposit: TransactDeposit;
    let source: DepositSource;
    if (settlement.kind === "sol") {
      source = { kind: "sol", funder };
      deposit = { kind: "sol", funder: params.depositor };
    } else {
      const { mint, sourceTokenAccount, tokenProgram } = settlement.accounts;
      const [splTokenInterface, splInterfaceBump] = await splInterfaceWithBump(mint);
      source = { kind: "spl", sourceTokenAccount, splInterfaceBump };
      deposit = {
        kind: "spl",
        mint,
        splTokenInterface,
        funder: params.depositor,
        sourceTokenAccount,
        tokenProgram,
      };
    }
    transfer.deposit(asset, params.amount, source);
    const input: CustomRingTransferInput = {
      ringProgramId,
      keys: LocalKeys.fromKeys(
        { address: sender, viewingKeys: [fresh.viewingKey()], nullifierKey },
        client.proofService,
      ),
      transfer,
      assets: await depositAssets(client, asset, context),
      deposits: [deposit],
      listSalts: paid.listSalts,
      ...(params.coSigners === undefined ? {} : { coSigners: params.coSigners }),
    };
    // 3. A confidential ring delivers to the recipient's tag, an anonymous ring pays a plan slot on
    //    the public owner rail, whose empty owner run the payer authorizes.
    let rail: DepositRail;
    if (paid.to === undefined) {
      transfer.send(paid.address, asset, params.amount);
      rail = CustomRingTransfer.new(input);
    } else {
      rail = CustomRingTransfer.new(input)
        .spendPublic(sender.solanaAddress())
        .withPayment({ to: paid.to, asset, amount: params.amount, reply: null });
    }
    return new PreparedRingDeposit({
      ringProgramId,
      recipient: paid.address,
      asset,
      amount: params.amount,
      rail,
      nullifierKey,
    });
  }
}

/** Prepares, proves and compiles one deposit. */
export async function buildRingDepositTransaction(
  params: RingDepositParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    return (await depositAttempt(params, context)).transaction;
  } catch (cause) {
    throw wrapRingError("RING_BUILD_DEPOSIT", cause);
  }
}

/** Each attempt proves a fresh frame. */
export async function createRingDepositSubmission(
  params: RingDepositParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const build = async (attemptContext?: RequestContext): Promise<RingSubmissionAttempt> => {
    try {
      return await depositAttempt(params, attemptContext);
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    }
  };
  return new RingTransactionSubmission({
    first: await build(context),
    build,
    registry: params.client,
  });
}

async function depositAttempt(
  params: RingDepositParams,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const prepared = await PreparedRingDeposit.prepare(params, context);
  return provenRingAttempt(
    {
      proven: await prepared.proveTransfer(params.client, context),
      feePayer: params.feePayer,
      chain: params.client,
      transaction: {},
      intentHash: intentHash(prepared.intent()),
    },
    context,
  );
}

/** The paid address, the plan slot on an anonymous ring and the salted reads it needs. */
async function depositPayee(
  params: Pick<RingDepositParams, "client" | "ringProgramId" | "recipient">,
  anonymous: boolean,
  context: RequestContext | undefined,
): Promise<
  Readonly<{ address: ShieldedAddress; to?: RingAddress; listSalts: readonly RingListSalt[] }>
> {
  const { recipient, ringProgramId } = params;
  const salted = (address: ShieldedAddress, salt: Bytes32 | undefined): RingListSalt[] =>
    salt === undefined ? [] : [{ owner: address.signingPublicKey.ownerProofInputHash(), salt }];
  if (recipient.kind === "confidential") {
    if (anonymous)
      throw new RingError("RING_ANONYMOUS_REFUSED", { details: { operation: "deposit" } });
    const address = await resolveShieldedRecipient(
      { rpc: params.client, recipient: recipient.address },
      (unregistered) =>
        new RingError("RING_BUILD_DEPOSIT", {
          details: { reason: "recipient not registered", recipient: unregistered },
        }),
      context,
    );
    return { address, listSalts: salted(address, recipient.listSalt) };
  }
  if (!anonymous) throw new RingError("RING_NOT_ANONYMOUS", { details: { operation: "deposit" } });
  const to =
    recipient.kind === "anonymous"
      ? new RingAddress({
          recipient: recipient.keys.address(),
          ringProgramId,
          listSalt: recipient.listSalt,
        })
      : recipient.to instanceof RingAddress
        ? recipient.to
        : recipient.to.address;
  return {
    address: to.recipient,
    to,
    listSalts: salted(to.recipient, isZero(to.listSalt) ? undefined : to.listSalt),
  };
}

/** SOL needs no registry entry, an SPL mint takes its on-chain asset id. */
async function depositAssets(
  client: RingDepositClient,
  asset: Address,
  context: RequestContext | undefined,
): Promise<AssetRegistry> {
  if (asset === SOL_MINT) return new AssetRegistry();
  const account = await client.getAccount(await splAssetRegistryAddress(asset), context);
  const registry = account === undefined ? undefined : decodeSplAssetRegistry(account.data);
  if (registry?.mint !== asset)
    throw new RingError("RING_BUILD_DEPOSIT", { details: { reason: "unregistered mint", asset } });
  return new AssetRegistry([[registry.assetId, asset]]);
}

function outputUtxo(output: ProofOutputUtxo, ringProgramId: Address): Utxo {
  const owner = output.ownerAddress;
  if (owner === undefined) throw new RingError("RING_BUILD_DEPOSIT");
  return new Utxo({
    owner: owner.signingPublicKey,
    asset: output.asset,
    amount: output.amount,
    blinding: output.blinding,
    data: new Data(),
    ringProgramId,
  });
}
