/** The three rails of a ring transfer, Rust `RingTransfer<Owner>`, `<Anonymous>` and `<Delegated>`. */
import { ownerSignerAddresses, prepareRingAuthorityTransfer } from "@heliuslabs/zolana/internal";
import type { AnonymousRingTransactProver } from "../../rpc/ports.js";
import type { ProofAuthority, Prover, WalletKeys } from "@heliuslabs/zolana/client";
import { type Shape, InstructionTag } from "@heliuslabs/zolana/interface";
import type { Address, RequestContext, TransactWithdrawal } from "@heliuslabs/zolana/interface";
import type { ShieldedAddress } from "@heliuslabs/zolana/keypair";
import { ViewingKey } from "@heliuslabs/zolana/keypair";
import type { AssetRegistry, ProofInputUtxo } from "@heliuslabs/zolana/transaction";
import { type ConfidentialTransfer, type PreparedTransfer } from "@heliuslabs/zolana/transaction";
import { DELIVERED_AUDIT_CAPACITIES } from "../../protocol/codec/ring-disclosure-layout.js";

import {
  anonymousExitTokenOwner,
  checkAnonymousSigner,
  checkSignersHideOwner,
  checkAnonymousSlots,
  checkEntryInputs,
  type AnonymousPayment,
  type AnonymousSpendSigner,
} from "./anonymous.js";
import type { RingProgramConfig } from "../../protocol/codec/ring-codecs.js";
import { fetchRingProgramConfig, requireActiveRing } from "../../protocol/membership/config.js";
import { RingError } from "../../protocol/error.js";
import { anonymousPartyIdentities } from "../../protocol/membership/parties.js";
import {
  proveStagedTransfer,
  type ProvenRingTransfer,
  type RingProvingClient,
  type RingTransactionFrame,
  type StagedTransfer,
  type StagedTransferInput,
} from "../workflow/pipeline.js";
import { AnonymousPlan, RingOutputRail, type RingDelivery } from "./output-rail.js";
import { isRingKeys, type RingKeys } from "../../state/ring-keys.js";
import {
  TransferTagging,
  type TransferTags,
  type ViewingHistory,
} from "../../state/viewing-history.js";

/** @internal */
export interface RingTransferApproval {
  readonly transaction: RingTransactionFrame;
  /** Runs once the transfer fits its transaction, before any proof. */
  approve(
    transfer: Readonly<{ prepared: PreparedTransfer; coSigner: Address | undefined }>,
  ): Promise<void>;
}

export type CustomRingTransferClient = RingProvingClient & Pick<Prover, "proveRingTransact">;

export type AnonymousTransferClient = RingProvingClient & AnonymousRingTransactProver;

export type DelegateTransferClient = RingProvingClient & Pick<Prover, "proveRingAuthorityTransact">;

/** Rust `CustomRingTransferInput`. */
export interface CustomRingTransferInput {
  readonly ringProgramId: Address;
  /** Reads the sender's address and transaction keys and completes its inputs, no secret leaves it. */
  readonly keys: WalletKeys;
  /** Prepared by the rail, every output it already holds keeps its slot. */
  readonly transfer: ConfidentialTransfer;
  readonly assets: AssetRegistry;
  /** Read only when the ring demands a co-signer, its record must cover the demand. */
  readonly coSigner?: Address;
}

/** The confidential rail, the owner signs its spends in public, Rust `RingTransfer<Owner>`. */
export class CustomRingTransfer {
  readonly #input: CustomRingTransferInput;
  readonly #withdrawal: TransactWithdrawal | undefined;

  private constructor(input: CustomRingTransferInput, withdrawal: TransactWithdrawal | undefined) {
    this.#input = input;
    this.#withdrawal = withdrawal;
    Object.freeze(this);
  }

  static new(input: CustomRingTransferInput): CustomRingTransfer {
    input.transfer.withRingProgramId(input.ringProgramId);
    return new CustomRingTransfer(input, undefined);
  }

  /** The settlement accounts of the transfer's public withdrawal, Rust `with_interface_transfer_accounts`. */
  withWithdrawalAccounts(withdrawal: TransactWithdrawal): CustomRingTransfer {
    return new CustomRingTransfer(this.#input, withdrawal);
  }

  /** The hidden Ed25519 owner an anonymous ring proves, it must be the sender's signing key. */
  withAnonymousSigner(signer: AnonymousSpendSigner, history: ViewingHistory): AnonymousTransfer {
    return AnonymousTransfer.of({
      owner: this.#input,
      ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
      signer,
      history,
    });
  }

  prove(client: CustomRingTransferClient, context?: RequestContext): Promise<ProvenRingTransfer> {
    return this.#prove(client, undefined, context);
  }

  /** @internal */
  proveApproved(
    client: CustomRingTransferClient,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<ProvenRingTransfer> {
    return this.#prove(client, approval, context);
  }

  async #prove(
    client: CustomRingTransferClient,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransfer> {
    const { ringProgramId, keys } = this.#input;
    const config = await activeConfig(client, ringProgramId, context);
    if (config.mode === "anonymous")
      throw new RingError("RING_ANONYMOUS_SIGNER_REQUIRED", { details: { ringProgramId } });
    const sender = keys.address();
    const prepared = this.#input.transfer.prepare();
    checkWithdrawalAccounts(prepared, this.#withdrawal);
    const rail = new RingOutputRail(
      await transactionKey(keys, sender, prepared, context),
      prepared.firstNullifier,
      confidentialDelivery(prepared.shape, "confidential"),
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender,
        assets: this.#input.assets,
        instructionDiscriminator: InstructionTag.ringTransact,
      });
      const ownerSigners = ownerSignerAddresses(proofInputs.inputUtxos, proofInputs.outputs);
      // A policy ring spends for exactly one owner.
      const mixed = ownerSigners.findIndex((signer) => signer !== ownerSigners[0]);
      if (config.hasPolicy && mixed >= 0)
        throw new RingError("RING_MIXED_OWNERS", { details: { index: mixed } });
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          staged: {
            proofInputs,
            rail,
            sender,
            ownerSigners,
            ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
            spend: {
              rail: "confidential",
              prove: (inputs, _coSigner, proveContext) =>
                client.proveRingTransact(
                  inputs,
                  ringProgramId,
                  keys,
                  { outputTree: client },
                  proveContext,
                ),
            },
          },
          ...suppliedCoSigner(this.#input.coSigner),
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      rail.txViewingKey.destroy();
    }
  }
}

/** The hidden owner's spends on an anonymous ring, no transaction signer names the owner, Rust `RingTransfer<Anonymous>`. */
export class AnonymousTransfer {
  readonly #owner: CustomRingTransferInput;
  readonly #withdrawal: TransactWithdrawal | undefined;
  readonly #signer: AnonymousSpendSigner;
  readonly #history: ViewingHistory;
  /** In declared order, the order of their ring outputs. */
  readonly #payments: readonly AnonymousPayment[];
  readonly #shape: Shape | undefined;
  readonly #exitTokenOwner: Address | undefined;

  private constructor(fields: AnonymousFields) {
    this.#owner = fields.owner;
    this.#withdrawal = fields.withdrawal;
    this.#signer = fields.signer;
    this.#history = fields.history;
    this.#payments = fields.payments;
    this.#shape = fields.shape;
    this.#exitTokenOwner = fields.exitTokenOwner;
    Object.freeze(this);
  }

  /** @internal */
  static of(
    input: Readonly<{
      owner: CustomRingTransferInput;
      withdrawal?: TransactWithdrawal;
      signer: AnonymousSpendSigner;
      history: ViewingHistory;
    }>,
  ): AnonymousTransfer {
    return new AnonymousTransfer({
      owner: input.owner,
      withdrawal: input.withdrawal,
      signer: input.signer,
      history: input.history,
      payments: Object.freeze([]),
      shape: undefined,
      exitTokenOwner: undefined,
    });
  }

  /** Every ring output owner other than the sender is paid here, Rust `with_payment`. */
  withPayment(payment: AnonymousPayment): AnonymousTransfer {
    if (payment.to.ringProgramId !== this.#owner.ringProgramId)
      throw new RingError("RING_FOREIGN_RING", {
        details: { address: payment.to.ringProgramId, ring: this.#owner.ringProgramId },
      });
    this.#owner.transfer.sendToRing(
      payment.to.recipient,
      payment.asset,
      payment.amount,
      payment.to.ringProgramId,
    );
    return new AnonymousTransfer({
      ...this.#fields(),
      payments: Object.freeze([...this.#payments, Object.freeze({ ...payment })]),
    });
  }

  /** Pads to `shape`, else the transfer takes the smallest supported shape. */
  withShape(shape: Shape): AnonymousTransfer {
    this.#owner.transfer.withShape(shape);
    return new AnonymousTransfer({ ...this.#fields(), shape });
  }

  /** A missing exit token account must be the owner's associated token account. */
  withExitTokenOwner(owner: Address): AnonymousTransfer {
    return new AnonymousTransfer({ ...this.#fields(), exitTokenOwner: owner });
  }

  /** The sender's viewing history past the transfer's tags, stored before it is sent. */
  async viewingHistory(context?: RequestContext): Promise<ViewingHistory> {
    const keys = this.#owner.keys;
    if (!isRingKeys(keys)) throw new RingError("RING_KEYS_REQUIRED");
    return (await this.#tags(keys, context)).history;
  }

  prove(client: AnonymousTransferClient, context?: RequestContext): Promise<ProvenRingTransfer> {
    return this.#prove(client, undefined, context);
  }

  /** @internal */
  proveApproved(
    client: AnonymousTransferClient,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<ProvenRingTransfer> {
    return this.#prove(client, approval, context);
  }

  async #prove(
    client: AnonymousTransferClient,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransfer> {
    const { ringProgramId, keys } = this.#owner;
    const config = await activeConfig(client, ringProgramId, context);
    if (config.mode !== "anonymous")
      throw new RingError("RING_NOT_ANONYMOUS", { details: { ringProgramId } });
    if (!isRingKeys(keys)) throw new RingError("RING_KEYS_REQUIRED");
    const sender = keys.address();
    const prepared = this.#owner.transfer.prepare();
    checkWithdrawalAccounts(prepared, this.#withdrawal);
    const owner = checkAnonymousSigner({
      signer: this.#signer,
      sender,
      payer: prepared.payer,
    });
    const exitTokenOwner = await anonymousExitTokenOwner(
      {
        client,
        transfers: prepared.interfaceTransfers,
        hiddenOwner: owner,
        ...(this.#exitTokenOwner === undefined ? {} : { tokenOwner: this.#exitTokenOwner }),
      },
      context,
    );
    const solExit = prepared.interfaceTransfers.find((t) => t.kind === "sol" && !t.isDeposit);
    const destination = solExit?.kind === "sol" ? solExit.userSolAccount : exitTokenOwner;
    if (destination !== undefined && exitTokenOwner !== undefined && destination !== exitTokenOwner)
      throw new RingError("RING_ANONYMOUS_EXIT_DESTINATIONS_DIFFER");
    const tags = await this.#tags(keys, context);
    const plan = tags.payments.reduce(
      (planned, tag) => planned.withPayment(tag.payment),
      AnonymousPlan.create(tags.senderTag),
    );
    const rail = new RingOutputRail(
      await transactionKey(keys, sender, prepared, context),
      prepared.firstNullifier,
      { kind: "anonymous", plan },
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender,
        assets: this.#owner.assets,
        instructionDiscriminator: InstructionTag.ringTransact,
      });
      checkAnonymousSlots(proofInputs);
      const foreign = proofInputs.inputUtxos.findIndex(
        (spent) => !spent.isDummy() && !spent.utxo.owner.equals(sender.signingPublicKey),
      );
      if (foreign >= 0) throw new RingError("RING_MIXED_OWNERS", { details: { index: foreign } });
      checkEntryInputs(proofInputs);
      const staged: StagedTransfer = {
        proofInputs,
        rail,
        sender,
        ownerSigners: [],
        ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
        spend: {
          rail: "anonymous",
          prove: async (inputs, _coSigner, proveContext) =>
            client.proveAnonymousRingTransact(
              {
                proofInputs: inputs,
                ringProgramId,
                owner: {
                  publicKey: owner,
                  signature: await this.#signer.sign(inputs.messageHash(), proveContext),
                },
                ...(exitTokenOwner === undefined ? {} : { exitTokenOwner }),
                keys,
                config: { outputTree: client },
              },
              proveContext,
            ),
          anonymous: {
            ...(exitTokenOwner === undefined ? {} : { tokenOwner: exitTokenOwner }),
            partyIdentities: (coSigner: Address | undefined) => {
              checkSignersHideOwner(owner, [coSigner]);
              return anonymousPartyIdentities(prepared.payer, coSigner, destination);
            },
            viewingHistory: tags.history,
          },
        },
      };
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          staged,
          ...suppliedCoSigner(this.#owner.coSigner),
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      rail.txViewingKey.destroy();
    }
  }

  /** The spec view tag selection over the stored history, the same on every attempt. */
  #tags(keys: RingKeys, context: RequestContext | undefined): Promise<TransferTags> {
    return new TransferTagging({
      keys,
      history: this.#history,
      recipients: this.#payments.map((payment) => ({
        viewingPublicKey: payment.to.recipient.viewingPublicKey,
        firstContact: payment.firstContact,
      })),
    }).plan(context);
  }

  #fields(): AnonymousFields {
    return {
      owner: this.#owner,
      withdrawal: this.#withdrawal,
      signer: this.#signer,
      history: this.#history,
      payments: this.#payments,
      shape: this.#shape,
      exitTokenOwner: this.#exitTokenOwner,
    };
  }
}

interface AnonymousFields {
  readonly owner: CustomRingTransferInput;
  readonly withdrawal: TransactWithdrawal | undefined;
  readonly signer: AnonymousSpendSigner;
  readonly history: ViewingHistory;
  readonly payments: readonly AnonymousPayment[];
  readonly shape: Shape | undefined;
  readonly exitTokenOwner: Address | undefined;
}

/** One output of a delegate move, inside the ring. */
export interface DelegateOutput {
  readonly recipient: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
}

/** Rust `DelegateTransferInput`. */
export interface DelegateTransferInput {
  readonly ringProgramId: Address;
  /** Signs the transaction beside the payer. */
  readonly delegate: Address;
  readonly payer: Address;
  /** The member whose notes move, its change returns to it. */
  readonly source: ShieldedAddress;
  /** Completes the source's inputs with the escrowed key the delegate recovered. */
  readonly sourceProofs: ProofAuthority;
  readonly inputs: readonly ProofInputUtxo[];
  readonly outputs: readonly DelegateOutput[];
  readonly assets: AssetRegistry;
  /** The outputs land in the first input's tree unless named. */
  readonly outputTreeId?: number;
  /** Read only when the ring demands a co-signer, its record must cover the demand. */
  readonly coSigner?: Address;
}

/** The delegate moves one member's notes with the member's escrowed key, the member does not sign, Rust `RingTransfer<Delegated>`. */
export class DelegateTransfer {
  readonly #input: DelegateTransferInput;

  private constructor(input: DelegateTransferInput) {
    this.#input = input;
    Object.freeze(this);
  }

  static new(input: DelegateTransferInput): DelegateTransfer {
    return new DelegateTransfer(input);
  }

  prove(client: DelegateTransferClient, context?: RequestContext): Promise<ProvenRingTransfer> {
    return this.#prove(client, undefined, context);
  }

  /** @internal */
  proveApproved(
    client: DelegateTransferClient,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<ProvenRingTransfer> {
    return this.#prove(client, approval, context);
  }

  async #prove(
    client: DelegateTransferClient,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransfer> {
    const input = this.#input;
    const { ringProgramId } = input;
    const config = await activeConfig(client, ringProgramId, context);
    if (config.delegate === undefined)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "missing" } });
    if (config.delegate !== input.delegate)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "unauthorized" } });
    if (config.mode !== "confidentialEscrow" || !config.hasPolicy)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "escrow" } });
    // A delegate move spends one member's notes.
    const mixed = input.inputs.findIndex(
      (spent) => !spent.utxo.owner.equals(input.source.signingPublicKey),
    );
    if (mixed >= 0) throw new RingError("RING_MIXED_OWNERS", { details: { index: mixed } });
    const first = input.inputs[0];
    if (first === undefined)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "inputs" } });
    const prepared = prepareRingAuthorityTransfer({
      owner: input.source,
      inputs: input.inputs,
      outputs: input.outputs,
      payer: input.payer,
      ringProgramId,
      outputTreeId: input.outputTreeId ?? first.treeId,
    });
    // The member never signs, a fresh transaction key seals the move to the auditor.
    const rail = new RingOutputRail(
      ViewingKey.generate(),
      prepared.firstNullifier,
      confidentialDelivery(prepared.shape, "delegate"),
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender: input.source,
        assets: input.assets,
        instructionDiscriminator: InstructionTag.ringAuthorityTransact,
      });
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          staged: {
            proofInputs,
            rail,
            sender: input.source,
            ownerSigners: [],
            spend: {
              rail: "delegate",
              delegate: input.delegate,
              prove: (inputs, _coSigner, proveContext) =>
                client.proveRingAuthorityTransact(
                  inputs,
                  ringProgramId,
                  input.sourceProofs,
                  proveContext,
                  client,
                ),
            },
          },
          ...suppliedCoSigner(input.coSigner),
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      rail.txViewingKey.destroy();
    }
  }
}

function suppliedCoSigner(coSigner: Address | undefined): Pick<StagedTransferInput, "coSigner"> {
  return coSigner === undefined ? {} : { coSigner };
}

/** The approval a pipeline runs, bound to the prepared transfer the rail proves. */
function approvedStage(
  approval: RingTransferApproval | undefined,
  prepared: PreparedTransfer,
): Pick<StagedTransferInput, "transaction" | "approve"> {
  if (approval === undefined) return {};
  return {
    transaction: approval.transaction,
    approve: (coSigner) => approval.approve({ prepared, coSigner }),
  };
}

/** The ring's config once SPP's registration admits it, Rust `require_config` and `require_active`. */
async function activeConfig(
  client: RingProvingClient,
  ringProgramId: Address,
  context: RequestContext | undefined,
): Promise<RingProgramConfig> {
  const [config] = await Promise.all([
    fetchRingProgramConfig(client, ringProgramId, context),
    requireActiveRing(client, ringProgramId, context),
  ]);
  return config;
}

function confidentialDelivery(shape: Shape, rail: "confidential" | "delegate"): RingDelivery {
  if (DELIVERED_AUDIT_CAPACITIES.includes(shape.outputs)) return { kind: "delivered" };
  throw new RingError("RING_TRANSACT_DATA_INVALID", {
    details: { reason: "RingShapeUnkeyed", rail },
  });
}

/** The sender's transaction key, derived by its key holder from the first nullifier. */
async function transactionKey(
  keys: WalletKeys,
  sender: ShieldedAddress,
  prepared: PreparedTransfer,
  context: RequestContext | undefined,
): Promise<ViewingKey> {
  const derived = await keys.transactionKeys(
    [{ viewingPublicKey: sender.viewingPublicKey, firstNullifier: prepared.firstNullifier }],
    context,
  );
  const [key, ...extra] = derived;
  for (const surplus of extra) surplus.destroy();
  if (key === undefined)
    throw new RingError("RING_KEYS_REQUIRED", { details: { reason: "transactionKey" } });
  return key;
}

/** A public withdrawal names its settlement accounts, a transfer without one names none. */
function checkWithdrawalAccounts(
  prepared: PreparedTransfer,
  withdrawal: TransactWithdrawal | undefined,
): void {
  const leg = prepared.interfaceTransfers.find((transfer) => !transfer.isDeposit);
  const matches =
    leg === undefined
      ? withdrawal === undefined
      : withdrawal !== undefined &&
        (leg.kind === "sol"
          ? withdrawal.kind === "sol" && withdrawal.recipient === leg.userSolAccount
          : withdrawal.kind === "spl" &&
            withdrawal.mint === leg.mint &&
            withdrawal.recipientTokenAccount === leg.tokenAccount);
  if (!matches) throw new RingError("RING_SETTLEMENT_ACCOUNTS_INVALID");
}
