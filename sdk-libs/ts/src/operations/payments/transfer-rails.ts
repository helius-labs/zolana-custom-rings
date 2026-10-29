/** The three rails of a ring transfer, Rust `RingTransfer<Owner>`, `<Anonymous>` and `<Delegated>`. */
import { getBase58Decoder, getBase64Decoder, type Signature } from "@solana/kit";

import {
  equalBytes,
  ownerSignerAddresses,
  prepareRingAuthorityTransfer,
} from "@heliuslabs/zolana/internal";
import type { AnonymousRingTransactProver } from "../../rpc/ports.js";
import type { ProofAuthority, Prover, WalletKeys } from "@heliuslabs/zolana/client";
import { type Shape, InstructionTag } from "@heliuslabs/zolana/interface";
import type {
  Address,
  Bytes32,
  RequestContext,
  TransactWithdrawal,
} from "@heliuslabs/zolana/interface";
import type { NullifierKey, ShieldedAddress } from "@heliuslabs/zolana/keypair";
import { ShieldedPublicKey, ViewingKey } from "@heliuslabs/zolana/keypair";
import type { AssetRegistry, ProofInputUtxo, WalletUtxo } from "@heliuslabs/zolana/transaction";
import { type ConfidentialTransfer, type PreparedTransfer } from "@heliuslabs/zolana/transaction";
import { DELIVERED_AUDIT_CAPACITIES } from "../../protocol/codec/ring-disclosure-layout.js";
import { encodeRelayProofInputs } from "../../protocol/ring-rpc/relay-proof-inputs.js";
import type {
  RelayIntent,
  RelayQuote,
  TokenAccountSetup,
} from "../../protocol/ring-rpc/ring-rpc-types.js";
import { PreparedRelay } from "../../rpc/relay.js";

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
  sealStagedTransfer,
  type AnonymousSpendValues,
  type ProvenRingTransfer,
  type RailSpend,
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

const base58 = getBase58Decoder();
const base64 = getBase64Decoder();

/** @internal */
export interface RingTransferApproval {
  readonly transaction: RingTransactionFrame;
  /** Runs once the transfer fits its transaction, before any proof. */
  approve(
    transfer: Readonly<{ prepared: PreparedTransfer; coSigner: Address | undefined }>,
  ): Promise<void>;
}

export type CustomRingTransferClient = RingProvingClient &
  Pick<Prover, "proveRingTransact" | "proveRingConfidentialEddsaTransact">;

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

/** The confidential rail, the owner signs its spends in public or inside the proof, Rust `RingTransfer<Owner>`. */
export class CustomRingTransfer {
  readonly #input: CustomRingTransferInput;
  readonly #withdrawal: TransactWithdrawal | undefined;
  readonly #inProofOwner: AnonymousSpendSigner | undefined;

  private constructor(
    input: CustomRingTransferInput,
    withdrawal: TransactWithdrawal | undefined,
    inProofOwner: AnonymousSpendSigner | undefined,
  ) {
    this.#input = input;
    this.#withdrawal = withdrawal;
    this.#inProofOwner = inProofOwner;
    Object.freeze(this);
  }

  static new(input: CustomRingTransferInput): CustomRingTransfer {
    input.transfer.withRingProgramId(input.ringProgramId);
    return new CustomRingTransfer(input, undefined, undefined);
  }

  /** The settlement accounts of the transfer's public withdrawal, Rust `with_interface_transfer_accounts`. */
  withWithdrawalAccounts(withdrawal: TransactWithdrawal): CustomRingTransfer {
    return new CustomRingTransfer(this.#input, withdrawal, this.#inProofOwner);
  }

  /** The sender's signing key signs inside the proof, any fee payer sends the transaction, Rust `with_in_proof_owner`. */
  withInProofOwner(signer: AnonymousSpendSigner): CustomRingTransfer {
    return new CustomRingTransfer(this.#input, this.#withdrawal, signer);
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

  /** Rust `prepare_relay`, the in-proof owner signs the message hash, the wallet reads no Merkle path and no record. */
  prepareRelay(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    context?: RequestContext,
  ): Promise<PreparedRelay> {
    return this.#prepareRelay(client, input, undefined, context);
  }

  /** @internal */
  prepareRelayApproved(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<PreparedRelay> {
    return this.#prepareRelay(client, input, approval, context);
  }

  async #prepareRelay(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<PreparedRelay> {
    const { ringProgramId, keys } = this.#input;
    const signer = this.#inProofOwner;
    if (signer === undefined) throw new RingError("RING_IN_PROOF_OWNER_MISMATCH");
    const { quote } = input;
    const { config, staged, prepared } = await this.#stage(client, context);
    try {
      if (prepared.payer !== quote.feePayer)
        throw new RingError("RING_RELAY_PAYER_MISMATCH", {
          details: { payer: prepared.payer, feePayer: quote.feePayer },
        });
      await approval?.approve({ prepared, coSigner: undefined });
      const sealed = sealStagedTransfer({
        ringProgramId,
        config,
        staged: { ...staged, spend: { rail: "confidential" } },
      });
      let payload: Uint8Array | undefined;
      try {
        const { proofInputs } = sealed;
        const ownerSignature = await signer.sign(proofInputs.messageHash(), context);
        payload = encodeRelayProofInputs({
          rail: { kind: "confidential" },
          ringProgramId,
          sender: keys.address(),
          nullifierKey: input.nullifierKey,
          txViewingKey: staged.rail.txViewingKey,
          auditEphemeralKey: sealed.sealed.ephemeralSecret,
          inputs: proofInputs.inputUtxos,
          leafIndexes: proofInputs.inputUtxos.map((spent) => leafIndexOf(spent, input.notes)),
          outputs: proofInputs.outputs,
          externalData: proofInputs.externalData,
          ...(staged.withdrawal === undefined ? {} : { withdrawal: staged.withdrawal }),
          blindingSeed: proofInputs.blindingSeed,
          outputTreeId: proofInputs.outputTreeId,
          assets: this.#input.assets,
        });
        return new PreparedRelay({
          ring: ringProgramId,
          quote,
          intent: {
            operation: "confidential",
            proofInputs: base64.decode(payload) as RelayIntent["proofInputs"],
            ownerSignature: base58.decode(ownerSignature) as Signature,
            ...(input.tokenAccountSetup === undefined
              ? {}
              : { tokenAccountSetup: input.tokenAccountSetup }),
          },
        });
      } finally {
        payload?.fill(0);
        sealed.sealed.ephemeralSecret.fill(0);
      }
    } finally {
      staged.rail.txViewingKey.destroy();
    }
  }

  async #prove(
    client: CustomRingTransferClient,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransfer> {
    const { ringProgramId } = this.#input;
    const { config, staged, prepared, owner } = await this.#stage(client, context);
    try {
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          staged: { ...staged, spend: this.#spend(client, owner) },
          ...suppliedCoSigner(this.#input.coSigner),
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      staged.rail.txViewingKey.destroy();
    }
  }

  /** The confidential rail's SPP proof, the in-proof owner signs the final inputs inside it. */
  #spend(client: CustomRingTransferClient, owner: Bytes32 | undefined): RailSpend {
    const { ringProgramId, keys } = this.#input;
    const signer = this.#inProofOwner;
    if (signer === undefined || owner === undefined)
      return {
        rail: "confidential",
        prove: (inputs, _coSigner, proveContext) =>
          client.proveRingTransact(
            inputs,
            ringProgramId,
            keys,
            { outputTree: client },
            proveContext,
          ),
      };
    return {
      rail: "confidential",
      inProofOwner: owner,
      prove: async (inputs, _coSigner, proveContext) =>
        client.proveRingConfidentialEddsaTransact(
          {
            proofInputs: inputs,
            ringProgramId,
            owner: {
              ownerPublicKey: owner,
              ownerSignature: await signer.sign(inputs.messageHash(), proveContext),
            },
            keys,
            config: { outputTree: client },
          },
          proveContext,
        ),
    };
  }

  /** The caller destroys `staged.rail.txViewingKey`. */
  async #stage(
    client: Pick<RingProvingClient, "getAccount">,
    context: RequestContext | undefined,
  ): Promise<
    Readonly<{
      config: RingProgramConfig;
      staged: Omit<StagedTransfer, "spend">;
      prepared: PreparedTransfer;
      owner: Bytes32 | undefined;
    }>
  > {
    const { ringProgramId, keys } = this.#input;
    const config = await activeConfig(client, ringProgramId, context);
    if (config.mode === "anonymous")
      throw new RingError("RING_ANONYMOUS_SIGNER_REQUIRED", { details: { ringProgramId } });
    const sender = keys.address();
    const owner = inProofOwnerKey(this.#inProofOwner, sender);
    const prepared = this.#input.transfer.prepare();
    checkWithdrawalAccounts(prepared, this.#withdrawal);
    const delivery = confidentialDelivery(prepared.shape, "confidential");
    const rail = new RingOutputRail(
      await transactionKey(keys, sender, prepared, context),
      prepared.firstNullifier,
      owner === undefined ? delivery : { kind: "owned" },
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender,
        assets: this.#input.assets,
        instructionDiscriminator: InstructionTag.ringTransact,
      });
      const ownerSigners =
        owner === undefined
          ? ownerSignerAddresses(proofInputs.inputUtxos, proofInputs.outputs)
          : [];
      // A policy ring spends for exactly one owner.
      const mixed = ownerSigners.findIndex((signer) => signer !== ownerSigners[0]);
      if (config.hasPolicy && mixed >= 0)
        throw new RingError("RING_MIXED_OWNERS", { details: { index: mixed } });
      return {
        config,
        prepared,
        owner,
        staged: {
          proofInputs,
          rail,
          sender,
          ownerSigners,
          ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
        },
      };
    } catch (cause) {
      rail.txViewingKey.destroy();
      throw cause;
    }
  }
}

/** The signer must hold the sender's signing key. */
function inProofOwnerKey(
  signer: AnonymousSpendSigner | undefined,
  sender: ShieldedAddress,
): Bytes32 | undefined {
  if (signer === undefined) return undefined;
  const signing = signer.publicKey();
  if (!(signing instanceof ShieldedPublicKey) || !signing.equals(sender.signingPublicKey))
    throw new RingError("RING_IN_PROOF_OWNER_MISMATCH");
  return signing.ed25519();
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
    const { config, staged, prepared, owner, exitTokenOwner } = await this.#stage(client, context);
    try {
      const spend: StagedTransfer["spend"] = {
        rail: "anonymous",
        anonymous: staged.anonymous,
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
      };
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          staged: { ...staged, spend },
          ...suppliedCoSigner(this.#owner.coSigner),
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      staged.rail.txViewingKey.destroy();
    }
  }

  /** Rust `prepare_relay`, the wallet reads no Merkle path and no record. */
  async prepareRelay(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    context?: RequestContext,
  ): Promise<PreparedRingRelay> {
    return this.#prepareRelay(client, input, undefined, context);
  }

  /** @internal */
  prepareRelayApproved(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<PreparedRingRelay> {
    return this.#prepareRelay(client, input, approval, context);
  }

  async #prepareRelay(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<PreparedRingRelay> {
    const { ringProgramId, keys } = this.#owner;
    const { quote } = input;
    const { config, staged, prepared } = await this.#stage(client, context);
    try {
      if (prepared.payer !== quote.feePayer)
        throw new RingError("RING_RELAY_PAYER_MISMATCH", {
          details: { payer: prepared.payer, feePayer: quote.feePayer },
        });
      await approval?.approve({ prepared, coSigner: undefined });
      const sealed = sealStagedTransfer({
        ringProgramId,
        config,
        staged: { ...staged, spend: { rail: "anonymous" } },
      });
      let payload: Uint8Array | undefined;
      try {
        const { proofInputs } = sealed;
        const ownerSignature = await this.#signer.sign(proofInputs.messageHash(), context);
        const plan = staged.rail.delivery;
        if (plan.kind !== "anonymous") throw new RingError("RING_NOT_ANONYMOUS");
        payload = encodeRelayProofInputs({
          rail: {
            kind: "anonymous",
            plan: plan.plan,
            ...(this.#exitTokenOwner === undefined ? {} : { exitTokenOwner: this.#exitTokenOwner }),
          },
          ringProgramId,
          sender: keys.address(),
          nullifierKey: input.nullifierKey,
          txViewingKey: staged.rail.txViewingKey,
          auditEphemeralKey: sealed.sealed.ephemeralSecret,
          inputs: proofInputs.inputUtxos,
          leafIndexes: proofInputs.inputUtxos.map((spent) => leafIndexOf(spent, input.notes)),
          outputs: proofInputs.outputs,
          externalData: proofInputs.externalData,
          ...(staged.withdrawal === undefined ? {} : { withdrawal: staged.withdrawal }),
          blindingSeed: proofInputs.blindingSeed,
          outputTreeId: proofInputs.outputTreeId,
          assets: this.#owner.assets,
        });
        return Object.freeze({
          relay: new PreparedRelay({
            ring: ringProgramId,
            quote,
            intent: {
              operation: "anonymous",
              proofInputs: base64.decode(payload) as RelayIntent["proofInputs"],
              ownerSignature: base58.decode(ownerSignature) as Signature,
              ...(input.tokenAccountSetup === undefined
                ? {}
                : { tokenAccountSetup: input.tokenAccountSetup }),
            },
          }),
          viewingHistory: staged.anonymous.viewingHistory,
        });
      } finally {
        payload?.fill(0);
        sealed.sealed.ephemeralSecret.fill(0);
      }
    } finally {
      staged.rail.txViewingKey.destroy();
    }
  }

  /** The caller destroys `staged.rail.txViewingKey`. */
  async #stage(
    client: Pick<RingProvingClient, "getAccount">,
    context: RequestContext | undefined,
  ): Promise<
    Readonly<{
      config: RingProgramConfig;
      staged: Omit<StagedTransfer, "spend"> & Readonly<{ anonymous: AnonymousSpendValues }>;
      prepared: PreparedTransfer;
      owner: Bytes32;
      exitTokenOwner: Address | undefined;
    }>
  > {
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
      const staged = {
        proofInputs,
        rail,
        sender,
        ownerSigners: [],
        ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
        anonymous: {
          ...(exitTokenOwner === undefined ? {} : { tokenOwner: exitTokenOwner }),
          partyIdentities: (coSigner: Address | undefined) => {
            checkSignersHideOwner(owner, [coSigner]);
            return anonymousPartyIdentities(prepared.payer, coSigner, destination);
          },
          viewingHistory: tags.history,
        },
      };
      return Object.freeze({ config, staged, prepared, owner, exitTokenOwner });
    } catch (cause) {
      rail.txViewingKey.destroy();
      throw cause;
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
  client: Pick<RingProvingClient, "getAccount">,
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

export interface RingRelayInput {
  /** Names the fee payer the transfer pays from. */
  readonly quote: RelayQuote;
  /** Ring RPC proves with it and so links every spend of the owner. */
  readonly nullifierKey: NullifierKey;
  /** The wallet notes the transfer spends, each names its leaf. */
  readonly notes: readonly WalletUtxo[];
  /** Ring RPC creates each account before the withdrawal pays it. */
  readonly tokenAccountSetup?: readonly TokenAccountSetup[];
}

/** Store `viewingHistory` in place of the old one before `relay.send`. */
export interface PreparedRingRelay {
  readonly relay: PreparedRelay;
  readonly viewingHistory: ViewingHistory;
}

/** A padding slot names no leaf. */
function leafIndexOf(input: ProofInputUtxo, notes: readonly WalletUtxo[]): bigint {
  if (input.isDummy()) return 0n;
  const note = notes.find((entry) => equalBytes(entry.nullifier, input.nullifier()));
  if (note === undefined)
    throw new RingError("RING_RELAY_PROOF_INPUTS", { details: { reason: "leafIndex" } });
  return note.outputContext.leafIndex;
}
