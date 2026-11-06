/** The rails of a ring transfer, Rust `RingTransfer<Owner>`, `<Anonymous>`, `<PublicOwners>` and `<Delegated>`. */
import { getBase64Decoder } from "@solana/kit";

import {
  encodeBase58,
  equalBytes,
  ownerSignerAddresses,
  prepareRingAuthorityTransfer,
  addressBytes,
  solanaOwnerIdentity,
} from "@heliuslabs/spr/internal";
import type { AnonymousRingTransactProver } from "../../rpc/ports.js";
import type {
  PreparedOwnerSignature,
  ProofAuthority,
  Prover,
  WalletKeys,
} from "@heliuslabs/spr/client";
import { type Shape, InstructionTag } from "@heliuslabs/spr/interface";
import type {
  Address,
  Bytes32,
  RequestContext,
  TransactWithdrawal,
} from "@heliuslabs/spr/interface";
import { associatedTokenAddress, signerAddress } from "@heliuslabs/spr/internal";
import type { NullifierKey, ShieldedAddress } from "@heliuslabs/spr/keypair";
import type {
  ExpectedSealed,
  RelayTransferTerms,
  TokenAccountCreate,
} from "../../rpc/relay-message.js";
import { randomBlinding, ShieldedPublicKey, ViewingKey } from "@heliuslabs/spr/keypair";
import type {
  AssetRegistry,
  ProofInputUtxo,
  ProofOutputUtxo,
  SettlementTransfer,
  WalletUtxo,
} from "@heliuslabs/spr/transaction";
import {
  createProofOutput,
  SOL_MINT,
  SppProofInputs,
  type ConfidentialTransfer,
  type PreparedTransfer,
  type WithdrawalTarget,
} from "@heliuslabs/spr/transaction";
import {
  encodeRelayProofInputs,
  type RelayLegAccounts,
} from "../../protocol/ring-rpc/relay-proof-inputs.js";
import type {
  RelayIntent,
  RelayQuote,
  TokenAccountSetup,
} from "../../protocol/ring-rpc/ring-rpc-types.js";
import { UnsignedRelay } from "../../rpc/relay.js";

import {
  anonymousExitTokenOwner,
  checkAnonymousSigner,
  checkHiddenParties,
  checkHiddenOwnerSpends,
  checkEntryInputs,
  type AnonymousPayment,
  type AnonymousSpendSigner,
} from "./anonymous.js";
import type { RingPolicy } from "../../protocol/codec/ring-codecs.js";
import { fetchRingPolicy, requireActiveRing } from "../../protocol/membership/config.js";
import { RingInstructionTag } from "../../protocol/transaction/instruction-tag.js";
import {
  isAnonymousFrame,
  ringRail,
  type FrameExtensions,
} from "../../protocol/transaction/transact.js";
import { RingError } from "../../protocol/error.js";
import { chargedOutflowsOf, relayListSalts, type RingListSalt } from "../../proof/policy-proof.js";
import { ownerDataCounts, transferApprovalOf } from "../../proof/transfer-proof.js";
import { isDefaultRingNote } from "../../proof/audit-proof.js";
import { anonymousPartyIdentities } from "../../protocol/membership/parties.js";
import {
  proveStagedTransfer,
  sealRelayedTransfer,
  sealedTransferTerms,
  type SealedTransfer,
  type AnonymousSpendValues,
  type ProvenRingTransfer,
  type RailSpend,
  type RingProvingClient,
  type RingTransactionFrame,
  type StagedTransfer,
  type StagedTransferInput,
  type TransactDeposit,
} from "../workflow/pipeline.js";
import type { SealRow } from "../workflow/transfer-plan.js";
import { isSmallOrder } from "../../crypto/keys/x25519.js";
import { AnonymousPlan, RingOutputRail } from "./output-rail.js";
import {
  checkCoOwnerKeys,
  checkZeroKeyInputs,
  ringSpendAuthority,
  standIn,
  type CoOwner,
} from "./ring-spend.js";

const base64 = getBase64Decoder();

/** Notes SPP reads from a cache account instead of proving their inclusion, Rust `ReadCache`. */
export interface ReadCache {
  readonly cache: Address;
  readonly notes: readonly Readonly<{ nullifier: Bytes32; slot: number }>[];
}

/** @internal */
export interface RingTransferApproval {
  readonly transaction: RingTransactionFrame;
  /** Runs once the transfer fits its transaction, before any proof. */
  approve(
    transfer: Readonly<{ prepared: PreparedTransfer; coSigners: readonly Address[] }>,
  ): Promise<void>;
}

export type CustomRingTransferClient = RingProvingClient &
  Pick<Prover, "proveRingTransact"> &
  AnonymousRingTransactProver;

export type AnonymousTransferClient = RingProvingClient & AnonymousRingTransactProver;

export type DelegateTransferClient = RingProvingClient & Pick<Prover, "proveRingAuthorityTransact">;

/** Public owners settle on SPP's confidential rail on either ring mode. */
export type PublicOwnerTransferClient = RingProvingClient & Pick<Prover, "proveRingTransact">;

/** Rust `CustomRingTransferInput`. */
export interface CustomRingTransferInput {
  readonly ringProgramId: Address;
  /** Reads the sender's address and transaction keys and completes its inputs, no secret leaves it. */
  readonly keys: WalletKeys;
  /** Prepared by the rail, every output it already holds keeps its slot. */
  readonly transfer: ConfidentialTransfer;
  readonly assets: AssetRegistry;
  /** Read in order while a demanded class stays uncovered. */
  readonly coSigners?: readonly Address[];
  /** Every enrolled owner a salted list reads, the sender and the recipients alike. */
  readonly listSalts?: readonly RingListSalt[];
  /** SPP's optional fields the frame carries through, the proof's own digests are set per attempt. */
  readonly extensions?: Omit<FrameExtensions, "approvalTotals" | "signerDataCounts" | "cache">;
  /** The frame carries a digest of its totals, Rust `with_exact_approval`. */
  readonly exactApproval?: boolean;
  /** The settlement accounts of each deposit leg `transfer` names, in leg order. */
  readonly deposits?: readonly TransactDeposit[];
}

/** The confidential rail, the owner signs its spends in public or inside the proof, Rust `RingTransfer<Owner>`. */
export class CustomRingTransfer {
  readonly #input: CustomRingTransferInput;
  readonly #withdrawal: TransactWithdrawal | undefined;
  readonly #inProofOwner: AnonymousSpendSigner | undefined;
  readonly #coOwners: readonly CoOwner[];

  private constructor(
    input: CustomRingTransferInput,
    withdrawal: TransactWithdrawal | undefined,
    inProofOwner: AnonymousSpendSigner | undefined,
    coOwners: readonly CoOwner[] = [],
  ) {
    this.#input = input;
    this.#withdrawal = withdrawal;
    this.#inProofOwner = inProofOwner;
    this.#coOwners = coOwners;
    Object.freeze(this);
  }

  static new(input: CustomRingTransferInput): CustomRingTransfer {
    input.transfer.withRingProgramId(input.ringProgramId);
    return new CustomRingTransfer(input, undefined, undefined);
  }

  /** The frame carries a digest of its totals, the opening reads as `approvalOpening`. */
  withExactApproval(): CustomRingTransfer {
    return new CustomRingTransfer(
      { ...this.#input, exactApproval: true },
      this.#withdrawal,
      this.#inProofOwner,
      this.#coOwners,
    );
  }

  /** The settlement accounts of the transfer's public withdrawal, Rust `with_interface_transfer_accounts`. */
  withWithdrawalAccounts(withdrawal: TransactWithdrawal): CustomRingTransfer {
    return new CustomRingTransfer(this.#input, withdrawal, this.#inProofOwner, this.#coOwners);
  }

  /** The sender's signing key signs inside the proof, any fee payer sends the transaction, Rust `with_in_proof_owner`. */
  withInProofOwner(signer: AnonymousSpendSigner): CustomRingTransfer {
    return new CustomRingTransfer(this.#input, this.#withdrawal, signer, this.#coOwners);
  }

  /** A co-owner of `ringSpendTransfer` inputs signs the transaction. */
  withCoOwner(coOwner: CoOwner): CustomRingTransfer {
    return new CustomRingTransfer(this.#input, this.#withdrawal, this.#inProofOwner, [
      ...this.#coOwners,
      Object.freeze({ ...coOwner }),
    ]);
  }

  /** `wallet` signs in public and may spend its zero-key notes, nothing selects them for it, Rust `spend_public`. */
  spendPublic(wallet: Address): PublicOwnerTransfer {
    return PublicOwnerTransfer.of({
      owner: this.#input,
      ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
      wallet,
      inProofOwner: this.#inProofOwner !== undefined,
      coOwners: this.#coOwners,
    });
  }

  /** The hidden Ed25519 owner an anonymous ring proves, it must be the sender's signing key. */
  withAnonymousSigner(signer: AnonymousSpendSigner): AnonymousTransfer {
    return AnonymousTransfer.of({
      owner: this.#input,
      ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
      signer,
      coOwners: this.#coOwners,
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

  /** Rust `prepare_relay`, the wallet reads no Merkle path and no record. */
  prepareRelay(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    context?: RequestContext,
  ): Promise<UnsignedRelay> {
    return this.#prepareRelay(client, input, undefined, context);
  }

  /** @internal */
  prepareRelayApproved(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<UnsignedRelay> {
    return this.#prepareRelay(client, input, approval, context);
  }

  /** @internal Rust `deposit_relay`, the wallet reads no record. */
  async depositRelay(
    client: Pick<RingProvingClient, "getAccount">,
    input: DepositRelayInput,
    context?: RequestContext,
  ): Promise<DepositRelayFrame> {
    const { config, staged, prepared } = await this.#stage(client, context);
    try {
      return depositRelayFrame({
        owner: this.#input,
        config,
        prepared,
        staged,
        spend: { rail: "confidential" },
        input,
      });
    } finally {
      staged.rail.txViewingKey.destroy();
    }
  }

  async #prepareRelay(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<UnsignedRelay> {
    const { ringProgramId, keys } = this.#input;
    const signer = this.#inProofOwner;
    if (signer === undefined) throw new RingError("RING_IN_PROOF_OWNER_MISMATCH");
    const { quote } = input;
    const { config, staged, prepared, owner, approvalBlinder } = await this.#stage(client, context);
    try {
      if (owner === undefined) throw new RingError("RING_IN_PROOF_OWNER_MISMATCH");
      if (prepared.payer !== quote.feePayer)
        throw new RingError("RING_RELAY_PAYER_MISMATCH", {
          details: { payer: prepared.payer, feePayer: quote.feePayer },
        });
      await approval?.approve({ prepared, coSigners: [] });
      const sealed = sealRelayedTransfer({
        ringProgramId,
        config,
        staged: { ...staged, spend: { rail: "confidential", inProofOwner: owner } },
        ...(input.sealRow === undefined ? {} : { sealRow: input.sealRow }),
      });
      let payload: Uint8Array | undefined;
      try {
        const { proofInputs } = sealed;
        payload = encodeRelayProofInputs({
          rail: { kind: "confidential" },
          ringProgramId,
          sender: keys.address(),
          nullifierKey: input.nullifierKey,
          txViewingKey: staged.rail.txViewingKey,
          inputs: proofInputs.inputUtxos,
          leafIndexes: proofInputs.inputUtxos.map((spent) => leafIndexOf(spent, input.notes)),
          outputs: proofInputs.outputs,
          externalData: proofInputs.externalData,
          interfaceTransferAccounts: staged.withdrawal === undefined ? [] : [staged.withdrawal],
          blindingSeed: proofInputs.blindingSeed,
          outputTreeId: proofInputs.outputTreeId,
          wideOwners: sealed.plan.wideOwners,
          assets: this.#input.assets,
          listSalts: relayListSalts(config, this.#input.listSalts ?? []),
          coOwners: this.#coOwners,
          ...stagedBlinder(approvalBlinder),
        });
        const coSigners = this.#input.coSigners ?? [];
        const terms = sealedTransferTerms({
          ringProgramId,
          feePayer: quote.feePayer,
          sealed,
          ownerSigners: staged.ownerSigners,
          setup: await tokenAccountCreates(input.tokenAccountSetup, staged.withdrawal),
        });
        return new UnsignedRelay({
          signer,
          messageHash: proofInputs.messageHash(),
          request: {
            ring: ringProgramId,
            quote,
            ...(coSigners.length === 0 ? {} : { coSigners }),
            intent: {
              operation: "confidential",
              proofInputs: base64.decode(payload) as RelayIntent["proofInputs"],
              ...(input.tokenAccountSetup === undefined
                ? {}
                : { tokenAccountSetup: input.tokenAccountSetup }),
            },
          },
          expected: sealedExpectation(terms, approvalBlinder, sealed),
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
    const { config, staged, prepared, owner, approvalBlinder } = await this.#stage(client, context);
    try {
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          staged: {
            ...staged,
            ...stagedBlinder(approvalBlinder),
            spend: this.#spend(client, owner),
          },
          ...suppliedCoSigners(this.#input.coSigners),
          listSalts: this.#input.listSalts ?? [],
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
        prove: (inputs, proveContext) =>
          client.proveRingTransact(
            inputs,
            ringProgramId,
            ringSpendAuthority({
              keys,
              coOwners: this.#coOwners,
              proofInputs: inputs,
              sender: keys.address(),
            }),
            { outputTree: client },
            proveContext,
          ),
      };
    return {
      rail: "confidential",
      inProofOwner: owner,
      // SPP's anonymous rail hides the owner, the statement publishes it.
      prove: async (inputs, proveContext) =>
        client.proveAnonymousRingTransact(
          {
            proofInputs: inputs,
            ringProgramId,
            owner: await preparedOwnerSignature(signer, owner, inputs, proveContext),
            keys: ringSpendAuthority({
              keys,
              coOwners: this.#coOwners,
              proofInputs: inputs,
              sender: keys.address(),
            }),
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
      config: RingPolicy;
      staged: Omit<StagedTransfer, "spend">;
      prepared: PreparedTransfer;
      owner: Bytes32 | undefined;
      approvalBlinder: Bytes32 | undefined;
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
    checkDepositAccounts(prepared, this.#input.deposits);
    const rail = new RingOutputRail(
      await transactionKey(keys, sender, prepared, context),
      prepared.firstNullifier,
      { kind: "delivered" },
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender,
        assets: this.#input.assets,
        instructionDiscriminator: InstructionTag.ringTransact,
      });
      checkZeroKeyInputs(proofInputs.inputUtxos, sender.signingPublicKey);
      if (owner !== undefined) checkRingNotes(proofInputs);
      // An in-proof owner may sit beside signing co-owners, the run names them alone.
      const ownerSigners = ownerSignerAddresses(proofInputs.inputUtxos, proofInputs.outputs, owner);
      if (!spendsNothing(proofInputs) && owner === undefined && ownerSigners.length === 0)
        throw new RingError("RING_NO_SIGNING_OWNER");
      checkCoOwnerKeys(proofInputs, sender, this.#coOwners);
      return {
        config,
        prepared,
        owner,
        approvalBlinder: attemptBlinder(this.#input),
        staged: {
          proofInputs,
          rail,
          sender,
          ownerSigners,
          ...stagedDeposits(this.#input),
          ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
          extensions: stagedExtensions(this.#input, proofInputs, ownerSigners),
        },
      };
    } catch (cause) {
      rail.txViewingKey.destroy();
      throw cause;
    }
  }
}

async function preparedOwnerSignature(
  signer: AnonymousSpendSigner,
  owner: Bytes32,
  proofInputs: SppProofInputs,
  context: RequestContext | undefined,
): Promise<PreparedOwnerSignature> {
  return {
    ownerPublicKey: owner,
    ownerSignature: await signer.sign(proofInputs.messageHash(), context),
  };
}

/** SPP's anonymous rail publishes the owner of a default-ring note, Rust `RingError::InProofDefaultRingInput`. */
function checkRingNotes(proofInputs: SppProofInputs): void {
  const index = proofInputs.inputUtxos.findIndex(isDefaultRingNote);
  if (index >= 0) throw new RingError("RING_IN_PROOF_DEFAULT_RING_INPUT", { details: { index } });
}

/** Padding alone, an address input still needs its owner to sign. */
function spendsNothing(proofInputs: SppProofInputs): boolean {
  return proofInputs.inputUtxos.every((spent) => spent.isDummy() || spent.isCompact());
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
  /** In declared order, the order of their ring outputs. */
  readonly #payments: readonly AnonymousPayment[];
  readonly #shape: Shape | undefined;
  readonly #exitTokenOwner: Address | undefined;
  readonly #coOwners: readonly CoOwner[];
  readonly #readCache: ReadCache | undefined;

  private constructor(fields: AnonymousFields) {
    this.#owner = fields.owner;
    this.#withdrawal = fields.withdrawal;
    this.#signer = fields.signer;
    this.#payments = fields.payments;
    this.#shape = fields.shape;
    this.#exitTokenOwner = fields.exitTokenOwner;
    this.#coOwners = fields.coOwners;
    this.#readCache = fields.readCache;
    Object.freeze(this);
  }

  /** @internal */
  static of(
    input: Readonly<{
      owner: CustomRingTransferInput;
      withdrawal?: TransactWithdrawal;
      signer: AnonymousSpendSigner;
      coOwners?: readonly CoOwner[];
    }>,
  ): AnonymousTransfer {
    return new AnonymousTransfer({
      owner: input.owner,
      withdrawal: input.withdrawal,
      signer: input.signer,
      payments: Object.freeze([]),
      shape: undefined,
      exitTokenOwner: undefined,
      coOwners: input.coOwners ?? [],
      readCache: undefined,
    });
  }

  /** A public co-owner of later `ringSpendTransfer` inputs signs the transaction. */
  withCoOwner(coOwner: CoOwner): AnonymousTransfer {
    return new AnonymousTransfer({
      ...this.#fields(),
      coOwners: [...this.#coOwners, Object.freeze({ ...coOwner })],
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

  /** Named notes spend from `cache`, SPP checks each slot against the frame's selector, Rust `with_read_cache`. */
  withReadCache(readCache: ReadCache): AnonymousTransfer {
    return new AnonymousTransfer({ ...this.#fields(), readCache });
  }

  /** The frame carries a digest of its totals, the opening reads as `approvalOpening`. */
  withExactApproval(): AnonymousTransfer {
    return new AnonymousTransfer({
      ...this.#fields(),
      owner: { ...this.#owner, exactApproval: true },
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
    const { config, staged, prepared, owner, approvalBlinder } = await this.#stage(client, context);
    try {
      const spend: StagedTransfer["spend"] = {
        rail: "anonymous",
        anonymous: staged.anonymous,
        prove: async (inputs, proveContext) =>
          client.proveAnonymousRingTransact(
            {
              proofInputs: inputs,
              ringProgramId,
              owner: await preparedOwnerSignature(this.#signer, owner, inputs, proveContext),
              keys: ringSpendAuthority({
                keys,
                coOwners: this.#coOwners,
                proofInputs: inputs,
                sender: keys.address(),
              }),
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
          staged: { ...staged, ...stagedBlinder(approvalBlinder), spend },
          ...suppliedCoSigners(this.#owner.coSigners),
          listSalts: this.#owner.listSalts ?? [],
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
    const { config, staged, prepared, approvalBlinder } = await this.#stage(client, context);
    try {
      if (prepared.payer !== quote.feePayer)
        throw new RingError("RING_RELAY_PAYER_MISMATCH", {
          details: { payer: prepared.payer, feePayer: quote.feePayer },
        });
      await approval?.approve({ prepared, coSigners: [] });
      const sealed = sealRelayedTransfer({
        ringProgramId,
        config,
        staged: { ...staged, spend: { rail: "anonymous" } },
        ...(input.sealRow === undefined ? {} : { sealRow: input.sealRow }),
      });
      let payload: Uint8Array | undefined;
      try {
        const { proofInputs } = sealed;
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
          inputs: proofInputs.inputUtxos,
          leafIndexes: proofInputs.inputUtxos.map((spent) => leafIndexOf(spent, input.notes)),
          outputs: proofInputs.outputs,
          externalData: proofInputs.externalData,
          interfaceTransferAccounts: staged.withdrawal === undefined ? [] : [staged.withdrawal],
          blindingSeed: proofInputs.blindingSeed,
          outputTreeId: proofInputs.outputTreeId,
          wideOwners: sealed.plan.wideOwners,
          assets: this.#owner.assets,
          listSalts: relayListSalts(config, this.#owner.listSalts ?? []),
          coOwners: this.#coOwners,
          ...stagedBlinder(approvalBlinder),
        });
        const coSigners = this.#owner.coSigners ?? [];
        const terms = sealedTransferTerms({
          ringProgramId,
          feePayer: quote.feePayer,
          sealed,
          ownerSigners: staged.ownerSigners,
          setup: await tokenAccountCreates(input.tokenAccountSetup, staged.withdrawal),
        });
        return Object.freeze({
          relay: new UnsignedRelay({
            signer: this.#signer,
            messageHash: proofInputs.messageHash(),
            request: {
              ring: ringProgramId,
              quote,
              ...(coSigners.length === 0 ? {} : { coSigners }),
              intent: {
                operation: "anonymous",
                proofInputs: base64.decode(payload) as RelayIntent["proofInputs"],
                ...(input.tokenAccountSetup === undefined
                  ? {}
                  : { tokenAccountSetup: input.tokenAccountSetup }),
              },
            },
            expected: sealedExpectation(terms, approvalBlinder, sealed),
          }),
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
      config: RingPolicy;
      staged: Omit<StagedTransfer, "spend"> & Readonly<{ anonymous: AnonymousSpendValues }>;
      prepared: PreparedTransfer;
      owner: Bytes32;
      exitTokenOwner: Address | undefined;
      approvalBlinder: Bytes32 | undefined;
    }>
  > {
    const { ringProgramId, keys } = this.#owner;
    const config = await activeConfig(client, ringProgramId, context);
    if (config.mode !== "anonymous")
      throw new RingError("RING_NOT_ANONYMOUS", { details: { ringProgramId } });
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
    if (this.#payments.some((payment) => isSmallOrder(payment.to.recipient.viewingPublicKey)))
      throw new RingError("RING_RECIPIENT_KEY_NOT_CONTRIBUTORY");
    const rail = new RingOutputRail(
      await transactionKey(keys, sender, prepared, context),
      prepared.firstNullifier,
      { kind: "anonymous", plan: anonymousPlan(this.#payments) },
      this.#payments.map((payment) => payment.data),
    );
    try {
      const encrypted = rail.encrypt({
        prepared,
        sender,
        assets: this.#owner.assets,
        instructionDiscriminator: InstructionTag.ringTransact,
      });
      const proofInputs =
        this.#readCache === undefined ? encrypted : withReadCacheSlots(encrypted, this.#readCache);
      // A cached write needs a public writer signing beside the hidden owner, and no party cell or
      // signer class names one. A cached read and an address slot name no signer.
      if (proofInputs.outputs.some((output) => output.cacheSlot !== undefined))
        throw new RingError("RING_TRANSACT_DATA_INVALID", {
          details: { reason: "InvalidAnonymousSlot" },
        });
      checkZeroKeyInputs(proofInputs.inputUtxos, sender.signingPublicKey);
      const coOwners = ownerSignerAddresses(proofInputs.inputUtxos, proofInputs.outputs, owner);
      checkHiddenOwnerSpends(proofInputs, sender);
      checkEntryInputs(proofInputs, sender);
      checkCoOwnerKeys(proofInputs, sender, this.#coOwners);
      const staged = {
        proofInputs,
        rail,
        sender,
        ownerSigners: coOwners,
        ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
        extensions: stagedExtensions(this.#owner, proofInputs, coOwners),
        anonymous: {
          ...(exitTokenOwner === undefined ? {} : { tokenOwner: exitTokenOwner }),
          partyIdentities: (coSigners: readonly Address[]) => {
            checkHiddenParties(owner, [prepared.payer, ...coSigners]);
            return anonymousPartyIdentities({
              payer: prepared.payer,
              coSigners,
              ...(destination === undefined ? {} : { exitDestination: destination }),
            });
          },
        },
      };
      return Object.freeze({
        config,
        staged,
        prepared,
        owner,
        exitTokenOwner,
        approvalBlinder: attemptBlinder(this.#owner),
      });
    } catch (cause) {
      rail.txViewingKey.destroy();
      throw cause;
    }
  }

  #fields(): AnonymousFields {
    return {
      owner: this.#owner,
      withdrawal: this.#withdrawal,
      signer: this.#signer,
      payments: this.#payments,
      shape: this.#shape,
      exitTokenOwner: this.#exitTokenOwner,
      coOwners: this.#coOwners,
      readCache: this.#readCache,
    };
  }
}

interface AnonymousFields {
  readonly owner: CustomRingTransferInput;
  readonly withdrawal: TransactWithdrawal | undefined;
  readonly signer: AnonymousSpendSigner;
  readonly payments: readonly AnonymousPayment[];
  readonly shape: Shape | undefined;
  readonly exitTokenOwner: Address | undefined;
  readonly coOwners: readonly CoOwner[];
  readonly readCache: ReadCache | undefined;
}

/** Every live owner signs in public, recipients stay hidden on an anonymous ring, Rust `RingTransfer<PublicOwners>`. */
export class PublicOwnerTransfer {
  readonly #owner: CustomRingTransferInput;
  readonly #withdrawal: TransactWithdrawal | undefined;
  readonly #wallet: Address;
  readonly #inProofOwner: boolean;
  readonly #coOwners: readonly CoOwner[];
  /** In declared order, the order of their ring outputs. */
  readonly #payments: readonly AnonymousPayment[];

  private constructor(fields: PublicOwnerFields) {
    this.#owner = fields.owner;
    this.#withdrawal = fields.withdrawal;
    this.#wallet = fields.wallet;
    this.#inProofOwner = fields.inProofOwner;
    this.#coOwners = fields.coOwners;
    this.#payments = fields.payments;
    Object.freeze(this);
  }

  /** @internal */
  static of(
    input: Readonly<{
      owner: CustomRingTransferInput;
      withdrawal?: TransactWithdrawal;
      wallet: Address;
      inProofOwner: boolean;
      coOwners: readonly CoOwner[];
    }>,
  ): PublicOwnerTransfer {
    return new PublicOwnerTransfer({
      ...input,
      withdrawal: input.withdrawal,
      payments: Object.freeze([]),
    });
  }

  /** Every ring output owner other than the wallet is paid here, Rust `with_payment`. */
  withPayment(payment: AnonymousPayment): PublicOwnerTransfer {
    checkPaymentRing(payment, this.#owner.ringProgramId);
    this.#owner.transfer.sendToRing(
      payment.to.recipient,
      payment.asset,
      payment.amount,
      payment.to.ringProgramId,
    );
    return new PublicOwnerTransfer({
      owner: this.#owner,
      withdrawal: this.#withdrawal,
      wallet: this.#wallet,
      inProofOwner: this.#inProofOwner,
      coOwners: this.#coOwners,
      payments: Object.freeze([...this.#payments, Object.freeze({ ...payment })]),
    });
  }

  /** The frame carries a digest of its totals, the opening reads as `approvalOpening`. */
  withExactApproval(): PublicOwnerTransfer {
    return new PublicOwnerTransfer({
      owner: { ...this.#owner, exactApproval: true },
      withdrawal: this.#withdrawal,
      wallet: this.#wallet,
      inProofOwner: this.#inProofOwner,
      coOwners: this.#coOwners,
      payments: this.#payments,
    });
  }

  prove(client: PublicOwnerTransferClient, context?: RequestContext): Promise<ProvenRingTransfer> {
    return this.#prove(client, undefined, context);
  }

  /** @internal */
  proveApproved(
    client: PublicOwnerTransferClient,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<ProvenRingTransfer> {
    return this.#prove(client, approval, context);
  }

  async #prove(
    client: PublicOwnerTransferClient,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransfer> {
    const { ringProgramId, keys } = this.#owner;
    const { config, prepared, staged, spend } = await this.#stage(client, context);
    const prove: RailSpend["prove"] = (inputs, proveContext) =>
      client.proveRingTransact(
        inputs,
        ringProgramId,
        ringSpendAuthority({
          keys,
          coOwners: this.#coOwners,
          proofInputs: inputs,
          sender: staged.sender,
        }),
        { outputTree: client },
        proveContext,
      );
    try {
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          staged: { ...staged, spend: { ...spend, prove } },
          ...suppliedCoSigners(this.#owner.coSigners),
          listSalts: this.#owner.listSalts ?? [],
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      staged.rail.txViewingKey.destroy();
    }
  }

  /** @internal Rust `deposit_relay`, the wallet reads no record. */
  async depositRelay(
    client: Pick<RingProvingClient, "getAccount">,
    input: DepositRelayInput,
    context?: RequestContext,
  ): Promise<DepositRelayFrame> {
    const { config, prepared, staged, spend } = await this.#stage(client, context);
    try {
      return depositRelayFrame({ owner: this.#owner, config, prepared, staged, spend, input });
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
      config: RingPolicy;
      prepared: PreparedTransfer;
      staged: Omit<StagedTransfer, "spend">;
      spend: Omit<RailSpend, "prove">;
    }>
  > {
    const { ringProgramId, keys } = this.#owner;
    const sender = keys.address();
    if (encodeBase58(sender.signingPublicKey.ed25519()) !== this.#wallet)
      throw new RingError("RING_PUBLIC_SPEND_WALLET_MISMATCH", {
        details: { named: this.#wallet, sender: encodeBase58(sender.signingPublicKey.ed25519()) },
      });
    if (this.#inProofOwner) throw new RingError("RING_PUBLIC_SPEND_IN_PROOF_OWNER");
    const config = await activeConfig(client, ringProgramId, context);
    const anonymous = config.mode === "anonymous";
    const prepared = this.#owner.transfer.prepare();
    checkWithdrawalAccounts(prepared, this.#withdrawal);
    checkDepositAccounts(prepared, this.#owner.deposits);
    if (
      anonymous &&
      this.#payments.some((payment) => isSmallOrder(payment.to.recipient.viewingPublicKey))
    )
      throw new RingError("RING_RECIPIENT_KEY_NOT_CONTRIBUTORY");
    const rail = new RingOutputRail(
      await transactionKey(keys, sender, prepared, context),
      prepared.firstNullifier,
      anonymous
        ? { kind: "anonymous", plan: anonymousPlan(this.#payments) }
        : { kind: "delivered" },
      this.#payments.map((payment) => payment.data),
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender,
        assets: this.#owner.assets,
        instructionDiscriminator: InstructionTag.ringTransact,
      });
      checkCoOwnerKeys(proofInputs, sender, this.#coOwners);
      const ownerSigners = ownerSignerAddresses(proofInputs.inputUtxos, proofInputs.outputs);
      const spend: Omit<RailSpend, "prove"> = anonymous
        ? {
            rail: "anonymous",
            publicOwners: true,
            anonymous: {
              partyIdentities: (coSigners) =>
                anonymousPartyIdentities({
                  payer: prepared.payer,
                  coSigners,
                  funders: (this.#owner.deposits ?? []).map(({ funder }) => signerAddress(funder)),
                }),
            },
          }
        : { rail: "confidential" };
      return {
        config,
        prepared,
        spend,
        staged: {
          proofInputs,
          rail,
          sender,
          ownerSigners,
          ...stagedDeposits(this.#owner),
          ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
          extensions: stagedExtensions(this.#owner, proofInputs, ownerSigners),
          ...stagedBlinder(attemptBlinder(this.#owner)),
        },
      };
    } catch (cause) {
      rail.txViewingKey.destroy();
      throw cause;
    }
  }
}

interface PublicOwnerFields {
  readonly owner: CustomRingTransferInput;
  readonly withdrawal: TransactWithdrawal | undefined;
  readonly wallet: Address;
  readonly inProofOwner: boolean;
  readonly coOwners: readonly CoOwner[];
  readonly payments: readonly AnonymousPayment[];
}

function checkPaymentRing(payment: AnonymousPayment, ringProgramId: Address): void {
  if (payment.to.ringProgramId !== ringProgramId)
    throw new RingError("RING_FOREIGN_RING", {
      details: { address: payment.to.ringProgramId, ring: ringProgramId },
    });
}

function anonymousPlan(payments: readonly AnonymousPayment[]): AnonymousPlan {
  return payments.reduce(
    (planned, payment) =>
      planned.withPayment({
        recipient: payment.to.recipient.viewingPublicKey,
        reply: payment.reply,
      }),
    AnonymousPlan.create(),
  );
}

/** One output of a delegate move. */
export interface DelegateOutput {
  readonly recipient: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
  /** Pays a default-ring note under SPP's `ring_authority_exit` circuit. */
  readonly exit?: boolean;
}

/** A delegate's public withdrawal, its settlement accounts named. */
export interface DelegateWithdrawal {
  readonly asset: Address;
  readonly amount: bigint;
  readonly target: WithdrawalTarget;
  readonly accounts: TransactWithdrawal;
}

/** Rust `DelegateTransferInput`. */
export interface DelegateTransferInput {
  readonly ringProgramId: Address;
  /** Signs the transaction beside the payer. */
  readonly delegate: Address;
  readonly payer: Address;
  /** The member whose notes move, its change returns to it. */
  readonly source: ShieldedAddress;
  /** Completes the source's inputs with the key the delegate recovered. */
  readonly sourceProofs: ProofAuthority;
  readonly inputs: readonly ProofInputUtxo[];
  /** Owners of the inputs `source` does not own. */
  readonly coSources?: readonly CoOwner[];
  /** The key the signed request names, fresh unless named. */
  readonly txViewingKey?: Bytes32;
  readonly outputs: readonly DelegateOutput[];
  readonly withdrawal?: DelegateWithdrawal;
  readonly assets: AssetRegistry;
  /** The outputs land in the first input's tree unless named. */
  readonly outputTreeId?: number;
}

/** The delegate moves members' notes with their keys, no member signs, Rust `RingTransfer<Delegated>`. */
export class DelegateTransfer {
  readonly #input: DelegateTransferInput;

  private constructor(input: DelegateTransferInput) {
    this.#input = input;
    Object.freeze(this);
  }

  static new(input: DelegateTransferInput): DelegateTransfer {
    return new DelegateTransfer(input);
  }

  withTxViewingKey(txViewingKey: Bytes32): DelegateTransfer {
    return new DelegateTransfer({ ...this.#input, txViewingKey });
  }

  withCoSource(coSource: CoOwner): DelegateTransfer {
    return new DelegateTransfer({
      ...this.#input,
      coSources: [...(this.#input.coSources ?? []), Object.freeze({ ...coSource })],
    });
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
    // The pinned core holds no exit key.
    if (input.outputs.some((output) => output.exit === true))
      throw new RingError("RING_EXIT_PROOF_UNAVAILABLE");
    const { ringProgramId } = input;
    const config = await activeConfig(client, ringProgramId, context);
    if (config.delegate === undefined)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "missing" } });
    if (config.delegate !== input.delegate)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "unauthorized" } });
    const railKind = ringRail(RingInstructionTag.authorityTransfer, config);
    const coSources = input.coSources ?? [];
    if (
      input.inputs.some(
        (spent) =>
          !spent.utxo.owner.equals(input.source.signingPublicKey) &&
          !coSources.some((coSource) => ownedBy(spent, coSource.owner)),
      )
    )
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "mixedOwners" } });
    const first = input.inputs[0];
    if (first === undefined)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "inputs" } });
    const prepared = prepareDelegateTransfer({
      input,
      outputTreeId: input.outputTreeId ?? first.treeId,
    });
    checkWithdrawalAccounts(prepared, input.withdrawal?.accounts);
    // The member never signs, the transaction key seals the move to the auditor.
    const rail = new RingOutputRail(
      input.txViewingKey === undefined
        ? ViewingKey.generate()
        : ViewingKey.fromBytes(input.txViewingKey.slice() as Bytes32),
      prepared.firstNullifier,
      isAnonymousFrame(railKind)
        ? { kind: "anonymous", plan: delegatePlan(input.outputs) }
        : { kind: "delivered" },
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender: input.source,
        assets: input.assets,
        instructionDiscriminator: InstructionTag.ringAuthorityTransact,
      });
      checkCoOwnerKeys(proofInputs, input.source, coSources);
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
            ...(input.withdrawal === undefined ? {} : { withdrawal: input.withdrawal.accounts }),
            spend: {
              rail: railKind,
              delegate: input.delegate,
              ...(isAnonymousFrame(railKind)
                ? {
                    anonymous: {
                      partyIdentities: (coSigners: readonly Address[]) =>
                        anonymousPartyIdentities({ payer: prepared.payer, coSigners }),
                    },
                  }
                : {}),
              prove: (inputs, proveContext) =>
                client.proveRingAuthorityTransact(
                  inputs,
                  ringProgramId,
                  ringSpendAuthority({
                    keys: input.sourceProofs,
                    coOwners: coSources,
                    proofInputs: inputs,
                    sender: input.source,
                  }),
                  proveContext,
                  client,
                ),
            },
          },
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      rail.txViewingKey.destroy();
    }
  }
}

/** Ring outputs in declared order, an exit carries no payment. */
function delegatePlan(outputs: readonly DelegateOutput[]): AnonymousPlan {
  return outputs
    .filter((output) => output.exit !== true)
    .reduce(
      (planned, output) =>
        planned.withPayment({ recipient: output.recipient.viewingPublicKey, reply: null }),
      AnonymousPlan.create(),
    );
}

/** SPP's authority builder takes no leg, the withdrawal holds a slot through its change sum and leaves padding. */
function prepareDelegateTransfer(
  params: Readonly<{ input: DelegateTransferInput; outputTreeId: number }>,
): PreparedTransfer {
  const { input, outputTreeId } = params;
  const { withdrawal } = input;
  const planned = {
    owner: input.source,
    inputs: input.inputs.map((spent) => standIn(spent, input.source)),
    payer: input.payer,
    ringProgramId: input.ringProgramId,
    outputTreeId,
  };
  const spendingReal = (prepared: PreparedTransfer): PreparedTransfer =>
    Object.freeze({ ...prepared, inputs: Object.freeze([...input.inputs]) });
  if (withdrawal === undefined)
    return spendingReal(prepareRingAuthorityTransfer({ ...planned, outputs: input.outputs }));
  const prepared = prepareRingAuthorityTransfer({
    ...planned,
    outputs: [
      ...input.outputs,
      { recipient: input.source, asset: withdrawal.asset, amount: withdrawal.amount },
    ],
  });
  const leg = prepared.outputs.length - 1;
  return spendingReal({
    ...prepared,
    interfaceTransfers: Object.freeze([settlementLeg(withdrawal)]),
    outputs: Object.freeze(prepared.outputs.slice(0, leg)),
    proofOutputs: () =>
      Object.freeze(
        prepared
          .proofOutputs()
          .map((output, slot) =>
            slot === leg ? delegatePadding(input.ringProgramId, output.blinding) : output,
          ),
      ),
  });
}

function delegatePadding(ringProgramId: Address, blinding: Bytes32): ProofOutputUtxo {
  return createProofOutput({ asset: SOL_MINT, amount: 0n, blinding, ringProgramId });
}

function settlementLeg(withdrawal: DelegateWithdrawal): SettlementTransfer {
  const { target, amount, asset } = withdrawal;
  return target.kind === "sol"
    ? { kind: "sol", isDeposit: false, amount, userSolAccount: target.recipient }
    : {
        kind: "spl",
        mint: asset,
        isDeposit: false,
        amount,
        tokenAccount: target.recipientTokenAccount,
        splInterfaceBump: target.splInterfaceBump,
      };
}

function suppliedCoSigners(
  coSigners: readonly Address[] | undefined,
): Pick<StagedTransferInput, "coSigners"> {
  return coSigners === undefined ? {} : { coSigners };
}

/** A Solana address names a wallet or a PDA alike, a key rebuilt as Ed25519 never equals a PDA owner. */
function ownedBy(spent: ProofInputUtxo, owner: Address): boolean {
  return equalBytes(spent.utxo.owner.confidentialViewTag(), addressBytes(owner));
}

/** Drawn per attempt, a retry never reuses a blinder a co-signer has seen. */
function attemptBlinder(input: CustomRingTransferInput): Bytes32 | undefined {
  return input.exactApproval === true ? randomBlinding() : undefined;
}

/** The caller's extensions and the counts the statement computes, a hidden owner stays out of the run. */
function stagedExtensions(
  input: CustomRingTransferInput,
  proofInputs: SppProofInputs,
  ownerSigners: readonly Address[],
): FrameExtensions {
  const signerDataCounts = ownerDataCounts(
    ownerSigners.map((signer) => solanaOwnerIdentity(addressBytes(signer)) as Bytes32),
    proofInputs.outputs,
  );
  return Object.freeze({
    ...input.extensions,
    ...(signerDataCounts === 0n ? {} : { signerDataCounts }),
  });
}

function stagedBlinder(blinder: Bytes32 | undefined): Readonly<{ approvalBlinder?: Bytes32 }> {
  return blinder === undefined ? {} : { approvalBlinder: blinder };
}

/** The relay builds the frame, the sealing wallet hands the opening to its co-signer. */
function sealedExpectation(
  terms: readonly RelayTransferTerms[],
  blinder: Bytes32 | undefined,
  sealed: Pick<SealedTransfer, "proofInputs" | "plan">,
): ExpectedSealed {
  return Object.freeze({
    kind: "sealed",
    terms,
    chargedOutflows: chargedOutflowsOf(sealed.proofInputs),
    ...(blinder === undefined
      ? {}
      : {
          approval: transferApprovalOf(sealed.proofInputs, sealed.plan.layout.capacity, blinder)
            .opening,
        }),
  });
}

/** After sealing, a slot's cache source changes no blinding and no output. */
function withReadCacheSlots(proofInputs: SppProofInputs, readCache: ReadCache): SppProofInputs {
  const inputUtxos = proofInputs.inputUtxos.slice();
  for (const note of readCache.notes) {
    const at = inputUtxos.findIndex((spent) => equalBytes(spent.nullifier(), note.nullifier));
    const spent = inputUtxos[at];
    if (spent === undefined)
      throw new RingError("RING_TRANSACT_DATA_INVALID", {
        details: { reason: "CachedInputUnknown" },
      });
    inputUtxos[at] = spent.withCacheSlot(note.slot);
  }
  return new SppProofInputs({
    payer: proofInputs.payer,
    inputUtxos,
    outputs: proofInputs.outputs,
    externalData: proofInputs.externalData,
    blindingSeed: proofInputs.blindingSeed,
    outputTreeId: proofInputs.outputTreeId,
  }).withReadCache(readCache.cache);
}

/** Rust `RelayProofInputs::token_account_setup`, each account the withdrawal pays. */
async function tokenAccountCreates(
  setup: readonly TokenAccountSetup[] | undefined,
  withdrawal: TransactWithdrawal | undefined,
): Promise<readonly TokenAccountCreate[]> {
  const created = new Set<Address>();
  return Promise.all(
    (setup ?? []).map(async (entry, index) => {
      const refused = (): RingError =>
        new RingError("RING_RELAY_PROOF_INPUTS", {
          details: { reason: "tokenAccountSetup", index },
        });
      if (withdrawal?.kind !== "spl" || withdrawal.mint !== entry.mint) throw refused();
      const { tokenProgram } = withdrawal;
      const account = await associatedTokenAddress(entry.owner, entry.mint, tokenProgram);
      if (account !== withdrawal.recipientTokenAccount || created.has(account)) throw refused();
      created.add(account);
      return Object.freeze({ owner: entry.owner, mint: entry.mint, tokenProgram });
    }),
  );
}

/** The approval a pipeline runs, bound to the prepared transfer the rail proves. */
function approvedStage(
  approval: RingTransferApproval | undefined,
  prepared: PreparedTransfer,
): Pick<StagedTransferInput, "transaction" | "approve"> {
  if (approval === undefined) return {};
  return {
    transaction: approval.transaction,
    approve: (coSigners) => approval.approve({ prepared, coSigners }),
  };
}

/** The ring's config once SPP's registration admits it, Rust `require_config` and `require_active`. */
async function activeConfig(
  client: Pick<RingProvingClient, "getAccount">,
  ringProgramId: Address,
  context: RequestContext | undefined,
): Promise<RingPolicy> {
  const [config] = await Promise.all([
    fetchRingPolicy(client, ringProgramId, context),
    requireActiveRing(client, ringProgramId, context),
  ]);
  return config;
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

/** Each deposit leg names its funder's accounts in leg order, Rust `funder_account_position`. */
function checkDepositAccounts(
  prepared: PreparedTransfer,
  deposits: readonly TransactDeposit[] | undefined,
): void {
  const legs = prepared.interfaceTransfers.filter((transfer) => transfer.isDeposit);
  const accounts = deposits ?? [];
  const matches =
    legs.length === accounts.length &&
    legs.every((leg, index) => {
      const named = accounts[index];
      return leg.kind === "sol"
        ? named?.kind === "sol" && signerAddress(named.funder) === leg.userSolAccount
        : named?.kind === "spl" &&
            named.mint === leg.mint &&
            named.sourceTokenAccount === leg.tokenAccount;
    });
  if (!matches) throw new RingError("RING_SETTLEMENT_ACCOUNTS_INVALID");
}

function stagedDeposits(
  input: CustomRingTransferInput,
): Readonly<{ deposits?: readonly TransactDeposit[] }> {
  return input.deposits === undefined ? {} : { deposits: input.deposits };
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
  /** The row a Ring RPC reseal refusal names, unset seals under the public counts' row. */
  readonly sealRow?: SealRow;
}

/** Rust `deposit_relay`'s inputs, the frame's sender proves nothing. */
export interface DepositRelayInput {
  readonly quote: RelayQuote;
  readonly nullifierKey: NullifierKey;
}

/** A sealed deposit frame, the caller wipes `payload`. */
export interface DepositRelayFrame {
  readonly payload: Uint8Array;
  readonly expected: ExpectedSealed;
}

/** One funder term per funding key, Ring RPC builds the frame and the funder signs its legs. */
function depositRelayFrame(
  input: Readonly<{
    owner: CustomRingTransferInput;
    config: RingPolicy;
    prepared: PreparedTransfer;
    staged: Omit<StagedTransfer, "spend">;
    spend: Pick<RailSpend, "rail" | "publicOwners">;
    input: DepositRelayInput;
  }>,
): DepositRelayFrame {
  const { owner, config, prepared, staged, spend } = input;
  const { quote, nullifierKey } = input.input;
  if (prepared.payer !== quote.feePayer)
    throw new RingError("RING_RELAY_PAYER_MISMATCH", {
      details: { payer: prepared.payer, feePayer: quote.feePayer },
    });
  const deposits = owner.deposits ?? [];
  const funders = [...new Set(deposits.map(({ funder }) => signerAddress(funder)))];
  // The fee payer signs whatever the relay sends, a leg naming it would fund the note from the relay.
  if (funders.includes(quote.feePayer)) throw new RingError("RING_RELAY_FEE_PAYER_FUNDS_DEPOSIT");
  const sealed = sealRelayedTransfer({
    ringProgramId: owner.ringProgramId,
    config,
    staged: { ...staged, spend },
  });
  try {
    const { proofInputs } = sealed;
    const plan = staged.rail.delivery;
    const legs = proofInputs.externalData.interfaceTransfers;
    return Object.freeze({
      payload: encodeRelayProofInputs({
        rail: { kind: "deposit", ...(plan.kind === "anonymous" ? { plan: plan.plan } : {}) },
        ringProgramId: owner.ringProgramId,
        sender: staged.sender,
        nullifierKey,
        txViewingKey: staged.rail.txViewingKey,
        inputs: proofInputs.inputUtxos,
        leafIndexes: proofInputs.inputUtxos.map(() => 0n),
        outputs: proofInputs.outputs,
        externalData: proofInputs.externalData,
        interfaceTransferAccounts: deposits.map(relayLegAccounts),
        blindingSeed: proofInputs.blindingSeed,
        outputTreeId: proofInputs.outputTreeId,
        wideOwners: sealed.plan.wideOwners,
        assets: owner.assets,
        listSalts: relayListSalts(config, owner.listSalts ?? []),
        coOwners: [],
      }),
      expected: Object.freeze({
        kind: "sealed",
        terms: [],
        funders: funders.map((signer) =>
          Object.freeze({
            ring: owner.ringProgramId,
            feePayer: quote.feePayer,
            signer,
            legs: Object.freeze(
              legs.flatMap((leg, index) => {
                const named = deposits[index];
                if (!leg.isDeposit || named === undefined || signerAddress(named.funder) !== signer)
                  return [];
                return [
                  leg.kind === "sol"
                    ? { amount: leg.amount }
                    : { mint: leg.mint, amount: leg.amount },
                ];
              }),
            ),
            setup: [],
          }),
        ),
        chargedOutflows: chargedOutflowsOf(proofInputs),
      }),
    });
  } finally {
    sealed.sealed.ephemeralSecret.fill(0);
  }
}

/** The relay wire's account group of one deposit leg, a SOL leg names its funder. */
function relayLegAccounts(deposit: TransactDeposit): RelayLegAccounts {
  return deposit.kind === "sol"
    ? { kind: "sol", recipient: signerAddress(deposit.funder) }
    : {
        kind: "splDeposit",
        mint: deposit.mint,
        splTokenInterface: deposit.splTokenInterface,
        tokenAuthority: signerAddress(deposit.funder),
        userTokenAccount: deposit.sourceTokenAccount,
        tokenProgram: deposit.tokenProgram,
      };
}

export interface PreparedRingRelay {
  readonly relay: UnsignedRelay;
}

/** A padding slot names no leaf. */
function leafIndexOf(input: ProofInputUtxo, notes: readonly WalletUtxo[]): bigint {
  if (input.isDummy()) return 0n;
  const note = notes.find((entry) => equalBytes(entry.nullifier, input.nullifier()));
  if (note === undefined)
    throw new RingError("RING_RELAY_PROOF_INPUTS", { details: { reason: "leafIndex" } });
  return note.outputContext.leafIndex;
}
