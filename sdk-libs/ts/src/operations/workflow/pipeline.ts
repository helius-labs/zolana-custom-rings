/**
 * One transfer pipeline for every rail, Rust `pipeline`. The rail seals the outputs, the ring proof
 * opens them to the auditor and screens the ring's table, the SPP proof spends.
 */
import type { AccountMeta, Instruction } from "@solana/kit";

import {
  addressBytes,
  bytesKey,
  compressG2,
  concatBytes,
  encodeBase58,
  equalBytes,
  meta,
  solanaOwnerIdentity,
  treeAddress,
  ZERO_32,
  type SignerAccount,
} from "@heliuslabs/spr/internal";
import { type RingProver } from "../../rpc/ports.js";
import type { ChainReader, ProvenRingTransact, TreeContext } from "@heliuslabs/spr/client";
import {
  ringTransactAccounts,
  SOL_INTERFACE,
  TransactCacheAccounts,
  type Shape,
} from "@heliuslabs/spr/interface";
import type {
  Address,
  Bytes32,
  RequestContext,
  TransactWithdrawal,
} from "@heliuslabs/spr/interface";
import type { RingTransactInstructionData } from "../../protocol/proof/circuit.js";
import type { ProvenAnonymousRingTransact } from "../../rpc/ports.js";
import type { ShieldedAddress, ShieldedPublicKey } from "@heliuslabs/spr/keypair";
import {
  ZERO_ADDRESS,
  type RelayTransferTerms,
  type TokenAccountCreate,
} from "../../rpc/relay-message.js";
import { SppProofInputs, createExternalData } from "@heliuslabs/spr/transaction";
import type { ProofInputUtxo, ProofOutputUtxo } from "@heliuslabs/spr/transaction";
import { CUSTOM_RING_PROOF_LENGTH } from "../../protocol/proof/custom-ring-proof.js";
import { ringAuthAddress, ringCoSignerMetas, ringPolicyAddress } from "../../protocol/pda/index.js";
import { ringIdField } from "../../crypto/derivation/ring-stream.js";

import { RingInstructionTag, ringComputeUnitLimit } from "../management/admin.js";
import {
  spentNotes,
  isDefaultRingNote,
  ownerRows,
  sealAudit,
  sealedAuditMessage,
  type SealedAudit,
} from "../../proof/audit-proof.js";
import { type RingPolicy } from "../../protocol/codec/ring-codecs.js";
import {
  NO_DEMAND,
  operationDemand,
  publicLegClasses,
  resolveRingCoSigners,
} from "../../proof/cosign.js";
import { RingError } from "../../protocol/error.js";
import {
  policyLegs,
  policyDemand,
  policyRoots,
  publishedNotes,
  readPolicy,
  screened,
  type BoundPolicy,
  type BoundRoot,
  type PolicyInputs,
  type PolicyReadClient,
  type RingListSalt,
} from "../../proof/policy-proof.js";
import {
  cacheAccessOf,
  checkOwnerSignerBound,
  transferApprovalOf,
  transferProofRequest,
  type TransferApproval,
} from "../../proof/transfer-proof.js";
import type { ApprovalOpening } from "../../protocol/membership/approval-totals.js";
import type { OwnerDebit } from "../../protocol/membership/owner-debits.js";
import { policyWithdrawalHash } from "../../proof/withdrawals.js";
import {
  framesData,
  publishedOutputs,
  type PublishedSlot,
  type RingOutputRail,
} from "../payments/output-rail.js";
import {
  ringTransferStatement,
  signerBinding,
  transferStatementHash,
} from "../../protocol/proof/statement.js";
import {
  ANONYMOUS_PARTIES,
  PLAIN_GROTH16_PROOF_LENGTH,
  RingTransactData,
  isDelegateRail,
  ringStreamLayout,
  ringSppInputs,
  type FrameExtensions,
  type InputTrees,
  type PolicyProof,
  type PublishedSenderBundle,
  type RingRail,
} from "../../protocol/transaction/transact.js";
import {
  MAX_SPP_CPI_ACCOUNTS,
  publicAmountFields,
  publicGrossFields,
  publicSlots,
  type PublicSlots,
  interfaceTransferOf,
  settlementAccounts,
} from "../../protocol/transaction/spp.js";
import { TransactionFit, type FitBudget, type FitSigners } from "./address-ceiling.js";
import { checkTransferFits } from "./compile.js";
import { ringRegistrySlots, transferRootRead } from "./ring-reads.js";
import {
  NO_RECORD_POOLS,
  planTransfer,
  planTransferAt,
  type PlanFrame,
  type PlannedTransfer,
  type SealRow,
} from "./transfer-plan.js";

/** The client a ring transfer reads the ring and proves with, every rail adds its SPP prover. */
export type RingProvingClient = TreeContext &
  Pick<ChainReader, "getAccount"> &
  PolicyReadClient &
  RingProver;

/** What an anonymous frame adds to a staged transfer, Rust `AnonymousSpend`. */
export interface AnonymousSpendValues {
  readonly tokenOwner?: Address;
  /** Binds the signing co-signers, each of `ANONYMOUS_PARTIES` zero when absent. */
  partyIdentities(coSigners: readonly Address[]): readonly Bytes32[];
}

/** How the SPP proof authorizes the spends of one rail, Rust `Spend`. */
export interface RailSpend {
  readonly rail: RingRail;
  /** The rail's SPP proof over the final inputs, the hidden owner signs them inside it. */
  prove(
    proofInputs: SppProofInputs,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransact | ProvenAnonymousRingTransact>;
  /** Signs the transaction beside the payer on the delegate rails. */
  readonly delegate?: Address;
  readonly anonymous?: AnonymousSpendValues;
  /** The confidential rail's owner key when it signs inside the SPP proof. */
  readonly inProofOwner?: Bytes32;
  /** The anonymous rail with every live owner a published signer. */
  readonly publicOwners?: true;
}

/** A transfer past its outputs' sealing, ready for its statements, Rust `Staged`. */
export interface StagedTransfer {
  /** Sealed by the rail, before the auditor message joins the external data. */
  readonly proofInputs: SppProofInputs;
  readonly rail: RingOutputRail;
  readonly sender: ShieldedAddress;
  /** SPP's owner signer run, empty on the authority rails. */
  readonly ownerSigners: readonly Address[];
  /** One per deposit leg in leg order, each funder signs. */
  readonly deposits?: readonly TransactDeposit[];
  readonly withdrawal?: TransactWithdrawal;
  /** Empty unless the caller sets them. */
  readonly extensions?: FrameExtensions;
  /** The frame discloses its totals under it, the digest waits for the selected key's `N`. */
  readonly approvalBlinder?: Bytes32;
  readonly spend: RailSpend;
}

/** Rust `TransactInterfaceTransferAccounts` of one deposit leg. */
export type TransactDeposit =
  | Readonly<{ kind: "sol"; funder: SignerAccount }>
  | Readonly<{
      kind: "spl";
      mint: Address;
      splTokenInterface: Address;
      funder: SignerAccount;
      sourceTokenAccount: Address;
      tokenProgram: Address;
    }>;

/** The accounts a ring transfer names besides its data, Rust `TransactAccounts`. */
export interface RingTransactAccounts {
  /** SPP's fee payer. */
  readonly payer: Address;
  /** One per tree context, in the data's order. */
  readonly inputTrees: readonly Address[];
  readonly outputTree: Address;
  readonly ownerSigners: readonly Address[];
  readonly deposits?: readonly TransactDeposit[];
  readonly withdrawal?: TransactWithdrawal;
  /** Read only, right after the ring account, tracking last. */
  readonly registries: readonly Address[];
  readonly coSigners: readonly Address[];
  readonly delegate?: Address;
  /** A cached input reads through it, last in SPP's list. */
  readonly cache?: TransactCacheAccounts;
}

/** Every value a transfer's proofs bind that the chain can move before it lands, Rust `BoundState`. */
export interface RingBoundState {
  /** The live roots the proofs bind by revision, the own root first. */
  readonly roots?: readonly BoundRoot[];
  /** Read from the tracking registry, a separate account layout. */
  readonly trackingRoot?: BoundRoot;
  readonly policy?: BoundPolicy;
}

/** A proven transfer, its compact data, accounts and the chain values its proofs bind, Rust `ProvenRingTransfer`. */
export class ProvenRingTransfer {
  readonly ringProgramId: Address;
  readonly data: RingTransactData;
  readonly accounts: RingTransactAccounts;
  /** Padding included, final slot order. */
  readonly outputs: readonly ProofOutputUtxo[];
  readonly coSigners: readonly Address[];
  /** The live roots the proofs bind, a submission proves again once one leaves its registry. */
  readonly roots: readonly BoundRoot[];
  readonly trackingRoot: BoundRoot;
  readonly policy?: BoundPolicy;
  /** What opens the frame's digest, handed to a co-signer under `CoSignerRule` exact. */
  readonly approvalOpening?: ApprovalOpening;
  /** Per owner and asset, a composed payment can charge an owner whose funds return to it. */
  readonly chargedOutflows: readonly OwnerDebit[];

  /** @internal */
  constructor(fields: Omit<ProvenRingTransfer, "instruction">) {
    this.ringProgramId = fields.ringProgramId;
    this.data = fields.data;
    this.accounts = fields.accounts;
    this.outputs = fields.outputs;
    this.coSigners = fields.coSigners;
    this.roots = fields.roots;
    this.trackingRoot = fields.trackingRoot;
    if (fields.policy !== undefined) this.policy = fields.policy;
    if (fields.approvalOpening !== undefined) this.approvalOpening = fields.approvalOpening;
    this.chargedOutflows = fields.chargedOutflows;
    Object.freeze(this);
  }

  instruction(): Promise<Instruction> {
    return ringTransactInstruction(this.ringProgramId, this.accounts, this.data);
  }
}

/** What a staged transfer's proofs read, valid inside the `assembleStagedTransfer` callback. */
interface AssembledTransfer {
  readonly sealed: SealedAudit;
  readonly published: readonly PublishedSlot[];
  readonly inputs: readonly ProofInputUtxo[];
  readonly proofInputs: SppProofInputs;
  readonly slots: PublicSlots;
  readonly policy: PolicyInputs;
  readonly coSigners: readonly Address[];
  /** Zeros off the anonymous frame. */
  readonly partyIdentities: readonly Bytes32[];
  /** The in-proof owner's identity, zero on every other rail. */
  readonly sender: Bytes32;
  /** SPP's owner signer run by owner identity, empty on the authority rails. */
  readonly signers: readonly Bytes32[];
  readonly privateTxHash: Bytes32;
  /** The one ring statement, hashed as the program rebuilds it. */
  readonly publicInputHash: Bytes32;
  readonly accounts: RingTransactAccounts;
  readonly ringId: Bytes32;
  readonly preview: RingTransactData;
  readonly approval?: TransferApproval;
}

export interface RingTransactionFrame {
  readonly priorityFeeLamports?: bigint;
  readonly setupInstructions?: readonly Instruction[];
}

/** The fit's view of a frame, one split for the preproof check and the attempt. */
export function fitSigners(payer: Address, frame: RingTransactionFrame | undefined): FitSigners {
  return frame?.setupInstructions === undefined
    ? { payer }
    : { payer, setupInstructions: frame.setupInstructions };
}

export function fitBudget(
  frame: RingTransactionFrame | undefined,
): Pick<FitBudget, "priorityFeeLamports"> {
  return frame?.priorityFeeLamports === undefined
    ? {}
    : { priorityFeeLamports: frame.priorityFeeLamports };
}

export type StagedTransferInput = Readonly<{
  client: RingProvingClient;
  ringProgramId: Address;
  config: RingPolicy;
  staged: StagedTransfer;
  coSigners?: readonly Address[];
  /** An enrolled subject on a ring reading a salted list needs its salt here. */
  listSalts?: readonly RingListSalt[];
  transaction?: RingTransactionFrame;
  approve?: (coSigners: readonly Address[]) => Promise<void>;
}>;

/** Rust `Pipeline::assemble` and `Assembled::prove`, neither proof is an input to the other. */
export function proveStagedTransfer(
  input: StagedTransferInput,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  return assembleStagedTransfer(input, context, async (assembled) => {
    await input.approve?.(assembled.coSigners);
    return proveAssembled(input, assembled, context);
  });
}

/** A staged transfer whose external data is final, Rust `Sealed`. */
export interface SealedTransfer {
  readonly sealed: SealedAudit;
  readonly plan: PlannedTransfer;
  readonly published: readonly PublishedSlot[];
  /** The spent notes in SPP order, compact padding left out. */
  readonly inputs: readonly ProofInputUtxo[];
  readonly senderBundle: PublishedSenderBundle | undefined;
  readonly shape: Shape;
  /** The owner signs its `messageHash`. */
  readonly proofInputs: SppProofInputs;
}

export function sealedTransferTerms(
  input: Readonly<{
    ringProgramId: Address;
    feePayer: Address;
    sealed: SealedTransfer;
    ownerSigners: readonly Address[];
    setup: readonly TokenAccountCreate[];
  }>,
): readonly RelayTransferTerms[] {
  const { sealed, ringProgramId } = input;
  const { proofInputs } = sealed;
  // Every signer reads every published slot, a dummy opens under the zero owner.
  const slots = Object.freeze(
    sealed.published.map(({ output }, slot) => {
      const owner = output.ownerAddress;
      return Object.freeze(
        owner === undefined || output.isDummy()
          ? {
              slot,
              owner: ZERO_ADDRESS,
              nullifierPk: ZERO_32,
              mint: ZERO_ADDRESS,
              amount: 0n,
              blinding: output.blinding,
              treeId: proofInputs.outputTreeId,
              dataHash: ZERO_32,
              ringDataHash: ZERO_32,
            }
          : {
              slot,
              owner: encodeBase58(owner.signingPublicKey.confidentialViewTag()) as Address,
              nullifierPk: owner.nullifierPublicKey,
              mint: output.asset,
              amount: output.amount,
              blinding: output.blinding,
              treeId: proofInputs.outputTreeId,
              dataHash: output.dataHash ?? ZERO_32,
              ringDataHash: output.ringDataHash ?? ZERO_32,
            },
      );
    }),
  );
  return input.ownerSigners.map((signer) => {
    // A Solana address names a wallet or a PDA alike, a key rebuilt as Ed25519 never equals a PDA owner.
    const ownedBy = (owner: ShieldedPublicKey): boolean =>
      equalBytes(owner.confidentialViewTag(), addressBytes(signer));
    return Object.freeze({
      ring: ringProgramId,
      feePayer: input.feePayer,
      signer,
      slots,
      nullifiers: Object.freeze(
        proofInputs.inputUtxos
          .filter((spent) => !spent.isDummy() && ownedBy(spent.utxo.owner))
          .map((spent) => spent.nullifier()),
      ),
      setup: input.setup,
    });
  });
}

/** The key a staged transfer selects, every stream counter follows it. */
async function selectStagedKey(input: StagedTransferInput, context: RequestContext | undefined) {
  const { client, config, staged } = input;
  const { spend } = staged;
  const delegate = isDelegateRail(spend.rail);
  const inputs = publishedNotes(staged.proofInputs);
  const transfers = staged.proofInputs.externalData.interfaceTransfers;
  const liveRows = ownerRows({ inputs, delegate });
  const demandInput = {
    client,
    config,
    rail: spend.rail,
    proofInputs: staged.proofInputs,
    publicSlots: publicSlots(transfers),
    listSalts: input.listSalts ?? [],
    ...(spend.anonymous?.tokenOwner === undefined
      ? {}
      : { tokenOwnerHint: spend.anonymous.tokenOwner }),
  };
  const demand = await policyDemand({ ...demandInput, rows: liveRows }, context);
  const shape = staged.proofInputs.checkShape();
  const addresses = { nInputs: shape.inputs, legs: transfers.length };
  checkOwnerSignerBound(
    { ...addresses, coSigners: input.coSigners?.length ?? 0 },
    staged.ownerSigners.length,
  );
  const plan = planTransfer(stagedPlanFrame(input), demand.pools);
  return { demandInput, demand, addresses, plan };
}

/** The counts a staged transfer's key is chosen from, Rust `Prepared::planner`. */
function stagedPlanFrame(
  input: Readonly<{
    config: RingPolicy;
    staged: Pick<StagedTransfer, "proofInputs"> &
      Readonly<{ spend: Pick<RailSpend, "rail" | "publicOwners"> }>;
  }>,
): PlanFrame {
  const { config, staged } = input;
  const { proofInputs, spend } = staged;
  const inputs = publishedNotes(proofInputs);
  const shape = proofInputs.checkShape();
  const published = publishedOutputs(proofInputs.outputs);
  const entry = spendsDefaultRing(proofInputs);
  return Object.freeze({
    subjects: Object.freeze({
      rail: spend.rail,
      inputs: inputs.length,
      outputs: shape.outputs,
      spendsDefaultRing: entry,
      // The program names the key from the legs its read screens, a ring reading no root
      // screens none and a deposit never counts.
      legs: policyLegs(config, spend.rail, proofInputs.externalData.interfaceTransfers),
      owners: ownerRows({ inputs, delegate: isDelegateRail(spend.rail) }).length,
      pools: NO_RECORD_POOLS,
      wide: false,
    }),
    layoutUnder: (wideOwners: boolean) =>
      ringStreamLayout({
        rail: spend.rail,
        nIn: shape.inputs,
        nOut: shape.outputs,
        inputs: inputs.length,
        outputs: published.length,
        entry,
        publicOwners: spend.publicOwners === true,
        wideOwners,
      }),
  });
}

/** A relayed owner's seal, the caller wipes `sealed.ephemeralSecret`. */
export function sealRelayedTransfer(
  input: Readonly<{
    ringProgramId: Address;
    config: RingPolicy;
    staged: Omit<StagedTransfer, "spend"> &
      Readonly<{ spend: Pick<RailSpend, "rail" | "inProofOwner" | "publicOwners"> }>;
    /** The row a Ring RPC reseal refusal names, the owner then signs the new seal. */
    sealRow?: SealRow;
  }>,
): SealedTransfer {
  const frame = stagedPlanFrame(input);
  // A direct transfer reads before it plans. The relay reads after the seal and keeps it only
  // where the read's key opens the same stream, so the seal takes the key the public counts
  // select and a later read never widens it in silence.
  const plan =
    input.sealRow === undefined
      ? planTransfer(frame, NO_RECORD_POOLS)
      : planTransferAt(frame, input.sealRow);
  return sealStagedTransfer({ ...input, plan });
}

/** The caller wipes `sealed.ephemeralSecret`. */
function sealStagedTransfer(
  input: Readonly<{
    ringProgramId: Address;
    config: RingPolicy;
    plan: PlannedTransfer;
    staged: Omit<StagedTransfer, "spend"> &
      Readonly<{ spend: Pick<RailSpend, "rail" | "inProofOwner" | "publicOwners"> }>;
  }>,
): SealedTransfer {
  const { ringProgramId, config, staged, plan } = input;
  const { rail, sender, spend } = staged;
  checkDistinctInputs(staged.proofInputs);
  checkMembership(ringProgramId, staged.proofInputs);
  checkDelegateLegs(spend.rail, staged.proofInputs);
  const shape = staged.proofInputs.checkShape();
  const inputs = publishedNotes(staged.proofInputs);
  const published = rail.publishedSlots(staged.proofInputs, sender, config.auditorPublicKey);
  const senderBundle = rail.publishedSender(staged.proofInputs, sender.viewingPublicKey);
  const auditor = config.auditorPublicKey;
  // The auditor message precedes every hash over the external data.
  const sealed = sealAudit({ rail, layout: plan.layout, published, inputs, auditor });
  try {
    return Object.freeze({
      sealed,
      plan,
      published,
      inputs,
      senderBundle,
      shape,
      proofInputs: withAuditorMessage(
        staged.proofInputs,
        sealedAuditMessage(sealed, auditor),
        staged.extensions ?? NO_EXTENSIONS,
      ),
    });
  } catch (cause) {
    sealed.ephemeralSecret.fill(0);
    throw cause;
  }
}

/** Every chain value is read once, the audit secret lives until `use` settles. */
async function assembleStagedTransfer<T>(
  input: StagedTransferInput,
  context: RequestContext | undefined,
  use: (assembled: AssembledTransfer) => Promise<T>,
): Promise<T> {
  const { client, ringProgramId, config, staged } = input;
  const { rail, spend } = staged;
  const ringRail = spend.rail;
  const delegate = isDelegateRail(ringRail);
  const { demandInput, demand, addresses, plan } = await selectStagedKey(input, context);
  const { circuit } = plan;
  const { sealed, published, inputs, senderBundle, shape, proofInputs } = sealStagedTransfer({
    ...input,
    plan,
  });
  const auditor = config.auditorPublicKey;
  try {
    const transfers = proofInputs.externalData.interfaceTransfers;
    const slots = publicSlots(transfers);
    const policy = await readPolicy(
      {
        ...demandInput,
        proofInputs,
        ringProgramId,
        publicOwners: spend.publicOwners === true,
        circuit,
        rows: ownerRows({ inputs, delegate, slots: circuit.owners }),
        demand,
      },
      context,
    );
    const noSpend = spentNotes(inputs).length === 0;
    const coSignDemand = delegate
      ? NO_DEMAND
      : operationDemand({
          spendsNote: !noSpend,
          publicLegs: publicLegClasses(transfers),
          approval: policy.approvalMask,
        });
    const coSigners = (
      await resolveRingCoSigners(
        {
          client,
          ringProgramId,
          config,
          demand: coSignDemand,
          supplied: input.coSigners ?? [],
          ownerSigners:
            spend.inProofOwner === undefined
              ? staged.ownerSigners
              : [...staged.ownerSigners, encodeBase58(spend.inProofOwner)],
        },
        context,
      )
    ).map(({ signer }) => signer);
    // The final co-signer count moves the account bound.
    checkOwnerSignerBound(
      { ...addresses, coSigners: coSigners.length },
      staged.ownerSigners.length,
    );
    const partyIdentities =
      spend.anonymous?.partyIdentities(coSigners) ??
      Array.from({ length: ANONYMOUS_PARTIES }, () => zeroField());
    const privateTxHash = proofInputs.privateTxHash();
    const statementSender =
      spend.inProofOwner === undefined
        ? zeroField()
        : (solanaOwnerIdentity(spend.inProofOwner) as Bytes32);
    const signers = staged.ownerSigners.map(
      (signer) => solanaOwnerIdentity(addressBytes(signer)) as Bytes32,
    );
    const accounts: RingTransactAccounts = Object.freeze({
      payer: proofInputs.payer,
      inputTrees: Object.freeze(proofInputs.inputTreeIds().map(treeAddress)),
      outputTree: treeAddress(proofInputs.outputTreeId),
      ownerSigners: staged.ownerSigners,
      ...(staged.deposits === undefined ? {} : { deposits: staged.deposits }),
      ...(staged.withdrawal === undefined ? {} : { withdrawal: staged.withdrawal }),
      registries: ringRegistrySlots(config, transferRootRead(config, delegate)),
      coSigners,
      ...(spend.delegate === undefined ? {} : { delegate: spend.delegate }),
      ...(proofInputs.cacheAccounts.read === undefined
        ? {}
        : { cache: TransactCacheAccounts.read(proofInputs.cacheAccounts.read) }),
    });
    const ringId = ringIdField(ringProgramId);
    const approval =
      staged.approvalBlinder === undefined
        ? undefined
        : transferApprovalOf(proofInputs, plan.layout.capacity, staged.approvalBlinder);
    const cache = cacheAccessOf(proofInputs);
    const frameExtensions: FrameExtensions = Object.freeze({
      ...staged.extensions,
      ...(approval === undefined ? {} : { approvalTotals: approval.digest }),
      ...(cache === undefined ? {} : { cache }),
    });
    const preview = previewData({
      rail: ringRail,
      shape,
      proofInputs,
      inputs,
      published,
      sealed,
      ...(senderBundle === undefined ? {} : { sender: senderBundle }),
      txViewingU: rail.txViewingKey.publicKey().u(),
      privateTxHash,
      policy,
      noSpend,
      wideOwners: plan.wideOwners,
      publicOwners: spend.publicOwners === true,
      extensions: frameExtensions,
      ...(spend.inProofOwner === undefined ? {} : { inProofOwner: spend.inProofOwner }),
    });
    const publicInputHash = transferStatementHash(
      ringTransferStatement(preview, {
        ringId,
        auditorPubkey: auditor.toBytes(),
        sender: statementSender,
        partyIdentities,
        signers: signerBinding(signers, circuit.class),
        roots: policyRoots(policy),
        publicAssets: slots.assets,
        publicAmounts: publicAmountFields(slots),
        publicGross: publicGrossFields(slots),
        withdrawalHash: policyWithdrawalHash(policy.withdrawals),
      }),
    );
    // The program's expansion must reproduce the external data the SPP proof binds.
    if (
      !equalBytes(
        RingTransactData.externalDataHash(
          preview,
          { auditorPubkey: auditor.toBytes() },
          transfers.map(settlementAccounts),
        ),
        proofInputs.externalData.hash(),
      )
    )
      throw new RingError("RING_EXTERNAL_DATA_MISMATCH");
    const inline = await ringTransactInstruction(ringProgramId, accounts, preview);
    const computeUnitLimit = ringComputeUnitLimit(transactTag(ringRail));
    checkTransferFits(shape, {
      ...input.transaction,
      feePayer: proofInputs.payer,
      instructions: [inline],
      computeUnitLimit,
    });
    TransactionFit.of(inline, fitSigners(proofInputs.payer, input.transaction), {
      ...fitBudget(input.transaction),
      computeUnitLimit,
    });
    return await use(
      Object.freeze({
        sealed,
        published,
        inputs,
        proofInputs,
        slots,
        policy,
        coSigners,
        partyIdentities,
        sender: statementSender,
        signers,
        privateTxHash,
        publicInputHash,
        accounts,
        ringId,
        preview,
        ...(approval === undefined ? {} : { approval }),
      }),
    );
  } finally {
    sealed.ephemeralSecret.fill(0);
  }
}

async function proveAssembled(
  input: StagedTransferInput,
  assembled: AssembledTransfer,
  context: RequestContext | undefined,
): Promise<ProvenRingTransfer> {
  const { client, ringProgramId, config, staged } = input;
  const { rail, spend } = staged;
  const { proofInputs, policy, coSigners, privateTxHash, ringId, preview, inputs } = assembled;
  const request = transferProofRequest({
    rail,
    ringRail: spend.rail,
    sealed: assembled.sealed,
    outputCount: assembled.published.length,
    inputs,
    proofInputs,
    recipientKeys: assembled.published.map((slot) => slot.recipientKey),
    auditor: config.auditorPublicKey,
    policy,
    proving: { ringId, publicSlots: assembled.slots },
    publicInputHash: assembled.publicInputHash,
    privateTxHash,
    sender: assembled.sender,
    inProof: spend.inProofOwner !== undefined,
    publicOwners: spend.publicOwners === true,
    partyIdentities: assembled.partyIdentities,
    signers: assembled.signers,
    ...(assembled.approval === undefined ? {} : { approval: assembled.approval }),
  });
  let proofs: readonly [ProvenRingTransact | ProvenAnonymousRingTransact, Uint8Array];
  try {
    // Each request runs in its own async call, a synchronous throw never strands the other proof.
    proofs = await Promise.all([
      (async () => spend.prove(proofInputs, context))(),
      (async () => client.proveRing(request, context))(),
    ]);
  } finally {
    wipeAuditRequest(request);
  }
  const [spp, proof] = proofs;
  const data = provenData({
    preview,
    spp: spp.data,
    privateTxHash,
    publishedInputs: inputs.length,
    proof,
  });
  return new ProvenRingTransfer({
    ringProgramId,
    data,
    accounts: assembled.accounts,
    outputs: proofInputs.outputs,
    coSigners,
    roots: boundRoots(policy),
    trackingRoot: policy.trackingBound,
    ...(screened(policy)
      ? { policy: Object.freeze({ ringProgramId, policyHash: policy.policyHash }) }
      : {}),
    ...(assembled.approval === undefined ? {} : { approvalOpening: assembled.approval.opening }),
    chargedOutflows: policy.chargedOutflows,
  });
}

/** The ring prefix, then SPP's own accounts, the data's tag by its rail, Rust `TransactAccounts::instruction`. */
export async function ringTransactInstruction(
  ringProgramId: Address,
  accounts: RingTransactAccounts,
  data: RingTransactData,
): Promise<Instruction> {
  const spp = ringSppInputs(data);
  const [ring, ringAuth] = await Promise.all([
    ringPolicyAddress(ringProgramId),
    ringAuthAddress(ringProgramId),
  ]);
  const signed = {
    payer: accounts.payer,
    inputTrees: accounts.inputTrees,
    outputTree: accounts.outputTree,
    ringAuth,
    inputs: spp.inputs,
    treeContexts: spp.treeContexts,
    ...(!isDelegateRail(data.rail) && accounts.ownerSigners.length > 0
      ? { ownerSigners: accounts.ownerSigners }
      : {}),
  };
  const settled = {
    ...signed,
    ...(accounts.withdrawal === undefined ? {} : { withdrawal: accounts.withdrawal }),
    ...(accounts.cache === undefined ? {} : { cache: accounts.cache }),
  };
  const deposits = accounts.deposits ?? [];
  let sppAccounts = await ringTransactAccounts(settled);
  if (deposits.length > 0) {
    // SPP reads the deposit groups after the owner signers and ahead of the withdrawal and cache.
    const head = await ringTransactAccounts(signed);
    sppAccounts = [
      ...head,
      ...deposits.flatMap(depositSettlementAccounts),
      ...sppAccounts.slice(head.length),
    ];
  }
  if (sppAccounts.length > MAX_SPP_CPI_ACCOUNTS)
    throw new RingError("RING_TOO_MANY_SETTLEMENT_ACCOUNTS", {
      details: { accounts: sppAccounts.length, limit: MAX_SPP_CPI_ACCOUNTS },
    });
  const prefix: AccountMeta[] = [
    meta(ring, false, false),
    ...accounts.registries.map((registry) => meta(registry, false, false)),
  ];
  for (const coSigner of accounts.coSigners)
    prefix.push(...(await ringCoSignerMetas(ringProgramId, coSigner)));
  if (accounts.delegate !== undefined) prefix.push(meta(accounts.delegate, true, false));
  const encoded = RingTransactData.encode(data);
  const bytes = new Uint8Array(1 + encoded.length);
  bytes[0] = transactTag(data.rail);
  bytes.set(encoded, 1);
  return Object.freeze({
    programAddress: ringProgramId,
    accounts: Object.freeze([...prefix, ...sppAccounts]),
    data: bytes,
  });
}

function depositSettlementAccounts(deposit: TransactDeposit): AccountMeta[] {
  if (deposit.kind === "sol")
    return [meta(SOL_INTERFACE, false, true), meta(deposit.funder, true, true)];
  return [
    meta(deposit.mint, false, false),
    meta(deposit.splTokenInterface, false, true),
    meta(deposit.funder, true, false),
    meta(deposit.sourceTokenAccount, false, true),
    meta(deposit.tokenProgram, false, false),
  ];
}

/** The auditor message joins the external data last, the expiry the compact data carries as a u32. */
function withAuditorMessage(
  proofInputs: SppProofInputs,
  message: Readonly<{ viewTag: Bytes32; data: Uint8Array }>,
  extensions: FrameExtensions,
): SppProofInputs {
  const external = proofInputs.externalData;
  return new SppProofInputs({
    payer: proofInputs.payer,
    inputUtxos: proofInputs.inputUtxos,
    outputs: proofInputs.outputs,
    externalData: createExternalData({
      instructionDiscriminator: external.instructionDiscriminator,
      expiryUnixTs: U32_MAX,
      interfaceTransfers: external.interfaceTransfers,
      ...(extensions.dataHash === undefined ? {} : { dataHash: extensions.dataHash }),
      ...(extensions.ringDataHash === undefined ? {} : { ringDataHash: extensions.ringDataHash }),
      txViewingPublicKey: external.txViewingPublicKey,
      salt: external.salt,
      outputs: external.outputs,
      resolvedOwnerTags: external.resolvedOwnerTags,
      messages: [...external.messages, ...(extensions.messages ?? []), message],
    }),
    blindingSeed: proofInputs.blindingSeed,
    outputTreeId: proofInputs.outputTreeId,
    cacheAccounts: proofInputs.cacheAccounts,
  });
}

/** The compact data before any proof, sized and hashed as the proven one, Rust `preview_parts`. */
function previewData(
  input: Readonly<{
    rail: RingRail;
    shape: Readonly<{ inputs: number; outputs: number }>;
    proofInputs: SppProofInputs;
    inputs: readonly ProofInputUtxo[];
    published: readonly PublishedSlot[];
    sealed: SealedAudit;
    sender?: PublishedSenderBundle;
    txViewingU: Bytes32;
    privateTxHash: Bytes32;
    policy: PolicyInputs;
    noSpend: boolean;
    wideOwners: boolean;
    publicOwners: boolean;
    extensions: FrameExtensions;
    inProofOwner?: Bytes32;
  }>,
): RingTransactData {
  const { policy, sealed, published } = input;
  const external = input.proofInputs.externalData;
  const zeroContext = { utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 };
  const trees = input.proofInputs.inputTreeIds().length;
  const inputTrees: InputTrees =
    trees === 1
      ? { kind: "one", context: zeroContext }
      : { kind: "two", first: zeroContext, second: zeroContext, secondInputs: 0n };
  const replies = published.flatMap((slot) => (slot.reply === undefined ? [] : [slot.reply]));
  const policySection: PolicyProof | undefined = screened(policy)
    ? Object.freeze(
        policy.curator === undefined ? {} : { curatorRevision: policy.curator.revision },
      )
    : undefined;
  const { entry } = sealed.audit;
  return Object.freeze({
    rail: input.rail,
    nIn: input.shape.inputs,
    nOut: input.shape.outputs,
    proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
    trackingRevision: policy.trackingBound.revision,
    ...(policy.own === undefined ? {} : { ownRevision: policy.own.revision }),
    ...(policySection === undefined ? {} : { policy: policySection }),
    splWithdrawalOwners: policy.own === undefined ? [] : policy.splWithdrawalOwners,
    approval: policy.approvalMask,
    noSpend: input.noSpend,
    publicOwners: input.publicOwners,
    expiryUnixTs: Number(U32_MAX),
    txViewingU: input.txViewingU,
    salt: external.salt,
    extensions: input.extensions,
    interfaceTransfers: external.interfaceTransfers.map(interfaceTransferOf),
    hasData: framesData(published.map((slot) => slot.output)),
    entry,
    wideOwners: input.wideOwners,
    outputs: Object.freeze(published.map((slot) => slot.wire)),
    ...(replies[0] === undefined
      ? {}
      : {
          replies: Object.freeze({
            length: replies[0].length,
            region: concatBytes(...replies),
          }),
        }),
    ...(input.sender === undefined ? {} : { sender: input.sender }),
    envelope: sealed.envelope,
    recipientKeys: concatBytes(...sealed.recipientKeys),
    privateTxHash: input.privateTxHash,
    ...(input.rail === "anonymous" && !input.publicOwners
      ? {
          anonymous: {
            commitment: zeroField(),
            commitmentPok: zeroField(),
            // SPP names the hidden owner's key exactly when a default-ring note is spent.
            ...(entry ? { defaultOwnerTag: zeroField() } : {}),
          },
        }
      : {}),
    ...(input.inProofOwner === undefined
      ? {}
      : {
          inProofOwner: {
            owner: input.inProofOwner,
            commitment: zeroField(),
            commitmentPok: zeroField(),
          },
        }),
    sppProof: new Uint8Array(PLAIN_GROTH16_PROOF_LENGTH),
    nullifiers: Object.freeze(input.inputs.map((spent) => spent.nullifier())),
    inputTrees,
  });
}

/** The preview with every proof in place, refused unless SPP published the preview's values. */
function provenData(
  input: Readonly<{
    preview: RingTransactData;
    spp: RingTransactInstructionData;
    privateTxHash: Bytes32;
    publishedInputs: number;
    proof: Uint8Array;
  }>,
): RingTransactData {
  const { preview, spp } = input;
  // SPP publishes the nullifier of every input slot but compact padding.
  const inputs = spp.inputs.slice(0, input.publishedInputs);
  const nullifiers = inputs.map((spent) => spent.nullifierHash);
  if (
    inputs.length !== input.publishedInputs ||
    !equalBytes(spp.privateTxHash, input.privateTxHash) ||
    nullifiers.some(
      (nullifier, index) => !equalBytes(nullifier, preview.nullifiers[index] ?? zeroField()),
    )
  )
    throw new RingError("RING_SPP_PROOF_MISMATCH");
  const [first, second, ...rest] = spp.treeContexts;
  if (first === undefined || rest.length > 0) throw new RingError("RING_SPP_PROOF_MISMATCH");
  const inputTrees: InputTrees =
    second === undefined
      ? { kind: "one", context: first }
      : {
          kind: "two",
          first,
          second,
          secondInputs: inputs.reduce(
            (bits, spent, index) => (spent.treeIndex === 1 ? bits | (1n << BigInt(index)) : bits),
            0n,
          ),
        };
  const circuit = spp.circuit;
  // The anonymous ring's hidden owner and a confidential ring's in-proof owner both prove on SPP's anonymous rail.
  const proofData =
    circuit.kind === "anonymousRingEddsa" || circuit.kind === "anonymousRingEddsaCached"
      ? circuit.proofData
      : undefined;
  const commitment =
    proofData === undefined
      ? undefined
      : {
          commitment: proofData.bsb22Commitment.commitment,
          commitmentPok: proofData.bsb22Commitment.commitmentPok,
        };
  const anonymous =
    commitment !== undefined && preview.anonymous !== undefined
      ? {
          ...commitment,
          ...(proofData?.defaultOwnerTag === undefined
            ? {}
            : { defaultOwnerTag: proofData.defaultOwnerTag }),
        }
      : undefined;
  const inProofOwner =
    commitment !== undefined && preview.inProofOwner !== undefined
      ? { owner: preview.inProofOwner.owner, ...commitment }
      : undefined;
  if (
    (commitment !== undefined) !==
      (preview.anonymous !== undefined || preview.inProofOwner !== undefined) ||
    // A default owner tag would publish the in-proof owner SPP hides.
    (inProofOwner !== undefined && proofData?.defaultOwnerTag !== undefined)
  )
    throw new RingError("RING_SPP_PROOF_MISMATCH");
  const sppProof = new Uint8Array(PLAIN_GROTH16_PROOF_LENGTH);
  sppProof.set(spp.proof.a, 0);
  sppProof.set(compressG2(spp.proof.b), 32);
  sppProof.set(spp.proof.c, 96);
  return Object.freeze({
    ...preview,
    proof: input.proof,
    ...(anonymous === undefined ? {} : { anonymous }),
    ...(inProofOwner === undefined ? {} : { inProofOwner }),
    sppProof,
    nullifiers: Object.freeze(nullifiers),
    inputTrees,
  });
}

export function spendsDefaultRing(proofInputs: SppProofInputs): boolean {
  return proofInputs.inputUtxos.some(isDefaultRingNote);
}

/** A deposit leg would bring an unlisted asset in, a delegate withdraws alone. */
function checkDelegateLegs(rail: RingRail, proofInputs: SppProofInputs): void {
  if (
    isDelegateRail(rail) &&
    proofInputs.externalData.interfaceTransfers.some((transfer) => transfer.isDeposit)
  )
    throw new RingError("RING_DELEGATE_DEPOSIT_LEG");
}

/** Each real input spends once, a repeated nullifier fails on chain after proving. */
function checkDistinctInputs(proofInputs: SppProofInputs): void {
  const seen = new Set<string>();
  proofInputs.inputUtxos.forEach((spent, index) => {
    if (spent.isDummy()) return;
    const key = bytesKey(spent.nullifier());
    if (seen.has(key)) throw new RingError("RING_DUPLICATE_INPUT", { details: { index } });
    seen.add(key);
  });
}

/** Every ring field names the transfer's ring, and only a ring note carries ring data. */
function checkMembership(ringProgramId: Address, proofInputs: SppProofInputs): void {
  const slots = [
    ...proofInputs.inputUtxos.map((spent) => ({
      ring: spent.utxo.ringProgramId,
      data: spent.ringDataHash,
    })),
    ...proofInputs.outputs.map((output) => ({
      ring: output.ringProgramId,
      data: output.ringDataHash,
    })),
  ];
  for (const { ring, data } of slots) {
    if (ring !== undefined && ring !== ringProgramId)
      throw new RingError("RING_FOREIGN_RING", { details: { ring } });
    if (ring === undefined && data !== undefined) throw new RingError("RING_DATA_OUTSIDE_RING");
  }
}

/** @internal What a submission attempt of `proven` checks before it proves again. */
export function boundState(proven: ProvenRingTransfer): RingBoundState {
  return Object.freeze({
    ...(proven.roots.length === 0 ? {} : { roots: proven.roots }),
    trackingRoot: proven.trackingRoot,
    ...(proven.policy === undefined ? {} : { policy: proven.policy }),
  });
}

function boundRoots(policy: PolicyInputs): readonly BoundRoot[] {
  return Object.freeze(
    [policy.own, policy.curator].filter((root): root is BoundRoot => root !== undefined),
  );
}

export function transactTag(rail: RingRail): RingInstructionTag {
  return isDelegateRail(rail) ? RingInstructionTag.authorityTransfer : RingInstructionTag.transfer;
}

function wipeAuditRequest(request: Readonly<{ txViewingSk: Bytes32 }>): void {
  request.txViewingSk.fill(0);
}

function zeroField(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}

const U32_MAX = 0xffff_ffffn;
const NO_EXTENSIONS: FrameExtensions = Object.freeze({});
