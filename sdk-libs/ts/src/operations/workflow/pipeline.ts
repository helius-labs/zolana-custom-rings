/**
 * One transfer pipeline for every rail, Rust `pipeline`. The rail seals the outputs, the audit proof
 * opens them to the auditor, the policy proof checks the ring's table, the SPP proof spends.
 */
import type { AccountMeta, Instruction } from "@solana/kit";

import { compressG2, meta, treeAddress, bytesKey, equalBytes } from "@heliuslabs/zolana/internal";
import { type RingProver, type RingRecordReader } from "../../rpc/ports.js";
import type { ChainReader, ProvenRingTransact, TreeContext } from "@heliuslabs/zolana/client";
import { ringTransactAccounts } from "@heliuslabs/zolana/interface";
import type {
  Address,
  Bytes32,
  RequestContext,
  TransactWithdrawal,
} from "@heliuslabs/zolana/interface";
import type { RingTransactInstructionData } from "../../protocol/proof/circuit.js";
import type { ProvenAnonymousRingTransact } from "../../rpc/ports.js";
import type { ShieldedAddress } from "@heliuslabs/zolana/keypair";
import { SppProofInputs, createExternalData } from "@heliuslabs/zolana/transaction";
import type { ProofOutputUtxo } from "@heliuslabs/zolana/transaction";
import { CUSTOM_RING_PROOF_LENGTH } from "../../protocol/proof/custom-ring-proof.js";
import { ringAuthAddress, ringConfigAddress, ringPolicyAddress } from "../../protocol/pda/index.js";
import type { AuditLayout } from "../../protocol/codec/ring-disclosure-layout.js";
import { ringIdField, senderCommitment } from "../../crypto/derivation/ring-stream.js";

import { RingInstructionTag, ringComputeUnitLimit } from "../management/admin.js";
import {
  auditProofRequest,
  sealAudit,
  sealedAuditMessage,
  type SealedAudit,
} from "../../proof/audit-proof.js";
import type { RingProgramConfig } from "../../protocol/codec/ring-codecs.js";
import {
  readWithdrawalExemption,
  type WithdrawalExemption,
} from "../../proof/withdrawal-exemption.js";
import { demandedCoSigner, transactDemand } from "../../proof/cosign.js";
import { RingError } from "../../protocol/error.js";
import {
  policyProofRequest,
  readPolicy,
  type BoundPolicy,
  type BoundRoot,
  type PolicyInputs,
} from "../../proof/policy-proof.js";
import type { PublishedSlot, RingOutputRail } from "../payments/output-rail.js";
import { auditStatementHash, ringAuditStatement } from "../../protocol/proof/statement.js";
import {
  PLAIN_GROTH16_PROOF_LENGTH,
  RingTransactData,
  ringDisclosureLayout,
  ringSppInputs,
  type InputTrees,
  type RingRail,
  type SenderBundle,
} from "../../protocol/transaction/transact.js";
import {
  publicSlots,
  type PublicSlots,
  interfaceTransferOf,
  settlementAccounts,
} from "../../protocol/transaction/spp.js";
import { checkTransactionFits } from "./compile.js";
import type { ViewingHistory } from "../../state/viewing-history.js";

/** The client a ring transfer reads the ring and proves with, every rail adds its SPP prover. */
export type RingProvingClient = TreeContext &
  Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getStorageMemberOpenings" | "getStorageRecordPool"> &
  RingProver;

/** What the anonymous rail adds to a staged transfer, Rust `AnonymousSpend`. */
export interface AnonymousSpendValues {
  readonly tokenOwner?: Address;
  readonly partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
  /** Past the transfer's tags. */
  readonly viewingHistory: ViewingHistory;
}

/** How the SPP proof authorizes the spends of one rail, Rust `Spend`. */
export interface RailSpend {
  readonly rail: RingRail;
  /** The rail's SPP proof over the final inputs, the anonymous rail signs them inside it. */
  prove(
    proofInputs: SppProofInputs,
    coSigner: Address | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransact | ProvenAnonymousRingTransact>;
  /** Signs the transaction beside the payer on the delegate rail. */
  readonly delegate?: Address;
  readonly anonymous?: AnonymousSpendValues;
}

/** A transfer past its outputs' sealing, ready for its statements, Rust `Staged`. */
export interface StagedTransfer {
  /** Sealed by the rail, before the auditor message joins the external data. */
  readonly proofInputs: SppProofInputs;
  readonly rail: RingOutputRail;
  readonly sender: ShieldedAddress;
  /** The confidential rail's owner signer run, empty on the other rails. */
  readonly ownerSigners: readonly Address[];
  readonly withdrawal?: TransactWithdrawal;
  readonly spend: RailSpend;
}

/** The accounts a ring transfer names besides its data, Rust `TransactAccounts`. */
export interface RingTransactAccounts {
  /** SPP's fee payer, the only signer an anonymous transfer takes. */
  readonly payer: Address;
  /** One per tree context, in the data's order. */
  readonly inputTrees: readonly Address[];
  readonly outputTree: Address;
  readonly ownerSigners: readonly Address[];
  readonly withdrawal?: TransactWithdrawal;
  /** Signs when the config demands it. */
  readonly coSigner?: Address;
  readonly delegate?: Address;
}

/** Every value a transfer's proofs bind that the chain can move before it lands, Rust `BoundState`. */
export interface RingBoundState {
  /** The mirrored roots the proofs bind by revision, the own root first. */
  readonly roots?: readonly BoundRoot[];
  readonly policy?: BoundPolicy;
}

/** A proven transfer, its compact data, accounts and the chain values its proofs bind, Rust `ProvenRingTransfer`. */
export class ProvenRingTransfer {
  readonly ringProgramId: Address;
  readonly data: RingTransactData;
  readonly accounts: RingTransactAccounts;
  /** Padding included, final slot order. */
  readonly outputs: readonly ProofOutputUtxo[];
  /** The co-signer the config demands, it signs the transaction. */
  readonly coSigner?: Address;
  readonly approvalRequired: boolean;
  /** The mirrored roots the proofs bind, a submission proves again once one leaves the mirror. */
  readonly roots: readonly BoundRoot[];
  readonly policy?: BoundPolicy;
  /** The anonymous sender's viewing history past the transfer's tags, stored before it is sent. */
  readonly viewingHistory?: ViewingHistory;

  /** @internal */
  constructor(fields: Omit<ProvenRingTransfer, "instruction">) {
    this.ringProgramId = fields.ringProgramId;
    this.data = fields.data;
    this.accounts = fields.accounts;
    this.outputs = fields.outputs;
    if (fields.coSigner !== undefined) this.coSigner = fields.coSigner;
    this.approvalRequired = fields.approvalRequired;
    this.roots = fields.roots;
    if (fields.policy !== undefined) this.policy = fields.policy;
    if (fields.viewingHistory !== undefined) this.viewingHistory = fields.viewingHistory;
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
  readonly publishedInputs: number;
  readonly proofInputs: SppProofInputs;
  readonly slots: PublicSlots;
  readonly senderPkHash: Bytes32;
  readonly policy: PolicyInputs | undefined;
  readonly withdrawalExemption: WithdrawalExemption | undefined;
  readonly approvalRequired: boolean;
  readonly coSigner: Address | undefined;
  readonly privateTxHash: Bytes32;
  readonly privateTxBlinding: Bytes32;
  readonly commitment: Bytes32 | undefined;
  readonly accounts: RingTransactAccounts;
  readonly ringId: Bytes32;
  readonly preview: RingTransactData;
}

export interface RingTransactionFrame {
  readonly priorityFeeLamports?: bigint;
  readonly setupInstructions?: readonly Instruction[];
}

export type StagedTransferInput = Readonly<{
  client: RingProvingClient;
  ringProgramId: Address;
  config: RingProgramConfig;
  staged: StagedTransfer;
  transaction?: RingTransactionFrame;
  approve?: (coSigner: Address | undefined) => Promise<void>;
}>;

/** Rust `Pipeline::assemble` and `Assembled::prove`, no proof is an input to another. */
export function proveStagedTransfer(
  input: StagedTransferInput,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  return assembleStagedTransfer(input, context, async (assembled) => {
    await input.approve?.(assembled.coSigner);
    return proveAssembled(input, assembled, context);
  });
}

/** Every chain value is read once, the audit secret lives until `use` settles. */
async function assembleStagedTransfer<T>(
  input: StagedTransferInput,
  context: RequestContext | undefined,
  use: (assembled: AssembledTransfer) => Promise<T>,
): Promise<T> {
  const { client, ringProgramId, config, staged } = input;
  const { rail, sender, spend } = staged;
  const ringRail = spend.rail;
  checkDistinctInputs(staged.proofInputs);
  checkMembership(ringProgramId, staged.proofInputs);
  const shape = staged.proofInputs.checkShape();
  const publishedInputs = staged.proofInputs.inputUtxos.filter((spent) => !spent.isCompact());
  const published = rail.publishedSlots(staged.proofInputs, sender);
  const senderBundle = rail.publishedSender(staged.proofInputs);
  const audit: AuditLayout = Object.freeze({
    exits: published.some((slot) => slot.wire.kind === "exit"),
    keyEscrow: config.keyEscrow,
    // A default-ring input takes the entry key, every commitment key refuses ring id zero.
    fullOpenings: ringRail === "anonymous" && spendsDefaultRing(staged.proofInputs),
  });
  const layout = ringDisclosureLayout({
    rail: ringRail,
    nIn: shape.inputs,
    nOut: shape.outputs,
    inputs: publishedInputs.length,
    outputs: published.length,
    layout: audit,
  });
  const auditor = config.auditorPublicKey;
  // The auditor message precedes every hash over the external data.
  const sealed = sealAudit({
    rail,
    audit,
    layout,
    published,
    proofInputs: staged.proofInputs,
    sender,
    auditor,
  });
  try {
    const proofInputs = withAuditorMessage(staged.proofInputs, sealedAuditMessage(sealed, auditor));
    const slots = publicSlots(proofInputs.externalData.interfaceTransfers);
    const senderPkHash = sender.signingPublicKey.ownerProofInputHash();
    const policy = config.hasPolicy
      ? await readPolicy(
          {
            ...(spend.anonymous?.tokenOwner === undefined
              ? {}
              : { tokenOwnerHint: spend.anonymous.tokenOwner }),
            client,
            ringProgramId,
            config,
            rail: ringRail,
            proofInputs,
            sender: senderPkHash,
            publicSlots: slots,
          },
          context,
        )
      : undefined;
    const approvalRequired = policy?.approvalRequired ?? false;
    const withdrawalExemption = await readWithdrawalExemption(
      {
        client,
        ringProgramId,
        config,
        demand: transactDemand(proofInputs.externalData.interfaceTransfers),
        approvalRequired,
        own: policy?.own,
      },
      context,
    );
    const coSigner = demandedCoSigner({
      withdrawalExempt: withdrawalExemption !== undefined,
      ringProgramId,
      configured: config.coSigner,
      approvalRequired,
      transfers: proofInputs.externalData.interfaceTransfers,
      ownerSigners: staged.ownerSigners,
      ...(spend.delegate === undefined ? {} : { delegate: spend.delegate }),
    });
    const privateTxHash = proofInputs.privateTxHash();
    const privateTxBlinding = proofInputs.privateTxBlinding();
    const anonymous = spend.anonymous;
    const commitment =
      anonymous !== undefined && policy !== undefined
        ? senderCommitment({ senderPkHash, privateTxBlinding })
        : undefined;
    const accounts: RingTransactAccounts = Object.freeze({
      payer: proofInputs.payer,
      inputTrees: Object.freeze(proofInputs.inputTreeIds().map(treeAddress)),
      outputTree: treeAddress(proofInputs.outputTreeId),
      ownerSigners: staged.ownerSigners,
      ...(staged.withdrawal === undefined ? {} : { withdrawal: staged.withdrawal }),
      ...(coSigner === undefined ? {} : { coSigner }),
      ...(spend.delegate === undefined ? {} : { delegate: spend.delegate }),
    });
    const ringId = ringIdField(ringProgramId);
    const preview = previewData({
      rail: ringRail,
      shape,
      audit,
      proofInputs,
      published,
      ...(senderBundle === undefined ? {} : { sender: senderBundle }),
      txViewingU: rail.txViewingKey.publicKey().u(),
      ephemeralU: sealed.ephemeralPublicKey.u(),
      sealed: sealed.sealed,
      disclosure: sealed.fields,
      privateTxHash,
      approvalRequired,
      ...(policy === undefined ? {} : { policy: { inputs: policy, senderCommitment: commitment } }),
      ...(withdrawalExemption === undefined ? {} : { withdrawalExemption }),
    });
    // The program's expansion must reproduce the external data the SPP proof binds.
    if (
      !equalBytes(
        RingTransactData.externalDataHash(
          preview,
          { auditorPubkey: auditor.toBytes() },
          proofInputs.externalData.interfaceTransfers.map(settlementAccounts),
        ),
        proofInputs.externalData.hash(),
      )
    )
      throw new RingError("RING_EXTERNAL_DATA_MISMATCH");
    checkTransactionFits({
      ...input.transaction,
      feePayer: proofInputs.payer,
      instructions: [await ringTransactInstruction(ringProgramId, accounts, preview)],
      computeUnitLimit: ringComputeUnitLimit(transactTag(ringRail)),
    });
    return await use(
      Object.freeze({
        sealed,
        published,
        publishedInputs: publishedInputs.length,
        proofInputs,
        slots,
        senderPkHash,
        policy,
        withdrawalExemption,
        approvalRequired,
        coSigner,
        privateTxHash,
        privateTxBlinding,
        commitment,
        accounts,
        ringId,
        preview,
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
  const { rail, sender, spend } = staged;
  const ringRail = spend.rail;
  const anonymous = spend.anonymous;
  const { proofInputs, policy, coSigner, privateTxHash, commitment, ringId } = assembled;
  const auditor = config.auditorPublicKey;
  const { preview } = assembled;
  const policyRequest =
    policy === undefined
      ? undefined
      : policyProofRequest(policy, {
          ringId,
          rail: ringRail,
          proofInputs,
          privateTxHash,
          sender: ringRail === "delegate" ? zeroField() : (commitment ?? assembled.senderPkHash),
          senderPkHash: assembled.senderPkHash,
          publicSlots: assembled.slots,
        });
  const auditRequest = auditProofRequest({
    rail,
    sealed: assembled.sealed,
    published: assembled.published,
    proofInputs,
    sender,
    auditor,
    ringId,
    publicInputHash: auditStatementHash(
      ringAuditStatement(preview, {
        partyIdentities: anonymous?.partyIdentities ?? [zeroField(), zeroField(), zeroField()],
        ringId,
        auditorPubkey: auditor.toBytes(),
        keyEscrow: config.keyEscrow,
      }),
    ),
    ...(anonymous === undefined
      ? {}
      : {
          anonymous: Object.freeze({
            partyIdentities: anonymous.partyIdentities,
            privateTxHash,
            privateTxBlinding: assembled.privateTxBlinding,
            senderCommitment: commitment ?? zeroField(),
          }),
        }),
  });
  let proofs: readonly [
    ProvenRingTransact | ProvenAnonymousRingTransact,
    Uint8Array,
    Uint8Array | undefined,
    Uint8Array | undefined,
  ];
  try {
    // Each request runs in its own async call, a synchronous throw never strands another proof.
    proofs = await Promise.all([
      (async () => spend.prove(proofInputs, coSigner, context))(),
      (async () => client.proveRing(auditRequest, context))(),
      (async () =>
        policyRequest === undefined ? undefined : client.proveRing(policyRequest, context))(),
      (async () =>
        assembled.withdrawalExemption === undefined
          ? undefined
          : client.proveRing(assembled.withdrawalExemption.request, context))(),
    ]);
  } finally {
    wipeAuditRequest(auditRequest);
  }
  const [spp, auditProof, policyProof, withdrawalProof] = proofs;
  const data = provenData({
    preview,
    spp: spp.data,
    privateTxHash,
    publishedInputs: assembled.publishedInputs,
    auditProof,
    ...(policyProof === undefined ? {} : { policyProof }),
    ...(withdrawalProof === undefined ? {} : { withdrawalProof }),
  });
  return new ProvenRingTransfer({
    ringProgramId,
    data,
    accounts: assembled.accounts,
    outputs: proofInputs.outputs,
    ...(coSigner === undefined ? {} : { coSigner }),
    approvalRequired: assembled.approvalRequired,
    roots: [
      ...(policy === undefined ? [] : boundRoots(policy)),
      ...(assembled.withdrawalExemption === undefined ? [] : [assembled.withdrawalExemption.root]),
    ],
    ...(policy === undefined
      ? {}
      : { policy: Object.freeze({ ringProgramId, policyHash: policy.pinned.policyHash }) }),
    ...(anonymous === undefined ? {} : { viewingHistory: anonymous.viewingHistory }),
  });
}

/** The ring prefix, then SPP's own accounts, the data's tag by its rail, Rust `TransactAccounts::instruction`. */
export async function ringTransactInstruction(
  ringProgramId: Address,
  accounts: RingTransactAccounts,
  data: RingTransactData,
): Promise<Instruction> {
  const spp = ringSppInputs(data);
  const [config, policy, ringAuth] = await Promise.all([
    ringConfigAddress(ringProgramId),
    ringPolicyAddress(ringProgramId),
    ringAuthAddress(ringProgramId),
  ]);
  const sppAccounts = await ringTransactAccounts({
    payer: accounts.payer,
    inputTrees: accounts.inputTrees,
    outputTree: accounts.outputTree,
    ringAuth,
    inputs: spp.inputs,
    treeContexts: spp.treeContexts,
    ...(data.rail === "confidential" && accounts.ownerSigners.length > 0
      ? { ownerSigners: accounts.ownerSigners }
      : {}),
    ...(accounts.withdrawal === undefined ? {} : { withdrawal: accounts.withdrawal }),
  });
  const prefix: AccountMeta[] = [meta(config, false, false)];
  if (data.policy !== undefined || data.withdrawalExemption !== undefined)
    prefix.push(meta(policy, false, false));
  if (accounts.coSigner !== undefined) prefix.push(meta(accounts.coSigner, true, false));
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

/** The auditor message joins the external data last, the expiry the compact data carries as a u32. */
function withAuditorMessage(
  proofInputs: SppProofInputs,
  message: Readonly<{ viewTag: Bytes32; data: Uint8Array }>,
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
      txViewingPublicKey: external.txViewingPublicKey,
      salt: external.salt,
      outputs: external.outputs,
      resolvedOwnerTags: external.resolvedOwnerTags,
      messages: [...external.messages, message],
    }),
    blindingSeed: proofInputs.blindingSeed,
    outputTreeId: proofInputs.outputTreeId,
  });
}

/** The compact data before any proof, sized and hashed as the proven one, Rust `preview_parts`. */
function previewData(
  input: Readonly<{
    rail: RingRail;
    shape: Readonly<{ inputs: number; outputs: number }>;
    audit: AuditLayout;
    proofInputs: SppProofInputs;
    published: readonly Readonly<{ wire: RingTransactData["outputs"][number] }>[];
    sender?: SenderBundle;
    txViewingU: Bytes32;
    ephemeralU: Bytes32;
    sealed: Bytes32;
    disclosure: readonly Bytes32[];
    privateTxHash: Bytes32;
    approvalRequired: boolean;
    policy?: Readonly<{ inputs: PolicyInputs; senderCommitment: Bytes32 | undefined }>;
    withdrawalExemption?: WithdrawalExemption;
  }>,
): RingTransactData {
  const external = input.proofInputs.externalData;
  const outputs = input.published.map((slot) => slot.wire);
  const zeroContext = { utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 };
  const trees = input.proofInputs.inputTreeIds().length;
  const inputTrees: InputTrees =
    trees === 1
      ? { kind: "one", context: zeroContext }
      : { kind: "two", first: zeroContext, second: zeroContext, secondInputs: 0n };
  return Object.freeze({
    rail: input.rail,
    nIn: input.shape.inputs,
    nOut: input.shape.outputs,
    auditProof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
    ...(input.policy === undefined
      ? {}
      : {
          policy: {
            proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
            ownRevision: input.policy.inputs.own.revision,
            splWithdrawalOwners: input.policy.inputs.splWithdrawalOwners,
            ...(input.policy.inputs.curator === undefined
              ? {}
              : { curatorRevision: input.policy.inputs.curator.root.revision }),
            ...(input.policy.senderCommitment === undefined
              ? {}
              : { senderCommitment: input.policy.senderCommitment }),
          },
        }),
    ...(input.withdrawalExemption === undefined
      ? {}
      : {
          withdrawalExemption: {
            proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
            revision: input.withdrawalExemption.root.revision,
          },
        }),
    approvalRequired: input.approvalRequired,
    expiryUnixTs: Number(U32_MAX),
    txViewingU: input.txViewingU,
    salt: external.salt,
    interfaceTransfers: external.interfaceTransfers.map(interfaceTransferOf),
    keyEscrow: input.audit.keyEscrow,
    fullOpenings: input.audit.fullOpenings,
    outputs: Object.freeze(outputs),
    ...(input.sender === undefined ? {} : { sender: input.sender }),
    ephU: input.ephemeralU,
    sealed: input.sealed,
    disclosure: input.disclosure,
    privateTxHash: input.privateTxHash,
    ...(input.rail === "anonymous"
      ? {
          anonymous: {
            commitment: zeroField(),
            commitmentPok: zeroField(),
            // SPP names the hidden owner's key exactly when a default-ring note is spent.
            ...(input.audit.fullOpenings ? { defaultOwnerTag: zeroField() } : {}),
          },
        }
      : {}),
    sppProof: new Uint8Array(PLAIN_GROTH16_PROOF_LENGTH),
    nullifiers: Object.freeze(
      input.proofInputs.inputUtxos
        .filter((spent) => !spent.isCompact())
        .map((spent) => spent.nullifier()),
    ),
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
    auditProof: Uint8Array;
    policyProof?: Uint8Array;
    withdrawalProof?: Uint8Array;
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
  const anonymous =
    circuit.kind === "anonymousRingEddsa"
      ? {
          commitment: circuit.proofData.bsb22Commitment.commitment,
          commitmentPok: circuit.proofData.bsb22Commitment.commitmentPok,
          ...(circuit.proofData.defaultOwnerTag === undefined
            ? {}
            : { defaultOwnerTag: circuit.proofData.defaultOwnerTag }),
        }
      : undefined;
  if ((anonymous !== undefined) !== (preview.rail === "anonymous"))
    throw new RingError("RING_SPP_PROOF_MISMATCH");
  const sppProof = new Uint8Array(PLAIN_GROTH16_PROOF_LENGTH);
  sppProof.set(spp.proof.a, 0);
  sppProof.set(compressG2(spp.proof.b), 32);
  sppProof.set(spp.proof.c, 96);
  return Object.freeze({
    ...preview,
    auditProof: input.auditProof,
    ...(preview.withdrawalExemption === undefined || input.withdrawalProof === undefined
      ? {}
      : { withdrawalExemption: { ...preview.withdrawalExemption, proof: input.withdrawalProof } }),
    ...(preview.policy === undefined || input.policyProof === undefined
      ? {}
      : { policy: { ...preview.policy, proof: input.policyProof } }),
    ...(anonymous === undefined ? {} : { anonymous }),
    sppProof,
    nullifiers: Object.freeze(nullifiers),
    inputTrees,
  });
}

export function spendsDefaultRing(proofInputs: SppProofInputs): boolean {
  return proofInputs.inputUtxos.some(
    (spent) => !spent.isCompact() && !spent.isDummy() && spent.utxo.ringProgramId === undefined,
  );
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
    ...(proven.policy === undefined ? {} : { policy: proven.policy }),
  });
}

function boundRoots(policy: PolicyInputs): readonly BoundRoot[] {
  return Object.freeze(
    policy.curator === undefined ? [policy.own] : [policy.own, policy.curator.root],
  );
}

function transactTag(rail: RingRail): RingInstructionTag {
  return rail === "delegate" ? RingInstructionTag.delegateTransact : RingInstructionTag.transact;
}

function wipeAuditRequest(request: Readonly<{ txViewingSk: Bytes32; ephSk: Bytes32 }>): void {
  request.txViewingSk.fill(0);
  request.ephSk.fill(0);
}

function zeroField(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}

const U32_MAX = 0xffff_ffffn;
