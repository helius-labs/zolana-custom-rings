import { getBase64Decoder, type Instruction } from "@solana/kit";

import { type RingProver, type RingRecordReader } from "../../rpc/ports.js";
import { encodeRingDepositPlaintext } from "../../protocol/codec/ring-deposit-plaintext.js";
import {
  bigIntBytes,
  compileUnsignedTransaction,
  equalBytes,
  resolveDepositSettlement,
  signerAddress,
  waitForProjection,
  ZERO_32,
  resolveShieldedRecipient,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import { checkIntentApproval, type SignerAccount } from "@heliuslabs/zolana/internal";
import type {
  Address,
  Bytes32,
  RequestContext,
  RingAssetDeposit,
  Transaction,
} from "@heliuslabs/zolana/interface";
import {
  randomBlinding,
  randomSalt,
  ShieldedAddress,
  ViewingKey,
} from "@heliuslabs/zolana/keypair";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  assetField,
  SOL_MINT,
  Data,
  Utxo,
  ownerUtxoHash,
  approveUnattended,
  type ApprovalHandler,
  type TransactionIntent,
} from "@heliuslabs/zolana/transaction";
import type { DepositClient } from "@heliuslabs/zolana/wallet";
import type { DepositProofRequest, PolicyTableProofInputs } from "../../rpc/prover/ring.js";
import { depositBlinding } from "../../crypto/derivation/ring-domain.js";

import { checkSignersHideOwner } from "./anonymous.js";
import type { RingPolicy } from "../../protocol/codec/ring-codecs.js";
import { fetchRingPolicy } from "../../protocol/membership/config.js";
import { DEPOSIT_DEMAND, resolveRingCoSigner } from "../../proof/cosign.js";
import { type RingDepositCapsule } from "../../protocol/codec/deposit-capsule.js";
import {
  ringDepositContextHash,
  ringDepositPublicInputHash,
  sealRingDepositOpenings,
  type DepositedAsset,
} from "../../proof/deposit-audit.js";
import {
  ringDepositInstruction,
  ringDepositSpp,
} from "../../protocol/transaction/deposit-instruction.js";
import { RingError, wrapRingError } from "../../protocol/error.js";
import {
  boundRoot,
  ownRoot,
  readMemberOpenings,
  type BoundRoot,
} from "../../rpc/registered-record.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "../../rpc/projection.js";
import { ownerEscrowed, type EscrowedRecord } from "../../protocol/membership/member-opening.js";
import type { RecordOpening } from "../../protocol/membership/member-registry.js";
import { pinnedPolicy, policyTableProofInputs } from "../../protocol/membership/policy.js";
import { type RingKeys } from "../../state/ring-keys.js";
import type { RingAddress } from "../../crypto/keys/ring-address.js";
import type { FirstContact, ViewingHistory } from "../../state/viewing-history.js";
import { encodeRelayDepositInputs } from "../../protocol/ring-rpc/relay-deposit-inputs.js";
import type { RelayIntent, RelayQuote } from "../../protocol/ring-rpc/ring-rpc-types.js";
import { PreparedRelay } from "../../rpc/relay.js";
import { ringIntentMismatch } from "../workflow/selection.js";
import { assetLabel } from "./transfer.js";

const base64 = getBase64Decoder();

/** Rust `compute_unit_limit(Deposit)`. */
export const RING_DEPOSIT_COMPUTE_UNIT_LIMIT = 1_400_000;

/** Who a deposit pays, Rust `DepositRecipient`. */
export type RingDepositRecipient =
  /** A confidential ring member, found under its viewing key's tag. */
  | Readonly<{ kind: "confidential"; address: Address | ShieldedAddress }>
  /** The depositor's own hidden identity on an anonymous ring, under its next sender tag. */
  | Readonly<{ kind: "anonymous"; keys: RingKeys; history: ViewingHistory }>
  /** Another member of an anonymous ring, its tag by the selection over the depositor's history. */
  | Readonly<{
      kind: "anonymousPayment";
      keys: RingKeys;
      history: ViewingHistory;
      to: RingAddress;
      firstContact: FirstContact;
    }>;

type TaggedRecipient = Readonly<{
  address: ShieldedAddress;
  viewTag: Bytes32;
  history?: ViewingHistory;
}>;

export type RingDepositClient = DepositClient &
  Pick<RingRecordReader, "getStorageMemberOpenings"> &
  RingProver;

export interface RingDepositParams {
  readonly client: RingDepositClient;
  readonly ringProgramId: Address;
  readonly feePayer: Address;
  /** Funds the deposit, the fee payer when absent. */
  readonly depositor?: SignerAccount;
  readonly tree?: Address;
  readonly recipient: RingDepositRecipient;
  readonly asset?: Address;
  readonly amount: bigint;
  readonly splTokenAccount?: Address;
  readonly splTokenProgram?: Address | null;
  readonly memo?: Uint8Array;
  /** Signs when a record covers deposits, the record must be its own. */
  readonly cosigner?: SignerAccount;
}

/** Rust `RingDeposit::prepare_relay`. */
export interface RingDepositRelayParams extends DepositSealingParams {
  readonly quote: RelayQuote;
  readonly approve?: ApprovalHandler;
}

/** Store `viewingHistory` in place of the old one before `relay.send`. */
export interface PreparedRingDepositRelay {
  readonly relay: PreparedRelay;
  readonly viewingHistory?: ViewingHistory;
}

type DepositSealingParams = Omit<
  RingDepositParams,
  "client" | "feePayer" | "depositor" | "cosigner"
> &
  Readonly<{
    client: DepositClient;
    /** Funds the deposit and signs its message. */
    depositor: SignerAccount;
  }>;

type DepositSealing = Readonly<{
  config: RingPolicy;
  recipient: TaggedRecipient;
  ownerKey: Bytes32 | undefined;
  asset: Address;
  settlement: RingAssetDeposit["asset"];
}>;

/** A proven deposit with the registry roots its proof binds. */
export interface ProvenRingDeposit {
  readonly instruction: Instruction;
  /** The own root an escrow or policy ring's proof binds by revision, then any curator root. */
  readonly roots?: readonly BoundRoot[];
}

/** Rust `DepositRecords`. */
interface DepositRecords {
  readonly root: BoundRoot;
  readonly escrowed?: EscrowedRecord;
  readonly policy?: Readonly<{
    policyHash: Bytes32;
    table: PolicyTableProofInputs;
    asset: RecordOpening;
    /** Absent without a curator source. */
    curator?: Readonly<{ root: BoundRoot; asset: RecordOpening }>;
  }>;
}

/** A deposit whose note and auditor ciphertext every proof reuses, Rust `PreparedRingDeposit`. */
export class PreparedRingDeposit {
  /** The note the deposit creates. */
  readonly utxo: Utxo;
  /** The depositor's viewing history past the deposit's tag, stored before it is sent. */
  readonly viewingHistory?: ViewingHistory;
  readonly #ringProgramId: Address;
  readonly #tree: Address;
  readonly #recipient: ShieldedAddress;
  readonly #depositor: SignerAccount;
  readonly #cosigner: SignerAccount | undefined;
  readonly #deposit: RingAssetDeposit;
  readonly #capsule: RingDepositCapsule;
  readonly #contextHash: Bytes32;
  readonly #ownerPkHash: Bytes32;
  readonly #nullifierPk: Bytes32;
  /** The Ed25519 owner key an anonymous ring discloses, the proof binds it to the owner hash. */
  readonly #ownerKey: Bytes32 | undefined;
  readonly #auditor: X25519PublicKey;
  readonly #keyEscrow: boolean;
  readonly #hasPolicy: boolean;
  readonly #asset: DepositedAsset;
  readonly #blindingSecret: Bytes32;
  readonly #ephemeralSecret: Bytes32;

  private constructor(state: {
    utxo: Utxo;
    viewingHistory: ViewingHistory | undefined;
    ringProgramId: Address;
    tree: Address;
    recipient: ShieldedAddress;
    depositor: SignerAccount;
    cosigner: SignerAccount | undefined;
    deposit: RingAssetDeposit;
    capsule: RingDepositCapsule;
    contextHash: Bytes32;
    ownerPkHash: Bytes32;
    nullifierPk: Bytes32;
    ownerKey: Bytes32 | undefined;
    auditor: X25519PublicKey;
    keyEscrow: boolean;
    hasPolicy: boolean;
    asset: DepositedAsset;
    blindingSecret: Bytes32;
    ephemeralSecret: Bytes32;
  }) {
    this.utxo = state.utxo;
    if (state.viewingHistory !== undefined) this.viewingHistory = state.viewingHistory;
    this.#ringProgramId = state.ringProgramId;
    this.#tree = state.tree;
    this.#recipient = state.recipient;
    this.#depositor = state.depositor;
    this.#cosigner = state.cosigner;
    this.#deposit = state.deposit;
    this.#capsule = state.capsule;
    this.#contextHash = state.contextHash;
    this.#ownerPkHash = state.ownerPkHash;
    this.#nullifierPk = state.nullifierPk;
    this.#ownerKey = state.ownerKey;
    this.#auditor = state.auditor;
    this.#keyEscrow = state.keyEscrow;
    this.#hasPolicy = state.hasPolicy;
    this.#asset = state.asset;
    this.#blindingSecret = state.blindingSecret;
    this.#ephemeralSecret = state.ephemeralSecret;
  }

  /** Fixes the note against the ring's mode, co-signer and auditor. */
  static async prepare(
    params: RingDepositParams,
    context?: RequestContext,
  ): Promise<PreparedRingDeposit> {
    try {
      const depositor = params.depositor ?? params.feePayer;
      const sealingParams = { ...params, depositor };
      const sealing = await depositSealing(sealingParams, context);
      checkDepositSigners(sealing, [params.feePayer, depositor, params.cosigner]);
      const demanded = await resolveRingCoSigner(
        {
          client: params.client,
          ringProgramId: params.ringProgramId,
          config: sealing.config,
          demand: DEPOSIT_DEMAND,
          approvalRequired: false,
          supplied: params.cosigner === undefined ? undefined : signerAddress(params.cosigner),
        },
        context,
      );
      return PreparedRingDeposit.#seal({
        params: sealingParams,
        sealing,
        cosigner: demanded === undefined ? undefined : params.cosigner,
        tree: params.tree ?? params.client.tree,
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    }
  }

  /** Reads no record, Ring RPC answers with the message the depositor signs. */
  static async prepareRelay(
    params: RingDepositRelayParams,
    context?: RequestContext,
  ): Promise<PreparedRingDepositRelay> {
    let prepared: PreparedRingDeposit | undefined;
    let payload: Uint8Array | undefined;
    try {
      const sealing = await depositSealing(params, context);
      checkDepositSigners(sealing, [params.quote.feePayer, params.depositor]);
      prepared = await PreparedRingDeposit.#seal({
        params,
        sealing,
        cosigner: undefined,
        tree: params.tree ?? params.client.tree,
      });
      const intent: TransactionIntent = {
        kind: "ringDeposit",
        ringProgramId: params.ringProgramId,
        asset: sealing.asset,
        amount: params.amount,
        recipient: prepared.#recipient,
      };
      const approval = await (params.approve ?? approveUnattended)({
        solanaPublicKey: signerAddress(params.depositor),
        intent,
        summary: `ring deposit of ${String(params.amount)} ${assetLabel(sealing.asset)} into ring ${params.ringProgramId}`,
      });
      checkIntentApproval(approval, intent, ringIntentMismatch);
      payload = encodeRelayDepositInputs({
        ringProgramId: prepared.#ringProgramId,
        tree: prepared.#tree,
        depositor: signerAddress(prepared.#depositor),
        recipient: prepared.#recipient,
        deposit: prepared.#deposit,
        blindingSecret: prepared.#blindingSecret,
        auditEphemeralKey: prepared.#ephemeralSecret,
      });
      return Object.freeze({
        relay: new PreparedRelay({
          ring: params.ringProgramId,
          quote: params.quote,
          intent: {
            operation: "deposit",
            proofInputs: base64.decode(payload) as RelayIntent["proofInputs"],
          },
        }),
        ...(prepared.viewingHistory === undefined
          ? {}
          : { viewingHistory: prepared.viewingHistory }),
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    } finally {
      payload?.fill(0);
      prepared?.destroy();
    }
  }

  /** A root below a raised floor is proved again over the same note under a fresh root. */
  async prove(client: RingDepositClient, context?: RequestContext): Promise<ProvenRingDeposit> {
    try {
      const records =
        this.#keyEscrow || this.#hasPolicy ? await this.#records(client, context) : undefined;
      const escrowed = records?.escrowed;
      const policy = records?.policy;
      const curator = policy?.curator;
      const anonymous = this.#ownerKey !== undefined;
      const commitment = this.#deposit.ownerUtxoHash;
      const first = <T>(value: T, _padding: T): readonly T[] => [value];
      const request: DepositProofRequest = {
        kind: "deposit",
        publicInputHash: ringDepositPublicInputHash({
          contextHash: this.#contextHash,
          anonymous,
          ownerCommitments: [commitment],
          capsules: [this.#capsule],
          assets: [this.#asset],
          auditorPublicKey: this.#auditor,
          ...(records === undefined
            ? {}
            : {
                registry: {
                  ownRoot: records.root.root,
                  ...(curator === undefined ? {} : { curatorRoot: curator.root.root }),
                  keyEscrow: this.#keyEscrow,
                  ...(policy === undefined ? {} : { policyHash: policy.policyHash }),
                },
              }),
        }),
        contextHash: this.#contextHash,
        count: 1,
        anonymous,
        ownerPkHashes: first(this.#ownerPkHash, ZERO_32),
        ...(this.#ownerKey === undefined ? {} : { ownerKeys: first(this.#ownerKey, ZERO_32) }),
        nullifierPks: first(this.#nullifierPk, ZERO_32),
        blindingSecrets: first(this.#blindingSecret, ZERO_32),
        ctHashes: first(escrowed?.ctHash ?? ZERO_32, ZERO_32),
        members: first(
          escrowed === undefined
            ? undefined
            : Object.freeze({
                kind: "present" as const,
                record: escrowed.record,
                path: escrowed.path,
              }),
          undefined,
        ),
        ephSk: this.#ephemeralSecret,
        auditorPk: this.#auditor.u(),
        keyEscrow: escrowed !== undefined,
        memberRegistryRoot: records?.root.root ?? ZERO_32,
        curatorRoot: curator?.root.root ?? ZERO_32,
        policyHash: policy?.policyHash ?? ZERO_32,
        assets: first(this.#asset.asset, ZERO_32),
        amounts: first(bigIntBytes(this.#asset.amount, 32) as Bytes32, ZERO_32),
        ...(policy === undefined ? {} : { table: policy.table }),
        assetRecords: first(policy?.asset, undefined),
        curatorAssetRecords: first(curator?.asset, undefined),
      };
      const proof = await client.proveRing(request, context);
      return Object.freeze({
        instruction: await ringDepositInstruction({
          ringProgramId: this.#ringProgramId,
          tree: this.#tree,
          depositor: this.#depositor,
          deposits: [this.#deposit],
          proof,
          ...(records === undefined ? {} : { ownRevision: records.root.revision }),
          ...(curator === undefined ? {} : { curatorRevision: curator.root.revision }),
          ...(this.#cosigner === undefined ? {} : { cosigner: this.#cosigner }),
        }),
        ...(records === undefined
          ? {}
          : {
              roots: Object.freeze(
                curator === undefined ? [records.root] : [records.root, curator.root],
              ),
            }),
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    }
  }

  /** Wipes the blinding secret and the auditor sealing key. */
  destroy(): void {
    this.#blindingSecret.fill(0);
    this.#ephemeralSecret.fill(0);
  }

  #records(
    client: RingDepositClient,
    context: RequestContext | undefined,
  ): Promise<DepositRecords> {
    return waitForProjection(
      async (attempt) => {
        const policy = await fetchRingPolicy(client, this.#ringProgramId, attempt);
        const root = ownRoot(this.#ringProgramId, policy);
        const pinned = equalBytes(policy.policyHash, ZERO_32) ? undefined : pinnedPolicy(policy);
        const owners = this.#keyEscrow ? [this.#ownerPkHash] : [];
        const assets = pinned === undefined ? [] : [this.#asset.asset];
        const reads = await readMemberOpenings(
          { client, root, members: [...owners, ...assets] },
          attempt,
        );
        const escrowed = this.#keyEscrow
          ? ownerEscrowed(this.#ownerPkHash, reads[0], this.#nullifierPk)
          : undefined;
        const asset = reads[owners.length];
        const curator =
          pinned?.curator === undefined
            ? undefined
            : await this.#curatorAsset(client, policy, pinned.curator, attempt);
        return Object.freeze({
          root,
          ...(escrowed === undefined ? {} : { escrowed }),
          ...(pinned === undefined || asset === undefined
            ? {}
            : {
                policy: Object.freeze({
                  policyHash: pinned.policyHash,
                  table: policyTableProofInputs(pinned.table, pinned.sources),
                  asset: asset.opening,
                  ...(curator === undefined ? {} : { curator }),
                }),
              }),
        });
      },
      MEMBER_REGISTRY_PROJECTION_ERRORS,
      context,
    );
  }

  async #curatorAsset(
    client: RingDepositClient,
    policy: RingPolicy,
    registry: Address,
    context: RequestContext | undefined,
  ): Promise<Readonly<{ root: BoundRoot; asset: RecordOpening }>> {
    const root = boundRoot({
      ringProgramId: this.#ringProgramId,
      policy,
      mirror: "curator",
      registry,
    });
    const [read] = await readMemberOpenings(
      { client, root, members: [this.#asset.asset] },
      context,
    );
    if (read === undefined) throw new RingError("RING_BUILD_DEPOSIT");
    return Object.freeze({ root, asset: read.opening });
  }

  /** The note, its recipient ciphertext and the auditor capsule, sealed under fresh secrets. */
  static async #seal(
    input: Readonly<{
      params: DepositSealingParams;
      sealing: DepositSealing;
      cosigner: SignerAccount | undefined;
      tree: Address;
    }>,
  ): Promise<PreparedRingDeposit> {
    const { params, sealing } = input;
    const { recipient } = sealing;
    const blindingSecret = randomBlinding();
    const blinding = depositBlinding(blindingSecret);
    const ownerHash = recipient.address.ownerHash();
    const envelope = ViewingKey.generate();
    const plaintext = encodeRingDepositPlaintext({
      blinding,
      ...(params.memo === undefined ? {} : { memo: params.memo }),
      ringData: new Uint8Array(),
    });
    let ephemeralSecret: Bytes32 | undefined;
    try {
      const salt = randomSalt();
      const sealed = sealRingDepositOpenings(
        [
          {
            ownerHash,
            blinding,
            ...(sealing.ownerKey === undefined ? {} : { ownerKey: sealing.ownerKey }),
            recipientCiphertext: envelope.encryptRingDeposit(
              recipient.address.viewingPublicKey,
              plaintext,
              salt,
            ),
          },
        ],
        sealing.config.auditorPublicKey,
      );
      ephemeralSecret = sealed.ephemeralSecret;
      const [capsule] = sealed.capsules;
      const [payload] = sealed.payloads;
      if (capsule === undefined || payload === undefined) throw new RingError("RING_BUILD_DEPOSIT");
      const deposit: RingAssetDeposit = Object.freeze({
        asset: sealing.settlement,
        viewTag: recipient.viewTag,
        ownerUtxoHash: ownerUtxoHash(ownerHash, blinding),
        amount: params.amount,
        ringDataHash: ZERO_32,
        encrypted: Object.freeze({
          txViewingPublicKey: envelope.publicKey().toBytes(),
          salt,
          ciphertext: payload,
        }),
      });
      const spp = await ringDepositSpp({
        ringProgramId: params.ringProgramId,
        tree: input.tree,
        depositor: params.depositor,
        deposits: [deposit],
      });
      const prepared = new PreparedRingDeposit({
        utxo: new Utxo({
          owner: recipient.address.signingPublicKey,
          asset: sealing.asset,
          amount: params.amount,
          blinding,
          data: new Data(),
          ringProgramId: params.ringProgramId,
        }),
        viewingHistory: recipient.history,
        ringProgramId: params.ringProgramId,
        tree: input.tree,
        recipient: recipient.address,
        depositor: params.depositor,
        cosigner: input.cosigner,
        deposit,
        capsule,
        contextHash: ringDepositContextHash(params.ringProgramId, input.tree, spp.data),
        ownerPkHash: recipient.address.signingPublicKey.ownerProofInputHash(),
        nullifierPk: recipient.address.nullifierPublicKey,
        ownerKey: sealing.ownerKey,
        auditor: sealing.config.auditorPublicKey,
        keyEscrow: sealing.config.keyEscrow,
        hasPolicy: sealing.config.hasPolicy,
        asset: Object.freeze({ asset: assetField(sealing.asset), amount: params.amount }),
        blindingSecret,
        ephemeralSecret,
      });
      ephemeralSecret = undefined;
      return prepared;
    } catch (cause) {
      blindingSecret.fill(0);
      throw cause;
    } finally {
      envelope.destroy();
      ownerHash.fill(0);
      plaintext.fill(0);
      ephemeralSecret?.fill(0);
    }
  }
}

/** Prepares, proves and compiles one audited deposit, Rust `RingDeposit::send`. */
export async function buildRingDepositTransaction(
  params: RingDepositParams,
  context?: RequestContext,
): Promise<Transaction> {
  const prepared = await PreparedRingDeposit.prepare(params, context);
  try {
    // A plain build drops the history past its tag.
    if (prepared.viewingHistory !== undefined)
      throw new RingError("RING_ANONYMOUS_SUBMISSION_REQUIRED", {
        details: { ringProgramId: params.ringProgramId, use: "PreparedRingDeposit" },
      });
    const { instruction } = await prepared.prove(params.client, context);
    return await compileUnsignedTransaction({
      feePayer: params.feePayer,
      lifetime: await params.client.getLatestBlockhash(context),
      computeUnitLimit: RING_DEPOSIT_COMPUTE_UNIT_LIMIT,
      instructions: [instruction],
    });
  } catch (cause) {
    throw wrapRingError("RING_BUILD_DEPOSIT", cause);
  } finally {
    prepared.destroy();
  }
}

async function depositSealing(
  params: DepositSealingParams,
  context: RequestContext | undefined,
): Promise<DepositSealing> {
  await initializePoseidon();
  const config = await fetchRingPolicy(params.client, params.ringProgramId, context);
  const anonymous = config.mode === "anonymous";
  const recipient = await depositRecipient(params, anonymous, context);
  const asset = params.asset ?? SOL_MINT;
  const settlement = await resolveDepositSettlement(
    {
      asset,
      depositor: signerAddress(params.depositor),
      ...(params.splTokenAccount === undefined ? {} : { splTokenAccount: params.splTokenAccount }),
      ...(params.splTokenProgram === undefined ? {} : { splTokenProgram: params.splTokenProgram }),
    },
    () => new RingError("RING_BUILD_DEPOSIT", { details: { reason: "missing token account" } }),
  );
  return Object.freeze({
    config,
    recipient,
    ownerKey: anonymous ? recipient.address.signingPublicKey.ed25519() : undefined,
    asset,
    settlement,
  });
}

/** No transaction signer may name an anonymous ring's owner. */
function checkDepositSigners(
  sealing: DepositSealing,
  signers: readonly (Address | SignerAccount | undefined)[],
): void {
  if (sealing.ownerKey === undefined) return;
  checkSignersHideOwner(
    sealing.ownerKey,
    signers.map((party) => (party === undefined ? undefined : signerAddress(party))),
  );
}

/** The recipient's address and the tag its scan reads, refused when the ring mode disagrees. */
async function depositRecipient(
  params: DepositSealingParams,
  anonymous: boolean,
  context: RequestContext | undefined,
): Promise<TaggedRecipient> {
  const recipient = params.recipient;
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
    return { address, viewTag: address.viewingPublicKey.u() };
  }
  if (!anonymous) throw new RingError("RING_NOT_ANONYMOUS", { details: { operation: "deposit" } });
  const tagged = await anonymousRecipient(recipient, params.ringProgramId, context);
  // An anonymous ring spends only through the hidden Ed25519 proof.
  if (tagged.address.signingPublicKey.signatureType() !== "ed25519")
    throw new RingError("RING_ANONYMOUS_RECIPIENT_CURVE");
  return tagged;
}

async function anonymousRecipient(
  recipient: Exclude<RingDepositRecipient, { kind: "confidential" }>,
  ringProgramId: Address,
  context: RequestContext | undefined,
): Promise<TaggedRecipient> {
  if (recipient.kind === "anonymous") {
    const { tag, history } = await recipient.history.senderTag(recipient.keys, context);
    return { address: recipient.keys.address(), viewTag: tag, history };
  }
  if (recipient.to.ringProgramId !== ringProgramId)
    throw new RingError("RING_FOREIGN_RING", {
      details: { address: recipient.to.ringProgramId, ring: ringProgramId },
    });
  const { tag, history } = await recipient.history.depositTag(
    recipient.keys,
    {
      viewingPublicKey: recipient.to.recipient.viewingPublicKey,
      firstContact: recipient.firstContact,
    },
    context,
  );
  return { address: recipient.to.recipient, viewTag: tag.payment.tag, history };
}
