import type { Instruction } from "@solana/kit";

import { type RingProver, type RingRecordReader } from "../../rpc/ports.js";
import { encodeRingDepositPlaintext } from "../../protocol/codec/ring-deposit-plaintext.js";
import {
  compileUnsignedTransaction,
  resolveDepositSettlement,
  signerAddress,
  ZERO_32,
  resolveShieldedRecipient,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import type { SignerAccount } from "@heliuslabs/zolana/internal";
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
import { SOL_MINT, Data, Utxo, ownerUtxoHash } from "@heliuslabs/zolana/transaction";
import type { DepositClient } from "@heliuslabs/zolana/wallet";
import type { DepositProofRequest } from "../../rpc/prover/ring.js";
import { depositBlinding } from "../../crypto/derivation/ring-domain.js";

import { checkSignersHideOwner } from "./anonymous.js";
import type { RingProgramConfig } from "../../protocol/codec/ring-codecs.js";
import { fetchRingProgramConfig } from "../../protocol/membership/config.js";
import { DEPOSIT_DEMAND, checkRingCoSigner } from "../../proof/cosign.js";
import { type RingDepositCapsule } from "../../protocol/codec/deposit-capsule.js";
import {
  ringDepositContextHash,
  ringDepositPublicInputHash,
  sealRingDepositOpenings,
} from "../../proof/deposit-audit.js";
import {
  ringDepositInstruction,
  ringDepositSpp,
} from "../../protocol/transaction/deposit-instruction.js";
import { RingError, wrapRingError } from "../../protocol/error.js";
import type { BoundRoot } from "../../proof/policy-proof.js";
import { readRegisteredRecord } from "../../rpc/registered-record.js";
import { type RingKeys } from "../../state/ring-keys.js";
import type { RingAddress } from "../../crypto/keys/ring-address.js";
import type { FirstContact, ViewingHistory } from "../../state/viewing-history.js";

/** Rust `compute_unit_limit(AuditedDeposit)`. */
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
  /** Signs when the config's scope covers deposits. */
  readonly cosigner?: SignerAccount;
}

/** A proven deposit with the registry root its proof binds. */
export interface ProvenRingDeposit {
  readonly instruction: Instruction;
  /** The own root an escrowing ring's proof binds by revision. */
  readonly roots?: readonly BoundRoot[];
}

/** A deposit whose note and auditor ciphertext every proof reuses, Rust `PreparedRingDeposit`. */
export class PreparedRingDeposit {
  /** The note the deposit creates. */
  readonly utxo: Utxo;
  /** The depositor's viewing history past the deposit's tag, stored before it is sent. */
  readonly viewingHistory?: ViewingHistory;
  readonly #ringProgramId: Address;
  readonly #tree: Address;
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
  readonly #blindingSecret: Bytes32;
  readonly #ephemeralSecret: Bytes32;

  private constructor(state: {
    utxo: Utxo;
    viewingHistory: ViewingHistory | undefined;
    ringProgramId: Address;
    tree: Address;
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
    blindingSecret: Bytes32;
    ephemeralSecret: Bytes32;
  }) {
    this.utxo = state.utxo;
    if (state.viewingHistory !== undefined) this.viewingHistory = state.viewingHistory;
    this.#ringProgramId = state.ringProgramId;
    this.#tree = state.tree;
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
    this.#blindingSecret = state.blindingSecret;
    this.#ephemeralSecret = state.ephemeralSecret;
  }

  /** Fixes the note against the ring's mode, co-signer and auditor. */
  static async prepare(
    params: RingDepositParams,
    context?: RequestContext,
  ): Promise<PreparedRingDeposit> {
    try {
      await initializePoseidon();
      const config = await fetchRingProgramConfig(params.client, params.ringProgramId, context);
      const anonymous = config.mode === "anonymous";
      const depositor = params.depositor ?? params.feePayer;
      const recipient = await depositRecipient(params, anonymous, context);
      const ownerKey = anonymous ? recipient.address.signingPublicKey.ed25519() : undefined;
      if (ownerKey !== undefined)
        checkSignersHideOwner(
          ownerKey,
          [params.feePayer, depositor, params.cosigner].map((party) =>
            party === undefined ? undefined : signerAddress(party),
          ),
        );
      const cosigner = checkRingCoSigner({
        ringProgramId: params.ringProgramId,
        configured: config.coSigner,
        supplied: params.cosigner,
        demand: DEPOSIT_DEMAND,
        approvalRequired: false,
      });
      const asset = params.asset ?? SOL_MINT;
      const settlement = await resolveDepositSettlement(
        {
          asset,
          depositor: signerAddress(depositor),
          ...(params.splTokenAccount === undefined
            ? {}
            : { splTokenAccount: params.splTokenAccount }),
          ...(params.splTokenProgram === undefined
            ? {}
            : { splTokenProgram: params.splTokenProgram }),
        },
        () => new RingError("RING_BUILD_DEPOSIT", { details: { reason: "missing token account" } }),
      );
      return PreparedRingDeposit.#seal({
        params,
        config,
        depositor,
        cosigner,
        recipient,
        ownerKey,
        asset,
        settlement,
        tree: params.tree ?? params.client.tree,
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    }
  }

  /** A root below a raised floor is proved again over the same note under a fresh root. */
  async prove(client: RingDepositClient, context?: RequestContext): Promise<ProvenRingDeposit> {
    try {
      const escrow = this.#keyEscrow
        ? await readRegisteredRecord(
            {
              client,
              ringProgramId: this.#ringProgramId,
              member: this.#ownerPkHash,
              escrowed: this.#nullifierPk,
            },
            context,
          )
        : undefined;
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
          auditorPublicKey: this.#auditor,
          ...(escrow === undefined ? {} : { memberRegistryRoot: escrow.root.root }),
        }),
        contextHash: this.#contextHash,
        count: 1,
        anonymous,
        ownerPkHashes: first(this.#ownerPkHash, ZERO_32),
        ...(this.#ownerKey === undefined ? {} : { ownerKeys: first(this.#ownerKey, ZERO_32) }),
        nullifierPks: first(this.#nullifierPk, ZERO_32),
        blindingSecrets: first(this.#blindingSecret, ZERO_32),
        ctHashes: first(escrow?.ctHash ?? ZERO_32, ZERO_32),
        members: first(escrow?.record, undefined),
        ephSk: this.#ephemeralSecret,
        auditorPk: this.#auditor.u(),
        keyEscrow: escrow !== undefined,
        memberRegistryRoot: escrow?.root.root ?? ZERO_32,
      };
      const proof = await client.proveRing(request, context);
      return Object.freeze({
        instruction: await ringDepositInstruction({
          ringProgramId: this.#ringProgramId,
          tree: this.#tree,
          depositor: this.#depositor,
          deposits: [this.#deposit],
          proof,
          ...(escrow === undefined ? {} : { ownRevision: escrow.root.revision }),
          ...(this.#cosigner === undefined ? {} : { cosigner: this.#cosigner }),
        }),
        ...(escrow === undefined ? {} : { roots: Object.freeze([escrow.root]) }),
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

  /** The note, its recipient ciphertext and the auditor capsule, sealed under fresh secrets. */
  static async #seal(
    input: Readonly<{
      params: RingDepositParams;
      config: RingProgramConfig;
      depositor: SignerAccount;
      cosigner: SignerAccount | undefined;
      recipient: TaggedRecipient;
      ownerKey: Bytes32 | undefined;
      asset: Address;
      settlement: RingAssetDeposit["asset"];
      tree: Address;
    }>,
  ): Promise<PreparedRingDeposit> {
    const { params, recipient } = input;
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
            ...(input.ownerKey === undefined ? {} : { ownerKey: input.ownerKey }),
            recipientCiphertext: envelope.encryptRingDeposit(
              recipient.address.viewingPublicKey,
              plaintext,
              salt,
            ),
          },
        ],
        input.config.auditorPublicKey,
      );
      ephemeralSecret = sealed.ephemeralSecret;
      const [capsule] = sealed.capsules;
      const [payload] = sealed.payloads;
      if (capsule === undefined || payload === undefined) throw new RingError("RING_BUILD_DEPOSIT");
      const deposit: RingAssetDeposit = Object.freeze({
        asset: input.settlement,
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
        depositor: input.depositor,
        deposits: [deposit],
      });
      const prepared = new PreparedRingDeposit({
        utxo: new Utxo({
          owner: recipient.address.signingPublicKey,
          asset: input.asset,
          amount: params.amount,
          blinding,
          data: new Data(),
          ringProgramId: params.ringProgramId,
        }),
        viewingHistory: recipient.history,
        ringProgramId: params.ringProgramId,
        tree: input.tree,
        depositor: input.depositor,
        cosigner: input.cosigner,
        deposit,
        capsule,
        contextHash: ringDepositContextHash(params.ringProgramId, input.tree, spp.data),
        ownerPkHash: recipient.address.signingPublicKey.ownerProofInputHash(),
        nullifierPk: recipient.address.nullifierPublicKey,
        ownerKey: input.ownerKey,
        auditor: input.config.auditorPublicKey,
        keyEscrow: input.config.keyEscrow,
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

/** The recipient's address and the tag its scan reads, refused when the ring mode disagrees. */
async function depositRecipient(
  params: RingDepositParams,
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
