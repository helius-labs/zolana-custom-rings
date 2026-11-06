/** The Ring RPC relay a wallet sends its transfer through, Rust `relay`. */
import type { WalletUtxo } from "@heliuslabs/spr/transaction";
import {
  type Address,
  type Signature,
  getBase58Decoder,
  getBase64Encoder,
  type TransactionPartialSigner,
} from "@solana/kit";

import type { RequestContext } from "@heliuslabs/spr/interface";
import { concatBytes, indexerScalars, sha256 } from "@heliuslabs/spr/internal";
import type { indexerTypes } from "@heliuslabs/spr/internal";

import { RingError } from "../protocol/error.js";
import type { ApprovalOpening } from "../protocol/membership/approval-totals.js";
import {
  encodePrepareAuthorityTransferRequest,
  encodePrepareRelayRequest,
} from "../protocol/ring-rpc/ring-rpc-codec.js";
import type { OwnerDebit } from "../protocol/membership/owner-debits.js";
import type {
  PrepareAuthorityTransferRequest,
  PrepareRelayRequest,
  RelayIntent,
  RelayStatus,
  RelayStep,
} from "../protocol/ring-rpc/ring-rpc-types.js";
import {
  checkRelayMessage,
  expectedPublicOwner,
  type RelayFunderTerms,
  type RelayTransferTerms,
  type DelegateRingConfig,
  type ExpectedRelayMessage,
  type ExpectedSealed,
  expectedDelegate,
  mismatch,
  type RequestedAuthorityTransfer,
  type VerifiedRelayMessage,
} from "./relay-message.js";
import type { RingRpc } from "./ring-rpc.js";

type Hash = indexerTypes.Hash;

const RELAY_DOMAIN = new TextEncoder().encode("zolana/ring-rpc-relay");
const base58 = getBase58Decoder();
const base64 = getBase64Encoder();

/** Rust `RingRelay`. */
export type RingRelayClient = Pick<
  RingRpc,
  "getRelayQuote" | "prepareRelay" | "submitRelay" | "getRelayStatus"
>;

/** Rust `RingRelay`, the calls an authority transfer makes. */
export type RingAuthorityRelayClient = Pick<RingRpc, "prepareAuthorityTransfer" | "submitRelay">;

/** Rust `PrepareRelayRequest::relay_id`, a retried request names the same relay. */
export function relayId(request: PrepareRelayRequest): Hash {
  return wireRelayId(encodePrepareRelayRequest(request));
}

function wireRelayId(wire: Readonly<Record<string, unknown>>): Hash {
  const bytes = new TextEncoder().encode(JSON.stringify(wire));
  return indexerScalars.checkedHash(
    base58.decode(sha256(concatBytes(RELAY_DOMAIN, bytes))),
    "relayId",
  );
}

/** Rust `UnsignedRelay`, the owner's signature waits on `sign`, the charges read first. */
export class UnsignedRelay {
  readonly #signer: RelayOwnerSigner;
  readonly #messageHash: Uint8Array;
  readonly #request: Omit<PrepareRelayRequest, "intent"> &
    Readonly<{ intent: Omit<OwnerRelayIntent, "ownerSignature"> }>;
  readonly #expected: ExpectedSealed;

  /** @internal */
  constructor(
    input: Readonly<{
      signer: RelayOwnerSigner;
      messageHash: Uint8Array;
      request: Omit<PrepareRelayRequest, "intent"> &
        Readonly<{ intent: Omit<OwnerRelayIntent, "ownerSignature"> }>;
      expected: ExpectedSealed;
    }>,
  ) {
    this.#signer = input.signer;
    this.#messageHash = input.messageHash.slice();
    this.#request = input.request;
    this.#expected = input.expected;
    Object.freeze(this);
  }

  /** Per owner and asset, Rust `charged_outflows`. */
  chargedOutflows(): readonly OwnerDebit[] {
    return this.#expected.chargedOutflows;
  }

  async sign(context?: RequestContext): Promise<PreparedRelay> {
    const ownerSignature = base58.decode(
      await this.#signer.sign(this.#messageHash, context),
    ) as Signature;
    return new PreparedRelay(
      { ...this.#request, intent: { ...this.#request.intent, ownerSignature } },
      this.#expected,
    );
  }
}

/** Signs the transfer's `messageHash`, Rust `SigningKey`. */
export interface RelayOwnerSigner {
  sign(message: Uint8Array, context?: RequestContext): Promise<Uint8Array>;
}

type OwnerRelayIntent = Extract<RelayIntent, { operation: "anonymous" | "confidential" }>;

/** Rust `PreparedRelay`. */
export class PreparedRelay {
  readonly request: PrepareRelayRequest;
  /** `undefined` on the rails that sign inside the proof. */
  readonly #expected: ExpectedRelayMessage | undefined;
  #sent = false;

  /** @internal */
  constructor(request: PrepareRelayRequest, expected?: ExpectedRelayMessage) {
    this.request = request;
    this.#expected = expected;
    Object.freeze(this);
  }

  relayId(): Hash {
    return relayId(this.request);
  }

  /** Per owner and asset, read before `send` hands the owner's signature over. */
  chargedOutflows(): readonly OwnerDebit[] {
    return chargedOutflowsOf(this.#expected);
  }

  /** Repeatable after a lost answer, Ring RPC keys every stored relay by its id. */
  async send(relay: RingRelayClient, context?: RequestContext): Promise<RelaySent> {
    const relayId = this.relayId();
    // 1. A retry reconciles by the relay id first, a relay Ring RPC sent never prepares again.
    if (this.#sent) {
      const status = await relayStatus(relay, relayId, context);
      if (status?.status === "sent" || status?.status === "confirmed")
        return Object.freeze({ step: "submitted", relayId });
      if (status?.status === "failed")
        throw new RingError("RING_RELAY_FAILED", { details: { reason: status.reason } });
      // 2. Ring RPC answers a stored relay from its store, an unknown one proves once.
    }
    this.#sent = true;
    const step = await relay.prepareRelay(this.request, context);
    return accepted({ step, relayId, expected: this.#expected });
  }
}

/** `undefined` when Ring RPC cannot answer, the relay then prepares once more. */
async function relayStatus(
  relay: RingRelayClient,
  relayId: Hash,
  context: RequestContext | undefined,
): Promise<RelayStatus | undefined> {
  try {
    return await relay.getRelayStatus(relayId, context);
  } catch {
    return undefined;
  }
}

function chargedOutflowsOf(expected: ExpectedRelayMessage | undefined): readonly OwnerDebit[] {
  return expected?.kind === "sealed" ? expected.chargedOutflows : [];
}

/** Rust `PreparedAuthorityTransfer`, the delegate signs only a message the quoted fee payer pays. */
export class PreparedAuthorityTransfer {
  readonly request: PrepareAuthorityTransferRequest;
  readonly #requested: RequestedAuthorityTransfer;

  /** Rust `RequestedAuthorityTransfer::prepare`, refuses an allowed set built for other sources. */
  constructor(requested: RequestedAuthorityTransfer) {
    requested.allowed.checkSources(requested.request.transfer.sources);
    this.request = requested.request;
    this.#requested = requested;
    Object.freeze(this);
  }

  /** Rust `PrepareAuthorityTransferRequest::relay_id`. */
  relayId(): Hash {
    return wireRelayId(encodePrepareAuthorityTransferRequest(this.request));
  }

  async send(relay: RingAuthorityRelayClient, context?: RequestContext): Promise<RelaySent> {
    const expected = await expectedDelegate(this.#requested);
    const step = await relay.prepareAuthorityTransfer(this.request, context);
    return accepted({ step, relayId: this.relayId(), expected });
  }
}

function accepted({
  step,
  relayId,
  expected,
}: Readonly<{
  step: RelayStep;
  relayId: Hash;
  expected: ExpectedRelayMessage | undefined;
}>): RelaySent {
  if (step.relayId !== relayId) throw new RingError("RING_RELAY_ID_MISMATCH");
  if (step.step === "submitted") return Object.freeze({ step: "submitted", relayId });
  return new PendingRelaySignature(relayId, base64.encode(step.message) as Uint8Array, expected);
}

/** Rust `RelaySent`, a `signMessage` step waits for its signer. */
export type RelaySent = Readonly<{ step: "submitted"; relayId: Hash }> | PendingRelaySignature;

/** Rust `RelaySent::submitted`, a public signature would name the hidden owner. */
export function submittedRelay(sent: RelaySent): Hash {
  if (sent instanceof PendingRelaySignature) throw new RingError("RING_RELAY_OWNER_SIGNATURE");
  return sent.relayId;
}

/** Rust `PendingSignature`. */
export class PendingRelaySignature {
  readonly step = "signMessage";
  readonly relayId: Hash;
  readonly #message: Uint8Array;
  readonly #expected: ExpectedRelayMessage | undefined;

  /** @internal */
  constructor(relayId: Hash, message: Uint8Array, expected?: ExpectedRelayMessage) {
    this.relayId = relayId;
    this.#message = message.slice();
    this.#expected = expected;
    Object.freeze(this);
  }

  /** What the wallet sealed for one public owner, an outside co-signer holds none. */
  transferTerms(signer: Address): RelayTransferTerms | undefined {
    if (this.#expected?.kind === "sealed")
      return this.#expected.terms.find((terms) => terms.signer === signer);
    return this.#expected?.kind === "publicOwner" && this.#expected.terms.signer === signer
      ? this.#expected.terms
      : undefined;
  }

  /** What the wallet sealed for one public funder of a deposit leg. */
  funderTerms(signer: Address): RelayFunderTerms | undefined {
    if (this.#expected?.kind === "sealed")
      return this.#expected.funders?.find((terms) => terms.signer === signer);
    return this.#expected?.kind === "funder" && this.#expected.terms.signer === signer
      ? this.#expected.terms
      : undefined;
  }

  /** Per owner and asset, read before a public owner signs. */
  chargedOutflows(): readonly OwnerDebit[] {
    return chargedOutflowsOf(this.#expected);
  }

  /** What opens the sealed frame's digest, for the wallet to hand to its co-signer, Rust `approval_opening`. */
  approvalOpening(): ApprovalOpening | undefined {
    return this.#expected?.kind === "sealed" ? this.#expected.approval : undefined;
  }

  /** Rust `PendingSignature::verify`, the expectation comes from the wallet's own request. */
  verify(signer: Address): VerifiedRelayMessage {
    if (this.#expected === undefined) throw mismatch("Unrequested");
    return checkRelayMessage(this.#expected, this.#message, signer);
  }

  async sign(
    relay: RingRelayClient,
    signer: TransactionPartialSigner,
    context?: RequestContext,
  ): Promise<RelayStatus> {
    return this.#submit(relay, this.verify(signer.address), signer, context);
  }

  async #submit(
    relay: RingRelayClient,
    verified: VerifiedRelayMessage,
    signer: TransactionPartialSigner,
    context: RequestContext | undefined,
  ): Promise<RelayStatus> {
    const signature = await verified.sign(signer, context);
    return relay.submitRelay(
      { relayId: this.relayId, signer: verified.signer, signature },
      context,
    );
  }
}

/** The notes are required, the owner's signature is the only gate on them. */
export class OwnerApproval {
  readonly #input: OwnerApprovalInput;

  constructor(input: OwnerApprovalInput) {
    this.#input = input;
    Object.freeze(this);
  }

  async pending(): Promise<PendingRelaySignature> {
    const { relayId, message, terms, config, knownNotes } = this.#input;
    return new PendingRelaySignature(
      relayId,
      message,
      await expectedPublicOwner({ terms, config, knownNotes }),
    );
  }
}

export interface OwnerApprovalInput {
  readonly relayId: Hash;
  readonly message: Uint8Array;
  readonly terms: RelayTransferTerms;
  readonly config: DelegateRingConfig;
  /** Every note the wallet holds, the nullifiers are the wallet's own derivation. */
  readonly knownNotes: readonly Pick<WalletUtxo, "nullifier">[];
}
