/** The Ring RPC relay a wallet sends its transfer through, Rust `relay`. */
import { getBase58Decoder, getBase64Encoder, type TransactionPartialSigner } from "@solana/kit";

import type { RequestContext } from "@heliuslabs/zolana/interface";
import { concatBytes, indexerScalars, sha256 } from "@heliuslabs/zolana/internal";
import type { indexerTypes } from "@heliuslabs/zolana/internal";

import { RingError } from "../protocol/error.js";
import {
  encodePrepareAuthorityTransferRequest,
  encodePrepareRelayRequest,
} from "../protocol/ring-rpc/ring-rpc-codec.js";
import type {
  PrepareAuthorityTransferRequest,
  PrepareRelayRequest,
  RelayQuote,
  RelayStatus,
  RelayStep,
} from "../protocol/ring-rpc/ring-rpc-types.js";
import {
  checkRelayMessage,
  type ExpectedRelayMessage,
  expectedDelegate,
  mismatch,
  type VerifiedRelayMessage,
} from "./relay-message.js";
import type { RingRpc } from "./ring-rpc.js";

type Hash = indexerTypes.Hash;

const RELAY_DOMAIN = new TextEncoder().encode("zolana/ring-rpc-relay/v1");
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

/** Rust `PreparedRelay`. */
export class PreparedRelay {
  readonly request: PrepareRelayRequest;
  /** `undefined` on the rails that sign inside the proof. */
  readonly #expected: ExpectedRelayMessage | undefined;

  /** @internal */
  constructor(request: PrepareRelayRequest, expected?: ExpectedRelayMessage) {
    this.request = request;
    this.#expected = expected;
    Object.freeze(this);
  }

  relayId(): Hash {
    return relayId(this.request);
  }

  async send(relay: RingRelayClient, context?: RequestContext): Promise<RelaySent> {
    const step = await relay.prepareRelay(this.request, context);
    return accepted({ step, relayId: this.relayId(), expected: this.#expected });
  }
}

/** Rust `PreparedAuthorityTransfer`, the delegate signs only a message the quoted fee payer pays. */
export class PreparedAuthorityTransfer {
  readonly request: PrepareAuthorityTransferRequest;
  readonly quote: RelayQuote;

  constructor(request: PrepareAuthorityTransferRequest, quote: RelayQuote) {
    this.request = request;
    this.quote = quote;
    Object.freeze(this);
  }

  /** Rust `PrepareAuthorityTransferRequest::relay_id`. */
  relayId(): Hash {
    return wireRelayId(encodePrepareAuthorityTransferRequest(this.request));
  }

  async send(relay: RingAuthorityRelayClient, context?: RequestContext): Promise<RelaySent> {
    const expected = await expectedDelegate(this.request, this.quote);
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
    this.#message = message;
    this.#expected = expected;
    Object.freeze(this);
  }

  /** Rust `PendingSignature::verify`, the expectation comes from the wallet's own request. */
  verify(): VerifiedRelayMessage {
    if (this.#expected === undefined) throw mismatch("Unrequested");
    return checkRelayMessage(this.#expected, this.#message);
  }

  async sign(
    relay: RingRelayClient,
    signer: TransactionPartialSigner,
    context?: RequestContext,
  ): Promise<RelayStatus> {
    const verified = this.verify();
    const signature = await verified.sign(signer, context);
    return relay.submitRelay(
      { relayId: this.relayId, signer: verified.signer, signature },
      context,
    );
  }
}
