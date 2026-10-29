/** The Ring RPC relay a wallet sends its transfer through, Rust `relay`. */
import {
  type Address,
  getBase58Decoder,
  getBase64Encoder,
  getCompiledTransactionMessageDecoder,
  getCompiledTransactionMessageEncoder,
  type TransactionMessageBytes,
  type TransactionPartialSigner,
} from "@solana/kit";

import type { RequestContext, Signature } from "@heliuslabs/zolana/interface";
import { concatBytes, equalBytes, indexerScalars, sha256 } from "@heliuslabs/zolana/internal";
import type { indexerTypes } from "@heliuslabs/zolana/internal";

import { RingError } from "../protocol/error.js";
import { encodePrepareRelayRequest } from "../protocol/ring-rpc/ring-rpc-codec.js";
import type { PrepareRelayRequest, RelayStatus } from "../protocol/ring-rpc/ring-rpc-types.js";
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

/** Rust `PrepareRelayRequest::relay_id`, a retried request names the same relay. */
export function relayId(request: PrepareRelayRequest): Hash {
  const wire = new TextEncoder().encode(JSON.stringify(encodePrepareRelayRequest(request)));
  return indexerScalars.checkedHash(
    base58.decode(sha256(concatBytes(RELAY_DOMAIN, wire))),
    "relayId",
  );
}

/** Rust `PreparedRelay`. */
export class PreparedRelay {
  readonly request: PrepareRelayRequest;

  /** @internal */
  constructor(request: PrepareRelayRequest) {
    this.request = request;
    Object.freeze(this);
  }

  relayId(): Hash {
    return relayId(this.request);
  }

  async send(relay: RingRelayClient, context?: RequestContext): Promise<RelaySent> {
    const expected = this.relayId();
    const step = await relay.prepareRelay(this.request, context);
    if (step.relayId !== expected) throw new RingError("RING_RELAY_ID_MISMATCH");
    if (step.step === "submitted") return Object.freeze({ step: "submitted", relayId: expected });
    return new PendingRelaySignature(expected, base64.encode(step.message) as Uint8Array);
  }
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

  /** @internal */
  constructor(relayId: Hash, message: Uint8Array) {
    this.relayId = relayId;
    this.#message = message;
    Object.freeze(this);
  }

  /** Signs only a v1 message that names `signer` among its signers. */
  async sign(
    relay: RingRelayClient,
    signer: TransactionPartialSigner,
    context?: RequestContext,
  ): Promise<RelayStatus> {
    const messageBytes = this.#message as unknown as TransactionMessageBytes;
    if (!namesSigner(this.#message, signer.address))
      throw new RingError("RING_RELAY_MESSAGE_INVALID");
    const transaction = { messageBytes, signatures: {} } as unknown as Parameters<
      TransactionPartialSigner["signTransactions"]
    >[0][number];
    const [signatures] = await signer.signTransactions(
      [transaction],
      context?.signal === undefined ? undefined : { abortSignal: context.signal },
    );
    const signature = signatures?.[signer.address];
    if (signature === undefined) throw new RingError("RING_RELAY_MESSAGE_INVALID");
    return relay.submitRelay(
      {
        relayId: this.relayId,
        signer: signer.address,
        signature: base58.decode(signature) as Signature,
      },
      context,
    );
  }
}

/** A canonical v1 message whose signer region holds `signer`. */
function namesSigner(bytes: Uint8Array, signer: Address): boolean {
  try {
    const message = getCompiledTransactionMessageDecoder().decode(bytes);
    const index = message.staticAccounts.indexOf(signer);
    return (
      message.version === 1 &&
      index >= 0 &&
      index < message.header.numSignerAccounts &&
      equalBytes(new Uint8Array(getCompiledTransactionMessageEncoder().encode(message)), bytes)
    );
  } catch {
    return false;
  }
}
