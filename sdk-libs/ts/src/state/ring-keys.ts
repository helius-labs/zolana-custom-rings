/** The ring derivations over a wallet's viewing key, Rust `zolana_ring_keys::RingKeys`. */
import type { Bytes16, Bytes32, RequestContext } from "@heliuslabs/zolana";
import { equalBytes } from "@heliuslabs/zolana/internal";
import {
  NullifierKey,
  ViewingKey,
  X25519PublicKey,
  type SharedViewTags,
  type ShieldedAddress,
  type ShieldedKeypair,
  type ViewTag,
} from "@heliuslabs/zolana/keypair";
import {
  LocalShieldedKeys,
  TransactionError,
  type ShieldedKeys,
} from "@heliuslabs/zolana/transaction";

import { extended } from "../operations/workflow/extended.js";
import { RingKeyError } from "../crypto/error.js";
import { deliveredSlotSecret } from "../crypto/derivation/ring-stream.js";

/** The public context of one delivered ring output slot. */
export interface RingDeliveryRequest {
  readonly viewingPublicKey: X25519PublicKey;
  readonly txViewingPublicKey: X25519PublicKey;
  readonly salt: Bytes16;
  readonly outputIndex: number;
  readonly firstNullifier: Bytes32;
}

/** One own-key view tag of an anonymous ring under a wallet viewing key, Rust `ViewTagStream`. */
export type ViewTagStream =
  | Readonly<{ kind: "sender"; txCount: bigint }>
  | Readonly<{ kind: "request"; requestCount: bigint }>;

export interface ViewTagRequest {
  readonly viewingPublicKey: X25519PublicKey;
  readonly stream: ViewTagStream;
}

/** The counterparty one direction of shared view tags is agreed with, Rust `SharedTagPair`. */
export type SharedTagPair = Readonly<{
  /** `toRecipient` tags the wallet pays under, `fromSender` tags a sender pays the wallet under. */
  kind: "toRecipient" | "fromSender";
  counterparty: X25519PublicKey;
}>;

export interface SharedTagsRequest {
  readonly viewingPublicKey: X25519PublicKey;
  readonly pair: SharedTagPair;
}

/** The ring derivations of a wallet's viewing keys, no viewing secret leaves the holder. */
export interface RingKeys extends ShieldedKeys {
  /** One CRDS slot secret per request. */
  ringDeliverySecrets(
    requests: readonly RingDeliveryRequest[],
    context?: RequestContext,
  ): Promise<readonly Bytes32[]>;
  /** One tag per request. */
  viewTags(
    requests: readonly ViewTagRequest[],
    context?: RequestContext,
  ): Promise<readonly ViewTag[]>;
  /** One pair domain per request, the one ECDH its pair costs. */
  sharedViewTags(
    requests: readonly SharedTagsRequest[],
    context?: RequestContext,
  ): Promise<readonly SharedViewTags[]>;
}

/** Every ring derivation, a partial holder is no ring holder. */
export function isRingKeys(keys: ShieldedKeys): keys is RingKeys {
  const candidate: Partial<Record<keyof RingKeys, unknown>> = keys;
  return (
    typeof candidate.ringDeliverySecrets === "function" &&
    typeof candidate.viewTags === "function" &&
    typeof candidate.sharedViewTags === "function"
  );
}

/** The proving keys of a wallet beside the ring derivations of the same address. */
export function ringWalletKeys<K extends ShieldedKeys>(keys: K, ring: RingKeys): K & RingKeys {
  if (!equalBytes(keys.address().toBytes(), ring.address().toBytes()))
    throw new TransactionError("TRANSACTION_KEYS_IDENTITY_MISMATCH");
  return extended(keys, {
    ringDeliverySecrets: ring.ringDeliverySecrets.bind(ring),
    viewTags: ring.viewTags.bind(ring),
    sharedViewTags: ring.sharedViewTags.bind(ring),
  });
}

export class LocalRingKeys implements RingKeys {
  readonly #keys: LocalShieldedKeys;
  /** Current first, retired after, each beside its public key. */
  readonly #viewing: readonly Readonly<{ key: ViewingKey; publicKey: X25519PublicKey }>[];

  private constructor(keys: LocalShieldedKeys, viewing: readonly ViewingKey[]) {
    this.#keys = keys;
    this.#viewing = viewing.map((key) => ({ key, publicKey: key.publicKey() }));
  }

  /** Copies the keypair's roles, the keypair stays the caller's. */
  static fromKeypair(keypair: ShieldedKeypair): LocalRingKeys {
    return new LocalRingKeys(LocalShieldedKeys.fromKeypair(keypair), [keypair.viewingKey()]);
  }

  /** `viewingKeys` lists the current key first, the caller's objects stay the caller's. */
  static fromKeys(
    input: Readonly<{
      address: ShieldedAddress;
      viewingKeys: readonly ViewingKey[];
      nullifierKey: NullifierKey;
    }>,
  ): LocalRingKeys {
    return new LocalRingKeys(
      LocalShieldedKeys.fromKeys(input),
      input.viewingKeys.map((key) => key.clone()),
    );
  }

  address(): ShieldedAddress {
    return this.#keys.address();
  }

  viewingPublicKeys(): readonly X25519PublicKey[] {
    return this.#keys.viewingPublicKeys();
  }

  decrypt(requests: Parameters<ShieldedKeys["decrypt"]>[0]): ReturnType<ShieldedKeys["decrypt"]> {
    return this.#keys.decrypt(requests);
  }

  derive(requests: Parameters<ShieldedKeys["derive"]>[0]): ReturnType<ShieldedKeys["derive"]> {
    return this.#keys.derive(requests);
  }

  transactionKeys(
    requests: Parameters<ShieldedKeys["transactionKeys"]>[0],
  ): ReturnType<ShieldedKeys["transactionKeys"]> {
    return this.#keys.transactionKeys(requests);
  }

  async ringDeliverySecrets(requests: readonly RingDeliveryRequest[]): Promise<readonly Bytes32[]> {
    const secrets: Bytes32[] = [];
    try {
      for (const request of requests) secrets.push(this.ringDeliverySecret(request));
    } catch (cause) {
      for (const secret of secrets) secret.fill(0);
      throw cause;
    }
    return secrets;
  }

  async viewTags(requests: readonly ViewTagRequest[]): Promise<readonly ViewTag[]> {
    return requests.map((request) => {
      const key = this.#held(request.viewingPublicKey);
      return request.stream.kind === "sender"
        ? key.senderViewTag(request.stream.txCount)
        : key.recipientRequestViewTag(request.stream.requestCount);
    });
  }

  async sharedViewTags(requests: readonly SharedTagsRequest[]): Promise<readonly SharedViewTags[]> {
    const tags: SharedViewTags[] = [];
    try {
      for (const { viewingPublicKey, pair } of requests) {
        const key = this.#held(viewingPublicKey);
        tags.push(
          pair.kind === "toRecipient"
            ? key.sendSharedViewTags(pair.counterparty)
            : key.recipientSharedViewTags(pair.counterparty),
        );
      }
    } catch (cause) {
      for (const tag of tags) tag.destroy();
      throw cause;
    }
    return tags;
  }

  /** The CRDS secret under the recipient key, the agreement never leaves the holder. */
  ringDeliverySecret(request: RingDeliveryRequest): Bytes32 {
    if (!(request.txViewingPublicKey instanceof X25519PublicKey)) {
      throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "txViewingPublicKey" });
    }
    const recipient = this.#held(request.viewingPublicKey);
    let agreement: Bytes32 | undefined;
    try {
      agreement = recipient.ecdh(request.txViewingPublicKey);
      return deliveredSlotSecret({
        agreement,
        txViewingKey: request.txViewingPublicKey,
        recipientViewingKey: recipient.publicKey(),
        salt: request.salt,
        outputIndex: request.outputIndex,
        firstNullifier: request.firstNullifier,
      });
    } finally {
      agreement?.fill(0);
    }
  }

  destroy(): void {
    this.#keys.destroy();
    for (const { key } of this.#viewing) key.destroy();
  }

  #held(publicKey: X25519PublicKey): ViewingKey {
    if (!(publicKey instanceof X25519PublicKey)) {
      throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "viewingPublicKey" });
    }
    const held = this.#viewing.find((candidate) => candidate.publicKey.equals(publicKey));
    if (held === undefined) throw new RingKeyError("KEYPAIR_UNKNOWN_VIEWING_KEY");
    return held.key;
  }
}
