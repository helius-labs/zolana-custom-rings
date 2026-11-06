/** The ring derivations over a wallet's viewing key, Rust `zolana_ring_keys::RingKeys`. */
import type { Bytes16, Bytes32, RequestContext } from "@heliuslabs/spr";
import type { Address } from "@solana/kit";
import { addressBytes, bytesKey, equalBytes, isCanonicalField } from "@heliuslabs/spr/internal";
import {
  KeypairError,
  NullifierKey,
  ShieldedAddress,
  ViewingKey,
  X25519PublicKey,
  type ShieldedKeypair,
  type ViewTag,
} from "@heliuslabs/spr/keypair";
import {
  LocalShieldedKeys,
  TransactionError,
  type ShieldedKeys,
} from "@heliuslabs/spr/transaction";

import { extended } from "../operations/workflow/extended.js";
import { RingKeyError } from "../crypto/error.js";
import { listSaltOf } from "../crypto/keys/list-salt.js";
import {
  anonymousSlotTag,
  bundleTag,
  confidentialSlotTag,
  deliveredSlotSecret,
} from "../crypto/derivation/ring-stream.js";

/** The public context of one delivered ring output slot. */
export interface RingDeliveryRequest {
  readonly viewingPublicKey: X25519PublicKey;
  readonly txViewingPublicKey: X25519PublicKey;
  readonly salt: Bytes16;
  readonly outputIndex: number;
  readonly firstNullifier: Bytes32;
}

/** One own-key view tag of an anonymous ring under a wallet viewing key, Rust `ViewTagStream`. */
export type ViewTagStream = Readonly<{ kind: "sender"; txCount: bigint }>;

export interface ViewTagRequest {
  readonly viewingPublicKey: X25519PublicKey;
  readonly stream: ViewTagStream;
}

/** The derivation a published tag follows, `recipient` being an anonymous payment's slot tag. */
export type RingTagKind = "confidential" | "recipient" | "senderBundle";

/** `outputIndex` is `m` on a sender bundle. */
export interface RingTagProbe {
  readonly kind: RingTagKind;
  readonly outputIndex: number;
  readonly tag: Bytes32;
}

/** The published tags of one transaction under one viewing key. */
export interface RingTagFrame {
  readonly viewingPublicKey: X25519PublicKey;
  readonly txViewingPublicKey: X25519PublicKey;
  readonly salt: Bytes16;
  readonly firstNullifier: Bytes32;
  readonly probes: readonly RingTagProbe[];
}

/** One zero-key merge under one viewing key. */
export interface MergeSeedRequest {
  readonly viewingPublicKey: X25519PublicKey;
  readonly ringProgramId: Address;
  readonly firstNullifier: Bytes32;
}

/** The ring derivations of a wallet's viewing keys, no viewing secret leaves the holder. */
export interface RingKeys extends ShieldedKeys {
  /** One salt per ring, a rotation keeps it. */
  listSalt(ringProgramId: Address, context?: RequestContext): Promise<Bytes32>;
  /** One seed per request, a keeper's merge under another seed does not open. */
  mergeSeeds(
    requests: readonly MergeSeedRequest[],
    context?: RequestContext,
  ): Promise<readonly Bytes32[]>;
  /** One CRDS slot secret per request, one agreement per transaction and key. */
  ringDeliverySecrets(
    requests: readonly RingDeliveryRequest[],
    context?: RequestContext,
  ): Promise<readonly Bytes32[]>;
  /** Per frame one answer per probe, the slot secret when its tag matches, one agreement per run of one key and transaction. */
  ringTagMatches(
    frames: readonly RingTagFrame[],
    context?: RequestContext,
  ): Promise<readonly (readonly (Bytes32 | undefined)[])[]>;
  /** One tag per request. */
  viewTags(
    requests: readonly ViewTagRequest[],
    context?: RequestContext,
  ): Promise<readonly ViewTag[]>;
}

/** Every ring derivation, a partial holder is no ring holder. */
export function isRingKeys(keys: ShieldedKeys): keys is RingKeys {
  const candidate: Partial<Record<keyof RingKeys, unknown>> = keys;
  return (
    typeof candidate.listSalt === "function" &&
    typeof candidate.mergeSeeds === "function" &&
    typeof candidate.ringDeliverySecrets === "function" &&
    typeof candidate.ringTagMatches === "function" &&
    typeof candidate.viewTags === "function"
  );
}

/** The proving keys of a wallet beside the ring derivations of the same address. */
export function ringWalletKeys<K extends ShieldedKeys>(keys: K, ring: RingKeys): K & RingKeys {
  if (!equalBytes(keys.address().toBytes(), ring.address().toBytes()))
    throw new TransactionError("TRANSACTION_KEYS_IDENTITY_MISMATCH");
  return extended(keys, {
    listSalt: ring.listSalt.bind(ring),
    mergeSeeds: ring.mergeSeeds.bind(ring),
    ringDeliverySecrets: ring.ringDeliverySecrets.bind(ring),
    ringTagMatches: ring.ringTagMatches.bind(ring),
    viewTags: ring.viewTags.bind(ring),
  });
}

export class LocalRingKeys implements RingKeys {
  readonly #keys: LocalShieldedKeys;
  readonly #tags: ViewingKeyHolder;
  /** The identity key, `list_tag` is final so a rotation keeps the salt. */
  readonly #listRoot: ViewingKey;
  readonly #nullifier: NullifierKey;
  #destroyed = false;

  private constructor(
    keys: LocalShieldedKeys,
    viewing: readonly ViewingKey[],
    listRoot: ViewingKey,
    nullifier: NullifierKey,
  ) {
    this.#keys = keys;
    this.#tags = new ViewingKeyHolder(viewing);
    this.#listRoot = listRoot;
    this.#nullifier = nullifier;
  }

  /** Copies the keypair's roles, the keypair stays the caller's. */
  static fromKeypair(keypair: ShieldedKeypair): LocalRingKeys {
    return new LocalRingKeys(
      LocalShieldedKeys.fromKeypair(keypair),
      [keypair.viewingKey()],
      keypair.viewingKey(),
      keypair.nullifierKey(),
    );
  }

  /** `viewingKeys` lists the current key first, the caller's objects stay the caller's. */
  static fromKeys(
    input: Readonly<{
      address: ShieldedAddress;
      viewingKeys: readonly ViewingKey[];
      /** The wallet's identity viewing key. */
      listRoot: ViewingKey;
      nullifierKey: NullifierKey;
    }>,
  ): LocalRingKeys {
    return new LocalRingKeys(
      LocalShieldedKeys.fromKeys(input),
      input.viewingKeys.map((key) => key.clone()),
      input.listRoot.clone(),
      input.nullifierKey.clone(),
    );
  }

  /** `next` becomes current and every earlier key stays held, the receiver and `next` stay the caller's. */
  rotate(next: ViewingKey): LocalRingKeys {
    this.#checkUsable();
    const address = this.address();
    return LocalRingKeys.fromKeys({
      address: ShieldedAddress.fromPublicKeys(
        address.signingPublicKey,
        address.nullifierPublicKey,
        next.publicKey(),
      ),
      viewingKeys: [next, ...this.viewingPublicKeys().map((key) => this.#tags.held(key))],
      listRoot: this.#listRoot,
      nullifierKey: this.#nullifier,
    });
  }

  address(): ShieldedAddress {
    return this.#keys.address();
  }

  viewingPublicKeys(): readonly X25519PublicKey[] {
    return this.#keys.viewingPublicKeys();
  }

  async decrypt(
    requests: Parameters<ShieldedKeys["decrypt"]>[0],
  ): ReturnType<ShieldedKeys["decrypt"]> {
    this.#checkUsable();
    return this.#keys.decrypt(requests);
  }

  async derive(
    requests: Parameters<ShieldedKeys["derive"]>[0],
  ): ReturnType<ShieldedKeys["derive"]> {
    this.#checkUsable();
    return this.#keys.derive(requests);
  }

  async transactionKeys(
    requests: Parameters<ShieldedKeys["transactionKeys"]>[0],
  ): ReturnType<ShieldedKeys["transactionKeys"]> {
    this.#checkUsable();
    return this.#keys.transactionKeys(requests);
  }

  async ringDeliverySecrets(requests: readonly RingDeliveryRequest[]): Promise<readonly Bytes32[]> {
    this.#checkUsable();
    return this.#tags.deliverySecrets(requests);
  }

  async listSalt(ringProgramId: Address): Promise<Bytes32> {
    this.#checkUsable();
    return listSaltOf(this.#listRoot, ringProgramId);
  }

  async mergeSeeds(requests: readonly MergeSeedRequest[]): Promise<readonly Bytes32[]> {
    this.#checkUsable();
    return requests.map((request) => {
      // A real nullifier is canonical, the list salt's label is not.
      if (!isCanonicalField(request.firstNullifier))
        throw new RingKeyError("KEYPAIR_INVALID_MERGE_SEED");
      return this.#tags
        .held(request.viewingPublicKey)
        .mergeSeed(
          addressBytes(request.ringProgramId, "ring program id") as Bytes32,
          request.firstNullifier,
        );
    });
  }

  async ringTagMatches(
    frames: readonly RingTagFrame[],
  ): Promise<readonly (readonly (Bytes32 | undefined)[])[]> {
    this.#checkUsable();
    return this.#tags.ringTagMatches(frames);
  }

  async viewTags(requests: readonly ViewTagRequest[]): Promise<readonly ViewTag[]> {
    this.#checkUsable();
    return requests.map((request) => {
      const key = this.#tags.held(request.viewingPublicKey);
      return key.senderViewTag(request.stream.txCount);
    });
  }

  /** The CRDS secret under the recipient key, the agreement never leaves the holder. */
  ringDeliverySecret(request: RingDeliveryRequest): Bytes32 {
    this.#checkUsable();
    return exactlySecret(this.#tags.deliverySecrets([request]));
  }

  /** Zeroes each held key buffer, a copy the JS engine made stays out of its reach. */
  destroy(): void {
    this.#destroyed = true;
    this.#keys.destroy();
    this.#tags.destroy();
    this.#listRoot.destroy();
    this.#nullifier.destroy();
  }

  // An empty request touches no key, the flag refuses it all the same.
  #checkUsable(): void {
    if (this.#destroyed)
      throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY", { reason: "destroyed" });
  }
}

/** The viewing keys alone, the holder a scan worker runs without any spending key. */
export class ViewingKeyHolder {
  /** Current first, retired after, each beside its public key. */
  readonly #viewing: readonly Readonly<{ key: ViewingKey; publicKey: X25519PublicKey }>[];

  /** The holder owns `viewing` and destroys it. */
  constructor(viewing: readonly ViewingKey[]) {
    this.#viewing = viewing.map((key) => ({ key, publicKey: key.publicKey() }));
  }

  viewingPublicKeys(): readonly X25519PublicKey[] {
    return this.#viewing.map(({ publicKey }) => publicKey);
  }

  deliverySecrets(requests: readonly RingDeliveryRequest[]): readonly Bytes32[] {
    const agreements = new AgreementBatch(this);
    const secrets: Bytes32[] = [];
    try {
      for (const request of requests)
        secrets.push(
          agreements.slotSecret(
            {
              viewingPublicKey: request.viewingPublicKey,
              txViewingPublicKey: request.txViewingPublicKey,
              salt: request.salt,
              firstNullifier: request.firstNullifier,
            },
            request.outputIndex,
          ),
        );
    } catch (cause) {
      for (const secret of secrets) secret.fill(0);
      throw cause;
    } finally {
      agreements.destroy();
    }
    return secrets;
  }

  async ringTagMatches(
    frames: readonly RingTagFrame[],
  ): Promise<readonly (readonly (Bytes32 | undefined)[])[]> {
    const agreements = new AgreementBatch(this);
    try {
      return frames.map((frame) =>
        frame.probes.map((probe) => {
          const secret = agreements.slotSecret(frame, probe.outputIndex);
          if (equalBytes(publishedTag(probe.kind, frame.viewingPublicKey, secret), probe.tag))
            return secret;
          secret.fill(0);
          return undefined;
        }),
      );
    } finally {
      agreements.destroy();
    }
  }

  held(publicKey: X25519PublicKey): ViewingKey {
    if (!(publicKey instanceof X25519PublicKey)) {
      throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "viewingPublicKey" });
    }
    const held = this.#viewing.find((candidate) => candidate.publicKey.equals(publicKey));
    if (held === undefined) throw new RingKeyError("KEYPAIR_UNKNOWN_VIEWING_KEY");
    return held.key;
  }

  destroy(): void {
    for (const { key } of this.#viewing) key.destroy();
  }
}

type SlotContext = Pick<
  RingTagFrame,
  "viewingPublicKey" | "txViewingPublicKey" | "salt" | "firstNullifier"
>;

/** One request's agreements, each `(transaction, key)` pair computed once and wiped together. */
class AgreementBatch {
  readonly #holder: ViewingKeyHolder;
  readonly #agreements = new Map<string, Bytes32>();

  constructor(holder: ViewingKeyHolder) {
    this.#holder = holder;
  }

  slotSecret(context: SlotContext, outputIndex: number): Bytes32 {
    return deliveredSlotSecret({
      agreement: this.#agreement(context),
      txViewingKey: context.txViewingPublicKey,
      recipientViewingKey: context.viewingPublicKey,
      salt: context.salt,
      outputIndex,
      firstNullifier: context.firstNullifier,
    });
  }

  destroy(): void {
    for (const agreement of this.#agreements.values()) agreement.fill(0);
    this.#agreements.clear();
  }

  #agreement({ viewingPublicKey, txViewingPublicKey }: SlotContext): Bytes32 {
    if (!(txViewingPublicKey instanceof X25519PublicKey)) {
      throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "txViewingPublicKey" });
    }
    const key = `${bytesKey(viewingPublicKey.toBytes())}:${bytesKey(txViewingPublicKey.toBytes())}`;
    const held = this.#agreements.get(key);
    if (held !== undefined) return held;
    const agreement = this.#holder.held(viewingPublicKey).ecdh(txViewingPublicKey);
    this.#agreements.set(key, agreement);
    return agreement;
  }
}

function publishedTag(
  kind: RingTagKind,
  viewingPublicKey: X25519PublicKey,
  secret: Bytes32,
): Bytes32 {
  switch (kind) {
    case "confidential":
      return confidentialSlotTag(viewingPublicKey.u());
    case "recipient":
      return anonymousSlotTag(secret);
    case "senderBundle":
      return bundleTag(secret);
  }
}

function exactlySecret(secrets: readonly Bytes32[]): Bytes32 {
  const [secret] = secrets;
  if (secret === undefined) throw new RingKeyError("KEYPAIR_UNKNOWN_VIEWING_KEY");
  return secret;
}
