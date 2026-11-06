import { getBase64Encoder, type Address } from "@solana/kit";

import type { ChainReader, SprClient } from "@heliuslabs/spr/client";
import { equalBytes, runKitRpc, ZERO_NULLIFIER_PK } from "@heliuslabs/spr/internal";
import type { Bytes32, RequestContext } from "@heliuslabs/spr/interface";
import type { ShieldedAddress, X25519PublicKey } from "@heliuslabs/spr/keypair";

import { listTagOf } from "../crypto/keys/list-salt.js";
import type { RingAddress } from "../crypto/keys/ring-address.js";
import { x25519FromU } from "../crypto/keys/x25519.js";
import { RingError } from "../protocol/error.js";
import {
  decodeTrackingAuthorization,
  decodeTrackingRegistry,
  verifyTrackingOpening,
  type TrackingAuthorization,
  type TrackingRegistry,
} from "../protocol/membership/tracking.js";
import { STORAGE_PROGRAM_ID, trackingAuthorizationPda } from "../protocol/pda/index.js";
import type { BoundRoot } from "./registered-record.js";
import type { TrackingReader } from "./ports.js";

/** Reads a tracking authorization at `confirmed` whatever the client reads at, Rust `AsyncRpc::get_account`. */
export type AuthorizationReader = Pick<SprClient, "solanaRpc">;

export type RingRecipientClient = Pick<ChainReader, "getAccount"> &
  AuthorizationReader &
  Pick<TrackingReader, "getTrackingOpenings">;

export type TrackingRoot = BoundRoot;

export type ResolvedRecipient =
  /** The authorization's viewing key, an address from before a rotation resolves to the current one, Rust `RecipientResolver`. */
  | Readonly<{
      kind: "enrolled";
      root: TrackingRoot;
      nullifierPk: Bytes32;
      viewingPublicKey: X25519PublicKey;
      listTag: Bytes32;
    }>
  /** Zero key resolution defers enrollment checks to payment validation. */
  | Readonly<{
      kind: "zeroKey";
      root: TrackingRoot;
      viewingPublicKey: X25519PublicKey;
    }>;

/**
 * Zero key resolution defers enrollment checks to payment validation.
 *
 * Reads the authorization at `confirmed`. A rotation that lands after the read leaves the payment
 * sealed to the key read, no program check reads a viewing key.
 */
export async function resolveRingRecipient(
  input: Readonly<{
    client: RingRecipientClient;
    trackingRegistry: Address;
    to: RingAddress;
  }>,
  context?: RequestContext,
): Promise<ResolvedRecipient> {
  const { client, trackingRegistry, to } = input;
  const root = await newestTrackingRoot(
    { client, trackingRegistry, ring: to.ringProgramId },
    context,
  );
  const member = to.recipient.signingPublicKey.ownerProofInputHash();
  const { openings } = await client.getTrackingOpenings(
    { registry: trackingRegistry, members: [member], expectedRoot: root.root },
    context,
  );
  const [opening] = openings;
  if (opening === undefined || openings.length !== 1)
    throw new RingError("RING_TRACKING_INVALID", {
      details: { reason: "openings", count: openings.length },
    });
  const row = verifyTrackingOpening(opening, root.root, member);
  const named = to.recipient.nullifierPublicKey;
  if (equalBytes(named, ZERO_NULLIFIER_PK)) {
    const viewingPublicKey =
      row === undefined
        ? to.recipient.viewingPublicKey
        : x25519FromU(
            await enrolledViewingKey({ client, trackingRegistry, owner: to.recipient }, context),
          );
    return Object.freeze({ kind: "zeroKey", root, viewingPublicKey });
  }
  if (row === undefined) throw new RingError("RING_RECIPIENT_NOT_ENROLLED");
  if (!equalBytes(row.nullifierPk, named))
    throw new RingError("RING_ADDRESS_MISMATCH", {
      details: { field: "nullifierPk" },
    });
  if (!equalBytes(row.listTag, listTagOf(to.listSalt)))
    throw new RingError("RING_ADDRESS_MISMATCH", {
      details: { field: "listSalt" },
    });
  const viewingU = await enrolledViewingKey(
    { client, trackingRegistry, owner: to.recipient },
    context,
  );
  return Object.freeze({
    kind: "enrolled",
    root,
    nullifierPk: row.nullifierPk,
    viewingPublicKey: x25519FromU(viewingU),
    listTag: row.listTag,
  });
}

/** The viewing key an enrolled owner's authorization holds, its row present under the read root. */
export async function enrolledViewingKey(
  input: Readonly<{
    client: AuthorizationReader;
    trackingRegistry: Address;
    owner: ShieldedAddress;
  }>,
  context?: RequestContext,
): Promise<Bytes32> {
  const authorization = await readTrackingAuthorization(
    {
      client: input.client,
      trackingRegistry: input.trackingRegistry,
      owner: input.owner.solanaAddress(),
    },
    context,
  );
  // A present row was inserted from the account, so a missing one is a forged or stale read.
  if (authorization === undefined)
    throw new RingError("RING_TRACKING_INVALID", {
      details: { reason: "authorization" },
    });
  return authorization.viewingU;
}

/** `undefined` before the owner's first enrollment, an account another program, registry or owner holds refuses. */
export async function readTrackingAuthorization(
  input: Readonly<{
    client: AuthorizationReader;
    trackingRegistry: Address;
    owner: Address;
  }>,
  context?: RequestContext,
): Promise<TrackingAuthorization | undefined> {
  const [address] = await trackingAuthorizationPda(input.trackingRegistry, input.owner);
  const { value: account } = await runKitRpc("getAccountInfo", context, (abortSignal) =>
    input.client.solanaRpc
      .getAccountInfo(address, {
        commitment: "confirmed",
        encoding: "base64",
      })
      .send({ abortSignal }),
  );
  if (account === null) return undefined;
  if (account.owner !== STORAGE_PROGRAM_ID)
    throw new RingError("RING_TRACKING_INVALID", {
      details: { reason: "authorization program" },
    });
  const authorization = decodeTrackingAuthorization(
    getBase64Encoder().encode(account.data[0]) as Uint8Array,
  );
  if (authorization.registry !== input.trackingRegistry)
    throw new RingError("RING_TRACKING_INVALID", {
      details: { reason: "authorization registry" },
    });
  if (authorization.owner !== input.owner)
    throw new RingError("RING_TRACKING_INVALID", {
      details: { reason: "authorization owner" },
    });
  return authorization;
}

export async function newestTrackingRoot(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount">;
    trackingRegistry: Address;
    ring: Address;
  }>,
  context?: RequestContext,
): Promise<TrackingRoot> {
  const registry = await fetchTrackingRegistry(input.client, input.trackingRegistry, context);
  const newest = registry.roots[0];
  if (newest === undefined)
    throw new RingError("RING_TRACKING_INVALID", {
      details: { reason: "no root" },
    });
  return Object.freeze({
    ringProgramId: input.ring,
    registry: input.trackingRegistry,
    revision: newest.revision,
    root: newest.hash,
  });
}

export async function fetchTrackingRegistry(
  client: Pick<ChainReader, "getAccount">,
  address: Address,
  context?: RequestContext,
): Promise<TrackingRegistry> {
  const account = await client.getAccount(address, context);
  if (account === undefined)
    throw new RingError("RING_TRACKING_INVALID", {
      details: { reason: "registry" },
    });
  return decodeTrackingRegistry(account.data);
}
