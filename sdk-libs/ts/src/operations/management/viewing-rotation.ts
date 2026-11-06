/**
 * A wallet's viewing key rotation through its tracking authorization.
 *
 * Read after `operations/management/enrollment.ts`, whose `Enroll` without a
 * proof carries the new key. Read after `LocalRingKeys` and `ViewingHistory`,
 * the two halves of a wallet a rotation moves together.
 *
 * A rotation runs in three steps. `rotateViewingKey` is local, and the wallet
 * stores the new viewing secret and the rotated history before the owner signs
 * what `updateViewingKey` builds. An authorization naming a key the wallet lost
 * routes every later payment to notes nobody opens. `confirmViewingKey` reads
 * the authorization back once the rotation lands. A rotation writes only the
 * authorization, so it moves no tracking root and waits on no apply. The
 * account holds only the current key, the history keeps every earlier one, and
 * notes sealed to an earlier key open through it.
 */
import type { Address, Instruction } from "@solana/kit";

import { equalBytes, type SignerAccount } from "@heliuslabs/spr/internal";
import type { RequestContext } from "@heliuslabs/spr/interface";
import type { ViewingKey } from "@heliuslabs/spr/keypair";

import { RingError } from "../../protocol/error.js";
import {
  isEnrollmentPending,
  type TrackingAuthorization,
} from "../../protocol/membership/tracking.js";
import type { LocalRingKeys, RingKeys } from "../../state/ring-keys.js";
import type { ViewingHistory } from "../../state/viewing-history.js";
import { enrollInstruction, enrollmentState, type EnrollmentReadClient } from "./enrollment.js";

/** `rotateViewingKey` moves both to one current key. */
export interface ViewingRotation {
  readonly keys: LocalRingKeys;
  readonly history: ViewingHistory;
}

/** `next` becomes current in both, every earlier key stays held and scanned. */
export function rotateViewingKey(
  input: Readonly<ViewingRotation & { next: ViewingKey; rotatedAt: bigint }>,
): ViewingRotation {
  const history = input.history.withRotatedKey(input.next.publicKey(), input.rotatedAt);
  return Object.freeze({ keys: input.keys.rotate(input.next), history });
}

/** The proofless `Enroll` of the holder's current key, `undefined` when the authorization already holds it. */
export async function updateViewingKey(
  input: Readonly<{
    client: EnrollmentReadClient;
    payer: SignerAccount;
    owner: SignerAccount;
    trackingRegistry: Address;
    keys: RingKeys;
    history: ViewingHistory;
  }>,
  context?: RequestContext,
): Promise<Instruction | undefined> {
  // 1. No sync reads a key the history lacks. Publishing one routes payments
  // to notes the wallet never finds.
  const viewingU = input.keys.address().viewingPublicKey.u();
  if (!equalBytes(input.history.current().viewingPublicKey.u(), viewingU))
    throw new RingError("RING_VIEWING_HISTORY_NOT_CURRENT");
  // 2. A rotation repeats the final seal of the first enrollment, the program
  // refuses any other. A holder of another nullifier key would publish a
  // viewing key the enrolled row does not belong to.
  const stored = await storedAuthorization(input, context);
  if (!equalBytes(stored.nullifierPk, input.keys.address().nullifierPublicKey))
    throw new RingError("RING_ENROLLMENT_KEY_MISMATCH");
  if (equalBytes(stored.viewingU, viewingU)) return undefined;
  return enrollInstruction(
    {
      payer: input.payer,
      owner: input.owner,
      trackingRegistry: input.trackingRegistry,
      seal: stored,
      viewingU,
    },
    input.client,
    context,
  );
}

/** Resolves once the authorization of an applied enrollment holds the holder's current key, a pending enrollment or an older key refuses. */
export async function confirmViewingKey(
  input: Readonly<{
    client: EnrollmentReadClient;
    owner: Address;
    trackingRegistry: Address;
    keys: RingKeys;
  }>,
  context?: RequestContext,
): Promise<TrackingAuthorization> {
  const stored = await storedAuthorization(input, context);
  if (
    isEnrollmentPending(stored) ||
    !equalBytes(stored.viewingU, input.keys.address().viewingPublicKey.u())
  )
    throw new RingError("RING_VIEWING_KEY_NOT_PUBLISHED", { details: { owner: input.owner } });
  return stored;
}

async function storedAuthorization(
  input: Readonly<{
    client: EnrollmentReadClient;
    owner: Address | SignerAccount;
    trackingRegistry: Address;
  }>,
  context?: RequestContext,
): Promise<TrackingAuthorization> {
  const owner = typeof input.owner === "string" ? input.owner : input.owner.address;
  const stored = await enrollmentState(
    { trackingRegistry: input.trackingRegistry, owner },
    input.client,
    context,
  );
  if (stored === undefined) throw new RingError("RING_KEY_NOT_REGISTERED", { details: { owner } });
  return stored;
}
