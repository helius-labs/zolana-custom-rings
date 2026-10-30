/** The ring intents beside the pinned SPP intents, Rust `TransactionIntent::RingAnonymousTransfer`. */
import { sha256 } from "@noble/hashes/sha2.js";

import type { Address, Bytes32 } from "@heliuslabs/zolana";
import {
  addressBytes,
  checkIntentApproval,
  checkPreparedTransfer,
  equalBytes,
  u64be,
} from "@heliuslabs/zolana/internal";
import {
  intentHash,
  type ApprovalRequest,
  type IntentApproval,
  type PreparedTransfer,
  type TransactionIntent,
} from "@heliuslabs/zolana/transaction";

import { RingAddress } from "../../crypto/keys/ring-address.js";
import { RingError } from "../error.js";

export type RingAnonymousTransferIntent = Readonly<{
  kind: "ringAnonymousTransfer";
  ringProgramId: Address;
  asset: Address;
  amount: bigint;
  /** The address the payment pays, inside `ringProgramId`. */
  recipient: RingAddress;
  /** Default-ring UTXO value the payment moves into the ring. */
  defaultFunding: bigint;
}>;

export type RingTransactionIntent = TransactionIntent | RingAnonymousTransferIntent;

export type RingApprovalRequest = Omit<ApprovalRequest, "intent"> &
  Readonly<{ intent: RingTransactionIntent }>;

export type RingApprovalHandler = (request: RingApprovalRequest) => Promise<IntentApproval>;

const INTENT_DOMAIN = "zolana/intent/v1";
/** Follows the pinned SPP kind tags, 1 to 10. */
const RING_ANONYMOUS_TRANSFER_TAG = 11;

export const approveRingUnattended: RingApprovalHandler = (request) =>
  Promise.resolve(Object.freeze({ intentHash: ringIntentHash(request.intent) }));

/** The pinned `intentHash` for every SPP kind. */
export function ringIntentHash(intent: RingTransactionIntent): Bytes32 {
  if (intent.kind !== "ringAnonymousTransfer") return intentHash(intent);
  if (
    !(intent.recipient instanceof RingAddress) ||
    intent.recipient.ringProgramId !== intent.ringProgramId
  )
    throw new RingError("RING_INTENT_MISMATCH", { details: { field: "recipient" } });
  const recipient = intent.recipient.toBytes();
  const hash = sha256.create();
  hash.update(new TextEncoder().encode(INTENT_DOMAIN));
  hash.update(Uint8Array.of(RING_ANONYMOUS_TRANSFER_TAG));
  hash.update(addressBytes(intent.ringProgramId, "ringProgramId"));
  hash.update(addressBytes(intent.asset, "asset"));
  hash.update(u64be(intent.amount));
  hash.update(Uint8Array.of(recipient.length >> 8, recipient.length & 0xff));
  hash.update(recipient);
  hash.update(u64be(intent.defaultFunding));
  return hash.digest() as Bytes32;
}

export function checkRingIntentApproval(
  approval: IntentApproval,
  intent: RingTransactionIntent,
  mismatch: (field: string) => Error,
): void {
  if (intent.kind !== "ringAnonymousTransfer") {
    checkIntentApproval(approval, intent, mismatch);
    return;
  }
  const got: unknown = (approval as Partial<IntentApproval> | null)?.intentHash;
  if (!(got instanceof Uint8Array) || got.length !== 32 || !equalBytes(got, ringIntentHash(intent)))
    throw mismatch("intentHash");
}

/** An anonymous payment binds its outputs as a ring transfer to the address's recipient does. */
export function checkRingPreparedTransfer(
  prepared: PreparedTransfer,
  intent: RingTransactionIntent,
  mismatch: (field: string) => Error,
): void {
  checkPreparedTransfer(
    prepared,
    intent.kind === "ringAnonymousTransfer"
      ? {
          kind: "ringTransfer",
          ringProgramId: intent.ringProgramId,
          asset: intent.asset,
          amount: intent.amount,
          recipient: intent.recipient.recipient,
          boundary: "transfer",
          defaultFunding: intent.defaultFunding,
        }
      : intent,
    mismatch,
  );
}
