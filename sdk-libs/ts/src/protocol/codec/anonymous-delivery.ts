/** The anonymous frame's sender bundle and replies, Rust `zolana_ring_transaction::recipient_delivery`. */
import { checkedBytes, concatBytes, encodeData, Reader, readData } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import type { X25519PublicKey } from "@heliuslabs/spr/keypair";
import type { Data } from "@heliuslabs/spr/transaction";

import {
  REPLY_ENC_INFO,
  SENDER_BUNDLE_ENC_INFO,
  symmetricAuditApply,
} from "../../crypto/audit/audit.js";
import { x25519FromU } from "../../crypto/keys/x25519.js";
import { checkedViewingU } from "../membership/member-opening.js";
import { STREAM_FIRST_COUNTER } from "./ring-disclosure-layout.js";
import { RingError } from "../error.js";

const FIELD_LEN = 32;

/** `viewing_u ‖ owner_key ‖ nullifier_pk`, the reply's fields ahead of its data. */
const REPLY_HEAD_LEN = 3 * FIELD_LEN;
/** A reply holding empty data. */
export const MIN_REPLY_LEN = REPLY_HEAD_LEN + 1;

/** Rust `BundleLayout`, the frame publishes `m` and the bundle spends no byte on it. */
export interface BundleLayout {
  /** The frame's `m`. */
  readonly outputs: number;
}

/** `output_seed ‖ recipient_u * m`. */
export function senderBundleLen(layout: BundleLayout): number {
  return FIELD_LEN + FIELD_LEN * layout.outputs;
}

/** Semantics unproved, the statement binds only its presence, length and bytes. */
export interface ReplyMetadata {
  readonly viewingKey: X25519PublicKey;
  readonly ownerKey: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly data: Data;
}

/** A decrypted reply, an unverified sender claim no authorization reads, Rust `ReplyClaim`. */
export interface ReplyClaim {
  readonly claimed: ReplyMetadata;
}

/** `output_seed ‖ recipient keys`, key `k` is slot `k`'s `V_k`, zero on an exit or a dummy. */
export interface SenderBundle {
  readonly outputSeed: Bytes32;
  readonly recipientKeys: readonly Bytes32[];
}

/** The longest reply `replies` encode to, every body of a frame shares one length. */
export function replyLength(replies: readonly ReplyMetadata[]): number {
  return replies.reduce(
    (longest, reply) => Math.max(longest, REPLY_HEAD_LEN + encodeData(reply.data).length),
    MIN_REPLY_LEN,
  );
}

/** Its own label gives the reply its own key and nonce, the body's counter never restarts. */
export function sealReply(slotSecret: Bytes32, reply: ReplyMetadata, length: number): Uint8Array {
  const data = encodeData(reply.data);
  if (length < REPLY_HEAD_LEN + data.length) throw replyInvalid("length");
  return seal(slotSecret, REPLY_ENC_INFO, () => {
    const plaintext = new Uint8Array(length);
    plaintext.set(reply.viewingKey.u(), 0);
    plaintext.set(checkedBytes<Bytes32>(reply.ownerKey, FIELD_LEN, "ownerKey"), FIELD_LEN);
    plaintext.set(
      checkedBytes<Bytes32>(reply.nullifierPk, FIELD_LEN, "nullifierPk"),
      2 * FIELD_LEN,
    );
    plaintext.set(data, REPLY_HEAD_LEN);
    return plaintext;
  });
}

/** The proof binds the bytes alone, `undefined` on a reply that never decodes. */
export function openReply(slotSecret: Bytes32, ciphertext: Uint8Array): ReplyClaim | undefined {
  if (ciphertext.length < MIN_REPLY_LEN) return undefined;
  return open(slotSecret, REPLY_ENC_INFO, ciphertext, ciphertext.length, (plaintext) => {
    const data = readReplyData(plaintext.subarray(REPLY_HEAD_LEN));
    const viewingKey = replyKey(plaintext.slice(0, FIELD_LEN) as Bytes32);
    if (data === undefined || viewingKey === undefined) return undefined;
    return Object.freeze({
      claimed: Object.freeze({
        viewingKey,
        ownerKey: plaintext.slice(FIELD_LEN, 2 * FIELD_LEN) as Bytes32,
        nullifierPk: plaintext.slice(2 * FIELD_LEN, REPLY_HEAD_LEN) as Bytes32,
        data,
      }),
    });
  });
}

export function sealSenderBundle(slotSecret: Bytes32, bundle: SenderBundle): Uint8Array {
  return seal(slotSecret, SENDER_BUNDLE_ENC_INFO, () =>
    concatBytes(
      checkedBytes<Bytes32>(bundle.outputSeed, FIELD_LEN, "outputSeed"),
      ...bundle.recipientKeys.map((key) => checkedBytes<Bytes32>(key, FIELD_LEN, "recipientKey")),
    ),
  );
}

/** `layout` holds the frame's published count, never a count a reader inferred from the ciphertext. */
export function openSenderBundle(
  slotSecret: Bytes32,
  ciphertext: Uint8Array,
  layout: BundleLayout,
): SenderBundle {
  return open(
    slotSecret,
    SENDER_BUNDLE_ENC_INFO,
    ciphertext,
    senderBundleLen(layout),
    (plaintext) => {
      const keyAt = (index: number): number => FIELD_LEN + FIELD_LEN * index;
      return Object.freeze({
        outputSeed: plaintext.slice(0, FIELD_LEN) as Bytes32,
        recipientKeys: Object.freeze(
          Array.from(
            { length: layout.outputs },
            (_, index) => plaintext.slice(keyAt(index), keyAt(index + 1)) as Bytes32,
          ),
        ),
      });
    },
  );
}

/** One data field then zero padding, `undefined` on any other bytes. */
function readReplyData(bytes: Uint8Array): Data | undefined {
  try {
    const data = readData(new Reader(bytes), "reply.data");
    return bytes.subarray(encodeData(data).length).every((byte) => byte === 0) ? data : undefined;
  } catch {
    return undefined;
  }
}

/** A zero or noncanonical key makes the claim malformed, unauthenticated as it stays. */
function replyKey(u: Bytes32): X25519PublicKey | undefined {
  try {
    return x25519FromU(checkedViewingU(u));
  } catch {
    return undefined;
  }
}

function seal(secret: Bytes32, label: Uint8Array, plaintext: () => Uint8Array): Uint8Array {
  const bytes = plaintext();
  try {
    return symmetricAuditApply(
      checkedBytes<Bytes32>(secret, FIELD_LEN, "slot secret"),
      position(label),
      bytes,
    );
  } finally {
    bytes.fill(0);
  }
}

function open<T>(
  secret: Bytes32,
  label: Uint8Array,
  ciphertext: Uint8Array,
  length: number,
  read: (plaintext: Uint8Array) => T,
): T {
  const plaintext = symmetricAuditApply(
    checkedBytes<Bytes32>(secret, FIELD_LEN, "slot secret"),
    position(label),
    checkedBytes(ciphertext, length, "ciphertext"),
  );
  try {
    return read(plaintext);
  } finally {
    plaintext.fill(0);
  }
}

function position(label: Uint8Array) {
  return Object.freeze({ label, counter: STREAM_FIRST_COUNTER });
}

function replyInvalid(reason: string): RingError {
  return new RingError("RING_REPLY_INVALID", { details: { reason } });
}
