/** Ring output bodies in SPP's output framing, Rust `custom_ring_interface::output`. */
import type { Bytes32 } from "@heliuslabs/zolana";
import { bytesToBigInt, checkedBytes, concatBytes, u64be } from "@heliuslabs/zolana/internal";
import { EncryptedScheme, TransactionError } from "@heliuslabs/zolana/transaction";

import { symmetricAuditApply } from "../../crypto/audit/audit.js";
import { checkedCounter } from "../../crypto/error.js";

/** The schemes a ring output publishes, SPP stores the ring-owned scheme 10 unparsed. */
export const RingScheme = Object.freeze({
  anonymousRecipient: EncryptedScheme.anonymousRecipient,
  anonymousSender: EncryptedScheme.anonymousSender,
  confidential: 3,
  ringConfidentialDelivered: 10,
} as const);
export type RingScheme = (typeof RingScheme)[keyof typeof RingScheme];

/** `be32(blinding) ‖ u64be(amount)` under the audit stream, Rust `RING_DELIVERED_BODY_LEN`. */
export const RING_DELIVERED_BODY_LEN = 40;
/** `0x04 ‖ u`, the recipient key a scheme 3 body leads with. */
export const RECIPIENT_KEY_LEN = 33;
/** Asset id, amount and blinding open every confidential plaintext. */
const CONFIDENTIAL_PLAINTEXT_HEAD_LEN = 8 + 8 + 32;
/** Scheme 3 body of an output with no data and no ring id, each one zero byte. */
export const CONFIDENTIAL_DATA_FREE_BODY_LEN =
  RECIPIENT_KEY_LEN + CONFIDENTIAL_PLAINTEXT_HEAD_LEN + 2;

const ENCODING_TAGS = ["plaintext", "encrypted", "verifiable"] as const;
export type RingOutputEncoding = (typeof ENCODING_TAGS)[number];

export interface RingOutputFrame {
  readonly encoding: RingOutputEncoding;
  readonly scheme: number;
  readonly body: Uint8Array;
}

/** `Encrypted(u32le(len) ‖ scheme ‖ payload)`, the length counting the scheme byte. */
export function encodeRingOutput(scheme: RingScheme, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + 4 + 1 + payload.length);
  out[0] = 1;
  new DataView(out.buffer).setUint32(1, 1 + payload.length, true);
  out[5] = scheme;
  out.set(payload, 6);
  return out;
}

/** Any scheme byte, the caller checks the scheme and the encoding it expects. */
export function readRingOutput(bytes: Uint8Array): RingOutputFrame {
  const encoding = ENCODING_TAGS[bytes[0] ?? -1];
  if (encoding === undefined || bytes.length < 6) {
    throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { field: "outputData" });
  }
  const length = new DataView(bytes.buffer, bytes.byteOffset + 1, 4).getUint32(0, true);
  if (length === 0 || length !== bytes.length - 5) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      field: "encryptedOutput",
      expected: bytes.length - 5,
      actual: length,
    });
  }
  return Object.freeze({ encoding, scheme: bytes[5] ?? 0, body: bytes.slice(6) });
}

export function anonymousRecipientOutputBody(data: Uint8Array): Uint8Array | undefined {
  return encryptedOutputBody(data, RingScheme.anonymousRecipient);
}

export function anonymousSenderOutputBody(data: Uint8Array): Uint8Array | undefined {
  return encryptedOutputBody(data, RingScheme.anonymousSender);
}

function encryptedOutputBody(data: Uint8Array, scheme: RingScheme): Uint8Array | undefined {
  let frame: RingOutputFrame;
  try {
    frame = readRingOutput(data);
  } catch {
    return undefined;
  }
  return frame.encoding === "encrypted" && frame.scheme === scheme ? frame.body : undefined;
}

/** What a scheme 10 body opens to, its asset matched against the published commitment. */
export interface DeliveredBodyOpening {
  readonly blinding: Bytes32;
  readonly amount: bigint;
}

/** AES-256-CTR of `be32(blinding) ‖ u64be(amount)` under the slot secret's audit stream. */
export function sealDeliveredBody(slotSecret: Bytes32, opening: DeliveredBodyOpening): Uint8Array {
  const plaintext = concatBytes(
    checkedBytes<Bytes32>(opening.blinding, 32, "blinding"),
    u64be(checkedCounter(opening.amount, "amount")),
  );
  try {
    return symmetricAuditApply(checkedBytes<Bytes32>(slotSecret, 32, "slot secret"), plaintext);
  } finally {
    plaintext.fill(0);
  }
}

/** The cipher is unauthenticated, only the rebuilt commitment tells a body of another key. */
export function openDeliveredBody(slotSecret: Bytes32, body: Uint8Array): DeliveredBodyOpening {
  const plaintext = symmetricAuditApply(
    checkedBytes<Bytes32>(slotSecret, 32, "slot secret"),
    checkedBytes(body, RING_DELIVERED_BODY_LEN, "delivered body"),
  );
  try {
    return Object.freeze({
      blinding: checkedBytes<Bytes32>(plaintext.subarray(0, 32), 32, "blinding"),
      amount: bytesToBigInt(plaintext.subarray(32)),
    });
  } finally {
    plaintext.fill(0);
  }
}
