/** Ring output bodies in SPP's output framing, Rust `custom_ring_interface::output`. */
import {
  COMPACT_RECIPIENT_BODY_LEN,
  DisclosureFormat,
  RECIPIENT_BODY_LEN,
} from "../codec/ring-disclosure-layout.js";
import { TransactionError } from "@heliuslabs/spr/transaction";

/** The schemes a ring output publishes, SPP stores the ring-owned ones unparsed. */
export const RingScheme = Object.freeze({
  confidential: 3,
  ringSenderBundle: 9,
  /** `u16le(body_len) ‖ body ‖ reply`, one form on every rail. */
  ringBody: 10,
  compactRingBody: 11,
} as const);
export type RingScheme = (typeof RingScheme)[keyof typeof RingScheme];

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

/** Ring body, Rust `encode_ring_body_output`. */
export function encodeRingBodyOutput(body: Uint8Array, reply: Uint8Array): Uint8Array {
  if (body.length > 0xffff)
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      field: "ringBody",
      expected: 0xffff,
      actual: body.length,
    });
  const payload = new Uint8Array(2 + body.length + reply.length);
  new DataView(payload.buffer).setUint16(0, body.length, true);
  payload.set(body, 2);
  payload.set(reply, 2 + body.length);
  return encodeRingOutput(
    body.length === COMPACT_RECIPIENT_BODY_LEN ? RingScheme.compactRingBody : RingScheme.ringBody,
    payload,
  );
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

/** The body and reply of a ring body output, `undefined` below the plain body's length, Rust `ring_body_output`. */
export function ringBodyOutput(
  data: Uint8Array,
): Readonly<{ body: Uint8Array; reply: Uint8Array; format: DisclosureFormat }> | undefined {
  let frame: RingOutputFrame;
  try {
    frame = readRingOutput(data);
  } catch {
    return undefined;
  }
  if (frame.encoding !== "encrypted") return undefined;
  const format =
    frame.scheme === RingScheme.ringBody
      ? DisclosureFormat.Standard
      : frame.scheme === RingScheme.compactRingBody
        ? DisclosureFormat.SingleAssetPayout
        : undefined;
  if (format === undefined || frame.body.length < 2) return undefined;
  const payload = frame.body;
  const length = new DataView(payload.buffer, payload.byteOffset, 2).getUint16(0, true);
  const rest = payload.subarray(2);
  if (
    length > rest.length ||
    (format === DisclosureFormat.SingleAssetPayout
      ? length !== COMPACT_RECIPIENT_BODY_LEN || rest.length !== length
      : length < RECIPIENT_BODY_LEN)
  )
    return undefined;
  return Object.freeze({ body: rest.subarray(0, length), reply: rest.subarray(length), format });
}

export function senderBundleOutputBody(data: Uint8Array): Uint8Array | undefined {
  return encryptedOutputBody(data, RingScheme.ringSenderBundle);
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
