/** Mirrors Rust `zolana_ring_keys::ring_address`, pinned by `test-vectors/wallet/ring_address.json`. */
import { equalBytes } from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  address,
  getAddressDecoder,
  getAddressEncoder,
  getBase58Decoder,
  getBase58Encoder,
  type Address,
} from "@solana/kit";

import { concatBytes, U64_MAX } from "@heliuslabs/zolana/internal";
import { ShieldedAddress, type ViewTag } from "@heliuslabs/zolana/keypair";

import { checkedCounter, RingKeyError } from "../error.js";

const addressDecoder = getAddressDecoder();
const addressEncoder = getAddressEncoder();
const base58Decoder = getBase58Decoder();
const base58Encoder = getBase58Encoder();
const encoder = new TextEncoder();

export const RING_ADDRESS_VERSION = 3;

export const RING_ADDRESS_CHECKSUM_DOMAIN = "zolana/ring-addr/v3";

export const RING_PAYMENT_SCHEME = "zolana:";

/** Rust `SHIELDED_ADDRESS_LEN`, signing key, nullifier key and tagged viewing key. */
const SHIELDED_ADDRESS_LENGTH = 34 + 32 + 33;
const CHECKSUM_LENGTH = 4;
/** `version ‖ recipient ‖ ring_program_id`. */
const BODY_LENGTH = 1 + SHIELDED_ADDRESS_LENGTH + 32;
const PROGRAM_OFFSET = 1 + SHIELDED_ADDRESS_LENGTH;

export const RING_ADDRESS_PAYLOAD_LENGTH = BODY_LENGTH + CHECKSUM_LENGTH;

/** Shared off chain, a payment to it names its first contact tag explicitly. */
export class RingAddress {
  readonly recipient: ShieldedAddress;
  readonly ringProgramId: Address;

  constructor(fields: Readonly<{ recipient: ShieldedAddress; ringProgramId: Address }>) {
    this.recipient = fields.recipient;
    this.ringProgramId = fields.ringProgramId;
    Object.freeze(this);
  }

  equals(other: RingAddress): boolean {
    return equalBytes(this.toBytes(), other.toBytes());
  }

  /** `version ‖ recipient ‖ ring_program_id ‖ checksum`. */
  toBytes(): Uint8Array {
    const body = concatBytes(
      Uint8Array.of(RING_ADDRESS_VERSION),
      this.recipient.toBytes(),
      new Uint8Array(addressEncoder.encode(this.ringProgramId)),
    );
    return concatBytes(body, checksum(body));
  }

  static fromBytes(bytes: Uint8Array): RingAddress {
    if (!(bytes instanceof Uint8Array) || bytes.length !== RING_ADDRESS_PAYLOAD_LENGTH)
      throw new RingKeyError("KEYPAIR_INVALID_RING_ADDRESS_LENGTH");
    const body = bytes.subarray(0, BODY_LENGTH);
    const version = body[0] ?? -1;
    if (version !== RING_ADDRESS_VERSION)
      throw new RingKeyError("KEYPAIR_UNKNOWN_RING_ADDRESS_VERSION", { actual: version });
    if (!equalBytes(bytes.subarray(BODY_LENGTH), checksum(body)))
      throw new RingKeyError("KEYPAIR_INVALID_RING_ADDRESS_CHECKSUM");
    return new RingAddress({
      recipient: ShieldedAddress.fromBytes(body.subarray(1, PROGRAM_OFFSET)),
      ringProgramId: addressDecoder.decode(body.subarray(PROGRAM_OFFSET)),
    });
  }

  toBase58(): string {
    return base58Decoder.decode(this.toBytes());
  }

  static fromBase58(text: string): RingAddress {
    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(base58Encoder.encode(text));
    } catch (error) {
      throw new RingKeyError("KEYPAIR_INVALID_RING_ADDRESS_BASE58", undefined, error);
    }
    return RingAddress.fromBytes(bytes);
  }
}

function checksum(body: Uint8Array): Uint8Array {
  return sha256(concatBytes(encoder.encode(RING_ADDRESS_CHECKSUM_DOMAIN), body)).subarray(
    0,
    CHECKSUM_LENGTH,
  );
}

export type RingPaymentRequestFields = Readonly<{
  address: RingAddress;
  /** The recipient's `recipientRequestViewTag`, a sender pays it until the pair is known. */
  requestViewTag: ViewTag;
  amount?: bigint | undefined;
  mint?: Address | undefined;
  label?: string | undefined;
}>;

/** `zolana:<address>?tag=&amount=&mint=&label=`, the query part is unauthenticated. */
export class RingPaymentRequest {
  readonly address: RingAddress;
  readonly requestViewTag: ViewTag;
  readonly amount: bigint | undefined;
  readonly mint: Address | undefined;
  readonly label: string | undefined;

  constructor(fields: RingPaymentRequestFields) {
    this.address = fields.address;
    this.requestViewTag = checkedRequestTag(fields.requestViewTag);
    this.amount = fields.amount === undefined ? undefined : checkedCounter(fields.amount, "amount");
    this.mint = fields.mint;
    this.label = fields.label;
    Object.freeze(this);
  }

  toString(): string {
    const query = [`tag=${bytesToHex(this.requestViewTag)}`];
    if (this.amount !== undefined) query.push(`amount=${this.amount}`);
    if (this.mint !== undefined) query.push(`mint=${this.mint}`);
    if (this.label !== undefined) query.push(`label=${encodeLabel(this.label)}`);
    return `${RING_PAYMENT_SCHEME}${this.address.toBase58()}?${query.join("&")}`;
  }

  static parse(text: string): RingPaymentRequest {
    const trimmed = text.trim();
    if (!trimmed.startsWith(RING_PAYMENT_SCHEME)) {
      throw new RingKeyError("KEYPAIR_INVALID_RING_ADDRESS_SCHEME");
    }
    const rest = trimmed.slice(RING_PAYMENT_SCHEME.length);
    const separator = rest.indexOf("?");
    const encoded = separator === -1 ? rest : rest.slice(0, separator);
    const query = separator === -1 ? [] : rest.slice(separator + 1).split("&");
    const address = RingAddress.fromBase58(encoded);
    let tag: ViewTag | undefined;
    let amount: bigint | undefined;
    let mint: Address | undefined;
    let label: string | undefined;
    for (const part of query) {
      const equals = part.indexOf("=");
      const key = equals === -1 ? part : part.slice(0, equals);
      const value = equals === -1 ? "" : part.slice(equals + 1);
      switch (key) {
        case "tag":
          tag = replaceOnce(tag, parseTag(value));
          break;
        case "amount":
          amount = replaceOnce(amount, parseAmount(value));
          break;
        case "mint":
          mint = replaceOnce(mint, parseMint(value));
          break;
        case "label":
          label = replaceOnce(label, decodeLabel(value));
          break;
        default:
          throw new RingKeyError("KEYPAIR_UNKNOWN_RING_PAYMENT_KEY", { name: key });
      }
    }
    if (tag === undefined) throw new RingKeyError("KEYPAIR_MISSING_RING_PAYMENT_TAG");
    return new RingPaymentRequest({ address, requestViewTag: tag, amount, mint, label });
  }
}

function replaceOnce<T>(slot: T | undefined, value: T): T {
  if (slot !== undefined) throw new RingKeyError("KEYPAIR_DUPLICATE_RING_PAYMENT_KEY");
  return value;
}

/** Lowercase hex with a leading zero byte, the one form a derived request tag takes. */
function parseTag(value: string): ViewTag {
  if (!/^00[0-9a-f]{62}$/.test(value)) throw new RingKeyError("KEYPAIR_INVALID_RING_PAYMENT_TAG");
  return hexToBytes(value) as ViewTag;
}

function checkedRequestTag(tag: ViewTag): ViewTag {
  if (!(tag instanceof Uint8Array) || tag.length !== 32 || tag[0] !== 0)
    throw new RingKeyError("KEYPAIR_INVALID_RING_PAYMENT_TAG");
  return Uint8Array.from(tag) as ViewTag;
}

function parseAmount(value: string): bigint {
  if (!/^[0-9]+$/.test(value)) throw new RingKeyError("KEYPAIR_INVALID_RING_PAYMENT_AMOUNT");
  const amount = BigInt(value);
  if (amount > U64_MAX) throw new RingKeyError("KEYPAIR_INVALID_RING_PAYMENT_AMOUNT");
  return amount;
}

function parseMint(value: string): Address {
  try {
    return address(value);
  } catch (error) {
    throw new RingKeyError("KEYPAIR_INVALID_RING_PAYMENT_MINT", undefined, error);
  }
}

/** RFC 3986 unreserved characters stay literal, everything else is percent-encoded. */
function encodeLabel(label: string): string {
  return encodeURIComponent(label).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/** Every `%` must open a two-digit escape. */
function decodeLabel(value: string): string {
  if (
    !value
      .split("%")
      .slice(1)
      .every((after) => /^[0-9a-fA-F]{2}/.test(after))
  ) {
    throw new RingKeyError("KEYPAIR_INVALID_RING_PAYMENT_LABEL");
  }
  try {
    return decodeURIComponent(value);
  } catch (error) {
    throw new RingKeyError("KEYPAIR_INVALID_RING_PAYMENT_LABEL", undefined, error);
  }
}
