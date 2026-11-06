/** Mirrors Rust `zolana_ring_keys::ring_address`, pinned by `test-vectors/wallet/ring_address.json`. */
import { equalBytes } from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  address,
  getAddressDecoder,
  getAddressEncoder,
  getBase58Decoder,
  getBase58Encoder,
  type Address,
} from "@solana/kit";

import {
  SHIELDED_ADDRESS_LENGTH,
  concatBytes,
  isCanonicalField,
  U64_MAX,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import { ShieldedAddress, type Bytes32, type ShieldedKeypairLike } from "@heliuslabs/spr/keypair";

import { checkedCounter, RingKeyError } from "../error.js";

const addressDecoder = getAddressDecoder();
const addressEncoder = getAddressEncoder();
const base58Decoder = getBase58Decoder();
const base58Encoder = getBase58Encoder();
const encoder = new TextEncoder();

export const RING_ADDRESS_CHECKSUM_DOMAIN = "zolana/ring-addr";

export const RING_PAYMENT_SCHEME = "zolana:";

const CHECKSUM_LENGTH = 4;
/** `recipient ‖ ring_program_id ‖ list_salt`. */
const BODY_LENGTH = SHIELDED_ADDRESS_LENGTH + 32 + 32;
const PROGRAM_OFFSET = SHIELDED_ADDRESS_LENGTH;
const SALT_OFFSET = PROGRAM_OFFSET + 32;

export const RING_ADDRESS_PAYLOAD_LENGTH = BODY_LENGTH + CHECKSUM_LENGTH;

/** Shared off chain, a transfer to it derives every tag from its slot secret. */
export class RingAddress {
  readonly recipient: ShieldedAddress;
  readonly ringProgramId: Address;
  /** Zero exactly under the zero key. */
  readonly listSalt: Bytes32;

  constructor(
    fields: Readonly<{ recipient: ShieldedAddress; ringProgramId: Address; listSalt: Bytes32 }>,
  ) {
    const zeroKey = equalBytes(fields.recipient.nullifierPublicKey, ZERO_NULLIFIER_PK);
    const salt = fields.listSalt;
    if (
      !(salt instanceof Uint8Array) ||
      salt.length !== 32 ||
      !isCanonicalField(salt) ||
      zeroKey !== salt.every((byte) => byte === 0)
    )
      throw new RingKeyError("KEYPAIR_INVALID_RING_ADDRESS_LIST_SALT");
    this.recipient = fields.recipient;
    this.ringProgramId = fields.ringProgramId;
    this.listSalt = Uint8Array.from(salt) as Bytes32;
    Object.freeze(this);
  }

  /** Reveals the owner's list status. */
  static async enrolled(
    holder: Pick<ShieldedKeypairLike, "shieldedAddress">,
    ringProgramId: Address,
    listSalt: Bytes32,
  ): Promise<RingAddress> {
    return new RingAddress({ recipient: await holder.shieldedAddress(), ringProgramId, listSalt });
  }

  equals(other: RingAddress): boolean {
    return equalBytes(this.toBytes(), other.toBytes());
  }

  /** `recipient ‖ ring_program_id ‖ list_salt ‖ checksum`. */
  toBytes(): Uint8Array {
    const body = concatBytes(
      this.recipient.toBytes(),
      new Uint8Array(addressEncoder.encode(this.ringProgramId)),
      this.listSalt,
    );
    return concatBytes(body, checksum(body));
  }

  static fromBytes(bytes: Uint8Array): RingAddress {
    if (!(bytes instanceof Uint8Array) || bytes.length !== RING_ADDRESS_PAYLOAD_LENGTH)
      throw new RingKeyError("KEYPAIR_INVALID_RING_ADDRESS_LENGTH");
    const body = bytes.subarray(0, BODY_LENGTH);
    if (!equalBytes(bytes.subarray(BODY_LENGTH), checksum(body)))
      throw new RingKeyError("KEYPAIR_INVALID_RING_ADDRESS_CHECKSUM");
    return new RingAddress({
      recipient: ShieldedAddress.fromBytes(body.subarray(0, PROGRAM_OFFSET)),
      ringProgramId: addressDecoder.decode(body.subarray(PROGRAM_OFFSET, SALT_OFFSET)),
      listSalt: body.slice(SALT_OFFSET) as Bytes32,
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
  amount?: bigint | undefined;
  mint?: Address | undefined;
  label?: string | undefined;
}>;

/** `zolana:<address>?amount=&mint=&label=`, the query part is unauthenticated. */
export class RingPaymentRequest {
  readonly address: RingAddress;
  readonly amount: bigint | undefined;
  readonly mint: Address | undefined;
  readonly label: string | undefined;

  constructor(fields: RingPaymentRequestFields) {
    this.address = fields.address;
    this.amount = fields.amount === undefined ? undefined : checkedCounter(fields.amount, "amount");
    this.mint = fields.mint;
    this.label = fields.label;
    Object.freeze(this);
  }

  toString(): string {
    const query: string[] = [];
    if (this.amount !== undefined) query.push(`amount=${this.amount}`);
    if (this.mint !== undefined) query.push(`mint=${this.mint}`);
    if (this.label !== undefined) query.push(`label=${encodeLabel(this.label)}`);
    const encoded = `${RING_PAYMENT_SCHEME}${this.address.toBase58()}`;
    return query.length === 0 ? encoded : `${encoded}?${query.join("&")}`;
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
    let amount: bigint | undefined;
    let mint: Address | undefined;
    let label: string | undefined;
    for (const part of query) {
      const equals = part.indexOf("=");
      const key = equals === -1 ? part : part.slice(0, equals);
      const value = equals === -1 ? "" : part.slice(equals + 1);
      switch (key) {
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
    return new RingPaymentRequest({ address, amount, mint, label });
  }
}

function replaceOnce<T>(slot: T | undefined, value: T): T {
  if (slot !== undefined) throw new RingKeyError("KEYPAIR_DUPLICATE_RING_PAYMENT_KEY");
  return value;
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
