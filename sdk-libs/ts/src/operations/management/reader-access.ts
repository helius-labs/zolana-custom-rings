import { p256 } from "@noble/curves/nist.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { isAddress, type Address } from "@solana/kit";
import {
  addressBytes,
  encodeBase58,
  equalBytes,
  checkedBytes,
  copyBytes,
  hashBytes,
  wrapKeypairError,
} from "@heliuslabs/zolana/internal";
import { type Bytes32, type Bytes33, ShieldedPublicKey } from "@heliuslabs/zolana";

import { memberOfIdentity, memberOfTag, type Member } from "../../protocol/membership/policy.js";
import { RingError } from "../../protocol/error.js";

/** Passkey public key for ring-rpc audit access. */
export class P256ReaderKey {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  static fromBytes(bytes: Bytes33): P256ReaderKey {
    const owned = checkedBytes<Bytes33>(bytes, 33, "P256 public key");
    try {
      p256.Point.fromBytes(owned);
    } catch (error) {
      throw wrapKeypairError("KEYPAIR_INVALID_PUBLIC_KEY", error);
    }
    return new P256ReaderKey(owned);
  }

  /** A 65-byte `0x04 || x || y` point, what WebAuthn and SPKI carry. */
  static fromUncompressed(bytes: Uint8Array): P256ReaderKey {
    try {
      return P256ReaderKey.fromBytes(p256.Point.fromBytes(bytes).toBytes(true) as Bytes33);
    } catch (error) {
      throw wrapKeypairError("KEYPAIR_INVALID_PUBLIC_KEY", error);
    }
  }

  toBytes(): Bytes33 {
    return copyBytes(this.#bytes) as Bytes33;
  }

  toUncompressed(): Uint8Array {
    return p256.Point.fromBytes(this.#bytes).toBytes(false);
  }

  /** Compares canonical compressed passkey encodings. */
  equals(other: P256ReaderKey): boolean {
    const left = this.#bytes;
    const right = other.#bytes;
    return left.length === right.length && left.every((byte, index) => byte === right[index]);
  }
}

/** Rust `READER_KEY_P256` and `READER_KEY_ED25519`. */
const READER_KEY_P256 = 0x00;
const READER_KEY_ED25519 = 0x01;

/** Mirrors Rust `ReaderKey`. */
export type ReaderKey = Address | P256ReaderKey;

/** Mirrors Rust `ReaderKey::ed25519` and `ReaderKey::p256`, a key that cannot sign a read is refused. */
export function checkedReaderKey(reader: ReaderKey): ReaderKey {
  if (typeof reader === "string") {
    const body = addressBytes(reader, "reader");
    let canonical = false;
    try {
      const point = ed25519.Point.fromBytes(body);
      canonical =
        equalBytes(point.toBytes(), body) && point.isTorsionFree() && !point.isSmallOrder();
    } catch {
      canonical = false;
    }
    if (!canonical) throw new RingError("RING_READER_KEY", { details: { reader } });
    return reader;
  }
  return reader;
}

/** The program's 34-byte scheme-tagged layout. */
export function readerKeyBytes(reader: ReaderKey): Uint8Array {
  if (typeof reader === "string") {
    return ShieldedPublicKey.fromEd25519(addressBytes(reader, "reader") as Bytes32).toBytes();
  }
  const bytes = new Uint8Array(34);
  bytes.set(reader.toBytes(), 1);
  return bytes;
}

/** Mirrors Rust `ReaderKey::member`, the member whose record holds the reader's ring-wide grant. */
export function readerKeyMember(reader: ReaderKey): Member {
  return typeof reader === "string"
    ? memberOfTag(addressBytes(reader, "reader"))
    : memberOfIdentity(hashBytes(readerKeyBytes(reader)) as Bytes32);
}

/** Mirrors Rust `ReaderKey::from_bytes`. */
export function readerKeyFromBytes(bytes: Uint8Array): ReaderKey {
  if (bytes.length !== 34) {
    throw new RingError("RING_READER_KEY", { details: { length: bytes.length } });
  }
  switch (bytes[0]) {
    case READER_KEY_ED25519:
      if (bytes[33] !== 0) throw new RingError("RING_READER_KEY", { details: { scheme: 1 } });
      return checkedReaderKey(encodeBase58(bytes.subarray(1, 33)));
    case READER_KEY_P256:
      return checkedReaderKey(P256ReaderKey.fromBytes(bytes.subarray(1) as Bytes33));
    default:
      throw new RingError("RING_READER_KEY", { details: { scheme: bytes[0] } });
  }
}

export function readerKeyEquals(left: ReaderKey, right: ReaderKey): boolean {
  return typeof left === "string" || typeof right === "string"
    ? left === right
    : left.equals(right);
}

/** Mirrors Rust `FromStr`, base58 for a wallet key and 66 hex characters for a P-256 key. */
export function parseReaderKey(text: string): ReaderKey {
  const trimmed = text.trim();
  if (isAddress(trimmed)) return checkedReaderKey(trimmed);
  if (!/^[0-9a-fA-F]{66}$/.test(trimmed)) {
    throw new RingError("RING_READER_KEY", { details: { text: trimmed } });
  }
  let key: P256ReaderKey;
  try {
    key = P256ReaderKey.fromBytes(hexToBytes(trimmed) as Bytes33);
  } catch (cause) {
    throw new RingError("RING_READER_KEY", { details: { text: trimmed }, cause });
  }
  return checkedReaderKey(key);
}

export function readerKeyToString(reader: ReaderKey): string {
  return typeof reader === "string" ? reader : bytesToHex(reader.toBytes());
}
