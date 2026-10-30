import { fieldU32, hideCause, sanitizeDetails, U64_MAX } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana";

/** Rust `zolana_ring_keys::RingKeyError` variants, another enum's variant written `Enum::Variant`. */
export const RING_KEY_ERROR_RUST_VARIANT = Object.freeze({
  KEYPAIR_INVALID_RING_ADDRESS_SCHEME: "InvalidRingAddressScheme",
  KEYPAIR_INVALID_RING_ADDRESS_BASE58: "InvalidRingAddressBase58",
  KEYPAIR_INVALID_RING_ADDRESS_LENGTH: "InvalidRingAddressLength",
  KEYPAIR_UNKNOWN_RING_ADDRESS_VERSION: "UnknownRingAddressVersion",
  KEYPAIR_INVALID_RING_ADDRESS_CHECKSUM: "InvalidRingAddressChecksum",
  KEYPAIR_UNKNOWN_RING_PAYMENT_KEY: "UnknownRingPaymentKey",
  KEYPAIR_DUPLICATE_RING_PAYMENT_KEY: "DuplicateRingPaymentKey",
  KEYPAIR_MISSING_RING_PAYMENT_TAG: "MissingRingPaymentTag",
  KEYPAIR_INVALID_RING_PAYMENT_TAG: "InvalidRingPaymentTag",
  KEYPAIR_INVALID_RING_PAYMENT_AMOUNT: "InvalidRingPaymentAmount",
  KEYPAIR_INVALID_RING_PAYMENT_MINT: "InvalidRingPaymentMint",
  KEYPAIR_INVALID_RING_PAYMENT_LABEL: "InvalidRingPaymentLabel",
  KEYPAIR_UNKNOWN_VIEWING_KEY: "UnknownViewingKey",
  KEYPAIR_DISCLOSURE_SHAPE: "AuditError::DisclosureLayout",
  KEYPAIR_DISCLOSURE_PADDING: "AuditError::DisclosurePadding",
  KEYPAIR_DISCLOSURE_FIELD: "AuditError::DisclosureField",
  KEYPAIR_INVALID_LENGTH: null,
} as const);

export type RingKeyErrorCode = keyof typeof RING_KEY_ERROR_RUST_VARIANT;

export class RingKeyError extends Error {
  readonly code: RingKeyErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(
    code: RingKeyErrorCode,
    details?: Readonly<Record<string, unknown>>,
    cause?: unknown,
  ) {
    super(code);
    this.name = "RingKeyError";
    this.code = code;
    const sanitized = sanitizeDetails(details);
    if (sanitized !== undefined) this.details = sanitized;
    hideCause(this, cause);
  }

  /** The Rust variant this code mirrors, or `null` for a TypeScript-only code. */
  get rustVariant(): string | null {
    return RING_KEY_ERROR_RUST_VARIANT[this.code];
  }

  toJSON(): Readonly<{
    name: string;
    code: RingKeyErrorCode;
    details?: Readonly<Record<string, unknown>>;
  }> {
    return this.details === undefined
      ? { name: this.name, code: this.code }
      : { name: this.name, code: this.code, details: this.details };
  }
}

/** A stream counter, `u64` in Rust. */
export function checkedCounter(value: bigint | number, name: string): bigint {
  const counter = typeof value === "number" && Number.isSafeInteger(value) ? BigInt(value) : value;
  if (typeof counter !== "bigint" || counter < 0n || counter > U64_MAX) {
    throw new RingKeyError("KEYPAIR_INVALID_LENGTH", { name, minimum: "0", maximum: "2^64-1" });
  }
  return counter;
}

/** `u32be(value)` right-aligned in one field element. */
export function u32Field(value: number, name: string): Bytes32 {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RingKeyError("KEYPAIR_INVALID_LENGTH", { name, minimum: 0, maximum: 0xffff_ffff });
  }
  return fieldU32(value);
}
