import { bigIntBytes, bytesToBigInt, equalBytes } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { RingError } from "../error.js";

/** Rust `AssetLimits`, co-signer limits no proof bounds an amount by. */
export interface AssetLimits {
  readonly senderCap: bigint;
  readonly senderWindowSlots: bigint;
  readonly volumeCap: bigint;
  readonly volumeWindowSlots: bigint;
  readonly depositCap: bigint;
  readonly withdrawalCap: bigint;
}

/** Per-mint settings stored in the ring's authenticated asset record. */
export interface MintPolicy {
  readonly threshold: bigint;
  readonly cap: bigint;
  readonly cosignAbove: bigint;
  readonly withdrawalThreshold: bigint;
  readonly limits: AssetLimits;
}

/** Rust `AssetLimits` field order. */
export const ASSET_LIMIT_KEYS = Object.freeze([
  "senderCap",
  "senderWindowSlots",
  "volumeCap",
  "volumeWindowSlots",
  "depositCap",
  "withdrawalCap",
] as const satisfies readonly (keyof AssetLimits)[]);

export const EMPTY_ASSET_LIMITS: AssetLimits = Object.freeze({
  senderCap: 0n,
  senderWindowSlots: 0n,
  volumeCap: 0n,
  volumeWindowSlots: 0n,
  depositCap: 0n,
  withdrawalCap: 0n,
});

export const EMPTY_MINT_POLICY: MintPolicy = Object.freeze({
  threshold: 0n,
  cap: 0n,
  cosignAbove: 0n,
  withdrawalThreshold: 0n,
  limits: EMPTY_ASSET_LIMITS,
});

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** Three u64 amounts packed in the same order as Rust `MintPolicy::field`. */
export function mintPolicyField(policy: MintPolicy): Bytes32 {
  if (
    typeof policy.withdrawalThreshold !== "bigint" ||
    policy.withdrawalThreshold < 0n ||
    policy.withdrawalThreshold > 0xffff_ffff_ffff_ffffn
  )
    throw new RingError("RING_MEMBER_REGISTRY_INVALID");
  return packed([policy.threshold, policy.cap, policy.cosignAbove]);
}

/** Bit 192 marks a replacement, including clearing every setting. */
export function mintPolicyWriteField(policy: MintPolicy | undefined): Bytes32 {
  return bigIntBytes(
    policy === undefined ? 0n : (1n << 192n) | bytesToBigInt(mintPolicyField(policy)),
  ) as Bytes32;
}

/** Rust `AssetLimits::fields`, the two leaf fields after the withdrawal threshold. */
export function assetLimitsFields(limits: AssetLimits): readonly [Bytes32, Bytes32] {
  const amounts = ASSET_LIMIT_KEYS.map((key) => limits[key]);
  return [packed(amounts.slice(0, 3)), packed(amounts.slice(3))];
}

/** Rust `mint_policy_write`, `1 || MintPolicy::bytes` replaces the settings, all zero keeps them. */
export function mintPolicyWrite(policy: MintPolicy | undefined): Uint8Array {
  const write = new Uint8Array(1 + MINT_POLICY_LEN);
  if (policy === undefined) return write;
  checkAssetLimits(policy.limits);
  write[0] = 1;
  write.set(mintPolicyBytes(policy), 1);
  return write;
}

export function sameMintPolicy(left: MintPolicy, right: MintPolicy): boolean {
  return equalBytes(mintPolicyBytes(left), mintPolicyBytes(right));
}

export function isEmptyMintPolicy(policy: MintPolicy): boolean {
  return sameMintPolicy(policy, EMPTY_MINT_POLICY);
}

/** Rust `AssetLimits::check`, a window cap and its window are both zero or both nonzero. */
export function checkAssetLimits(limits: AssetLimits): AssetLimits {
  assetLimitsFields(limits);
  if (
    (limits.senderCap === 0n) !== (limits.senderWindowSlots === 0n) ||
    (limits.volumeCap === 0n) !== (limits.volumeWindowSlots === 0n)
  )
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", {
      details: { reason: "UnpairedWindow" },
    });
  return limits;
}

/** Rust `MintPolicy::LEN`. */
const MINT_POLICY_LEN = 80;

/** Rust `MintPolicy::bytes`, big endian u64 amounts in field order. */
function mintPolicyBytes(policy: MintPolicy): Uint8Array {
  const bytes = new Uint8Array(MINT_POLICY_LEN);
  bytes.set(mintPolicyField(policy).subarray(8));
  bytes.set(bigIntBytes(policy.withdrawalThreshold, 8), 24);
  assetLimitsFields(policy.limits).forEach((field, index) =>
    bytes.set(field.subarray(8), 32 + 24 * index),
  );
  return bytes;
}

function packed(amounts: readonly bigint[]): Bytes32 {
  let field = 0n;
  for (const amount of amounts) {
    if (typeof amount !== "bigint" || amount < 0n || amount > U64_MAX)
      throw new RingError("RING_MEMBER_REGISTRY_INVALID", {
        details: { reason: "MintPolicyRange" },
      });
    field = (field << 64n) | amount;
  }
  return bigIntBytes(field) as Bytes32;
}
