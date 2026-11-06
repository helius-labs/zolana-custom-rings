/** Each public signer's count of data-bearing outputs, Rust `SignerDataCounts`. */
import { equalBytes, isZero } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";

/** `solana_message::v1::MAX_SIGNATURES`, a CPI caller's PDAs can sign past it. */
export const SIGNER_DATA_ENTRIES = 12;
export const SIGNER_DATA_ENTRY_BITS = 5;
const ENTRY_MASK = (1n << BigInt(SIGNER_DATA_ENTRY_BITS)) - 1n;
const USED_BITS = (1n << BigInt(SIGNER_DATA_ENTRIES * SIGNER_DATA_ENTRY_BITS)) - 1n;

/** One live output slot as the count reads it, `ownerIdentity` is `solana_owner_identity`. */
export interface LiveSlot {
  readonly ownerIdentity: Bytes32;
  readonly dataHash: Bytes32;
}

/** The frame carries zero as a clear bit, so a present value is nonzero and fits the entries. */
export function validSignerDataCounts(packed: bigint): boolean {
  return packed > 0n && (packed & ~USED_BITS) === 0n;
}

/**
 * Entry `k` holds bits `5k..5k + 5` for signer `k` of the run `SignerSet` chains. SPP takes one
 * signature for any number of data-bearing slots of its owner, the proved count lets a signer's
 * check notice a slot the sender left out of its terms. A member past the last entry has no bits to
 * publish a count, so it must own no such slot, the element would understate what it authorizes.
 * `undefined` where the circuit has no solution.
 */
export function signerDataCountsOf(
  run: readonly Bytes32[],
  slots: readonly LiveSlot[],
): bigint | undefined {
  let packed = 0n;
  for (const [entry, signer] of run.entries()) {
    const count = BigInt(
      slots.filter((slot) => !isZero(slot.dataHash) && equalBytes(slot.ownerIdentity, signer))
        .length,
    );
    if (count === 0n) continue;
    if (entry >= SIGNER_DATA_ENTRIES || count > ENTRY_MASK) return undefined;
    packed |= count << BigInt(entry * SIGNER_DATA_ENTRY_BITS);
  }
  return packed;
}

/** Zero past the entries. */
export function signerDataCountAt(packed: bigint, entry: number): number {
  return entry < SIGNER_DATA_ENTRIES
    ? Number((packed >> BigInt(entry * SIGNER_DATA_ENTRY_BITS)) & ENTRY_MASK)
    : 0;
}
