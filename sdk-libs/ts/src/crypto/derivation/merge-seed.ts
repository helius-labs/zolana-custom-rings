/**
 * Go `spp_merge/shared/seeded.go`, keyed on `ViewingKey.mergeSeed` because a zero nullifier secret
 * lets any reader recompute the merged output.
 */
import type { Bytes32 } from "@heliuslabs/spr";
import {
  checkedBytes,
  DOMAIN_MERGE_DUMMY_NULLIFIER,
  DOMAIN_MERGE_OUTPUT_BLINDING_V1,
  DOMAIN_MERGE_OUTPUT_KEY,
  fieldU32,
  poseidon,
} from "@heliuslabs/spr/internal";
import { privateTxBlinding } from "@heliuslabs/spr/keypair";

export function seededMergeOutputBlinding(seed: Bytes32, firstNullifier: Bytes32): Bytes32 {
  return seededHash(DOMAIN_MERGE_OUTPUT_BLINDING_V1, seed, firstNullifier);
}

export function seededMergeOutputKey(seed: Bytes32, firstNullifier: Bytes32): Bytes32 {
  return seededHash(DOMAIN_MERGE_OUTPUT_KEY, seed, firstNullifier);
}

/** The seed takes the nullifier secret's place in `TXPB`. */
export function seededMergePrivateTxBlinding(seed: Bytes32, firstNullifier: Bytes32): Bytes32 {
  return privateTxBlinding(
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(seed, 32, "merge seed"),
  );
}

export function seededMergeDummyNullifier(
  seed: Bytes32,
  firstNullifier: Bytes32,
  slotIndex: number,
): Bytes32 {
  if (!Number.isInteger(slotIndex) || slotIndex < 0 || slotIndex > 0xff)
    throw new RangeError("merge dummy slot index must fit in u8");
  return poseidon([
    fieldU32(DOMAIN_MERGE_DUMMY_NULLIFIER),
    checkedBytes<Bytes32>(seed, 32, "merge seed"),
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
    fieldU32(slotIndex),
  ]) as Bytes32;
}

function seededHash(domain: number, seed: Bytes32, firstNullifier: Bytes32): Bytes32 {
  return poseidon([
    fieldU32(domain),
    checkedBytes<Bytes32>(seed, 32, "merge seed"),
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
  ]) as Bytes32;
}
