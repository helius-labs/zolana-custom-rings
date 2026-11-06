import { isZero, poseidon } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";

import { domainField, RingDomain } from "../../crypto/derivation/ring-domain.js";
import { RingError } from "../error.js";

/**
 * `Poseidon(CRPL, owner_pk_hash, 0)`, the key of an owner's public lists, Rust `Member::public`.
 * Registration refuses a zero salt, so no private record shares it.
 */
export function publicListKey(ownerPkHash: Bytes32): Bytes32 {
  return lookupKey(ownerPkHash, ZERO_SALT);
}

/** `Poseidon(CRPL, owner_pk_hash, list_salt)`, the key of a private entry, Rust `Member::salted`. */
export function privateListKey(ownerPkHash: Bytes32, listSalt: Bytes32): Bytes32 {
  if (isZero(listSalt))
    throw new RingError("RING_ENTRY_INVALID", { details: { reason: "zeroSalt" } });
  return lookupKey(ownerPkHash, listSalt);
}

const ZERO_SALT = new Uint8Array(32) as Bytes32;

function lookupKey(ownerPkHash: Bytes32, listSalt: Bytes32): Bytes32 {
  return poseidon([domainField(RingDomain.listPosition), ownerPkHash, listSalt]) as Bytes32;
}
