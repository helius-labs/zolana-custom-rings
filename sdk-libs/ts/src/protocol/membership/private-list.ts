import { poseidon } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";

import { domainField, RingDomain } from "../../crypto/derivation/ring-domain.js";

/** `Poseidon(CRPL, owner_pk_hash, list_salt)`, the member key of a private entry. */
export function privateListKey(ownerPkHash: Bytes32, listSalt: Bytes32): Bytes32 {
  return poseidon([domainField(RingDomain.listPosition), ownerPkHash, listSalt]) as Bytes32;
}
