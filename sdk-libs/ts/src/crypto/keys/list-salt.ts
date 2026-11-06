/** Rust `zolana_ring_keys::ListSaltHolder`. */
import { poseidon } from "@heliuslabs/spr/internal";
import type { Bytes32, ViewingKey } from "@heliuslabs/spr/keypair";
import { getAddressEncoder, type Address } from "@solana/kit";

import { domainField, RingDomain } from "../derivation/ring-domain.js";

/** Above the field modulus, so no merge of a real nullifier derives a salt. */
export const LIST_SALT_LABEL = (() => {
  const label = new Uint8Array(32);
  label.set(new TextEncoder().encode("CRING/list_salt"));
  return label as Bytes32;
})();

/** `key` is the identity viewing key, no root the auditor holds reaches another ring's salt. */
export function listSaltOf(key: ViewingKey, ringProgramId: Address): Bytes32 {
  return key.mergeSeed(
    new Uint8Array(getAddressEncoder().encode(ringProgramId)) as Bytes32,
    LIST_SALT_LABEL,
  );
}

/** `Poseidon(CRPT, list_salt)`, final in the tracking leaf. */
export function listTagOf(listSalt: Bytes32): Bytes32 {
  return poseidon([domainField(RingDomain.listTag), listSalt]) as Bytes32;
}
