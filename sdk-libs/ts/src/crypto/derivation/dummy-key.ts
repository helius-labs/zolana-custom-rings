/**
 * The recipient key a dummy slot seals its zero record to, Rust `zolana_ring_keys::dummy_recipient_key`.
 * A relay holding the transaction viewing secret rederives every dummy key, no wire carries them. The
 * circuit checks no derivation, the auditor reads each key from the stream.
 */
import { X25519Keypair, type Bytes32, type X25519PublicKey } from "@heliuslabs/spr/keypair";

import { u32Field } from "../error.js";
import { packBytesBe } from "./hasher.js";
import { RingDomain, domainHash } from "./ring-domain.js";

/** `clamp(Poseidon(CRDK, pack_be(tx_viewing_sk), i))` as an X25519 secret, the public key of dummy slot `slot`. */
export function dummyRecipientKey(txViewingSecret: Bytes32, slot: number): X25519PublicKey {
  const secret = domainHash(RingDomain.dummyKey, [
    ...packBytesBe(txViewingSecret),
    u32Field(slot, "slot"),
  ]);
  // RFC 7748 clamping of the scalar bytes the multiplication reads.
  secret[0] = (secret[0] ?? 0) & 248;
  secret[31] = ((secret[31] ?? 0) & 127) | 64;
  const keypair = X25519Keypair.fromBytes(secret);
  try {
    return keypair.publicKey();
  } finally {
    keypair.destroy();
    secret.fill(0);
  }
}
