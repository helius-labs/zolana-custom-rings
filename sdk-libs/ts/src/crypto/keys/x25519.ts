import { x25519 } from "@noble/curves/ed25519.js";

import type { Bytes32 } from "@heliuslabs/spr";
import { X25519PublicKey } from "@heliuslabs/spr/keypair";

/** The tagged key of a bare u coordinate, the inverse of `X25519PublicKey.u`. */
export function x25519FromU(u: Bytes32): X25519PublicKey {
  return X25519PublicKey.fromBytes(
    new Uint8Array([4, ...u]) as Parameters<typeof X25519PublicKey.fromBytes>[0],
  );
}

const SMALL_ORDER_PROBE = new Uint8Array(32).fill(1);

/** X25519 maps a small-order key to zero under every clamped scalar. */
export function isSmallOrder(key: X25519PublicKey): boolean {
  try {
    x25519.getSharedSecret(SMALL_ORDER_PROBE, key.u()).fill(0);
    return false;
  } catch {
    return true;
  }
}
