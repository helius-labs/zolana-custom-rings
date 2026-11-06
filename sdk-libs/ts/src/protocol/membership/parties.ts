import { addressBytes, ZERO_32 } from "@heliuslabs/spr/internal";
import { solanaOwnerIdentity } from "@heliuslabs/spr/keypair";
import type { Address, Bytes32 } from "@heliuslabs/spr/interface";

import { RingError } from "../error.js";
import { ANONYMOUS_PARTIES } from "../transaction/transact.js";

/**
 * The co-signers in `CoSigners` account order, zero past the last, Rust `AnonymousParties`. The
 * proof holds the hidden owner apart from every cell, a hidden co-signer would approve its own outflow.
 */
export function anonymousPartyIdentities(coSigners: readonly Address[]): readonly Bytes32[] {
  if (coSigners.length > ANONYMOUS_PARTIES)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "anonymousParties", expected: ANONYMOUS_PARTIES, actual: coSigners.length },
    });
  return Object.freeze(
    Array.from({ length: ANONYMOUS_PARTIES }, (_, cell): Bytes32 => {
      const coSigner = coSigners[cell];
      return coSigner === undefined
        ? ZERO_32
        : (solanaOwnerIdentity(addressBytes(coSigner)) as Bytes32);
    }),
  );
}
