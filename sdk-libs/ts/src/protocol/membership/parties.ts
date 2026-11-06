import { addressBytes, ZERO_32 } from "@heliuslabs/spr/internal";
import { solanaOwnerIdentity } from "@heliuslabs/spr/keypair";
import type { Address, Bytes32 } from "@heliuslabs/spr/interface";

import { RingError } from "../error.js";
import { ANONYMOUS_PARTIES, MAX_CO_SIGNERS } from "../transaction/transact.js";

/** Ordered exactly as the verifier's `AnonymousParties`, zero for an absent party. */
export function anonymousPartyIdentities(
  input: Readonly<{
    payer: Address;
    coSigners: readonly Address[];
    /** In leg order, a key another party already names takes no cell. */
    funders?: readonly Address[];
    exitDestination?: Address;
  }>,
): readonly Bytes32[] {
  const identity = (party: Address): Bytes32 => solanaOwnerIdentity(addressBytes(party)) as Bytes32;
  const funders = (input.funders ?? []).filter(
    (funder, at, all) =>
      funder !== input.payer && !input.coSigners.includes(funder) && all.indexOf(funder) === at,
  );
  // The circuit holds the hidden owner apart from every nonzero cell, a public signature would name
  // it otherwise. A funder signs in public like a co-signer and shares the same cells, the
  // statement's layout stays fixed. Rust `TooManyAnonymousParties` past them.
  const shared = [...input.coSigners, ...funders];
  if (shared.length > MAX_CO_SIGNERS)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "anonymousParties", expected: MAX_CO_SIGNERS, actual: shared.length },
    });
  const identities = Array.from({ length: ANONYMOUS_PARTIES }, (): Bytes32 => ZERO_32);
  identities[0] = identity(input.payer);
  shared.forEach((party, slot) => {
    identities[slot + 1] = identity(party);
  });
  if (input.exitDestination !== undefined)
    identities[ANONYMOUS_PARTIES - 1] = identity(input.exitDestination);
  return Object.freeze(identities);
}
