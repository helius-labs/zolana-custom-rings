import type { ChainReader, RpcAccount } from "@heliuslabs/spr/client";
import type { Address, RequestContext } from "@heliuslabs/spr";

import { decodeRingPolicy, RING_ROLES, type RingAuthorityRole } from "../codec/ring-codecs.js";
import { ringPolicyAddress } from "../pda/index.js";
import { RingError } from "../error.js";
import { readerKeyEquals, type ReaderKey } from "../../operations/management/reader-access.js";

type AccountReader = Pick<ChainReader, "getMultipleAccounts">;

export type RingRole = RingAuthorityRole | "participant only";

/** Every role the key holds, or only `participant only`. One key may hold several roles. */
export async function ringRole(
  input: Readonly<{ rpc: AccountReader; ring: Address; reader: ReaderKey }>,
  context?: RequestContext,
): Promise<readonly RingRole[]> {
  const address = await ringPolicyAddress(input.ring);
  const [account] = await input.rpc.getMultipleAccounts([address], context);
  const data = owned(account, input.ring);
  if (data === undefined) {
    throw new RingError("RING_CONFIG_INVALID", { details: { reason: "ring has no config" } });
  }
  const { roles } = decodeRingPolicy(data);
  const held = RING_ROLES.filter((role) => readerKeyEquals(roles[role], input.reader));
  return held.length === 0 ? ["participant only"] : held;
}

/** An account another program owns says nothing about this ring. */
function owned(account: RpcAccount | undefined, owner: Address): Uint8Array | undefined {
  return account === undefined || account.owner !== owner ? undefined : account.data;
}
