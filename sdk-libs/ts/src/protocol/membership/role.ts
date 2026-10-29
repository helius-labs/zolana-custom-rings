import type { ChainReader, RpcAccount } from "@heliuslabs/zolana/client";
import type { Address, RequestContext } from "@heliuslabs/zolana";

import { decodeRingProgramConfig } from "../codec/ring-codecs.js";
import { ringConfigAddress } from "../pda/index.js";
import { RingError } from "../error.js";
import { readerKeyEquals, type ReaderKey } from "../../operations/management/reader-access.js";

type AccountReader = Pick<ChainReader, "getMultipleAccounts">;

export type RingRole = "authority" | "participant only";

/** What a ring's config says about one key. */
export async function ringRole(
  input: Readonly<{ rpc: AccountReader; ring: Address; reader: ReaderKey }>,
  context?: RequestContext,
): Promise<RingRole> {
  const config = await ringConfigAddress(input.ring);
  const [configAccount] = await input.rpc.getMultipleAccounts([config], context);
  const configData = owned(configAccount, input.ring);
  if (configData === undefined) {
    throw new RingError("RING_CONFIG_INVALID", { details: { reason: "ring has no config" } });
  }
  return readerKeyEquals(decodeRingProgramConfig(configData).authority, input.reader)
    ? "authority"
    : "participant only";
}

/** An account another program owns says nothing about this ring. */
function owned(account: RpcAccount | undefined, owner: Address): Uint8Array | undefined {
  return account === undefined || account.owner !== owner ? undefined : account.data;
}
