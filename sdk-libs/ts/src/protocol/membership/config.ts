import { getProgramDerivedAddress, type Address, type ProgramDerivedAddress } from "@solana/kit";

import type { ChainReader } from "@heliuslabs/zolana/client";
import { decodeRingConfig, SHIELDED_POOL_PROGRAM_ID } from "@heliuslabs/zolana/interface";
import { addressBytes } from "@heliuslabs/zolana/internal";
import type { RequestContext } from "@heliuslabs/zolana/interface";
import { ringAuthAddress, ringCoSignerPda, ringConfigPda, ringPolicyPda } from "../pda/index.js";

import {
  decodeRingCoSigner,
  decodeRingPolicy,
  decodeRingProgramConfig,
  type RingCoSigner,
  type RingPolicy,
  type RingProgramConfig,
} from "../codec/ring-codecs.js";
import { RingError, type RingErrorCode } from "../error.js";

export const BPF_LOADER_UPGRADEABLE_ID = "BPFLoaderUpgradeab1e11111111111111111111111" as Address;

type AccountReader = Pick<ChainReader, "getAccount">;

/** Mirrors Rust `CustomRing::program_data_pda`. */
export async function ringProgramDataAddress(ringProgramId: Address): Promise<Address> {
  const [address] = await getProgramDerivedAddress({
    programAddress: BPF_LOADER_UPGRADEABLE_ID,
    seeds: [addressBytes(ringProgramId, "ringProgramId")],
  });
  return address;
}

/** Mirrors Rust `CustomRing::require_config`. */
export function fetchRingProgramConfig(
  client: AccountReader,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingProgramConfig> {
  return readRingAccount(client, ringProgramId, context, {
    pda: ringConfigPda,
    decode: decodeRingProgramConfig,
    missing: "RING_CONFIG_NOT_FOUND",
    invalid: "RING_CONFIG_INVALID",
  });
}

export function fetchRingPolicy(
  client: AccountReader,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingPolicy> {
  return readRingAccount(client, ringProgramId, context, {
    pda: ringPolicyPda,
    decode: decodeRingPolicy,
    missing: "RING_POLICY_MISSING",
    invalid: "RING_POLICY_INVALID",
  });
}

/** Mirrors Rust `CustomRing::co_signer`, `undefined` when `signer` holds no record. */
export async function fetchRingCoSignerRecord(
  client: AccountReader,
  ringProgramId: Address,
  signer: Address,
  context?: RequestContext,
): Promise<RingCoSigner | undefined> {
  const [address, bump] = await ringCoSignerPda(ringProgramId, signer);
  const stored = await client.getAccount(address, context);
  if (stored === undefined) return undefined;
  const record = stored.owner === ringProgramId ? decodeRingCoSigner(stored.data) : undefined;
  if (record?.bump !== bump || record.signer !== signer)
    throw new RingError("RING_CO_SIGNER_INVALID", { details: { ringProgramId, address } });
  return record;
}

/** Rust `CustomRing::require_active`, every SPP call through the ring refuses one unregistered, inactive or paused. */
export async function requireActiveRing(
  client: AccountReader,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<void> {
  const address = await ringAuthAddress(ringProgramId);
  const account = await client.getAccount(address, context);
  if (account === undefined)
    throw new RingError("RING_NOT_REGISTERED", { details: { ringProgramId } });
  if (account.owner !== SHIELDED_POOL_PROGRAM_ID)
    throw new RingError("RING_CONFIG_INVALID", { details: { ringProgramId, address } });
  let registration;
  try {
    registration = decodeRingConfig(account.data);
  } catch (cause) {
    throw new RingError("RING_CONFIG_INVALID", { details: { ringProgramId, address }, cause });
  }
  if (registration.programId !== ringProgramId)
    throw new RingError("RING_CONFIG_INVALID", { details: { ringProgramId, address } });
  if (!registration.activated)
    throw new RingError("RING_NOT_ACTIVATED", { details: { ringProgramId } });
  if (registration.paused) throw new RingError("RING_PAUSED", { details: { ringProgramId } });
}

/** Mirrors Rust `CustomRing::read`, a foreign owner or a non-canonical bump is invalid. */
async function readRingAccount<A extends Readonly<{ bump: number }>>(
  client: AccountReader,
  ringProgramId: Address,
  context: RequestContext | undefined,
  account: Readonly<{
    pda: (ringProgramId: Address) => Promise<ProgramDerivedAddress>;
    decode: (data: Uint8Array) => A;
    missing: RingErrorCode;
    invalid: RingErrorCode;
  }>,
): Promise<A> {
  const [address, bump] = await account.pda(ringProgramId);
  const stored = await client.getAccount(address, context);
  if (stored === undefined)
    throw new RingError(account.missing, {
      details: { ringProgramId, address },
    });
  if (stored.owner !== ringProgramId)
    throw new RingError(account.invalid, {
      details: { ringProgramId, owner: stored.owner },
    });
  const decoded = account.decode(stored.data);
  if (decoded.bump !== bump)
    throw new RingError(account.invalid, {
      details: { ringProgramId, address },
    });
  return decoded;
}
