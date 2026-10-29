import {
  getAddressEncoder,
  getProgramDerivedAddress,
  type AccountMeta,
  type Address,
  type ProgramDerivedAddress,
  type ReadonlyUint8Array,
} from "@solana/kit";

import { meta, signerAddress, type SignerAccount } from "@heliuslabs/zolana/internal";

export { ringAuthAddress } from "@heliuslabs/zolana/internal";

const encoder = new TextEncoder();

function ringPda(
  ringProgramId: Address,
  ...seeds: readonly ReadonlyUint8Array[]
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: ringProgramId,
    seeds: [...seeds],
  });
}

async function ringAddress(pda: Promise<ProgramDerivedAddress>): Promise<Address> {
  return (await pda)[0];
}

export function ringConfigPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("config"));
}

export function ringConfigAddress(ringProgramId: Address): Promise<Address> {
  return ringAddress(ringConfigPda(ringProgramId));
}

export function ringCoSignerPda(
  ringProgramId: Address,
  signer: Address,
): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("co_signer"), getAddressEncoder().encode(signer));
}

export function ringCoSignerAddress(ringProgramId: Address, signer: Address): Promise<Address> {
  return ringAddress(ringCoSignerPda(ringProgramId, signer));
}

/** The program reads the record first, the signer next. */
export async function ringCoSignerMetas(
  ringProgramId: Address,
  signer: SignerAccount,
): Promise<readonly [AccountMeta, AccountMeta]> {
  const record = await ringCoSignerAddress(ringProgramId, signerAddress(signer));
  return [meta(record, false, false), meta(signer, true, false)];
}

export function ringPolicyPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("policy"));
}

export function ringPolicyAddress(ringProgramId: Address): Promise<Address> {
  return ringAddress(ringPolicyPda(ringProgramId));
}
