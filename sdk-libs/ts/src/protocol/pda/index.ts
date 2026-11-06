import {
  address,
  getAddressEncoder,
  getProgramDerivedAddress,
  type AccountMeta,
  type Address,
  type ProgramDerivedAddress,
  type ReadonlyUint8Array,
} from "@solana/kit";

import {
  hashBytes,
  meta,
  ringAuthAddress,
  signerAddress,
  type SignerAccount,
} from "@heliuslabs/spr/internal";

export { ringAuthAddress };

const encoder = new TextEncoder();

export const STORAGE_PROGRAM_ID = address("6cGXszer5keoaWm8Co5G9f4KGBThuGz4NsKTqYij1emg");

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

/** Seeds match Rust `InitializeStorage::records`. */
export function ringRecordsAddress(
  ringProgramId: Address,
  storageAuthority: Address,
): Promise<Address> {
  const addresses = getAddressEncoder();
  return ringAddress(
    getProgramDerivedAddress({
      programAddress: STORAGE_PROGRAM_ID,
      seeds: [
        encoder.encode("storage"),
        addresses.encode(storageAuthority),
        addresses.encode(ringProgramId),
      ],
    }),
  );
}

/** The ring's tracking registry, created through CPI with its ring auth PDA as creator. */
export async function trackingRegistryPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  const ringAuth = await ringAuthAddress(ringProgramId);
  const addresses = getAddressEncoder();
  return getProgramDerivedAddress({
    programAddress: STORAGE_PROGRAM_ID,
    seeds: [
      encoder.encode("tracking_registry"),
      addresses.encode(ringAuth),
      hashBytes(new Uint8Array(addresses.encode(ringProgramId))),
    ],
  });
}

/** One enrollment per owner per tracking registry. */
export function trackingAuthorizationPda(
  registry: Address,
  owner: Address,
): Promise<ProgramDerivedAddress> {
  const addresses = getAddressEncoder();
  return getProgramDerivedAddress({
    programAddress: STORAGE_PROGRAM_ID,
    seeds: [encoder.encode("tracking"), addresses.encode(registry), addresses.encode(owner)],
  });
}

/** One account per owner per reader, the key splits because a seed holds 32 bytes. */
export function ownerGrantPda(
  registry: Address,
  owner: Address,
  reader: Uint8Array,
): Promise<ProgramDerivedAddress> {
  const addresses = getAddressEncoder();
  return getProgramDerivedAddress({
    programAddress: STORAGE_PROGRAM_ID,
    seeds: [
      encoder.encode("owner_grant"),
      addresses.encode(registry),
      addresses.encode(owner),
      reader.subarray(0, 2),
      reader.subarray(2),
    ],
  });
}
