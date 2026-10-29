import {
  getProgramDerivedAddress,
  type Address,
  type ProgramDerivedAddress,
  type ReadonlyUint8Array,
} from "@solana/kit";

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

export function ringMemberRegistryPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("members"));
}

export function ringMemberRegistryAddress(ringProgramId: Address): Promise<Address> {
  return ringAddress(ringMemberRegistryPda(ringProgramId));
}

export function ringRecordQueuePda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("queue"));
}

export function ringRecordQueueAddress(ringProgramId: Address): Promise<Address> {
  return ringAddress(ringRecordQueuePda(ringProgramId));
}

export function ringPolicyPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("policy"));
}

export function ringPolicyAddress(ringProgramId: Address): Promise<Address> {
  return ringAddress(ringPolicyPda(ringProgramId));
}
