/** Rust `RelayEnrollInputs` in wincode. */
import {
  addressBytes,
  concatBytes,
  instruction,
  meta,
  sha256,
  SYSTEM_PROGRAM,
  Writer,
  type SignerAccount,
} from "@heliuslabs/spr/internal";
import type { Address, Bytes32 } from "@heliuslabs/spr/interface";
import type { AccountMeta, Instruction } from "@solana/kit";

import { STORAGE_PROGRAM_ID, trackingAuthorizationPda } from "../pda/index.js";

export interface RelayEnrollInputs {
  readonly ringProgramId: Address;
  readonly owner: Address;
  readonly trackingRegistry: Address;
  /** Tag 6 first, the program holds every field to the owner's signature and proof. */
  readonly instructionData: Uint8Array;
}

/** The ceiling a relayed enrollment asks and its owner checks. */
export const ENROLL_COMPUTE_UNITS = 400_000;

const ENROLL_REQUEST_DOMAIN = new TextEncoder().encode("zolana/ring-rpc-relay-enroll");

export function encodeRelayEnrollInputs(value: RelayEnrollInputs): Uint8Array {
  return new Writer()
    .bytes(addressBytes(value.ringProgramId), 32, "ringProgramId")
    .bytes(addressBytes(value.owner), 32, "owner")
    .bytes(addressBytes(value.trackingRegistry), 32, "trackingRegistry")
    .u64(BigInt(value.instructionData.length), "instructionData.length")
    .bytes(value.instructionData, undefined, "instructionData")
    .finish();
}

/** The owner's signature over it spends the relay's budget, it names no quote so a retry keeps it. */
export function enrollRequestDigest(value: RelayEnrollInputs): Bytes32 {
  return sha256(
    concatBytes(
      ENROLL_REQUEST_DOMAIN,
      addressBytes(value.ringProgramId),
      addressBytes(value.owner),
      addressBytes(value.trackingRegistry),
      value.instructionData,
    ),
  ) as Bytes32;
}

export async function enrollAccounts(
  input: Readonly<{ payer: SignerAccount; owner: SignerAccount; trackingRegistry: Address }>,
  owner: Address,
): Promise<readonly AccountMeta[]> {
  const [authorization] = await trackingAuthorizationPda(input.trackingRegistry, owner);
  return [
    meta(input.payer, true, true),
    meta(input.owner, true, false),
    meta(input.trackingRegistry, false, true),
    meta(authorization, false, true),
    meta(SYSTEM_PROGRAM, false, false),
  ];
}

export async function relayEnrollInstruction(
  value: RelayEnrollInputs,
  feePayer: Address,
): Promise<Instruction> {
  return instruction(
    value.instructionData,
    await enrollAccounts(
      { payer: feePayer, owner: value.owner, trackingRegistry: value.trackingRegistry },
      value.owner,
    ),
    STORAGE_PROGRAM_ID,
  );
}
