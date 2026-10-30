import { getBase58Decoder, type Address, type Signature } from "@solana/kit";
import {
  EncryptedScheme,
  Writer,
  addressBytes,
  encodeOutputData,
  encodeRingDepositInstructionData,
} from "@heliuslabs/zolana/internal";
import { InstructionTag } from "@heliuslabs/zolana/interface";
import { SHIELDED_POOL_PROGRAM_ID, type Bytes16, type Bytes32 } from "@heliuslabs/zolana";
import { AUDITED_DEPOSIT_PREFIX_LENGTH } from "../../src/protocol/transaction/deposit-instruction.js";
import {
  encodeRingDepositCapsule,
  type RingDepositCapsule,
} from "../../src/protocol/codec/deposit-capsule.js";

/** Borsh `RingDepositOutput`, the capsule as its ciphertext. */
export function ringDepositPayload(
  input: Readonly<{
    ring: Address;
    ownerCommitment: Bytes32;
    asset: Address;
    amount: bigint;
    capsule: RingDepositCapsule;
  }>,
): Uint8Array {
  const ciphertext = encodeRingDepositCapsule(input.capsule);
  const body = new Writer()
    .bytes(input.ownerCommitment)
    .bytes(addressBytes(input.asset))
    .u64(input.amount, "amount")
    .u8(0, "dataHash")
    .bytes(addressBytes(input.ring))
    .bytes(new Uint8Array(32))
    .bytes(input.capsule.ephemeralPublicKey)
    .bytes(new Uint8Array(16))
    .u32(ciphertext.length, "ciphertext.length")
    .bytes(ciphertext)
    .finish();
  return encodeOutputData(EncryptedScheme.ringDeposit, body, "encrypted");
}

/** A successful confirmed wrapper and its exact SPP self-CPI ancestry. */
export function confirmedDepositTransaction(
  ring: Address,
  signature: Signature,
  capsules: readonly RingDepositCapsule[],
  owners: readonly Bytes32[],
) {
  const wire = Uint8Array.of(
    InstructionTag.ringDeposit,
    ...encodeRingDepositInstructionData({
      assets: [{ kind: "sol" }],
      deposits: capsules.map((capsule, index) => {
        const ownerUtxoHash = owners[index];
        if (ownerUtxoHash === undefined) throw new Error("missing owner commitment");
        return {
          assetIndex: 0,
          viewTag: new Uint8Array(32) as Bytes32,
          ownerUtxoHash,
          amount: 1n,
          ringDataHash: new Uint8Array(32) as Bytes32,
          encrypted: {
            txViewingPublicKey: capsule.ephemeralPublicKey,
            salt: new Uint8Array(16) as Bytes16,
            ciphertext: encodeRingDepositCapsule(capsule),
          },
        };
      }),
    }),
  );
  const encode = getBase58Decoder();
  const wrapper = Uint8Array.of(31, ...new Uint8Array(AUDITED_DEPOSIT_PREFIX_LENGTH - 1), ...wire);
  return {
    transaction: {
      signatures: [signature],
      message: {
        accountKeys: [ring, SHIELDED_POOL_PROGRAM_ID],
        instructions: [{ programIdIndex: 0, accounts: [], data: encode.decode(wrapper) }],
      },
    },
    meta: {
      err: null,
      innerInstructions: [
        {
          index: 0,
          instructions: [
            { programIdIndex: 1, accounts: [], data: encode.decode(wire), stackHeight: 2 },
            {
              programIdIndex: 1,
              accounts: [],
              data: encode.decode(Uint8Array.of(InstructionTag.emitEvent, 0)),
              stackHeight: 3,
            },
          ],
        },
      ],
    },
  };
}
