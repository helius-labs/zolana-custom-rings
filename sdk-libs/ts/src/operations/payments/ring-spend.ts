/** A spend of co-owner and zero key notes the core transfer builder refuses. */
import type { Address } from "@solana/kit";

import type { ProofAuthority } from "@heliuslabs/spr/client";
import {
  bigIntBytes,
  bytesToBigInt,
  equalBytes,
  poseidon,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import type { Bytes31, Bytes32 } from "@heliuslabs/spr/interface";
import {
  NullifierKey,
  type ShieldedAddress,
  type ShieldedPublicKey,
} from "@heliuslabs/spr/keypair";
import {
  ConfidentialTransfer,
  ProofInputUtxo,
  Utxo,
  type SppProofInputs,
} from "@heliuslabs/spr/transaction";

import { RingError } from "../../protocol/error.js";

/** A public co-owner of later inputs, it signs the transaction and one prover holds its secret. */
export interface CoOwner {
  readonly owner: Address;
  readonly nullifierKey: NullifierKey;
}

/** Input 0 seeds every output blinding, the rail refuses a frame whose hidden owner does not lead it. */
export function ringSpendTransfer(
  input: Readonly<{
    owner: ShieldedAddress;
    inputs: readonly ProofInputUtxo[];
    feePayer: Address;
    /** Leaves a suffix of unused slots out of the frame. */
    compact?: boolean;
  }>,
): ConfidentialTransfer {
  const { owner, inputs, feePayer } = input;
  // The core builder counts each stand-in's value and carries its nullifier, the frame spends `inputs`.
  const counted = inputs.map((spent) => standIn(spent, owner));
  const transfer =
    input.compact === true
      ? ConfidentialTransfer.compact(owner, counted, feePayer)
      : new ConfidentialTransfer(owner, counted, feePayer);
  const prepare = transfer.prepare.bind(transfer);
  transfer.prepare = () => Object.freeze({ ...prepare(), inputs: Object.freeze([...inputs]) });
  return transfer;
}

/** Fills the secret of each co-owner and zero key input, a spend of the sender's own notes keeps `keys`. */
export function ringSpendAuthority(
  input: Readonly<{
    keys: ProofAuthority;
    coOwners: readonly CoOwner[];
    proofInputs: SppProofInputs;
    sender: ShieldedAddress;
  }>,
): ProofAuthority {
  const { keys, coOwners, proofInputs, sender } = input;
  if (proofInputs.inputUtxos.every((spent) => spent.isDummy() || isOwn(spent, sender))) return keys;
  const held = [ZERO_NULLIFIER_KEY, ...coOwners.map((coOwner) => coOwner.nullifierKey)];
  const authority: ProofAuthority = {
    prove: (inputs, context) =>
      keys.prove(
        {
          ...inputs,
          payload: {
            ...inputs.payload,
            inputs: inputs.payload.inputs.map((slot) => completed(slot, held)),
          },
        } as typeof inputs,
        context,
      ),
    proveMerge: (inputs, context) => keys.proveMerge(inputs, context),
  };
  return Object.freeze(authority);
}

/** Every input outside the sender's signing key needs its owner's secret before any proof. */
export function checkCoOwnerKeys(
  proofInputs: SppProofInputs,
  sender: ShieldedAddress,
  coOwners: readonly CoOwner[],
): void {
  const index = proofInputs.inputUtxos.findIndex(
    (spent) =>
      !spent.isDummy() &&
      !spent.utxo.owner.equals(sender.signingPublicKey) &&
      !equalBytes(spent.nullifierPublicKey, ZERO_NULLIFIER_PK) &&
      !coOwners.some((coOwner) =>
        equalBytes(coOwner.nullifierKey.publicKey(), spent.nullifierPublicKey),
      ),
  );
  if (index >= 0) throw new RingError("RING_MISSING_CO_OWNER_KEY", { details: { index } });
}

/** Only a spend that named its wallet takes a zero-key note of that wallet, Rust `check_zero_key_inputs`. */
export function checkZeroKeyInputs(
  inputs: readonly ProofInputUtxo[],
  owner: ShieldedPublicKey,
): void {
  const index = inputs.findIndex(
    (spent) =>
      !spent.isDummy() &&
      equalBytes(spent.nullifierPublicKey, ZERO_NULLIFIER_PK) &&
      spent.utxo.owner.equals(owner),
  );
  if (index >= 0) throw new RingError("RING_ZERO_KEY_INPUT_UNNAMED", { details: { index } });
}

type TransferSlot = Parameters<ProofAuthority["prove"]>[0]["payload"]["inputs"][number];

const ZERO_NULLIFIER_KEY = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);

/** Leaves a slot the listed keys do not open as it came. */
function completed<T extends TransferSlot>(slot: T, held: readonly NullifierKey[]): T {
  if (slot.nullifierSecret !== undefined || slot.isDummy !== 0n) return slot;
  const key = held.find(
    (candidate) =>
      slot.circuit.owner ===
      bytesToBigInt(
        poseidon([bigIntBytes(slot.ownerPublicKeyHash) as Bytes32, candidate.publicKey()]),
      ),
  );
  if (key === undefined) return slot;
  const secret = key.secretBytes();
  try {
    return Object.freeze({ ...slot, nullifierSecret: bytesToBigInt(secret) });
  } finally {
    secret.fill(0);
  }
}

function isOwn(input: ProofInputUtxo, owner: ShieldedAddress): boolean {
  return (
    input.utxo.owner.equals(owner.signingPublicKey) &&
    equalBytes(input.nullifierPublicKey, owner.nullifierPublicKey)
  );
}

/** The core builders and intent check hold every input to one owner, the value stays the note's. */
export function standIn(input: ProofInputUtxo, owner: ShieldedAddress): ProofInputUtxo {
  if (isOwn(input, owner)) return input;
  const { utxo } = input;
  return new ProofInputUtxo({
    utxo: new Utxo({
      owner: owner.signingPublicKey,
      asset: utxo.asset,
      amount: utxo.amount,
      blinding: utxo.blinding,
      data: utxo.data,
      ...(utxo.ringProgramId === undefined ? {} : { ringProgramId: utxo.ringProgramId }),
    }),
    nullifierPublicKey: owner.nullifierPublicKey,
    nullifier: input.nullifier(),
    treeId: input.treeId,
    ...(input.dataHash === undefined ? {} : { dataHash: input.dataHash }),
    ...(input.ringDataHash === undefined ? {} : { ringDataHash: input.ringDataHash }),
  });
}
