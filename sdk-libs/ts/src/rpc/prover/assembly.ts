import type { Bytes32 } from "@heliuslabs/spr";
import { bigintToBytes, inputCircuitUtxo, outputCircuitUtxo } from "@heliuslabs/spr/internal";
import { DUMMY_DOMAIN, UTXO_DOMAIN, treeIdField } from "@heliuslabs/spr/interface";
import type { ProofInputUtxo, ProofOutputUtxo, TreeId } from "@heliuslabs/spr/transaction";

import type { RingSlotOpening } from "./ring.js";

/** Rust `Opening::input`, a dummy opens its domain, tree and blinding only. */
export function ringInputOpening(input: ProofInputUtxo): RingSlotOpening {
  if (input.isDummy())
    return Object.freeze({
      ...zeroOpening(DUMMY_DOMAIN),
      treeId: treeIdField(input.treeId),
      blinding: input.utxo.blinding,
    });
  const utxo = inputCircuitUtxo(input);
  const real = !input.isAddress();
  return Object.freeze({
    domain: openingField(utxo.domain),
    treeId: treeIdField(input.treeId),
    ownerPkHash: real ? input.utxo.owner.ownerProofInputHash() : openingField(0n),
    nullifierPk: real ? input.nullifierPublicKey : openingField(0n),
    asset: openingField(utxo.asset),
    amount: openingField(utxo.amount),
    blinding: openingField(utxo.blinding),
    dataHash: openingField(utxo.dataHash),
    ringDataHash: openingField(utxo.ringDataHash),
    ringProgramId: openingField(utxo.ringProgramId),
  });
}

/** Rust `Opening::output`, the output hashed into `outputTreeId`. */
export function ringOutputOpening(output: ProofOutputUtxo, outputTreeId: TreeId): RingSlotOpening {
  const treeId = treeIdField(outputTreeId);
  const owner = output.ownerAddress;
  if (owner === undefined) {
    return Object.freeze({
      ...zeroOpening(DUMMY_DOMAIN),
      treeId,
      blinding: output.blinding,
    });
  }
  const utxo = outputCircuitUtxo(output);
  return Object.freeze({
    domain: openingField(BigInt(UTXO_DOMAIN)),
    treeId,
    ownerPkHash: owner.signingPublicKey.ownerProofInputHash(),
    nullifierPk: owner.nullifierPublicKey,
    asset: openingField(utxo.asset),
    amount: openingField(utxo.amount),
    blinding: openingField(utxo.blinding),
    dataHash: openingField(utxo.dataHash),
    ringDataHash: openingField(utxo.ringDataHash),
    ringProgramId: openingField(utxo.ringProgramId),
  });
}

/** An input slot past the published count, the circuit admits a dummy domain alone. */
export const RING_INPUT_PADDING: RingSlotOpening = zeroOpening(DUMMY_DOMAIN);

/** Rust `Opening::default`, the slot past a key's used capacity. */
export const EMPTY_RING_OPENING: RingSlotOpening = zeroOpening(0);

function zeroOpening(domain: number): RingSlotOpening {
  return Object.freeze({
    domain: openingField(BigInt(domain)),
    treeId: openingField(0n),
    ownerPkHash: openingField(0n),
    nullifierPk: openingField(0n),
    asset: openingField(0n),
    amount: openingField(0n),
    blinding: openingField(0n),
    dataHash: openingField(0n),
    ringDataHash: openingField(0n),
    ringProgramId: openingField(0n),
  });
}

function openingField(value: bigint): Bytes32 {
  return bigintToBytes(value, "opening") as Bytes32;
}
