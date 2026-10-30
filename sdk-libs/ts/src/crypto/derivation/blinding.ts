/** The ring side of SPP's output blinding, Rust `custom_ring_interface::blinding`. */
import type { Address, Bytes16, Bytes32 } from "@heliuslabs/zolana";
import {
  checkedBytes,
  equalBytes,
  isCanonicalField,
  rightAlign,
} from "@heliuslabs/zolana/internal";
import type { ShieldedPublicKey } from "@heliuslabs/zolana/keypair";
import {
  Data,
  outputBlindingSeed,
  transactOutputBlinding,
  Utxo,
  type AssetRegistry,
  type ProofOutputUtxo,
  type TreeId,
} from "@heliuslabs/zolana/transaction";

import { openDeliveredBody } from "../../protocol/transaction/output.js";
import { domainHash, RingDomain } from "./ring-domain.js";
import { packedSecret } from "./ring-stream.js";
import { withOutputFields } from "../../protocol/proof/proof-output.js";

/** SPP's `blinding_seed`, the seed of every ring output's TXOB blinding. */
export function ringBlindingSeed(txViewingSecret: Bytes32, salt: Bytes16): Bytes32 {
  return domainHash(RingDomain.blindingSeed, [
    ...packedSecret(txViewingSecret, "transaction viewing secret"),
    rightAlign(checkedBytes<Bytes16>(salt, 16, "salt")),
  ]);
}

/** `TXOB(first_nullifier, TXOS(first_nullifier, blinding_seed), position)` per output, Rust `OutputBlindings`. */
export class OutputBlindings {
  readonly #firstNullifier: Bytes32;
  readonly #outputSeed: Bytes32;

  /** `blindingSeed` is the rail's `CRBS(tx_viewing_sk, salt)`. */
  constructor(firstNullifier: Bytes32, blindingSeed: Bytes32) {
    this.#firstNullifier = checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier");
    this.#outputSeed = outputBlindingSeed(
      this.#firstNullifier,
      checkedBytes<Bytes32>(blindingSeed, 32, "blinding seed"),
    );
  }

  at(position: number): Bytes32 {
    return transactOutputBlinding(this.#firstNullifier, this.#outputSeed, position);
  }

  /** A copy of the seed the sender bundle publishes, every change blinding derives from it. */
  outputSeed(): Bytes32 {
    return this.#outputSeed.slice() as Bytes32;
  }

  destroy(): void {
    this.#outputSeed.fill(0);
  }
}

/** SPP's TXOB blinding of slot `outputIndex` under the ring blinding seed. */
export function ringOutputBlinding(
  input: Readonly<{ firstNullifier: Bytes32; blindingSeed: Bytes32; outputIndex: number }>,
): Bytes32 {
  const blindings = new OutputBlindings(input.firstNullifier, input.blindingSeed);
  try {
    return blindings.at(input.outputIndex);
  } finally {
    blindings.destroy();
  }
}

/** Every output's blinding rederived at its slot. */
export function ringBlindedOutputs(
  input: Readonly<{
    outputs: readonly ProofOutputUtxo[];
    firstNullifier: Bytes32;
    blindingSeed: Bytes32;
  }>,
): readonly ProofOutputUtxo[] {
  const blindings = new OutputBlindings(input.firstNullifier, input.blindingSeed);
  try {
    return Object.freeze(
      input.outputs.map((output, index) =>
        withOutputFields(output, { blinding: blindings.at(index) }),
      ),
    );
  } finally {
    blindings.destroy();
  }
}

/** Where a delivered ring output sits, Rust `RingDeliverySlot`. */
export interface RingDeliverySlot {
  readonly ring: Address;
}

/** The keys of a delivered output's owner. */
export interface RingNoteOwner {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly nullifierPublicKey: Bytes32;
}

/** One published delivered body and the secret its recipient agreed for it. */
export interface RingDeliveryOpening {
  readonly body: Uint8Array;
  readonly slotSecret: Bytes32;
  readonly owner: RingNoteOwner;
  /** The published commitment and the tree it was appended to. */
  readonly commitment: Bytes32;
  readonly treeId: TreeId;
}

/** A delivered output opened to the note its published commitment binds. */
export interface RingDeliveredNote {
  readonly utxo: Utxo;
  readonly utxoHash: Bytes32;
}

/** The body names no mint, `undefined` when no registered asset rebuilds the commitment. */
export function openRingDelivery(
  slot: RingDeliverySlot,
  opening: RingDeliveryOpening,
  assets: AssetRegistry,
): RingDeliveredNote | undefined {
  const body = openDeliveredBody(opening.slotSecret, opening.body);
  // be32 below q is the only blinding a commitment binds.
  if (!isCanonicalField(body.blinding)) return undefined;
  for (const [, asset] of assets.entries()) {
    const utxo = new Utxo({
      owner: opening.owner.signingPublicKey,
      asset,
      amount: body.amount,
      blinding: body.blinding,
      data: new Data(),
      ringProgramId: slot.ring,
    });
    const utxoHash = utxo.hash(opening.owner.nullifierPublicKey, opening.treeId);
    if (equalBytes(utxoHash, opening.commitment)) return Object.freeze({ utxo, utxoHash });
  }
  return undefined;
}
