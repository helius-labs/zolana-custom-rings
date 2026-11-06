/** The ring side of SPP's output blinding, Rust `custom_ring_interface::blinding`. */
import type { Address, Bytes16, Bytes32 } from "@heliuslabs/spr";
import {
  addressBytes,
  checkedBytes,
  equalBytes,
  hashBytes,
  isCanonicalField,
  isZero,
  rightAlign,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import type { ShieldedPublicKey } from "@heliuslabs/spr/keypair";
import {
  Data,
  outputBlindingSeed,
  transactOutputBlinding,
  Utxo,
  type AssetRegistry,
  type ProofOutputUtxo,
  type TreeId,
} from "@heliuslabs/spr/transaction";

import type { RecipientBody } from "../../protocol/codec/anonymous-delivery.js";
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

/** Where a published ring output sits and who reads it, Rust `AnonymousOutput`. */
export interface RingOutputReader {
  readonly owner: RingNoteOwner;
  readonly ring: Address;
  readonly treeId: TreeId;
  readonly commitment: Bytes32;
  readonly assets: AssetRegistry;
}

/** The keys of a ring output's owner. */
export interface RingNoteOwner {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly nullifierPublicKey: Bytes32;
}

/** A body whose rebuilt commitment names the reader, a match establishes ownership, Rust `OpenedNote`. */
export interface OpenedRingNote {
  readonly utxo: Utxo;
  readonly utxoHash: Bytes32;
  /** The reader's key or zero, whichever rebuilt. */
  readonly nullifierPublicKey: Bytes32;
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
  /** Clear under a mint the registry does not name, the note stays spendable once it does. */
  readonly registered: boolean;
}

/** Tries the reader's key then the zero key, `undefined` when neither rebuilds the commitment, Rust `AnonymousOutput::open_body`. */
export function openRecipientNote(
  reader: RingOutputReader,
  body: RecipientBody,
): OpenedRingNote | undefined {
  const { data = new Uint8Array(), ringDataHash } = body;
  // A nonempty data field leads with the hash the commitment reads.
  if (data.length > 0 && data.length < 32) return undefined;
  if (!isCanonicalField(body.blinding)) return undefined;
  const dataHash = data.length === 0 ? undefined : (data.slice(0, 32) as Bytes32);
  // The commitment reads a zero hash as no data, bytes under it bind to nothing and a reader would store them as the note's.
  if (dataHash !== undefined && isZero(dataHash)) return undefined;
  const appData = data.subarray(32);
  const { signingPublicKey, nullifierPublicKey } = reader.owner;
  const utxo = new Utxo({
    owner: signingPublicKey,
    asset: body.mint,
    amount: body.amount,
    blinding: body.blinding,
    data: appData.length === 0 ? new Data() : new Data([{ kind: "utxoData", bytes: appData }]),
    ringProgramId: reader.ring,
  });
  for (const candidate of [nullifierPublicKey, ZERO_NULLIFIER_PK as Bytes32]) {
    const utxoHash = utxo.hash(candidate, reader.treeId, dataHash, ringDataHash);
    if (equalBytes(utxoHash, reader.commitment))
      return Object.freeze({
        utxo,
        utxoHash,
        nullifierPublicKey: candidate,
        ...(dataHash === undefined ? {} : { dataHash }),
        ...(ringDataHash === undefined ? {} : { ringDataHash }),
        registered:
          reader.assets.addressForField(hashBytes(addressBytes(body.mint, "mint")) as Bytes32) !==
          undefined,
      });
  }
  return undefined;
}
