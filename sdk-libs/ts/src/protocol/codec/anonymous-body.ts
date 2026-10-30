/** The rebuild of a published anonymous output from its plaintext, Rust `anonymous_body`. */
import type { Address, Bytes32 } from "@heliuslabs/zolana";
import { equalBytes } from "@heliuslabs/zolana/internal";
import { X25519PublicKey, type ShieldedAddress } from "@heliuslabs/zolana/keypair";
import { Utxo, type AssetRegistry, type TreeId } from "@heliuslabs/zolana/transaction";

import {
  anonymousRecipientUtxo,
  anonymousSenderUtxos,
  type AnonymousRecipientPlaintext,
  type AnonymousSenderPlaintext,
} from "./anonymous-plaintext.js";

export { RECIPIENT_BODY_LEN } from "./anonymous-plaintext.js";

/** `0x04 ‖ 0^32`, the sender bundle's entry for an output no anonymous recipient reads. */
export const DUMMY_RECIPIENT_VIEWING_PK = X25519PublicKey.fromBytes(
  Uint8Array.of(4, ...new Uint8Array(32)),
);

export interface AnonymousOutput {
  readonly owner: ShieldedAddress;
  readonly assets: AssetRegistry;
  readonly ring: Address;
  readonly treeId: TreeId;
  readonly utxoHash: Bytes32;
}

/** `undefined` unless the plaintext names the reader as owner and rebuilds the hash. */
export function openRecipient(
  output: AnonymousOutput,
  plaintext: AnonymousRecipientPlaintext,
): Utxo | undefined {
  if (!plaintext.verified.ownerPublicKey.equals(output.owner.signingPublicKey)) return undefined;
  const utxo = inRing(output.ring, anonymousRecipientUtxo(plaintext, output.assets));
  return rebuilds(output, utxo) ? utxo : undefined;
}

/** The bundle's change in output order, the change leading at output 0. */
export function senderChange(
  output: Pick<AnonymousOutput, "assets" | "ring">,
  plaintext: AnonymousSenderPlaintext,
  firstNullifier: Bytes32,
): readonly Utxo[] {
  return anonymousSenderUtxos(plaintext, output.assets, firstNullifier).map((utxo) =>
    inRing(output.ring, utxo),
  );
}

/** Ring outputs commit to no data, a hashed record rebuilds nothing. */
export function rebuilds(output: AnonymousOutput, utxo: Utxo): boolean {
  if (utxo.data.ringData() !== undefined || utxo.data.utxoData() !== undefined) return false;
  try {
    return equalBytes(utxo.hash(output.owner.nullifierPublicKey, output.treeId), output.utxoHash);
  } catch {
    return false;
  }
}

/** Dummy entries left out. */
export function listedRecipients(plaintext: AnonymousSenderPlaintext): readonly X25519PublicKey[] {
  return plaintext.verified.recipientViewingPublicKeys.filter((key) => !isDummyRecipient(key));
}

export function isDummyRecipient(key: X25519PublicKey): boolean {
  return key.equals(DUMMY_RECIPIENT_VIEWING_PK);
}

/** Every anonymous output is the ring's, its plaintext names no ring. */
function inRing(ring: Address, utxo: Utxo): Utxo {
  return new Utxo({
    owner: utxo.owner,
    asset: utxo.asset,
    amount: utxo.amount,
    blinding: utxo.blinding,
    data: utxo.data,
    ringProgramId: ring,
  });
}
