/** Ring deposits opened by the wallet they were sealed to, Rust `zolana_ring_client::deposit`. */
import { equalBytes, isZero, readOutputData } from "@heliuslabs/zolana/internal";
import type { Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import { X25519PublicKey, type ShieldedAddress } from "@heliuslabs/zolana/keypair";
import {
  EncryptedScheme,
  type DepositPayloadDecoder,
  type OutputSlot,
  type ShieldedKeys,
  type Utxo,
} from "@heliuslabs/zolana/transaction";

import { isSmallOrder } from "../crypto/keys/x25519.js";
import {
  decodeRingDepositOutput,
  ringDepositUtxo,
} from "../protocol/codec/ring-deposit-plaintext.js";
import { exactlyOne } from "./batch.js";

export interface RingDepositSlot {
  readonly keys: ShieldedKeys;
  readonly owner: ShieldedAddress;
  readonly viewingPublicKey: X25519PublicKey;
  readonly outputSlot: OutputSlot;
  readonly depositPayload: DepositPayloadDecoder;
}

export interface RingDepositNote {
  readonly utxo: Utxo;
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
}

/** A deposit's published hash, not its decryption, proves it the owner's, Rust `DepositOpener::open`. */
export async function openRingDeposit(
  input: RingDepositSlot,
  context?: RequestContext,
): Promise<RingDepositNote | undefined> {
  const slot = input.outputSlot;
  const treeId = slot.outputContext.treeId;
  const output = decoded(() => {
    const frame = readOutputData(slot.payload);
    return frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.ringDeposit
      ? decodeRingDepositOutput(frame.body)
      : undefined;
  });
  if (output === undefined || treeId === undefined) return undefined;
  const txViewingPublicKey = decoded(() =>
    X25519PublicKey.fromBytes(output.encrypted.txViewingPublicKey),
  );
  if (txViewingPublicKey === undefined || isSmallOrder(txViewingPublicKey)) return undefined;
  const ciphertext = decoded(() => input.depositPayload(output.encrypted.ciphertext));
  if (ciphertext === undefined) return undefined;
  const plaintext = exactlyOne(
    await input.keys.decrypt(
      [
        {
          ciphertext,
          viewingPublicKey: input.viewingPublicKey,
          txViewingPublicKey,
          salt: output.encrypted.salt,
          slotIndex: 0,
          label: "ringDeposit",
        },
      ],
      context,
    ),
  );
  try {
    // A zero ring data hash is absent in the commitment.
    const ringDataHash = !isZero(output.ringDataHash) ? output.ringDataHash : undefined;
    return decoded(() => {
      const opened = ringDepositUtxo(output, plaintext, input.owner.signingPublicKey);
      // Utxo data under a zero data hash is unbound.
      if (
        opened.data.utxoData() !== undefined &&
        (output.dataHash === undefined || isZero(output.dataHash))
      )
        return undefined;
      const hash = opened.hash(
        input.owner.nullifierPublicKey,
        treeId,
        output.dataHash,
        ringDataHash,
      );
      if (!equalBytes(hash, slot.outputContext.hash)) return undefined;
      return Object.freeze({
        utxo: opened,
        ...(output.dataHash === undefined ? {} : { dataHash: output.dataHash }),
        ...(ringDataHash === undefined ? {} : { ringDataHash }),
      });
    });
  } finally {
    plaintext.fill(0);
  }
}

/** A malformed body is another key's or a forgery, it is skipped. */
export function decoded<T>(decode: () => T | undefined): T | undefined {
  try {
    return decode();
  } catch {
    return undefined;
  }
}
