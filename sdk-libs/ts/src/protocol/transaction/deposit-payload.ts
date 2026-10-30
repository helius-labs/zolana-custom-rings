import { ringDepositRecipientCiphertext } from "../codec/ring-deposit-capsule.js";
import { X25519PublicKey, type ViewingKeyLike } from "@heliuslabs/zolana/keypair";
import type { ShieldedPublicKey, Utxo } from "@heliuslabs/zolana";
import { ringDepositUtxo, type RingDepositOutput } from "../codec/ring-deposit-plaintext.js";

export { ringDepositRecipientCiphertext as customRingDepositPayload };

/** Rust `RingDepositPlaintext::decrypt` + `into_utxo`. The ring data record is always present, the UTXO is ring-bound. */
export function decryptRingDepositUtxo(
  output: RingDepositOutput,
  key: ViewingKeyLike,
  owner: ShieldedPublicKey,
): Utxo {
  return ringDepositUtxo(
    output,
    key.decryptRingDeposit(
      ringDepositRecipientCiphertext(output.encrypted.ciphertext),
      X25519PublicKey.fromBytes(output.encrypted.txViewingPublicKey),
      output.encrypted.salt,
    ),
    owner,
  );
}
