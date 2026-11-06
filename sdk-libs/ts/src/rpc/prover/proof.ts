import { CUSTOM_RING_PROOF_LENGTH } from "../../protocol/proof/custom-ring-proof.js";
import { ClientError } from "@heliuslabs/spr";
import { compressG2 } from "@heliuslabs/spr/internal";
import { compressProof, type Proof } from "@heliuslabs/spr/client";

/** `a(32) || b(64) || c(32) || commitment(32) || commitmentPok(32)`, Rust `CustomRingProof`. */
export function customRingProof(proof: Proof): Uint8Array {
  const { a, b, c, commitment, commitmentPok } = compressProof(proof);
  if (commitment === undefined || commitmentPok === undefined) {
    throw new ClientError("CLIENT_PROOF_PARSE", {
      details: { path: "$.proof.proofCommitment", reason: "missing commitment" },
    });
  }
  const bytes = new Uint8Array(CUSTOM_RING_PROOF_LENGTH);
  bytes.set(a, 0);
  bytes.set(compressG2(b), 32);
  bytes.set(c, 96);
  bytes.set(commitment, 128);
  bytes.set(commitmentPok, 160);
  return bytes;
}
