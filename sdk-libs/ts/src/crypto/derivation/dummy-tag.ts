import { isCanonicalField } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/keypair";

/** BN254's order is 254 bits wide. */
const TOP_BYTE_MASK = 0x3f;

/** A hidden dummy's preimage, uniform below `q`, a biased first byte marks a dummy against live tags. */
export function randomTagPreimage(draw: () => Uint8Array = randomBytes32): Bytes32 {
  for (;;) {
    const candidate = draw();
    candidate[0] = (candidate[0] ?? 0) & TOP_BYTE_MASK;
    if (isCanonicalField(candidate)) return candidate as Bytes32;
    candidate.fill(0);
  }
}

function randomBytes32(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}
