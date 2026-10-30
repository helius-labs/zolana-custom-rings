import type { ProverClient } from "@heliuslabs/zolana/internal";
import { parseCheckedProof } from "@heliuslabs/zolana/internal";
import type { RequestContext } from "@heliuslabs/zolana";
import type { Proof, ProvingKeyReport } from "@heliuslabs/zolana/client";

import { RingError } from "../../protocol/error.js";
import { RING_PROVING_KEY_SHA256S } from "../../protocol/proof/proving-keys.js";
import { ringProofRequestBody, ringRequestKey, type RingProofRequest } from "./ring.js";

export class CustomRingProver {
  readonly #prover: ProverClient;

  constructor(prover: ProverClient) {
    this.#prover = prover;
  }

  async proveRing(request: RingProofRequest, context?: RequestContext): Promise<Proof> {
    const key = ringRequestKey(request);
    const body = JSON.stringify(ringProofRequestBody(request));
    return parseCheckedProof(await this.#prover.send(body, "queued", key, context), key);
  }

  /** The prover's catalog leaves out a key it does not serve. */
  async checkProvingKeys(context?: RequestContext): Promise<ProvingKeyReport> {
    const report = await this.#prover.checkProvingKeys(context, RING_PROVING_KEY_SHA256S);
    const served = new Set(report.keys.map((key) => key.name));
    const missing = Object.keys(RING_PROVING_KEY_SHA256S).filter((name) => !served.has(name));
    if (missing.length > 0)
      throw new RingError("RING_PROVING_KEYS_MISSING", {
        details: { keyNames: missing.join(",") },
      });
    return report;
  }
}
