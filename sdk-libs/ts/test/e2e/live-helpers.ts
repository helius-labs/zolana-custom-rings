import type { ProofDataSource } from "@heliuslabs/spr/client";
import { createCustomRingClient, type CustomRingClient } from "../../src/rpc/client.js";
import { liveHarness as sppLiveHarness } from "../../../../zolana/sdk-libs/ts/test/e2e/live-helpers.js";
import type { LiveHarness } from "../../../../zolana/sdk-libs/ts/test/e2e/live-helpers.js";

export {
  actor,
  currentSlot,
  fund,
  signSendAndConfirm,
  sync,
  waitForSignature,
  type Actor,
} from "../../../../zolana/sdk-libs/ts/test/e2e/live-helpers.js";

/** The zolana harness whose client also proves and reads the ring circuits. */
export async function liveHarness(
  proofDataSource?: ProofDataSource,
): Promise<LiveHarness & Readonly<{ client: CustomRingClient }>> {
  const harness = await sppLiveHarness();
  const client = await createCustomRingClient({
    solanaRpcUrl: harness.rpcUrl,
    indexerUrl: harness.indexerUrl,
    proverUrl: harness.proverUrl,
    tree: harness.tree,
    ...(proofDataSource === undefined ? {} : { proofDataSource }),
    indexerConfig: harness.client.indexerConfig,
  });
  return { ...harness, client };
}
