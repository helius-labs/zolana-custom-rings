import type { BlockhashProvider, ChainReader } from "@heliuslabs/zolana/client";
import { compileUnsignedTransaction } from "@heliuslabs/zolana/internal";
import type {
  Address,
  Instruction,
  RequestContext,
  Transaction,
} from "@heliuslabs/zolana/interface";
import { ringMemberRegistryAddress } from "../../protocol/pda/index.js";

import {
  RingInstructionTag,
  ringComputeUnitLimit,
  updateRingPolicyInstruction,
  type RingPolicyUpdate,
  type RingSharedSource,
} from "./admin.js";
import { registryCurator } from "../../protocol/codec/ring-codecs.js";
import {
  fetchRingMemberRegistry,
  fetchRingProgramConfig,
} from "../../protocol/membership/config.js";
import { RingError, wrapRingError } from "../../protocol/error.js";

export type RingPolicyAdminClient = BlockhashProvider & Pick<ChainReader, "getAccount">;

interface RingPolicyAdminParams {
  readonly client: RingPolicyAdminClient;
  readonly ringProgramId: Address;
  /** The config authority, also the fee payer. */
  readonly authority: Address;
  readonly computeUnitLimit?: number;
  readonly priorityFeeLamports?: bigint;
}

export interface RingUpdatePolicyTransactionParams extends RingPolicyAdminParams {
  readonly update: RingPolicyUpdate;
}

/** Refuses off chain a table or source write the program would refuse, a proof over the old hash fails from the next slot. */
export async function buildRingUpdatePolicyTransaction(
  params: RingUpdatePolicyTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const { update } = params;
    if (update.kind === "rules") {
      await checkTier(params, context);
      await checkCurators(params, update.sharedSources ?? [], context);
    }
    if (update.kind === "source") await checkSource(params, update, context);
    return await compile(params, await updateRingPolicyInstruction(params), context);
  } catch (cause) {
    throw wrapRingError("RING_BUILD_POLICY", cause);
  }
}

/** The list is referenced and the sources keep at most one curator. */
async function checkSource(
  params: RingPolicyAdminParams,
  update: Extract<RingPolicyUpdate, { kind: "source" }>,
  context: RequestContext | undefined,
): Promise<void> {
  const registry = await fetchRingMemberRegistry(params.client, params.ringProgramId, context);
  if (registry.sources[update.listId - 1]?.listId !== update.listId)
    throw sourceInvalid("UnreferencedList", { listId: update.listId });
  if (update.source.kind !== "curator") return;
  const curator = await ringMemberRegistryAddress(update.source.ringProgramId);
  const others = registry.sources.filter((slot) => slot.listId !== update.listId);
  const current = registryCurator({ ...registry, sources: others });
  if (current !== undefined && current !== curator) throw sourceInvalid("MultipleCurators");
  await checkCurators(
    params,
    [{ listId: update.listId, curatorRingProgramId: update.source.ringProgramId }],
    context,
  );
}

/** An audit-only ring takes no policy, Rust `PolicyOnAuditOnlyRing`. */
async function checkTier(
  params: RingPolicyAdminParams,
  context: RequestContext | undefined,
): Promise<void> {
  const config = await fetchRingProgramConfig(params.client, params.ringProgramId, context);
  if (!config.hasPolicy)
    throw new RingError("RING_POLICY_TIER_MISMATCH", {
      details: { ringProgramId: params.ringProgramId },
    });
}

/** Every curator ring holds the registry the program loads, Rust `load_curator_registry`. */
async function checkCurators(
  params: RingPolicyAdminParams,
  shared: readonly RingSharedSource[],
  context: RequestContext | undefined,
): Promise<void> {
  const curators = new Set(shared.map((source) => source.curatorRingProgramId));
  if (curators.size > 1) throw sourceInvalid("MultipleCurators");
  for (const curator of curators) {
    if (curator === params.ringProgramId) throw sourceInvalid("OwnCurator");
    await fetchRingMemberRegistry(params.client, curator, context);
  }
}

async function compile(
  params: RingPolicyAdminParams,
  instruction: Instruction,
  context: RequestContext | undefined,
): Promise<Transaction> {
  const lifetime = await params.client.getLatestBlockhash(context);
  return compileUnsignedTransaction({
    feePayer: params.authority,
    lifetime,
    instructions: [instruction],
    computeUnitLimit:
      params.computeUnitLimit ?? ringComputeUnitLimit(RingInstructionTag.updatePolicy),
    ...(params.priorityFeeLamports === undefined
      ? {}
      : { priorityFeeLamports: params.priorityFeeLamports }),
  });
}

function sourceInvalid(reason: string, details: Readonly<Record<string, unknown>> = {}): RingError {
  return new RingError("RING_POLICY_SOURCE_INVALID", { details: { reason, ...details } });
}
