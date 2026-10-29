import type { BlockhashProvider, ChainReader } from "@heliuslabs/zolana/client";
import { compileUnsignedTransaction } from "@heliuslabs/zolana/internal";
import type {
  Address,
  Instruction,
  RequestContext,
  Transaction,
} from "@heliuslabs/zolana/interface";

import {
  RingInstructionTag,
  createRingPolicyInstruction,
  ringComputeUnitLimit,
  setRingPolicyRulesInstruction,
  setRingPolicySourceInstruction,
  type RingPolicySourceOwner,
  type RingPolicyTableInput,
  type RingSharedSource,
} from "./admin.js";
import { registryCurator } from "../../protocol/codec/ring-codecs.js";
import { fetchRingPolicy, fetchRingProgramConfig } from "../../protocol/membership/config.js";
import { RingError, wrapRingError } from "../../protocol/error.js";
import type { ListId } from "../../protocol/membership/policy.js";

export type RingPolicyAdminClient = BlockhashProvider & Pick<ChainReader, "getAccount">;

interface RingPolicyAdminParams {
  readonly client: RingPolicyAdminClient;
  readonly ringProgramId: Address;
  /** The config authority, also the fee payer. */
  readonly authority: Address;
  readonly computeUnitLimit?: number;
  readonly priorityFeeLamports?: bigint;
}

export interface RingCreatePolicyTransactionParams
  extends RingPolicyAdminParams, RingPolicyTableInput {}

/** Pins the table and its sources, a policy ring takes one before it registers with the pool. */
export async function buildRingCreatePolicyTransaction(
  params: RingCreatePolicyTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    await checkTier(params, context);
    await checkCurators(params, params.sharedSources ?? [], undefined, context);
    return await compile(
      params,
      await createRingPolicyInstruction(params),
      RingInstructionTag.createPolicy,
      context,
    );
  } catch (cause) {
    throw wrapRingError("RING_BUILD_POLICY", cause);
  }
}

export interface RingSetPolicyRulesTransactionParams
  extends RingPolicyAdminParams, RingPolicyTableInput {}

/** Replaces the pinned table and the complete source map, a proof over the old hash fails from the next slot. */
export async function buildRingSetPolicyRulesTransaction(
  params: RingSetPolicyRulesTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    await checkTier(params, context);
    const { records } = await fetchRingPolicy(params.client, params.ringProgramId, context);
    await checkCurators(params, params.sharedSources ?? [], records, context);
    return await compile(
      params,
      await setRingPolicyRulesInstruction(params),
      RingInstructionTag.setPolicyRules,
      context,
    );
  } catch (cause) {
    throw wrapRingError("RING_BUILD_POLICY", cause);
  }
}

export interface RingSetPolicySourceTransactionParams extends RingPolicyAdminParams {
  readonly listId: ListId;
  readonly source: RingPolicySourceOwner;
}

/** Re-points one referenced list, the rows stay and the sources keep at most one curator. */
export async function buildRingSetPolicySourceTransaction(
  params: RingSetPolicySourceTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const policy = await fetchRingPolicy(params.client, params.ringProgramId, context);
    if (policy.sources[params.listId - 1]?.listId !== params.listId)
      throw sourceInvalid("UnreferencedList", { listId: params.listId });
    if (params.source.kind === "curator") {
      const curator = params.source.registry;
      const others = policy.sources.filter((slot) => slot.listId !== params.listId);
      const current = registryCurator({ sources: others });
      if (current !== undefined && current !== curator) throw sourceInvalid("MultipleCurators");
      await checkCurators(
        params,
        [{ listId: params.listId, curatorRegistry: curator }],
        policy.records,
        context,
      );
    }
    return await compile(
      params,
      await setRingPolicySourceInstruction(params),
      RingInstructionTag.setPolicySource,
      context,
    );
  } catch (cause) {
    throw wrapRingError("RING_BUILD_POLICY", cause);
  }
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

/** Rust `curator_source`, `records` unknown before the policy exists. */
async function checkCurators(
  params: RingPolicyAdminParams,
  shared: readonly RingSharedSource[],
  records: Address | undefined,
  context: RequestContext | undefined,
): Promise<void> {
  const curators = new Set(shared.map((source) => source.curatorRegistry));
  if (curators.size > 1) throw sourceInvalid("MultipleCurators");
  for (const curator of curators) {
    if (curator === records) throw sourceInvalid("OwnCurator");
    if ((await params.client.getAccount(curator, context)) === undefined)
      throw new RingError("RING_MEMBER_REGISTRY_MISSING", { details: { registry: curator } });
  }
}

async function compile(
  params: RingPolicyAdminParams,
  instruction: Instruction,
  tag: RingInstructionTag,
  context: RequestContext | undefined,
): Promise<Transaction> {
  const lifetime = await params.client.getLatestBlockhash(context);
  return compileUnsignedTransaction({
    feePayer: params.authority,
    lifetime,
    instructions: [instruction],
    computeUnitLimit: params.computeUnitLimit ?? ringComputeUnitLimit(tag),
    ...(params.priorityFeeLamports === undefined
      ? {}
      : { priorityFeeLamports: params.priorityFeeLamports }),
  });
}

function sourceInvalid(reason: string, details: Readonly<Record<string, unknown>> = {}): RingError {
  return new RingError("RING_POLICY_SOURCE_INVALID", { details: { reason, ...details } });
}
