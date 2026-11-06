import type { BlockhashProvider, ChainReader } from "@heliuslabs/spr/client";
import { compileUnsignedTransaction } from "@heliuslabs/spr/internal";
import type { Address, Instruction, RequestContext, Transaction } from "@heliuslabs/spr/interface";

import {
  RingInstructionTag,
  ringComputeUnitLimit,
  updateRingPolicyInstruction,
  type RingPolicyUpdate,
  type RingSharedSource,
} from "./admin.js";
import { isZeroAddress, registryCurator } from "../../protocol/codec/ring-codecs.js";
import { fetchRingPolicy, fetchStorageRegistry } from "../../protocol/membership/config.js";
import { isPrivateList, listIdFromByte } from "../../protocol/membership/policy.js";
import { RingError, wrapRingError } from "../../protocol/error.js";

export type RingPolicyAdminClient = BlockhashProvider & Pick<ChainReader, "getAccount">;

interface RingPolicyAdminParams {
  readonly client: RingPolicyAdminClient;
  readonly ringProgramId: Address;
  /** The policy authority, also the fee payer. */
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
    const current = await fetchRingPolicy(params.client, params.ringProgramId, context);
    if (update.kind === "rules") {
      await checkTier(params, context);
      await checkCurators(params, update.sharedSources ?? [], current.records, context);
    }
    if (update.kind === "source") await checkSource(params, update, context);
    return await compile(
      params,
      await updateRingPolicyInstruction({ ...params, current }),
      context,
    );
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
  const policy = await fetchRingPolicy(params.client, params.ringProgramId, context);
  if (policy.sources[update.listId - 1]?.listId !== update.listId)
    throw sourceInvalid("UnreferencedList", { listId: update.listId });
  const curator = update.source.kind === "curator" ? update.source.registry : undefined;
  if (curator !== undefined) {
    const others = policy.sources.filter((slot) => slot.listId !== update.listId);
    const current = registryCurator({ sources: others });
    if (current !== undefined && current !== curator) throw sourceInvalid("MultipleCurators");
  }
  const address = curator ?? policy.records;
  const source = await fetchStorageRegistry(params.client, address, context);
  // Rust `check_source_pair`, an unpaired source serving a private list takes no floor. A public
  // read holds no such risk, one curator serves many rings and pins at most one of their registries.
  const servesPrivate = policy.sources.some(({ listId, registry }) => {
    const id = listIdFromByte(listId);
    if (id === undefined || !isPrivateList(id)) return false;
    if (id === update.listId) return true;
    return (isZeroAddress(registry) ? policy.records : registry) === address;
  });
  if (source.trackingRegistry !== policy.tracking && servesPrivate)
    throw sourceInvalid("SaltedSourceOtherTracking");
  if (curator === undefined) return;
  await checkCurators(
    params,
    [{ listId: update.listId, curatorRegistry: curator }],
    policy.records,
    context,
  );
}

/** An audit-only ring takes no policy, Rust `PolicyOnAuditOnlyRing`. */
async function checkTier(
  params: RingPolicyAdminParams,
  context: RequestContext | undefined,
): Promise<void> {
  const config = await fetchRingPolicy(params.client, params.ringProgramId, context);
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
