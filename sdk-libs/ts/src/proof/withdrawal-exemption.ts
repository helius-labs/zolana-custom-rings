import type { Address, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import { hashChain4, bigIntBytes, ZERO_32 } from "@heliuslabs/zolana/internal";
import type { RingProgramConfig } from "../protocol/codec/ring-codecs.js";
import { fetchRingPolicy } from "../protocol/membership/config.js";
import { memberOfAsset } from "../protocol/membership/policy.js";
import { RingError } from "../protocol/error.js";
import { domainField, RingDomain } from "../crypto/derivation/ring-domain.js";
import { ownRoot, readMemberOpenings, type BoundRoot } from "../rpc/registered-record.js";
import type { WithdrawalExemptionProofRequest } from "../rpc/prover/ring.js";
import { N_PUBLIC_SLOTS } from "../protocol/transaction/spp.js";
import type { PolicyReadClient } from "./policy-proof.js";
import { checkRingCoSigner, type CoSignDemand } from "./cosign.js";

export interface WithdrawalExemption {
  readonly root: BoundRoot;
  readonly request: WithdrawalExemptionProofRequest;
}
export async function readWithdrawalExemption(
  input: Readonly<{
    client: PolicyReadClient;
    ringProgramId: Address;
    config: RingProgramConfig;
    demand: CoSignDemand;
    approvalRequired: boolean;
    own: BoundRoot | undefined;
  }>,
  context?: RequestContext,
): Promise<WithdrawalExemption | undefined> {
  const { client, ringProgramId, config, demand, approvalRequired } = input;
  const signer = (withdrawalExempt: boolean) =>
    checkRingCoSigner({
      ringProgramId,
      configured: config.coSigner,
      supplied: config.coSigner?.signer,
      demand,
      approvalRequired,
      withdrawalExempt,
    });
  if (demand.withdrawals.length === 0 || signer(false) === undefined || signer(true) !== undefined)
    return undefined;
  let root = input.own;
  if (root === undefined) {
    try {
      root = ownRoot(ringProgramId, await fetchRingPolicy(client, ringProgramId, context));
    } catch (error) {
      if (error instanceof RingError && error.code === "RING_POLICY_MISSING") return undefined;
      throw error;
    }
  }
  const assets = demand.withdrawals.map((row) => memberOfAsset(row.mint) as Bytes32);
  const amounts = demand.withdrawals.map((row) => bigIntBytes(row.amount, 32) as Bytes32);
  if (assets.length > N_PUBLIC_SLOTS) throw new RingError("RING_MEMBER_REGISTRY_INVALID");
  const reads = await readMemberOpenings({ client, root, members: assets }, context);
  if (
    reads.some(
      (read, i) =>
        read.record() === undefined ||
        demand.withdrawals[i]!.amount > read.record()!.mintPolicy.withdrawalThreshold,
    )
  )
    return undefined;
  const entries = Array.from({ length: N_PUBLIC_SLOTS }, (_, i) => reads[i]?.opening);
  while (assets.length < N_PUBLIC_SLOTS) {
    assets.push(ZERO_32);
    amounts.push(ZERO_32);
  }
  const fields = [
    domainField(RingDomain.withdrawalExemption),
    root.root,
    ...assets.flatMap((asset, i) => [asset, amounts[i]!]),
  ];
  const publicInputHash = hashChain4(fields) as Bytes32;
  return {
    root,
    request: {
      kind: "withdrawalExemption",
      publicInputHash,
      root: root.root,
      assets,
      amounts,
      entries,
    },
  };
}
