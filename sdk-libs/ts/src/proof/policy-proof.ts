import { EMPTY_MINT_POLICY } from "../protocol/membership/mint-policy.js";
import type { RecordPool } from "../protocol/membership/member-registry.js";
import {
  readPolicyWithdrawals,
  policyWithdrawalHash,
  withdrawalCapacity,
  type PolicyWithdrawal,
} from "./withdrawals.js";
/** The policy half of a ring transfer, the ring's table and every subject's record under the roots the statement binds, Rust `pipeline::policy`. */
import { ringInputOpening, ringOutputOpening } from "../rpc/prover/assembly.js";
import {
  privateTxAddressChain,
  sppPrivateTxHashInput,
  ZERO_32,
  nonZeroHashChain,
  bytesKey,
  equalBytes,
} from "@heliuslabs/zolana/internal";
import { type RingRecordReader } from "../rpc/ports.js";
import type { ChainReader } from "@heliuslabs/zolana/client";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import { assetField, type SppProofInputs } from "@heliuslabs/zolana/transaction";
import type {
  DelegatePolicyProofRequest,
  MemberPolicyProofRequest,
  PolicySubjectEntry,
} from "../rpc/prover/ring.js";

import {
  registryCurrentRoot,
  type RingMemberRegistry,
  type RingProgramConfig,
} from "../protocol/codec/ring-codecs.js";
import { fetchCuratorRegistry, fetchRingMemberRegistry } from "../protocol/membership/config.js";
import { RingError } from "../protocol/error.js";
import { ownerEscrowed, type MemberOpeningRead } from "../protocol/membership/member-opening.js";
import {
  admitTransfer,
  memberOfAsset,
  pinnedPolicy,
  policyTableProofInputs,
  type OutflowLimit,
  type PinnedPolicy,
  type RecordLists,
  type RuleRefusal,
} from "../protocol/membership/policy.js";
import { readRecordPool } from "../rpc/registered-record.js";
import { policyStatementHash, type PolicyKey } from "../protocol/proof/statement.js";
import { policyPoolCapacity } from "../protocol/proof/proving-keys.js";
import { publishesRecipients, type RingRail } from "../protocol/transaction/transact.js";
import { publicAmountFields, type PublicSlots } from "../protocol/transaction/spp.js";

/** The registry root a statement names by its history slot. */
export interface BoundRoot {
  readonly ringProgramId: Address;
  readonly rootIndex: number;
  readonly root: Bytes32;
}

/** The registry policy hash a policy statement binds, Rust `BoundPolicy`. */
export interface BoundPolicy {
  readonly ringProgramId: Address;
  readonly policyHash: Bytes32;
}

export type PolicyReadClient = Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getRingMemberOpenings" | "getRingRecordPool">;

/** The ring's table, its roots and every subject's openings, read before the statement, Rust `PolicyInputs`. */
export interface PolicyInputs {
  readonly withdrawals: readonly PolicyWithdrawal[];
  readonly splWithdrawalOwners: readonly Bytes32[];
  readonly pinned: PinnedPolicy;
  readonly own: BoundRoot;
  readonly ownPool: RecordPool;
  /** The curator registry account, the root bound from it and its pool. */
  readonly curator?: Readonly<{ registry: Address; root: BoundRoot; pool: RecordPool }>;
  readonly senderEntry: PolicySubjectEntry;
  /** Outputs then every withdrawal slot. */
  readonly ownerEntries: readonly PolicySubjectEntry[];
  readonly assetEntries: readonly PolicySubjectEntry[];
  /** Empty on the delegate rail. */
  readonly publicAssetEntries: readonly number[];
  /** The escrowed key ciphertext hash of every UTXO output's owner, under key escrow. */
  readonly ctHashes: readonly (Bytes32 | undefined)[];
  /** One per output slot, zero on a dummy and on the anonymous rail. */
  readonly recipients: readonly Bytes32[];
  readonly approvalRequired: boolean;
  readonly keyEscrow: boolean;
}

/** What the statement and the request read besides the policy inputs, Rust `PolicyProving`. */
export interface PolicyProving {
  readonly ringId: Bytes32;
  readonly rail: RingRail;
  readonly proofInputs: SppProofInputs;
  readonly privateTxHash: Bytes32;
  /** The owner identity, the anonymous rail's sender commitment, zero on the delegate rail. */
  readonly sender: Bytes32;
  readonly senderPkHash: Bytes32;
  readonly publicSlots: PublicSlots;
}

/** Rust `PolicyRead::read`, `sender` is the owner identity the rules read as the sender. */
export async function readPolicy(
  input: Readonly<{
    tokenOwnerHint?: Address;
    client: PolicyReadClient;
    ringProgramId: Address;
    config: RingProgramConfig;
    rail: RingRail;
    proofInputs: SppProofInputs;
    sender: Bytes32;
    publicSlots: PublicSlots;
  }>,
  context?: RequestContext,
): Promise<PolicyInputs> {
  const { client, ringProgramId, proofInputs } = input;
  const registry = await fetchRingMemberRegistry(client, ringProgramId, context);
  const pinned = pinnedPolicy(registry);
  const own = currentRoot(ringProgramId, registry);
  const curatorRegistry = pinned.curator;
  const curatorRoot =
    curatorRegistry === undefined
      ? undefined
      : await (async () => {
          const read = await fetchCuratorRegistry(client, curatorRegistry, context);
          return currentRoot(read.ringProgramId, read.registry);
        })();
  const { withdrawals, splWithdrawalOwners } = await readPolicyWithdrawals(
    client,
    proofInputs.externalData.interfaceTransfers,
    input.tokenOwnerHint,
    context,
  );
  const outputs = proofInputs.outputs;
  const owners = outputs.map((output) =>
    output.ownerAddress?.signingPublicKey.ownerProofInputHash(),
  );
  const assets = outputs.map((output) =>
    !output.isDummy() ? memberOfAsset(output.asset) : undefined,
  );
  const memberRail = input.rail !== "delegate";
  const publicAssets = memberRail
    ? input.publicSlots.assets.filter((asset) => !equalBytes(asset, ZERO_32))
    : [];
  const withdrawalSlots = withdrawalCapacity(withdrawals.length);
  const ownOnly = curatorRoot === undefined;
  const capacity = policyPoolCapacity(
    memberRail
      ? { family: "memberPolicy", outputs: outputs.length, withdrawals: withdrawalSlots, ownOnly }
      : {
          family: "delegatePolicy",
          inputs: proofInputs.inputUtxos.length,
          outputs: outputs.length,
          ownOnly,
        },
  );
  // Rust builds the same subject order.
  const curatorMembers = firstSeen([
    input.sender,
    ...outputs.flatMap((_, slotIndex) => [owners[slotIndex], assets[slotIndex]]),
    ...withdrawals.flatMap((w) => [w.owner, w.asset]),
  ]);
  const ownMembers = firstSeen([...curatorMembers, ...publicAssets]);
  const ownPool = await readRecordPool(
    { client, ringProgramId, root: own.root, members: ownMembers, openings: capacity.own },
    context,
  );
  const curatorPool =
    curatorRoot === undefined
      ? undefined
      : await readRecordPool(
          {
            client,
            ringProgramId: curatorRoot.ringProgramId,
            root: curatorRoot.root,
            members: curatorMembers,
            openings: capacity.curator,
          },
          context,
        );
  const ownReads = subjectReads(ownMembers, ownPool.reads);
  const curatorReads =
    curatorPool === undefined ? undefined : subjectReads(curatorMembers, curatorPool.reads);
  const reads = (member: Bytes32 | undefined) =>
    member === undefined
      ? { own: undefined, curator: undefined }
      : {
          own: ownReads.get(bytesKey(member))?.read,
          curator: curatorReads?.get(bytesKey(member))?.read,
        };
  const subject = (pool: SubjectReads, member: Bytes32 | undefined): number =>
    member === undefined ? 0 : (pool.get(bytesKey(member))?.index ?? 0);
  const entry = (member: Bytes32 | undefined): PolicySubjectEntry =>
    curatorReads === undefined
      ? { own: subject(ownReads, member) }
      : { own: subject(ownReads, member), curator: subject(curatorReads, member) };
  const padding = Array.from({ length: withdrawalSlots - withdrawals.length }, () =>
    entry(undefined),
  );
  const lists = (member: Bytes32 | undefined): RecordLists => {
    const { own, curator } = reads(member);
    return Object.freeze({
      own: own?.record()?.lists ?? 0n,
      curator: curator?.record()?.lists ?? 0n,
    });
  };
  const mintPolicy = (asset: Bytes32 | undefined) =>
    reads(asset).own?.record()?.mintPolicy ?? EMPTY_MINT_POLICY;
  const live = outputs.flatMap((output, slotIndex) =>
    output.isDummy() ? [] : [{ output, slotIndex }],
  );
  const refusal = admitTransfer(pinned.table, pinned.sources, {
    sender: lists(input.sender),
    outputs: [
      ...live.map(({ output, slotIndex }) => ({
        owner: owners[slotIndex] ?? ZERO_32,
        asset: memberOfAsset(output.asset),
        amount: output.amount,
        ownerLists: lists(owners[slotIndex]),
        assetLists: lists(assets[slotIndex]),
        mintPolicy: mintPolicy(assets[slotIndex]),
      })),
      ...withdrawals.map((w) => ({
        ...w,
        ownerLists: lists(w.owner),
        assetLists: lists(w.asset),
        mintPolicy: mintPolicy(w.asset),
      })),
    ],
  });
  if (refusal !== undefined)
    throw ruleUnsatisfied(
      refusal,
      live.map(({ slotIndex }) => slotIndex),
    );
  const keyEscrow = input.config.keyEscrow;
  const ctHashes = outputs.map((output, slotIndex) => {
    const owner = owners[slotIndex];
    const address = output.ownerAddress;
    if (!keyEscrow || owner === undefined || address === undefined) return undefined;
    return ownerEscrowed(owner, reads(owner).own, address.nullifierPublicKey).ctHash;
  });
  const approvalRequired =
    input.rail === "delegate"
      ? false
      : outflowApproval({
          sender: input.sender,
          ringProgramId,
          proofInputs,
          publicSlots: input.publicSlots,
          limits: uniqueMembers([...assets, ...publicAssets]).flatMap((asset) => {
            const policy = mintPolicy(asset);
            return policy.cap === 0n && policy.cosignAbove === 0n
              ? []
              : [
                  {
                    asset: asset as OutflowLimit["asset"],
                    cap: policy.cap,
                    cosignAbove: policy.cosignAbove,
                  },
                ];
          }),
        });
  return Object.freeze({
    pinned,
    withdrawals,
    splWithdrawalOwners,
    own,
    ownPool: ownPool.pool,
    ...(curatorRegistry === undefined || curatorRoot === undefined || curatorPool === undefined
      ? {}
      : {
          curator: Object.freeze({
            registry: curatorRegistry,
            root: curatorRoot,
            pool: curatorPool.pool,
          }),
        }),
    senderEntry: entry(input.sender),
    ownerEntries: Object.freeze([
      ...owners.map((owner) => entry(owner)),
      ...withdrawals.map((w) => entry(w.owner)),
      ...padding,
    ]),
    assetEntries: Object.freeze([
      ...assets.map((asset) => entry(asset)),
      ...withdrawals.map((w) => entry(w.asset)),
      ...padding,
    ]),
    publicAssetEntries: Object.freeze(
      memberRail ? input.publicSlots.assets.map((asset) => subject(ownReads, asset)) : [],
    ),
    ctHashes: Object.freeze(ctHashes),
    recipients: Object.freeze(
      owners.map((owner) =>
        publishesRecipients(input.rail) && owner !== undefined ? owner : zeroField(),
      ),
    ),
    approvalRequired,
    keyEscrow,
  });
}

/** Rust `PolicyInputs::statement`, the delegate key always proves escrowed keys. */
export function policyPublicInputHash(policy: PolicyInputs, proving: PolicyProving): Bytes32 {
  const key = policyKey(proving.rail);
  return policyStatementHash({
    withdrawalHash: policyWithdrawalHash(policy.withdrawals),
    key,
    privateTxHash: proving.privateTxHash,
    policyHash: policy.pinned.policyHash,
    ringId: proving.ringId,
    approvalRequired: policy.approvalRequired,
    keyEscrow: key.kind === "delegate" || policy.keyEscrow,
    ownRoot: policy.own.root,
    curatorRoot: policy.curator?.root.root ?? zeroField(),
    sender: proving.sender,
    recipients: policy.recipients,
    publicAssets: proving.publicSlots.assets,
    publicAmounts: publicAmountFields(proving.publicSlots),
  });
}

/** The policy proof's request, Rust `PolicyInputs::prove`. */
export function policyProofRequest(
  policy: PolicyInputs,
  proving: PolicyProving,
): MemberPolicyProofRequest | DelegatePolicyProofRequest {
  const { proofInputs } = proving;
  const publicInputHash = policyPublicInputHash(policy, proving);
  const privateTx = sppPrivateTxHashInput(proofInputs);
  const capacity = withdrawalCapacity(policy.withdrawals.length);
  const padding = capacity - policy.withdrawals.length;
  const params = {
    withdrawalCount: policy.withdrawals.length,
    withdrawalHash: policyWithdrawalHash(policy.withdrawals),
    withdrawals: [
      ...policy.withdrawals,
      ...Array.from({ length: padding }, () => ({
        owner: zeroField(),
        asset: zeroField(),
        amount: 0n,
      })),
    ],
    ...policyTableProofInputs(policy.pinned.table, policy.pinned.sources),
    privateTxHash: proving.privateTxHash,
    policyHash: policy.pinned.policyHash,
    ringId: proving.ringId,
    ownRoot: policy.own.root,
    curatorRoot: policy.curator?.root.root ?? zeroField(),
    publicAssets: proving.publicSlots.assets,
    publicAmounts: publicAmountFields(proving.publicSlots),
    addressChain: privateTxAddressChain(privateTx),
    privateTxBlinding: proofInputs.privateTxBlinding(),
    outputs: proofInputs.outputs.map((output, slotIndex) => {
      const ctHash = policy.ctHashes[slotIndex];
      return Object.freeze({
        ...ringOutputOpening(output, proofInputs.outputTreeId),
        ...(ctHash === undefined ? {} : { ctHash }),
      });
    }),
    recipients: policy.recipients,
    senderPkHash: proving.senderPkHash,
    ownPool: policy.ownPool,
    ...(policy.curator === undefined ? {} : { curatorPool: policy.curator.pool }),
    senderEntry: policy.senderEntry,
    ownerEntries: policy.ownerEntries,
    assetEntries: policy.assetEntries,
    publicAssetEntries: policy.publicAssetEntries,
  };
  if (proving.rail === "delegate")
    return Object.freeze({
      kind: "delegatePolicy",
      publicInputHash,
      ...params,
      inputs: proofInputs.inputUtxos.map(ringInputOpening),
    });
  return Object.freeze({
    kind: "memberPolicy",
    publicInputHash,
    ...params,
    anonymous: proving.rail === "anonymous",
    approvalRequired: policy.approvalRequired,
    keyEscrow: policy.keyEscrow,
    sender: proving.sender,
    inputChain: nonZeroHashChain(privateTx.inputHashes),
  });
}

/** Rust `RingRail::policy_key`. */
export function policyKey(rail: RingRail): PolicyKey {
  return rail === "delegate"
    ? { kind: "delegate" }
    : { kind: "member", anonymous: rail === "anonymous" };
}

/**
 * Rust `Outflows::approval_required`. Every UTXO output but the sender's change inside the ring
 * leaves it, less the asset's public net, a nonzero cap refuses more and a nonzero co-sign bound sets
 * the approval bit.
 */
export function outflowApproval(
  input: Readonly<{
    sender: Bytes32;
    ringProgramId: Address;
    proofInputs: SppProofInputs;
    publicSlots: PublicSlots;
    limits: readonly OutflowLimit[];
  }>,
): boolean {
  let approval = false;
  for (const limit of input.limits) {
    const outflow = assetOutflow(input, limit.asset);
    const over = (bound: bigint): boolean => bound !== 0n && outflow > bound;
    if (over(limit.cap))
      throw new RingError("RING_OUTFLOW_CAP_EXCEEDED", {
        details: { cap: limit.cap.toString(), outflow: outflow.toString() },
      });
    approval ||= over(limit.cosignAbove);
  }
  return approval;
}

function assetOutflow(
  input: Readonly<{
    sender: Bytes32;
    ringProgramId: Address;
    proofInputs: SppProofInputs;
    publicSlots: PublicSlots;
  }>,
  asset: Bytes32,
): bigint {
  let others = 0n;
  for (const output of input.proofInputs.outputs) {
    const owner = output.ownerAddress;
    if (owner === undefined) continue;
    const change =
      equalBytes(owner.signingPublicKey.ownerProofInputHash(), input.sender) &&
      output.ringProgramId === input.ringProgramId;
    if (!change && equalBytes(assetField(output.asset), asset)) others += output.amount;
  }
  const net = input.publicSlots.assets.reduce(
    (sum, publicAsset, index) =>
      equalBytes(publicAsset, asset) ? sum + (input.publicSlots.nets[index] ?? 0n) : sum,
    0n,
  );
  if (net > others) throw new RingError("RING_DEPOSIT_ABOVE_OUTFLOW");
  return others - net;
}

/** The rule and the subject a refusal names, outputs by their SPP slot. */
function ruleUnsatisfied(refusal: RuleRefusal, live: readonly number[]): RingError {
  const slot = (output: number): number => live[output] ?? -1;
  return new RingError("RING_POLICY_RULE_UNSATISFIED", {
    details:
      refusal.kind !== "lists"
        ? { reason: refusal.kind, ruleIndex: refusal.rule, slotIndex: slot(refusal.output) }
        : refusal.subject.kind === "sender"
          ? { reason: refusal.kind, ruleIndex: refusal.rule, subject: "sender" }
          : {
              reason: refusal.kind,
              ruleIndex: refusal.rule,
              subject: refusal.subject.kind,
              slotIndex: slot(refusal.subject.output),
            },
  });
}

/** Rust `BoundRoot::current`, the newest root of the registry. */
export function currentRoot(ringProgramId: Address, registry: RingMemberRegistry): BoundRoot {
  return Object.freeze({
    ringProgramId,
    rootIndex: registry.historyCursor,
    root: registryCurrentRoot(registry).root,
  });
}

type SubjectReads = ReadonlyMap<string, Readonly<{ index: number; read: MemberOpeningRead }>>;

/** Every subject's pool index and verified read, keyed by member. */
function subjectReads(
  members: readonly Bytes32[],
  reads: readonly MemberOpeningRead[],
): SubjectReads {
  return new Map(
    members.flatMap((member, index) => {
      const read = reads[index];
      return read === undefined ? [] : [[bytesKey(member), { index, read }] as const];
    }),
  );
}

/** Distinct members in first-seen order, padding dropped. */
function firstSeen(members: readonly (Bytes32 | undefined)[]): readonly Bytes32[] {
  const unique = new Map<string, Bytes32>();
  for (const member of members)
    if (member !== undefined && !unique.has(bytesKey(member))) unique.set(bytesKey(member), member);
  return [...unique.values()];
}

/** Sorted by bytes like Rust's `BTreeSet`, padding and duplicates dropped. */
function uniqueMembers(members: readonly (Bytes32 | undefined)[]): readonly Bytes32[] {
  const unique = new Map<string, Bytes32>();
  for (const member of members) if (member !== undefined) unique.set(bytesKey(member), member);
  return [...unique.entries()]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([, member]) => member);
}

function zeroField(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}
