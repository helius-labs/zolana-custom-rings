/** The policy section of a ring transfer, every record read under a root the statement binds. */
import type { ShieldedAddress, ShieldedPublicKey } from "@heliuslabs/spr/keypair";
import { EMPTY_MINT_POLICY, type MintPolicy } from "../protocol/membership/mint-policy.js";
import type { RecordPool } from "../protocol/membership/member-registry.js";
import {
  readPolicyWithdrawals,
  policyWithdrawalHash,
  type PolicyWithdrawal,
} from "./withdrawals.js";
import {
  ZERO_32,
  ZERO_NULLIFIER_PK,
  addressBytes,
  bytesKey,
  equalBytes,
  isZero,
} from "@heliuslabs/spr/internal";
import { type RingRecordReader, type TrackingReader } from "../rpc/ports.js";
import type { ChainReader } from "@heliuslabs/spr/client";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/spr/interface";
import {
  assetField,
  type ProofInputUtxo,
  type ProofOutputUtxo,
  type SettlementTransfer,
  type SppProofInputs,
} from "@heliuslabs/spr/transaction";
import type {
  PolicyOwnerEntry,
  PolicyProofInputs,
  PolicySubjectEntry,
  PolicyTableProofInputs,
  TrackingProofInputs,
} from "../rpc/prover/ring.js";
import { RING_RULE_SLOTS, RING_SOURCE_SLOTS } from "../rpc/prover/types.js";

import type { RingPolicy } from "../protocol/codec/ring-codecs.js";
import { RingError } from "../protocol/error.js";
import { InputClass } from "../protocol/codec/audit-stream.js";
import { inputClassOf } from "./audit-proof.js";
import {
  unopenedRecordPool,
  type MemberOpeningRead,
} from "../protocol/membership/member-opening.js";
import { ApprovalTotals } from "../protocol/membership/approval-totals.js";
import {
  approvalMask,
  ownerDebits,
  type DebitInput,
  type DebitOutput,
  type OwnerDebit,
  type PublicGross,
} from "../protocol/membership/owner-debits.js";
import { listTagOf } from "../crypto/keys/list-salt.js";
import { privateListKey } from "../protocol/membership/private-list.js";
import {
  evaluateInputAssets,
  evaluatePayments,
  evaluateSenders,
  memberOfAsset,
  pinnedPolicy,
  policySourceView,
  policyTableProofInputs,
  type PinnedPolicy,
  type RecordLists,
  type RuleRefusal,
  type SourceView,
} from "../protocol/membership/policy.js";
import { verifyTrackingPool, type TrackingRecord } from "../protocol/membership/tracking.js";
import { fetchBoundRoot, readRecordPool, type BoundRoot } from "../rpc/registered-record.js";
import {
  enrolledViewingKey,
  newestTrackingRoot,
  type AuthorizationReader,
} from "../rpc/tracking-resolver.js";
import type { TransferRoots } from "../protocol/proof/statement.js";
import {
  transferPoolCapacity,
  type PolicyPoolCapacity,
  type TransferKeyCircuit,
} from "../protocol/proof/transfer-shapes.js";
import { isDelegateRail, type RingRail } from "../protocol/transaction/transact.js";
import {
  publicAmountFields,
  publicGrossFields,
  publicSlots,
  N_PUBLIC_SLOTS,
  type PublicSlots,
} from "../protocol/transaction/spp.js";

export type { BoundRoot } from "../rpc/registered-record.js";

/** The registry policy hash a statement binds, Rust `BoundPolicy`. */
export interface BoundPolicy {
  readonly ringProgramId: Address;
  readonly policyHash: Bytes32;
}

/** Rust `GetTrackingRecordPool`, the pool's canopy needs nodes no single opening's path holds. */
export type PolicyReadClient = Pick<ChainReader, "getAccount"> &
  AuthorizationReader &
  Pick<RingRecordReader, "getStorageRecordPool"> &
  Pick<TrackingReader, "getTrackingRecordPool">;

/** The section's values read before the statement. */
export interface PolicyInputs {
  readonly circuit: TransferKeyCircuit;
  readonly withdrawals: readonly PolicyWithdrawal[];
  readonly splWithdrawalOwners: readonly Bytes32[];
  /** Zero rows off a policy. */
  readonly table: PolicyTableProofInputs;
  /** Zero off a policy, the gate of every rule. */
  readonly policyHash: Bytes32;
  /** Bound while thresholds are active. */
  readonly own?: BoundRoot;
  readonly curator?: BoundRoot;
  /** Absent is the unopened pool of a key whose queries are all off. */
  readonly ownPool?: RecordPool;
  readonly curatorPool?: RecordPool;
  /** At the key's owner rows, zero rows last. */
  readonly rows: readonly Bytes32[];
  readonly senderEntries: readonly PolicyOwnerEntry[];
  /** The output slots then the withdrawals, the request pads them to the key. */
  readonly ownerEntries: readonly PolicyOwnerEntry[];
  readonly assetEntries: readonly PolicySubjectEntry[];
  /** One per published input slot, the request pads them to the key's input class past the payments. */
  readonly inputAssetEntries: readonly PolicySubjectEntry[];
  readonly publicAssetEntries: readonly number[];
  /** Every rail reads it. */
  readonly trackingBound: BoundRoot;
  readonly tracking: TrackingProofInputs;
  /** The statement's proven bits, zero while thresholds are off. */
  readonly approvalMask: number;
  /** Empty while the ring reads no own records, the circuit then bounds no outflow. */
  readonly chargedOutflows: readonly OwnerDebit[];
}

/** What the request reads beside the section, Rust `PolicyProving`. */
export interface PolicyProving {
  readonly ringId: Bytes32;
  readonly publicSlots: PublicSlots;
}

/** From the owner's `RingAddress` or `RingKeys.listSalt`. */
export interface RingListSalt {
  readonly owner: Bytes32;
  readonly salt: Bytes32;
}

/** Read before any record opens. */
export interface PolicyDemand {
  readonly withdrawals: readonly PolicyWithdrawal[];
  readonly splWithdrawalOwners: readonly Bytes32[];
  /** Taken at every subject's own record, a salted owner counts its key. */
  readonly pools: PolicyPoolCapacity;
}

export type PolicyDemandInput = Readonly<{
  tokenOwnerHint?: Address;
  client: PolicyReadClient;
  config: RingPolicy;
  rail: RingRail;
  /** Live and padded rows alike, a zero row opens nothing. */
  rows: readonly Bytes32[];
  proofInputs: SppProofInputs;
  publicSlots: PublicSlots;
  listSalts: readonly RingListSalt[];
}>;

export type PolicyReadInput = PolicyDemandInput &
  Readonly<{
    ringProgramId: Address;
    /** Clear on the hidden sender rail, its input 0 owner refuses a zero key. */
    publicOwners: boolean;
    circuit: TransferKeyCircuit;
    demand: PolicyDemand;
  }>;

const ABSENT_ENTRY: PolicySubjectEntry = Object.freeze({ own: 0, curator: 0 });
const ABSENT_OWNER: PolicyOwnerEntry = Object.freeze({
  ...ABSENT_ENTRY,
  tracking: 0,
  listSalt: ZERO_32,
  ownSalted: 0,
  curatorSalted: 0,
});
/** A subject when nothing live opens a row, it brackets under the sentinel or holds its own leaf. */
const PADDING_SUBJECT = Uint8Array.from({ length: 32 }, (_, at) => (at === 31 ? 1 : 0)) as Bytes32;

/** Set on a ring with an own policy registry off the delegate rail, independent of `policy_hash`. */
export function thresholdsActive(config: Pick<RingPolicy, "records">, rail: RingRail): boolean {
  return !isDelegateRail(rail) && !equalBytes(addressBytes(config.records, "records"), ZERO_32);
}

/** The withdrawal rows a key must hold, the program reads none on a rail with no policy root. */
export function policyLegs(
  config: Pick<RingPolicy, "records" | "hasPolicy">,
  rail: RingRail,
  transfers: readonly Pick<SettlementTransfer, "isDeposit">[],
): number {
  return readsPolicyRoot(config, rail)
    ? transfers.filter((transfer) => !transfer.isDeposit).length
    : 0;
}

/** Rust `RootRead::transfer` is not `None`. */
export function readsPolicyRoot(
  config: Pick<RingPolicy, "records" | "hasPolicy">,
  rail: RingRail,
): boolean {
  return !isDelegateRail(rail) && (config.hasPolicy || thresholdsActive(config, rail));
}

interface PolicySubjects {
  readonly pinned?: PinnedPolicy;
  readonly view?: SourceView;
  readonly liveRows: readonly Bytes32[];
  /** By output slot, undefined on a dummy. */
  readonly owners: readonly (Bytes32 | undefined)[];
  readonly assets: readonly (Bytes32 | undefined)[];
  /** By published input slot, undefined on a dummy or an address slot and off a policy. */
  readonly inputAssets: readonly (Bytes32 | undefined)[];
  /** Screened owners, empty off a policy. */
  readonly ownerMembers: readonly Bytes32[];
  readonly assetMembers: readonly Bytes32[];
  readonly publicAssets: readonly Bytes32[];
  /** Live rows and ring output owners, any other owner only under a salted list, Go `resolveOwner`. */
  readonly trackingMembers: readonly Bytes32[];
}

function policySubjects(
  input: PolicyDemandInput,
  withdrawals: readonly PolicyWithdrawal[],
): PolicySubjects {
  const { config, rail, proofInputs } = input;
  const pinned = config.hasPolicy && !isDelegateRail(rail) ? pinnedPolicy(config) : undefined;
  const view = pinned === undefined ? undefined : policySourceView(pinned.sources);
  const liveRows = input.rows.filter((row) => !isZero(row));
  const { outputs } = proofInputs;
  const owners = outputs.map((output) =>
    output.ownerAddress?.signingPublicKey.ownerProofInputHash(),
  );
  const assets = outputs.map((output) =>
    output.isDummy() ? undefined : memberOfAsset(output.asset),
  );
  // Only the rules read an input's asset, so the thresholds alone open none.
  const inputAssets = publishedNotes(proofInputs).map((spent) =>
    pinned === undefined || inputClassOf(spent) !== InputClass.note
      ? undefined
      : memberOfAsset(spent.utxo.asset),
  );
  const ownerMembers =
    pinned === undefined
      ? []
      : firstSeen([...liveRows, ...owners, ...withdrawals.map((leg) => leg.owner)]);
  const ringOwners = outputs.map((output) =>
    output.ringProgramId === undefined
      ? undefined
      : output.ownerAddress?.signingPublicKey.ownerProofInputHash(),
  );
  return {
    ...(pinned === undefined ? {} : { pinned }),
    ...(view === undefined ? {} : { view }),
    liveRows,
    owners,
    assets,
    inputAssets,
    ownerMembers,
    assetMembers: firstSeen([...assets, ...withdrawals.map((leg) => leg.asset), ...inputAssets]),
    publicAssets: input.publicSlots.assets.filter((asset) => !isZero(asset)),
    trackingMembers: firstSeen([
      ...liveRows,
      ...ringOwners,
      ...(view !== undefined && view.salted !== 0 ? ownerMembers : []),
    ]),
  };
}

/** The members each pool opens, Go `resolveSubjects`. */
function poolMembers(
  subjects: PolicySubjects,
  saltedKeys: readonly Bytes32[],
): Readonly<{ own: readonly Bytes32[]; curator: readonly Bytes32[] }> {
  const { view, ownerMembers, assetMembers, publicAssets, pinned } = subjects;
  return {
    own: firstSeen([
      ...ownerMembers,
      ...assetMembers,
      ...publicAssets,
      ...(view?.saltedOwn === true ? saltedKeys : []),
    ]),
    curator:
      pinned?.curator === undefined
        ? []
        : firstSeen([
            ...(view?.publicForeign === true ? ownerMembers : []),
            ...assetMembers,
            ...(view?.saltedCurated === true ? saltedKeys : []),
          ]),
  };
}

/** A ring reading no salted list discloses no salt to a relay. */
export function relayListSalts(
  config: RingPolicy,
  salts: readonly RingListSalt[],
): readonly RingListSalt[] {
  if (!config.hasPolicy) return [];
  return policySourceView(pinnedPolicy(config).sources).salted === 0 ? [] : salts;
}

function saltsByOwner(salts: readonly RingListSalt[]): ReadonlyMap<string, Bytes32> {
  return new Map(salts.map(({ owner, salt }) => [bytesKey(owner), salt]));
}

/** The withdrawals and the pools a key must hold, a salted read takes a row beside the public one. */
export async function policyDemand(
  input: PolicyDemandInput,
  context?: RequestContext,
): Promise<PolicyDemand> {
  const { client, config, rail, proofInputs } = input;
  const read = readsPolicyRoot(config, rail)
    ? await readPolicyWithdrawals(
        client,
        proofInputs.externalData.interfaceTransfers,
        input.tokenOwnerHint,
        context,
      )
    : { withdrawals: [], splWithdrawalOwners: [] };
  const subjects = policySubjects(input, read.withdrawals);
  const salts = saltsByOwner(input.listSalts);
  const saltedKeys =
    subjects.view === undefined || subjects.view.salted === 0
      ? []
      : subjects.ownerMembers.flatMap((member) => {
          const salt = salts.get(bytesKey(member));
          return salt === undefined ? [] : [privateListKey(member, salt)];
        });
  const members = poolMembers(subjects, saltedKeys);
  return Object.freeze({
    withdrawals: read.withdrawals,
    splWithdrawalOwners: read.splWithdrawalOwners,
    pools: Object.freeze({
      own: members.own.length,
      curator: members.curator.length,
      tracking: subjects.trackingMembers.length,
    }),
  });
}

/** Every record the key opens, the rules admitted under a written policy, a delegate reads tracking alone. */
export async function readPolicy(
  input: PolicyReadInput,
  context?: RequestContext,
): Promise<PolicyInputs> {
  const { client, config, proofInputs, circuit, rail, ringProgramId, demand } = input;
  const { withdrawals } = demand;
  const subjects = policySubjects(input, withdrawals);
  const { pinned, view, liveRows, owners, assets, inputAssets } = subjects;
  const screening = pinned !== undefined;
  const { trackingBound, tracking, rowOf, trackingEntry } = await readTracking(
    input,
    subjects,
    context,
  );
  const base = {
    circuit,
    withdrawals: Object.freeze([]) as readonly PolicyWithdrawal[],
    splWithdrawalOwners: Object.freeze([]) as readonly Bytes32[],
    table: emptyTable(),
    policyHash: ZERO_32,
    rows: input.rows,
    senderEntries: Object.freeze(input.rows.map(() => ABSENT_OWNER)),
    ownerEntries: Object.freeze([]) as readonly PolicyOwnerEntry[],
    assetEntries: Object.freeze([]) as readonly PolicySubjectEntry[],
    inputAssetEntries: Object.freeze([]) as readonly PolicySubjectEntry[],
    publicAssetEntries: Object.freeze(Array.from({ length: N_PUBLIC_SLOTS }, () => 0)),
    trackingBound,
    tracking,
    approvalMask: 0,
    chargedOutflows: Object.freeze([]) as readonly OwnerDebit[],
  };
  if (!readsPolicyRoot(config, rail)) return Object.freeze(base);
  const own = await fetchBoundRoot({ client, ringProgramId, registry: config.records }, context);
  const curatorRoot =
    pinned?.curator === undefined
      ? undefined
      : await fetchBoundRoot({ client, ringProgramId, registry: pinned.curator }, context);
  const salts = saltsByOwner(input.listSalts);
  const anySalted = view !== undefined && view.salted !== 0;
  const saltOf = new Map(
    (anySalted ? subjects.ownerMembers : []).flatMap((member) => {
      const salt = enrolledSalt(member, rowOf(member), salts);
      return salt === undefined ? [] : [[bytesKey(member), salt] as const];
    }),
  );
  const keyOf = new Map(
    [...saltOf].map(([owner, salt]) => {
      const member = subjects.ownerMembers.find((candidate) => bytesKey(candidate) === owner);
      return [owner, privateListKey(member as Bytes32, salt)] as const;
    }),
  );
  const members = poolMembers(subjects, [...keyOf.values()]);
  const capacity = transferPoolCapacity(circuit);
  const ownMembers = members.own.length === 0 ? [PADDING_SUBJECT] : members.own;
  const ownPool = await readRecordPool(
    { client, root: own, members: ownMembers, openings: capacity.own },
    context,
  );
  const curatorPool =
    curatorRoot === undefined
      ? undefined
      : await readRecordPool(
          {
            client,
            root: curatorRoot,
            members: members.curator.length === 0 ? [PADDING_SUBJECT] : members.curator,
            openings: capacity.curator,
          },
          context,
        );
  const ownReads = subjectReads(ownMembers, ownPool.reads);
  const curatorReads =
    curatorPool === undefined ? undefined : subjectReads(members.curator, curatorPool.reads);
  const subject = (pool: SubjectReads, member: Bytes32 | undefined): number =>
    member === undefined ? 0 : (pool.get(bytesKey(member))?.index ?? 0);
  // A curator query reads the subject at the same index, index 0 without a curator pool.
  const entry = (member: Bytes32 | undefined): PolicySubjectEntry => ({
    own: subject(ownReads, member),
    curator: curatorReads === undefined ? 0 : subject(curatorReads, member),
  });
  const ownerEntry = (member: Bytes32 | undefined): PolicyOwnerEntry => {
    if (member === undefined || !screening) return ABSENT_OWNER;
    const key = keyOf.get(bytesKey(member));
    return {
      ...entry(member),
      tracking: trackingEntry(member),
      listSalt: saltOf.get(bytesKey(member)) ?? ZERO_32,
      ownSalted: subject(ownReads, key),
      curatorSalted: curatorReads === undefined ? 0 : subject(curatorReads, key),
    };
  };
  const recordLists = (member: Bytes32 | undefined): RecordLists => {
    const on = (reads: SubjectReads | undefined, read: Bytes32 | undefined): bigint =>
      read === undefined ? 0n : (reads?.get(bytesKey(read))?.read.record()?.lists ?? 0n);
    const key = member === undefined ? undefined : keyOf.get(bytesKey(member));
    const foreign = BigInt(view?.foreign ?? 0);
    return Object.freeze({
      own: on(ownReads, member),
      curator: on(curatorReads, member),
      salted: (on(ownReads, key) & ~foreign) | (on(curatorReads, key) & foreign),
    });
  };
  const policyOf = (asset: Bytes32): MintPolicy =>
    ownReads.get(bytesKey(asset))?.read.record()?.mintPolicy ?? EMPTY_MINT_POLICY;
  const padding = <T>(zero: T): readonly T[] =>
    Array.from({ length: circuit.outputs - owners.length }, () => zero);
  const spent = spentNotes(proofInputs);
  if (pinned !== undefined) {
    const sources = pinned.sources;
    const live = proofInputs.outputs.flatMap((output, slot) =>
      output.isDummy() ? [] : [{ output, slot }],
    );
    const ringInputs = spent.filter((note) => note.ring);
    const payments = [
      ...live.map(({ output, slot }) => ({
        ring: output.ringProgramId !== undefined,
        owner: owners[slot] ?? ZERO_32,
        asset: memberOfAsset(output.asset),
        amount: output.amount,
        ownerLists: recordLists(owners[slot]),
        assetLists: recordLists(assets[slot]),
        mintPolicy: policyOf(memberOfAsset(output.asset)),
      })),
      ...withdrawals.map((leg) => ({
        ...leg,
        ring: false,
        ownerLists: recordLists(leg.owner),
        assetLists: recordLists(leg.asset),
        mintPolicy: policyOf(leg.asset),
      })),
    ];
    // A co-owner who receives nothing is screened, every row passes the sender rules. Payments
    // read once with or without a row, a dummy sender would hold a deposit to sender rules.
    const refusal =
      evaluateSenders(pinned.table, sources, liveRows.map(recordLists)) ??
      evaluatePayments(pinned.table, sources, { ringInputs, outputs: payments }) ??
      evaluateInputAssets(
        pinned.table,
        sources,
        inputAssets.flatMap((asset, input) =>
          asset === undefined ? [] : [{ input, lists: recordLists(asset) }],
        ),
      );
    if (refusal !== undefined)
      throw ruleUnsatisfied(
        refusal,
        live.map(({ slot }) => slot),
      );
  }
  return Object.freeze({
    ...base,
    withdrawals,
    splWithdrawalOwners: demand.splWithdrawalOwners,
    ...(pinned === undefined
      ? {}
      : {
          table: policyTableProofInputs(pinned.table, pinned.sources),
          policyHash: pinned.policyHash,
        }),
    own,
    ...(curatorRoot === undefined ? {} : { curator: curatorRoot }),
    ownPool: ownPool.pool,
    ...(curatorPool === undefined ? {} : { curatorPool: curatorPool.pool }),
    senderEntries: Object.freeze(
      input.rows.map((row) => (isZero(row) ? ABSENT_OWNER : ownerEntry(row))),
    ),
    ownerEntries: Object.freeze([
      ...owners.map(ownerEntry),
      ...padding(ABSENT_OWNER),
      ...withdrawals.map((leg) => ownerEntry(leg.owner)),
    ]),
    assetEntries: Object.freeze([
      ...assets.map((asset) => entry(asset)),
      ...padding(ABSENT_ENTRY),
      ...withdrawals.map((leg) => entry(leg.asset)),
    ]),
    inputAssetEntries: Object.freeze(inputAssets.map((asset) => entry(asset))),
    publicAssetEntries: Object.freeze(
      input.publicSlots.assets.map((asset) => subject(ownReads, asset)),
    ),
    ...transferOutflows({
      rows: liveRows,
      proofInputs,
      publicSlots: input.publicSlots,
      policyOf,
    }),
  });
}

/** A proven absent row is the one skip, a present row forces its salt, Go `resolveOwner`. */
export function enrolledSalt(
  member: Bytes32,
  row: TrackingRecord | undefined,
  salts: ReadonlyMap<string, Bytes32>,
): Bytes32 | undefined {
  if (row === undefined) return undefined;
  const salt = salts.get(bytesKey(member));
  if (salt === undefined)
    throw new RingError("RING_LIST_SALT_MISSING", { details: { member: bytesKey(member) } });
  if (!equalBytes(listTagOf(salt), row.listTag))
    throw new RingError("RING_ADDRESS_MISMATCH", {
      details: { field: "listSalt", member: bytesKey(member) },
    });
  return salt;
}

/** Opens every tracking member once under the newest root, refusing what the predicates refuse. */
async function readTracking(
  input: PolicyReadInput,
  subjects: PolicySubjects,
  context: RequestContext | undefined,
): Promise<
  Pick<PolicyInputs, "trackingBound" | "tracking"> &
    Readonly<{
      rowOf: (member: Bytes32) => TrackingRecord | undefined;
      trackingEntry: (member: Bytes32 | undefined) => number;
    }>
> {
  const { client, config, circuit, proofInputs } = input;
  const trackingBound = await newestTrackingRoot(
    { client, trackingRegistry: config.tracking, ring: input.ringProgramId },
    context,
  );
  const ringOutputs = proofInputs.outputs.map((output) =>
    output.ringProgramId === undefined || output.ownerAddress === undefined ? undefined : output,
  );
  const outputOwners = ringOutputs.map((output) =>
    output?.ownerAddress?.signingPublicKey.ownerProofInputHash(),
  );
  const members =
    subjects.trackingMembers.length === 0 ? [PADDING_SUBJECT] : subjects.trackingMembers;
  const openings = transferPoolCapacity(circuit).tracking;
  const served = await client.getTrackingRecordPool(
    { registry: config.tracking, members, expectedRoot: trackingBound.root, openings },
    context,
  );
  const pool = verifyTrackingPool({ pool: served, root: trackingBound.root, members, openings });
  const position = new Map(members.map((member, index) => [bytesKey(member), index]));
  const rowOf = (member: Bytes32): TrackingRecord | undefined =>
    pool.rows[position.get(bytesKey(member)) ?? -1];
  checkInputKeys({
    inputs: publishedNotes(proofInputs),
    rail: input.rail,
    publicOwners: input.publicOwners,
    rowOf,
  });
  const spenders = publishedNotes(proofInputs).map((note) => note.utxo.owner);
  const viewingKeys = await readPayeeViewingKeys(
    {
      client,
      trackingRegistry: config.tracking,
      owners: ringOutputs.flatMap((output) => {
        const owner = output?.ownerAddress;
        return owner === undefined ||
          rowOf(owner.signingPublicKey.ownerProofInputHash()) === undefined ||
          spenders.some((spender) => owner.signingPublicKey.equals(spender))
          ? []
          : [owner];
      }),
    },
    context,
  );
  checkOutputKeys({
    outputs: ringOutputs,
    rowOf,
    viewingKeyOf: (member) => viewingKeys.get(bytesKey(member)),
    spenders,
  });
  const trackingEntry = (member: Bytes32 | undefined): number =>
    member === undefined || isZero(member) ? 0 : (position.get(bytesKey(member)) ?? 0);
  return {
    trackingBound,
    tracking: Object.freeze({
      trackingRoot: trackingBound.root,
      trackingPool: Object.freeze({
        records: pool.records,
        canopy: pool.canopy,
        paths: pool.paths,
        subjects: pool.subjects,
      }),
      rowEntries: Object.freeze(input.rows.map(trackingEntry)),
      outputEntries: Object.freeze([
        ...outputOwners.map(trackingEntry),
        ...Array.from({ length: circuit.outputs - outputOwners.length }, () => 0),
      ]),
    }),
    rowOf,
    trackingEntry,
  };
}

/** A zero key waives only the key equality, a delegate moves it with no row and a hidden owner refuses it. */
export function checkInputKeys(
  input: Readonly<{
    inputs: readonly ProofInputUtxo[];
    rail: RingRail;
    publicOwners: boolean;
    rowOf: (member: Bytes32) => TrackingRecord | undefined;
  }>,
): void {
  const { inputs, rail, rowOf } = input;
  const hidden =
    rail === "anonymous" && !input.publicOwners
      ? inputs[0]?.utxo.owner.ownerProofInputHash()
      : undefined;
  for (const spent of inputs) {
    if (spent.isDummy()) continue;
    const owner = spent.utxo.owner.ownerProofInputHash();
    if (spent.utxo.ringProgramId === undefined) continue;
    if (equalBytes(spent.nullifierPublicKey, ZERO_NULLIFIER_PK)) {
      if (hidden !== undefined && equalBytes(owner, hidden))
        throw new RingError("RING_ZERO_KEY_INPUT_UNNAMED", {
          details: { owner: bytesKey(owner) },
        });
      continue;
    }
    const row = rowOf(owner);
    if (row === undefined)
      throw new RingError("RING_ADDRESS_NOT_ENROLLED", { details: { member: bytesKey(owner) } });
    if (!equalBytes(row.nullifierPk, spent.nullifierPublicKey))
      throw new RingError("RING_ADDRESS_MISMATCH", {
        details: { field: "nullifierPk", member: bytesKey(owner) },
      });
  }
}

/** Zero key recipients require absence at the accepted tracking root. */
export function checkOutputKeys(
  input: Readonly<{
    outputs: readonly (ProofOutputUtxo | undefined)[];
    rowOf: (member: Bytes32) => TrackingRecord | undefined;
    /** The key the owner's authorization held when read, `readPayeeViewingKeys`. */
    viewingKeyOf: (member: Bytes32) => Bytes32 | undefined;
    /** A spending owner holds every key it ever enrolled. */
    spenders: readonly ShieldedPublicKey[];
  }>,
): void {
  for (const output of input.outputs) {
    const owner = output?.ownerAddress;
    if (owner === undefined) continue;
    const member = owner.signingPublicKey.ownerProofInputHash();
    const row = input.rowOf(member);
    checkOutputKey({
      member,
      nullifierPk: owner.nullifierPublicKey,
      row,
    });
    if (
      row === undefined ||
      input.spenders.some((spender) => owner.signingPublicKey.equals(spender))
    )
      continue;
    const current = input.viewingKeyOf(member);
    if (current === undefined)
      throw new RingError("RING_TRACKING_INVALID", { details: { reason: "authorization" } });
    if (!equalBytes(current, owner.viewingPublicKey.u())) throw staleViewingKey(member);
  }
}

/**
 * Each payee's viewing key from its authorization, keyed by member.
 *
 * Reads at `confirmed` as `resolveRingRecipient` does. A rotation that lands after the read leaves the
 * payment sealed to the key read, no program check reads a viewing key.
 */
export async function readPayeeViewingKeys(
  input: Readonly<{
    client: AuthorizationReader;
    trackingRegistry: Address;
    owners: readonly ShieldedAddress[];
  }>,
  context?: RequestContext,
): Promise<ReadonlyMap<string, Bytes32>> {
  const distinct = new Map(
    input.owners.map(
      (owner) => [bytesKey(owner.signingPublicKey.ownerProofInputHash()), owner] as const,
    ),
  );
  return new Map(
    await Promise.all(
      [...distinct].map(
        async ([member, owner]) =>
          [
            member,
            await enrolledViewingKey(
              { client: input.client, trackingRegistry: input.trackingRegistry, owner },
              context,
            ),
          ] as const,
      ),
    ),
  );
}

function checkOutputKey(
  input: Readonly<{
    member: Bytes32;
    nullifierPk: Bytes32;
    row: TrackingRecord | undefined;
  }>,
): void {
  const { member, nullifierPk, row } = input;
  if (equalBytes(nullifierPk, ZERO_NULLIFIER_PK)) {
    if (row !== undefined) throw new RingError("RING_RECIPIENT_ENROLLED");
    return;
  }
  if (row === undefined) throw new RingError("RING_RECIPIENT_NOT_ENROLLED");
  if (!equalBytes(row.nullifierPk, nullifierPk))
    throw new RingError("RING_ADDRESS_MISMATCH", {
      details: { field: "nullifierPk", member: bytesKey(member) },
    });
}

function staleViewingKey(member: Bytes32): RingError {
  return new RingError("RING_RECIPIENT_VIEWING_KEY_STALE", {
    details: { member: bytesKey(member) },
  });
}

/** The roots the statement binds, zero where the program reads none, Rust `PolicyInputs::roots`. */
export function policyRoots(policy: PolicyInputs): TransferRoots {
  return Object.freeze({
    policyHash: policy.policyHash,
    ownRoot: policy.own?.root ?? ZERO_32,
    curatorRoot: policy.curator?.root ?? ZERO_32,
    trackingRoot: policy.tracking.trackingRoot,
  });
}

export function screened(policy: PolicyInputs): boolean {
  return !isZero(policy.policyHash);
}

/** The section at the key's capacities, an unopened pool where no root is bound, Rust `PolicyInputs::params`. */
export function policyParams(policy: PolicyInputs, proving: PolicyProving): PolicyProofInputs {
  const capacity = transferPoolCapacity(policy.circuit);
  const withdrawalSlots = policy.circuit.withdrawals;
  const slots = policy.circuit.outputs + withdrawalSlots;
  const pad = <T>(values: readonly T[], length: number, zero: T): readonly T[] =>
    Object.freeze([...values, ...Array.from({ length: length - values.length }, () => zero)]);
  const roots = policyRoots(policy);
  return Object.freeze({
    withdrawalCount: policy.withdrawals.length,
    withdrawalHash: policyWithdrawalHash(policy.withdrawals),
    withdrawals: pad(policy.withdrawals, withdrawalSlots, {
      owner: ZERO_32,
      asset: ZERO_32,
      amount: 0n,
    }),
    policyHash: roots.policyHash,
    ringId: proving.ringId,
    ownRoot: roots.ownRoot,
    curatorRoot: roots.curatorRoot,
    publicAssets: proving.publicSlots.assets,
    publicAmounts: publicAmountFields(proving.publicSlots),
    publicGross: publicGrossFields(proving.publicSlots),
    ...policy.table,
    ownPool: policy.ownPool ?? unopenedRecordPool(capacity.own),
    curatorPool: policy.curatorPool ?? unopenedRecordPool(capacity.curator),
    senderEntries: policy.senderEntries,
    ownerEntries: pad(policy.ownerEntries, slots, ABSENT_OWNER),
    assetEntries: [
      ...pad(policy.assetEntries, slots, ABSENT_ENTRY),
      ...pad(policy.inputAssetEntries, policy.circuit.class, ABSENT_ENTRY),
    ],
    publicAssetEntries: policy.publicAssetEntries,
  });
}

/** Each owner's charged outflow and the proven mask, a nonzero cap refuses a larger charged outflow, no record reads no threshold. */
export function transferOutflows(
  input: Readonly<{
    rows: readonly Bytes32[];
    proofInputs: SppProofInputs;
    publicSlots: PublicSlots;
    policyOf: (asset: Bytes32) => MintPolicy;
  }>,
): Readonly<{ chargedOutflows: readonly OwnerDebit[]; approvalMask: number }> {
  const { proofInputs, publicSlots, policyOf } = input;
  const debitOutputs = slotOutputs(proofInputs);
  const publicGross = grossOf(publicSlots);
  const flows = ownerDebits({
    senders: input.rows,
    assets: [
      ...debitOutputs.map((output) => output.asset),
      ...publicGross.map((slot) => slot.asset),
      ...publicSlots.assets.filter((asset) => !isZero(asset)),
    ],
    inputs: spentNotes(proofInputs),
    outputs: debitOutputs,
    publicGross,
  });
  for (const flow of flows) {
    const { cap } = policyOf(flow.asset);
    if (cap !== 0n && flow.chargedOutflow > cap)
      throw new RingError("RING_OUTFLOW_CAP_EXCEEDED", {
        details: { cap: cap.toString(), chargedOutflow: flow.chargedOutflow.toString() },
      });
  }
  return { chargedOutflows: flows, approvalMask: approvalMask({ flows, publicGross, policyOf }) };
}

/**
 * The wallet and the relay read one layout, one slot per output of the key and every public slot in
 * statement order, rows are the inputs' owners whatever their padding, Rust `approval_totals_of`.
 */
export function approvalTotalsOf(proofInputs: SppProofInputs, outputSlots: number): ApprovalTotals {
  const slots = publicSlots(proofInputs.externalData.interfaceTransfers);
  const inputs = spentNotes(proofInputs);
  const outputs = slotOutputs(proofInputs);
  return ApprovalTotals.new({
    transfer: {
      senders: inputs.map((note) => note.owner),
      assets: [],
      inputs,
      outputs,
      publicGross: grossOf(slots),
    },
    slotAssets: Array.from({ length: outputSlots }, (_, slot) => {
      const output = proofInputs.outputs[slot];
      return output === undefined || output.isDummy() ? undefined : assetField(output.asset);
    }),
    publicSlots: slots.assets.map((asset, slot) => ({ asset, gross: slots.gross[slot] ?? 0n })),
  });
}

/** Rust `charged_outflows_of`, the rows the relay reads from the same inputs. */
export function chargedOutflowsOf(proofInputs: SppProofInputs): readonly OwnerDebit[] {
  const inputs = spentNotes(proofInputs);
  const outputs = slotOutputs(proofInputs);
  const publicGross = grossOf(publicSlots(proofInputs.externalData.interfaceTransfers));
  return ownerDebits({
    senders: inputs.map((note) => note.owner),
    assets: [...outputs, ...inputs, ...publicGross].map((entry) => entry.asset),
    inputs,
    outputs,
    publicGross,
  });
}

function grossOf(slots: PublicSlots): readonly PublicGross[] {
  return slots.assets.flatMap((asset, slot) => {
    const gross = slots.gross[slot] ?? 0n;
    return gross === 0n ? [] : [{ asset, gross }];
  });
}

/** The published input slots, compact padding left out. */
export function publishedNotes(proofInputs: SppProofInputs): readonly ProofInputUtxo[] {
  return proofInputs.inputUtxos.filter((input) => !input.isCompact());
}

/** Live notes, `ring` clear on a default-ring note, held for debit and no same-ring input. */
function spentNotes(proofInputs: SppProofInputs): readonly (DebitInput & { ring: boolean })[] {
  return publishedNotes(proofInputs)
    .filter((input) => inputClassOf(input) === InputClass.note)
    .map((input) => ({
      owner: input.utxo.owner.ownerProofInputHash(),
      asset: assetField(input.utxo.asset),
      amount: input.utxo.amount,
      ring: input.utxo.ringProgramId !== undefined,
    }));
}

/** An exit carries no ring id, it counts as leaving. */
function slotOutputs(proofInputs: SppProofInputs): readonly DebitOutput[] {
  return proofInputs.outputs.flatMap((output) => {
    const owner = output.ownerAddress;
    return owner === undefined
      ? []
      : [
          {
            owner: owner.signingPublicKey.ownerProofInputHash(),
            asset: assetField(output.asset),
            amount: output.amount,
            ring: output.ringProgramId !== undefined,
          },
        ];
  });
}

/** The zero table, every gate reads it switched off. */
function emptyTable(): PolicyTableProofInputs {
  return Object.freeze({
    sources: Object.freeze(
      Array.from({ length: RING_SOURCE_SLOTS }, () =>
        Object.freeze({ listId: 0, registry: ZERO_32 }),
      ),
    ),
    salted: 0,
    policyLen: 0,
    rules: Object.freeze(Array.from({ length: RING_RULE_SLOTS }, () => ZERO_32)),
  });
}

/** The rule and the subject a refusal names, outputs by their SPP slot. */
function ruleUnsatisfied(refusal: RuleRefusal, live: readonly number[]): RingError {
  const { subject } = refusal;
  const reason = { reason: refusal.kind, ruleIndex: refusal.rule, subject: subject.kind };
  return new RingError("RING_POLICY_RULE_UNSATISFIED", {
    details:
      subject.kind === "sender"
        ? reason
        : subject.kind === "inputAsset"
          ? { ...reason, inputIndex: subject.input }
          : { ...reason, slotIndex: live[subject.output] ?? -1 },
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
