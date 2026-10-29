import { type RingMemberOpening, type RingRecordReader, type StorageRoot } from "./ports.js";
import { type PresentRecordOpening } from "./prover/types.js";
import { MAX_RING_MEMBER_BATCH } from "../protocol/indexer/indexer-limits.js";
import type { ChainReader } from "@heliuslabs/zolana/client";
import { waitForProjection, equalBytes } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import type { ShieldedAddress } from "@heliuslabs/zolana/keypair";

import {
  mirrorCurrentRoot,
  registryCurrentRoot,
  rootMirror,
  type RingPolicy,
  type RootMirrorKind,
} from "../protocol/codec/ring-codecs.js";
import {
  fetchRingMemberRegistry,
  fetchRingPolicy,
  fetchRingProgramConfig,
} from "../protocol/membership/config.js";
import { RingError } from "../protocol/error.js";
import {
  MemberOpeningRead,
  ownerEscrowed,
  verifyRecordPool,
} from "../protocol/membership/member-opening.js";
import type { RecordPool } from "../protocol/membership/member-registry.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "./projection.js";

export type RingRecordReadClient = Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getStorageMemberOpenings">;

/** A storage root the ring's policy mirrors, named by the revision the program reads it back by. */
export interface BoundRoot {
  readonly ringProgramId: Address;
  readonly mirror: RootMirrorKind;
  readonly registry: Address;
  readonly revision: bigint;
  readonly root: Bytes32;
}

/** The newest root `mirror` copied from `registry`, refused when the mirror holds another registry. */
export function boundRoot(
  input: Readonly<{
    ringProgramId: Address;
    policy: RingPolicy;
    mirror: RootMirrorKind;
    registry: Address;
  }>,
): BoundRoot {
  const current = mirrorCurrentRoot(rootMirror(input.policy, input.mirror), input.registry);
  return Object.freeze({
    ringProgramId: input.ringProgramId,
    mirror: input.mirror,
    registry: input.registry,
    revision: current.revision,
    root: current.hash,
  });
}

/** The newest root of the ring's own records. */
export function ownRoot(ringProgramId: Address, policy: RingPolicy): BoundRoot {
  return boundRoot({ ringProgramId, policy, mirror: "own", registry: policy.records });
}

/** A member's present record under the ring's newest own root. */
export interface RegisteredRecord {
  readonly root: BoundRoot;
  readonly record: PresentRecordOpening;
  /** `hash_bytes` of the escrowed key ciphertext, the record's escrow key binds it. */
  readonly ctHash: Bytes32;
}

/** Members' records under the ring's newest own root, in member order, Rust `MemberRecords::read`. */
export async function readMemberRecords(
  input: Readonly<{
    client: RingRecordReadClient;
    ringProgramId: Address;
    members: readonly Bytes32[];
  }>,
  context?: RequestContext,
): Promise<readonly MemberOpeningRead[]> {
  return (await readOwnRecords(input, context)).reads;
}

/** @internal `readMemberRecords` with the root the reads verify under. */
export function readOwnRecords(
  input: Readonly<{
    client: RingRecordReadClient;
    ringProgramId: Address;
    members: readonly Bytes32[];
  }>,
  context?: RequestContext,
): Promise<Readonly<{ root: BoundRoot; reads: readonly MemberOpeningRead[] }>> {
  return waitForProjection(
    async (attempt) => {
      const policy = await fetchRingPolicy(input.client, input.ringProgramId, attempt);
      const root = ownRoot(input.ringProgramId, policy);
      const reads = await readMemberOpenings(
        { client: input.client, root, members: input.members },
        attempt,
      );
      return { root, reads };
    },
    MEMBER_REGISTRY_PROJECTION_ERRORS,
    context,
  );
}

/** Under key escrow the first recipient without an escrowed nullifier key is refused, Rust `EscrowedRecipients::check`. */
export async function checkEscrowedRecipients(
  input: Readonly<{
    client: RingRecordReadClient;
    ringProgramId: Address;
    recipients: readonly ShieldedAddress[];
  }>,
  context?: RequestContext,
): Promise<void> {
  const config = await fetchRingProgramConfig(input.client, input.ringProgramId, context);
  if (config.mode !== "confidentialEscrow") return;
  const owners = input.recipients.map((recipient) =>
    recipient.signingPublicKey.ownerProofInputHash(),
  );
  const reads = await readMemberRecords(
    { client: input.client, ringProgramId: input.ringProgramId, members: owners },
    context,
  );
  input.recipients.forEach((recipient, index) => {
    const owner = owners[index];
    if (owner !== undefined) ownerEscrowed(owner, reads[index], recipient.nullifierPublicKey);
  });
}

/** One opening per member in member order, each verified against `root`, Rust `RecordReads::read`. */
export function readMemberOpenings(
  input: Readonly<{
    client: Pick<RingRecordReader, "getStorageMemberOpenings">;
    root: BoundRoot;
    members: readonly Bytes32[];
  }>,
  context?: RequestContext,
): Promise<readonly MemberOpeningRead[]> {
  const { root } = input;
  return openingsInBatches(input.members, root.root, async (members) => {
    const served = await input.client.getStorageMemberOpenings(
      { registry: root.registry, members, expectedRoot: root.root },
      context,
    );
    checkServedRoot(served.root, root, "openings");
    return served.openings;
  });
}

/** A pool verified under its root, with every member's read in member order. */
export interface RecordPoolRead {
  /** Records and subjects repeat cyclically up to the pool capacity. */
  readonly pool: RecordPool;
  readonly reads: readonly MemberOpeningRead[];
}

/** `members` under `root` in one pool of `openings` records. */
export async function readRecordPool(
  input: Readonly<{
    client: Pick<RingRecordReader, "getStorageRecordPool">;
    root: BoundRoot;
    members: readonly Bytes32[];
    openings: number;
  }>,
  context?: RequestContext,
): Promise<RecordPoolRead> {
  const { members, openings, root } = input;
  if (members.length < 1 || members.length > openings)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "poolCapacity" } });
  const served = await input.client.getStorageRecordPool(
    { registry: root.registry, members, expectedRoot: root.root, openings },
    context,
  );
  checkServedRoot(served.root, root, "pool");
  const reads = verifyRecordPool(served, root.root, members, openings);
  const records = cyclic(served.records, openings);
  return Object.freeze({
    pool: Object.freeze({
      records: Object.freeze(records.map(({ record }) => record)),
      canopy: Object.freeze([...served.canopy]),
      paths: Object.freeze(records.map(({ path }) => path)),
      subjects: Object.freeze(
        cyclic(
          members.map((member, index) =>
            Object.freeze({ member, recordIndex: served.subjects[index] ?? 0 }),
          ),
          openings,
        ),
      ),
    }),
    reads,
  });
}

/** The indexer's opening checked against the ring's newest own root. */
export function readRegisteredRecord(
  input: Readonly<{
    client: RingRecordReadClient;
    ringProgramId: Address;
    member: Bytes32;
    /** The nullifier key the record must escrow. */
    escrowed: Bytes32;
  }>,
  context?: RequestContext,
): Promise<RegisteredRecord> {
  return waitForProjection(
    async (attempt) => {
      const policy = await fetchRingPolicy(input.client, input.ringProgramId, attempt);
      const root = ownRoot(input.ringProgramId, policy);
      const [read] = await readMemberOpenings(
        { client: input.client, root, members: [input.member] },
        attempt,
      );
      const escrowed = ownerEscrowed(input.member, read, input.escrowed);
      return Object.freeze({
        root,
        record: Object.freeze({
          kind: "present" as const,
          record: escrowed.record,
          path: escrowed.path,
        }),
        ctHash: escrowed.ctHash,
      });
    },
    MEMBER_REGISTRY_PROJECTION_ERRORS,
    context,
  );
}

/** @internal The member registry's newest root and every member's read under it. */
export async function readNewest(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount"> & Pick<RingRecordReader, "getRingMemberOpenings">;
    ringProgramId: Address;
    members: readonly Bytes32[];
  }>,
  context: RequestContext | undefined,
): Promise<Readonly<{ root: Bytes32; reads: readonly MemberOpeningRead[] }>> {
  const registry = await fetchRingMemberRegistry(input.client, input.ringProgramId, context);
  const { root } = registryCurrentRoot(registry);
  const reads = await openingsInBatches(input.members, root, async (members) => {
    const served = await input.client.getRingMemberOpenings(
      { ringProgramId: input.ringProgramId, members, expectedRoot: root },
      context,
    );
    if (!equalBytes(served.root.root, root))
      throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "openings" } });
    return served.openings;
  });
  return { root, reads };
}

/** An indexer answer under a root or revision other than the bound one is refused. */
function checkServedRoot(served: StorageRoot, bound: BoundRoot, reason: string): void {
  if (!equalBytes(served.root, bound.root) || served.revision !== bound.revision)
    throw new RingError("RING_ROOT_NOT_MIRRORED", {
      details: { reason, registry: bound.registry, revision: served.revision.toString() },
    });
}

async function openingsInBatches(
  members: readonly Bytes32[],
  root: Bytes32,
  fetch: (members: readonly Bytes32[]) => Promise<readonly RingMemberOpening[]>,
): Promise<readonly MemberOpeningRead[]> {
  const reads: MemberOpeningRead[] = [];
  for (let offset = 0; offset < members.length; offset += MAX_RING_MEMBER_BATCH) {
    const chunk = members.slice(offset, offset + MAX_RING_MEMBER_BATCH);
    const openings = await fetch(chunk);
    if (openings.length !== chunk.length)
      throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "openings" } });
    chunk.forEach((member, index) => {
      const opening = openings[index];
      if (opening === undefined)
        throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "openings" } });
      reads.push(MemberOpeningRead.verify(opening, root, member));
    });
  }
  return reads;
}

function cyclic<T>(values: readonly T[], length: number): readonly T[] {
  return Array.from({ length }, (_, index) => values[index % values.length] as T);
}
