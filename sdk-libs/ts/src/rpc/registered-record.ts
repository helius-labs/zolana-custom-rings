import { type RingRecordReader } from "./ports.js";
import { type PresentRecordOpening } from "./prover/types.js";
import { MAX_RING_MEMBER_BATCH } from "../protocol/indexer/indexer-limits.js";
import type { ChainReader } from "@heliuslabs/zolana/client";
import { waitForProjection, equalBytes } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import type { ShieldedAddress } from "@heliuslabs/zolana/keypair";

import { registryCurrentRoot } from "../protocol/codec/ring-codecs.js";
import { fetchRingMemberRegistry, fetchRingProgramConfig } from "../protocol/membership/config.js";
import { RingError } from "../protocol/error.js";
import {
  MemberOpeningRead,
  ownerEscrowed,
  verifyRecordPool,
} from "../protocol/membership/member-opening.js";
import type { RecordPool } from "../protocol/membership/member-registry.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "./projection.js";

export type RingRecordReadClient = Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getRingMemberOpenings">;

/** A member's present record under the registry's newest root. */
export interface RegisteredRecord {
  readonly root: Bytes32;
  /** The root's history slot, the program reads the bound root back through it. */
  readonly index: number;
  readonly record: PresentRecordOpening;
  /** `hash_bytes` of the escrowed key ciphertext, the record's escrow key binds it. */
  readonly ctHash: Bytes32;
}

/** Members' records under the registry's newest root, in member order, Rust `MemberRecords::read`. */
export function readMemberRecords(
  input: Readonly<{
    client: RingRecordReadClient;
    ringProgramId: Address;
    members: readonly Bytes32[];
  }>,
  context?: RequestContext,
): Promise<readonly MemberOpeningRead[]> {
  return waitForProjection(
    async (attempt) => (await readNewest(input, attempt)).reads,
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
export async function readMemberOpenings(
  input: Readonly<{
    client: Pick<RingRecordReader, "getRingMemberOpenings">;
    ringProgramId: Address;
    root: Bytes32;
    members: readonly Bytes32[];
  }>,
  context?: RequestContext,
): Promise<readonly MemberOpeningRead[]> {
  const reads: MemberOpeningRead[] = [];
  for (let offset = 0; offset < input.members.length; offset += MAX_RING_MEMBER_BATCH) {
    const chunk = input.members.slice(offset, offset + MAX_RING_MEMBER_BATCH);
    const response = await input.client.getRingMemberOpenings(
      { ringProgramId: input.ringProgramId, members: chunk, expectedRoot: input.root },
      context,
    );
    if (response.openings.length !== chunk.length || !equalBytes(response.root.root, input.root))
      throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "openings" } });
    chunk.forEach((member, index) => {
      const opening = response.openings[index];
      if (opening === undefined)
        throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "openings" } });
      reads.push(MemberOpeningRead.verify(opening, input.root, member));
    });
  }
  return reads;
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
    client: Pick<RingRecordReader, "getRingRecordPool">;
    ringProgramId: Address;
    root: Bytes32;
    members: readonly Bytes32[];
    openings: number;
  }>,
  context?: RequestContext,
): Promise<RecordPoolRead> {
  const { members, openings } = input;
  if (members.length < 1 || members.length > openings)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "poolCapacity" } });
  const served = await input.client.getRingRecordPool(
    { ringProgramId: input.ringProgramId, members, expectedRoot: input.root, openings },
    context,
  );
  if (!equalBytes(served.root.root, input.root))
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "pool" } });
  const reads = verifyRecordPool(served, input.root, members, openings);
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

/** The indexer's opening checked against the chain's newest root, Rust `MemberMerge::read`. */
export function readRegisteredRecord(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount"> & Pick<RingRecordReader, "getRingMemberRecord">;
    ringProgramId: Address;
    member: Bytes32;
    /** The nullifier key the record must escrow. */
    escrowed: Bytes32;
  }>,
  context?: RequestContext,
): Promise<RegisteredRecord> {
  return waitForProjection(
    async (attempt) => {
      const registry = await fetchRingMemberRegistry(input.client, input.ringProgramId, attempt);
      const { root } = registryCurrentRoot(registry);
      const read = await input.client.getRingMemberRecord(
        {
          ringProgramId: input.ringProgramId,
          member: input.member,
          expectedRoot: root,
          expectedNextIndex: registry.nextIndex,
        },
        attempt,
      );
      const escrowed = ownerEscrowed(
        input.member,
        MemberOpeningRead.verify(read.opening, root, input.member),
        input.escrowed,
      );
      return Object.freeze({
        root,
        index: registry.historyCursor,
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

/** @internal The registry's newest root, its history slot and every member's read under it. */
export async function readNewest(
  input: Readonly<{
    client: RingRecordReadClient;
    ringProgramId: Address;
    members: readonly Bytes32[];
  }>,
  context: RequestContext | undefined,
): Promise<Readonly<{ root: Bytes32; reads: readonly MemberOpeningRead[] }>> {
  const registry = await fetchRingMemberRegistry(input.client, input.ringProgramId, context);
  const { root } = registryCurrentRoot(registry);
  const reads = await readMemberOpenings({ ...input, root }, context);
  return { root, reads };
}

function cyclic<T>(values: readonly T[], length: number): readonly T[] {
  return Array.from({ length }, (_, index) => values[index % values.length] as T);
}
