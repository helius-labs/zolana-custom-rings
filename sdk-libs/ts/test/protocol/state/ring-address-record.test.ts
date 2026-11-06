import { address } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { readFileSync } from "node:fs";

import emptyVector from "../../../../../test-vectors/registry/empty_root.json" with { type: "json" };
import { initializePoseidon } from "@heliuslabs/spr";
import {
  SYSTEM_PROGRAM,
  encodeBase58,
  poseidon,
  solanaOwnerIdentity,
} from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";

import { enrollInstruction } from "../../../src/operations/management/enrollment.js";
import {
  MEMBER_REGISTRY_EMPTY_ROOT,
  SENTINEL_RECORD,
  memberRecordHash,
  quadPathRoot,
} from "../../../src/protocol/membership/member-opening.js";
import { QUAD_HEIGHT } from "../../../src/protocol/membership/member-registry.js";
import {
  TRACKING_EMPTY_ROOT,
  TRACKING_QUAD_HEIGHT,
  TRACKING_SENTINEL,
  decodeTrackingAuthorization,
  trackingEntryChained,
  trackingEntryHash,
  trackingRecordHash,
} from "../../../src/protocol/membership/tracking.js";
import { STORAGE_PROGRAM_ID, trackingAuthorizationPda } from "../../../src/protocol/pda/index.js";
import { withConfirmedReads } from "../../helpers/clients.js";
import { recordTree } from "../../helpers/member-registry.js";

function field(value: string): Bytes32 {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (decoded.length !== 32) throw new RangeError("expected 32 bytes");
  return decoded as Bytes32;
}

function hex(value: Readonly<ArrayLike<number>> | undefined): string {
  return Buffer.from(Uint8Array.from(value ?? [])).toString("hex");
}

/** The tracking fields the core generator writes beside the member registry's. */
const empty = emptyVector as typeof emptyVector &
  Readonly<{ tracking_sentinel: Readonly<{ leaf_hash: string }>; tracking_empty_root: string }>;

const enroll = JSON.parse(
  readFileSync(
    new URL("../../../../../test-vectors/registry/tracking_enroll.json", import.meta.url),
    "utf8",
  ),
) as Readonly<
  Record<
    | "registry"
    | "owner"
    | "account"
    | "member"
    | "ct_hash"
    | "enroll_data"
    | "authorization"
    | "entry_hash"
    | "chain_start"
    | "chain_end",
    string
  > & { bump: number }
>;

const REGISTRY = address(encodeBase58(field(enroll.registry)));
const OWNER = address(encodeBase58(field(enroll.owner)));
const PAYER = address(encodeBase58(new Uint8Array(32).fill(0x77)));
const ACCOUNT = decodeTrackingAuthorization(Uint8Array.from(Buffer.from(enroll.account, "hex")));
const SEAL = {
  nullifierPk: ACCOUNT.nullifierPk,
  listTag: ACCOUNT.listTag,
  ephU: ACCOUNT.ephU,
  ciphertext: ACCOUNT.ciphertext,
};
const ENTRY = {
  member: field(enroll.member),
  nullifierPk: ACCOUNT.nullifierPk,
  ctHash: field(enroll.ct_hash),
  listTag: ACCOUNT.listTag,
};

const UNENROLLED = withConfirmedReads({ getAccount: async () => undefined }) as never;

beforeAll(initializePoseidon);

describe("empty_root.json", () => {
  it("folds the sentinel over the zero subtrees to the registry's first root", () => {
    expect(hex(memberRecordHash(SENTINEL_RECORD))).toBe(empty.sentinel.leaf_hash);
    expect(empty.zero_subtrees).toHaveLength(TRACKING_QUAD_HEIGHT + 1);
    empty.zero_subtrees.slice(1).forEach((node, level) => {
      const below = field(empty.zero_subtrees[level] ?? "");
      expect(hex(poseidon([below, below, below, below]))).toBe(node);
    });
    const siblings = empty.zero_subtrees
      .slice(0, QUAD_HEIGHT)
      .map((node) => [field(node), field(node), field(node)]);
    const root = quadPathRoot({ index: 0, siblings }, memberRecordHash(SENTINEL_RECORD));
    expect(hex(root)).toBe(empty.empty_root);
    expect(hex(MEMBER_REGISTRY_EMPTY_ROOT)).toBe(empty.empty_root);
    expect(hex(recordTree().root)).toBe(empty.empty_root);
  });

  it("folds the tracking sentinel over the same subtrees to the tracking registry's first root", () => {
    const sentinel = trackingRecordHash(TRACKING_SENTINEL);
    expect(hex(sentinel)).toBe(empty.tracking_sentinel.leaf_hash);
    const siblings = empty.zero_subtrees
      .slice(0, TRACKING_QUAD_HEIGHT)
      .map((node) => [field(node), field(node), field(node)]);
    const root = siblings.reduce<Bytes32>(
      (node, level) => poseidon([node, ...level]) as Bytes32,
      sentinel,
    );
    expect(hex(root)).toBe(empty.tracking_empty_root);
    expect(hex(TRACKING_EMPTY_ROOT)).toBe(empty.tracking_empty_root);
  });
});

describe("tracking_enroll.json", () => {
  it("builds the enrollment byte for byte with the program's account order", async () => {
    const instruction = await enrollInstruction(
      {
        payer: PAYER,
        owner: OWNER,
        trackingRegistry: REGISTRY,
        seal: SEAL,
        viewingU: ACCOUNT.viewingU,
      },
      UNENROLLED,
    );
    expect(hex(instruction.data)).toBe(`06${enroll.enroll_data}`);
    expect(instruction.programAddress).toBe(STORAGE_PROGRAM_ID);
    expect(instruction.accounts?.map(({ address: account }) => account)).toEqual([
      PAYER,
      OWNER,
      REGISTRY,
      encodeBase58(field(enroll.authorization)),
      SYSTEM_PROGRAM,
    ]);
  });

  it("appends a first enrollment's proof and refuses another length", async () => {
    const proof = new Uint8Array(192).fill(5);
    const input = {
      payer: PAYER,
      owner: OWNER,
      trackingRegistry: REGISTRY,
      seal: SEAL,
      viewingU: ACCOUNT.viewingU,
    };
    const first = await enrollInstruction({ ...input, proof }, UNENROLLED);
    expect(hex(first.data)).toBe(`06${enroll.enroll_data}${hex(proof)}`);
    await expect(
      enrollInstruction({ ...input, proof: proof.subarray(1) }, UNENROLLED),
    ).rejects.toMatchObject({
      code: "RING_PROOF_LENGTH",
    });
  });

  it("decodes the authorization account after its apply", () => {
    expect(ACCOUNT.registry).toBe(REGISTRY);
    expect(ACCOUNT.owner).toBe(OWNER);
    expect(ACCOUNT.applied).toBe(true);
    expect(hex(ACCOUNT.nullifierPk)).toBe(enroll.enroll_data.slice(0, 64));
    expect(hex(ACCOUNT.listTag)).toBe(enroll.enroll_data.slice(64, 128));
    expect(hex(ACCOUNT.viewingU)).toBe(enroll.enroll_data.slice(128, 192));
    expect(hex(ACCOUNT.ephU)).toBe(enroll.enroll_data.slice(192, 256));
    expect(hex(ACCOUNT.ciphertext)).toBe(enroll.enroll_data.slice(256, 384));
  });

  it("derives the authorization PDA from the registry and the owner", async () => {
    const [authorization, bump] = await trackingAuthorizationPda(REGISTRY, OWNER);
    expect(authorization).toBe(encodeBase58(field(enroll.authorization)));
    expect(bump).toBe(enroll.bump);
  });

  it("derives the owner's member from its address", () => {
    expect(hex(solanaOwnerIdentity(field(enroll.owner)))).toBe(enroll.member);
  });

  it("hashes the entry and chains it from the apply's start", () => {
    expect(hex(trackingEntryHash(ENTRY))).toBe(enroll.entry_hash);
    expect(hex(trackingEntryChained(field(enroll.chain_start), ENTRY))).toBe(enroll.chain_end);
    const moved = { ...ENTRY, listTag: field(enroll.member) };
    expect(hex(trackingEntryHash(moved))).not.toBe(enroll.entry_hash);
  });
});
