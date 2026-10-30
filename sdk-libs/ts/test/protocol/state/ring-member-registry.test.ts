import { address, type Address } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import records from "../../../../../test-vectors/registry/ring-records.json" with { type: "json" };
import {
  type RingMemberOpening,
  type RingRecordReader,
  type RingSealedKey,
} from "../../../src/rpc/ports.js";
import type { RpcAccount } from "@heliuslabs/zolana/client";
import { initializePoseidon } from "@heliuslabs/zolana";
import { addressBytes } from "@heliuslabs/zolana/internal";
import type { Bytes31, Bytes32 } from "@heliuslabs/zolana/interface";
import {
  NullifierKey,
  ShieldedKeypair,
  SigningKey,
  X25519Keypair,
} from "@heliuslabs/zolana/keypair";
import { ringPolicyPda } from "../../../src/protocol/pda/index.js";
import type { RingMode } from "../../../src/protocol/codec/ring-codecs.js";
import {
  MEMBER_REGISTRY_EMPTY_ROOT,
  escrowKeyHash,
} from "../../../src/protocol/membership/member-opening.js";
import { memberOfTag } from "../../../src/protocol/membership/policy.js";
import {
  fetchRingSealedKey,
  openNullifierKey,
  openRingSealedKey,
  sealNullifierKey,
  sealNullifierKeyWith,
} from "../../../src/operations/management/register-key.js";
import { recordTree, type FixtureRecord } from "../../helpers/member-registry.js";
import {
  ownedAccount,
  ringPolicyData,
  storageRegistryAccount,
} from "../../helpers/ring-accounts.js";

// sdk-libs/client/src/crypto/encryption/mod.rs `the_sealed_key_and_its_escrow_key_match_the_pinned_vector`.
const AUDITOR_SK = hex("01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c");
const EPHEMERAL_SK = hex("011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e");
const NULLIFIER_SECRET = hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const NULLIFIER_PK = hex("2d1faf6cf358763421511eb637adf7b6609443d38edc4ed2b042dfbf834b03f5");
const EPH_PK = hex("043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63");
const CIPHERTEXT = hex("2c2a1650e3a2a0d012a0d438341ff610ad99bd3c1cde0dd169179174880e755d");
const KEY_HASH = hex("1c73c14786dd7354525c98368bca8dbc5f836e957c45f552f377c84e266546c4");

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const AUTHORITY = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const RECORDS = address("6NxnStrvfxkDAnWHyvc6SVXkZvBKtpHS3Bd9WfCSgUSv");
const REVISION = 2n;
const AUDITOR = X25519Keypair.fromBytes(AUDITOR_SK);

beforeAll(initializePoseidon);

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function actor(seed: number) {
  const keypair = ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );
  const shielded = keypair.shieldedAddress();
  const signer = shielded.solanaAddress();
  return { keypair, shielded, signer, member: memberOfTag(addressBytes(signer)) };
}

/** The chain and indexer of a ring whose registry holds `members`. */
async function ring(
  members: readonly FixtureRecord[],
  options: Readonly<{ mode?: RingMode; opening?: RingMemberOpening }> = {},
) {
  const tree = recordTree(members);
  const [policy, policyBump] = await ringPolicyPda(RING);
  const accounts = new Map<Address, RpcAccount>([
    [
      policy,
      ownedAccount(
        RING,
        ringPolicyData({
          bump: policyBump,
          roles: { policy: AUTHORITY },
          auditorPublicKey: AUDITOR.publicKey().toBytes(),
          mode: options.mode ?? "confidentialEscrow",
          policyHash: new Uint8Array(32).fill(1) as Bytes32,
          records: RECORDS,
        }),
      ),
    ],
    [RECORDS, storageRegistryAccount([{ hash: tree.root, revision: REVISION, expiresAt: 0n }])],
  ]);
  const getStorageMemberOpenings = vi.fn<RingRecordReader["getStorageMemberOpenings"]>(
    async (request) => ({
      context: { slot: 1n, blockTime: 1n },
      root: { root: request.expectedRoot, revision: REVISION, nextIndex: tree.nextIndex },
      openings: request.members.map((member) => options.opening ?? tree.opening(member)),
    }),
  );
  return {
    tree,
    client: {
      getAccount: async (account: Address) => accounts.get(account),
      getStorageMemberOpenings,
    },
  };
}

/** A member whose record escrows its sealed key, served beside the record. */
function registered(seed: number) {
  const who = actor(seed);
  const envelope = sealNullifierKey(who.keypair.nullifierKey(), AUDITOR.publicKey());
  envelope.ephemeralSecret.fill(0);
  const sealed: RingSealedKey = {
    owner: who.signer,
    nullifierPk: envelope.nullifierPublicKey,
    ephemeralPublicKey: envelope.sealed.ephemeralPublicKey,
    ciphertext: envelope.sealed.ciphertext,
  };
  const record: FixtureRecord = {
    member: who.member,
    lists: 1n << 7n,
    escrowKey: escrowKeyHash({ nullifierPk: sealed.nullifierPk, ciphertext: sealed.ciphertext }),
    sealed,
  };
  return { ...who, record, sealed };
}

describe("nullifier key envelope", () => {
  it("matches the Rust vector and opens only for the auditor", () => {
    const ephemeral = X25519Keypair.fromBytes(EPHEMERAL_SK);
    const nullifierKey = NullifierKey.fromSecret(NULLIFIER_SECRET as Bytes31);
    const envelope = sealNullifierKeyWith(ephemeral, nullifierKey, AUDITOR.publicKey());
    expect(envelope.nullifierPublicKey).toEqual(NULLIFIER_PK);
    expect(envelope.sealed.ephemeralPublicKey.toBytes()).toEqual(EPH_PK);
    expect(envelope.sealed.ciphertext).toEqual(CIPHERTEXT);
    expect(
      escrowKeyHash({
        nullifierPk: envelope.nullifierPublicKey,
        ciphertext: envelope.sealed.ciphertext,
      }),
    ).toEqual(KEY_HASH);
    expect(openNullifierKey(envelope.sealed, AUDITOR).secretBytes()).toEqual(NULLIFIER_SECRET);
    const fresh = sealNullifierKey(nullifierKey, AUDITOR.publicKey());
    expect(fresh.sealed.ciphertext).not.toEqual(CIPHERTEXT);
    expect(openNullifierKey(fresh.sealed, AUDITOR).secretBytes()).toEqual(NULLIFIER_SECRET);
  });

  it("pins the sentinel-only root the registry starts from", () => {
    expect(Buffer.from(MEMBER_REGISTRY_EMPTY_ROOT).toString("hex")).toBe(records.empty_root);
    expect(recordTree().root).toEqual(MEMBER_REGISTRY_EMPTY_ROOT);
  });
});

describe("escrowed keys", () => {
  it("opens a registered member's key for the auditor only", async () => {
    const who = registered(11);
    const { client, tree } = await ring([who.record]);
    const entry = await fetchRingSealedKey({ client, ringProgramId: RING, member: who.member });
    expect(entry.root).toEqual(tree.root);
    expect(entry.sealed).toEqual(who.sealed);
    expect(openRingSealedKey(entry, AUDITOR).secretBytes()).toEqual(
      who.keypair.nullifierKey().secretBytes(),
    );
    expect(() => openRingSealedKey(entry, X25519Keypair.generate())).toThrow(
      expect.objectContaining({ code: "RING_KEY_ENVELOPE_INVALID" }),
    );
  });

  it("refuses an envelope the record does not bind and an absent member", async () => {
    const who = registered(12);
    const ciphertext = Uint8Array.from(who.sealed.ciphertext) as Bytes32;
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
    const altered = { ...who.sealed, ciphertext };
    const { client } = await ring([{ ...who.record, sealed: altered }]);
    await expect(
      fetchRingSealedKey({ client, ringProgramId: RING, member: who.member }),
    ).rejects.toMatchObject({ code: "RING_KEY_NOT_REGISTERED" });
    await expect(
      fetchRingSealedKey({ client, ringProgramId: RING, member: actor(13).member }),
    ).rejects.toMatchObject({ code: "RING_KEY_NOT_REGISTERED" });
  });
});
