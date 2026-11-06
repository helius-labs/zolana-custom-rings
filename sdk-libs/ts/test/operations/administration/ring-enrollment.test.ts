import { address, generateKeyPairSigner, type Address } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { readFileSync } from "node:fs";

import { initializePoseidon } from "@heliuslabs/spr";
import { Reader, ZERO_32, ZERO_NULLIFIER_PK, addressBytes } from "@heliuslabs/spr/internal";
import type { Bytes32, Bytes33, Bytes64 } from "@heliuslabs/spr/interface";
import { ShieldedKeypair, SigningKey, X25519Keypair } from "@heliuslabs/spr/keypair";
import { hexToBytes } from "@noble/hashes/utils.js";

import { withConfirmedReads } from "../../helpers/clients.js";
import { listTagOf } from "../../../src/crypto/keys/list-salt.js";
import {
  applyEnrollmentsInstruction,
  checkEnrollment,
  enrollInstruction,
  enrollmentState,
  ownerGrantInstruction,
  proveEnrollment,
  type EnrollmentSeal,
} from "../../../src/operations/management/enrollment.js";
import { memberOfTag } from "../../../src/protocol/membership/policy.js";
import {
  decodeOwnerGrant,
  decodeTrackingAuthorization,
  decodeTrackingRegistry,
  isEnrollmentPending,
  TRACKING_CAPACITY,
  TRACKING_EMPTY_ROOT,
  TRACKING_QUAD_HEIGHT,
  TRACKING_SENTINEL,
  trackingRecordHash,
  verifyTrackingOpening,
  type TrackingAuthorization,
  type TrackingRecord,
} from "../../../src/protocol/membership/tracking.js";
import {
  ownerGrantPda,
  STORAGE_PROGRAM_ID,
  trackingAuthorizationPda,
} from "../../../src/protocol/pda/index.js";
import { registerKeyStatementHash } from "../../../src/protocol/proof/statement.js";
import type { RegisterKeyProofRequest } from "../../../src/rpc/prover/ring.js";
import { poseidon } from "@heliuslabs/spr/internal";

const REGISTRY = address("Stor111111111111111111111111111111111111111");
const OWNER = address("Cura111111111111111111111111111111111111111");
const field = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;
const PROOF = new Uint8Array(192).fill(5);

const SEAL: EnrollmentSeal = Object.freeze({
  nullifierPk: field(0x11),
  listTag: field(0x12),
  ephU: field(0x13),
  ciphertext: new Uint8Array(64).fill(0x14) as Bytes64,
});

function stored(fields: Partial<TrackingAuthorization> = {}): TrackingAuthorization {
  return {
    registry: REGISTRY,
    owner: OWNER,
    ...SEAL,
    viewingU: field(0x15),
    applied: true,
    ...fields,
  };
}

const unenrolled = withConfirmedReads({
  getAccount: async () => undefined,
}) as never;

function authorizationBytes(applied = 0, owner: Address = OWNER): Uint8Array {
  const data = new Uint8Array(258);
  data[0] = 4;
  data.set(addressBytes(REGISTRY, "registry"), 1);
  data.set(addressBytes(owner, "owner"), 33);
  data.set(SEAL.nullifierPk, 65);
  data.set(SEAL.listTag, 97);
  data.set(field(0x15), 129);
  data.set(SEAL.ephU, 161);
  data.set(SEAL.ciphertext, 193);
  data[257] = applied;
  return data;
}

beforeAll(initializePoseidon);

describe("checkEnrollment", () => {
  it("passes a first enrollment and a rotation of the viewing key", () => {
    expect(() => checkEnrollment({ seal: SEAL, stored: undefined })).not.toThrow();
    expect(() => checkEnrollment({ seal: SEAL, stored: stored() })).not.toThrow();
  });

  it("refuses the zero key before the owner signs", () => {
    expect(() =>
      checkEnrollment({
        seal: { ...SEAL, nullifierPk: ZERO_NULLIFIER_PK as Bytes32 },
        stored: undefined,
      }),
    ).toThrow("RING_ENROLLMENT_ZERO_KEY");
  });

  it.each(["nullifierPk", "listTag", "ephU", "ciphertext"] as const)(
    "refuses a changed %s, it is final after the first enrollment",
    (name) => {
      expect(() =>
        checkEnrollment({
          seal: { ...SEAL, [name]: field(0x77) },
          stored: stored(),
        }),
      ).toThrow("RING_ENROLLMENT_KEY_MISMATCH");
    },
  );
});

describe("tracking accounts", () => {
  it("decodes an authorization at its field offsets and reports it pending", () => {
    const decoded = decodeTrackingAuthorization(authorizationBytes());
    expect(decoded).toMatchObject({ registry: REGISTRY, owner: OWNER, applied: false });
    expect(decoded.nullifierPk).toEqual(SEAL.nullifierPk);
    expect(decoded.ciphertext).toEqual(SEAL.ciphertext);
    expect(isEnrollmentPending(decoded)).toBe(true);
    expect(isEnrollmentPending(decodeTrackingAuthorization(authorizationBytes(1)))).toBe(false);
  });

  it("refuses an account off its discriminator or size", () => {
    const data = authorizationBytes();
    expect(() => decodeTrackingAuthorization(data.subarray(1))).toThrow("RING_TRACKING_INVALID");
    const other = data.slice();
    other[0] = 2;
    expect(() => decodeTrackingAuthorization(other)).toThrow("RING_TRACKING_INVALID");
  });

  it("decodes a registry and refuses a next index past the tree", () => {
    const data = new Uint8Array(1610);
    data[0] = 3;
    data.set(field(0x21), 1);
    data[33] = 4;
    const nextIndex = (value: bigint) => new DataView(data.buffer).setBigUint64(66, value, true);
    nextIndex(1n);
    data.set(TRACKING_EMPTY_ROOT, 74);
    const decoded = decodeTrackingRegistry(data);
    expect(decoded.nextIndex).toBe(1n);
    expect(decoded.roots[0]?.hash).toEqual(TRACKING_EMPTY_ROOT);
    expect(decoded.roots[1]).toBeUndefined();
    // A full tree's next index is its capacity, the u64 field holds no index past it.
    nextIndex(TRACKING_CAPACITY);
    expect(decodeTrackingRegistry(data).nextIndex).toBe(1n << 32n);
    nextIndex(TRACKING_CAPACITY + 1n);
    expect(() => decodeTrackingRegistry(data)).toThrow("RING_TRACKING_INVALID");
    nextIndex(0n);
    expect(() => decodeTrackingRegistry(data)).toThrow("RING_TRACKING_INVALID");
  });

  it("decodes an owner grant, only one means active", () => {
    const data = new Uint8Array(2);
    data[0] = 5;
    data[1] = 1;
    expect(decodeOwnerGrant(data).active).toBe(true);
    data[1] = 0;
    expect(decodeOwnerGrant(data).active).toBe(false);
  });
});

describe("tracking openings", () => {
  const paths = () => {
    const zeros: Bytes32[] = [ZERO_32];
    for (let level = 0; level < TRACKING_QUAD_HEIGHT; level += 1) {
      const below = zeros[level] as Bytes32;
      zeros.push(poseidon([below, below, below, below]) as Bytes32);
    }
    return zeros;
  };

  /** The tree holding only `leaf` at index 0. */
  function single(leaf: TrackingRecord) {
    const zeros = paths();
    const siblings = zeros.slice(0, TRACKING_QUAD_HEIGHT).map((zero) => [zero, zero, zero]);
    let root = trackingRecordHash(leaf);
    for (const level of siblings) root = poseidon([root, ...level]) as Bytes32;
    return { root, path: { index: 0, siblings } };
  }

  it("folds the sentinel to the registry's first root", () => {
    expect(single(TRACKING_SENTINEL).root).toEqual(TRACKING_EMPTY_ROOT);
  });

  it("proves absence through the low row and refuses a member outside it", () => {
    const { root, path } = single(TRACKING_SENTINEL);
    expect(
      verifyTrackingOpening({ kind: "absent", low: TRACKING_SENTINEL, path }, root, field(0x05)),
    ).toBeUndefined();
    const member = field(0x05);
    const low = { ...TRACKING_SENTINEL, next: field(0x04) };
    const short = single(low);
    expect(() =>
      verifyTrackingOpening({ kind: "absent", low, path: short.path }, short.root, member),
    ).toThrow("RING_TRACKING_INVALID");
  });

  it("returns a present row only under its own root and member", () => {
    const record = { ...TRACKING_SENTINEL, member: field(0x05), revision: 2n };
    const { root, path } = single(record);
    expect(verifyTrackingOpening({ kind: "present", record, path }, root, field(0x05))).toEqual(
      record,
    );
    expect(() =>
      verifyTrackingOpening({ kind: "present", record, path }, field(0x06), field(0x05)),
    ).toThrow("RING_TRACKING_INVALID");
    expect(() =>
      verifyTrackingOpening({ kind: "present", record, path }, root, field(0x06)),
    ).toThrow("RING_TRACKING_INVALID");
  });
});

describe("enrollment instructions", () => {
  it("lays out tag 6, the fields then the proof on a first enrollment, none on a rotation", async () => {
    const owner = await generateKeyPairSigner();
    const first = await enrollInstruction(
      {
        payer: owner,
        owner,
        trackingRegistry: REGISTRY,
        seal: SEAL,
        viewingU: field(0x15),
        proof: PROOF,
      },
      unenrolled,
    );
    const data = new Reader(new Uint8Array(first.data ?? []));
    expect(data.u8("tag")).toBe(6);
    expect(data.bytes(32, "nullifierPk")).toEqual(SEAL.nullifierPk);
    expect(data.bytes(32, "listTag")).toEqual(SEAL.listTag);
    expect(data.bytes(32, "viewingU")).toEqual(field(0x15));
    expect(data.bytes(32, "ephU")).toEqual(SEAL.ephU);
    expect(data.bytes(64, "ciphertext")).toEqual(SEAL.ciphertext);
    expect(data.bytes(192, "proof")).toEqual(PROOF);
    data.done();
    expect(first.programAddress).toBe(STORAGE_PROGRAM_ID);
    const [authorization] = await trackingAuthorizationPda(REGISTRY, owner.address);
    expect(first.accounts?.map((account) => account.address)).toEqual([
      owner.address,
      owner.address,
      REGISTRY,
      authorization,
      "11111111111111111111111111111111",
    ]);
    const rotation = await enrollInstruction(
      {
        payer: owner,
        owner,
        trackingRegistry: REGISTRY,
        seal: SEAL,
        viewingU: field(0x15),
      },
      unenrolled,
    );
    expect(rotation.data).toHaveLength(1 + 192);
  });

  it("checks the stored authorization of the signing owner before it builds", async () => {
    const owner = await generateKeyPairSigner();
    const [authorization] = await trackingAuthorizationPda(REGISTRY, owner.address);
    const enrolled = withConfirmedReads({
      getAccount: async (key: Address) =>
        key === authorization
          ? { owner: STORAGE_PROGRAM_ID, data: authorizationBytes(1, owner.address) }
          : undefined,
    }) as never;
    const enroll = (seal: EnrollmentSeal) =>
      enrollInstruction(
        { payer: owner, owner, trackingRegistry: REGISTRY, seal, viewingU: field(0x15) },
        enrolled,
      );
    await expect(enroll(SEAL)).resolves.toBeDefined();
    await expect(
      enroll({ ...SEAL, ciphertext: new Uint8Array(64).fill(0x16) as Bytes64 }),
    ).rejects.toMatchObject({
      code: "RING_ENROLLMENT_KEY_MISMATCH",
    });
    await expect(
      enrollInstruction(
        {
          payer: owner,
          owner,
          trackingRegistry: REGISTRY,
          seal: { ...SEAL, nullifierPk: ZERO_NULLIFIER_PK as Bytes32 },
          viewingU: field(0x15),
        },
        unenrolled,
      ),
    ).rejects.toMatchObject({ code: "RING_ENROLLMENT_ZERO_KEY" });
  });

  it("names the authorizations in chain order and refuses an apply naming none", async () => {
    const other = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
    const applied = await applyEnrollmentsInstruction({
      trackingRegistry: REGISTRY,
      revision: 9n,
      proof: PROOF,
      newRoot: field(0x31),
      newNextIndex: 3n,
      owners: [other, OWNER],
    });
    expect(applied.data).toHaveLength(1 + 8 + 192 + 32 + 8);
    expect(applied.data?.subarray(1 + 8 + 192 + 32)).toEqual(Uint8Array.of(3, 0, 0, 0, 0, 0, 0, 0));
    expect(applied.accounts?.map((account) => account.address)).toEqual([
      REGISTRY,
      (await trackingAuthorizationPda(REGISTRY, other))[0],
      (await trackingAuthorizationPda(REGISTRY, OWNER))[0],
    ]);
    await expect(
      applyEnrollmentsInstruction({
        trackingRegistry: REGISTRY,
        revision: 9n,
        proof: PROOF,
        newRoot: field(0x31),
        newNextIndex: 3n,
        owners: [],
      }),
    ).rejects.toMatchObject({ code: "RING_ENROLLMENT_NONE_NAMED" });
  });

  it("writes an owner grant under the split reader key", async () => {
    const owner = await generateKeyPairSigner();
    const reader = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
    const built = await ownerGrantInstruction({
      payer: owner,
      owner,
      trackingRegistry: REGISTRY,
      reader,
      active: true,
    });
    const data = new Uint8Array(built.data ?? []);
    expect(data[0]).toBe(8);
    expect(data).toHaveLength(1 + 34 + 1);
    expect(data[35]).toBe(1);
    const [grant] = await ownerGrantPda(REGISTRY, owner.address, data.subarray(1, 35));
    expect(built.accounts?.[3]?.address).toBe(grant);
  });
});

const SALT = Uint8Array.of(0, ...new Uint8Array(31).fill(9)) as Bytes32;

describe("proveEnrollment", () => {
  const auditor = X25519Keypair.generate();

  function registryAccount(ringId: Bytes32): { data: Uint8Array } {
    const data = new Uint8Array(1610);
    data[0] = 3;
    data.set(ringId, 1);
    data.set(auditor.publicKey().toBytes(), 33);
    new DataView(data.buffer).setBigUint64(66, 1n, true);
    return { data };
  }

  it("seals the ring key to the registry's auditor and states ring, member and list tag", async () => {
    const holder = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(7) as Bytes32),
    );
    const ringId = field(0x1e);
    const seen: RegisterKeyProofRequest[] = [];
    const { seal, proof } = await proveEnrollment({
      holder,
      owner: OWNER,
      trackingRegistry: REGISTRY,
      listSalt: SALT,
      client: {
        getAccount: vi.fn(async () => registryAccount(ringId)),
      } as never,
      prover: {
        proveRing: async (request: RegisterKeyProofRequest) => {
          seen.push({ ...request });
          return PROOF;
        },
      } as never,
    });
    expect(proof).toEqual(PROOF);
    expect(seal.nullifierPk).toEqual(holder.nullifierPublicKey());
    expect(seal.listTag).toEqual(listTagOf(SALT));
    const [request] = seen;
    if (request === undefined) throw new Error("no proof asked");
    expect(request.ringId).toEqual(ringId);
    expect(request.member).toEqual(memberOfTag(addressBytes(OWNER, "owner")));
    expect(request.publicInputHash).toEqual(
      registerKeyStatementHash({
        ringId,
        member: request.member,
        nullifierPk: seal.nullifierPk,
        listTag: seal.listTag,
        auditorPubkey: auditor.publicKey().toBytes() as Bytes33,
        ephU: seal.ephU,
        ciphertext: seal.ciphertext,
      }),
    );
    // The holder wipes its copies once the prover answers.
    expect(request.nullifierSecret.every((byte) => byte === 0)).toBe(true);
    expect(request.ephSk.every((byte) => byte === 0)).toBe(true);
  });

  it("refuses a registry account it cannot read before any proof", async () => {
    const holder = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(7) as Bytes32),
    );
    const proveRing = vi.fn();
    await expect(
      proveEnrollment({
        holder,
        owner: OWNER,
        trackingRegistry: REGISTRY,
        listSalt: SALT,
        client: { getAccount: async () => undefined } as never,
        prover: { proveRing } as never,
      }),
    ).rejects.toMatchObject({ code: "RING_TRACKING_INVALID" });
    expect(proveRing).not.toHaveBeenCalled();
  });

  it("reads the stored enrollment by its account address", async () => {
    const [account] = await trackingAuthorizationPda(REGISTRY, OWNER);
    const getAccount = vi.fn(async (key: Address) =>
      key === account ? { owner: STORAGE_PROGRAM_ID, data: authorizationBytes(1) } : undefined,
    );
    const state = await enrollmentState(
      { trackingRegistry: REGISTRY, owner: OWNER },
      withConfirmedReads({ getAccount }) as never,
    );
    expect(state?.applied).toBe(true);
    expect(
      await enrollmentState(
        { trackingRegistry: REGISTRY, owner: REGISTRY },
        withConfirmedReads({ getAccount }) as never,
      ),
    ).toBeUndefined();
  });
});

describe("list salt vector", () => {
  const vector = JSON.parse(
    readFileSync(
      new URL("../../../../../test-vectors/proof/ring-statements.json", import.meta.url),
      "utf8",
    ),
  ) as { tracking: Record<string, string> };

  it("derives the list salt and tag the Go circuit proves", () => {
    const { list_salt: salt, secret_list_tag: tag } = vector.tracking;
    if (salt === undefined || tag === undefined) throw new Error("no vector");
    expect(Buffer.from(listTagOf(hexToBytes(salt) as Bytes32)).toString("hex")).toBe(tag);
  });
});
