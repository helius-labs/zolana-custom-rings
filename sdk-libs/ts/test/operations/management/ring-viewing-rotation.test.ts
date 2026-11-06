import { address, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { addressBytes } from "@heliuslabs/spr/internal";
import type { Bytes16, Bytes32 } from "@heliuslabs/spr/interface";
import { ShieldedKeypair, SigningKey, ViewingKey } from "@heliuslabs/spr/keypair";

import { ENROLL_TAG } from "../../../src/operations/management/enrollment.js";
import {
  confirmViewingKey,
  rotateViewingKey,
  updateViewingKey,
} from "../../../src/operations/management/viewing-rotation.js";
import { STORAGE_PROGRAM_ID, trackingAuthorizationPda } from "../../../src/protocol/pda/index.js";
import { LocalRingKeys } from "../../../src/state/ring-keys.js";
import { ViewingHistory } from "../../../src/state/viewing-history.js";
import { withConfirmedReads } from "../../helpers/clients.js";

const OWNER = address("7xKqmYUZ7pQHXcQnaZaZzR1oPjQb8kk8gA7XN3XxKzKq");
const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const REGISTRY = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");
const SALT = new Uint8Array(16).fill(5) as Bytes16;

const wallet = (seed: number) =>
  ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );

/** `OWNER`'s tracking authorization for `holder`, `enroll` lands a rotation. */
async function enrolled(holder: ShieldedKeypair, applied = 1) {
  const [pda] = await trackingAuthorizationPda(REGISTRY, OWNER);
  const data = new Uint8Array(258);
  data[0] = 4;
  data.set(addressBytes(REGISTRY), 1);
  data.set(addressBytes(OWNER), 33);
  data.set(holder.nullifierPublicKey(), 65);
  data.fill(0x11, 97, 129);
  data.set(holder.viewingPublicKey().u(), 129);
  data.fill(0x22, 161, 193);
  data.fill(0x33, 193, 257);
  data[257] = applied;
  const client = withConfirmedReads({
    getAccount: async (read: Address) =>
      read === pda ? { owner: STORAGE_PROGRAM_ID, data: data.slice(), lamports: 1n } : undefined,
  });
  // A rotation writes the key alone, the applied flag stays.
  const enroll = (viewingU: Uint8Array) => data.set(viewingU, 129);
  return { client, enroll };
}

function rotation(holder: ShieldedKeypair, next: ViewingKey) {
  return rotateViewingKey({
    keys: LocalRingKeys.fromKeypair(holder),
    history: ViewingHistory.create(holder.viewingPublicKey(), 0n),
    next,
    rotatedAt: 1n,
  });
}

describe("viewing key rotation through the tracking row", () => {
  it("enrolls the new key without a proof and confirms it once the rotation lands", async () => {
    const holder = wallet(1);
    const { client, enroll } = await enrolled(holder);
    const rotated = rotation(holder, ViewingKey.generate());
    const current = rotated.keys.address().viewingPublicKey.u();
    const update = () =>
      updateViewingKey({
        client,
        payer: PAYER,
        owner: OWNER,
        trackingRegistry: REGISTRY,
        keys: rotated.keys,
        history: rotated.history,
      });
    const confirm = () =>
      confirmViewingKey({ client, owner: OWNER, trackingRegistry: REGISTRY, keys: rotated.keys });

    // 1. The rotation repeats the seal, carries the new key and no proof.
    const instruction = await update();
    expect(instruction?.data?.[0]).toBe(ENROLL_TAG);
    expect(instruction?.data).toHaveLength(1 + 192);
    expect(instruction?.data?.subarray(65, 97)).toEqual(current);
    await expect(confirm()).rejects.toMatchObject({ code: "RING_VIEWING_KEY_NOT_PUBLISHED" });

    // 2. The landed rotation confirms without an apply.
    enroll(current);
    expect((await confirm()).viewingU).toEqual(current);
    expect(await update()).toBeUndefined();
  });

  it("confirms nothing for a first enrollment no apply has inserted", async () => {
    const holder = wallet(5);
    const { client } = await enrolled(holder, 0);
    await expect(
      confirmViewingKey({
        client,
        owner: OWNER,
        trackingRegistry: REGISTRY,
        keys: LocalRingKeys.fromKeypair(holder),
      }),
    ).rejects.toMatchObject({ code: "RING_VIEWING_KEY_NOT_PUBLISHED" });
  });

  it("opens a note sealed to the old key only with the retained key", async () => {
    const holder = wallet(2);
    const next = ViewingKey.generate();
    const rotated = rotation(holder, next);
    const tx = ViewingKey.generate();
    const old = holder.viewingPublicKey();
    const plaintext = new TextEncoder().encode("old note");
    const request = {
      ciphertext: tx.encryptSlot(old, plaintext, SALT, 0),
      viewingPublicKey: old,
      txViewingPublicKey: tx.publicKey(),
      salt: SALT,
      slotIndex: 0,
      label: "transfer",
    } as const;
    expect(await rotated.keys.decrypt([request])).toEqual([plaintext]);

    const currentOnly = LocalRingKeys.fromKeys({
      address: rotated.keys.address(),
      viewingKeys: [next],
      listRoot: holder.viewingKey(),
      nullifierKey: holder.nullifierKey(),
    });
    await expect(currentOnly.decrypt([request])).rejects.toThrow();
  });

  it("refuses a holder of another nullifier key and one ahead of its history", async () => {
    const holder = wallet(3);
    const { client } = await enrolled(holder);
    const stranger = rotation(wallet(4), ViewingKey.generate());
    const input = { client, payer: PAYER, owner: OWNER, trackingRegistry: REGISTRY };
    await expect(
      updateViewingKey({ ...input, keys: stranger.keys, history: stranger.history }),
    ).rejects.toMatchObject({ code: "RING_ENROLLMENT_KEY_MISMATCH" });
    await expect(
      updateViewingKey({
        ...input,
        keys: LocalRingKeys.fromKeypair(holder).rotate(ViewingKey.generate()),
        history: ViewingHistory.create(holder.viewingPublicKey(), 0n),
      }),
    ).rejects.toMatchObject({ code: "RING_VIEWING_HISTORY_NOT_CURRENT" });
  });
});
