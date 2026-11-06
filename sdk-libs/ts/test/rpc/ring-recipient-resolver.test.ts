import { address, type Address } from "@solana/kit";

import type { RpcAccount } from "@heliuslabs/spr/client";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import { poseidon, ZERO_32, ZERO_NULLIFIER_PK } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { ShieldedAddress, ShieldedKeypair, SigningKey } from "@heliuslabs/spr/keypair";

import { withConfirmedReads } from "../helpers/clients.js";
import { RingAddress } from "../../src/crypto/keys/ring-address.js";
import { readOutputKeys } from "../../src/operations/workflow/ring-reads.js";
import { checkOutputKeys } from "../../src/proof/policy-proof.js";
import type { ProofOutputUtxo } from "@heliuslabs/spr/transaction";
import { listSaltOf, listTagOf } from "../../src/crypto/keys/list-salt.js";
import {
  TRACKING_QUAD_HEIGHT,
  TRACKING_SENTINEL,
  trackingRecordHash,
  type TrackingOpening,
  type TrackingRecord,
} from "../../src/protocol/membership/tracking.js";
import { resolveRingRecipient, type RingRecipientClient } from "../../src/rpc/tracking-resolver.js";
import { trackingAuthorizationAccount } from "../helpers/ring-accounts.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const REGISTRY = address("Stor111111111111111111111111111111111111111");

const holder = () =>
  ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(7) as Bytes32));

function zeroSiblings(): readonly (readonly Bytes32[])[] {
  const levels: Bytes32[][] = [];
  let zero: Bytes32 = ZERO_32;
  for (let level = 0; level < TRACKING_QUAD_HEIGHT; level += 1) {
    levels.push([zero, zero, zero]);
    zero = poseidon([zero, zero, zero, zero]) as Bytes32;
  }
  return levels;
}

/** The tree holding only `leaf` at index 0, served as `opening`, beside the authorizations given. */
function chain(
  leaf: TrackingRecord,
  kind: "present" | "absent",
  authorizations: ReadonlyMap<Address, RpcAccount> = new Map(),
): RingRecipientClient {
  const siblings = zeroSiblings();
  let root = trackingRecordHash(leaf);
  for (const level of siblings) root = poseidon([root, ...level]) as Bytes32;
  const data = new Uint8Array(1610);
  data[0] = 3;
  new DataView(data.buffer).setBigUint64(66, 1n, true);
  data.set(root, 74);
  const path = { index: 0, siblings };
  const opening: TrackingOpening =
    kind === "present" ? { kind, record: leaf, path } : { kind, low: leaf, path };
  return withConfirmedReads({
    getAccount: async (read: Address) => (read === REGISTRY ? { data } : authorizations.get(read)),
    getTrackingOpenings: async () => ({
      slot: 1n,
      root,
      revision: 0n,
      openings: [opening],
    }),
  } as unknown as RingRecipientClient);
}

/** `fields` overrides the authorization the account holds for the addressed owner. */
async function authorization(
  to: RingAddress,
  fields: Readonly<{
    registry?: Address;
    owner?: Address;
    viewingU?: Uint8Array;
  }> = {},
  programOwner?: Address,
): Promise<ReadonlyMap<Address, RpcAccount>> {
  const owner = to.recipient.solanaAddress();
  const [at, account] = await trackingAuthorizationAccount({
    registry: REGISTRY,
    owner,
    nullifierPk: to.recipient.nullifierPublicKey,
    listTag: listTagOf(to.listSalt),
    viewingU: to.recipient.viewingPublicKey.u(),
    ...fields,
  });
  return new Map([
    [at, programOwner === undefined ? account : { ...account, owner: programOwner }],
  ]);
}

async function addressed() {
  const wallet = holder();
  const to = await RingAddress.enrolled(wallet, RING, listSaltOf(wallet.viewingKey(), RING));
  const member = to.recipient.signingPublicKey.ownerProofInputHash();
  const row: TrackingRecord = {
    ...TRACKING_SENTINEL,
    member,
    nullifierPk: wallet.nullifierPublicKey(),
    listTag: listTagOf(to.listSalt),
  };
  return { to, row, wallet, accounts: await authorization(to) };
}

beforeAll(initializePoseidon);

describe("resolveRingRecipient", () => {
  it("returns the row's key and tag and the authorization's viewing key, never a salt", async () => {
    const { to, row, accounts } = await addressed();
    const resolved = await resolveRingRecipient({
      client: chain(row, "present", accounts),
      trackingRegistry: REGISTRY,
      to,
    });
    if (resolved.kind !== "enrolled") throw new Error("enrolled");
    expect(resolved.nullifierPk).toEqual(row.nullifierPk);
    expect(resolved.viewingPublicKey.u()).toEqual(to.recipient.viewingPublicKey.u());
    expect(resolved.listTag).toEqual(listTagOf(to.listSalt));
    expect(Object.keys(resolved)).not.toContain("listSalt");
  });

  it("refuses a key or salt the verified row does not hold", async () => {
    const { to, row, accounts } = await addressed();
    for (const [name, wrong] of [
      ["nullifierPk", { nullifierPk: new Uint8Array(32).fill(5) as Bytes32 }],
      ["listSalt", { listTag: new Uint8Array(32).fill(5) as Bytes32 }],
    ] as const)
      await expect(
        resolveRingRecipient({
          client: chain({ ...row, ...wrong }, "present", accounts),
          trackingRegistry: REGISTRY,
          to,
        }),
      ).rejects.toMatchObject({
        code: "RING_ADDRESS_MISMATCH",
        details: { field: name },
      });
  });

  it("refuses a keyed address with no row, a pending enrollment grants nothing", async () => {
    const { to } = await addressed();
    await expect(
      resolveRingRecipient({
        client: chain(TRACKING_SENTINEL, "absent"),
        trackingRegistry: REGISTRY,
        to,
      }),
    ).rejects.toMatchObject({ code: "RING_RECIPIENT_NOT_ENROLLED" });
  });

  it("resolves an address from before a rotation to the authorization's current viewing key", async () => {
    const { to, row } = await addressed();
    const rotated = ShieldedKeypair.generate().viewingPublicKey();
    const resolved = await resolveRingRecipient({
      client: chain(row, "present", await authorization(to, { viewingU: rotated.u() })),
      trackingRegistry: REGISTRY,
      to,
    });
    if (resolved.kind !== "enrolled") throw new Error("enrolled");
    expect(resolved.viewingPublicKey.u()).toEqual(rotated.u());
    expect(resolved.viewingPublicKey.u()).not.toEqual(to.recipient.viewingPublicKey.u());
  });

  it("refuses an authorization another program, registry or owner holds", async () => {
    const { to, row } = await addressed();
    const stranger = address("Cura111111111111111111111111111111111111111");
    for (const [reason, accounts] of [
      ["authorization program", await authorization(to, {}, stranger)],
      ["authorization registry", await authorization(to, { registry: stranger })],
      ["authorization owner", await authorization(to, { owner: stranger })],
    ] as const) {
      // The served account sits at the addressed owner's PDA whatever it names.
      const [served] = [...accounts.values()];
      const [at] = [...(await authorization(to)).keys()];
      await expect(
        resolveRingRecipient({
          client: chain(row, "present", new Map([[at as Address, served as RpcAccount]])),
          trackingRegistry: REGISTRY,
          to,
        }),
      ).rejects.toMatchObject({
        code: "RING_TRACKING_INVALID",
        details: { reason },
      });
    }
  });

  describe("under the zero key", () => {
    const zeroAddressed = (wallet: ShieldedKeypair) => {
      const address_ = wallet.shieldedAddress();
      return new RingAddress({
        recipient: ShieldedAddress.fromPublicKeys(
          address_.signingPublicKey,
          ZERO_NULLIFIER_PK as Bytes32,
          address_.viewingPublicKey,
        ),
        ringProgramId: RING,
        listSalt: ZERO_32,
      });
    };

    it("admits an owner with no row under the address's viewing key", async () => {
      const to = zeroAddressed(holder());
      const resolved = await resolveRingRecipient({
        client: chain(TRACKING_SENTINEL, "absent"),
        trackingRegistry: REGISTRY,
        to,
      });
      expect(resolved.kind).toBe("zeroKey");
      expect(resolved.viewingPublicKey.u()).toEqual(to.recipient.viewingPublicKey.u());
    });

    it("resolves a rotated enrolled owner's old address to the authorization's current key", async () => {
      const { to, row, wallet } = await addressed();
      const rotated = ShieldedKeypair.generate().viewingPublicKey();
      const resolved = await resolveRingRecipient({
        client: chain(row, "present", await authorization(to, { viewingU: rotated.u() })),
        trackingRegistry: REGISTRY,
        to: zeroAddressed(wallet),
      });
      expect(resolved.kind).toBe("zeroKey");
      expect(resolved.viewingPublicKey.u()).toEqual(rotated.u());
      await expect(
        resolveRingRecipient({
          client: chain(row, "present"),
          trackingRegistry: REGISTRY,
          to: zeroAddressed(wallet),
        }),
      ).rejects.toMatchObject({
        code: "RING_TRACKING_INVALID",
        details: { reason: "authorization" },
      });
    });

    it("refuses a zero key payment to an enrolled owner after viewing key resolution", async () => {
      const { to, row, wallet } = await addressed();
      const rotated = ShieldedKeypair.generate().viewingPublicKey();
      const old = zeroAddressed(wallet);
      const resolved = await resolveRingRecipient({
        client: chain(row, "present", await authorization(to, { viewingU: rotated.u() })),
        trackingRegistry: REGISTRY,
        to: old,
      });
      const paying = (viewing: typeof rotated) =>
        checkOutputKeys({
          outputs: [
            {
              ownerAddress: ShieldedAddress.fromPublicKeys(
                old.recipient.signingPublicKey,
                ZERO_NULLIFIER_PK as Bytes32,
                viewing,
              ),
            } as ProofOutputUtxo,
          ],
          rowOf: () => row,
          viewingKeyOf: () => rotated.u(),
          spenders: [],
        });
      expect(() => paying(old.recipient.viewingPublicKey)).toThrow(
        expect.objectContaining({ code: "RING_RECIPIENT_ENROLLED" }),
      );
      expect(() => paying(resolved.viewingPublicKey)).toThrow(
        expect.objectContaining({ code: "RING_RECIPIENT_ENROLLED" }),
      );
    });

    it("lets a merge preserve an enrolled owner's zero key", async () => {
      const { row } = await addressed();
      const client = chain(row, "present");
      const { root } = await client.getTrackingOpenings({
        registry: REGISTRY,
        members: [row.member],
        expectedRoot: ZERO_32,
      });
      const [opening] = await readOutputKeys({
        client,
        root: { ringProgramId: RING, registry: REGISTRY, revision: 1n, root },
        outputs: [{ member: row.member, nullifierPk: ZERO_NULLIFIER_PK as Bytes32 }],
      });
      expect(opening?.kind).toBe("present");
    });
  });

  it("refuses an opening under another root", async () => {
    const { to, row, accounts } = await addressed();
    const client = chain(row, "present", accounts);
    const other = chain({ ...row, ctHash: new Uint8Array(32).fill(9) as Bytes32 }, "present");
    await expect(
      resolveRingRecipient({
        client: { ...client, getTrackingOpenings: other.getTrackingOpenings },
        trackingRegistry: REGISTRY,
        to,
      }),
    ).rejects.toMatchObject({ code: "RING_TRACKING_INVALID" });
  });

  it("refuses any opening count but one for the one owner asked", async () => {
    const { to, row, accounts } = await addressed();
    const client = chain(row, "present", accounts);
    const served = await client.getTrackingOpenings({
      registry: REGISTRY,
      members: [],
      expectedRoot: new Uint8Array(32) as Bytes32,
    });
    for (const openings of [[], [...served.openings, ...served.openings]])
      await expect(
        resolveRingRecipient({
          client: { ...client, getTrackingOpenings: async () => ({ ...served, openings }) },
          trackingRegistry: REGISTRY,
          to,
        }),
      ).rejects.toMatchObject({
        code: "RING_TRACKING_INVALID",
        details: { reason: "openings", count: openings.length },
      });
  });
});
