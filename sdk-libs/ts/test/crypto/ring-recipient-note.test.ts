import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon, SOL_MINT } from "@heliuslabs/spr";
import { ZERO_NULLIFIER_PK } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { ShieldedPublicKey } from "@heliuslabs/spr/keypair";
import { AssetRegistry, Data, Utxo } from "@heliuslabs/spr/transaction";
import { address, type Address } from "@solana/kit";

import { openRecipientNote, type RingOutputReader } from "../../src/crypto/derivation/blinding.js";
import type { RecipientBody } from "../../src/protocol/codec/anonymous-delivery.js";

const RING = address("11111111111111111111111111111112");
const UNREGISTERED: Address = address("So11111111111111111111111111111111111111112");
const ENROLLED_KEY = new Uint8Array(32).fill(7) as Bytes32;
const OTHER_KEY = new Uint8Array(32).fill(8) as Bytes32;
const TREE = 3;

function field(byte: number): Bytes32 {
  const value = new Uint8Array(32);
  value[31] = byte;
  return value as Bytes32;
}

describe("openRecipientNote", () => {
  let owner: ShieldedPublicKey;
  let assets: AssetRegistry;

  beforeAll(async () => {
    await initializePoseidon();
    owner = ShieldedPublicKey.fromEd25519(new Uint8Array(32).fill(5) as Bytes32);
    assets = new AssetRegistry();
  });

  const plain = (mint: Address = SOL_MINT): RecipientBody => ({
    blinding: field(11),
    amount: 42n,
    mint,
  });

  function commitment(
    body: RecipientBody,
    nullifierPk: Bytes32,
    extra: Readonly<{ dataHash?: Bytes32; ringDataHash?: Bytes32; appData?: Uint8Array }> = {},
  ): Bytes32 {
    return new Utxo({
      owner,
      asset: body.mint,
      amount: body.amount,
      blinding: body.blinding,
      data:
        extra.appData === undefined
          ? new Data()
          : new Data([{ kind: "utxoData", bytes: extra.appData }]),
      ringProgramId: RING,
    }).hash(nullifierPk, TREE, extra.dataHash, extra.ringDataHash);
  }

  const reader = (published: Bytes32): RingOutputReader => ({
    owner: { signingPublicKey: owner, nullifierPublicKey: ENROLLED_KEY },
    ring: RING,
    treeId: TREE,
    commitment: published,
    assets,
  });

  it("accepts the exact match under the wallet's ring key", () => {
    const note = openRecipientNote(reader(commitment(plain(), ENROLLED_KEY)), plain());
    expect(note?.nullifierPublicKey).toEqual(ENROLLED_KEY);
    expect(note?.utxo.amount).toBe(42n);
    expect(note?.registered).toBe(true);
  });

  it("accepts the exact match under the zero key", () => {
    const note = openRecipientNote(
      reader(commitment(plain(), ZERO_NULLIFIER_PK as Bytes32)),
      plain(),
    );
    expect(note?.nullifierPublicKey).toEqual(ZERO_NULLIFIER_PK);
  });

  it("refuses a commitment under any other key", () => {
    expect(openRecipientNote(reader(commitment(plain(), OTHER_KEY)), plain())).toBeUndefined();
  });

  it("refuses a body off the commitment by amount, mint or blinding", () => {
    const published = commitment(plain(), ENROLLED_KEY);
    expect(openRecipientNote(reader(published), { ...plain(), amount: 43n })).toBeUndefined();
    expect(
      openRecipientNote(reader(published), { ...plain(), blinding: field(12) }),
    ).toBeUndefined();
    expect(openRecipientNote(reader(published), plain(UNREGISTERED))).toBeUndefined();
  });

  it("opens under a mint the registry does not name and says so", () => {
    const body = plain(UNREGISTERED);
    const note = openRecipientNote(reader(commitment(body, ENROLLED_KEY)), body);
    expect(note?.registered).toBe(false);
  });

  it("rebuilds with the ring data hash and the data hash the body carries", () => {
    const ringDataHash = field(21);
    const dataHash = field(22);
    const appData = Uint8Array.of(1, 2, 3);
    const body: RecipientBody = {
      ...plain(),
      ringDataHash,
      data: Uint8Array.of(...dataHash, ...appData),
    };
    const published = commitment(body, ENROLLED_KEY, { dataHash, ringDataHash, appData });
    const note = openRecipientNote(reader(published), body);
    expect(note?.dataHash).toEqual(dataHash);
    expect(note?.ringDataHash).toEqual(ringDataHash);
    expect(note?.utxo.data.utxoData()).toEqual(appData);
    expect(openRecipientNote(reader(published), { ...plain(), ringDataHash })).toBeUndefined();
  });

  it("refuses application bytes under a zero hash, the commitment reads no data", () => {
    const published = commitment(plain(), ENROLLED_KEY);
    expect(openRecipientNote(reader(published), plain())).toBeDefined();
    const unbound = new Uint8Array(32 + 7).fill(9);
    unbound.fill(0, 0, 32);
    expect(openRecipientNote(reader(published), { ...plain(), data: unbound })).toBeUndefined();
    expect(
      openRecipientNote(reader(published), { ...plain(), data: new Uint8Array(32) }),
    ).toBeUndefined();
  });

  it("refuses data shorter than its leading hash and a blinding off the field", () => {
    const published = commitment(plain(), ENROLLED_KEY);
    expect(
      openRecipientNote(reader(published), { ...plain(), data: new Uint8Array(31) }),
    ).toBeUndefined();
    expect(
      openRecipientNote(reader(published), {
        ...plain(),
        blinding: new Uint8Array(32).fill(0xff) as Bytes32,
      }),
    ).toBeUndefined();
  });
});
