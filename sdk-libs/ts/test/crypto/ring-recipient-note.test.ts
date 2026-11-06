import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon, SOL_MINT } from "@heliuslabs/spr";
import { ZERO_NULLIFIER_PK } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { ShieldedPublicKey } from "@heliuslabs/spr/keypair";
import { AssetRegistry, Data, Utxo } from "@heliuslabs/spr/transaction";
import { address, type Address } from "@solana/kit";

import { openRecipientNote, type RingOutputReader } from "../../src/crypto/derivation/blinding.js";
import type { OpenedOutput } from "../../src/crypto/audit/ring-disclosure.js";
import { RecordKind } from "../../src/protocol/codec/audit-stream.js";

const RING = address("11111111111111111111111111111112");
const UNREGISTERED: Address = address("So11111111111111111111111111111111111111112");
const ENROLLED_KEY = new Uint8Array(32).fill(7) as Bytes32;
const OTHER_KEY = new Uint8Array(32).fill(8) as Bytes32;
const TREE = 3;

/** The slot plaintext a recipient opens, its record and the payload past it. */
interface Body {
  readonly blinding: Bytes32;
  readonly amount: bigint;
  readonly mint: Address;
  readonly ringDataHash?: Bytes32;
  readonly data?: Uint8Array;
}

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

  const plain = (mint: Address = SOL_MINT): Body => ({
    blinding: field(11),
    amount: 42n,
    mint,
  });

  /** The record names `nullifierPk` and the reader's own owner key unless told otherwise. */
  const opened = (
    body: Body,
    nullifierPk: Bytes32 = ENROLLED_KEY,
    record: Partial<OpenedOutput["record"]> = {},
  ): OpenedOutput => ({
    record: {
      kind: RecordKind.ring,
      amount: body.amount,
      ownerKey: owner.confidentialViewTag() as Bytes32,
      mint: body.mint,
      nullifierPk,
      blinding: body.blinding,
      ...record,
    },
    payload: {
      ...(body.ringDataHash === undefined ? {} : { ringDataHash: body.ringDataHash }),
      data: body.data ?? new Uint8Array(),
    },
  });

  function commitment(
    body: Body,
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
    const note = openRecipientNote(reader(commitment(plain(), ENROLLED_KEY)), opened(plain()));
    expect(note?.nullifierPublicKey).toEqual(ENROLLED_KEY);
    expect(note?.utxo.amount).toBe(42n);
    expect(note?.registered).toBe(true);
  });

  it("accepts the exact match under the zero key", () => {
    const note = openRecipientNote(
      reader(commitment(plain(), ZERO_NULLIFIER_PK as Bytes32)),
      opened(plain(), ZERO_NULLIFIER_PK as Bytes32),
    );
    expect(note?.nullifierPublicKey).toEqual(ZERO_NULLIFIER_PK);
  });

  it("refuses a record naming a key the reader holds no part of, even when it rebuilds", () => {
    const published = commitment(plain(), OTHER_KEY);
    expect(openRecipientNote(reader(published), opened(plain(), OTHER_KEY))).toBeUndefined();
    expect(openRecipientNote(reader(published), opened(plain()))).toBeUndefined();
  });

  it("refuses a record naming another owner key or another kind than a ring note", () => {
    const published = commitment(plain(), ENROLLED_KEY);
    expect(
      openRecipientNote(
        reader(published),
        opened(plain(), ENROLLED_KEY, { ownerKey: new Uint8Array(32).fill(6) as Bytes32 }),
      ),
    ).toBeUndefined();
    expect(
      openRecipientNote(
        reader(published),
        opened(plain(), ENROLLED_KEY, { kind: RecordKind.exit }),
      ),
    ).toBeUndefined();
  });

  it("refuses a record off the commitment by amount, mint or blinding", () => {
    const published = commitment(plain(), ENROLLED_KEY);
    expect(
      openRecipientNote(reader(published), opened({ ...plain(), amount: 43n })),
    ).toBeUndefined();
    expect(
      openRecipientNote(reader(published), opened({ ...plain(), blinding: field(12) })),
    ).toBeUndefined();
    expect(openRecipientNote(reader(published), opened(plain(UNREGISTERED)))).toBeUndefined();
  });

  it("opens under a mint the registry does not name and says so", () => {
    const body = plain(UNREGISTERED);
    const note = openRecipientNote(reader(commitment(body, ENROLLED_KEY)), opened(body));
    expect(note?.registered).toBe(false);
  });

  it("rebuilds with the ring data hash and the data hash the payload carries", () => {
    const ringDataHash = field(21);
    const dataHash = field(22);
    const appData = Uint8Array.of(1, 2, 3);
    const body: Body = {
      ...plain(),
      ringDataHash,
      data: Uint8Array.of(...dataHash, ...appData),
    };
    const published = commitment(body, ENROLLED_KEY, { dataHash, ringDataHash, appData });
    const note = openRecipientNote(reader(published), opened(body));
    expect(note?.dataHash).toEqual(dataHash);
    expect(note?.ringDataHash).toEqual(ringDataHash);
    expect(note?.utxo.data.utxoData()).toEqual(appData);
    expect(
      openRecipientNote(reader(published), opened({ ...plain(), ringDataHash })),
    ).toBeUndefined();
  });

  it("refuses application bytes under a zero hash, the commitment reads no data", () => {
    const published = commitment(plain(), ENROLLED_KEY);
    expect(openRecipientNote(reader(published), opened(plain()))).toBeDefined();
    const unbound = new Uint8Array(32 + 7).fill(9);
    unbound.fill(0, 0, 32);
    expect(
      openRecipientNote(reader(published), opened({ ...plain(), data: unbound })),
    ).toBeUndefined();
    expect(
      openRecipientNote(reader(published), opened({ ...plain(), data: new Uint8Array(32) })),
    ).toBeUndefined();
  });

  it("refuses data shorter than its leading hash and a blinding off the field", () => {
    const published = commitment(plain(), ENROLLED_KEY);
    expect(
      openRecipientNote(reader(published), opened({ ...plain(), data: new Uint8Array(31) })),
    ).toBeUndefined();
    expect(
      openRecipientNote(
        reader(published),
        opened({ ...plain(), blinding: new Uint8Array(32).fill(0xff) as Bytes32 }),
      ),
    ).toBeUndefined();
  });
});
