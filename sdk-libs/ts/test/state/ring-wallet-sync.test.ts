import { address, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";
import {
  Data,
  LocalShieldedKeys,
  SOL_MINT,
  ShieldedKeypair,
  Utxo,
  ViewingKey,
  type Bytes16,
  type Bytes32,
} from "@heliuslabs/zolana";
import { DEFAULT_TREE_ID } from "@heliuslabs/zolana/interface";
import { AssetRegistry, type IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";

import {
  encodeRingOutput,
  RingScheme,
  sealDeliveredBody,
} from "../../src/protocol/transaction/output.js";
import { deliveredSlotSecret } from "../../src/crypto/derivation/ring-stream.js";
import { LocalRingKeys } from "../../src/state/ring-keys.js";
import { openRingNotes } from "../../src/state/ring-sync.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const SALT = new Uint8Array(16).fill(7) as Bytes16;
const FIRST_NULLIFIER = new Uint8Array(32).fill(9) as Bytes32;
const AMOUNT = 25_000n;

/** Below the field modulus, a commitment binds it. */
function blinding(): Bytes32 {
  const bytes = new Uint8Array(32).fill(3);
  bytes[0] = 0;
  return bytes as Bytes32;
}

function note(owner: ShieldedKeypair): Readonly<{ utxo: Utxo; hash: Bytes32 }> {
  const utxo = new Utxo({
    owner: owner.shieldedAddress().signingPublicKey,
    asset: SOL_MINT,
    amount: AMOUNT,
    blinding: blinding(),
    data: new Data(),
    ringProgramId: RING,
  });
  return { utxo, hash: utxo.hash(owner.nullifierPublicKey(), DEFAULT_TREE_ID) };
}

function transaction(
  txKey: ViewingKey,
  viewTag: Bytes32,
  hash: Bytes32,
  payload: Uint8Array,
): IndexedShieldedTransaction {
  return {
    slot: 1n,
    txSignature: "1".repeat(64) as Signature,
    txViewingPublicKey: txKey.publicKey(),
    salt: SALT,
    outputSlots: [
      {
        viewTag,
        outputContext: { hash, tree: TREE, treeId: DEFAULT_TREE_ID, leafIndex: 0n },
        payload,
      },
    ],
    messages: [],
    nullifiers: [FIRST_NULLIFIER],
    proofless: false,
    ringProgramId: RING,
  };
}

/** Scheme 10 under the sender's agreement with the recipient key, the body names no asset. */
function delivered(
  recipient: ShieldedKeypair,
  hash = note(recipient).hash,
): IndexedShieldedTransaction {
  const txKey = ViewingKey.generate();
  const viewing = recipient.shieldedAddress().viewingPublicKey;
  const slotSecret = deliveredSlotSecret({
    agreement: txKey.ecdh(viewing),
    txViewingKey: txKey.publicKey(),
    recipientViewingKey: viewing,
    salt: SALT,
    outputIndex: 0,
    firstNullifier: FIRST_NULLIFIER,
  });
  const body = sealDeliveredBody(slotSecret, { blinding: blinding(), amount: AMOUNT });
  return transaction(
    txKey,
    viewing.u(),
    hash,
    encodeRingOutput(RingScheme.ringConfidentialDelivered, body),
  );
}

async function opened(
  keys: Parameters<typeof openRingNotes>[0]["keys"],
  transactions: readonly IndexedShieldedTransaction[],
) {
  return openRingNotes({ keys, assets: new AssetRegistry(), transactions });
}

describe("openRingNotes", () => {
  it("opens a delivered note under ring keys by trial over the registered mints", async () => {
    const recipient = ShieldedKeypair.generate();
    const tx = delivered(recipient);
    const notes = await opened(LocalRingKeys.fromKeypair(recipient), [tx]);
    expect(notes.utxos.map((entry) => [entry.utxo.amount, entry.utxo.asset])).toEqual([
      [AMOUNT, SOL_MINT],
    ]);
    expect(notes.utxos[0]?.outputContext.hash).toEqual(note(recipient).hash);
    expect(notes.utxos[0]?.outputContext.tree).toBe(TREE);
    expect(notes.utxos[0]?.spent).toBe(false);
    expect(notes.pending).toBe(0);
    const plain = await opened(LocalShieldedKeys.fromKeypair(recipient), [tx]);
    expect(plain.utxos).toEqual([]);
    const stranger = await opened(LocalRingKeys.fromKeypair(ShieldedKeypair.generate()), [tx]);
    expect(stranger).toEqual({ utxos: [], pending: 0 });
  });

  it("keeps no note and counts it pending when no registered mint rebuilds its commitment", async () => {
    const recipient = ShieldedKeypair.generate();
    const unregistered = new Uint8Array(32).fill(1) as Bytes32;
    const notes = await opened(LocalRingKeys.fromKeypair(recipient), [
      delivered(recipient, unregistered),
    ]);
    expect(notes).toEqual({ utxos: [], pending: 1 });
  });
});
