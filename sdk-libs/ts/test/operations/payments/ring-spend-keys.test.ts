import { generateKeyPairSigner, type Address } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import type { ProofAuthority, ProverInputs } from "@heliuslabs/spr/client";
import {
  bigIntBytes,
  bytesToBigInt,
  poseidon,
  randomBytes,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import type { Bytes31, Bytes32 } from "@heliuslabs/spr/interface";
import { NullifierKey, ShieldedKeypair } from "@heliuslabs/spr/keypair";
import { SOL_MINT, Utxo, type SppProofInputs, type WalletUtxo } from "@heliuslabs/spr/transaction";

import {
  checkCoOwnerKeys,
  ringSpendAuthority,
  ringSpendTransfer,
} from "../../../src/operations/payments/ring-spend.js";
import {
  noteNullifierPublicKey,
  ringProofInput,
} from "../../../src/operations/workflow/selection.js";
import { RingError } from "../../../src/protocol/error.js";

const TREE_ID = 0;
const TREE = "11111111111111111111111111111111" as Address;
const CLIENT = { tree: TREE, treeId: TREE_ID } as Parameters<typeof ringProofInput>[2];

function note(
  owner: ShieldedKeypair,
  key: Bytes32,
  amount: bigint,
  nullifier: Bytes32,
): WalletUtxo {
  const utxo = new Utxo({
    owner: owner.signingPublicKey(),
    asset: SOL_MINT,
    amount,
    blinding: Uint8Array.of(0, ...randomBytes(31)) as Bytes32,
  });
  return {
    utxo,
    outputContext: { hash: utxo.proofInput(key, TREE_ID).hash(), tree: TREE, leafIndex: 0n },
    nullifier,
    spent: false,
  } as WalletUtxo;
}

describe("a spend of notes the core builder refuses", () => {
  beforeAll(initializePoseidon);

  it("finds the key a note's commitment rebuilds under, own first and zero after", () => {
    const owner = ShieldedKeypair.generate();
    const address = owner.shieldedAddress();
    const own = note(owner, address.nullifierPublicKey, 5n, ZERO_NULLIFIER_PK);
    const zero = note(owner, ZERO_NULLIFIER_PK, 5n, ZERO_NULLIFIER_PK);
    expect(noteNullifierPublicKey(own, address, TREE_ID)).toEqual(address.nullifierPublicKey);
    expect(noteNullifierPublicKey(zero, address, TREE_ID)).toEqual(ZERO_NULLIFIER_PK);
    expect(ringProofInput(zero, address, CLIENT).nullifierPublicKey).toEqual(ZERO_NULLIFIER_PK);
  });

  it("spends a zero key note beside an own note and counts both toward the change", async () => {
    const owner = ShieldedKeypair.generate();
    const address = owner.shieldedAddress();
    const inputs = [
      ringProofInput(
        note(owner, address.nullifierPublicKey, 30n, address.nullifierPublicKey),
        address,
        CLIENT,
      ),
      ringProofInput(note(owner, ZERO_NULLIFIER_PK, 12n, ZERO_NULLIFIER_PK), address, CLIENT),
    ];
    const payer = await generateKeyPairSigner();
    const prepared = ringSpendTransfer({ owner: address, inputs, feePayer: payer.address })
      .withOutputTreeId(TREE_ID)
      .prepare();
    expect(prepared.inputs).toEqual(inputs);
    expect(prepared.proofOutputs()[0]?.amount).toBe(42n);
  });

  it("carries a co-owner's value and its first input's nullifier", async () => {
    const owner = ShieldedKeypair.generate();
    const coOwner = ShieldedKeypair.generate();
    const address = owner.shieldedAddress();
    const inputs = [
      ringProofInput(
        note(owner, address.nullifierPublicKey, 30n, address.nullifierPublicKey),
        address,
        CLIENT,
      ),
    ];
    const payer = await generateKeyPairSigner();
    const foreign = ringProofInput(
      note(coOwner, coOwner.shieldedAddress().nullifierPublicKey, 8n, ZERO_NULLIFIER_PK),
      coOwner.shieldedAddress(),
      CLIENT,
    );
    const prepared = ringSpendTransfer({
      owner: address,
      inputs: [...inputs, foreign],
      feePayer: payer.address,
    }).prepare();
    expect(prepared.firstNullifier).toEqual(address.nullifierPublicKey);
    expect(prepared.proofOutputs()[0]?.amount).toBe(38n);
    expect(prepared.inputs[1]?.utxo.owner.equals(coOwner.signingPublicKey())).toBe(true);
  });

  it("completes a co-owner's and a zero key input and passes the sender's to its keys", async () => {
    const coOwnerKey = NullifierKey.fromSecret(new Uint8Array(31).fill(7) as Bytes31);
    const hash = 5n;
    const slot = (key: Bytes32) => ({
      circuit: { owner: bytesToBigInt(poseidon([bigIntBytes(hash) as Bytes32, key])) },
      ownerPublicKeyHash: hash,
      isDummy: 0n,
    });
    const own = slot(new Uint8Array(32).fill(1) as Bytes32);
    const coOwned = slot(coOwnerKey.publicKey());
    const zero = slot(ZERO_NULLIFIER_PK);
    let seen: ProverInputs | undefined;
    const keys: ProofAuthority = {
      prove: async (inputs) => {
        seen = inputs;
        return {} as Awaited<ReturnType<ProofAuthority["prove"]>>;
      },
      proveMerge: async () => ({}) as Awaited<ReturnType<ProofAuthority["proveMerge"]>>,
    };
    const sender = ShieldedKeypair.generate();
    const foreign = ringProofInput(
      note(ShieldedKeypair.generate(), ZERO_NULLIFIER_PK, 5n, ZERO_NULLIFIER_PK),
      sender.shieldedAddress(),
      CLIENT,
    );
    await ringSpendAuthority({
      keys,
      coOwners: [{ owner: TREE, nullifierKey: coOwnerKey }],
      proofInputs: { inputUtxos: [foreign] } as unknown as SppProofInputs,
      sender: sender.shieldedAddress(),
    }).prove({ payload: { inputs: [own, coOwned, zero] } } as unknown as ProverInputs);
    const secrets = (
      seen as unknown as { payload: { inputs: { nullifierSecret?: bigint }[] } }
    ).payload.inputs.map((input) => input.nullifierSecret);
    expect(secrets[0]).toBeUndefined();
    expect(secrets[1]).toBe(bytesToBigInt(coOwnerKey.secretBytes()));
    expect(secrets[2]).toBe(0n);
  });

  it("refuses a foreign input without its owner's key before any proof", () => {
    const sender = ShieldedKeypair.generate();
    const stranger = ShieldedKeypair.generate();
    const foreign = ringProofInput(
      note(stranger, stranger.shieldedAddress().nullifierPublicKey, 5n, ZERO_NULLIFIER_PK),
      stranger.shieldedAddress(),
      CLIENT,
    );
    const proofInputs = { inputUtxos: [foreign] } as unknown as Parameters<
      typeof checkCoOwnerKeys
    >[0];
    expect(() => checkCoOwnerKeys(proofInputs, sender.shieldedAddress(), [])).toThrow(RingError);
    expect(() =>
      checkCoOwnerKeys(proofInputs, sender.shieldedAddress(), [
        { owner: TREE, nullifierKey: stranger.nullifierKey() },
      ]),
    ).not.toThrow();
  });
});
