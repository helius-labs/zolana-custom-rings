import { readFileSync } from "node:fs";

import { getBase58Decoder, getBase64Encoder, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import { TransactWithdrawal, type Bytes32 } from "@heliuslabs/zolana/interface";
import { ShieldedKeypair, SigningKey, ViewingKey } from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  createExternalData,
  createProofOutput,
} from "@heliuslabs/zolana/transaction";

import { AnonymousPlan } from "../../../src/operations/payments/output-rail.js";
import {
  decodeRelayProofInputs,
  encodeRelayProofInputs,
} from "../../../src/protocol/ring-rpc/relay-proof-inputs.js";

await initializePoseidon();

const base58 = getBase58Decoder();

function filled(byte: number, length = 32): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

function address(byte: number): Address {
  return base58.decode(filled(byte)) as Address;
}

describe("relay proof inputs", () => {
  it("encodes the anonymous payload byte for byte as the Rust vector and derives its spend on decode", async () => {
    const vector = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/relay_proof_inputs.json", import.meta.url),
        "utf8",
      ),
    ) as { proofInputs: string };
    const owner = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(5) as Bytes32));
    const sender = owner.shieldedAddress();
    const ring = address(6);
    const utxo = new Utxo({
      owner: sender.signingPublicKey,
      asset: SOL_MINT,
      amount: 900n,
      blinding: filled(11) as Bytes32,
      ringProgramId: ring,
    });
    const utxoHash = utxo.proofInput(sender.nullifierPublicKey, 4).hash();
    const spend = new ProofInputUtxo({
      utxo,
      nullifierPublicKey: sender.nullifierPublicKey,
      nullifier: utxo.nullifier(utxoHash, owner.nullifierKey()),
      treeId: 4,
    });
    const txViewingKey = ViewingKey.fromBytes(filled(13) as Bytes32);
    const recipient = address(14);
    const encoded = encodeRelayProofInputs({
      rail: {
        kind: "anonymous",
        plan: AnonymousPlan.fromTags(
          filled(23) as Bytes32,
          [{ recipient: owner.viewingPublicKey(), tag: filled(24) as Bytes32 }],
          Array.from({ length: 16 }, () => filled(25) as Bytes32),
        ),
      },
      ringProgramId: ring,
      sender,
      nullifierKey: owner.nullifierKey(),
      txViewingKey,
      auditEphemeralKey: filled(26) as Bytes32,
      inputs: [spend, ProofInputUtxo.dummy(filled(27) as Bytes32, 4)],
      leafIndexes: [17n, 0n],
      outputs: [
        createProofOutput({
          ownerAddress: sender,
          asset: SOL_MINT,
          amount: 800n,
          blinding: filled(12) as Bytes32,
          ringProgramId: ring,
        }),
      ],
      externalData: createExternalData({
        interfaceTransfers: [
          { kind: "sol", isDeposit: false, amount: 100n, userSolAccount: recipient },
        ],
        txViewingPublicKey: txViewingKey.publicKey(),
        salt: filled(15, 16) as never,
        outputs: [
          {
            utxoHash: filled(16) as Bytes32,
            ownerTag: { kind: "inline", value: filled(17) as Bytes32 },
            data: Uint8Array.of(18, 19),
          },
        ],
        resolvedOwnerTags: [filled(20) as Bytes32],
        messages: [{ viewTag: filled(21) as Bytes32, data: Uint8Array.of(22) }],
      }),
      withdrawal: TransactWithdrawal.sol({ recipient }),
      blindingSeed: filled(28) as Bytes32,
      outputTreeId: 4,
      assets: new AssetRegistry(),
    });
    const wire = new Uint8Array(getBase64Encoder().encode(vector.proofInputs));
    expect(encoded).toEqual(wire);
    const read = await decodeRelayProofInputs(wire, new AssetRegistry());
    expect(read.inputs[0]?.nullifier()).toEqual(spend.nullifier());
    expect(encodeRelayProofInputs(read)).toEqual(wire);
  });
});
