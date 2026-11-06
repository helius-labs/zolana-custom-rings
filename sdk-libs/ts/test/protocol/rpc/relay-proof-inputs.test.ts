import { readFileSync } from "node:fs";

import { getBase58Decoder, getBase64Encoder, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import { Writer, addressBytes, splInterfaceWithBump } from "@heliuslabs/spr/internal";
import { TransactWithdrawal, type Bytes32 } from "@heliuslabs/spr/interface";
import { ShieldedKeypair, SigningKey, ViewingKey } from "@heliuslabs/spr/keypair";
import {
  AssetRegistry,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  createExternalData,
  createProofOutput,
} from "@heliuslabs/spr/transaction";

import { AnonymousPlan } from "../../../src/operations/payments/output-rail.js";
import {
  decodeRelayProofInputs,
  encodeRelayMergeInputs,
  encodeRelayProofInputs,
  writeRelayListSalts,
  type RelayProofInputs,
  type RelayRail,
} from "../../../src/protocol/ring-rpc/relay-proof-inputs.js";

await initializePoseidon();

const base58 = getBase58Decoder();

function filled(byte: number, length = 32): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

function address(byte: number): Address {
  return base58.decode(filled(byte)) as Address;
}

function ownerSpend() {
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
  return { owner, sender, ring, spend };
}

function anonymousPayload() {
  const vector = JSON.parse(
    readFileSync(
      new URL("../../../../../test-vectors/rpc/relay_proof_inputs.json", import.meta.url),
      "utf8",
    ),
  ) as { proofInputs: string };
  const { owner, sender, ring, spend } = ownerSpend();
  const txViewingKey = ViewingKey.fromBytes(filled(13) as Bytes32);
  const recipient = address(14);
  const proofInputs: RelayProofInputs = {
    rail: {
      kind: "anonymous",
      plan: AnonymousPlan.fromDummyPreimages(
        [{ recipient: owner.viewingPublicKey(), reply: null }],
        Array.from({ length: 16 }, () => filled(25) as Bytes32),
      ),
    },
    ringProgramId: ring,
    sender,
    nullifierKey: owner.nullifierKey(),
    txViewingKey,
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
        {
          kind: "sol",
          isDeposit: false,
          amount: 100n,
          userSolAccount: recipient,
        },
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
    interfaceTransferAccounts: [TransactWithdrawal.sol({ recipient })],
    blindingSeed: filled(28) as Bytes32,
    outputTreeId: 4,
    wideOwners: false,
    assets: new AssetRegistry(),
    listSalts: [],
    coOwners: [],
  };
  const wire = new Uint8Array(getBase64Encoder().encode(vector.proofInputs));
  return { proofInputs, wire, spend, recipient };
}

describe("relay proof inputs", () => {
  it("names other owners' salts, the sender's and a zero-key salt left out", () => {
    const { sender } = ownerSpend();
    const senderOwner = sender.signingPublicKey.ownerProofInputHash();
    const owner = filled(70) as Bytes32;
    const salt = filled(71) as Bytes32;
    const written = writeRelayListSalts(
      new Writer(),
      [
        { owner: senderOwner, salt },
        { owner, salt },
        { owner: filled(72) as Bytes32, salt: filled(0) as Bytes32 },
      ],
      sender,
    ).finish();
    expect(written).toEqual(Uint8Array.of(1, ...owner, ...salt));
  });

  it("encodes the anonymous payload byte for byte as the Rust vector and derives its spend on decode", async () => {
    const { proofInputs, wire, spend, recipient } = anonymousPayload();
    expect(encodeRelayProofInputs(proofInputs)).toEqual(wire);
    const read = await decodeRelayProofInputs(wire, new AssetRegistry());
    expect(read.inputs[0]?.nullifier()).toEqual(spend.nullifier());
    expect(encodeRelayProofInputs(read)).toEqual(wire);
    expect(read.approvalBlinder).toBeUndefined();

    const blinder = filled(29) as Bytes32;
    const disclosed = encodeRelayProofInputs({ ...proofInputs, approvalBlinder: blinder });
    expect(disclosed).toEqual(Uint8Array.of(...wire.subarray(0, -1), 1, ...blinder));
    expect((await decodeRelayProofInputs(disclosed, new AssetRegistry())).approvalBlinder).toEqual(
      blinder,
    );
    const badTag = wire.slice();
    badTag[badTag.length - 1] = 2;
    await expect(decodeRelayProofInputs(badTag, new AssetRegistry())).rejects.toMatchObject({
      code: "RING_RELAY_PROOF_INPUTS",
    });

    const { plan } = proofInputs.rail as Extract<RelayRail, { kind: "anonymous" }>;
    const delegated = await decodeRelayProofInputs(
      encodeRelayProofInputs({
        ...proofInputs,
        rail: { kind: "delegate", delegate: recipient, plan },
      }),
      new AssetRegistry(),
    );
    expect(delegated.rail).toMatchObject({ kind: "delegate", delegate: recipient });
    const plainPlan = (delegated.rail as Extract<RelayRail, { kind: "delegate" }>).plan;
    expect(plainPlan?.dummyPreimages()).toEqual(plan.dummyPreimages());
    expect(plainPlan?.payments.map((payment) => payment.recipient.toBytes())).toEqual(
      plan.payments.map((payment) => payment.recipient.toBytes()),
    );
    const planless = await decodeRelayProofInputs(
      encodeRelayProofInputs({ ...proofInputs, rail: { kind: "delegate", delegate: recipient } }),
      new AssetRegistry(),
    );
    expect(planless.rail).toEqual({ kind: "delegate", delegate: recipient });
  });

  describe("deposit legs", () => {
    const funder = address(30);
    const mint = address(31);
    const tokenAuthority = address(32);
    const userTokenAccount = address(33);
    const tokenProgram = address(34);
    const funded = async (): Promise<RelayProofInputs> => {
      const { proofInputs } = anonymousPayload();
      const [splTokenInterface, splInterfaceBump] = await splInterfaceWithBump(mint);
      return {
        ...proofInputs,
        externalData: proofInputs.externalData.withInterfaceTransfers([
          { kind: "sol", isDeposit: true, amount: 7n, userSolAccount: funder },
          {
            kind: "spl",
            mint,
            isDeposit: true,
            amount: 8n,
            tokenAccount: userTokenAccount,
            splInterfaceBump,
          },
        ]),
        interfaceTransferAccounts: [
          TransactWithdrawal.sol({ recipient: funder }),
          {
            kind: "splDeposit",
            mint,
            splTokenInterface,
            tokenAuthority,
            userTokenAccount,
            tokenProgram,
          },
        ],
      };
    };

    it("writes each leg in the Rust `LegWire` layout and reads it back", async () => {
      const { wire, recipient } = anonymousPayload();
      const withdrawal = new Writer()
        .u8(1, "legs")
        .u8(0, "tag")
        .u64(100n, "amount")
        .bytes(addressBytes(recipient), 32, "recipient")
        .finish();
      const at = Buffer.from(wire).indexOf(withdrawal);
      expect(at).toBeGreaterThan(0);
      const legs = new Writer()
        .u8(2, "legs")
        .u8(2, "tag")
        .u64(7n, "amount")
        .bytes(addressBytes(funder), 32, "funder")
        .u8(3, "tag")
        .bytes(addressBytes(mint), 32, "mint")
        .u64(8n, "amount")
        .bytes(addressBytes(tokenAuthority), 32, "tokenAuthority")
        .bytes(addressBytes(userTokenAccount), 32, "userTokenAccount")
        .bytes(addressBytes(tokenProgram), 32, "tokenProgram")
        .finish();
      const input = await funded();
      const encoded = encodeRelayProofInputs(input);
      expect(encoded).toEqual(
        Uint8Array.of(...wire.subarray(0, at), ...legs, ...wire.subarray(at + withdrawal.length)),
      );
      const read = await decodeRelayProofInputs(encoded, new AssetRegistry());
      expect(read.externalData.interfaceTransfers).toEqual(input.externalData.interfaceTransfers);
      expect(read.interfaceTransferAccounts).toEqual(input.interfaceTransferAccounts);
      expect(encodeRelayProofInputs(read)).toEqual(encoded);
    });

    it("refuses a leg whose accounts name another funder, mint or direction", async () => {
      const input = await funded();
      const [sol, spl] = input.interfaceTransferAccounts;
      if (sol === undefined || spl?.kind !== "splDeposit") throw new Error("two legs");
      const refusesAt = (index: number, accounts: RelayProofInputs["interfaceTransferAccounts"]) =>
        expect(() =>
          encodeRelayProofInputs({ ...input, interfaceTransferAccounts: accounts }),
        ).toThrow(
          expect.objectContaining({
            code: "RING_RELAY_PROOF_INPUTS",
            details: { reason: "settlement", index },
          }),
        );
      refusesAt(0, [TransactWithdrawal.sol({ recipient: mint }), spl]);
      refusesAt(1, [sol, { ...spl, mint: funder }]);
      refusesAt(1, [sol, { ...spl, userTokenAccount: funder }]);
      refusesAt(1, [
        sol,
        TransactWithdrawal.spl({
          mint,
          splTokenInterface: spl.splTokenInterface,
          recipientTokenAccount: userTokenAccount,
          tokenProgram,
        }),
      ]);
      refusesAt(1, [sol]);
    });

    it("refuses a leg tag past the deposits", async () => {
      const encoded = encodeRelayProofInputs(await funded());
      const tag = Buffer.from(encoded).indexOf(
        Uint8Array.of(2, ...new Writer().u64(7n, "amount").finish(), ...addressBytes(funder)),
      );
      const forged = encoded.slice();
      forged[tag] = 4;
      await expect(decodeRelayProofInputs(forged, new AssetRegistry())).rejects.toMatchObject({
        code: "RING_RELAY_PROOF_INPUTS",
      });
    });
  });

  it("encodes the merge payload byte for byte as the Rust vector", () => {
    const vector = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/relay_merge_inputs.json", import.meta.url),
        "utf8",
      ),
    ) as { proofInputs: string };
    const { owner, sender, ring, spend } = ownerSpend();
    const encoded = encodeRelayMergeInputs({
      ringProgramId: ring,
      sender,
      nullifierKey: owner.nullifierKey(),
      inputs: [spend],
      leafIndexes: [17n],
      assets: new AssetRegistry(),
    });
    expect(encoded).toEqual(new Uint8Array(getBase64Encoder().encode(vector.proofInputs)));
  });

  it("reads and writes the Rust deposit rail vector byte for byte", async () => {
    const vector = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/relay_deposit_proof_inputs.json", import.meta.url),
        "utf8",
      ),
    ) as { proofInputs: string };
    const wire = new Uint8Array(getBase64Encoder().encode(vector.proofInputs));
    const read = await decodeRelayProofInputs(wire, new AssetRegistry());
    expect(read.rail).toMatchObject({ kind: "deposit", plan: expect.anything() });
    expect(read.inputs.every((spent) => spent.isDummy())).toBe(true);
    expect(encodeRelayProofInputs(read)).toEqual(wire);
  });

  it("writes the deposit rail as tag 3, its plan exactly on an anonymous ring", async () => {
    const { proofInputs } = anonymousPayload();
    const { plan } = proofInputs.rail as Extract<RelayRail, { kind: "anonymous" }>;
    for (const rail of [{ kind: "deposit" } as const, { kind: "deposit", plan } as const]) {
      const wire = encodeRelayProofInputs({ ...proofInputs, rail });
      expect(wire[0]).toBe(3);
      expect(wire[1]).toBe(rail.plan === undefined ? 0 : 1);
      const read = await decodeRelayProofInputs(wire, new AssetRegistry());
      expect(read.rail.kind).toBe("deposit");
      expect(encodeRelayProofInputs(read)).toEqual(wire);
    }
  });
});
