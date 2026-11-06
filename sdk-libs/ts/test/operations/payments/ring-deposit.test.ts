import {
  AccountRole,
  getBase58Decoder,
  getBase58Encoder,
  getBase64Encoder,
  type Address,
} from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import type { Bytes32, Bytes64 } from "@heliuslabs/spr/interface";
import { ShieldedKeypair, SigningKey } from "@heliuslabs/spr/keypair";
import {
  AssetRegistry,
  SOL_MINT,
  type IndexedShieldedTransaction,
} from "@heliuslabs/spr/transaction";

import { RingAddress } from "../../../src/crypto/keys/ring-address.js";
import {
  PreparedRingDeposit,
  type RingDepositClient,
} from "../../../src/operations/payments/deposit.js";
import {
  decodeRelayProofInputs,
  depositRequestDigest,
} from "../../../src/protocol/ring-rpc/relay-proof-inputs.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import { AnonymousSync } from "../../../src/state/anonymous-sync.js";
import { ViewingHistory } from "../../../src/state/viewing-history.js";
import { BLOCKHASH } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import {
  PROOF_SERVICE,
  TREE,
  TREE_ID,
  randomAddress,
  ringFixture,
  walletKeys,
  type Fixture,
} from "../../helpers/ring-pipeline.js";
import { ScanIndexer } from "../../helpers/ring-scan.js";

const SALT = new Uint8Array(32).fill(1) as Bytes32;

beforeAll(async () => {
  await initializePoseidon();
});

function depositClient(fixture: Fixture): RingDepositClient {
  return {
    ...fixture.client,
    proofService: PROOF_SERVICE,
    getLatestBlockhash: async () => BLOCKHASH,
  };
}

/** The ring row Photon serves for the frame the fixture proved last. */
function indexedFrame(fixture: Fixture): IndexedShieldedTransaction {
  const call = fixture.sppCalls.at(-1);
  if (call === undefined) throw new Error("no SPP proof");
  const { proofInputs } = call;
  const { externalData } = proofInputs;
  return {
    slot: 3n,
    txSignature: getBase58Decoder().decode(new Uint8Array(64).fill(9)) as never,
    eventIndex: 0,
    txViewingPublicKey: externalData.txViewingPublicKey,
    salt: externalData.salt,
    outputSlots: externalData.outputs.map((output, index) => ({
      viewTag: externalData.resolvedOwnerTags[index] ?? new Uint8Array(32),
      outputContext: {
        hash: output.utxoHash,
        tree: TREE,
        treeId: TREE_ID,
        leafIndex: BigInt(index),
      },
      payload: output.data ?? new Uint8Array(),
    })) as IndexedShieldedTransaction["outputSlots"],
    messages: externalData.messages,
    nullifiers: proofInputs.inputUtxos.map((spent) => spent.nullifier()),
    proofless: false,
    ringProgramId: fixture.ringProgramId,
  };
}

describe("ring deposit", () => {
  it("proves a confidential deposit as a transfer that spends no note, the funder signing its leg", async () => {
    const fixture = await ringFixture();
    const recipient = ShieldedKeypair.generate();
    fixture.enroll(recipient.shieldedAddress());
    const funder = randomAddress();
    const client = depositClient(fixture);
    const prepared = await PreparedRingDeposit.prepare({
      client,
      ringProgramId: fixture.ringProgramId,
      feePayer: fixture.authority,
      depositor: funder,
      recipient: { kind: "confidential", address: recipient.shieldedAddress() },
      amount: 25n,
    });
    const proven = await prepared.prove(client);

    expect(proven.instruction.data?.[0]).toBe(RingInstructionTag.transfer);
    const [call] = fixture.sppCalls;
    expect(call?.proofInputs.inputUtxos.every((spent) => spent.isDummy())).toBe(true);
    expect(call?.proofInputs.externalData.interfaceTransfers).toEqual([
      { kind: "sol", isDeposit: true, amount: 25n, userSolAccount: funder },
    ]);
    expect(proven.instruction.accounts?.filter((meta) => meta.address === funder)).toEqual([
      expect.objectContaining({ role: AccountRole.WRITABLE_SIGNER }),
    ]);
    expect(fixture.ringRequests.map((request) => request.kind)).toEqual(["transfer"]);
    expect(proven.utxo.amount).toBe(25n);
    expect(proven.utxo.owner.equals(recipient.signingPublicKey())).toBe(true);
    await expect(prepared.prove(client)).rejects.toMatchObject({
      causeCode: "RING_DEPOSIT_FRAME_REUSED",
    });
  });

  it("pays an anonymous recipient a plan slot it finds through its normal sync", async () => {
    const fixture = await ringFixture({ mode: "anonymous" });
    const recipient = ShieldedKeypair.generate();
    fixture.enroll(recipient.shieldedAddress());
    const to = new RingAddress({
      recipient: recipient.shieldedAddress(),
      ringProgramId: fixture.ringProgramId,
      listSalt: SALT,
    });
    const client = depositClient(fixture);
    const prepared = await PreparedRingDeposit.prepare({
      client,
      ringProgramId: fixture.ringProgramId,
      feePayer: fixture.authority,
      recipient: { kind: "anonymousPayment", to },
      amount: 40n,
    });
    await prepared.prove(client);

    const indexer = new ScanIndexer();
    indexer.publish(indexedFrame(fixture));
    const keys = walletKeys(recipient);
    const scan = await AnonymousSync.create(keys, new AssetRegistry()).fetch(
      indexer.client(),
      ViewingHistory.create(recipient.shieldedAddress().viewingPublicKey, 0n).withRing(
        fixture.ringProgramId,
      ),
    );
    expect(scan.utxos.map((note) => [note.utxo.amount, note.utxo.asset])).toEqual([
      [40n, SOL_MINT],
    ]);
  });

  it("refuses a recipient of the other ring mode and a ring address of another ring before proving", async () => {
    const confidential = await ringFixture();
    const anonymous = await ringFixture({ mode: "anonymous" });
    const owner = ShieldedKeypair.generate();
    const keys = walletKeys(owner);
    const attempt = (
      fixture: Fixture,
      recipient: Parameters<typeof PreparedRingDeposit.prepare>[0]["recipient"],
    ) =>
      PreparedRingDeposit.prepare({
        client: depositClient(fixture),
        ringProgramId: fixture.ringProgramId,
        feePayer: fixture.authority,
        recipient,
        amount: 1n,
      });
    await expect(
      attempt(anonymous, { kind: "confidential", address: owner.shieldedAddress() }),
    ).rejects.toMatchObject({ causeCode: "RING_ANONYMOUS_REFUSED" });
    await expect(
      attempt(confidential, { kind: "anonymous", keys, listSalt: SALT }),
    ).rejects.toMatchObject({ causeCode: "RING_NOT_ANONYMOUS" });
    const foreign = new RingAddress({
      recipient: owner.shieldedAddress(),
      ringProgramId: randomAddress(),
      listSalt: SALT,
    });
    await expect(
      attempt(anonymous, { kind: "anonymousPayment", to: foreign }),
    ).rejects.toMatchObject({ causeCode: "RING_FOREIGN_RING" });
    expect([...confidential.sppCalls, ...anonymous.sppCalls]).toEqual([]);
  });

  it("relays a deposit on the deposit rail under the funder's request signature and refuses a funding fee payer", async () => {
    const fixture = await ringFixture({ mode: "anonymous" });
    const owner = ShieldedKeypair.generate();
    fixture.enroll(owner.shieldedAddress());
    const signing = SigningKey.generate();
    const funder = getBase58Decoder().decode(signing.publicKey().ed25519()) as Address;
    const depositorSigner = {
      address: funder,
      signMessages: async (messages: readonly { content: Uint8Array }[]) =>
        messages.map((message) => ({ [funder]: signing.sign(message.content) })),
    } as never;
    const params = {
      client: depositClient(fixture),
      ringProgramId: fixture.ringProgramId,
      depositor: funder,
      depositorSigner,
      recipient: { kind: "anonymous", keys: walletKeys(owner), listSalt: SALT } as const,
      amount: 9n,
    };
    const { relay } = await PreparedRingDeposit.prepareRelay({
      ...params,
      quote: { feePayer: fixture.authority, validUntilSlot: 100n },
    });
    const { intent } = relay.request;
    if (intent.operation !== "deposit") throw new Error("a deposit relay");
    const payload = new Uint8Array(getBase64Encoder().encode(intent.proofInputs));
    expect(payload[0]).toBe(3);
    const decoded = await decodeRelayProofInputs(payload, new AssetRegistry());
    expect(decoded.rail.kind).toBe("deposit");
    expect(decoded.inputs.every((spent) => spent.isDummy())).toBe(true);
    const signature = new Uint8Array(getBase58Encoder().encode(intent.depositorSignature));
    expect(signing.verify(depositRequestDigest(payload), signature as Bytes64)).toBe(true);
    expect(fixture.sppCalls).toEqual([]);

    await expect(
      PreparedRingDeposit.prepareRelay({
        ...params,
        quote: { feePayer: funder, validUntilSlot: 100n },
      }),
    ).rejects.toMatchObject({ causeCode: "RING_RELAY_FEE_PAYER_FUNDS_DEPOSIT" });
  });
});
