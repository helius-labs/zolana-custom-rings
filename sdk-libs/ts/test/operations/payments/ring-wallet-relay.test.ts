import { getBase64Decoder, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import { randomBlinding, ShieldedKeypair, SigningKey } from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  SOL_MINT,
  Utxo,
  Wallet,
  approveUnattended,
  type ApprovalHandler,
  type ApprovalRequest,
} from "@heliuslabs/zolana/transaction";
import type { Bytes32 } from "@heliuslabs/zolana/interface";

import { PreparedRingDeposit } from "../../../src/operations/payments/deposit.js";
import { prepareRingMergeRelay } from "../../../src/operations/payments/merge.js";
import { signingKeySpendSigner } from "../../../src/operations/payments/anonymous.js";
import {
  prepareRingTransferRelay,
  prepareRingWithdrawalRelay,
} from "../../../src/operations/payments/transfer.js";
import { buildRuleTable } from "../../../src/protocol/membership/policy.js";
import { CustomRingClient } from "../../../src/rpc/client.js";
import type { PreparedRelay } from "../../../src/rpc/relay.js";
import { RingRpc } from "../../../src/rpc/ring-rpc.js";

import {
  TREE,
  TREE_ID,
  randomAddress,
  ringFixture,
  walletKeys,
  type Fixture,
} from "../../helpers/ring-pipeline.js";

await initializePoseidon();

const CHAIN_READS = new Set(["getAccountInfo"]);
const base64 = getBase64Decoder();

function walletNetwork(fixture: Fixture) {
  const methods: string[] = [];
  let relayAnswer: string | undefined;
  const account = (address: Address): string => {
    const served = fixture.accounts.get(address);
    if (served === undefined) return "null";
    return JSON.stringify({
      data: [base64.decode(served.data), "base64"],
      executable: false,
      lamports: Number(served.lamports),
      owner: served.owner,
      rentEpoch: 0,
      space: served.data.length,
    });
  };
  const fetch: typeof globalThis.fetch = async (_input, init) => {
    const body = JSON.parse(String(init?.body)) as {
      id: unknown;
      method: string;
      params: unknown;
    };
    methods.push(body.method);
    const params = body.params as readonly [Address, ...unknown[]];
    const result =
      body.method === "getAccountInfo"
        ? `{"context":{"slot":1},"value":${account(params[0])}}`
        : body.method === "prepareRelay"
          ? relayAnswer
          : undefined;
    const reply =
      result === undefined ? `"error":{"code":-32601,"message":"unserved"}` : `"result":${result}`;
    return new Response(`{"jsonrpc":"2.0","id":${JSON.stringify(body.id)},${reply}}`, {
      headers: { "content-type": "application/json" },
    });
  };
  const client = new CustomRingClient({
    solanaRpcUrl: "https://solana.example",
    indexerUrl: "https://photon.example",
    proverUrl: "https://prover.example",
    tree: TREE,
    fetch,
  });
  const ringRpc = new RingRpc("https://ring-rpc.example", { fetch });
  return {
    client,
    methods,
    /** Every request but the chain reads, once Ring RPC accepts the relay. */
    send: async (relay: PreparedRelay) => {
      relayAnswer = JSON.stringify({ step: "submitted", relayId: relay.relayId() });
      await relay.send(ringRpc);
      return methods.filter((method) => !CHAIN_READS.has(method));
    },
  };
}

/** An Ed25519 owner holding `count` ring notes, each naming its leaf. */
function owner(fixture: Fixture, count: number, asset: Address = SOL_MINT) {
  const signing = SigningKey.generate();
  const keypair = ShieldedKeypair.fromKeypair(signing);
  const registry = new AssetRegistry();
  if (asset !== SOL_MINT) registry.insert(2n, asset);
  const wallet = new Wallet({ identity: keypair.shieldedAddress(), registry });
  wallet._replace({
    utxos: Array.from({ length: count }, (_, index) => {
      const utxo = new Utxo({
        owner: keypair.signingPublicKey(),
        asset,
        amount: 10n,
        blinding: randomBlinding(),
        ringProgramId: fixture.ringProgramId,
      });
      const hash = utxo.proofInput(keypair.nullifierPublicKey(), TREE_ID).hash();
      return {
        utxo,
        outputContext: { hash, tree: TREE, leafIndex: BigInt(index) },
        nullifier: utxo.nullifier(hash, keypair.nullifierKey()),
        spent: false,
      };
    }),
    transactions: [],
    nullifiers: new Set(),
  });
  return { signing, keypair, wallet };
}

describe("wallet relay", () => {
  it("relays a confidential policy ring transfer and SPL withdrawal with no path, opening or pool request", async () => {
    const fixture = await ringFixture({ table: buildRuleTable({ rules: [] }) });
    const network = walletNetwork(fixture);
    const sender = owner(fixture, 2);
    const prepared = await prepareRingTransferRelay({
      client: network.client,
      ringProgramId: fixture.ringProgramId,
      wallet: sender.wallet,
      keys: walletKeys(sender.keypair),
      amount: 15n,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      confidential: {
        quote: { feePayer: fixture.authority, validUntilSlot: 100n },
        nullifierKey: sender.keypair.nullifierKey(),
        signer: signingKeySpendSigner(sender.signing),
      },
    });

    expect(prepared.relay.request.intent.operation).toBe("confidential");
    expect(await network.send(prepared.relay)).toEqual(["prepareRelay"]);

    const mint = randomAddress();
    const holder = owner(fixture, 1, mint);
    const recipient = randomAddress();
    const exit = walletNetwork(fixture);
    const withdrawal = await prepareRingWithdrawalRelay({
      client: exit.client,
      ringProgramId: fixture.ringProgramId,
      wallet: holder.wallet,
      keys: walletKeys(holder.keypair),
      asset: mint,
      amount: 4n,
      recipient,
      confidential: {
        quote: { feePayer: fixture.authority, validUntilSlot: 100n },
        nullifierKey: holder.keypair.nullifierKey(),
        signer: signingKeySpendSigner(holder.signing),
      },
    });

    expect(withdrawal.relay.request.intent).toMatchObject({
      operation: "confidential",
      tokenAccountSetup: [{ owner: recipient, mint }],
    });
    expect(await exit.send(withdrawal.relay)).toEqual(["prepareRelay"]);
  });

  it("relays a deposit into a key escrow ring with no opening request", async () => {
    const fixture = await ringFixture({ mode: "confidentialEscrow", records: [] });
    const network = walletNetwork(fixture);
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const approvals: ApprovalRequest[] = [];
    const prepared = await PreparedRingDeposit.prepareRelay({
      client: network.client,
      ringProgramId: fixture.ringProgramId,
      depositor: randomAddress(),
      recipient: { kind: "confidential", address: recipient },
      amount: 5n,
      quote: { feePayer: fixture.authority, validUntilSlot: 100n },
      approve: (request) => {
        approvals.push(request);
        return approveUnattended(request);
      },
    });

    expect(approvals).toMatchObject([
      {
        intent: {
          kind: "ringDeposit",
          ringProgramId: fixture.ringProgramId,
          amount: 5n,
          recipient,
        },
      },
    ]);
    expect(await network.send(prepared.relay)).toEqual(["prepareRelay"]);
  });

  it("relays an approved merge of the wallet's leased notes with no path or opening request", async () => {
    const fixture = await ringFixture({ mode: "confidentialEscrow", records: [] });
    const network = walletNetwork(fixture);
    const sender = owner(fixture, 3);
    const approvals: ApprovalRequest[] = [];
    const recorded: ApprovalHandler = (request) => {
      approvals.push(request);
      return approveUnattended(request);
    };
    const merge = (feePayer: Address, approve = recorded) =>
      prepareRingMergeRelay({
        client: network.client,
        ringProgramId: fixture.ringProgramId,
        wallet: sender.wallet,
        nullifierKey: sender.keypair.nullifierKey(),
        quote: { feePayer, validUntilSlot: 100n },
        approve,
      });

    await expect(merge(sender.keypair.shieldedAddress().solanaAddress())).rejects.toMatchObject({
      cause: { code: "RING_ANONYMOUS_SIGNER_LINKS_OWNER" },
    });
    // A refused approval releases the lease, the next merge takes the same notes.
    await expect(
      merge(fixture.authority, () =>
        Promise.resolve({ intentHash: new Uint8Array(32) as Bytes32 }),
      ),
    ).rejects.toMatchObject({ cause: { code: "RING_INTENT_MISMATCH" } });
    const relay = await merge(fixture.authority);

    expect(approvals).toMatchObject([
      { intent: { kind: "ringMerge", numInputs: 3, mergedAmount: 30n, outputTree: TREE } },
    ]);
    expect(await network.send(relay)).toEqual(["prepareRelay"]);
    await expect(merge(fixture.authority)).rejects.toMatchObject({
      cause: { code: "RING_NOTHING_TO_MERGE" },
    });
  });
});
