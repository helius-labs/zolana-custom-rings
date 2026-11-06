import {
  generateKeyPairSigner,
  getBase64Decoder,
  getBase64Encoder,
  type Address,
  type Signature,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import { randomBlinding, ShieldedKeypair, SigningKey } from "@heliuslabs/spr/keypair";
import {
  AssetRegistry,
  SOL_MINT,
  Utxo,
  Wallet,
  approveUnattended,
  type ApprovalHandler,
  type ApprovalRequest,
} from "@heliuslabs/spr/transaction";
import type { Bytes32 } from "@heliuslabs/spr/interface";

import { PreparedRingDeposit } from "../../../src/operations/payments/deposit.js";
import { prepareRingMergeRelay } from "../../../src/operations/payments/merge.js";
import { signingKeySpendSigner } from "../../../src/operations/payments/anonymous.js";
import {
  prepareRingTransferRelay,
  prepareRingWithdrawalRelay,
} from "../../../src/operations/payments/transfer.js";
import { buildRuleTable } from "../../../src/protocol/membership/policy.js";
import { decodeRelayProofInputs } from "../../../src/protocol/ring-rpc/relay-proof-inputs.js";
import { CustomRingClient } from "../../../src/rpc/client.js";
import type { PreparedRelay, RingRelayClient } from "../../../src/rpc/relay.js";
import type { RelayStatus } from "../../../src/protocol/ring-rpc/ring-rpc-types.js";
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
  let relayRefusal: number | undefined;
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
    const refusal = body.method === "prepareRelay" ? relayRefusal : undefined;
    const reply =
      refusal !== undefined
        ? `"error":{"code":${refusal},"message":"refused"}`
        : result === undefined
          ? `"error":{"code":-32601,"message":"unserved"}`
          : `"result":${result}`;
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
    /** Ring RPC answers every `prepareRelay` with `code`. */
    refuse: (code: number) => {
      relayRefusal = code;
    },
    ringRpc,
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
  it("reseals under the row a Ring RPC reseal refusal names and under the public counts' row unset", async () => {
    const fixture = await ringFixture({ table: buildRuleTable({ rules: [] }) });
    const network = walletNetwork(fixture);
    // Each preparation reserves its wallet's notes, so each takes its own sender.
    const prepare = (sender: ReturnType<typeof owner>, sealRow?: "wide") =>
      prepareRingTransferRelay({
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
          ...(sealRow === undefined ? {} : { sealRow }),
        },
      }).then(({ relay }) => relay.sign());
    const sealedWide = async (sealRow?: "wide") => {
      const sender = owner(fixture, 2);
      const prepared = await prepare(sender, sealRow);
      const { intent } = prepared.request;
      if (intent.operation !== "confidential") throw new Error("a confidential relay");
      const inputs = await decodeRelayProofInputs(
        new Uint8Array(getBase64Encoder().encode(intent.proofInputs)),
        sender.wallet.registry,
      );
      return inputs.wideOwners;
    };
    // Ring RPC names the row in its code.
    network.refuse(-32212);
    const unread = await prepare(owner(fixture, 2));
    const refusal = await unread.send(network.ringRpc).then(
      () => undefined,
      (cause: unknown) => cause,
    );
    expect(refusal).toMatchObject({
      code: "RING_RPC_REFUSED",
      details: { method: "prepareRelay", refusal: "resealWide" },
    });
    const named = (refusal as { details: { refusal: string } }).details.refusal;
    expect(await sealedWide()).toBe(false);
    expect(await sealedWide(named === "resealWide" ? "wide" : undefined)).toBe(true);
  });

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
    }).then(({ relay }) => relay.sign());

    expect(prepared.request.intent.operation).toBe("confidential");
    expect(await network.send(prepared)).toEqual(["prepareRelay"]);

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
    }).then(({ relay }) => relay.sign());

    expect(withdrawal.request.intent).toMatchObject({
      operation: "confidential",
      tokenAccountSetup: [{ owner: recipient, mint }],
    });
    expect(await exit.send(withdrawal)).toEqual(["prepareRelay"]);
  });

  it("holds the owner's signature until the charged outflows were read", async () => {
    const fixture = await ringFixture({ table: buildRuleTable({ rules: [] }) });
    const network = walletNetwork(fixture);
    const sender = owner(fixture, 2);
    const inner = signingKeySpendSigner(sender.signing);
    let signed = 0;
    const unsigned = await prepareRingTransferRelay({
      client: network.client,
      ringProgramId: fixture.ringProgramId,
      wallet: sender.wallet,
      keys: walletKeys(sender.keypair),
      amount: 15n,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      confidential: {
        quote: { feePayer: fixture.authority, validUntilSlot: 100n },
        nullifierKey: sender.keypair.nullifierKey(),
        signer: {
          publicKey: () => inner.publicKey(),
          sign: (message, context) => {
            signed += 1;
            return inner.sign(message, context);
          },
        },
      },
    });

    const charged = unsigned.relay.chargedOutflows();
    expect(signed).toBe(0);
    expect(charged).toMatchObject([
      { owner: sender.keypair.signingPublicKey().ownerProofInputHash(), chargedOutflow: 15n },
    ]);
    const prepared = await unsigned.relay.sign();
    expect(signed).toBe(1);
    expect(prepared.request.intent).toHaveProperty("ownerSignature");
    expect(prepared.chargedOutflows()).toEqual(charged);
  });

  it("reconciles a resent relay by its id and never prepares it twice", async () => {
    const fixture = await ringFixture({ table: buildRuleTable({ rules: [] }) });
    const network = walletNetwork(fixture);
    const relayOf = async () => {
      const sender = owner(fixture, 2);
      return (
        await prepareRingTransferRelay({
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
        })
      ).relay.sign();
    };
    const lostAnswer = (status: RelayStatus) => {
      const calls: string[] = [];
      const relay: RingRelayClient = {
        getRelayQuote: () => Promise.reject(new Error("unread")),
        submitRelay: () => Promise.reject(new Error("unread")),
        prepareRelay: async () => {
          calls.push("prepareRelay");
          throw new Error("lost answer");
        },
        getRelayStatus: async () => {
          calls.push("getRelayStatus");
          return status;
        },
      };
      return { relay, calls };
    };

    const sent = await relayOf();
    const signature = "1".repeat(64) as Signature;
    const sentRelay = lostAnswer({ status: "sent", signature });
    await expect(sent.send(sentRelay.relay)).rejects.toThrow("lost answer");
    expect(await sent.send(sentRelay.relay)).toEqual({
      step: "submitted",
      relayId: sent.relayId(),
    });
    expect(sentRelay.calls).toEqual(["prepareRelay", "getRelayStatus"]);

    const failed = await relayOf();
    const failedRelay = lostAnswer({ status: "failed", reason: "expired" });
    await expect(failed.send(failedRelay.relay)).rejects.toThrow("lost answer");
    await expect(failed.send(failedRelay.relay)).rejects.toMatchObject({
      code: "RING_RELAY_FAILED",
      details: { reason: "expired" },
    });
    expect(failedRelay.calls).toEqual(["prepareRelay", "getRelayStatus"]);
  });

  it("relays a deposit into a key escrow ring with no opening request", async () => {
    const fixture = await ringFixture({ mode: "confidential", records: [] });
    const network = walletNetwork(fixture);
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const approvals: ApprovalRequest[] = [];
    const depositorSigner = await generateKeyPairSigner();
    await expect(
      PreparedRingDeposit.prepareRelay({
        client: network.client,
        ringProgramId: fixture.ringProgramId,
        depositor: randomAddress(),
        depositorSigner,
        recipient: { kind: "confidential", address: recipient },
        amount: 5n,
        quote: { feePayer: fixture.authority, validUntilSlot: 100n },
      }),
    ).rejects.toThrow();
    const prepared = await PreparedRingDeposit.prepareRelay({
      client: network.client,
      ringProgramId: fixture.ringProgramId,
      depositor: depositorSigner.address,
      depositorSigner,
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
    const fixture = await ringFixture({ mode: "confidential", records: [] });
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
        signer: signingKeySpendSigner(sender.signing),
        quote: { feePayer, validUntilSlot: 100n },
        approve,
      });

    await expect(merge(sender.keypair.shieldedAddress().solanaAddress())).rejects.toMatchObject({
      cause: { code: "RING_ANONYMOUS_SIGNER_LINKS_OWNER" },
    });
    await expect(
      prepareRingMergeRelay({
        client: network.client,
        ringProgramId: fixture.ringProgramId,
        wallet: sender.wallet,
        nullifierKey: sender.keypair.nullifierKey(),
        signer: signingKeySpendSigner(SigningKey.generate()),
        quote: { feePayer: fixture.authority, validUntilSlot: 100n },
        approve: recorded,
      }),
    ).rejects.toMatchObject({ cause: { code: "RING_ANONYMOUS_SIGNER_MISMATCH" } });
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
