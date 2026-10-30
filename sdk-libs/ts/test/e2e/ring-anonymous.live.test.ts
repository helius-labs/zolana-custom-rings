// Fresh anonymous rings keyed by the harness ring rpc in derived mode.
import { generateKeyPairSigner, type KeyPairSigner } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { bytesKey } from "@heliuslabs/zolana/internal";
import type { RuleTable } from "../../src/ring/advanced.js";
import {
  AnonymousSync,
  createRingTransferSubmission,
  prepareRingTransferRelay,
  messageSignerSpendSigner,
  PreparedRingDeposit,
  RING_DEPOSIT_COMPUTE_UNIT_LIMIT,
} from "../../src/ring/index.js";
import { currentSlot, type Actor } from "./live-helpers.js";
import {
  airdrop,
  auditedRingAmounts,
  freshActor,
  readableRing,
  ringHoldings,
  ringKeys,
  sendInstruction,
  settle,
  waitForAudited,
  type ReadableRing,
} from "./ring-live-helpers.js";
import type { RingKeys } from "../../src/state/ring-keys.js";
import { ViewingHistory } from "../../src/state/viewing-history.js";
import { RingAddress } from "../../src/crypto/keys/ring-address.js";
import { submittedRelay } from "../../src/rpc/relay.js";

const DEPOSIT = 1_000_000_000n;
const PAYMENT = 250_000_000n;

interface AnonymousRing extends ReadableRing {
  /** Pays every fee, an anonymous ring refuses a signer holding the hidden owner's key. */
  readonly funder: KeyPairSigner;
}

interface Member extends Actor {
  readonly keys: Actor["keys"] & RingKeys;
  history: ViewingHistory;
}

type Payment = (ring: AnonymousRing, sender: Member, to: RingAddress) => Promise<string>;

async function anonymousRing(
  kind: Readonly<{ kind: "anonymous" }> | Readonly<{ kind: "anonymousPolicy"; table: RuleTable }>,
): Promise<AnonymousRing> {
  const ring = await readableRing(kind);
  const funder = await generateKeyPairSigner();
  await airdrop(ring.client, funder.address);
  return { ...ring, funder };
}

async function member(ring: AnonymousRing): Promise<Member> {
  const actor = await freshActor(ring.client);
  return {
    ...actor,
    keys: ringKeys(actor),
    history: ViewingHistory.create(actor.keypair.shieldedAddress().viewingPublicKey, 0n),
  };
}

/** The ring rpc names the hidden sender and opens the payment and its change. */
async function expectAudited(ring: AnonymousRing, sender: Actor, signature: string): Promise<void> {
  const item = await waitForAudited(ring.ringRpc, ring.target, ring.authority, signature);
  expect(item.sender?.ownerKey).toEqual(sender.keypair.signingPublicKey().ed25519());
  expect(item.payloadErrors).toEqual([]);
  expect(auditedRingAmounts(item)).toEqual([PAYMENT, DEPOSIT - PAYMENT]);
}

async function syncRing(ring: AnonymousRing, actor: Member): Promise<void> {
  const state = actor.wallet._state();
  const scan = await AnonymousSync.create(actor.keys, actor.wallet.registry)
    .withIndexerConfig({
      ...ring.client.indexerConfig,
      requireSlot: await currentSlot(ring.client),
    })
    .withHeldNotes(state.utxos)
    .fetch(ring.client, actor.history);
  actor.history = scan.history;
  const spent = new Set(scan.spentNullifiers.map(bytesKey));
  const known = new Set(state.utxos.map((entry) => bytesKey(entry.outputContext.hash)));
  actor.wallet._replace({
    ...state,
    utxos: [
      ...state.utxos.map((entry) =>
        spent.has(bytesKey(entry.nullifier)) ? { ...entry, spent: true } : entry,
      ),
      ...scan.utxos.filter((entry) => !known.has(bytesKey(entry.outputContext.hash))),
    ],
    nullifiers: new Set([...state.nullifiers, ...spent]),
  });
}

/** A member whose own deposit funds its hidden identity on the ring. */
async function depositor(ring: AnonymousRing): Promise<Member> {
  const sender = await member(ring);
  const prepared = await PreparedRingDeposit.prepare({
    client: ring.client,
    ringProgramId: ring.ringProgramId,
    feePayer: ring.funder.address,
    recipient: { kind: "anonymous", keys: sender.keys, history: sender.history },
    amount: DEPOSIT,
  });
  try {
    sender.history = returnedHistory(prepared.viewingHistory);
    const { instruction } = await prepared.prove(ring.client);
    await sendInstruction(ring.client, instruction, ring.funder, RING_DEPOSIT_COMPUTE_UNIT_LIMIT);
  } finally {
    prepared.destroy();
  }
  await syncRing(ring, sender);
  expect(ringHoldings(sender, ring.ringProgramId)).toBe(DEPOSIT);
  return sender;
}

function returnedHistory(history: ViewingHistory | undefined): ViewingHistory {
  if (history === undefined) throw new Error("anonymous submission returned no viewing history");
  return history;
}

function spendRequest(ring: AnonymousRing, sender: Member, to: RingAddress) {
  return {
    request: {
      client: ring.client,
      ringProgramId: ring.ringProgramId,
      wallet: sender.wallet,
      keys: sender.keys,
      recipient: to,
      amount: PAYMENT,
    },
    anonymous: {
      signer: messageSignerSpendSigner(sender.signer),
      history: sender.history,
      firstContact: { kind: "bootstrap" },
    },
  } as const;
}

/** The hidden owner signs inside the proof, Ring RPC pays, proves and sends. */
const relayed: Payment = async (ring, sender, to) => {
  const quote = await ring.ringRpc.getRelayQuote({
    ring: ring.ringProgramId,
    operation: "anonymous",
  });
  const { request, anonymous } = spendRequest(ring, sender, to);
  const prepared = await prepareRingTransferRelay({
    ...request,
    anonymous: { ...anonymous, quote, nullifierKey: sender.keypair.nullifierKey() },
  });
  sender.history = prepared.viewingHistory;
  return confirmedRelay(ring, submittedRelay(await prepared.relay.send(ring.ringRpc)));
};

/** The wallet proves the spend, the funder sends it. */
const direct: Payment = async (ring, sender, to) => {
  const { request, anonymous } = spendRequest(ring, sender, to);
  const submission = await createRingTransferSubmission({
    ...request,
    feePayer: ring.funder.address,
    anonymous,
  });
  sender.history = returnedHistory(submission.viewingHistory);
  return (await settle(submission, ring.client, [ring.funder])).signature;
};

async function confirmedRelay(
  ring: AnonymousRing,
  relayId: Parameters<AnonymousRing["ringRpc"]["getRelayStatus"]>[0],
): Promise<string> {
  const deadline = Date.now() + 180_000;
  for (;;) {
    const status = await ring.ringRpc.getRelayStatus(relayId);
    if (status.status === "confirmed") return status.signature;
    if (status.status === "failed") throw new Error(`relay failed, ${status.reason}`);
    if (Date.now() > deadline) throw new Error("relay unresolved");
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

describe("anonymous ring", () => {
  let ring: AnonymousRing;
  beforeAll(async () => {
    ring = await anonymousRing({ kind: "anonymous" });
  }, 600_000);

  it.each([
    ["through Ring RPC", relayed],
    ["proved by the wallet, sent by the funder", direct],
  ] as const)(
    "pays a ring address %s, the recipient and the sender's change found by sync",
    async (_, pay) => {
      const sender = await depositor(ring);
      const recipient = await member(ring);
      const to = new RingAddress({
        recipient: recipient.keypair.shieldedAddress(),
        ringProgramId: ring.ringProgramId,
      });
      const signature = await pay(ring, sender, to);
      await expectAudited(ring, sender, signature);
      await syncRing(ring, recipient);
      expect(ringHoldings(recipient, ring.ringProgramId)).toBe(PAYMENT);
      await syncRing(ring, sender);
      expect(ringHoldings(sender, ring.ringProgramId)).toBe(DEPOSIT - PAYMENT);
    },
    900_000,
  );
});
