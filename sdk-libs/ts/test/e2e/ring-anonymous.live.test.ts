// Fresh anonymous rings keyed by the harness ring rpc in derived mode.
import { generateKeyPairSigner, type KeyPairSigner } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { RuleTable } from "../../src/ring/advanced.js";
import {
  prepareRingTransferRelay,
  messageSignerSpendSigner,
  PreparedRingDeposit,
  RING_DEPOSIT_COMPUTE_UNIT_LIMIT,
  syncRingWallet,
} from "../../src/ring/index.js";
import { currentSlot, type Actor } from "./live-helpers.js";
import {
  airdrop,
  auditedRingAmounts,
  freshActor,
  readableRing,
  ringHoldings,
  sendInstruction,
  waitForAudited,
  type ReadableRing,
} from "./ring-live-helpers.js";
import { LocalRingKeys, ringWalletKeys } from "../../src/state/ring-keys.js";
import { ViewingHistory } from "../../src/state/viewing-history.js";
import { RingAddress } from "../../src/crypto/keys/ring-address.js";
import { submittedRelay } from "../../src/rpc/relay.js";

const DEPOSIT = 1_000_000_000n;
const PAYMENT = 250_000_000n;

interface AnonymousRing extends ReadableRing {
  /** Pays every fee, an anonymous ring refuses a signer holding the hidden owner's key. */
  readonly funder: KeyPairSigner;
}

async function anonymousRing(
  kind: Readonly<{ kind: "anonymous" }> | Readonly<{ kind: "anonymousPolicy"; table: RuleTable }>,
): Promise<AnonymousRing> {
  const ring = await readableRing(kind);
  const funder = await generateKeyPairSigner();
  await airdrop(ring.client, funder.address);
  return { ...ring, funder };
}

/** The ring rpc names the hidden sender and opens the payment and its change. */
async function expectAudited(ring: AnonymousRing, sender: Actor, signature: string): Promise<void> {
  const item = await waitForAudited(ring.ringRpc, ring.target, ring.authority, signature);
  expect(item.sender?.ownerKey).toEqual(sender.keypair.signingPublicKey().ed25519());
  expect(item.payloadErrors).toEqual([]);
  expect(auditedRingAmounts(item)).toEqual([PAYMENT, DEPOSIT - PAYMENT]);
}

/** Reads every stream of the ring through the current slot. */
async function syncRing(ring: AnonymousRing, actor: Actor): Promise<void> {
  const slot = await currentSlot(ring.client);
  await syncRingWallet({
    client: ring.client,
    wallet: actor.wallet,
    keys: actor.keys,
    config: { requireSlot: slot },
  });
}

/** A member whose own deposit funds its hidden identity on the ring. */
async function depositor(ring: AnonymousRing): Promise<Actor> {
  const sender = await freshActor(ring.client);
  const prepared = await PreparedRingDeposit.prepare({
    client: ring.client,
    ringProgramId: ring.ringProgramId,
    feePayer: ring.funder.address,
    recipient: {
      kind: "anonymous",
      keys: LocalRingKeys.fromKeypair(sender.keypair),
      history: ViewingHistory.create(sender.keypair.shieldedAddress().viewingPublicKey, 0n),
    },
    amount: DEPOSIT,
  });
  try {
    const { instruction } = await prepared.prove(ring.client);
    await sendInstruction(ring.client, instruction, ring.funder, RING_DEPOSIT_COMPUTE_UNIT_LIMIT);
  } finally {
    prepared.destroy();
  }
  await syncRing(ring, sender);
  expect(ringHoldings(sender, ring.ringProgramId)).toBe(DEPOSIT);
  return sender;
}

/** The hidden owner signs inside the proof, Ring RPC pays, proves and sends. */
async function payment(ring: AnonymousRing, sender: Actor, recipient: Actor) {
  const to = new RingAddress({
    recipient: recipient.keypair.shieldedAddress(),
    ringProgramId: ring.ringProgramId,
  });
  const history = ViewingHistory.create(sender.keypair.shieldedAddress().viewingPublicKey, 1n);
  return async () => {
    const quote = await ring.ringRpc.getRelayQuote({
      ring: ring.ringProgramId,
      operation: "anonymous",
    });
    const prepared = await prepareRingTransferRelay({
      client: ring.client,
      ringProgramId: ring.ringProgramId,
      wallet: sender.wallet,
      keys: ringWalletKeys(sender.keys, LocalRingKeys.fromKeypair(sender.keypair)),
      recipient: to,
      amount: PAYMENT,
      anonymous: {
        quote,
        nullifierKey: sender.keypair.nullifierKey(),
        signer: messageSignerSpendSigner(sender.signer),
        history,
        firstContact: { kind: "bootstrap" },
      },
    });
    return confirmedRelay(ring, submittedRelay(await prepared.relay.send(ring.ringRpc)));
  };
}

async function confirmedRelay(
  ring: AnonymousRing,
  relayId: Parameters<AnonymousRing["ringRpc"]["getRelayStatus"]>[0],
): Promise<Readonly<{ signature: string }>> {
  const deadline = Date.now() + 180_000;
  for (;;) {
    const status = await ring.ringRpc.getRelayStatus(relayId);
    if (status.status === "confirmed") return { signature: status.signature };
    if (status.status === "failed") throw new Error(`relay failed, ${status.reason}`);
    if (Date.now() > deadline) throw new Error("relay unresolved");
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

// The pinned zolana TS lacks the anonymous ring prover.
describe.skip("anonymous ring", () => {
  it("pays a ring address end to end, the recipient and the sender's change found by sync", async () => {
    const ring = await anonymousRing({ kind: "anonymous" });
    const sender = await depositor(ring);
    const recipient = await freshActor(ring.client);
    const pay = await payment(ring, sender, recipient);
    const { signature } = await pay();
    await expectAudited(ring, sender, signature);
    await syncRing(ring, recipient);
    expect(ringHoldings(recipient, ring.ringProgramId)).toBe(PAYMENT);
    await syncRing(ring, sender);
    expect(ringHoldings(sender, ring.ringProgramId)).toBe(DEPOSIT - PAYMENT);
  }, 900_000);
});
