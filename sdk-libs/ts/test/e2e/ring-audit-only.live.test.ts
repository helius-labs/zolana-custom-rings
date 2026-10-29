import { describe, expect, it } from "vitest";

import { buildRingDepositTransaction } from "../../src/operations/payments/deposit.js";
import { buildRingTransferTransaction } from "../../src/operations/payments/transfer.js";
import { signSendAndConfirm } from "./live-helpers.js";
import {
  airdrop,
  auditedRingAmounts,
  freshActor,
  readableRing,
  ringHoldings,
  sync,
  waitForAudited,
} from "./ring-live-helpers.js";

const DEPOSIT = 1_000_000_000n;
const PAYMENT = 250_000_000n;

describe("confidential audit-only ring", () => {
  it("moves a deposit to another member and opens the transfer to the auditor", async () => {
    const { client, ringProgramId, authority, ringRpc, target } = await readableRing({
      kind: "auditOnly",
    });
    const sender = await freshActor(client);
    const recipient = await freshActor(client);
    await airdrop(client, sender.signer.address);
    const deposit = await buildRingDepositTransaction({
      client,
      ringProgramId,
      feePayer: sender.signer.address,
      recipient: { kind: "confidential", address: sender.keypair.shieldedAddress() },
      amount: DEPOSIT,
    });
    await signSendAndConfirm(client, deposit, [sender.signer]);
    await sync(client, sender);
    expect(ringHoldings(sender, ringProgramId)).toBe(DEPOSIT);

    const transfer = await buildRingTransferTransaction({
      client,
      ringProgramId,
      wallet: sender.wallet,
      keys: sender.keys,
      feePayer: sender.signer.address,
      recipient: recipient.keypair.shieldedAddress(),
      amount: PAYMENT,
    });
    const signature = await signSendAndConfirm(client, transfer, [sender.signer]);
    const audited = await waitForAudited(ringRpc, target, authority, signature);
    expect(audited.payloadErrors).toEqual([]);
    expect(auditedRingAmounts(audited)).toEqual([PAYMENT, DEPOSIT - PAYMENT]);

    await sync(client, recipient);
    expect(ringHoldings(recipient, ringProgramId)).toBe(PAYMENT);
    await sync(client, sender);
    expect(ringHoldings(sender, ringProgramId)).toBe(DEPOSIT - PAYMENT);
  }, 900_000);
});
