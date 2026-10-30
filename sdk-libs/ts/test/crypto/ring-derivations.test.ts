import { describe, expect, it } from "vitest";

import secrets from "../../../../test-vectors/wallet/ring-secrets.json" with { type: "json" };
import {
  solanaOwnerIdentity,
  DOMAIN_PRIVATE_TX_BLINDING_V1,
  DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
  DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
} from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import {
  outputBlindingSeed,
  privateTxBlinding,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import { RingDomain, depositBlinding } from "../../src/crypto/derivation/ring-domain.js";
import { deliveredSlotSecret, senderCommitment } from "../../src/crypto/derivation/ring-stream.js";
import { ringBlindingSeed, ringOutputBlinding } from "../../src/crypto/derivation/blinding.js";

function bytes<T extends Uint8Array>(value: string, length: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (decoded.length !== length) throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function ascii(tag: string): number {
  return Buffer.from(tag, "ascii").readUInt32BE(0);
}

describe("ring domains", () => {
  it("spells every domain from its ASCII tag, no two alike", () => {
    expect(RingDomain).toEqual({
      auditStatement: ascii("CRAU"),
      deliveredSlotSecret: ascii("CRDS"),
      blindingSeed: ascii("CRBS"),
      senderCommitment: ascii("CRSC"),
      disclosurePad: ascii("CROD"),
      policyStatement: ascii("CRPO"),
      policyTable: ascii("CRTB"),
      queueWrite: ascii("CRQW"),
      applyRecords: ascii("CRAP"),
      registerKey: ascii("CRRG"),
      depositBlinding: ascii("CRDB"),
      depositStatement: ascii("CRDP"),
      mergeStatement: ascii("CRMG"),
      withdrawals: ascii("CRPW"),
      withdrawalExemption: ascii("CRWX"),
      recordUpdate: ascii("CRRU"),
      walletGrant: ascii("CRWG"),
    });
    const values = [
      ...Object.values(RingDomain),
      DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
      DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
      DOMAIN_PRIVATE_TX_BLINDING_V1,
    ];
    expect(new Set(values).size).toBe(values.length);
  });
});

describe("ring-secrets.json", () => {
  const txSecret = bytes<Bytes32>(secrets.tx_viewing_secret, 32);
  const txViewingKey = X25519PublicKey.fromBytes(bytes<Bytes33>(secrets.tx_viewing_pk, 33));
  const recipientViewingKey = X25519PublicKey.fromBytes(
    bytes<Bytes33>(secrets.recipient_viewing_pk, 33),
  );
  const salt = bytes<Bytes16>(secrets.salt, 16);
  const firstNullifier = bytes<Bytes32>(secrets.first_nullifier, 32);

  it("reaches one agreement from the sender and the recipient", () => {
    const sender = X25519Keypair.fromBytes(txSecret);
    const recipient = X25519Keypair.fromBytes(bytes<Bytes32>(secrets.recipient_viewing_secret, 32));
    try {
      expect(sender.publicKey().equals(txViewingKey)).toBe(true);
      expect(recipient.publicKey().equals(recipientViewingKey)).toBe(true);
      expect(hex(sender.ecdh(recipientViewingKey))).toBe(secrets.agreement);
      expect(hex(recipient.ecdh(txViewingKey))).toBe(secrets.agreement);
    } finally {
      sender.destroy();
      recipient.destroy();
    }
  });

  it("derives the blinding seed, every slot secret and output blinding", () => {
    const blindingSeed = ringBlindingSeed(txSecret, salt);
    expect(hex(blindingSeed)).toBe(secrets.blinding_seed);
    expect(hex(outputBlindingSeed(firstNullifier, blindingSeed))).toBe(
      secrets.output_blinding_seed,
    );
    for (const output of secrets.outputs) {
      const outputIndex = output.output_index;
      const delivered = deliveredSlotSecret({
        agreement: bytes<Bytes32>(secrets.agreement, 32),
        txViewingKey,
        recipientViewingKey,
        salt,
        outputIndex,
        firstNullifier,
      });
      expect(hex(delivered)).toBe(output.delivered_slot_secret);
      expect(hex(ringOutputBlinding({ firstNullifier, blindingSeed, outputIndex }))).toBe(
        output.blinding,
      );
    }
    expect(hex(depositBlinding(bytes<Bytes32>(secrets.deposit_blinding_secret, 32)))).toBe(
      secrets.deposit_blinding,
    );
  });

  it("commits the hidden sender of the same transaction", () => {
    const senderPkHash = solanaOwnerIdentity(bytes<Bytes32>(secrets.sender_key, 32)) as Bytes32;
    expect(hex(senderPkHash)).toBe(secrets.sender_pk_hash);
    const blinding = privateTxBlinding(firstNullifier, bytes<Bytes32>(secrets.blinding_seed, 32));
    expect(hex(blinding)).toBe(secrets.private_tx_blinding);
    expect(hex(senderCommitment({ senderPkHash, privateTxBlinding: blinding }))).toBe(
      secrets.sender_commitment,
    );
  });
});
