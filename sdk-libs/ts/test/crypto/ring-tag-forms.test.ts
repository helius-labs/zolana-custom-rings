import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import { isCanonicalField } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { poseidon } from "@heliuslabs/spr/keypair";

import { randomTagPreimage } from "../../src/crypto/derivation/dummy-tag.js";
import { RingDomain, domainField } from "../../src/crypto/derivation/ring-domain.js";
import { bundleTag, recipientTag } from "../../src/crypto/derivation/ring-stream.js";
import { RingPaymentRequest } from "../../src/crypto/keys/ring-address.js";

await initializePoseidon();

describe("ring tag forms", () => {
  const secret = new Uint8Array(32).fill(0x07) as Bytes32;

  it("hashes each tag under its own domain and keeps the secret", () => {
    expect(RingDomain.recipientTagDomain).toBe(0x43525254);
    expect(RingDomain.senderTagDomain).toBe(0x43525354);
    const kept = Uint8Array.from(secret);
    expect(recipientTag(secret)).toEqual(
      poseidon([domainField(RingDomain.recipientTagDomain), kept]),
    );
    expect(bundleTag(secret)).toEqual(poseidon([domainField(RingDomain.senderTagDomain), kept]));
    expect(secret).toEqual(kept);
    expect(recipientTag(secret)).not.toEqual(bundleTag(secret));
    expect(isCanonicalField(recipientTag(secret))).toBe(true);
  });

  it("masks the top two bits of a draw and rejects a value at or above q", () => {
    const aboveOrder = new Uint8Array(32).fill(0xff);
    const accepted = new Uint8Array(32).fill(0xff);
    accepted[0] = 0x4f;
    const draws = [aboveOrder, accepted];
    const drawn = randomTagPreimage(() => {
      const next = draws.shift();
      if (next === undefined) throw new Error("drew past the rejection");
      return next;
    });
    expect(draws).toEqual([]);
    expect(aboveOrder.every((byte) => byte === 0)).toBe(true);
    expect(drawn[0]).toBe(0x0f);
    expect(isCanonicalField(drawn)).toBe(true);
  });

  it("draws values with a nonzero first byte, in a live tag's encoding", () => {
    const firstBytes = new Set(Array.from({ length: 64 }, () => randomTagPreimage()[0]));
    expect(firstBytes.size).toBeGreaterThan(1);
    expect(isCanonicalField(recipientTag(randomTagPreimage()))).toBe(true);
  });

  it("names no tag on a payment request but the deposit tag", () => {
    expect(RingPaymentRequest.prototype).not.toHaveProperty("requestViewTag");
  });
});
