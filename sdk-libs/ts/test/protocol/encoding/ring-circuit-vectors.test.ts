import { describe, expect, it } from "vitest";

import bodies from "../../../../../test-vectors/audit/anonymous_bodies.json" with { type: "json" };
import signerSet from "../../../../../test-vectors/audit/signer_set.json" with { type: "json" };
import debits from "../../../../../test-vectors/policy/debit.json" with { type: "json" };
import zeroNullifier from "../../../../../test-vectors/registry/zero_nullifier.json" with { type: "json" };
import { ZERO_32, ZERO_NULLIFIER_PK, bigIntBytes, bytesToBigInt } from "@heliuslabs/spr/internal";
import type { Bytes16, Bytes31, Bytes32 } from "@heliuslabs/spr/interface";
import {
  ViewingKey,
  X25519Keypair,
  poseidon,
  NullifierKey,
  ShieldedAddress,
  ShieldedKeypair,
} from "@heliuslabs/spr/keypair";
import { Data } from "@heliuslabs/spr/transaction";

import { RingDomain } from "../../../src/crypto/derivation/ring-domain.js";
import {
  bundleTag,
  deliveredSlotSecret,
  txKeySlotSecret,
  slotTag,
} from "../../../src/crypto/derivation/ring-stream.js";
import { anonymousTag } from "../../../src/operations/payments/output-rail.js";
import { x25519FromU } from "../../../src/crypto/keys/x25519.js";
import {
  MIN_REPLY_LEN,
  openReply,
  openSenderBundle,
  senderBundleLen,
  sealReply,
  sealSenderBundle,
} from "../../../src/protocol/codec/anonymous-delivery.js";
import { ownerDebits } from "../../../src/protocol/membership/owner-debits.js";
import { ciphertextDigest, signerBinding } from "../../../src/protocol/proof/statement.js";
import { LocalRingKeys, type RingTagProbe } from "../../../src/state/ring-keys.js";

function bytes<T extends Uint8Array>(value: string, length: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (decoded.length !== length) throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function field(value: string): Bytes32 {
  return bytes<Bytes32>(value, 32);
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

describe("signer_set.json", () => {
  it.each(signerSet.cases.map((vector) => [vector.name, vector] as const))(
    "chains %s",
    (_, vector) => {
      const binding = signerBinding(vector.signers.map(field), vector.slots);
      expect(binding.count).toBe(vector.signers.length);
      expect(hex(binding.chain)).toBe(vector.signer_chain);
    },
  );

  it("refuses a run past the key's slots", () => {
    expect(() => signerBinding([field(signerSet.cases[2]?.signers[0] ?? "")], 0)).toThrow(
      expect.objectContaining({ code: "RING_INVALID_LENGTH" }),
    );
  });
});

describe("anonymous_bodies.json", () => {
  it("reads the published tags through the holder under each reader's own key", async () => {
    const holderOf = (secret: string): LocalRingKeys => {
      const viewing = ViewingKey.fromBytes(field(secret));
      const nullifierKey = NullifierKey.fromSecret(new Uint8Array(31).fill(7) as Bytes31);
      return LocalRingKeys.fromKeys({
        address: ShieldedAddress.fromPublicKeys(
          ShieldedKeypair.generate().signingPublicKey(),
          nullifierKey.publicKey(),
          viewing.publicKey(),
        ),
        viewingKeys: [viewing],
        listRoot: viewing,
        nullifierKey,
      });
    };
    const txViewing = X25519Keypair.fromBytes(field(bodies.tx_viewing_sk));
    const frame = (holder: LocalRingKeys, probes: readonly RingTagProbe[]) => ({
      viewingPublicKey: holder.address().viewingPublicKey,
      txViewingPublicKey: txViewing.publicKey(),
      salt: bytes<Bytes16>(bodies.salt, 16),
      firstNullifier: field(bodies.first_nullifier),
      probes,
    });
    const recipient = holderOf(bodies.recipient_viewing_sk);
    const [recipientMatches] = await recipient.ringTagMatches([
      frame(recipient, [
        { kind: "recipient", outputIndex: bodies.body_index, tag: slotTag(field(bodies.body_tag)) },
        {
          kind: "recipient",
          outputIndex: bodies.body_index,
          tag: slotTag(field(bodies.dummy_tag)),
        },
      ]),
    ]);
    expect(recipientMatches?.map((secret) => secret && hex(secret))).toEqual([
      bodies.body_slot_secret,
      undefined,
    ]);
    const sender = holderOf(bodies.sender_viewing_sk);
    const [senderMatches] = await sender.ringTagMatches([
      frame(sender, [
        { kind: "senderBundle", outputIndex: bodies.output_count, tag: field(bodies.bundle_tag) },
      ]),
    ]);
    expect(senderMatches?.map((secret) => secret && hex(secret))).toEqual([
      bodies.bundle_slot_secret,
    ]);
  });

  // Key `k` names slot `k`, the change slot carries the sender's own key.
  const layout = { outputs: bodies.output_count };
  const recipientKey = bodies.recipient_keys[bodies.body_index] ?? "";
  const bundle = {
    outputSeed: field(bodies.output_seed),
    recipientKeys: bodies.recipient_keys.map((key) => (key === "" ? ZERO_32 : field(key))),
  };

  it("rebuilds both CRDS slot secrets, the bundle's at index m", () => {
    const txViewing = X25519Keypair.fromBytes(field(bodies.tx_viewing_sk));
    const secret = (u: string, outputIndex: number): string => {
      const recipientViewingKey = x25519FromU(field(u));
      return hex(
        deliveredSlotSecret({
          agreement: txViewing.ecdh(recipientViewingKey),
          txViewingKey: txViewing.publicKey(),
          recipientViewingKey,
          salt: bytes<Bytes16>(bodies.salt, 16),
          outputIndex,
          firstNullifier: field(bodies.first_nullifier),
        }),
      );
    };
    expect(secret(recipientKey, bodies.body_index)).toBe(bodies.body_slot_secret);
    expect(secret(bodies.sender_viewing_key, bodies.output_count)).toBe(bodies.bundle_slot_secret);
    txViewing.destroy();
  });

  it("derives every published tag through the rail's own functions", () => {
    expect(bodies.recipient_tag_domain).toBe(RingDomain.recipientTagDomain.toString(16));
    expect(bodies.sender_tag_domain).toBe(RingDomain.senderTagDomain.toString(16));
    const txViewingKey = ViewingKey.fromBytes(field(bodies.tx_viewing_sk));
    const slotSecret = (u: string, outputIndex: number): Bytes32 =>
      txKeySlotSecret({
        txViewingKey,
        recipientViewingKey: x25519FromU(field(u)),
        salt: bytes<Bytes16>(bodies.salt, 16),
        outputIndex,
        firstNullifier: field(bodies.first_nullifier),
      });
    const recipient = x25519FromU(field(recipientKey));
    const unreached = (): Bytes32 => {
      throw new Error("no slot secret on this slot");
    };
    const payment = anonymousTag({ kind: "payment", payment: { recipient, reply: null } }, (key) =>
      slotSecret(hex(key.u()), bodies.body_index),
    );
    expect(hex(payment ?? ZERO_32)).toBe(hex(slotTag(field(bodies.body_tag))));
    const dummy = anonymousTag(
      { kind: "dummy", preimage: field(bodies.dummy_tag_preimage) },
      unreached,
    );
    expect(hex(dummy ?? ZERO_32)).toBe(hex(slotTag(field(bodies.dummy_tag))));
    expect(anonymousTag({ kind: "change" }, unreached)).toEqual(ZERO_32);
    expect(anonymousTag({ kind: "exit" }, unreached)).toBeUndefined();
    expect(hex(bundleTag(slotSecret(bodies.sender_viewing_key, bodies.output_count)))).toBe(
      bodies.bundle_tag,
    );
    txViewingKey.destroy();
  });

  it("seals and opens the sender bundle and hashes its digest", () => {
    const secret = field(bodies.bundle_slot_secret);
    const sealed = bytes(bodies.bundle, senderBundleLen(layout));
    expect(hex(sealSenderBundle(secret, bundle))).toBe(bodies.bundle);
    expect(openSenderBundle(secret, sealed, layout)).toEqual(bundle);
    expect(hex(ciphertextDigest(sealed))).toBe(bodies.bundle_digest);
  });

  it("opens a reply under the slot's secret", () => {
    const secret = field(bodies.body_slot_secret);
    const viewingKey = x25519FromU(field(bodies.sender_viewing_key));
    const reply = {
      viewingKey,
      ownerKey: new Uint8Array(32).fill(1) as Bytes32,
      nullifierPk: new Uint8Array(32).fill(2) as Bytes32,
      data: new Data(),
    };
    const sealed = sealReply(secret, reply, MIN_REPLY_LEN);
    const opened = openReply(secret, sealed);
    expect(opened?.claimed.viewingKey.u()).toEqual(viewingKey.u());
    expect(opened?.claimed.ownerKey).toEqual(reply.ownerKey);
    expect(opened?.claimed.nullifierPk).toEqual(reply.nullifierPk);
  });
});

describe("debit.json", () => {
  const identity = (value: number): Bytes32 => bigIntBytes(BigInt(value), 32) as Bytes32;
  const slot = (row: Readonly<{ owner: number; asset: number; amount: number }>) => ({
    owner: identity(row.owner),
    asset: identity(row.asset),
    amount: BigInt(row.amount),
  });

  it.each(debits.cases.map((vector) => [vector.name, vector] as const))(
    "debits %s, a zero row absent",
    (_, vector) => {
      const rows = ownerDebits({
        senders: vector.debits.map((row) => identity(row.owner)),
        assets: vector.debits.map((row) => identity(row.asset)),
        inputs: vector.inputs.map(slot),
        outputs: vector.outputs.map((output) => ({ ...slot(output), ring: output.ring })),
        publicGross: [],
      });
      expect(
        rows.map((row) => [bytesToBigInt(row.owner), bytesToBigInt(row.asset), row.debit]),
      ).toEqual(
        vector.debits
          .filter((row) => row.debit > 0)
          .map((row) => [BigInt(row.owner), BigInt(row.asset), BigInt(row.debit)]),
      );
    },
  );
});

describe("zero_nullifier.json", () => {
  it("names the key of nullifier secret zero", () => {
    expect(hex(ZERO_NULLIFIER_PK)).toBe(zeroNullifier.nullifier_pk);
    expect(hex(poseidon([ZERO_32]))).toBe(zeroNullifier.nullifier_pk);
  });
});
