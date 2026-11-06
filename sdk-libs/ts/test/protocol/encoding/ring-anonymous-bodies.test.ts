import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { beforeAll, describe, expect, it } from "vitest";

import replyVector from "../../../../../test-vectors/wallet/reply_metadata.json" with { type: "json" };
import { initializePoseidon } from "@heliuslabs/spr";
import { concatBytes, encodeBase58, ZERO_32 } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { X25519Keypair } from "@heliuslabs/spr/keypair";
import { Data } from "@heliuslabs/spr/transaction";

import {
  RECIPIENT_BODY_ENC_INFO,
  REPLY_ENC_INFO,
  SENDER_BUNDLE_ENC_INFO,
  symmetricAuditApply,
} from "../../../src/crypto/audit/audit.js";
import { x25519FromU } from "../../../src/crypto/keys/x25519.js";
import {
  MIN_REPLY_LEN,
  RECIPIENT_BODY_LEN,
  openRecipientBody,
  openReply,
  openSenderBundle,
  replyLength,
  sealRecipientBody,
  sealReply,
  sealSenderBundle,
  senderBundleLen,
  type RecipientBody,
  type ReplyMetadata,
  type BundleLayout,
  type SenderBundle,
} from "../../../src/protocol/codec/anonymous-delivery.js";
import { STREAM_FIRST_COUNTER } from "../../../src/protocol/codec/ring-disclosure-layout.js";

const SECRET = new Uint8Array(32).fill(0x11) as Bytes32;
const OTHER_SECRET = new Uint8Array(32).fill(0x12) as Bytes32;

function filled(byte: number): Bytes32 {
  return new Uint8Array(32).fill(byte) as Bytes32;
}

function keystream(label: Uint8Array, length: number): Uint8Array {
  return symmetricAuditApply(
    SECRET,
    { label, counter: STREAM_FIRST_COUNTER },
    new Uint8Array(length),
  );
}

function sealedReplyBytes(plaintext: Uint8Array): Uint8Array {
  return symmetricAuditApply(
    SECRET,
    { label: REPLY_ENC_INFO, counter: STREAM_FIRST_COUNTER },
    plaintext,
  );
}

const BODY: RecipientBody = {
  blinding: filled(0x11),
  amount: 0x0102_0304_0506_0708n,
  mint: encodeBase58(filled(0x22)),
};

function reply(data = new Data()): ReplyMetadata {
  return {
    viewingKey: X25519Keypair.fromBytes(filled(9)).publicKey(),
    ownerKey: filled(0x44),
    nullifierPk: filled(0x55),
    data,
  };
}

/** `change` leading cells, then one key per other slot. */
function bundle(layout: BundleLayout): SenderBundle {
  return {
    outputSeed: filled(0x77),
    change: Array.from({ length: layout.change }, (_, cell) => ({
      mint: encodeBase58(filled(0x66 + cell)),
      amount: 7n + BigInt(cell),
    })),
    recipientKeys: Array.from({ length: layout.outputs - layout.change }, (_, key) =>
      filled(0x80 + key),
    ),
  };
}

beforeAll(initializePoseidon);

describe("ring body", () => {
  it("opens what it sealed at the fixed length", () => {
    const sealed = sealRecipientBody(SECRET, BODY);
    expect(sealed).toHaveLength(RECIPIENT_BODY_LEN);
    expect(sealed.subarray(0, 32)).not.toEqual(BODY.blinding);
    expect(openRecipientBody(SECRET, sealed)).toEqual(BODY);
    expect(openRecipientBody(OTHER_SECRET, sealed)).not.toEqual(BODY);
  });

  it("refuses a body off its length", () => {
    const sealed = sealRecipientBody(SECRET, BODY);
    expect(() => openRecipientBody(SECRET, sealed.subarray(1))).toThrow();
    expect(() => openRecipientBody(SECRET, Uint8Array.of(...sealed, 0))).toThrow();
  });

  it("refuses an amount past u64 at sealing", () => {
    expect(() => sealRecipientBody(SECRET, { ...BODY, amount: 1n << 64n })).toThrow();
  });
});

describe("reply metadata", () => {
  it("opens what it sealed, padded to the frame's one length", () => {
    const short = reply();
    const long = reply(new Data([{ kind: "ringData", bytes: new Uint8Array(40).fill(3) }]));
    const length = replyLength([short, long]);
    expect(length).toBeGreaterThan(MIN_REPLY_LEN);
    expect(replyLength([])).toBe(MIN_REPLY_LEN);
    for (const metadata of [short, long]) {
      const sealed = sealReply(SECRET, metadata, length);
      expect(sealed).toHaveLength(length);
      const opened = openReply(SECRET, sealed);
      expect(opened?.claimed.viewingKey.toBytes()).toEqual(metadata.viewingKey.toBytes());
      expect(opened?.claimed.ownerKey).toEqual(metadata.ownerKey);
      expect(opened?.claimed.nullifierPk).toEqual(metadata.nullifierPk);
      expect(opened?.claimed.data.records()).toEqual(metadata.data.records());
    }
  });

  it("refuses a length its data does not fit at sealing", () => {
    const metadata = reply(new Data([{ kind: "ringData", bytes: new Uint8Array(40) }]));
    expect(() => sealReply(SECRET, metadata, MIN_REPLY_LEN)).toThrow(
      expect.objectContaining({ code: "RING_REPLY_INVALID", details: { reason: "length" } }),
    );
  });

  it("reads undefined on nonzero padding", () => {
    const plaintext = symmetricAuditApply(
      SECRET,
      { label: REPLY_ENC_INFO, counter: STREAM_FIRST_COUNTER },
      sealReply(SECRET, reply(), MIN_REPLY_LEN + 8),
    );
    expect(openReply(SECRET, sealedReplyBytes(plaintext))).toBeDefined();
    plaintext[plaintext.length - 1] = 1;
    expect(openReply(SECRET, sealedReplyBytes(plaintext))).toBeUndefined();
  });

  it("reads undefined on a short reply, a key past the field and bytes that decode to no data", () => {
    const honest = symmetricAuditApply(
      SECRET,
      { label: REPLY_ENC_INFO, counter: STREAM_FIRST_COUNTER },
      sealReply(SECRET, reply(), MIN_REPLY_LEN),
    );
    expect(openReply(SECRET, new Uint8Array(MIN_REPLY_LEN - 1))).toBeUndefined();
    const pastField = honest.slice();
    pastField.fill(0xff, 0, 32);
    expect(openReply(SECRET, sealedReplyBytes(pastField))).toBeUndefined();
    const garbage = honest.slice();
    garbage[96] = 0xff;
    expect(openReply(SECRET, sealedReplyBytes(garbage))).toBeUndefined();
  });

  it("differs from a body over the same bytes under one secret", () => {
    const metadata = reply();
    const u = metadata.viewingKey.u();
    const body: RecipientBody = {
      blinding: u,
      amount: 0x4444_4444_4444_4444n,
      mint: encodeBase58(concatBytes(new Uint8Array(24).fill(0x44), new Uint8Array(8).fill(0x55))),
    };
    const sealedBody = sealRecipientBody(SECRET, body);
    const sealedReply = sealReply(SECRET, metadata, MIN_REPLY_LEN);
    expect(sealedReply.subarray(0, RECIPIENT_BODY_LEN)).not.toEqual(sealedBody);
  });
});

describe("the shared reply vector", () => {
  const slotSecret = hexToBytes(replyVector.slotSecret) as Bytes32;

  it.each(replyVector.opens)(
    "opens and seals again $name",
    ({ name, ciphertext, viewingU, ownerKey, nullifierPk, replyLen }) => {
      const data =
        name === "a memo"
          ? new Data([{ kind: "memo", bytes: new Uint8Array(12).fill(0xab) }])
          : new Data();
      const sealed = hexToBytes(ciphertext);
      expect(sealed).toHaveLength(replyLen);
      const opened = openReply(slotSecret, sealed);
      expect(bytesToHex(opened?.claimed.viewingKey.u() ?? ZERO_32)).toBe(viewingU);
      expect(bytesToHex(opened?.claimed.ownerKey ?? ZERO_32)).toBe(ownerKey);
      expect(bytesToHex(opened?.claimed.nullifierPk ?? ZERO_32)).toBe(nullifierPk);
      expect(opened?.claimed.data.records()).toEqual(data.records());
      const metadata: ReplyMetadata = {
        viewingKey: x25519FromU(hexToBytes(viewingU) as Bytes32),
        ownerKey: hexToBytes(ownerKey) as Bytes32,
        nullifierPk: hexToBytes(nullifierPk) as Bytes32,
        data,
      };
      expect(bytesToHex(sealReply(slotSecret, metadata, replyLen))).toBe(ciphertext);
    },
  );

  it.each(replyVector.refused)("reads undefined on $name", ({ ciphertext }) => {
    expect(openReply(slotSecret, hexToBytes(ciphertext))).toBeUndefined();
  });
});

describe("sender bundle", () => {
  it.each([
    { outputs: 1, change: 0 },
    { outputs: 2, change: 1 },
    { outputs: 4, change: 2 },
    { outputs: 8, change: 8 },
  ])("opens what it sealed at $outputs outputs and $change change cells", (layout) => {
    const sealed = sealSenderBundle(SECRET, bundle(layout));
    expect(sealed).toHaveLength(senderBundleLen(layout));
    expect(sealed).toHaveLength(32 + 40 * layout.change + 32 * (layout.outputs - layout.change));
    expect(openSenderBundle(SECRET, sealed, layout)).toEqual(bundle(layout));
  });

  it("refuses a bundle off the length the published counts fix", () => {
    const sealed = sealSenderBundle(SECRET, bundle({ outputs: 2, change: 1 }));
    expect(() => openSenderBundle(SECRET, sealed, { outputs: 3, change: 1 })).toThrow();
    expect(() => openSenderBundle(SECRET, sealed, { outputs: 2, change: 2 })).toThrow();
    expect(() => openSenderBundle(SECRET, sealed.subarray(1), { outputs: 2, change: 1 })).toThrow();
    expect(() => openSenderBundle(SECRET, sealed, { outputs: 1, change: 2 })).toThrow();
  });
});

describe("delivery streams", () => {
  it("names one CTR label per region and each seal runs under its own", () => {
    expect(
      new Set(
        [RECIPIENT_BODY_ENC_INFO, REPLY_ENC_INFO, SENDER_BUNDLE_ENC_INFO].map((label) =>
          Buffer.from(label).toString("latin1"),
        ),
      ).size,
    ).toBe(3);
    const streams = [RECIPIENT_BODY_ENC_INFO, REPLY_ENC_INFO, SENDER_BUNDLE_ENC_INFO].map((label) =>
      Buffer.from(keystream(label, RECIPIENT_BODY_LEN)).toString("hex"),
    );
    expect(new Set(streams).size).toBe(3);
    const zeroBody: RecipientBody = {
      blinding: ZERO_32,
      amount: 0n,
      mint: encodeBase58(ZERO_32),
    };
    expect(Buffer.from(sealRecipientBody(SECRET, zeroBody)).toString("hex")).toBe(streams[0]);
  });
});
