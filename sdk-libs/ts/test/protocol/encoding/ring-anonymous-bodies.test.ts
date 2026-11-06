import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { beforeAll, describe, expect, it } from "vitest";

import replyVector from "../../../../../test-vectors/wallet/reply_metadata.json" with { type: "json" };
import { initializePoseidon } from "@heliuslabs/spr";
import { concatBytes, encodeBase58, ZERO_32 } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { X25519Keypair } from "@heliuslabs/spr/keypair";
import { Data } from "@heliuslabs/spr/transaction";

import { openOutputSlot, sealOutputSlot } from "../../../src/crypto/audit/ring-disclosure.js";
import {
  OUTPUT_RECORD_ENC_INFO,
  REPLY_ENC_INFO,
  SENDER_BUNDLE_ENC_INFO,
  symmetricAuditApply,
} from "../../../src/crypto/audit/audit.js";
import { x25519FromU } from "../../../src/crypto/keys/x25519.js";
import {
  MIN_REPLY_LEN,
  openReply,
  openSenderBundle,
  replyLength,
  sealReply,
  sealSenderBundle,
  senderBundleLen,
  type ReplyMetadata,
  type BundleLayout,
  type SenderBundle,
} from "../../../src/protocol/codec/anonymous-delivery.js";
import {
  DUMMY_RECORD,
  RecordKind,
  type OutputRecord,
} from "../../../src/protocol/codec/audit-stream.js";
import {
  OUTPUT_RECORD_LEN,
  STREAM_FIRST_COUNTER,
} from "../../../src/protocol/codec/ring-disclosure-layout.js";

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

const RECORD: OutputRecord = {
  kind: RecordKind.ring,
  amount: 0x0102_0304_0506_0708n,
  ownerKey: filled(0x33),
  mint: encodeBase58(filled(0x22)),
  nullifierPk: filled(0x0a),
  blinding: filled(0x11),
};

function reply(data = new Data()): ReplyMetadata {
  return {
    viewingKey: X25519Keypair.fromBytes(filled(9)).publicKey(),
    ownerKey: filled(0x44),
    nullifierPk: filled(0x55),
    data,
  };
}

/** One key per slot, zero on an exit or a dummy. */
function bundle(layout: BundleLayout): SenderBundle {
  return {
    outputSeed: filled(0x77),
    recipientKeys: Array.from({ length: layout.outputs }, (_, key) =>
      key % 3 === 2 ? ZERO_32 : filled(0x80 + key),
    ),
  };
}

beforeAll(initializePoseidon);

describe("output slot body", () => {
  it("opens what it sealed at the record's length", () => {
    const sealed = sealOutputSlot(SECRET, { record: RECORD });
    expect(sealed).toHaveLength(OUTPUT_RECORD_LEN);
    expect(openOutputSlot(SECRET, sealed)).toEqual({ record: RECORD });
    expect(() => openOutputSlot(OTHER_SECRET, sealed)).toThrow();
  });

  it("refuses a body shorter than a record and a record its kind refuses", () => {
    const sealed = sealOutputSlot(SECRET, { record: RECORD });
    expect(() => openOutputSlot(SECRET, sealed.subarray(1))).toThrow();
    // A payload byte past a record without one reads a two byte length it cannot hold.
    expect(() => openOutputSlot(SECRET, Uint8Array.of(...sealed, 0))).toThrow();
    expect(openOutputSlot(SECRET, sealOutputSlot(SECRET, { record: DUMMY_RECORD }))).toEqual({
      record: DUMMY_RECORD,
    });
  });

  it("refuses an amount past u64 at sealing", () => {
    expect(() => sealOutputSlot(SECRET, { record: { ...RECORD, amount: 1n << 64n } })).toThrow();
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

  it("differs from a record over the same bytes under one secret", () => {
    const metadata = reply();
    const sealedReply = sealReply(SECRET, metadata, MIN_REPLY_LEN);
    const plaintext = symmetricAuditApply(
      SECRET,
      { label: REPLY_ENC_INFO, counter: STREAM_FIRST_COUNTER },
      sealedReply,
    );
    const asRecord = symmetricAuditApply(
      SECRET,
      { label: OUTPUT_RECORD_ENC_INFO, counter: STREAM_FIRST_COUNTER },
      concatBytes(plaintext, new Uint8Array(OUTPUT_RECORD_LEN - MIN_REPLY_LEN)),
    );
    expect(sealedReply).not.toEqual(asRecord.subarray(0, MIN_REPLY_LEN));
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
  it.each([{ outputs: 1 }, { outputs: 2 }, { outputs: 4 }, { outputs: 8 }])(
    "opens what it sealed at $outputs outputs",
    (layout) => {
      const sealed = sealSenderBundle(SECRET, bundle(layout));
      expect(sealed).toHaveLength(senderBundleLen(layout));
      expect(sealed).toHaveLength(32 + 32 * layout.outputs);
      expect(openSenderBundle(SECRET, sealed, layout)).toEqual(bundle(layout));
    },
  );

  it("refuses a bundle off the length the published count fixes", () => {
    const sealed = sealSenderBundle(SECRET, bundle({ outputs: 2 }));
    expect(() => openSenderBundle(SECRET, sealed, { outputs: 3 })).toThrow();
    expect(() => openSenderBundle(SECRET, sealed, { outputs: 1 })).toThrow();
    expect(() => openSenderBundle(SECRET, sealed.subarray(1), { outputs: 2 })).toThrow();
  });
});

describe("delivery streams", () => {
  it("names one CTR label per region and each seal runs under its own", () => {
    expect(
      new Set(
        [OUTPUT_RECORD_ENC_INFO, REPLY_ENC_INFO, SENDER_BUNDLE_ENC_INFO].map((label) =>
          Buffer.from(label).toString("latin1"),
        ),
      ).size,
    ).toBe(3);
    const streams = [OUTPUT_RECORD_ENC_INFO, REPLY_ENC_INFO, SENDER_BUNDLE_ENC_INFO].map((label) =>
      Buffer.from(keystream(label, OUTPUT_RECORD_LEN)).toString("hex"),
    );
    expect(new Set(streams).size).toBe(3);
    expect(Buffer.from(sealOutputSlot(SECRET, { record: DUMMY_RECORD })).toString("hex")).toBe(
      streams[0],
    );
  });
});
