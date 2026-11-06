import { describe, expect, it } from "vitest";
import { encodeBase58 } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import {
  decodeCompactRecipientBody,
  decodeRecipientBody,
  encodeCompactRecipientBody,
  encodeRecipientBody,
} from "../../src/protocol/codec/anonymous-delivery.js";
import {
  decodeAuditEnvelope,
  decodeCompactAuditRecord,
  encodeAuditEnvelope,
  encodeCompactAuditRecord,
  RecordKind,
} from "../../src/protocol/codec/audit-stream.js";
import {
  auditLayoutValue,
  checkedStreamLayout,
  DisclosureFormat,
  envelopeRegion,
  recordRegion,
} from "../../src/protocol/codec/ring-disclosure-layout.js";
import {
  encodeRingBodyOutput,
  readRingOutput,
  ringBodyOutput,
} from "../../src/protocol/transaction/output.js";
import { RingTransactData } from "../../src/protocol/transaction/transact.js";
import { ringFrame } from "../helpers/ring-frame.js";

const FIELD = new Uint8Array(32).fill(3) as Bytes32;
const MINT = encodeBase58(FIELD);
const FORMAT = DisclosureFormat.SingleAssetPayout;
const LAYOUT = {
  key: { class: 1, entry: false, format: FORMAT },
  inputs: 1,
  outputs: 16,
  capacity: 16,
  hasData: false,
};

describe("single asset payout", () => {
  it("selects the compact recipient codec through the published scheme", () => {
    const plain = { blinding: FIELD, amount: 7n, assetId: 12n };
    const bytes = encodeCompactRecipientBody(plain);
    expect(bytes.length).toBe(48);
    expect(decodeCompactRecipientBody(bytes)).toEqual(plain);
    expect(() => decodeRecipientBody(bytes)).toThrow();
    const output = encodeRingBodyOutput(bytes, new Uint8Array());
    expect(readRingOutput(output).scheme).toBe(11);
    expect(ringBodyOutput(output)?.format).toBe(FORMAT);
    const wrongScheme = output.slice();
    wrongScheme[5] = 10;
    expect(ringBodyOutput(wrongScheme)).toBeUndefined();
    expect(
      ringBodyOutput(encodeRingBodyOutput(new Uint8Array(71), new Uint8Array())),
    ).toBeUndefined();
    expect(ringBodyOutput(encodeRingBodyOutput(new Uint8Array(72), new Uint8Array()))?.format).toBe(
      DisclosureFormat.Standard,
    );
    expect(ringBodyOutput(encodeRingBodyOutput(bytes, Uint8Array.of(1)))).toBeUndefined();
  });

  it("binds the common mint and format to the auditor layout", () => {
    const envelope = {
      txViewingSecret: FIELD,
      realInputs: 1,
      addressInputBits: 0n,
      evidence: { kind: "singleAssetPayout" as const, mint: MINT },
    };
    const encoded = encodeAuditEnvelope(envelope);
    expect(encoded.length).toBe(73);
    expect(decodeAuditEnvelope(encoded, LAYOUT)).toEqual(envelope);
    expect(envelopeRegion(LAYOUT)).toEqual({ startCounter: 2, maxBlocks: 5, length: 73 });
    expect(recordRegion(LAYOUT, 15)).toEqual({ startCounter: 82, maxBlocks: 5, length: 73 });
    expect(auditLayoutValue({ hasData: false, entry: false, format: FORMAT })).toBe(4);
    expect(() => checkedStreamLayout({ ...LAYOUT, hasData: true })).toThrow();
    expect(() =>
      decodeAuditEnvelope(encoded, {
        ...LAYOUT,
        key: { ...LAYOUT.key, format: DisclosureFormat.Standard },
      }),
    ).toThrow();
    const record = {
      kind: RecordKind.ring,
      amount: 9n,
      ownerKey: FIELD,
      mint: MINT,
      nullifierPk: FIELD,
    };
    expect(decodeCompactAuditRecord(encodeCompactAuditRecord(record), MINT)).toEqual(record);
    expect(() => encodeCompactAuditRecord({ ...record, kind: RecordKind.exit })).toThrow();
  });

  it("requires the explicit frame format and rejects mixed recipient widths", () => {
    const frame = ringFrame({ rail: "confidential", inputs: 1, outputs: 16, format: FORMAT });
    const encoded = RingTransactData.encode(frame);
    const decoded = RingTransactData.parse(encoded, "confidential");
    expect(decoded.extensions.format).toBe(FORMAT);
    expect(decoded.outputs).toHaveLength(16);
    expect(() => RingTransactData.encode({ ...frame, extensions: {} })).toThrow();
    expect(() =>
      RingTransactData.encode({
        ...frame,
        outputs: frame.outputs.map((output, index) =>
          index === 0
            ? { ...output, body: { kind: "recipient", body: new Uint8Array(72) } }
            : output,
        ),
      }),
    ).toThrow();
  });
});

describe("padded recipient data", () => {
  it("keeps actual data length encrypted and rejects nonzero padding", () => {
    const plain = { blinding: FIELD, amount: 7n, mint: MINT };
    const withData = { ...plain, data: Uint8Array.of(3, 1, 4) };
    const width = encodeRecipientBody(withData).length;
    const empty = encodeRecipientBody(plain, width);
    const full = encodeRecipientBody(withData, width);
    expect(empty.length).toBe(full.length);
    expect(decodeRecipientBody(empty)).toEqual(plain);
    expect(decodeRecipientBody(full)).toEqual(withData);
    empty[empty.length - 1] = 1;
    expect(() => decodeRecipientBody(empty)).toThrow();
    expect(encodeRecipientBody(plain).length).toBe(72);
  });
});
