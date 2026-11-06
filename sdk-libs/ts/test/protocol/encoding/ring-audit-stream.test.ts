import { describe, expect, it } from "vitest";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { address } from "@solana/kit";

import { initializePoseidon } from "@heliuslabs/spr";
import { addressBytes, hashBytes, solanaOwnerIdentity } from "@heliuslabs/spr/internal";
import { ownerHash, X25519Keypair } from "@heliuslabs/spr/keypair";
import type { Bytes16, Bytes32 } from "@heliuslabs/spr/interface";

import ranges from "../../../../../test-vectors/audit/ring-disclosure-ranges.json" with { type: "json" };
import vector from "../../../../../test-vectors/audit/audit-stream.json" with { type: "json" };
import { parseAuditorMessage, sealSaltedAuditorStream } from "../../../src/crypto/audit/audit.js";
import {
  openRingDisclosure,
  sealRingDisclosure,
  type RingDisclosure,
} from "../../../src/crypto/audit/ring-disclosure.js";
import { ringBlindingSeed, ringOutputBlinding } from "../../../src/crypto/derivation/blinding.js";
import {
  decodeAuditEnvelope,
  decodeAuditRecord,
  decodeDataTail,
  decodeOpeningRecord,
  encodeAuditEnvelope,
  encodeAuditRecord,
  encodeCompactAuditRecord,
  encodeDataTail,
  encodeOpeningRecord,
  RecordKind,
} from "../../../src/protocol/codec/audit-stream.js";
import {
  decodeRecipientBody,
  encodeRecipientBody,
} from "../../../src/protocol/codec/anonymous-delivery.js";
import {
  auditorMessageLen,
  DisclosureFormat,
  capacityBlocks,
  checkedStreamLayout,
  envelopeBlocks,
  envelopeRegion,
  firstRecordCounter,
  firstTailCounter,
  recordRegion,
  tailRegion,
  type AuditStreamLayout,
} from "../../../src/protocol/codec/ring-disclosure-layout.js";
import { ciphertextDigest, recordChain, tailChain } from "../../../src/protocol/proof/statement.js";
import { dummyUtxoHash, fieldUtxoHash } from "../../../src/protocol/membership/utxo-hash.js";
import { RingError } from "../../../src/protocol/error.js";

const hex = (value: string): Uint8Array => hexToBytes(value);

describe("the stream regions", () => {
  it("are the shared vector for every key", () => {
    for (const key of ranges.keys) {
      const layoutAt = (inputs: number): AuditStreamLayout => ({
        key: {
          class: key.class,
          entry: key.entry,
          format:
            "single_asset_payout" in key && key.single_asset_payout === true
              ? DisclosureFormat.SingleAssetPayout
              : DisclosureFormat.Standard,
        },
        inputs,
        outputs: key.outputs,
        capacity: key.outputs,
        hasData: key.has_data,
      });
      const layout = layoutAt(1);
      expect(envelopeBlocks(layout.key)).toBe(key.envelope_blocks);
      expect(firstRecordCounter(layout.key)).toBe(key.first_record_counter);
      expect(firstTailCounter(layout)).toBe(key.first_tail_counter);
      expect(capacityBlocks(layout)).toBe(key.capacity_blocks);
      key.envelope_len_by_input_count.forEach((length, index) =>
        expect(envelopeRegion(layoutAt(index + 1)).length).toBe(length),
      );
      key.message_len_by_input_count.forEach((length, index) =>
        expect(auditorMessageLen(layoutAt(index + 1))).toBe(length),
      );
      key.record_start_counters.forEach((counter, slot) => {
        const region = recordRegion(layout, slot);
        expect(region.startCounter).toBe(counter);
        expect(region.length).toBe(key.record_len);
      });
      key.tail_start_counters.forEach((counter, slot) => {
        const region = tailRegion(layout, slot);
        expect(region.startCounter).toBe(counter);
        expect(region.length).toBe(key.tail_len);
      });
    }
  });

  it("refuses an input past the class and an output past the capacity", () => {
    const base: AuditStreamLayout = {
      key: { class: 2, entry: false },
      inputs: 2,
      outputs: 2,
      capacity: 2,
      hasData: false,
    };
    expect(checkedStreamLayout(base)).toBe(base);
    expect(() => checkedStreamLayout({ ...base, inputs: 3 })).toThrow();
    expect(() => checkedStreamLayout({ ...base, inputs: 0 })).toThrow();
    expect(() => checkedStreamLayout({ ...base, outputs: 3 })).toThrow();
  });
});

describe("the stream vector", () => {
  const auditor = (): X25519Keypair => X25519Keypair.fromBytes(hex(vector.auditor_sk) as Bytes32);

  for (const testCase of vector.cases) {
    const layout: AuditStreamLayout = {
      key: {
        class: testCase.input_class,
        entry: (testCase.layout & 2) !== 0,
        format:
          (testCase.layout & 4) !== 0
            ? DisclosureFormat.SingleAssetPayout
            : DisclosureFormat.Standard,
      },
      inputs: testCase.input_count,
      outputs: testCase.output_count,
      capacity: testCase.outputs,
      hasData: (testCase.layout & 1) !== 0,
    };
    const salt = hex(vector.salt) as Bytes16;
    const txKey = (): X25519Keypair =>
      X25519Keypair.fromBytes(hex(vector.tx_viewing_sk) as Bytes32);
    const message = () => ({
      ephemeralPublicKey: txKey().publicKey(),
      envelope: hex(testCase.envelope_ciphertext),
      records: testCase.record_ciphertexts.map(hex),
      ...(testCase.tail_ciphertexts === null ? {} : { tails: testCase.tail_ciphertexts.map(hex) }),
    });

    it(`${testCase.name} seals byte for byte as Rust and refuses another salt`, async () => {
      await initializePoseidon();
      const sealed = sealSaltedAuditorStream({
        txViewingSecret: hex(vector.tx_viewing_sk) as Bytes32,
        salt,
        auditorPublicKey: auditor().publicKey(),
        envelope: hex(testCase.envelope_plaintext),
        records: testCase.records.map((bytes, slot) => ({
          counter: recordRegion(layout, slot).startCounter,
          bytes: hex(bytes),
        })),
      });
      expect(bytesToHex(sealed.envelope)).toBe(testCase.envelope_ciphertext);
      expect(sealed.records.map((bytes) => bytesToHex(bytes))).toEqual(testCase.record_ciphertexts);
      const other = Uint8Array.from(salt, (byte) => byte ^ 1) as Bytes16;
      expect(() =>
        openRingDisclosure(auditor(), { layout, message: message(), salt: other }),
      ).toThrow(RingError);
    });

    it(`${testCase.name} opens under the auditor to its plaintexts`, async () => {
      await initializePoseidon();
      const opened = openRingDisclosure(auditor(), { layout, message: message(), salt });
      expect(bytesToHex(encodeAuditEnvelope(opened.envelope))).toBe(testCase.envelope_plaintext);
      expect(
        opened.records.map((record) =>
          bytesToHex(
            (layout.key.format === DisclosureFormat.SingleAssetPayout
              ? encodeCompactAuditRecord
              : encodeAuditRecord)(record),
          ),
        ),
      ).toEqual(testCase.records);
      if (testCase.tails === null) expect(opened.tails).toBeUndefined();
      else
        expect(opened.tails?.map((tail) => bytesToHex(encodeDataTail(tail)))).toEqual(
          testCase.tails,
        );
    });

    it(`${testCase.name} binds its digest and chains`, async () => {
      await initializePoseidon();
      const outputs = testCase.record_ciphertexts.map((record, slot) => ({
        record: hex(record),
        ...(testCase.tail_ciphertexts === null
          ? {}
          : { tail: hex(testCase.tail_ciphertexts[slot] as string) }),
      }));
      expect(bytesToHex(ciphertextDigest(hex(testCase.envelope_ciphertext)))).toBe(
        testCase.envelope_digest,
      );
      expect(bytesToHex(recordChain(outputs, testCase.outputs))).toBe(testCase.record_chain);
      expect(bytesToHex(tailChain(outputs, testCase.outputs))).toBe(testCase.tail_chain);
    });

    it(`${testCase.name} rebuilds every published hash from its record alone`, async () => {
      await initializePoseidon();
      const opened = openRingDisclosure(auditor(), { layout, message: message(), salt });
      const firstNullifier = hex(vector.first_nullifier) as Bytes32;
      const seed = ringBlindingSeed(opened.envelope.txViewingSecret, salt);
      opened.records.forEach((record, slot) => {
        const blinding = ringOutputBlinding({
          firstNullifier,
          blindingSeed: seed,
          outputIndex: slot,
        });
        expect(bytesToHex(blinding)).toBe(testCase.blindings[slot]);
        const tail = opened.tails?.[slot];
        const hash =
          record.kind === RecordKind.dummy
            ? dummyUtxoHash(vector.output_tree_id, blinding)
            : fieldUtxoHash({
                owner: ownerHash(
                  solanaOwnerIdentity(record.ownerKey),
                  record.nullifierPk,
                ) as Bytes32,
                assetField: hashBytes(addressBytes(record.mint, "mint")) as Bytes32,
                amount: record.amount,
                blinding,
                treeId: vector.output_tree_id,
                ...(tail === undefined
                  ? {}
                  : { dataHash: tail.dataHash, ringDataHash: tail.ringDataHash }),
                ringId:
                  record.kind === RecordKind.ring
                    ? (hex(vector.ring_id) as Bytes32)
                    : (new Uint8Array(32) as Bytes32),
              });
        expect(bytesToHex(hash)).toBe(testCase.output_hashes[slot]);
      });
    });

    it(`${testCase.name} reads a record only at its own counter`, async () => {
      await initializePoseidon();
      const swapped = message();
      const [first, second] = swapped.records;
      if (first === undefined || second === undefined) throw new Error("two records");
      const crossed = { ...swapped, records: [second, first, ...swapped.records.slice(2)] };
      let same: boolean;
      try {
        const opened = openRingDisclosure(auditor(), { layout, message: crossed, salt });
        same = bytesToHex(encodeAuditRecord(opened.records[0] as never)) === testCase.records[0];
      } catch {
        same = false;
      }
      expect(same).toBe(false);
    });
  }

  it("seals what it opens", async () => {
    await initializePoseidon();
    const layout: AuditStreamLayout = {
      key: { class: 2, entry: false },
      inputs: 1,
      outputs: 2,
      capacity: 2,
      hasData: true,
    };
    const record = decodeAuditRecord(hex(vector.cases[2]?.records[0] as string));
    const disclosure: RingDisclosure = {
      envelope: {
        txViewingSecret: hex(vector.tx_viewing_sk) as Bytes32,
        realInputs: 1,
        addressInputBits: 0n,
        evidence: { kind: "none" },
      },
      records: [record, record],
      tails: [
        { dataHash: new Uint8Array(32) as Bytes32, ringDataHash: new Uint8Array(32) as Bytes32 },
        { dataHash: new Uint8Array(32) as Bytes32, ringDataHash: new Uint8Array(32) as Bytes32 },
      ],
    };
    const keypair = X25519Keypair.fromBytes(hex(vector.auditor_sk) as Bytes32);
    const sealed = sealRingDisclosure({
      layout,
      auditorPublicKey: keypair.publicKey(),
      salt: hex(vector.salt) as Bytes16,
      disclosure,
    });
    const message = parseAuditorMessage(
      Uint8Array.of(
        ...sealed.ephemeralPublicKey.toBytes(),
        ...sealed.envelope,
        ...sealed.records.flatMap((bytes) => [...bytes]),
        ...(sealed.tails ?? []).flatMap((bytes) => [...bytes]),
      ),
      layout,
    );
    const opened = openRingDisclosure(keypair, {
      layout,
      message,
      salt: hex(vector.salt) as Bytes16,
    });
    expect(opened.records).toEqual(disclosure.records);
    expect(opened.tails).toEqual(disclosure.tails);
    expect(() =>
      sealRingDisclosure({
        layout: { ...layout, hasData: false },
        auditorPublicKey: keypair.publicKey(),
        salt: hex(vector.salt) as Bytes16,
        disclosure,
      }),
    ).toThrow();
  });
});

describe("the stream codecs", () => {
  const record = {
    kind: RecordKind.ring,
    amount: 7n,
    ownerKey: new Uint8Array(32).fill(1) as Bytes32,
    mint: address("11111111111111111111111111111111"),
    nullifierPk: new Uint8Array(32).fill(2) as Bytes32,
  } as const;

  it("lays the record out at its contract bytes", () => {
    const bytes = encodeAuditRecord(record);
    expect(bytes).toHaveLength(105);
    expect(bytes[0]).toBe(1);
    expect(bytes[8]).toBe(7);
    expect(decodeAuditRecord(bytes)).toEqual(record);
  });

  it("refuses a kind off the three and a dummy with a value", () => {
    const bytes = encodeAuditRecord(record);
    const kind = bytes.slice();
    kind[0] = 3;
    const dummy = bytes.slice();
    dummy[0] = 0;
    for (const refused of [kind, dummy, bytes.subarray(1)])
      expect(() => decodeAuditRecord(refused)).toThrow(RingError);
  });

  it("carries a 144 byte opening record and a 64 byte tail", () => {
    const secret = new Uint8Array(32).fill(5) as Bytes32;
    const opening = encodeOpeningRecord({ record, secret });
    expect(opening).toHaveLength(144);
    expect(decodeOpeningRecord(opening)).toEqual({ record, secret });
    const padded = opening.slice();
    padded[105] = 1;
    expect(() => decodeOpeningRecord(padded)).toThrow(RingError);
    expect(() => decodeOpeningRecord(opening.subarray(1))).toThrow(RingError);
    const tail = { dataHash: secret, ringDataHash: secret };
    expect(decodeDataTail(encodeDataTail(tail))).toEqual(tail);
    expect(() => decodeDataTail(new Uint8Array(63))).toThrow(RingError);
  });

  it("refuses an envelope off its layout", () => {
    const layout: AuditStreamLayout = {
      key: { class: 2, entry: true },
      inputs: 1,
      outputs: 2,
      capacity: 2,
      hasData: false,
    };
    const envelope = new Uint8Array(envelopeRegion(layout).length);
    expect(decodeAuditEnvelope(envelope, layout).evidence.kind).toBe("entry");
    expect(() => decodeAuditEnvelope(envelope.subarray(1), layout)).toThrow(RingError);
  });

  it("keeps a plain body fixed and bounds its encrypted data length", () => {
    const body = {
      blinding: new Uint8Array(32).fill(3) as Bytes32,
      amount: 9n,
      mint: address("11111111111111111111111111111111"),
    };
    expect(encodeRecipientBody(body)).toHaveLength(72);
    expect(decodeRecipientBody(encodeRecipientBody(body))).toEqual(body);
    const ringDataHash = new Uint8Array(32).fill(4) as Bytes32;
    const withHash = encodeRecipientBody({ ...body, ringDataHash });
    expect(withHash).toHaveLength(72 + 2 + 1 + 32);
    expect(withHash[74]).toBe(1);
    expect(decodeRecipientBody(withHash).ringDataHash).toEqual(ringDataHash);
    const data = new Uint8Array(40).fill(6);
    const withData = encodeRecipientBody({ ...body, data });
    expect(withData[74]).toBe(0);
    expect(decodeRecipientBody(withData).data).toEqual(data);
    for (const refused of [new Uint8Array(71), Uint8Array.of(...new Uint8Array(72), 2)])
      expect(() => decodeRecipientBody(refused)).toThrow(RingError);
    expect(() => decodeRecipientBody(Uint8Array.of(...new Uint8Array(72), 1, 1))).toThrow(
      RingError,
    );
  });
});
