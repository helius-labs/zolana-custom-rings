import { describe, expect, it } from "vitest";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { address } from "@solana/kit";

import { initializePoseidon } from "@heliuslabs/spr";
import { addressBytes, hashBytes, solanaOwnerIdentity } from "@heliuslabs/spr/internal";
import { ownerHash, X25519Keypair } from "@heliuslabs/spr/keypair";
import type { Bytes16, Bytes32 } from "@heliuslabs/spr/interface";

import rangesJson from "../../../../../test-vectors/audit/ring-disclosure-ranges.json" with { type: "json" };
import vectorJson from "../../../../../test-vectors/audit/audit-stream.json" with { type: "json" };
import { parseAuditorMessage, sealSaltedAuditorStream } from "../../../src/crypto/audit/audit.js";
import {
  openOutputSlot,
  openRingDisclosure,
  sealOutputSlot,
  sealRingDisclosure,
  type RingDisclosure,
} from "../../../src/crypto/audit/ring-disclosure.js";
import { ringBlindingSeed, ringOutputBlinding } from "../../../src/crypto/derivation/blinding.js";
import {
  decodeAuditEnvelope,
  decodeMergeRecord,
  decodeOutputRecord,
  decodeRecipientPayload,
  DUMMY_RECORD,
  encodeAuditEnvelope,
  encodeMergeRecord,
  encodeOutputRecord,
  encodeRecipientPayload,
  RecordKind,
  type OutputRecord,
} from "../../../src/protocol/codec/audit-stream.js";
import {
  auditorMessageLen,
  capacityBlocks,
  checkedStreamLayout,
  envelopeBlocks,
  envelopeRegion,
  firstRecipientKeyCounter,
  recipientKeyRegion,
  RECIPIENT_KEY_LEN,
  type AuditStreamLayout,
} from "../../../src/protocol/codec/ring-disclosure-layout.js";
import { envelopeDigest, recordChain } from "../../../src/protocol/proof/statement.js";
import { dummyUtxoHash, fieldUtxoHash } from "../../../src/protocol/membership/utxo-hash.js";
import { RingError } from "../../../src/protocol/error.js";

const hex = (value: string): Uint8Array => hexToBytes(value);

/** The regenerated writers' field names, Rust `AuditStreamLayout::{envelope, recipient_key, keys_len}`. */
interface RangeKey {
  readonly class: number;
  readonly entry: boolean;
  readonly outputs: number;
  readonly envelope_blocks: number;
  readonly first_key_counter: number;
  readonly capacity_blocks: number;
  readonly envelope_len_by_input_count: readonly number[];
  readonly key_start_counters: readonly number[];
}

interface StreamCase {
  readonly name: string;
  readonly layout: number;
  readonly input_class: number;
  readonly outputs: number;
  readonly output_count: number;
  readonly input_count: number;
  readonly envelope_plaintext: string;
  readonly envelope_ciphertext: string;
  readonly recipient_keys: readonly string[];
  readonly recipient_keys_ciphertext: string;
  readonly records: readonly string[];
  readonly record_ciphertexts: readonly string[];
  readonly output_hashes: readonly string[];
  readonly blindings: readonly string[];
  readonly envelope_digest: string;
  readonly record_chain: string;
}

const ranges = rangesJson as unknown as { readonly keys: readonly RangeKey[] };
const vector = vectorJson as unknown as {
  readonly auditor_sk: string;
  readonly tx_viewing_sk: string;
  readonly salt: string;
  readonly first_nullifier: string;
  readonly output_tree_id: number;
  readonly ring_id: string;
  readonly cases: readonly StreamCase[];
};

describe("the stream regions", () => {
  it("are the shared vector for every key", () => {
    for (const key of ranges.keys) {
      const layoutAt = (inputs: number): AuditStreamLayout => ({
        key: { class: key.class, entry: key.entry },
        inputs,
        outputs: key.outputs,
        capacity: key.outputs,
      });
      const layout = layoutAt(1);
      expect(envelopeBlocks(layout.key)).toBe(key.envelope_blocks);
      expect(firstRecipientKeyCounter(layout.key)).toBe(key.first_key_counter);
      expect(capacityBlocks(layout)).toBe(key.capacity_blocks);
      key.envelope_len_by_input_count.forEach((length, index) =>
        expect(envelopeRegion(layoutAt(index + 1)).length).toBe(length),
      );
      key.key_start_counters.forEach((counter, slot) => {
        const region = recipientKeyRegion(layout, slot);
        expect(region.startCounter).toBe(counter);
        expect(region.length).toBe(32);
      });
    }
  });

  it("counts two blocks per key and transmits 32 bytes per published slot", () => {
    const layout: AuditStreamLayout = {
      key: { class: 2, entry: false },
      inputs: 2,
      outputs: 2,
      capacity: 4,
    };
    expect(envelopeBlocks(layout.key)).toBe(3);
    expect(firstRecipientKeyCounter(layout.key)).toBe(5);
    expect([0, 1, 2, 3].map((slot) => recipientKeyRegion(layout, slot).startCounter)).toEqual([
      5, 7, 9, 11,
    ]);
    expect(recipientKeyRegion(layout, 2).length).toBe(0);
    expect(capacityBlocks(layout)).toBe(3 + 4 * 2);
    // `0x04 ‖ eph_u ‖ envelope ‖ keys ‖ one exit record`.
    expect(auditorMessageLen(layout, 1)).toBe(33 + 33 + 64 + 137);
  });

  it("refuses an input past the class and an output past the capacity", () => {
    const base: AuditStreamLayout = {
      key: { class: 2, entry: false },
      inputs: 2,
      outputs: 2,
      capacity: 2,
    };
    expect(checkedStreamLayout(base)).toBe(base);
    expect(() => checkedStreamLayout({ ...base, inputs: 3 })).toThrow();
    expect(() => checkedStreamLayout({ ...base, inputs: 0 })).toThrow();
    expect(() => checkedStreamLayout({ ...base, outputs: 3 })).toThrow();
  });
});

/** The vector carries no payload, the Go writer's hashes on the data case's first output stand in. */
const dataHashes = (
  name: string,
  slot: number,
): Readonly<{ dataHash?: Bytes32; ringDataHash?: Bytes32 }> => {
  if (name !== "data" || slot !== 0) return {};
  const field = (value: number): Bytes32 => {
    const bytes = new Uint8Array(32);
    new DataView(bytes.buffer).setUint32(28, value, false);
    return bytes as Bytes32;
  };
  return { dataHash: field(0xda7a), ringDataHash: field(0x5ca1e) };
};

const keyCiphertexts = (testCase: StreamCase): string[] =>
  testCase.recipient_keys.map((_, slot) =>
    testCase.recipient_keys_ciphertext.slice(
      slot * 2 * RECIPIENT_KEY_LEN,
      (slot + 1) * 2 * RECIPIENT_KEY_LEN,
    ),
  );

describe("the stream vector", () => {
  const auditor = (): X25519Keypair => X25519Keypair.fromBytes(hex(vector.auditor_sk) as Bytes32);

  for (const testCase of vector.cases) {
    const layout: AuditStreamLayout = {
      key: { class: testCase.input_class, entry: (testCase.layout & 2) !== 0 },
      inputs: testCase.input_count,
      outputs: testCase.output_count,
      capacity: testCase.outputs,
    };
    const salt = hex(vector.salt) as Bytes16;
    const txKey = (): X25519Keypair =>
      X25519Keypair.fromBytes(hex(vector.tx_viewing_sk) as Bytes32);
    const message = () => ({
      ephemeralPublicKey: txKey().publicKey(),
      envelope: hex(testCase.envelope_ciphertext),
      recipientKeys: keyCiphertexts(testCase).map(hex),
    });

    it(`${testCase.name} seals byte for byte as Rust and refuses another salt`, async () => {
      await initializePoseidon();
      const sealed = sealSaltedAuditorStream({
        txViewingSecret: hex(vector.tx_viewing_sk) as Bytes32,
        salt,
        auditorPublicKey: auditor().publicKey(),
        envelope: hex(testCase.envelope_plaintext),
        recipientKeys: testCase.recipient_keys.map((key, slot) => ({
          counter: recipientKeyRegion(layout, slot).startCounter,
          bytes: hex(key),
        })),
      });
      expect(bytesToHex(sealed.envelope)).toBe(testCase.envelope_ciphertext);
      expect(sealed.recipientKeys.map((bytes) => bytesToHex(bytes))).toEqual(
        keyCiphertexts(testCase),
      );
      const other = Uint8Array.from(salt, (byte) => byte ^ 1) as Bytes16;
      expect(() =>
        openRingDisclosure(auditor(), { layout, message: message(), salt: other }),
      ).toThrow(RingError);
    });

    it(`${testCase.name} opens under the auditor to its plaintexts`, async () => {
      await initializePoseidon();
      const opened = openRingDisclosure(auditor(), { layout, message: message(), salt });
      expect(bytesToHex(encodeAuditEnvelope(opened.envelope))).toBe(testCase.envelope_plaintext);
      expect(opened.recipientKeys.map((key) => bytesToHex(key))).toEqual(testCase.recipient_keys);
    });

    it(`${testCase.name} binds its digest and record chain`, async () => {
      await initializePoseidon();
      const outputs = testCase.record_ciphertexts.map((record) => ({ record: hex(record) }));
      expect(
        bytesToHex(
          envelopeDigest(
            hex(testCase.envelope_ciphertext),
            hex(testCase.recipient_keys_ciphertext),
          ),
        ),
      ).toBe(testCase.envelope_digest);
      expect(bytesToHex(recordChain(outputs, testCase.outputs))).toBe(testCase.record_chain);
    });

    it(`${testCase.name} rebuilds every published hash from its record and data hashes`, async () => {
      await initializePoseidon();
      const opened = openRingDisclosure(auditor(), { layout, message: message(), salt });
      const firstNullifier = hex(vector.first_nullifier) as Bytes32;
      const seed = ringBlindingSeed(hex(vector.tx_viewing_sk) as Bytes32, salt);
      testCase.records.forEach((plaintext, slot) => {
        const record = decodeOutputRecord(hex(plaintext));
        const blinding = ringOutputBlinding({
          firstNullifier,
          blindingSeed: seed,
          outputIndex: slot,
        });
        expect(bytesToHex(blinding)).toBe(testCase.blindings[slot]);
        if (record.kind !== RecordKind.dummy) expect(record.blinding).toEqual(blinding);
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
                blinding: record.blinding,
                treeId: vector.output_tree_id,
                ...dataHashes(testCase.name, slot),
                ringId:
                  record.kind === RecordKind.ring
                    ? (hex(vector.ring_id) as Bytes32)
                    : (new Uint8Array(32) as Bytes32),
              });
        expect(bytesToHex(hash)).toBe(testCase.output_hashes[slot]);
      });
      expect(opened.recipientKeys).toHaveLength(testCase.output_count);
    });
  }

  it("seals what it opens and reads a key only at its own counter", async () => {
    await initializePoseidon();
    const layout: AuditStreamLayout = {
      key: { class: 2, entry: false },
      inputs: 1,
      outputs: 2,
      capacity: 2,
    };
    const keys = [
      X25519Keypair.generate().publicKey().u(),
      X25519Keypair.generate().publicKey().u(),
    ];
    const disclosure: RingDisclosure = {
      envelope: {
        txViewingSecret: hex(vector.tx_viewing_sk) as Bytes32,
        realInputs: 1,
        evidence: { kind: "none" },
      },
      recipientKeys: keys,
    };
    const keypair = X25519Keypair.fromBytes(hex(vector.auditor_sk) as Bytes32);
    const salt = hex(vector.salt) as Bytes16;
    const sealed = sealRingDisclosure({
      layout,
      auditorPublicKey: keypair.publicKey(),
      salt,
      disclosure,
    });
    const exitRecord = new Uint8Array(137).fill(5);
    const message = parseAuditorMessage(
      Uint8Array.of(
        ...sealed.ephemeralPublicKey.toBytes(),
        ...sealed.envelope,
        ...sealed.recipientKeys.flatMap((bytes) => [...bytes]),
        ...exitRecord,
      ),
      layout,
      1,
    );
    expect(message.exitRecords).toEqual([exitRecord]);
    const opened = openRingDisclosure(keypair, { layout, message, salt });
    expect(opened.recipientKeys).toEqual(keys);
    const [first, second] = message.recipientKeys;
    const crossed = { ...message, recipientKeys: [second as Uint8Array, first as Uint8Array] };
    expect(
      openRingDisclosure(keypair, { layout, message: crossed, salt }).recipientKeys,
    ).not.toEqual(keys);
    expect(() =>
      sealRingDisclosure({
        layout: { ...layout, outputs: 1 },
        auditorPublicKey: keypair.publicKey(),
        salt,
        disclosure,
      }),
    ).toThrow();
    expect(() => parseAuditorMessage(Uint8Array.of(...sealed.envelope), layout, 0)).toThrow();
  });
});

describe("the stream codecs", () => {
  const record: OutputRecord = {
    kind: RecordKind.ring,
    amount: 7n,
    ownerKey: new Uint8Array(32).fill(1) as Bytes32,
    mint: address("11111111111111111111111111111111"),
    nullifierPk: new Uint8Array(32).fill(2) as Bytes32,
    blinding: new Uint8Array(32).fill(3) as Bytes32,
  };

  it("lays the output record out at its contract bytes", () => {
    const bytes = encodeOutputRecord(record);
    expect(bytes).toHaveLength(137);
    expect(bytes[0]).toBe(1);
    expect(bytes[8]).toBe(7);
    expect(bytes.subarray(105)).toEqual(record.blinding);
    expect(decodeOutputRecord(bytes)).toEqual(record);
    expect(encodeOutputRecord(DUMMY_RECORD).every((byte) => byte === 0)).toBe(true);
  });

  it("refuses a kind off the three, a dummy with any nonzero byte and another length", () => {
    const bytes = encodeOutputRecord(record);
    const kind = bytes.slice();
    kind[0] = 3;
    const dummy = bytes.slice();
    dummy[0] = 0;
    const dummyBlinding = new Uint8Array(137);
    dummyBlinding[136] = 1;
    for (const refused of [kind, dummy, dummyBlinding, bytes.subarray(1)])
      expect(() => decodeOutputRecord(refused)).toThrow(RingError);
  });

  it("carries a 169 byte merge record of a ring note", () => {
    const seed = new Uint8Array(32).fill(5) as Bytes32;
    const merge = encodeMergeRecord({ record, seed });
    expect(merge).toHaveLength(169);
    expect(decodeMergeRecord(merge)).toEqual({ record, seed });
    // The codec reads any kind as Rust does, the merge reader refuses one other than a ring note.
    const exit = merge.slice();
    exit[0] = RecordKind.exit;
    expect(decodeMergeRecord(exit).record.kind).toBe(RecordKind.exit);
    expect(() => decodeMergeRecord(merge.subarray(1))).toThrow(RingError);
  });

  it("refuses an envelope off its layout", () => {
    const layout: AuditStreamLayout = {
      key: { class: 2, entry: true },
      inputs: 1,
      outputs: 2,
      capacity: 2,
    };
    const envelope = new Uint8Array(envelopeRegion(layout).length);
    expect(decodeAuditEnvelope(envelope, layout).evidence.kind).toBe("entry");
    expect(() => decodeAuditEnvelope(envelope.subarray(1), layout)).toThrow(RingError);
  });

  it("frames the payload with its length and refuses what the encoder never writes", () => {
    const ringDataHash = new Uint8Array(32).fill(4) as Bytes32;
    // The presence byte is always written, an empty payload is `u16be(1) ‖ 0`.
    expect(encodeRecipientPayload({ data: new Uint8Array() })).toEqual(Uint8Array.of(0, 1, 0));
    const withHash = encodeRecipientPayload({ ringDataHash, data: new Uint8Array() }, 40);
    expect(withHash).toHaveLength(40);
    expect([...withHash.subarray(0, 3)]).toEqual([0, 33, 1]);
    expect(decodeRecipientPayload(withHash)).toEqual({ ringDataHash, data: new Uint8Array() });
    const data = new Uint8Array(40).fill(6);
    const withData = encodeRecipientPayload({ data });
    expect(withData[2]).toBe(0);
    expect(decodeRecipientPayload(withData).data).toEqual(data);
    const padding = withHash.slice();
    padding[39] = 1;
    const pastBytes = Uint8Array.of(0, 9, 0);
    const presence = Uint8Array.of(0, 1, 2);
    const shortHash = Uint8Array.of(0, 2, 1, 0);
    const empty = Uint8Array.of(0, 0, 0);
    for (const refused of [padding, pastBytes, presence, shortHash, empty, new Uint8Array(1)])
      expect(() => decodeRecipientPayload(refused)).toThrow(RingError);
    expect(() => encodeRecipientPayload({ data }, 10)).toThrow(RingError);
  });

  it("seals the record and payload as one stream the slot secret opens", async () => {
    await initializePoseidon();
    const secret = new Uint8Array(32).fill(9) as Bytes32;
    secret[0] = 0;
    const payload = { data: new Uint8Array(40).fill(6) };
    const body = sealOutputSlot(secret, { record, payload, payloadLength: 50 });
    expect(body).toHaveLength(187);
    expect(openOutputSlot(secret, body)).toEqual({ record, payload });
    const bare = sealOutputSlot(secret, { record });
    // One keystream from counter 2, the record bytes seal alike with or without a payload.
    expect(bare).toEqual(body.subarray(0, 137));
    expect(openOutputSlot(secret, bare)).toEqual({ record });
    expect(() => openOutputSlot(secret, bare.subarray(1))).toThrow();
  });
});
