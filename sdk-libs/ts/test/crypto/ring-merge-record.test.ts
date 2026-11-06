import { describe, expect, it } from "vitest";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";

import { initializePoseidon } from "@heliuslabs/spr";
import { ViewingKey, X25519Keypair, X25519PublicKey } from "@heliuslabs/spr/keypair";
import { encodeBase58, hashChain } from "@heliuslabs/spr/internal";
import type { Address, Bytes32, Bytes33 } from "@heliuslabs/spr/interface";

import vector from "../../../../test-vectors/merge/merge.json" with { type: "json" };
import {
  decodeRingMergeRequest,
  encodeRingMergeRequest,
  MergeRingAuthority,
  mergePublicInputElements,
  mergePublicInputHash,
  openMergeRecord,
  openOwnMergeRecord,
  sealMergeRecordWith,
  type MergePublicInput,
} from "../../src/crypto/audit/merge-disclosure.js";
import {
  decodeMergeRecord,
  encodeMergeRecord,
  RecordKind,
  type MergeRecord,
} from "../../src/protocol/codec/audit-stream.js";
import {
  MERGE_ENVELOPE_LEN,
  MERGE_RECORD_LEN,
} from "../../src/protocol/codec/ring-disclosure-layout.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../../src/protocol/proof/custom-ring-proof.js";
import { RingError } from "../../src/protocol/error.js";

const hex = (value: string): Uint8Array => hexToBytes(value.replace(/^0x/, ""));
const unhex = (bytes: Uint8Array): string => bytesToHex(bytes);

describe("the merge record vector", () => {
  const auditor = (): X25519Keypair => X25519Keypair.fromBytes(hex(vector.auditor_sk) as Bytes32);

  for (const testCase of vector.cases) {
    const request = testCase.request;

    it(`${testCase.name} seals the record and envelope under its ephemeral and opens for the auditor`, async () => {
      await initializePoseidon();
      const merge = decodeMergeRecord(hex(testCase.record));
      expect(unhex(encodeMergeRecord(merge))).toBe(testCase.record.replace(/^0x/, ""));
      const recipient = X25519PublicKey.fromBytes(Uint8Array.of(4, ...hex(request.recipientKey)));
      const { sealed } = sealMergeRecordWith({
        merge,
        recipient,
        auditorPublicKey: X25519PublicKey.fromBytes(hex(vector.auditor_pk) as Bytes33),
        firstNullifier: hex(request.firstNullifier) as Bytes32,
        ephemeral: X25519Keypair.fromBytes(hex(request.ephSk) as Bytes32),
      });
      expect(unhex(sealed.record)).toBe(testCase.ciphertext.replace(/^0x/, ""));
      expect(unhex(sealed.envelope)).toBe(testCase.envelope_ciphertext.replace(/^0x/, ""));
      expect(hex(testCase.envelope)).toEqual(
        Uint8Array.of(...hex(request.ephSk), ...hex(request.recipientKey)),
      );
      expect(unhex(sealed.ephemeralPublicKey)).toBe(vector.eph_pk.replace(/^0x/, ""));
      expect(openMergeRecord(auditor(), sealed, hex(request.firstNullifier) as Bytes32)).toEqual(
        merge,
      );
    });

    it(`${testCase.name} rebuilds the statement elements and hash`, async () => {
      await initializePoseidon();
      const zeroMode = testCase.name === "zero";
      const input: MergePublicInput = {
        outputUtxoHash: hex(request.outputUtxoHash) as Bytes32,
        firstNullifier: hex(request.firstNullifier) as Bytes32,
        ringId: hex(request.ringProgramId) as Bytes32,
        auditorPubkey: hex(vector.auditor_pk) as Bytes33,
        ephemeralPublicKey: hex(vector.eph_pk) as Bytes33,
        envelope: hex(testCase.envelope_ciphertext),
        record: hex(testCase.ciphertext),
        payer: hex(request.payer) as Bytes32,
        publishedOwner: zeroMode
          ? (hex(request.ownerPkHash) as Bytes32)
          : (new Uint8Array(32) as Bytes32),
        trackingRoot: hex(request.trackingRoot) as Bytes32,
      };
      expect(mergePublicInputElements(input).map((element) => `0x${unhex(element)}`)).toEqual(
        testCase.elements,
      );
      expect(`0x${unhex(mergePublicInputHash(input))}`).toBe(testCase.public_input_hash);
      expect(request.publicInputHash).toBe(testCase.public_input_hash);
      expect(hashChain(testCase.elements.map((element) => hex(element) as Bytes32))).toEqual(
        mergePublicInputHash(input),
      );
    });
  }
});

describe("the merge record seal", () => {
  const firstNullifier = (() => {
    const field = new Uint8Array(32);
    field[31] = 17;
    return field as Bytes32;
  })();
  const merge: MergeRecord = Object.freeze({
    record: Object.freeze({
      kind: RecordKind.ring,
      amount: 21n,
      ownerKey: new Uint8Array(32).fill(5) as Bytes32,
      mint: encodeBase58(new Uint8Array(32).fill(6)) as Address,
      nullifierPk: (() => {
        const field = new Uint8Array(32);
        field[31] = 7;
        return field as Bytes32;
      })(),
      blinding: (() => {
        const field = new Uint8Array(32);
        field[31] = 8;
        return field as Bytes32;
      })(),
    }),
    seed: (() => {
      const field = new Uint8Array(32);
      field[31] = 9;
      return field as Bytes32;
    })(),
  });

  const sealed = () => {
    const auditor = X25519Keypair.generate();
    const owner = ViewingKey.generate();
    const ephemeral = X25519Keypair.generate();
    const { sealed: record } = sealMergeRecordWith({
      merge,
      recipient: owner.publicKey(),
      auditorPublicKey: auditor.publicKey(),
      firstNullifier,
      ephemeral,
    });
    return { auditor, owner, ephemeral, record };
  };

  it("opens for the auditor through the envelope and for the owner under its viewing key", async () => {
    await initializePoseidon();
    const { auditor, owner, record } = sealed();
    expect(record.envelope).toHaveLength(MERGE_ENVELOPE_LEN);
    expect(record.record).toHaveLength(MERGE_RECORD_LEN);
    expect(openMergeRecord(auditor, record, firstNullifier)).toEqual(merge);
    expect(openOwnMergeRecord(owner, record, firstNullifier)).toEqual(merge);
  });

  it("refuses an envelope sealing another ephemeral than the published one", async () => {
    await initializePoseidon();
    const { auditor, owner, record } = sealed();
    const other = sealMergeRecordWith({
      merge,
      recipient: owner.publicKey(),
      auditorPublicKey: auditor.publicKey(),
      firstNullifier,
      ephemeral: X25519Keypair.generate(),
    }).sealed;
    expect(() =>
      openMergeRecord(auditor, { ...record, envelope: other.envelope }, firstNullifier),
    ).toThrow(RingError);
  });

  it("opens no record under another first nullifier", async () => {
    await initializePoseidon();
    const { auditor, record } = sealed();
    const moved = new Uint8Array(32);
    moved[31] = 18;
    expect(() => openMergeRecord(auditor, record, moved as Bytes32)).toThrow(RingError);
  });

  it("refuses an envelope or a record off its length", async () => {
    await initializePoseidon();
    const { auditor, record } = sealed();
    expect(() =>
      openMergeRecord(auditor, { ...record, envelope: new Uint8Array(63) }, firstNullifier),
    ).toThrow(RingError);
    expect(() =>
      openMergeRecord(auditor, { ...record, record: new Uint8Array(168) }, firstNullifier),
    ).toThrow(RingError);
  });
});

describe("the tag 57 request", () => {
  const request = {
    trackingRevision: 3n,
    outputRingDataHash: new Uint8Array(32).fill(8) as Bytes32,
    authority: MergeRingAuthority.ownerSigned,
    sealed: {
      proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH).fill(9),
      ephemeralPublicKey: new Uint8Array(33).fill(4) as Bytes33,
      envelope: new Uint8Array(MERGE_ENVELOPE_LEN).fill(13),
      record: new Uint8Array(MERGE_RECORD_LEN).fill(14),
    },
    compactBody: new Uint8Array(200).fill(1),
  };

  it("round trips", () => {
    expect(decodeRingMergeRequest(encodeRingMergeRequest(request))).toEqual(request);
  });

  it("refuses an authority byte off the two", () => {
    const bytes = encodeRingMergeRequest(request);
    bytes[40] = 2;
    expect(() => decodeRingMergeRequest(bytes)).toThrow(RingError);
  });
});
