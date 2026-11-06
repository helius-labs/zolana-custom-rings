import { describe, expect, it } from "vitest";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";

import { initializePoseidon } from "@heliuslabs/spr";
import { X25519Keypair, X25519PublicKey } from "@heliuslabs/spr/keypair";
import { hashChain } from "@heliuslabs/spr/internal";
import type { Bytes32, Bytes33 } from "@heliuslabs/spr/interface";

import vector from "../../../../test-vectors/merge/merge.json" with { type: "json" };
import {
  decodeRingMergeRequest,
  encodeRingMergeRequest,
  MergeRingAuthority,
  mergePublicInputElements,
  mergePublicInputHash,
  openMergeRecord,
  sealMergeRecordWith,
  type MergePublicInput,
} from "../../src/crypto/audit/merge-disclosure.js";
import { encodeOpeningRecord, decodeOpeningRecord } from "../../src/protocol/codec/audit-stream.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../../src/protocol/proof/custom-ring-proof.js";
import { RingError } from "../../src/protocol/error.js";

const hex = (value: string): Uint8Array => hexToBytes(value.replace(/^0x/, ""));

describe("the merge record vector", () => {
  const auditor = (): X25519Keypair => X25519Keypair.fromBytes(hex(vector.auditor_sk) as Bytes32);

  for (const testCase of vector.cases) {
    const request = testCase.request;

    it(`${testCase.name} seals the record under its ephemeral and opens for the auditor`, async () => {
      await initializePoseidon();
      const opening = decodeOpeningRecord(hex(testCase.record));
      expect(bytesToHex(encodeOpeningRecord(opening))).toBe(testCase.record.replace(/^0x/, ""));
      const { sealed } = sealMergeRecordWith({
        opening,
        auditorPublicKey: X25519PublicKey.fromBytes(hex(vector.auditor_pk) as Bytes33),
        ephemeral: X25519Keypair.fromBytes(hex(request.ephSk) as Bytes32),
      });
      expect(bytesToHex(sealed.ciphertext)).toBe(testCase.ciphertext.replace(/^0x/, ""));
      expect(bytesToHex(sealed.ephemeralPublicKey)).toBe(vector.eph_pk.replace(/^0x/, ""));
      expect(openMergeRecord(auditor(), sealed)).toEqual(opening);
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
        ciphertext: hex(testCase.ciphertext),
        payer: hex(request.payer) as Bytes32,
        publishedOwner: zeroMode
          ? (hex(request.ownerPkHash) as Bytes32)
          : (new Uint8Array(32) as Bytes32),
        trackingRoot: hex(request.trackingRoot) as Bytes32,
      };
      expect(mergePublicInputElements(input).map((element) => `0x${bytesToHex(element)}`)).toEqual(
        testCase.elements,
      );
      expect(`0x${bytesToHex(mergePublicInputHash(input))}`).toBe(testCase.public_input_hash);
      expect(request.publicInputHash).toBe(testCase.public_input_hash);
      expect(hashChain(testCase.elements.map((element) => hex(element) as Bytes32))).toEqual(
        mergePublicInputHash(input),
      );
    });
  }

  it("refuses a ciphertext off its length", () => {
    expect(() =>
      openMergeRecord(auditor(), {
        ephemeralPublicKey: hex(vector.eph_pk) as Bytes33,
        ciphertext: new Uint8Array(143),
      }),
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
      ciphertext: new Uint8Array(144).fill(14),
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
