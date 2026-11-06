// The envelope cases of Rust `program-libs/interface/tests/input_layout_parity.rs`, the same bytes and counters.
import { describe, expect, it } from "vitest";
import type { Address } from "@solana/kit";

import { initializePoseidon } from "@heliuslabs/spr";
import { bigIntBytes } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import type { SettlementTransfer } from "@heliuslabs/spr/transaction";

import {
  decodeAuditEnvelope,
  EMPTY_ENTRY_RECORD,
  encodeAuditEnvelope,
  type AuditEnvelope,
} from "../../../src/protocol/codec/audit-stream.js";
import {
  envelopeRegion,
  firstRecipientKeyCounter,
  recipientKeyRegion,
  type AuditStreamLayout,
} from "../../../src/protocol/codec/ring-disclosure-layout.js";
import { publicGrossFields, publicSlots } from "../../../src/protocol/transaction/spp.js";

await initializePoseidon();

const refusedLength = expect.objectContaining({
  code: "RING_TRANSACT_DATA_INVALID",
  details: expect.objectContaining({ reason: "RingTransactLength" }),
});
const fill = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;

describe("the envelope", () => {
  it("carries the key and R alone on an ordinary key", () => {
    const layout: AuditStreamLayout = {
      key: { class: 64, entry: false },
      inputs: 64,
      outputs: 1,
      capacity: 2,
    };
    const envelope: AuditEnvelope = {
      txViewingSecret: fill(0x23),
      realInputs: 63,
      evidence: { kind: "none" },
    };
    const plaintext = encodeAuditEnvelope(envelope);
    expect(plaintext).toHaveLength(33);
    expect(plaintext.subarray(0, 32)).toEqual(fill(0x23));
    expect(plaintext[32]).toBe(63);
    expect(envelopeRegion(layout).length).toBe(33);
    expect(firstRecipientKeyCounter(layout.key)).toBe(5);
    expect(recipientKeyRegion(layout, 1).startCounter).toBe(7);
    expect(decodeAuditEnvelope(plaintext, layout)).toEqual(envelope);
    expect(() => decodeAuditEnvelope(plaintext.subarray(0, 32), layout)).toThrow(refusedLength);
    expect(() => decodeAuditEnvelope(Uint8Array.of(...plaintext, 0), layout)).toThrow(
      refusedLength,
    );
    // The retired address bitmap lengthens the envelope past its region.
    expect(() =>
      decodeAuditEnvelope(Uint8Array.of(...plaintext, ...new Uint8Array(8)), layout),
    ).toThrow(refusedLength);
  });

  it("refuses an R past the published inputs", () => {
    const layout: AuditStreamLayout = {
      key: { class: 4, entry: false },
      inputs: 2,
      outputs: 1,
      capacity: 2,
    };
    const plaintext = encodeAuditEnvelope({
      txViewingSecret: fill(0x23),
      realInputs: 2,
      evidence: { kind: "none" },
    });
    expect(decodeAuditEnvelope(plaintext, layout).realInputs).toBe(2);
    plaintext[32] = 3;
    expect(() => decodeAuditEnvelope(plaintext, layout)).toThrow(refusedLength);
  });

  it("keeps entry records by note order and stream counters at capacity offsets", () => {
    const layout: AuditStreamLayout = {
      key: { class: 4, entry: true },
      inputs: 3,
      outputs: 2,
      capacity: 4,
    };
    const record = { ...EMPTY_ENTRY_RECORD, amount: 0x0102_0304_0506_0708n, ownerKey: fill(0x31) };
    const envelope: AuditEnvelope = {
      txViewingSecret: fill(0x23),
      realInputs: 2,
      evidence: {
        kind: "entry",
        defaultNoteBits: 2n,
        inputs: [EMPTY_ENTRY_RECORD, record, EMPTY_ENTRY_RECORD],
      },
    };
    const plaintext = encodeAuditEnvelope(envelope);
    expect(plaintext).toHaveLength(449);
    expect(plaintext[32]).toBe(2);
    expect([...plaintext.subarray(33, 41)]).toEqual([0, 0, 0, 0, 0, 0, 0, 2]);
    expect(plaintext.subarray(41, 177).every((byte) => byte === 0)).toBe(true);
    expect(plaintext.subarray(177, 209)).toEqual(fill(0x31));
    expect([...plaintext.subarray(241, 249)]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    const region = envelopeRegion(layout);
    expect([region.length, region.maxBlocks]).toEqual([449, 37]);
    expect(firstRecipientKeyCounter(layout.key)).toBe(39);
    expect(recipientKeyRegion(layout, 1).startCounter).toBe(41);
    expect(decodeAuditEnvelope(plaintext, layout)).toEqual(envelope);

    // R past n, a default bit at or past R, a record off its bit, a record past R.
    for (const [offset, mask] of [
      [32, 6],
      [40, 4],
      [41, 1],
      [313, 1],
    ] as const) {
      const changed = plaintext.slice();
      changed[offset]! ^= mask;
      expect(() => decodeAuditEnvelope(changed, layout), `${offset}`).toThrow(refusedLength);
    }
    // The 200 byte opening layout refuses.
    const fullOpenings = Uint8Array.of(...plaintext, ...new Uint8Array(3 * 64));
    expect(() => decodeAuditEnvelope(fullOpenings, layout)).toThrow(refusedLength);
  });
});

describe("the public gross", () => {
  const USER = "11111111111111111111111111111111" as Address;
  const U64_MAX = (1n << 64n) - 1n;
  const sol = (amount: bigint, isDeposit: boolean): SettlementTransfer => ({
    kind: "sol",
    isDeposit,
    amount,
    userSolAccount: USER,
  });

  it("passes u64 with a net inside it, encoded as a right aligned u128", () => {
    const slots = publicSlots([sol(U64_MAX, false), sol(U64_MAX, true), sol(1n, false)]);
    expect([slots.nets[0], slots.gross[0]]).toEqual([-1n, 1n << 64n]);
    expect(publicGrossFields(slots)[0]).toEqual(bigIntBytes(1n << 64n));
  });

  it("sums sixteen withdrawal and deposit pairs at the leg ceiling", () => {
    const legs = Array.from({ length: 16 }, (_, pair) => [
      sol(U64_MAX, false),
      sol(pair === 15 ? U64_MAX - 1n : U64_MAX, true),
    ]).flat();
    const slots = publicSlots(legs);
    expect([slots.nets[0], slots.gross[0]]).toEqual([-1n, 16n * U64_MAX]);
  });

  it("keeps the u64 net bound", () => {
    expect(() => publicSlots([sol(U64_MAX, false), sol(1n, false)])).toThrow(
      expect.objectContaining({ code: "CLIENT_PROVER_INPUT" }),
    );
  });
});
