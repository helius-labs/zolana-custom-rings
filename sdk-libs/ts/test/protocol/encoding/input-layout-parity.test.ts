// The cases of Rust `program-libs/interface/tests/input_layout_parity.rs`, the same bytes and counters.
import { describe, expect, it } from "vitest";
import type { Address } from "@solana/kit";

import { initializePoseidon } from "@heliuslabs/spr";
import { bigIntBytes, hashChain4 } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import type { SettlementTransfer } from "@heliuslabs/spr/transaction";

import {
  decodeAuditEnvelope,
  EMPTY_ENTRY_INPUT,
  encodeAuditEnvelope,
  envelopeInputMap,
  InputClass,
  InputMap,
  type AuditEnvelope,
  type InputClassification,
} from "../../../src/protocol/codec/audit-stream.js";
import {
  envelopeRegion,
  firstRecordCounter,
  firstTailCounter,
  recordRegion,
  tailRegion,
  type AuditStreamLayout,
} from "../../../src/protocol/codec/ring-disclosure-layout.js";
import { inputNullifierChain } from "../../../src/protocol/proof/statement.js";
import { publicGrossFields, publicSlots } from "../../../src/protocol/transaction/spp.js";

await initializePoseidon();

const { note: Note, address: Addr, dummy: Dummy } = InputClass;
const refusedLength = expect.objectContaining({
  code: "RING_TRANSACT_DATA_INVALID",
  details: expect.objectContaining({ reason: "RingTransactLength" }),
});
const fill = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;

describe("the input map", () => {
  it("keeps absolute slots with notes and addresses interleaved", () => {
    for (const [classes, published, notes, addresses] of [
      [[Note, Addr, Note, Dummy], 4, 2, 2n],
      [[Addr, Note, Addr, Dummy], 3, 1, 5n],
      [[Addr, Addr, Dummy, Dummy], 3, 0, 3n],
      [[Note, Note, Dummy, Dummy], 2, 2, 0n],
      [[Dummy, Dummy, Dummy, Dummy], 1, 0, 0n],
    ] as const) {
      const map = InputMap.fromClasses(classes, published);
      expect([map.noteCount, map.addressInputBits, map.publishedInputs]).toEqual([
        notes,
        addresses,
        published,
      ]);
      expect(map.classes()).toEqual(classes);
      expect(map.slot(4)).toBeUndefined();
    }
  });

  it("refuses noncanonical padding and counts", () => {
    for (const classes of [
      [Note, Dummy, Addr],
      [Addr, Dummy, Note],
    ])
      expect(() => InputMap.fromClasses(classes, 3)).toThrow(refusedLength);
    expect(() => InputMap.fromClasses([Note, Addr], 1)).toThrow(refusedLength);
    expect(() => InputMap.fromClasses(Array<InputClass>(65).fill(Dummy), 1)).toThrow(refusedLength);
    const valid: InputClassification = {
      publishedInputs: 3,
      capacity: 4,
      noteCount: 1,
      addressInputBits: 1n,
    };
    expect(InputMap.check(valid).nonDummyCount).toBe(2);
    for (const invalid of [
      { publishedInputs: 0 },
      { publishedInputs: 5 },
      { capacity: 65 },
      { noteCount: 4 },
      { addressInputBits: 1n << 3n },
      { addressInputBits: 1n << 2n },
      { addressInputBits: 1n << 64n },
    ])
      expect(() => InputMap.check({ ...valid, ...invalid })).toThrow(refusedLength);
  });

  it("selects default bits on note positions alone", () => {
    const map = InputMap.fromClasses([Addr, Note, Note, Dummy], 3);
    for (const accepted of [0n, 2n, 4n, 6n])
      expect(map.validateDefaultInputBits(accepted)).toBe(undefined);
    for (const rejected of [1n, 3n, 8n, 1n << 63n])
      expect(() => map.validateDefaultInputBits(rejected)).toThrow(refusedLength);
  });
});

describe("the envelope", () => {
  it("encodes the high address bit big endian on an ordinary key", () => {
    const layout: AuditStreamLayout = {
      key: { class: 64, entry: false },
      inputs: 64,
      outputs: 1,
      capacity: 2,
      hasData: false,
    };
    const envelope: AuditEnvelope = {
      txViewingSecret: fill(0x23),
      realInputs: 63,
      addressInputBits: 1n << 63n,
      evidence: { kind: "none" },
    };
    const plaintext = encodeAuditEnvelope(envelope);
    expect(plaintext).toHaveLength(41);
    expect(plaintext.subarray(0, 32)).toEqual(fill(0x23));
    expect(plaintext[32]).toBe(63);
    expect([...plaintext.subarray(33, 41)]).toEqual([0x80, 0, 0, 0, 0, 0, 0, 0]);
    expect(envelopeRegion(layout).length).toBe(41);
    expect(firstRecordCounter(layout.key)).toBe(5);
    expect(decodeAuditEnvelope(plaintext, layout)).toEqual(envelope);
    const map = envelopeInputMap(envelope, layout);
    expect([map.slot(62), map.slot(63), map.slot(64)]).toEqual([Note, Addr, undefined]);
    expect(map.validateDefaultInputBits(1n << 62n)).toBe(undefined);
    expect(() => map.validateDefaultInputBits(1n << 63n)).toThrow(refusedLength);
    expect(() => decodeAuditEnvelope(plaintext.subarray(0, 33), layout)).toThrow(refusedLength);
    expect(() => decodeAuditEnvelope(Uint8Array.of(...plaintext, 0), layout)).toThrow(
      refusedLength,
    );
  });

  it("keeps entry openings and stream counters at capacity offsets", () => {
    const layout: AuditStreamLayout = {
      key: { class: 4, entry: true },
      inputs: 3,
      outputs: 2,
      capacity: 4,
      hasData: true,
    };
    const opening = { ...EMPTY_ENTRY_INPUT, amount: 0x0102_0304_0506_0708n, ownerKey: fill(0x31) };
    const envelope: AuditEnvelope = {
      txViewingSecret: fill(0x23),
      realInputs: 2,
      addressInputBits: 2n,
      evidence: {
        kind: "entry",
        defaultInputBits: 4n,
        inputs: [EMPTY_ENTRY_INPUT, EMPTY_ENTRY_INPUT, opening],
      },
    };
    const plaintext = encodeAuditEnvelope(envelope);
    expect(plaintext).toHaveLength(649);
    expect([...plaintext.subarray(33, 41)]).toEqual([0, 0, 0, 0, 0, 0, 0, 2]);
    expect([...plaintext.subarray(41, 49)]).toEqual([0, 0, 0, 0, 0, 0, 0, 4]);
    expect(plaintext.subarray(49, 449).every((byte) => byte === 0)).toBe(true);
    expect(plaintext.subarray(449, 481)).toEqual(fill(0x31));
    expect([...plaintext.subarray(513, 521)]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    const region = envelopeRegion(layout);
    expect([region.length, region.maxBlocks]).toEqual([649, 54]);
    expect(firstRecordCounter(layout.key)).toBe(56);
    expect(recordRegion(layout, 1).startCounter).toBe(63);
    expect(firstTailCounter(layout)).toBe(84);
    expect(tailRegion(layout, 1).startCounter).toBe(88);
    expect(decodeAuditEnvelope(plaintext, layout)).toEqual(envelope);

    // An address bit past `L`, a default bit on an address, an opening off a default bit.
    for (const [offset, mask] of [
      [40, 1],
      [48, 2],
      [49, 1],
      [249, 1],
    ] as const) {
      const changed = plaintext.slice();
      changed[offset]! ^= mask;
      expect(() => decodeAuditEnvelope(changed, layout), `${offset}`).toThrow(refusedLength);
    }
    const earlierLayout = Uint8Array.of(...plaintext.subarray(0, 33), ...plaintext.subarray(41));
    expect(() => decodeAuditEnvelope(earlierLayout, layout)).toThrow(refusedLength);
  });
});

describe("the input nullifier chain", () => {
  it("hashes the published count and the nullifiers zero filled to the class", () => {
    const [first, second] = [fill(1), fill(2)];
    const zero = fill(0);
    expect(inputNullifierChain([first, second], 4)).toEqual(
      hashChain4([bigIntBytes(2n) as Bytes32, first, second, zero, zero]),
    );
    expect(inputNullifierChain([second, first], 4)).not.toEqual(
      inputNullifierChain([first, second], 4),
    );
    expect(inputNullifierChain([first, second, zero], 4)).not.toEqual(
      inputNullifierChain([first, second], 4),
    );
    expect(() => inputNullifierChain([first, second], 1)).toThrow(
      expect.objectContaining({ code: "RING_INVALID_LENGTH" }),
    );
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
