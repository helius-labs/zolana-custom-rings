import { describe, expect, it } from "vitest";

import { MAX_CACHE_WRITES } from "@heliuslabs/spr/interface";
import type { Bytes32, Bytes33 } from "@heliuslabs/spr/interface";
import { hashBytes, hashChain4 } from "@heliuslabs/spr/internal";

import { CUSTOM_RING_PROOF_LENGTH } from "../../../src/protocol/proof/custom-ring-proof.js";
import { encodeRingTransactInstructionData } from "../../../src/protocol/proof/circuit.js";
import { field, ringFrame, ringInstructionData } from "../../helpers/ring-frame.js";
import { RingError } from "../../../src/protocol/error.js";
import {
  envelopeDigest,
  ringTransferStatement,
  signerBinding,
  transferStatementElements,
  transferStatementHash,
  type TransferBinding,
} from "../../../src/protocol/proof/statement.js";
import {
  OUTPUT_RECORD_LEN,
  RECIPIENT_KEY_LEN,
} from "../../../src/protocol/codec/ring-disclosure-layout.js";
import {
  CONFIDENTIAL_DATA_FREE_BODY_LEN,
  encodeRingBodyOutput,
  ringBodyOutput,
  RingScheme,
  readRingOutput,
} from "../../../src/protocol/transaction/output.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import {
  ANONYMOUS_PARTIES,
  ApprovalMask,
  landedRingRail,
  maxApplicationMessages,
  RingTransactData,
  ringRailOf,
  ringTransactOutput,
  type RingTransactData as Frame,
} from "../../../src/protocol/transaction/transact.js";

const ZERO = new Uint8Array(32) as Bytes32;
const AUDITOR = Uint8Array.of(4, ...new Uint8Array(31), 9) as Bytes33;

function binding(signers: readonly Bytes32[] = [], slots = 24): TransferBinding {
  return {
    ringId: field(21),
    auditorPubkey: AUDITOR,
    sender: field(22),
    partyIdentities: Array.from({ length: ANONYMOUS_PARTIES }, () => ZERO),
    signers: signerBinding(signers, slots),
    roots: {
      policyHash: field(23),
      ownRoot: field(24),
      curatorRoot: field(25),
      trackingRoot: field(26),
    },
    publicAssets: [ZERO, ZERO, ZERO],
    publicAmounts: [ZERO, ZERO, ZERO],
    publicGross: [ZERO, ZERO, ZERO],
    withdrawalHash: ZERO,
  };
}

/** The first offset of `needle` in `haystack`, -1 when absent. */
function indexOf(haystack: Uint8Array, needle: Uint8Array): number {
  for (let at = 0; at + needle.length <= haystack.length; at += 1)
    if (needle.every((byte, offset) => haystack[at + offset] === byte)) return at;
  return -1;
}

function reason(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    if (error instanceof RingError) return error.details?.["reason"];
    throw error;
  }
  throw new Error("expected a refusal");
}

const roundTrips: readonly Readonly<{ name: string; frame: Frame }>[] = [
  { name: "confidential", frame: ringFrame({ rail: "confidential", inputs: 2, outputs: 4 }) },
  { name: "anonymous", frame: ringFrame({ rail: "anonymous", inputs: 2, outputs: 4 }) },
  { name: "delegate", frame: ringFrame({ rail: "delegate", inputs: 2, outputs: 2 }) },
  {
    name: "anonymous delegate",
    frame: ringFrame({ rail: "anonymousDelegate", inputs: 2, outputs: 2 }),
  },
  {
    name: "public owners",
    frame: ringFrame({ rail: "anonymous", inputs: 2, outputs: 2, publicOwners: true }),
  },
  {
    name: "entry with data and wide owners",
    frame: ringFrame({
      rail: "confidential",
      inputs: 2,
      outputs: 2,
      entry: true,
      hasData: true,
      wideOwners: true,
    }),
  },
];

describe("the ring frame", () => {
  it.each(roundTrips)("$name round trips", ({ frame }) => {
    const bytes = RingTransactData.encode(frame);
    expect(RingTransactData.parse(bytes, frame.rail)).toEqual(frame);
  });

  it("puts the wide owner flag at bit 7 of the output count and the approval mask past the header", () => {
    const frame: Frame = {
      ...ringFrame({ rail: "confidential", inputs: 1, outputs: 2, wideOwners: true }),
      approval: ApprovalMask.outflow | ApprovalMask.withdrawal,
    };
    const bytes = RingTransactData.encode(frame);
    expect(bytes[3]).toBe(2 | (1 << 7));
    expect(bytes[4]).toBe(3);
    expect(RingTransactData.parse(bytes, "confidential").approval).toBe(frame.approval);
  });

  it("refuses an approval mask past its two bits", () => {
    const frame = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    for (const approval of [4, -1, 1.5])
      expect(reason(() => RingTransactData.encode({ ...frame, approval }))).toBe("FlagNotAllowed");
    const bytes = RingTransactData.encode(frame);
    for (const mask of [1 << 2, 6 << 2, 1 << 5, 1 << 7]) {
      bytes[4] = mask;
      expect(reason(() => RingTransactData.parse(bytes, "confidential"))).toBe("FlagNotAllowed");
    }
  });

  it("publishes a live slot's tag in eight bytes, an exit's whole, and refuses leading tag bytes", () => {
    const frame = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    const whole = new Uint8Array(32).fill(7) as Bytes32;
    const tagged = (output: Frame["outputs"][number]) => ({ ...output, ownerTag: whole });
    expect(
      reason(() => RingTransactData.encode({ ...frame, outputs: frame.outputs.map(tagged) })),
    ).toBe("RingTransactLength");
    const exit: Frame = {
      ...frame,
      outputs: frame.outputs.map((output, slot) =>
        slot === 1
          ? {
              ...tagged(output),
              body: {
                kind: "exit" as const,
                payload: new Uint8Array(CONFIDENTIAL_DATA_FREE_BODY_LEN),
              },
            }
          : output,
      ),
    };
    const bytes = RingTransactData.encode(exit);
    expect(RingTransactData.parse(bytes, "confidential")).toEqual(exit);
    expect(bytes.length).toBe(
      RingTransactData.encode(frame).length + 32 - 8 + CONFIDENTIAL_DATA_FREE_BODY_LEN,
    );
  });

  it("refuses an appended byte and a truncation", () => {
    const bytes = RingTransactData.encode(
      ringFrame({ rail: "confidential", inputs: 1, outputs: 2 }),
    );
    for (const refused of [Uint8Array.of(...bytes, 0), bytes.subarray(0, bytes.length - 1)])
      expect(reason(() => RingTransactData.parse(refused, "confidential"))).toBe(
        "RingTransactLength",
      );
  });

  it("refuses a payload without has_data and payloads of two lengths under it", () => {
    const plain = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    const payload = { kind: "recipient" as const, payload: new Uint8Array(2) };
    expect(
      reason(() =>
        RingTransactData.encode({
          ...plain,
          outputs: plain.outputs.map((output) => ({ ...output, body: payload })),
        }),
      ),
    ).toBe("RingTransactLength");
    const data = ringFrame({ rail: "confidential", inputs: 1, outputs: 2, hasData: true });
    const carried = {
      ...data,
      outputs: data.outputs.map((output) => ({
        ...output,
        body: { kind: "recipient" as const, payload: new Uint8Array(40).fill(4) },
      })),
    };
    expect(RingTransactData.parse(RingTransactData.encode(carried), "confidential")).toEqual(
      carried,
    );
    const uneven = {
      ...carried,
      outputs: carried.outputs.map((output, slot) =>
        slot === 1
          ? { ...output, body: { kind: "recipient" as const, payload: new Uint8Array(41) } }
          : output,
      ),
    };
    expect(reason(() => RingTransactData.encode(uneven))).toBe("OutputBodyLength");
    const short = {
      ...carried,
      outputs: carried.outputs.map((output) => ({
        ...output,
        body: { kind: "recipient" as const, payload: new Uint8Array(1) },
      })),
    };
    expect(reason(() => RingTransactData.encode(short))).toBe("OutputBodyLength");
    // A parsed frame of two lengths under has_data refuses alike.
    const bytes = RingTransactData.encode(carried);
    const at = indexOf(bytes, carried.outputs[1]!.hash) - 2;
    bytes[at] = 39;
    expect(() => RingTransactData.parse(bytes, "confidential")).toThrow(RingError);
  });

  it("carries one 137 byte record per slot and 32 bytes per recipient key", () => {
    const frame = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    const shortRecord = {
      ...frame,
      outputs: frame.outputs.map((output) => ({ ...output, record: new Uint8Array(105) })),
    };
    expect(reason(() => RingTransactData.encode(shortRecord))).toBe("RingTransactLength");
    for (const length of [RECIPIENT_KEY_LEN, 3 * RECIPIENT_KEY_LEN, 2 * RECIPIENT_KEY_LEN + 1])
      expect(
        reason(() => RingTransactData.encode({ ...frame, recipientKeys: new Uint8Array(length) })),
      ).toBe("RingTransactLength");
    const bytes = RingTransactData.encode(frame);
    expect(indexOf(bytes, frame.outputs[0]!.record)).toBeGreaterThan(0);
    expect(frame.outputs[0]!.record).toHaveLength(OUTPUT_RECORD_LEN);
  });

  it("refuses flags the rail forbids", () => {
    const anonymous = ringFrame({ rail: "anonymous", inputs: 1, outputs: 2 });
    expect(reason(() => RingTransactData.encode({ ...anonymous, rail: "confidential" }))).toBe(
      "RingTransactLength",
    );
    const delegate = ringFrame({ rail: "delegate", inputs: 2, outputs: 2 });
    expect(reason(() => RingTransactData.encode({ ...delegate, entry: true }))).toBe(
      "FlagNotAllowed",
    );
    expect(reason(() => RingTransactData.encode({ ...delegate, ownRevision: 1n }))).toBe(
      "FlagNotAllowed",
    );
    expect(reason(() => RingTransactData.encode({ ...delegate, publicOwners: true }))).toBe(
      "FlagNotAllowed",
    );
    expect(
      reason(() =>
        RingTransactData.encode({
          ...delegate,
          extensions: {
            cache: {
              readBitmap: 0n,
              writeSlots: Array.from({ length: 16 }, () => ({ output: 0xff, slot: 0xff })),
            },
          },
        }),
      ),
    ).toBe("FlagNotAllowed");
  });

  it("refuses an application message count past SPP's list on each rail, writing and reading", () => {
    for (const rail of ["confidential", "anonymous"] as const) {
      const limit = maxApplicationMessages(rail);
      expect(limit).toBe(rail === "anonymous" ? 253 : 254);
      const message = { viewTag: field(84), data: new Uint8Array() };
      const base = ringFrame({ rail, inputs: 1, outputs: 2 });
      expect(
        reason(() =>
          RingTransactData.encode({
            ...base,
            extensions: { messages: Array.from({ length: limit + 1 }, () => message) },
          }),
        ),
      ).toBe("TooManyApplicationMessages");
      const bytes = RingTransactData.encode({ ...base, extensions: { messages: [message] } });
      const count = indexOf(bytes, message.viewTag) - 1;
      expect(bytes[count]).toBe(1);
      const patched = bytes.slice();
      patched[count] = limit + 1;
      expect(reason(() => RingTransactData.parse(patched, rail))).toBe(
        "TooManyApplicationMessages",
      );
    }
  });

  it("carries the extensions and forwards the application message ahead of the auditor's", () => {
    const frame: Frame = {
      ...ringFrame({ rail: "confidential", inputs: 1, outputs: 2 }),
      extensions: {
        dataHash: field(81),
        ringDataHash: field(82),
        messages: [{ viewTag: field(83), data: Uint8Array.of(1, 2, 3) }],
        cache: {
          readBitmap: 0n,
          writeSlots: Array.from({ length: MAX_CACHE_WRITES }, () => ({
            output: 0xff,
            slot: 0xff,
          })),
        },
      },
    };
    const bytes = RingTransactData.encode(frame);
    expect(RingTransactData.parse(bytes, "confidential")).toEqual(frame);
    // The extension byte follows the salt, bits 5 and 6 carried the retired counts and payout.
    const extensions = 4 + 1 + CUSTOM_RING_PROOF_LENGTH + 8 + 8 + 4 + 32 + 16;
    expect(bytes[extensions]).toBe(1 | 2 | 4 | 8);
    for (const retired of [1 << 5, 1 << 6, 1 << 7]) {
      const flagged = bytes.slice();
      flagged[extensions] = 1 | 2 | 4 | 8 | retired;
      expect(reason(() => RingTransactData.parse(flagged, "confidential"))).toBe("FlagNotAllowed");
    }
    const { messages } = RingTransactData.expand(frame, { auditorPubkey: AUDITOR });
    expect(messages.map((message) => message.viewTag)).toEqual([field(83), AUDITOR.slice(1)]);
  });

  it("gives every non-exit slot a reply and frames each under ring body", () => {
    const frame = ringFrame({ rail: "anonymous", inputs: 1, outputs: 2 });
    const reply = new Uint8Array(2 * 97).fill(9);
    const withReply: Frame = { ...frame, replies: { length: 97, region: reply } };
    expect(RingTransactData.slotReplies(withReply).map((bytes) => bytes.length)).toEqual([97, 97]);
    expect(
      reason(() =>
        RingTransactData.encode({ ...frame, replies: { length: 97, region: reply.subarray(97) } }),
      ),
    ).toBe("ReplyLength");
    expect(RingTransactData.parse(RingTransactData.encode(withReply), "anonymous")).toEqual(
      withReply,
    );
  });

  it("selects SPP's confidential rail for public owners and the exit circuit for a delegate exit", () => {
    const owners = ringFrame({ rail: "anonymous", inputs: 2, outputs: 2, publicOwners: true });
    expect(RingTransactData.circuit(owners).kind).toBe("confidentialRingEddsa");
    const delegate = ringFrame({ rail: "delegate", inputs: 2, outputs: 2 });
    expect(RingTransactData.circuit(delegate).kind).toBe("ringAuthority");
    const exit: Frame = {
      ...delegate,
      outputs: delegate.outputs.map((output, slot) =>
        slot === 1
          ? { ...output, body: { kind: "exit" as const, payload: new Uint8Array(83) } }
          : output,
      ),
    };
    expect(RingTransactData.circuit(exit).kind).toBe("ringAuthorityExit");
  });

  it("encodes the exit selector as Rust `CircuitId::RingAuthorityExit`", () => {
    const transact = {
      expiryUnixTs: 0n,
      txViewingPk: new Uint8Array(33) as Bytes33,
      salt: new Uint8Array(16),
      interfaceTransfers: [],
      outputs: [],
      messages: [],
      privateTxHash: new Uint8Array(32) as Bytes32,
      proof: { a: new Uint8Array(32), b: new Uint8Array(128), c: new Uint8Array(32) },
      inputs: [],
      treeContexts: [],
    };
    const shape = { inputs: 2, outputs: 2, publicAssetSlots: 3 };
    const authority = encodeRingTransactInstructionData({
      ...transact,
      circuit: { kind: "ringAuthority", ...shape },
    } as never);
    const exit = encodeRingTransactInstructionData({
      ...transact,
      circuit: { kind: "ringAuthorityExit", ...shape },
    } as never);
    const at = authority.findIndex((byte, index) => byte !== exit[index]);
    expect([authority[at], authority[at + 1], exit[at], exit[at + 1]]).toEqual([2, 0, 9, 0]);
    expect(exit.slice(at + 2)).toEqual(authority.slice(at + 2));
  });

  it("names the rail from the tag and refuses an unknown tag", () => {
    expect(RingInstructionTag.transfer).toBe(55);
    expect(RingInstructionTag.authorityTransfer).toBe(56);
    expect(RingInstructionTag.merge).toBe(57);
    expect(ringRailOf(55, "anonymous")).toBe("anonymous");
    expect(ringRailOf(56, "anonymous")).toBe("anonymousDelegate");
    expect(ringRailOf(56, "confidential")).toBe("delegate");
    expect(reason(() => ringRailOf(45, "confidential"))).toBe("InvalidInstructionData");
  });

  it.each(roundTrips)("reads the $name rail back from the landed instruction", ({ frame }) => {
    const instruction = ringInstructionData(frame);
    const sppAnonymous = frame.rail === "anonymous" && !frame.publicOwners;
    expect(landedRingRail(instruction, sppAnonymous)).toBe(frame.rail);
  });
});

describe("the transfer statement", () => {
  const STATEMENT_LENGTH = 43;

  it("orders the confidential elements and closes on the length", () => {
    const frame: Frame = {
      ...ringFrame({ rail: "confidential", inputs: 2, outputs: 2 }),
      approval: ApprovalMask.outflow | ApprovalMask.withdrawal,
      noSpend: true,
    };
    const elements = transferStatementElements(ringTransferStatement(frame, binding([field(31)])));
    expect(elements).toHaveLength(STATEMENT_LENGTH);
    const bigint = (bytes: Bytes32 | undefined): bigint =>
      bytes === undefined ? -1n : BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
    expect(elements[7]).toEqual(envelopeDigest(frame.envelope, frame.recipientKeys));
    expect(bigint(elements[13])).toBe(3n);
    expect(bigint(elements[14])).toBe(0n);
    expect(bigint(elements[15])).toBe(1n);
    expect(bigint(elements[16])).toBe(2n);
    expect(elements[17]).toEqual(
      hashChain4(frame.outputs.map((output) => hashBytes(output.record) as Bytes32)) as Bytes32,
    );
    expect(bigint(elements[18])).toBe(2n);
    expect(elements[19]).toEqual(frame.privateTxHash);
    expect(bigint(elements[26])).toBe(1n);
    expect(bigint(elements.at(-1))).toBe(BigInt(elements.length));
    const disclosed: Frame = { ...frame, extensions: { approvalTotals: field(88) } };
    expect(
      transferStatementElements(ringTransferStatement(disclosed, binding([field(31)])))[14],
    ).toEqual(field(88));
  });

  it("zero fills the record chain to the capacity and binds the keys through the envelope digest", () => {
    const frame = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    const base = transferStatementHash(ringTransferStatement(frame, binding()));
    const keys = frame.recipientKeys.slice();
    keys[0] = (keys[0] ?? 0) ^ 1;
    expect(
      transferStatementHash(ringTransferStatement({ ...frame, recipientKeys: keys }, binding())),
    ).not.toEqual(base);
    const record = frame.outputs.map((output, slot) =>
      slot === 0 ? { ...output, record: new Uint8Array(OUTPUT_RECORD_LEN) } : output,
    );
    expect(
      transferStatementHash(ringTransferStatement({ ...frame, outputs: record }, binding())),
    ).not.toEqual(base);
    // The proof binds the outputs through `private_tx_hash` alone, a hash moves no element.
    const hashes = frame.outputs.map((output) => ({ ...output, hash: field(99) }));
    expect(
      transferStatementHash(ringTransferStatement({ ...frame, outputs: hashes }, binding())),
    ).toEqual(base);
  });

  it("carries five co-signer cells and both rail bits on the anonymous frame", () => {
    const frame = ringFrame({ rail: "anonymous", inputs: 1, outputs: 2, publicOwners: true });
    const statement = ringTransferStatement(frame, binding());
    expect(statement.family).toMatchObject({
      kind: "anonymous",
      publicOwners: true,
      delegate: false,
    });
    expect(transferStatementElements(statement)).toHaveLength(STATEMENT_LENGTH);
    expect(ANONYMOUS_PARTIES).toBe(5);
    const delegate = ringFrame({ rail: "anonymousDelegate", inputs: 2, outputs: 2 });
    expect(ringTransferStatement(delegate, binding()).family).toMatchObject({ delegate: true });
  });

  it("hashes apart on any bound field", () => {
    const frame = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    const base = transferStatementHash(ringTransferStatement(frame, binding()));
    const moved = {
      ...binding(),
      roots: { ...binding().roots, trackingRoot: field(99) },
    };
    expect(transferStatementHash(ringTransferStatement(frame, moved))).not.toEqual(base);
    expect(
      transferStatementHash(
        ringTransferStatement({ ...frame, approval: ApprovalMask.outflow }, binding()),
      ),
    ).not.toEqual(base);
  });

  it("dedups the signer run by first occurrence and refuses one past the slots", () => {
    expect(signerBinding([field(1), field(1), field(2)], 4).count).toBe(2);
    expect(signerBinding([], 4).chain).toEqual(ZERO);
    expect(() => signerBinding([field(1), field(2)], 1)).toThrow(RingError);
  });
});

describe("ring body", () => {
  const slot = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 }).outputs[1];

  it("frames record, payload then reply and reads them back", () => {
    if (slot === undefined) throw new Error("a slot");
    const record = new Uint8Array(OUTPUT_RECORD_LEN).fill(5);
    const payload = new Uint8Array(4).fill(6);
    const reply = new Uint8Array(97).fill(9);
    const { data } = ringTransactOutput(
      { ...slot, record, body: { kind: "recipient", payload } },
      reply,
    );
    if (data === undefined) throw new Error("a framed body");
    expect(readRingOutput(data).scheme).toBe(RingScheme.ringBody);
    expect(ringBodyOutput(data)).toEqual({ body: Uint8Array.of(...record, ...payload), reply });
  });

  it("refuses a length past the payload and below a record", () => {
    expect(ringBodyOutput(new Uint8Array())).toBeUndefined();
    const short = encodeRingBodyOutput(new Uint8Array(OUTPUT_RECORD_LEN - 1), new Uint8Array());
    expect(ringBodyOutput(short)).toBeUndefined();
    const framed = encodeRingBodyOutput(new Uint8Array(OUTPUT_RECORD_LEN), new Uint8Array());
    const past = framed.slice();
    past[6] = OUTPUT_RECORD_LEN + 1;
    expect(ringBodyOutput(past)).toBeUndefined();
  });

  it("keeps an exit under scheme 3 and its record out of SPP's data", () => {
    if (slot === undefined) throw new Error("a slot");
    const payload = new Uint8Array(83).fill(2);
    const exit = ringTransactOutput({ ...slot, body: { kind: "exit", payload } }).data;
    if (exit === undefined) throw new Error("a framed exit");
    expect(readRingOutput(exit).scheme).toBe(RingScheme.confidential);
    expect(readRingOutput(exit).body).toEqual(payload);
  });

  it("puts each exit's record in the auditor message after the keys", () => {
    const frame = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    const exit: Frame = {
      ...frame,
      outputs: frame.outputs.map((output, index) =>
        index === 1
          ? {
              ...output,
              ownerTag: field(7),
              body: {
                kind: "exit" as const,
                payload: new Uint8Array(CONFIDENTIAL_DATA_FREE_BODY_LEN),
              },
            }
          : output,
      ),
    };
    const message = RingTransactData.auditorMessage(exit);
    expect(message).toHaveLength(33 + frame.envelope.length + 64 + OUTPUT_RECORD_LEN);
    expect(message.subarray(message.length - OUTPUT_RECORD_LEN)).toEqual(exit.outputs[1]!.record);
    expect(RingTransactData.auditorMessage(frame)).toHaveLength(33 + frame.envelope.length + 64);
  });
});
