/** Refuses a relay message that moves more than the request, against the Rust check's vectors. */
import { decompileTransactionMessage, getCompiledTransactionMessageDecoder } from "@solana/kit";
import type { Instruction } from "@heliuslabs/spr/interface";
import { encodeBase58, equalBytes } from "@heliuslabs/spr/internal";
import {
  openOutputSlot,
  openSealedDisclosure,
  sealOutputSlot,
  type RingDisclosure,
} from "../../../src/crypto/audit/ring-disclosure.js";
import { txKeySlotSecret } from "../../../src/crypto/derivation/ring-stream.js";
import { x25519FromU } from "../../../src/crypto/keys/x25519.js";
import { RecordKind, type OutputRecord } from "../../../src/protocol/codec/audit-stream.js";
import {
  PAYLOAD_LENGTH_LEN,
  RECIPIENT_KEY_LEN,
} from "../../../src/protocol/codec/ring-disclosure-layout.js";
import {
  RingTransactData,
  ringRailOf,
  type Replies,
} from "../../../src/protocol/transaction/transact.js";
import { replyLength, sealReply } from "../../../src/protocol/codec/anonymous-delivery.js";
import { ringInstructionData } from "../../helpers/ring-frame.js";
import { compileUnsignedTransaction } from "@heliuslabs/spr/internal";
import { ringComputeUnitLimit } from "../../../src/operations/management/admin.js";
import { SIZE_PROBE_LIFETIME } from "../../../src/operations/workflow/compile.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import { readFileSync } from "node:fs";

import {
  getBase58Encoder,
  getBase64Encoder,
  type Address,
  type TransactionPartialSigner,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import type { Bytes32, Bytes33 } from "@heliuslabs/spr/interface";
import type { indexerTypes } from "@heliuslabs/spr/internal";
import {
  ShieldedAddress,
  ShieldedKeypair,
  ViewingKey,
  X25519PublicKey,
} from "@heliuslabs/spr/keypair";
import { Data } from "@heliuslabs/spr/transaction";

import {
  type AllowedNullifiers,
  checkRelayMessage,
  decodeRelayTransferTerms,
  expectedDelegate,
  expectedEnroll,
  expectedPublicOwner,
  openingHash,
  ZERO_ADDRESS,
  type ExpectedRelayMessage,
  type DelegateRingConfig,
} from "../../../src/rpc/relay-message.js";
import { PendingRelaySignature, type RingRelayClient } from "../../../src/rpc/relay.js";
import type {
  PrepareAuthorityTransferRequest,
  RelayStatus,
} from "../../../src/protocol/ring-rpc/ring-rpc-types.js";

await initializePoseidon();

const base58 = getBase58Encoder();
const base64 = getBase64Encoder();

interface MessageCase {
  readonly name: string;
  readonly message: string;
  readonly verdict: string;
}

interface Vector<R> {
  readonly request: R;
  readonly cases: readonly MessageCase[];
}

interface DelegateRequest {
  readonly auditor: string;
  readonly prepare: {
    readonly ring: Address;
    readonly delegate: Address;
    readonly txViewingKey: string;
    readonly transfer: {
      readonly sources: readonly string[];
      readonly payments: readonly {
        readonly recipient: string;
        readonly mint: Address;
        readonly amount: number;
      }[];
      readonly exits: readonly { recipient: string; mint: Address; amount: number }[];
      readonly withdrawals: readonly {
        recipient: Address;
        mint: Address;
        amount: number;
        tokenProgram?: Address;
      }[];
    };
  };
  readonly feePayer: Address;
}

interface EnrollRequest {
  readonly ringProgramId: Address;
  readonly owner: Address;
  readonly trackingRegistry: Address;
  readonly instructionData: string;
  readonly feePayer: Address;
}

interface OwnerCase extends MessageCase {
  readonly terms: { readonly signer: Address };
  readonly knownNullifiers: readonly string[];
}

function fixture<V>(name: string): V {
  return JSON.parse(
    readFileSync(new URL(`../../../../../test-vectors/rpc/${name}`, import.meta.url), "utf8"),
  ) as V;
}

function vector<R>(name: string): Vector<R> {
  return fixture<Vector<R>>(name);
}

function auditorOf(request: DelegateRequest): X25519PublicKey {
  return X25519PublicKey.fromBytes(new Uint8Array(base64.encode(request.auditor)) as Bytes33);
}

function delegate(
  request: DelegateRequest,
  pinned: Vector<DelegateRequest> = delegates,
): Promise<ExpectedRelayMessage> {
  const shielded = (text: string) => ShieldedAddress.fromBytes(new Uint8Array(base58.encode(text)));
  const { prepare } = request;
  return expectedDelegate({
    request: {
      ring: prepare.ring,
      delegate: prepare.delegate,
      txViewingKey: new Uint8Array(base64.encode(prepare.txViewingKey)),
      transfer: {
        sources: prepare.transfer.sources.map(shielded),
        exits: prepare.transfer.exits.map((exit) => ({
          recipient: shielded(exit.recipient),
          mint: exit.mint,
          amount: BigInt(exit.amount),
        })),
        withdrawals: prepare.transfer.withdrawals.map((withdrawal) => ({
          ...withdrawal,
          amount: BigInt(withdrawal.amount),
        })),
        payments: prepare.transfer.payments.map((payment) => ({
          recipient: shielded(payment.recipient),
          mint: payment.mint,
          amount: BigInt(payment.amount),
        })),
      },
    } as unknown as PrepareAuthorityTransferRequest,
    quote: { feePayer: request.feePayer, validUntilSlot: 0n },
    config: { mode: "confidential", auditorPublicKey: auditorOf(request) },
    allowed: pinnedAllowed(pinned),
  });
}

/** The vector holds no openings, the honest frame's spent notes stand in as in Rust. */
function pinnedAllowed({ request, cases }: Vector<DelegateRequest>): AllowedNullifiers {
  const compiled = getCompiledTransactionMessageDecoder().decode(message(cases, "honest"));
  const { instructions } = decompileTransactionMessage(
    compiled as Parameters<typeof decompileTransactionMessage>[0] & { version: 1 },
  );
  const rail = ringRailOf(RingInstructionTag.authorityTransfer, "confidential");
  const honest = new Set(
    (instructions as readonly Instruction[])
      .map((instruction) => Uint8Array.from(instruction.data ?? []))
      .filter((data) => data[0] === RingInstructionTag.authorityTransfer)
      .flatMap((data) => {
        const frame = RingTransactData.parse(data.subarray(1), rail);
        // The authority rail publishes its notes ahead of the padding.
        const spent = openedStream(request, frame).envelope.realInputs;
        return frame.nullifiers.slice(0, spent).map(encodeBase58);
      }),
  );
  return {
    checkSources: () => undefined,
    countsSpends: (spent: number, published: Iterable<Bytes32>) =>
      [...published].filter((nullifier) => honest.has(encodeBase58(nullifier))).length === spent,
  } as unknown as AllowedNullifiers;
}

function openedStream(request: DelegateRequest, frame: RingTransactData): RingDisclosure {
  return openSealedDisclosure(txViewingSecretOf(request), auditorOf(request), {
    layout: RingTransactData.streamLayout(frame),
    salt: frame.salt,
    message: {
      ephemeralPublicKey: x25519FromU(frame.txViewingU),
      envelope: frame.envelope,
      recipientKeys: frame.outputs.map((_, slot) =>
        frame.recipientKeys.subarray(slot * RECIPIENT_KEY_LEN, (slot + 1) * RECIPIENT_KEY_LEN),
      ),
    },
  });
}

function txViewingSecretOf(request: DelegateRequest): Bytes32 {
  return Uint8Array.from(Buffer.from(request.prepare.txViewingKey, "base64")) as Bytes32;
}

function verdict(
  expected: ExpectedRelayMessage,
  message: string,
  by: Address = expected.kind === "delegate" ? expected.delegate : ("" as Address),
): string {
  try {
    checkRelayMessage(expected, new Uint8Array(base64.encode(message)), by);
    return "Accepted";
  } catch (error) {
    return String((error as { details?: { mismatch?: unknown } }).details?.mismatch);
  }
}

function message(cases: readonly MessageCase[], name: string): Uint8Array {
  const found = cases.find((entry) => entry.name === name);
  if (found === undefined) throw new Error(`no case ${name}`);
  return new Uint8Array(base64.encode(found.message));
}

/** The signature bytes are the relay's to verify, the check runs before any signer. */
function signer(address: Address): TransactionPartialSigner & { calls: number } {
  const fake = {
    address,
    calls: 0,
    signTransactions: async () => {
      fake.calls += 1;
      return [{ [address]: new Uint8Array(64) }];
    },
  };
  return fake as unknown as TransactionPartialSigner & { calls: number };
}

function recording(address: Address): TransactionPartialSigner & { signed: Uint8Array[] } {
  const fake = {
    address,
    signed: [] as Uint8Array[],
    signTransactions: async (transactions: readonly { messageBytes: Uint8Array }[]) => {
      fake.signed.push(...transactions.map(({ messageBytes }) => Uint8Array.from(messageBytes)));
      return [{ [address]: new Uint8Array(64) }];
    },
  };
  return fake as unknown as TransactionPartialSigner & { signed: Uint8Array[] };
}

function overwrite(bytes: Uint8Array): void {
  bytes.forEach((byte, index) => {
    bytes[index] = byte ^ 0xff;
  });
}

function relay(): RingRelayClient & { submitRelay: ReturnType<typeof vi.fn> } {
  return {
    getRelayQuote: vi.fn(),
    prepareRelay: vi.fn(),
    getRelayStatus: vi.fn(),
    submitRelay: vi.fn(async (): Promise<RelayStatus> => ({ status: "awaitingSignature" })),
  } as unknown as RingRelayClient & { submitRelay: ReturnType<typeof vi.fn> };
}

const RELAY_ID = "11111111111111111111111111111111" as indexerTypes.Hash;
const delegates = vector<DelegateRequest>("relay_delegate_messages.json");
const settlements = vector<DelegateRequest>("relay_delegate_settlement_messages.json");
const DELEGATE = delegates.request.prepare.delegate;
const owners = fixture<{ readonly cases: readonly OwnerCase[] }>("relay_transfer_messages.json");
const enrolls = vector<EnrollRequest>("relay_enroll_messages.json");

describe("relay message check", () => {
  it.each(delegates.cases)("reaches the Rust verdict on delegate message $name", async (entry) => {
    expect(verdict(await delegate(delegates.request), entry.message)).toBe(entry.verdict);
  });

  it.each(settlements.cases)("binds every hosted settlement field for $name", async (entry) => {
    expect(verdict(await delegate(settlements.request, settlements), entry.message)).toBe(
      entry.verdict,
    );
  });

  it.each(owners.cases)("reaches the Rust verdict on owner message $name", async (entry) => {
    const expected = await expectedPublicOwner({
      terms: decodeRelayTransferTerms(JSON.stringify(entry.terms)),
      config: { mode: "anonymous" } as DelegateRingConfig,
      knownNotes: entry.knownNullifiers.map((nullifier) => ({
        nullifier: new Uint8Array(base58.encode(nullifier)) as Bytes32,
      })),
    });
    expect(verdict(expected, entry.message, entry.terms.signer)).toBe(entry.verdict);
  });

  it.each(enrolls.cases)("reaches the Rust verdict on enroll message $name", async (entry) => {
    const { feePayer, instructionData, ...named } = enrolls.request;
    const expected = await expectedEnroll(
      { ...named, instructionData: new Uint8Array(base64.encode(instructionData)) },
      feePayer,
    );
    expect(verdict(expected, entry.message)).toBe(entry.verdict);
  });

  it("refuses a delegate message with a swapped recipient before signing", async () => {
    const expected = await delegate(delegates.request);
    const delegateSigner = signer(delegates.request.prepare.delegate);
    const ringRpc = relay();
    const pending = new PendingRelaySignature(
      RELAY_ID,
      message(delegates.cases, "swappedRecipient"),
      expected,
    );
    await expect(pending.sign(ringRpc, delegateSigner)).rejects.toMatchObject({
      details: { mismatch: "Recipients" },
    });
    expect(delegateSigner.calls).toBe(0);
  });

  describe("the records a delegate frame proves", () => {
    const honestInstruction = (): Instruction => {
      const compiled = getCompiledTransactionMessageDecoder().decode(
        message(delegates.cases, "honest"),
      );
      const [instruction] = decompileTransactionMessage(
        compiled as Parameters<typeof decompileTransactionMessage>[0] & { version: 1 },
      ).instructions;
      if (instruction === undefined) throw new Error("no instruction");
      return instruction as Instruction;
    };
    const honestFrame = (): RingTransactData =>
      RingTransactData.parse(
        Uint8Array.from(honestInstruction().data ?? []).subarray(1),
        "delegate",
      );
    const verdictOf = async (frame: RingTransactData): Promise<string> => {
      const { messageBytes } = compileUnsignedTransaction({
        feePayer: delegates.request.feePayer,
        lifetime: SIZE_PROBE_LIFETIME,
        instructions: [{ ...honestInstruction(), data: ringInstructionData(frame) }],
        computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.authorityTransfer),
      });
      return verdict(
        await delegate(delegates.request),
        Buffer.from(new Uint8Array(messageBytes)).toString("base64"),
      );
    };
    /** Reseals the payment's record to its slot key under the frame's own transaction key. */
    const rewritten = (change: (record: OutputRecord) => OutputRecord): RingTransactData => {
      const frame = honestFrame();
      const txViewingSecret = txViewingSecretOf(delegates.request);
      const { recipientKeys } = openedStream(delegates.request, frame);
      const payee = new Uint8Array(
        base58.encode(delegates.request.prepare.transfer.payments[0]!.recipient),
      );
      const paid = ShieldedAddress.fromBytes(payee).signingPublicKey.confidentialViewTag();
      const txKey = ViewingKey.fromBytes(txViewingSecret);
      const outputs = frame.outputs.map((output, slot) => {
        const secret = txKeySlotSecret({
          txViewingKey: txKey,
          recipientViewingKey: x25519FromU(recipientKeys[slot] as Bytes32),
          salt: frame.salt,
          outputIndex: slot,
          firstNullifier: RingTransactData.firstNullifier(frame),
        });
        const { record } = openOutputSlot(secret, output.record);
        return equalBytes(record.ownerKey, paid)
          ? { ...output, record: sealOutputSlot(secret, { record: change(record) }) }
          : output;
      });
      txKey.destroy();
      return { ...frame, outputs };
    };

    it("passes the honest frame rebuilt from its parts", async () => {
      expect(await verdictOf(rewritten((record) => record))).toBe("Accepted");
    });

    it("refuses a frame under another transaction key and a key off its clamp", async () => {
      for (const key of [new Uint8Array(32).fill(0x48), new Uint8Array(32).fill(0xff)]) {
        const expected = await delegate({
          ...delegates.request,
          prepare: {
            ...delegates.request.prepare,
            txViewingKey: Buffer.from(key).toString("base64"),
          },
        });
        expect(
          verdict(expected, Buffer.from(message(delegates.cases, "honest")).toString("base64")),
        ).toBe("TransactionKey");
      }
    });

    it("refuses a record of another mint", async () => {
      const mint = encodeBase58(new Uint8Array(32).fill(9));
      expect(await verdictOf(rewritten((record) => ({ ...record, mint })))).toBe("Recipients");
    });

    it("refuses an exit in place of a payment", async () => {
      expect(await verdictOf(rewritten((record) => ({ ...record, kind: RecordKind.exit })))).toBe(
        "Recipients",
      );
    });

    it("refuses an interface transfer the request does not name", async () => {
      const leg = {
        kind: "solWithdrawal" as const,
        amount: 1n,
      };
      expect(await verdictOf({ ...honestFrame(), interfaceTransfers: [leg] })).toBe("Data");
    });

    it("refuses a data commitment the request does not name", async () => {
      const frame = honestFrame();
      expect(
        await verdictOf({
          ...frame,
          hasData: true,
          outputs: frame.outputs.map((output) =>
            output.body.kind === "recipient"
              ? {
                  ...output,
                  body: { kind: "recipient" as const, payload: new Uint8Array(PAYLOAD_LENGTH_LEN) },
                }
              : output,
          ),
        }),
      ).toBe("Data");
    });
  });

  describe("the slots a public owner opens before it signs", async () => {
    const entry = owners.cases.find((owner) => owner.verdict === "Accepted");
    if (entry === undefined) throw new Error("no accepted owner case");
    const terms = decodeRelayTransferTerms(JSON.stringify(entry.terms));
    const [first] = terms.slots;
    if (first === undefined) throw new Error("no opening");
    const dataOpening = { ...first, dataHash: new Uint8Array(32).fill(9) as Bytes32 };
    const instruction = (): Instruction => {
      const compiled = getCompiledTransactionMessageDecoder().decode(
        new Uint8Array(base64.encode(entry.message)),
      );
      const found = decompileTransactionMessage(
        compiled as Parameters<typeof decompileTransactionMessage>[0] & { version: 1 },
      ).instructions.at(-1);
      if (found === undefined) throw new Error("no instruction");
      return found as Instruction;
    };
    /** The frame's commitments rebuilt from `published`, the terms naming `named`. */
    const verdictWith = async (
      named: typeof terms,
      published: readonly (typeof first)[] = [dataOpening],
      replies?: Replies,
    ): Promise<string> => {
      const frame = RingTransactData.parse(
        Uint8Array.from(instruction().data ?? []).subarray(1),
        "anonymous",
      );
      const { messageBytes } = compileUnsignedTransaction({
        feePayer: terms.feePayer,
        lifetime: SIZE_PROBE_LIFETIME,
        instructions: [
          {
            ...instruction(),
            data: ringInstructionData({
              ...frame,
              ...(replies === undefined ? {} : { replies }),
              outputs: frame.outputs.map((output, slot) => {
                const opening = published.find((open) => open.slot === slot);
                return opening === undefined
                  ? output
                  : { ...output, hash: openingHash(opening, terms.ring) };
              }),
            }),
          },
        ],
        computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.transfer),
      });
      return verdict(
        await expectedPublicOwner({
          terms: named,
          config: { mode: "anonymous" } as DelegateRingConfig,
          knownNotes: entry.knownNullifiers.map((nullifier) => ({
            nullifier: new Uint8Array(base58.encode(nullifier)) as Bytes32,
          })),
        }),
        Buffer.from(new Uint8Array(messageBytes)).toString("base64"),
        terms.signer,
      );
    };
    const opened = { ...terms, slots: [dataOpening, ...terms.slots.slice(1)] };
    const ordinary = { ...terms, slots: [first, ...terms.slots.slice(1)] };

    it("passes one opening per published slot in slot order", async () => {
      expect(terms.slots.map((opening) => opening.slot)).toEqual(
        terms.slots.map((_, slot) => slot),
      );
      expect(await verdictWith(opened)).toBe("Accepted");
    });

    it("moves no verdict on a reply that claims another sender", async () => {
      const frame = RingTransactData.parse(
        Uint8Array.from(instruction().data ?? []).subarray(1),
        "anonymous",
      );
      const thief = ShieldedKeypair.generate().shieldedAddress();
      const forged = {
        viewingKey: thief.viewingPublicKey,
        ownerKey: thief.signingPublicKey.ed25519(),
        nullifierPk: thief.nullifierPublicKey,
        data: new Data(),
      };
      const length = replyLength([forged]);
      const bodies = frame.outputs.filter((output) => output.body.kind === "recipient");
      const replies = {
        length,
        region: Uint8Array.from(
          bodies.flatMap(() => [
            ...sealReply(new Uint8Array(32).fill(7) as Bytes32, forged, length),
          ]),
        ),
      };
      const carried = RingTransactData.parse(
        ringInstructionData({ ...frame, replies }).subarray(1),
        "anonymous",
      );
      expect(bodies.length).toBeGreaterThan(0);
      expect(carried.replies?.region).toEqual(replies.region);
      expect(await verdictWith(opened, [dataOpening], replies)).toBe("Accepted");
      expect(await verdictWith(ordinary, [dataOpening], replies)).toBe("Recipients");
    });

    it("refuses terms that leave a published slot unopened", async () => {
      expect(await verdictWith({ ...opened, slots: opened.slots.slice(1) })).toBe("UnopenedOutput");
      expect(await verdictWith({ ...opened, slots: opened.slots.slice(0, -1) })).toBe(
        "UnopenedOutput",
      );
    });

    it("refuses a repeated opening and openings out of slot order", async () => {
      expect(await verdictWith({ ...opened, slots: [dataOpening, ...opened.slots] })).toBe(
        "UnopenedOutput",
      );
      if (opened.slots.length > 1)
        expect(await verdictWith({ ...opened, slots: opened.slots.toReversed() })).toBe(
          "UnopenedOutput",
        );
    });

    it("refuses an ordinary output standing in for a data output", async () => {
      expect(await verdictWith(ordinary)).toBe("Recipients");
    });

    it("refuses a dummy opening that carries a value", async () => {
      const dummy = {
        ...first,
        owner: ZERO_ADDRESS,
        mint: ZERO_ADDRESS,
        nullifierPk: new Uint8Array(32) as Bytes32,
        dataHash: new Uint8Array(32) as Bytes32,
        ringDataHash: new Uint8Array(32) as Bytes32,
        amount: 0n,
      };
      expect(
        await verdictWith({ ...terms, slots: [dummy, ...terms.slots.slice(1)] }, [dummy]),
      ).toBe("Accepted");
      const valued = { ...dummy, amount: 1n };
      expect(
        await verdictWith({ ...terms, slots: [valued, ...terms.slots.slice(1)] }, [dummy]),
      ).toBe("Recipients");
    });
  });

  it("signs the checked inline and enroll bytes after the caller overwrites its array", async () => {
    const { feePayer, instructionData, ...named } = enrolls.request;
    const enroll = await expectedEnroll(
      { ...named, instructionData: new Uint8Array(base64.encode(instructionData)) },
      feePayer,
    );
    for (const [expected, cases, address] of [
      [await delegate(delegates.request), delegates.cases, DELEGATE],
      [enroll, enrolls.cases, enrolls.request.owner],
    ] as const) {
      const caller = message(cases, "honest");
      const checked = caller.slice();
      const verified = checkRelayMessage(expected, caller, address);
      overwrite(caller);
      const recorder = recording(address);
      await verified.sign(recorder);
      expect(recorder.signed).toEqual([checked]);
    }
  });

  it("signs the honest messages the relay builds", async () => {
    for (const [expected, cases, address] of [
      [await delegate(delegates.request), delegates.cases, delegates.request.prepare.delegate],
    ] as const) {
      const ringRpc = relay();
      await new PendingRelaySignature(RELAY_ID, message(cases, "honest"), expected).sign(
        ringRpc,
        signer(address),
      );
      expect(ringRpc.submitRelay).toHaveBeenCalledWith(
        expect.objectContaining({ relayId: RELAY_ID, signer: address }),
        undefined,
      );
    }
  });
});
