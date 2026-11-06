import { readFileSync } from "node:fs";

import { initializePoseidon } from "@heliuslabs/spr";
import { getCreateAssociatedTokenAccountInstructionAsync } from "@heliuslabs/spr/instructions";
import type { Bytes32, Instruction } from "@heliuslabs/spr/interface";
import { compileUnsignedTransaction, type indexerTypes } from "@heliuslabs/spr/internal";
import { ShieldedKeypair, SigningKey } from "@heliuslabs/spr/keypair";
import {
  AssetRegistry,
  SOL_MINT,
  type ProofInputUtxo,
  type WalletUtxo,
} from "@heliuslabs/spr/transaction";
import {
  AccountRole,
  getBase64Decoder,
  getBase64Encoder,
  type Address,
  type TransactionPartialSigner,
} from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { RingAddress } from "../../../src/crypto/keys/ring-address.js";
import { ringComputeUnitLimit } from "../../../src/operations/management/admin.js";
import {
  signingKeySpendSigner,
  type AnonymousPayment,
} from "../../../src/operations/payments/anonymous.js";
import { ringSpendTransfer } from "../../../src/operations/payments/ring-spend.js";
import {
  CustomRingTransfer,
  type AnonymousTransfer,
  type PreparedRingRelay,
} from "../../../src/operations/payments/transfer-rails.js";
import { publishedOutputs } from "../../../src/operations/payments/output-rail.js";
import { SIZE_PROBE_LIFETIME } from "../../../src/operations/workflow/compile.js";
import {
  sealedTransferTerms,
  type SealedTransfer,
} from "../../../src/operations/workflow/pipeline.js";
import { RING_COSIGN_TRANSFERS } from "../../../src/protocol/codec/ring-codecs.js";
import {
  decodeRelayProofInputs,
  encodeRelayProofInputs,
} from "../../../src/protocol/ring-rpc/relay-proof-inputs.js";
import type { RelayStatus } from "../../../src/protocol/ring-rpc/ring-rpc-types.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import { RingTransactData } from "../../../src/protocol/transaction/transact.js";
import {
  decodeRelayTransferTerms,
  encodeRelayTransferTerms,
  openingHash,
  type RelayTransferTerms,
} from "../../../src/rpc/relay-message.js";
import {
  OwnerApproval,
  PendingRelaySignature,
  type PreparedRelay,
  type RingRelayClient,
} from "../../../src/rpc/relay.js";
import {
  noteInput,
  randomAddress,
  ringFixture,
  TREE,
  walletKeys,
  type Fixture,
} from "../../helpers/ring-pipeline.js";

const assets = new AssetRegistry();
const RELAY_ID = "11111111111111111111111111111111" as indexerTypes.Hash;

function fakeSigner(address: Address): TransactionPartialSigner {
  return {
    address,
    signTransactions: async () => [{ [address]: new Uint8Array(64) }],
  } as unknown as TransactionPartialSigner;
}

function relayClient(relayId: indexerTypes.Hash = RELAY_ID) {
  return {
    getRelayQuote: vi.fn(),
    getRelayStatus: vi.fn(),
    prepareRelay: vi.fn(async () => ({
      step: "signMessage",
      relayId,
      message: getBase64Decoder().decode(new Uint8Array()),
    })),
    submitRelay: vi.fn(async (): Promise<RelayStatus> => ({ status: "awaitingSignature" })),
  } as unknown as RingRelayClient & { submitRelay: ReturnType<typeof vi.fn> };
}

function noteOf(input: ProofInputUtxo, leafIndex: number): WalletUtxo {
  return {
    utxo: input.utxo,
    outputContext: { hash: new Uint8Array(32), tree: TREE, leafIndex: BigInt(leafIndex) },
    nullifier: input.nullifier(),
    spent: false,
  } as unknown as WalletUtxo;
}

function messageOf(
  feePayer: Address,
  instructions: readonly Instruction[],
  tag: RingInstructionTag = RingInstructionTag.transfer,
): Uint8Array {
  const { messageBytes } = compileUnsignedTransaction({
    feePayer,
    lifetime: SIZE_PROBE_LIFETIME,
    instructions,
    computeUnitLimit: ringComputeUnitLimit(tag),
  });
  return new Uint8Array(messageBytes);
}

/** The owner signs once the charges were read. */
const signed = async (prepared: Promise<PreparedRingRelay>): Promise<PreparedRelay> =>
  (await prepared).relay.sign();

const pendingOf = async (relay: PreparedRelay) => {
  const sent = await relay.send(relayClient(relay.relayId()));
  if (!(sent instanceof PendingRelaySignature)) throw new Error("the relay asks a signature");
  return sent;
};

const refusal = (attempt: () => unknown): unknown => {
  try {
    attempt();
  } catch (error) {
    return (error as { details?: { mismatch?: unknown } }).details?.mismatch;
  }
  return "accepted";
};

interface Paid {
  readonly fixture: Fixture;
  readonly sender: ShieldedKeypair;
  readonly payee: ShieldedKeypair;
  readonly payeeAddress: Address;
  readonly relay: PreparedRelay;
  /** What `prepareRelay` sealed, under its own blindings. */
  readonly sealedTerms: RelayTransferTerms;
  readonly terms: RelayTransferTerms;
  readonly instruction: Instruction;
  readonly message: Uint8Array;
  pending(
    terms: RelayTransferTerms,
    message?: Uint8Array,
    knownNotes?: readonly Pick<WalletUtxo, "nullifier">[],
  ): Promise<PendingRelaySignature>;
  payTo(owner: ShieldedKeypair): Promise<Instruction>;
}

function addressOf(fixture: Fixture, owner: ShieldedKeypair): RingAddress {
  return new RingAddress({
    recipient: owner.shieldedAddress(),
    ringProgramId: fixture.ringProgramId,
    listSalt: new Uint8Array(32).fill(1) as Bytes32,
  });
}

function dataPayment(fixture: Fixture, owner: ShieldedKeypair): AnonymousPayment {
  return {
    to: addressOf(fixture, owner),
    asset: SOL_MINT,
    amount: 4n,
    reply: null,
    data: {
      application: {
        hash: new Uint8Array(32).fill(4) as Bytes32,
        bytes: Uint8Array.of(1, 2, 3),
      },
    },
  };
}

function railOf(
  fixture: Fixture,
  signing: SigningKey,
  notes: readonly ProofInputUtxo[],
): AnonymousTransfer {
  const sender = ShieldedKeypair.fromKeypair(signing);
  return CustomRingTransfer.new({
    ringProgramId: fixture.ringProgramId,
    keys: walletKeys(sender),
    transfer: ringSpendTransfer({
      owner: sender.shieldedAddress(),
      inputs: notes,
      feePayer: fixture.authority,
    }),
    assets,
  }).withAnonymousSigner(signingKeySpendSigner(signing));
}

/** A data payment asks its recipient, the hidden sender stays out of the terms. */
async function paid(): Promise<Paid> {
  const fixture = await ringFixture({ mode: "anonymous" });
  const signing = SigningKey.generate();
  const sender = ShieldedKeypair.fromKeypair(signing);
  const payee = ShieldedKeypair.generate();
  fixture.enroll(sender.shieldedAddress());
  fixture.enroll(payee.shieldedAddress());
  const payTo = (owner: ShieldedKeypair) => {
    fixture.enroll(owner.shieldedAddress());
    const input = noteInput(sender, 10n, fixture.ringProgramId);
    return {
      input,
      rail: railOf(fixture, signing, [input]).withPayment(dataPayment(fixture, owner)),
    };
  };
  const { input, rail } = payTo(payee);
  const relay = await signed(
    rail.prepareRelay(fixture.client, {
      quote: { feePayer: fixture.authority, validUntilSlot: 100n },
      nullifierKey: sender.nullifierKey(),
      notes: [noteOf(input, 0)],
    }),
  );
  const payeeAddress = payee.shieldedAddress().solanaAddress();
  const sealedTerms = (await pendingOf(relay)).transferTerms(payeeAddress);
  if (sealedTerms === undefined) throw new Error("the sealing wallet holds the payee's terms");
  const instruction = await (await rail.prove(fixture.client)).instruction();
  const message = messageOf(fixture.authority, [instruction]);
  const [terms] = termsOfCall(fixture, payeeAddress);
  if (terms === undefined) throw new Error("the frame names the payee");
  return {
    fixture,
    sender,
    payee,
    payeeAddress,
    relay,
    sealedTerms,
    terms,
    instruction,
    message,
    pending: (held, framed = message, knownNotes = []) =>
      new OwnerApproval({
        relayId: RELAY_ID,
        message: framed,
        terms: held,
        config: { mode: "anonymous", auditorPublicKey: fixture.auditor.publicKey() },
        knownNotes,
      }).pending(),
    payTo: async (owner) => (await payTo(owner).rail.prove(fixture.client)).instruction(),
  };
}

/** Each run seals fresh blindings, the frame's own proof inputs name its openings. */
function termsOfCall(fixture: Fixture, signer: Address): readonly RelayTransferTerms[] {
  const call = fixture.sppCalls.at(-1);
  if (call === undefined) throw new Error("a frame proved");
  const { proofInputs } = call;
  return sealedTransferTerms({
    ringProgramId: fixture.ringProgramId,
    feePayer: fixture.authority,
    sealed: {
      published: publishedOutputs(proofInputs.outputs).map((output) => ({ output })),
      proofInputs,
    } as unknown as SealedTransfer,
    ownerSigners: [signer],
    setup: [],
  });
}

describe("relay transfer terms", () => {
  beforeAll(async () => {
    await initializePoseidon();
  });

  it("seals every published slot for a data recipient, each opening rebuilding its published hash", async () => {
    const { sealedTerms, relay, payeeAddress } = await paid();
    expect(sealedTerms.slots.map((opening) => opening.slot)).toEqual([0, 1]);
    expect(sealedTerms.nullifiers).toHaveLength(0);
    const { intent } = relay.request;
    if (intent.operation !== "anonymous") throw new Error("an anonymous relay");
    const decoded = await decodeRelayProofInputs(
      new Uint8Array(getBase64Encoder().encode(intent.proofInputs)),
      assets,
    );
    expect(sealedTerms.slots.map((opening) => opening.owner)).toContain(payeeAddress);
    for (const opening of sealedTerms.slots)
      expect(openingHash(opening, sealedTerms.ring)).toEqual(
        decoded.externalData.outputs[opening.slot]?.utxoHash,
      );
  });

  it("gives the sealing wallet the terms and no signature", async () => {
    const { relay, payeeAddress, sender } = await paid();
    const sealed = await pendingOf(relay);
    expect(refusal(() => sealed.verify(payeeAddress))).toBe("Unrequested");
    expect(refusal(() => sealed.verify(sender.shieldedAddress().solanaAddress()))).toBe(
      "Unrequested",
    );
    await expect(sealed.sign(relayClient(), fakeSigner(payeeAddress))).rejects.toMatchObject({
      details: { mismatch: "Unrequested" },
    });
  });

  it("lets a data recipient sign its own slot more than once", async () => {
    const { terms, payeeAddress, sender, pending } = await paid();
    const held = decodeRelayTransferTerms(encodeRelayTransferTerms(terms));
    expect(held).toEqual(terms);
    expect(held.slots).toHaveLength(2);
    expect(held.nullifiers).toHaveLength(0);
    expect(held.slots[1]?.owner).toBe(payeeAddress);

    const signing = await pending(held);
    expect(signing.verify(payeeAddress).signer).toBe(payeeAddress);
    const relay = relayClient();
    await signing.sign(relay, fakeSigner(payeeAddress));
    await signing.sign(relay, fakeSigner(payeeAddress));
    expect(relay.submitRelay).toHaveBeenCalledTimes(2);
    expect(refusal(() => signing.verify(sender.shieldedAddress().solanaAddress()))).toBe(
      "Unrequested",
    );
  });

  it("refuses a false opening and another owner with Recipients, a moved slot unopened", async () => {
    const { terms, payeeAddress, pending } = await paid();
    const [change, opening] = terms.slots;
    if (change === undefined || opening === undefined) throw new Error("two slots");
    const verdict = async (changed: Partial<typeof opening>) => {
      const held = await pending({ ...terms, slots: [change, { ...opening, ...changed }] });
      return refusal(() => held.verify(payeeAddress));
    };
    expect(await verdict({ amount: opening.amount + 1n })).toBe("Recipients");
    expect(await verdict({ owner: randomAddress() })).toBe("Recipients");
    expect(await verdict({ slot: opening.slot + 1 })).toBe("UnopenedOutput");
    expect(await verdict({ slot: 99 })).toBe("UnopenedOutput");
    const omitted = await pending({ ...terms, slots: [opening] });
    expect(refusal(() => omitted.verify(payeeAddress))).toBe("UnopenedOutput");
  });

  it("refuses a thief's slot under the terms of the payee with Recipients", async () => {
    const { terms, payeeAddress, fixture, payTo, pending } = await paid();
    const stolen = await payTo(ShieldedKeypair.generate());
    const held = await pending(terms, messageOf(fixture.authority, [stolen]));
    expect(refusal(() => held.verify(payeeAddress))).toBe("Recipients");
  });

  it("refuses empty terms, and a co-signer holds none", async () => {
    const { terms, payeeAddress, pending } = await paid();
    const empty = await pending({ ...terms, slots: [], nullifiers: [] });
    expect(refusal(() => empty.verify(payeeAddress))).toBe("Unrequested");

    const coSigner = randomAddress();
    const fixture = await ringFixture({
      mode: "anonymous",
      coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS },
    });
    const signing = SigningKey.generate();
    const sender = ShieldedKeypair.fromKeypair(signing);
    const payee = ShieldedKeypair.generate();
    fixture.enroll(sender.shieldedAddress());
    fixture.enroll(payee.shieldedAddress());
    const input = noteInput(sender, 10n, fixture.ringProgramId);
    const relay = await signed(
      railOf(fixture, signing, [input])
        .withPayment({ to: addressOf(fixture, payee), asset: SOL_MINT, amount: 4n, reply: null })
        .prepareRelay(fixture.client, {
          quote: { feePayer: fixture.authority, validUntilSlot: 100n },
          nullifierKey: sender.nullifierKey(),
          notes: [noteOf(input, 0)],
        }),
    );
    const held = await pendingOf(relay);
    expect(held.transferTerms(coSigner)).toBeUndefined();
    expect(refusal(() => held.verify(coSigner))).toBe("Unrequested");
    expect(relay.request.coSigners).toBeUndefined();
  });

  it("keeps a held co-owner's key off the wire while it spends nothing", async () => {
    const fixture = await ringFixture({ mode: "anonymous" });
    const signing = SigningKey.generate();
    const sender = ShieldedKeypair.fromKeypair(signing);
    const idle = ShieldedKeypair.generate();
    const payee = ShieldedKeypair.generate();
    for (const owner of [sender, idle, payee]) fixture.enroll(owner.shieldedAddress());
    const input = noteInput(sender, 10n, fixture.ringProgramId);
    const relay = await signed(
      railOf(fixture, signing, [input])
        .withCoOwner({
          owner: idle.shieldedAddress().solanaAddress(),
          nullifierKey: idle.nullifierKey(),
        })
        .withPayment({ to: addressOf(fixture, payee), asset: SOL_MINT, amount: 4n, reply: null })
        .prepareRelay(fixture.client, {
          quote: { feePayer: fixture.authority, validUntilSlot: 100n },
          nullifierKey: sender.nullifierKey(),
          notes: [noteOf(input, 0)],
        }),
    );
    const { intent } = relay.request;
    if (intent.operation !== "anonymous") throw new Error("an anonymous relay");
    const decoded = await decodeRelayProofInputs(
      new Uint8Array(getBase64Encoder().encode(intent.proofInputs)),
      assets,
    );
    expect(decoded.coOwners).toEqual([]);
  });

  it.each(["anonymous", "confidential"] as const)(
    "sends a spending co-owner's key and keeps an idle one's off the %s relay",
    async (mode) => {
      const fixture = await ringFixture({ mode });
      const signing = SigningKey.generate();
      const sender = ShieldedKeypair.fromKeypair(signing);
      const [spending, idle, payee] = [0, 1, 2].map(() => ShieldedKeypair.generate()) as [
        ShieldedKeypair,
        ShieldedKeypair,
        ShieldedKeypair,
      ];
      for (const owner of [sender, spending, idle, payee]) fixture.enroll(owner.shieldedAddress());
      const notes = [
        noteInput(sender, 10n, fixture.ringProgramId),
        noteInput(spending, 10n, fixture.ringProgramId),
      ];
      const coOwnerOf = (owner: ShieldedKeypair) => ({
        owner: owner.shieldedAddress().solanaAddress(),
        nullifierKey: owner.nullifierKey(),
      });
      const relayInput = {
        quote: { feePayer: fixture.authority, validUntilSlot: 100n },
        nullifierKey: sender.nullifierKey(),
        notes: notes.map(noteOf),
      };
      const transfer = ringSpendTransfer({
        owner: sender.shieldedAddress(),
        inputs: notes,
        feePayer: fixture.authority,
      });
      const confidential = CustomRingTransfer.new({
        ringProgramId: fixture.ringProgramId,
        keys: walletKeys(sender),
        transfer,
        assets,
      })
        .withCoOwner(coOwnerOf(idle))
        .withCoOwner(coOwnerOf(spending));
      let relay;
      if (mode === "anonymous") {
        relay = await signed(
          confidential
            .withAnonymousSigner(signingKeySpendSigner(signing))
            .withPayment({
              to: addressOf(fixture, payee),
              asset: SOL_MINT,
              amount: 4n,
              reply: null,
            })
            .prepareRelay(fixture.client, relayInput),
        );
      } else {
        transfer.send(payee.shieldedAddress(), SOL_MINT, 4n);
        relay = await (
          await confidential
            .withInProofOwner(signingKeySpendSigner(signing))
            .prepareRelay(fixture.client, relayInput)
        ).sign();
      }
      const { intent } = relay.request;
      if (intent.operation !== mode) throw new Error(`a ${mode} relay`);
      const decoded = await decodeRelayProofInputs(
        new Uint8Array(getBase64Encoder().encode(intent.proofInputs)),
        assets,
      );
      expect(decoded.coOwners.map((held) => held.owner)).toEqual([coOwnerOf(spending).owner]);
    },
  );

  it("carries a public co-owner's key across the wire and opens its notes to it", async () => {
    const fixture = await ringFixture({ mode: "anonymous" });
    const signing = SigningKey.generate();
    const sender = ShieldedKeypair.fromKeypair(signing);
    const coOwner = ShieldedKeypair.generate();
    const payee = ShieldedKeypair.generate();
    for (const owner of [sender, coOwner, payee]) fixture.enroll(owner.shieldedAddress());
    const notes = [
      noteInput(sender, 10n, fixture.ringProgramId),
      noteInput(coOwner, 10n, fixture.ringProgramId),
    ];
    const owner = coOwner.shieldedAddress().solanaAddress();
    const rail = railOf(fixture, signing, notes)
      .withCoOwner({ owner, nullifierKey: coOwner.nullifierKey() })
      .withPayment({ to: addressOf(fixture, payee), asset: SOL_MINT, amount: 4n, reply: null });
    const relay = await signed(
      rail.prepareRelay(fixture.client, {
        quote: { feePayer: fixture.authority, validUntilSlot: 100n },
        nullifierKey: sender.nullifierKey(),
        notes: notes.map(noteOf),
      }),
    );
    const terms = (await pendingOf(relay)).transferTerms(owner);
    if (terms === undefined) throw new Error("the sealing wallet holds the co-owner's terms");
    expect(terms.nullifiers).toEqual([notes[1]?.nullifier()]);

    const { intent } = relay.request;
    if (intent.operation !== "anonymous") throw new Error("an anonymous relay");
    const wire = new Uint8Array(getBase64Encoder().encode(intent.proofInputs));
    const decoded = await decodeRelayProofInputs(wire, assets);
    expect(decoded.coOwners.map((held) => held.owner)).toEqual([owner]);
    expect(decoded.inputs.map((spent) => spent.nullifier())).toEqual(
      notes.map((spent) => spent.nullifier()),
    );
    expect(encodeRelayProofInputs(decoded)).toEqual(wire);
    const unheld = expect.objectContaining({ code: "RING_RELAY_PROOF_INPUTS" });
    expect(() => encodeRelayProofInputs({ ...decoded, coOwners: [] })).toThrow(unheld);
    expect(() =>
      encodeRelayProofInputs({
        ...decoded,
        coOwners: [{ owner, nullifierKey: payee.nullifierKey() }],
      }),
    ).toThrow(unheld);

    const instruction = await (await rail.prove(fixture.client)).instruction();
    // Every published slot opens to the signer, the openings come from the frame's own build.
    const [framedTerms] = termsOfCall(fixture, owner);
    if (framedTerms === undefined) throw new Error("the frame names the co-owner");
    expect(framedTerms.nullifiers).toEqual(terms.nullifiers);
    const approval = (
      framed: Instruction,
      knownNotes: readonly Pick<WalletUtxo, "nullifier">[],
    ): Promise<PendingRelaySignature> =>
      new OwnerApproval({
        relayId: RELAY_ID,
        message: messageOf(fixture.authority, [framed]),
        terms: framedTerms,
        config: { mode: "anonymous", auditorPublicKey: fixture.auditor.publicKey() },
        knownNotes,
      }).pending();
    const [spent] = terms.nullifiers;
    if (spent === undefined) throw new Error("one named note");
    const kept = new Uint8Array(32).fill(7) as Bytes32;
    const known = [{ nullifier: spent }, { nullifier: kept }];
    const honest = await approval(instruction, known);
    expect(honest.verify(owner).signer).toBe(owner);

    // No list stands behind the check, the note the terms name is not the wallet's.
    const unlisted = await approval(instruction, []);
    expect(refusal(() => unlisted.verify(owner))).toBe("Data");

    const parsed = RingTransactData.parse(
      Uint8Array.from(instruction.data ?? []).subarray(1),
      "anonymous",
    );
    const spending = (nullifiers: readonly Bytes32[]): Instruction => ({
      ...instruction,
      data: Uint8Array.of(
        RingInstructionTag.transfer,
        ...RingTransactData.encode({ ...parsed, nullifiers }),
      ),
    });
    // The relay holds the key, its frame spends a second note the terms do not name.
    const alsoKept = await approval(spending([kept, spent]), known);
    expect(refusal(() => alsoKept.verify(owner))).toBe("SpendsUnnamedNote");
    const others = await approval(
      spending(parsed.nullifiers.map(() => new Uint8Array(32).fill(9) as Bytes32)),
      known,
    );
    expect(refusal(() => others.verify(owner))).toBe("Data");
  });

  it("refuses setup the terms do not name and a frame that writes through the signer", async () => {
    const { terms, payeeAddress, instruction, fixture, pending } = await paid();
    const framed = async (instructions: readonly Instruction[], held = terms) =>
      pending(held, messageOf(fixture.authority, instructions));

    const extra = { programAddress: randomAddress(), accounts: [], data: new Uint8Array(1) };
    const padded = await framed([extra, instruction]);
    expect(refusal(() => padded.verify(payeeAddress))).toBe("Instructions");

    const accounts = (instruction.accounts ?? []).map((meta) =>
      meta.address === payeeAddress ? { ...meta, role: AccountRole.WRITABLE_SIGNER } : meta,
    );
    const writable = await framed([{ ...instruction, accounts }]);
    expect(refusal(() => writable.verify(payeeAddress))).toBe("Accounts");

    const elsewhere = await framed([{ ...instruction, programAddress: randomAddress() }]);
    expect(refusal(() => elsewhere.verify(payeeAddress))).toBe("Program");

    const setup = { owner: randomAddress(), mint: randomAddress(), tokenProgram: randomAddress() };
    const omitted = await framed([instruction], { ...terms, setup: [setup] });
    expect(omitted.verify(payeeAddress).signer).toBe(payeeAddress);
    const create = await getCreateAssociatedTokenAccountInstructionAsync({
      payer: fixture.authority,
      ...setup,
    });
    const named = await framed([create, instruction], { ...terms, setup: [setup] });
    expect(named.verify(payeeAddress).signer).toBe(payeeAddress);
    const second = { ...setup, owner: randomAddress() };
    const createSecond = await getCreateAssociatedTokenAccountInstructionAsync({
      payer: fixture.authority,
      ...second,
    });
    const both = { ...terms, setup: [setup, second] };
    const last = await framed([createSecond, instruction], both);
    expect(last.verify(payeeAddress).signer).toBe(payeeAddress);
    const reordered = await framed([createSecond, create, instruction], both);
    expect(refusal(() => reordered.verify(payeeAddress))).toBe("Instructions");
    const repeated = await framed([create, create, instruction], both);
    expect(refusal(() => repeated.verify(payeeAddress))).toBe("Instructions");
    const other = await framed([create, instruction], {
      ...terms,
      setup: [{ ...setup, owner: randomAddress() }],
    });
    expect(refusal(() => other.verify(payeeAddress))).toBe("Instructions");
  });

  it("writes and reads the terms as the Rust vector does", () => {
    const { wire } = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/relay_transfer_terms.json", import.meta.url),
        "utf8",
      ),
    ) as { wire: string };
    const terms = decodeRelayTransferTerms(wire);
    expect(terms.slots[0]?.amount).toBe(2n ** 64n - 1n);
    expect(terms.slots[0]?.slot).toBe(7);
    expect(encodeRelayTransferTerms(terms)).toBe(wire);
  });

  it("refuses unknown and missing fields as Rust does", async () => {
    const { terms } = await paid();
    const wire = JSON.parse(encodeRelayTransferTerms(terms)) as Record<string, unknown>;
    const undecodable = (changed: object) =>
      refusal(() => decodeRelayTransferTerms(JSON.stringify({ ...wire, ...changed })));
    expect(undecodable({ extra: 1 })).toBe("Undecodable");
    expect(undecodable({ nullifiers: ["1"] })).toBe("Undecodable");
    const setup = { owner: terms.signer, mint: terms.signer, tokenProgram: terms.signer };
    expect(undecodable({ setup: [{ ...setup, extra: 1 }] })).toBe("Undecodable");
    const opening = (wire["slots"] as readonly object[])[0];
    const rewritten = (from: RegExp, to: string) =>
      refusal(() => decodeRelayTransferTerms(JSON.stringify(wire).replace(from, to)));
    expect(rewritten(/"amount":\d+/, '"amount":[]')).toBe("Undecodable");
    expect(rewritten(/"amount":\d+/, '"amount":-0')).toBe("Undecodable");
    expect(rewritten(/"slot":\d+/, '"slot":0.0')).toBe("Undecodable");
    expect(opening).toBeDefined();
    const { signer: _signer, ...missing } = wire;
    expect(refusal(() => decodeRelayTransferTerms(JSON.stringify(missing)))).toBe("Undecodable");
  });
});
