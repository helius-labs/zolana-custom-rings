import {
  TRANSACTION_SIZE_LIMIT,
  type Address,
  type Bytes32,
  type Instruction,
} from "@heliuslabs/spr/interface";
import { encodeBase58 } from "@heliuslabs/spr/internal";
import { ShieldedKeypair } from "@heliuslabs/spr/keypair";
import { SOL_MINT } from "@heliuslabs/spr/transaction";
import { AccountRole } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { field, ringFrame, ringInstructionData } from "../../helpers/ring-frame.js";
import { MAX_CPI_DATA_LEN } from "../../../src/protocol/transaction/transact.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import { MAX_TRANSACTION_ADDRESSES as LIMIT } from "../../../src/operations/workflow/compile.js";
import {
  decideAddressCeiling,
  TransactionFit,
  type CeilingDecision,
  type MergeCapacity,
  type SpentInput,
} from "../../../src/operations/workflow/address-ceiling.js";

function address(seed: number): Address {
  const bytes = new Uint8Array(32).fill(0xaa);
  new DataView(bytes.buffer).setUint32(0, seed);
  return encodeBase58(bytes);
}

const owners = new Map<number, ShieldedKeypair>();
const ownerOf = (owner: number): ShieldedKeypair => {
  const held = owners.get(owner) ?? ShieldedKeypair.generate();
  owners.set(owner, held);
  return held;
};

const note = (owner: number, seed: number): SpentInput => ({
  owner: ownerOf(owner).signingPublicKey(),
  asset: SOL_MINT,
  nullifierPublicKey: new Uint8Array(32).fill(owner) as Bytes32,
  ringProgramId: address(0),
  treeId: 1,
  nullifierPda: address(1000 + seed),
});

function decide(
  inputs: readonly SpentInput[],
  other: number,
  mergeCapacity: MergeCapacity = { keyed: 45, zeroKey: 45 },
): CeilingDecision {
  const accounts = [
    ...inputs.map((input) => input.nullifierPda),
    ...Array.from({ length: other }, (_, seed) => address(5000 + seed)),
  ].map((account) => ({ address: account, role: 1 }));
  const instruction = { programAddress: address(2), accounts } as unknown as Instruction;
  return decideAddressCeiling({
    payer: address(1),
    instruction,
    computeUnitLimit: 1_000_000,
    inputs,
    mergeCapacity,
  });
}

const notes = (owner: number, count: number): readonly SpentInput[] =>
  Array.from({ length: count }, (_, seed) => note(owner, seed));

const refused = (inputs: readonly SpentInput[], other: number) =>
  (thrown(() => decide(inputs, other)) as { details?: unknown }).details;

function thrown(action: () => unknown): unknown {
  try {
    action();
  } catch (error) {
    return error;
  }
  throw new Error("accepted");
}

/** A frame that parses under its rail, each message stretches it. */
const realFrame = (messages: readonly number[] = []): Instruction =>
  ({
    programAddress: address(2),
    accounts: [],
    data: ringInstructionData({
      ...ringFrame({ rail: "confidential", inputs: 1, outputs: 2 }),
      extensions: {
        messages: messages.map((length) => ({ viewTag: field(9), data: new Uint8Array(length) })),
      },
    }),
  }) as unknown as Instruction;

const signing = (key: number): Instruction =>
  ({
    programAddress: address(3),
    accounts: [{ address: address(key), role: 2 }],
  }) as unknown as Instruction;

const BUDGET = { computeUnitLimit: 1_000_000 };

describe("decideAddressCeiling, the cases of Rust `validation::address_ceiling`", () => {
  it("keeps a transaction at the ceiling one transaction", () => {
    expect(decide(notes(1, 10), LIMIT - 2 - 10)).toMatchObject({
      kind: "inline",
      size: { addresses: LIMIT },
    });
  });

  it("names only the groups the ceiling needs", () => {
    const inputs = [...notes(1, 4), note(2, 4), note(2, 5)];
    const decision = decide(inputs, LIMIT - 2 - 6 + 2);
    if (decision.kind !== "mergeFirst") throw new Error("merge first");
    expect(decision.addresses).toBe(LIMIT - 1);
    expect(decision.groups.map((group) => group.inputs)).toEqual([[0, 1, 2, 3]]);
    expect(decision.groups[0]?.owner.equals(inputs[0]?.owner as never)).toBe(true);
  });

  it("forms no group of mixed owners and reports the compiled count", () => {
    const inputs = [0, 1, 2, 3].map((seed) => note(seed + 1, seed));
    expect(refused(inputs, LIMIT - 2 - 4 + 1)).toEqual({
      compiled: LIMIT + 1,
      limit: LIMIT,
      afterMerging: LIMIT + 1,
      dataNotes: 0,
    });
  });

  it("keeps a data note out of every group", () => {
    const inputs = notes(1, 4).map((input) => ({
      ...input,
      dataHash: new Uint8Array(32).fill(9) as Bytes32,
    }));
    expect(refused(inputs, LIMIT - 2 - 4 + 1)).toMatchObject({
      afterMerging: LIMIT + 1,
      dataNotes: 4,
    });
  });

  it("merges no notes of another asset, key or tree", () => {
    const inputs = [
      note(1, 0),
      { ...note(1, 1), asset: address(7) },
      { ...note(1, 2), nullifierPublicKey: new Uint8Array(32).fill(9) as Bytes32 },
      { ...note(1, 3), treeId: 2 },
    ];
    expect(refused(inputs, LIMIT - 2 - 4 + 1)).toMatchObject({ afterMerging: LIMIT + 1 });
  });

  it("refuses consolidation short of the ceiling with how far it reached", () => {
    expect(refused(notes(1, 4), LIMIT - 2 - 4 + 5)).toMatchObject({
      compiled: LIMIT + 5,
      afterMerging: LIMIT + 2,
    });
  });

  it("names no merge for a lone note past the capacity", () => {
    const decision = decide(notes(1, 4), LIMIT - 2 - 4 + 1, { keyed: 3, zeroKey: 3 });
    if (decision.kind !== "mergeFirst") throw new Error("merge first");
    expect(decision.groups.map((group) => group.inputs)).toEqual([[0, 1, 2]]);
    expect(decision.addresses).toBe(LIMIT - 1);
  });

  it("reads a frame that parses under neither rail as unparsed, whatever its length", () => {
    const data = new Uint8Array(1000);
    data[0] = RingInstructionTag.transfer;
    const instruction = {
      programAddress: address(2),
      accounts: [],
      data,
    } as unknown as Instruction;
    expect(
      thrown(() =>
        decideAddressCeiling({
          payer: address(1),
          instruction,
          computeUnitLimit: 1_000_000,
          inputs: [],
          mergeCapacity: { keyed: 45, zeroKey: 45 },
        }),
      ),
    ).toMatchObject({ code: "RING_FIT_UNPARSED_FRAME" });
  });
});

describe("TransactionFit, the refusals of Rust `TransactionFit`", () => {
  const payer = { payer: address(1) };

  it("keeps a frame under the ceiling inline and reads its CPI bytes", () => {
    const fit = TransactionFit.of(realFrame(), payer, BUDGET);
    expect(fit).toMatchObject({ signatures: 1, addresses: 2 });
    expect(fit.cpiBytes).toBeGreaterThan(realFrame().data?.length ?? 0);
    expect(fit.setup).toEqual({ instructions: 0, signatures: 0, bytes: 0, addresses: 0 });
  });

  it("names no CPI bytes off the transfer tags", () => {
    const fit = TransactionFit.of(signing(4), payer, BUDGET);
    expect(fit.cpiBytes).toBeUndefined();
    expect(fit.signatures).toBe(2);
  });

  it("refuses a transfer past the byte ceiling by its bytes", () => {
    expect(thrown(() => TransactionFit.of(realFrame([4000]), payer, BUDGET))).toMatchObject({
      code: "RING_FIT_BYTES",
      details: { limit: TRANSACTION_SIZE_LIMIT },
    });
  });

  it("refuses bytes on any other tag", () => {
    const instruction = {
      ...signing(4),
      data: new Uint8Array(TRANSACTION_SIZE_LIMIT).fill(0xff),
    } as unknown as Instruction;
    expect(thrown(() => TransactionFit.of(instruction, payer, BUDGET))).toMatchObject({
      code: "RING_FIT_BYTES",
    });
  });

  it("refuses an expansion past one CPI ahead of every other ceiling", () => {
    const instruction = realFrame([MAX_CPI_DATA_LEN]);
    const refusal = { code: "RING_FIT_CPI_BYTES", details: { limit: MAX_CPI_DATA_LEN } };
    expect(thrown(() => TransactionFit.of(instruction, payer, BUDGET))).toMatchObject(refusal);
    const crowded = Array.from({ length: 13 }, (_, key) => signing(50 + key));
    expect(
      thrown(() =>
        TransactionFit.of(instruction, { ...payer, setupInstructions: crowded }, BUDGET),
      ),
    ).toMatchObject(refusal);
  });

  it("counts a signer two instructions share once and refuses past twelve", () => {
    const twelve = Array.from({ length: 11 }, (_, key) => signing(50 + key));
    const fit = TransactionFit.of(signing(50), { ...payer, setupInstructions: twelve }, BUDGET);
    expect(fit.signatures).toBe(12);
    expect(fit.setup).toMatchObject({ instructions: 11, signatures: 10 });
    expect(
      thrown(() => TransactionFit.of(signing(61), { ...payer, setupInstructions: twelve }, BUDGET)),
    ).toMatchObject({
      code: "RING_FIT_SIGNATURES",
      details: { signers: 13, limit: 12 },
    });
  });

  it("refuses instructions past the v1 ceiling after signatures", () => {
    const setupInstructions = Array.from({ length: 64 }, () => signing(4));
    expect(
      thrown(() => TransactionFit.of(signing(4), { ...payer, setupInstructions }, BUDGET)),
    ).toMatchObject({
      code: "RING_FIT_INSTRUCTIONS",
      details: { instructions: 65, limit: 64 },
    });
  });

  it("refuses addresses by their compiled count", () => {
    const accounts = Array.from({ length: LIMIT }, (_, seed) => ({
      address: address(5000 + seed),
      role: 1,
    }));
    const instruction = { programAddress: address(2), accounts } as unknown as Instruction;
    expect(thrown(() => TransactionFit.of(instruction, payer, BUDGET))).toMatchObject({
      code: "RING_FIT_ADDRESSES",
      details: { addresses: LIMIT + 2, limit: LIMIT },
    });
  });

  it("refuses the address a setup instruction adds past the ceiling", () => {
    const accounts = Array.from({ length: LIMIT - 3 }, (_, seed) => ({
      address: address(5000 + seed),
      role: AccountRole.READONLY,
    }));
    const instruction = { programAddress: address(2), accounts } as unknown as Instruction;
    const setup = (extra: number): Instruction =>
      ({
        programAddress: address(3),
        accounts: Array.from({ length: extra }, (_, seed) => ({
          address: address(8000 + seed),
          role: AccountRole.READONLY,
        })),
      }) as unknown as Instruction;
    const fit = (extra: number) =>
      TransactionFit.of(instruction, { ...payer, setupInstructions: [setup(extra)] }, BUDGET);
    expect(fit(0).addresses).toBe(LIMIT);
    expect(thrown(() => fit(1))).toMatchObject({
      code: "RING_FIT_ADDRESSES",
      details: { addresses: LIMIT + 1, limit: LIMIT },
    });
  });

  it("names what setup adds to the shared transaction", () => {
    const fit = TransactionFit.of(
      signing(4),
      { ...payer, setupInstructions: [signing(5)] },
      BUDGET,
    );
    expect(fit.setup).toMatchObject({ instructions: 1, signatures: 1, addresses: 1 });
    expect(fit.setup.bytes).toBeGreaterThan(0);
  });
});
