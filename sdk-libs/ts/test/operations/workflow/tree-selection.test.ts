import { ShieldedKeypair, SigningKey } from "@heliuslabs/spr/keypair";
import { treeAddress } from "@heliuslabs/spr/internal";
import type { Address, Bytes32 } from "@heliuslabs/spr/interface";
import { AssetRegistry, Data, SOL_MINT, Utxo, Wallet } from "@heliuslabs/spr/transaction";
import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import vectors from "../../../../../test-vectors/wallet/tree-selection.json" with { type: "json" };
import { selectAuthorityNotes } from "../../../src/operations/management/delegate.js";
import {
  anonymousInputCap,
  selectAnonymousInputs,
  selectRingInputs,
} from "../../../src/operations/payments/transfer.js";
import { ringSelectionErrors, selectFunding } from "../../../src/operations/workflow/selection.js";

const RING = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

type Note = readonly [tree: number, amount: bigint, asset?: Address, origin?: "default"];

const MINT = address("Mint111111111111111111111111111111111111111");

function noteId(index: number): Bytes32 {
  const bytes = new Uint8Array(32);
  new DataView(bytes.buffer).setUint32(0, index + 1, true);
  return bytes as Bytes32;
}

function walletOf(notes: readonly Note[], ringProgramId?: Address): Wallet {
  const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry([[2n, MINT]]),
  });
  wallet._replace({
    utxos: notes.map(([tree, amount, asset = SOL_MINT, origin], index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset,
        amount,
        blinding: filled((index % 250) + 1),
        data: new Data(),
        ...(ringProgramId === undefined || origin === "default" ? {} : { ringProgramId }),
      }),
      outputContext: {
        hash: noteId(index),
        tree: treeAddress(tree),
        leafIndex: BigInt(index),
      },
      nullifier: noteId(index),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

function sortedByTree(
  entries: readonly { outputContext: { tree: Address }; utxo: { amount: bigint } }[],
) {
  return entries
    .map((entry) => [entry.outputContext.tree, entry.utxo.amount] as const)
    .sort(([left, leftAmount], [right, rightAmount]) =>
      left === right ? Number(rightAmount - leftAmount) : left.localeCompare(right),
    );
}

/** Each picked note as its tree and amount, sorted by tree address. */
function picked(notes: readonly Note[], amount: bigint, maxInputs: number) {
  return sortedByTree(
    selectFunding({
      wallet: walletOf(notes),
      covers: [{ asset: SOL_MINT, amount }],
      policy: {
        eligible: () => true,
        ordering: "largestFirst",
        maxInputs,
        errors: ringSelectionErrors,
      },
    }),
  );
}

function expected(notes: readonly Note[]) {
  return sortedByTree(
    notes.map(([tree, amount]) => ({
      outputContext: { tree: treeAddress(tree) },
      utxo: { amount },
    })),
  );
}

describe("selectFunding", () => {
  it("rejects three selected trees without searching for an alternative", () => {
    expect(() =>
      picked(
        [
          [0, 60n],
          [0, 20n],
          [1, 55n],
          [2, 50n],
        ],
        130n,
        4,
      ),
    ).toThrow("RING_TOO_MANY_INPUT_TREES");
  });

  it("returns a tree refusal for a large fragmented wallet", () => {
    const notes: Note[] = Array.from({ length: 1_000 }, (_, tree) => [tree, 1n]);
    expect(() => picked(notes, 3n, 5)).toThrow("RING_TOO_MANY_INPUT_TREES");
  });

  it("tries default funding after a ring tree refusal", () => {
    const wallet = walletOf(
      [
        [0, 60n],
        [0, 20n],
        [1, 55n],
        [2, 50n],
        [0, 140n, SOL_MINT, "default"],
      ],
      RING,
    );
    const selected = selectAnonymousInputs(
      { wallet, ringProgramId: RING, asset: SOL_MINT, amount: 130n },
      "ring-or-default",
    );
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.ringProgramId).toBeUndefined();
    expect(selected[0]?.utxo.amount).toBe(140n);
  });

  it("reports the default tree refusal when the ring balance is empty", () => {
    const wallet = walletOf([
      [0, 60n],
      [0, 20n],
      [1, 55n],
      [2, 50n],
    ]);
    expect(() =>
      selectAnonymousInputs(
        { wallet, ringProgramId: RING, asset: SOL_MINT, amount: 130n },
        "ring-or-default",
      ),
    ).toThrow("RING_TOO_MANY_INPUT_TREES");
  });

  it("selects a large default note without exact funding search", () => {
    const selected = selectRingInputs({
      wallet: walletOf([
        [0, 40n],
        [0, 15n],
        [0, 10n],
      ]),
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 25n,
      inputs: "entry",
      maxInputs: 8,
    });
    expect(selected.map((entry) => entry.utxo.amount)).toEqual([40n]);
  });

  it("checks the tree limit across all assets", () => {
    expect(() =>
      selectFunding({
        wallet: walletOf([
          [0, 6n],
          [1, 6n],
          [2, 10n, MINT],
        ]),
        covers: [
          { asset: SOL_MINT, amount: 10n },
          { asset: MINT, amount: 10n },
        ],
        policy: {
          eligible: () => true,
          ordering: "largestFirst",
          maxInputs: 4,
          errors: ringSelectionErrors,
        },
      }),
    ).toThrow("RING_TOO_MANY_INPUT_TREES");
  });

  it("shares the input budget across assets", () => {
    expect(() =>
      selectFunding({
        wallet: walletOf([
          [0, 6n],
          [0, 6n],
          [0, 5n, MINT],
          [0, 5n, MINT],
        ]),
        covers: [
          { asset: SOL_MINT, amount: 10n },
          { asset: MINT, amount: 10n },
        ],
        policy: {
          eligible: () => true,
          ordering: "largestFirst",
          maxInputs: 3,
          errors: ringSelectionErrors,
        },
      }),
    ).toThrow("RING_TOO_MANY_INPUTS");
  });

  it("pays ten from six on each of two trees", () => {
    expect(
      picked(
        [
          [0, 6n],
          [1, 6n],
          [2, 1n],
        ],
        10n,
        5,
      ),
    ).toEqual(
      expected([
        [0, 6n],
        [1, 6n],
      ]),
    );
  });

  it("takes large notes from a fragmented wallet", () => {
    const small = Array.from({ length: 8 }, (_, tree) =>
      [20n, 20n, 20n, 5n].map((amount) => [tree + 1, amount] as const),
    ).flat();
    expect(picked([...small, [9, 60n], [10, 60n]], 120n, 4)).toEqual(
      expected([
        [9, 60n],
        [10, 60n],
      ]),
    );
  });

  it("funds a delegate move from two trees", () => {
    const selected = selectAuthorityNotes({
      wallet: walletOf(
        [
          [0, 6n],
          [1, 6n],
        ],
        RING,
      ),
      covers: [{ asset: SOL_MINT, amount: 10n }],
      outputs: 2,
      eligible: () => true,
    });
    expect(sortedByTree(selected)).toEqual(
      expected([
        [0, 6n],
        [1, 6n],
      ]),
    );
  });

  it("refuses delegate funding across three trees", () => {
    expect(() =>
      selectAuthorityNotes({
        wallet: walletOf(
          [
            [0, 4n],
            [1, 4n],
            [2, 4n],
          ],
          RING,
        ),
        covers: [{ asset: SOL_MINT, amount: 10n }],
        outputs: 2,
        eligible: () => true,
      }),
    ).toThrow("RING_TOO_MANY_INPUT_TREES");
  });

  it("leaves delegate change feasibility to transaction assembly", () => {
    const notes: readonly Note[] = [
      [0, 101n],
      [1, 50n],
      [1, 50n],
    ];
    const selected = selectAuthorityNotes({
      wallet: walletOf(notes),
      covers: [{ asset: SOL_MINT, amount: 100n }],
      outputs: 4,
      eligible: () => true,
    });
    expect(sortedByTree(selected)).toEqual(expected([[0, 101n]]));
  });

  /** Rust `an_anonymous_move_counts_the_sender_change_before_selection`. */
  it("counts the anonymous sender change before selection", () => {
    expect(anonymousInputCap("ring", 2)).toBe(24);
    const ones: readonly Note[] = Array.from({ length: 25 }, () => [1, 1n] as const);
    const select = (notes: readonly Note[]) =>
      selectRingInputs({
        wallet: walletOf(notes, RING),
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 25n,
        inputs: "ring",
        maxInputs: anonymousInputCap("ring", 2),
      });
    expect(() => select(ones)).toThrow("RING_TOO_MANY_INPUTS");
    const selected = select([...ones, [2, 5n]]);
    expect(selected).toHaveLength(21);
    expect(new Set(selected.map((entry) => entry.outputContext.tree))).toEqual(
      new Set([treeAddress(1), treeAddress(2)]),
    );
  });

  it("names an asset with insufficient balance", () => {
    const select = () =>
      selectFunding({
        wallet: walletOf([
          [1, 10n],
          [2, 5n, MINT],
        ]),
        covers: [
          { asset: SOL_MINT, amount: 10n },
          { asset: MINT, amount: 100n },
        ],
        policy: {
          eligible: () => true,
          ordering: "largestFirst",
          maxInputs: 4,
          errors: ringSelectionErrors,
        },
      });
    expect(select).toThrow(
      expect.objectContaining({
        code: "RING_INSUFFICIENT_BALANCE",
        details: expect.objectContaining({ asset: MINT }),
      }),
    );
  });

  it.each(vectors.cases)("matches the shared vector: $name", (vector) => {
    expect(
      picked(
        vector.notes.map((note) => [note.tree, BigInt(note.amount)] as const),
        BigInt(vector.amount),
        vector.maxInputs,
      ),
    ).toEqual(expected(vector.selected.map((note) => [note.tree, BigInt(note.amount)] as const)));
  });
});
