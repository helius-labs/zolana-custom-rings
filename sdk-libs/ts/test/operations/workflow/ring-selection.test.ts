import { X25519Keypair, ShieldedKeypair, SigningKey } from "@heliuslabs/zolana/keypair";
import { LocalKeys, type ProofService } from "@heliuslabs/zolana/client";
import { treeAddress } from "@heliuslabs/zolana/internal";
import { type Bytes32 } from "@heliuslabs/zolana/interface";
import { Data, SOL_MINT, Utxo, Wallet, AssetRegistry } from "@heliuslabs/zolana/transaction";
import {
  approveRingUnattended,
  type RingApprovalHandler,
  type RingApprovalRequest,
} from "../../../src/protocol/transaction/intent.js";
import { LocalRingKeys, ringWalletKeys, type RingKeys } from "../../../src/state/ring-keys.js";
import { address, type Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import {
  buildRingEntryTransaction,
  buildRingTransferTransaction,
  prepareRingEntryRelay,
  selectRingInputs,
} from "../../../src/operations/payments/transfer.js";
import { ringTransferClient } from "../../helpers/clients.js";
import { ringProgramConfigData, sppRingRegistration } from "../../helpers/ring-accounts.js";
import { signingKeySpendSigner } from "../../../src/operations/payments/anonymous.js";
import type { RingMode } from "../../../src/protocol/codec/ring-codecs.js";
import { ringConfigPda } from "../../../src/protocol/pda/index.js";
import { ViewingHistory } from "../../../src/state/viewing-history.js";

const TREE = treeAddress(0);
const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const RECIPIENT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const RING = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function spendingKeypair(): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
}

/** Unit tests never reach the prover; the keys still need one to exist. */
function stubProofs(): ProofService {
  return {
    prove: vi.fn(async () => {
      throw new Error("prove must not be called");
    }),
    proveMerge: vi.fn(async () => {
      throw new Error("proveMerge must not be called");
    }),
  };
}

function localKeys(keypair: ShieldedKeypair): LocalKeys & RingKeys {
  return ringWalletKeys(
    LocalKeys.fromKeypair(keypair, stubProofs()),
    LocalRingKeys.fromKeypair(keypair),
  );
}

/** Records every approval a build asks for and grants it. */
function recordingApproval(): Readonly<{
  approve: RingApprovalHandler;
  requests: RingApprovalRequest[];
}> {
  const requests: RingApprovalRequest[] = [];
  return {
    approve: (request) => {
      requests.push(request);
      return approveRingUnattended(request);
    },
    requests,
  };
}

function fundedWallet(
  keypair: ShieldedKeypair,
  amounts: readonly bigint[],
  options: Readonly<{ asset?: Address; ringProgramId?: Address }> = {},
): Wallet {
  const asset = options.asset ?? SOL_MINT;
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry(asset === SOL_MINT ? [] : [[2n, asset]]),
  });
  wallet._replace({
    utxos: amounts.map((amount, index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset,
        amount,
        blinding: new Uint8Array(32).fill(index + 1) as Bytes32,
        data: new Data(),
        ...(options.ringProgramId === undefined ? {} : { ringProgramId: options.ringProgramId }),
      }),
      outputContext: {
        hash: filled(index + 1),
        tree: TREE,
        leafIndex: BigInt(index),
      },
      nullifier: filled(index + 20),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

function ringUtxoWallet(
  keypair: ShieldedKeypair,
  utxos: readonly (readonly [bigint, Address | undefined, Address?])[],
): Wallet {
  const wallet = fundedWallet(keypair, []);
  wallet._replace({
    utxos: utxos.map(([amount, ringProgramId, tree], index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: filled(index + 1),
        data: new Data(),
        ...(ringProgramId === undefined ? {} : { ringProgramId }),
      }),
      outputContext: { hash: filled(index + 1), tree: tree ?? TREE, leafIndex: BigInt(index) },
      nullifier: filled(index + 20),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

/** The cap `refuses a cover wider than the input cap` runs into with six UTXOs. */
const INPUT_CAP = 5;

describe("selectRingInputs", () => {
  it("refuses a zero amount", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [[10n, RING]]);
    expect(() =>
      selectRingInputs({
        wallet: wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 0n,
        inputs: "ring",
        tree: TREE,
        maxInputs: INPUT_CAP,
      }),
    ).toThrow("RING_ZERO_AMOUNT");
  });

  it("keeps default UTXOs out of ring funding unless the entry opts in", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [10n, undefined],
      [10n, RING],
    ]);
    expect(() =>
      selectRingInputs({
        wallet: wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 15n,
        inputs: "ring",
        tree: TREE,
        maxInputs: INPUT_CAP,
      }),
    ).toThrow("RING_INSUFFICIENT_BALANCE");
    const selected = selectRingInputs({
      wallet: wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 15n,
      inputs: "ring-or-default",
      tree: TREE,
      maxInputs: INPUT_CAP,
    });
    expect(selected).toHaveLength(2);
  });

  it("funds a default-only entry even when a ring UTXO covers", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [100n, RING],
      [25n, undefined],
    ]);
    const selected = selectRingInputs({
      wallet: wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 25n,
      inputs: "default",
      tree: TREE,
      maxInputs: INPUT_CAP,
    });
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.ringProgramId).toBeUndefined();
    expect(() =>
      selectRingInputs({
        wallet: wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 30n,
        inputs: "default",
        tree: TREE,
        maxInputs: INPUT_CAP,
      }),
    ).toThrow("RING_INSUFFICIENT_BALANCE");
  });

  it("never offers a UTXO outside the requested tree", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [50n, RING, RECIPIENT],
      [20n, RING],
    ]);
    const selected = selectRingInputs({
      wallet: wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 20n,
      inputs: "ring",
      tree: TREE,
      maxInputs: INPUT_CAP,
    });
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.amount).toBe(20n);
    expect(() =>
      selectRingInputs({
        wallet: wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 30n,
        inputs: "ring",
        tree: TREE,
        maxInputs: INPUT_CAP,
      }),
    ).toThrow("RING_INSUFFICIENT_BALANCE");
  });

  it("covers a fragmented balance with the largest UTXO", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      ...Array.from({ length: 6 }, () => [5n, RING] as const),
      [100n, RING],
    ]);
    const selected = selectRingInputs({
      wallet: wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 100n,
      inputs: "ring",
      tree: TREE,
      maxInputs: INPUT_CAP,
    });
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.amount).toBe(100n);
  });

  it("refuses a cover wider than the input cap", () => {
    const wallet = ringUtxoWallet(
      spendingKeypair(),
      Array.from({ length: 6 }, () => [5n, RING] as const),
    );
    expect(() =>
      selectRingInputs({
        wallet: wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 30n,
        inputs: "ring",
        tree: TREE,
        maxInputs: INPUT_CAP,
      }),
    ).toThrow("RING_TOO_MANY_INPUTS");
  });

  it("never offers another ring's UTXOs under either mode", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [50n, RECIPIENT],
      [20n, undefined],
    ]);
    const selected = selectRingInputs({
      wallet: wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 20n,
      inputs: "ring-or-default",
      tree: TREE,
      maxInputs: INPUT_CAP,
    });
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.ringProgramId).toBeUndefined();
    expect(() =>
      selectRingInputs({
        wallet: wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 30n,
        inputs: "ring-or-default",
        tree: TREE,
        maxInputs: INPUT_CAP,
      }),
    ).toThrow("RING_INSUFFICIENT_BALANCE");
  });
});

describe("ring approval summary", () => {
  /** An active ring, every build reaches its approval and stops at the prover. */
  async function approvalClient(_keypair: ShieldedKeypair, mode: RingMode = "confidential") {
    const [config, bump] = await ringConfigPda(RING);
    const [ringAuth, registration] = await sppRingRegistration({
      authority: PAYER,
      ringProgramId: RING,
    });
    return ringTransferClient({
      tree: TREE,
      getAccount: async (address: Address) =>
        address === config
          ? {
              owner: RING,
              lamports: 1n,
              data: ringProgramConfigData({
                authority: PAYER,
                auditorPublicKey: X25519Keypair.fromBytes(new Uint8Array(32).fill(9))
                  .publicKey()
                  .toBytes(),
                bump,
                hasPolicy: false,
                mode,
              }),
            }
          : address === ringAuth
            ? registration
            : undefined,
    });
  }
  it("approves the exact amount moved into the ring", async () => {
    const keypair = spendingKeypair();
    const wallet = ringUtxoWallet(keypair, [[40n, undefined]]);
    const { approve, requests } = recordingApproval();

    await expect(
      buildRingEntryTransaction({
        client: await approvalClient(keypair),
        ringProgramId: RING,
        wallet,
        keys: localKeys(keypair),
        approve,
        feePayer: keypair.shieldedAddress().solanaAddress(),
        amount: 25n,
      }),
    ).rejects.toMatchObject({ code: "RING_BUILD_ENTRY" });
    expect(requests.map((request) => request.summary)).toEqual([
      `ring entry of 25 SOL into ring ${RING}`,
    ]);
    expect(requests[0]?.intent).toMatchObject({ kind: "ringEntry", amount: 25n });
  });

  async function capturedSummary(
    utxos: readonly (readonly [bigint, Address | undefined])[],
    amount: bigint,
    inputs: "ring" | "ring-or-default" | "default",
  ): Promise<string> {
    const keypair = spendingKeypair();
    const wallet = ringUtxoWallet(keypair, utxos);
    const { approve, requests } = recordingApproval();
    await expect(
      buildRingTransferTransaction({
        client: await approvalClient(keypair),
        ringProgramId: RING,
        wallet,
        keys: localKeys(keypair),
        approve,
        feePayer: keypair.shieldedAddress().solanaAddress(),
        recipient: ShieldedKeypair.generate().shieldedAddress(),
        amount,
        inputs,
      }),
    ).rejects.toMatchObject({ code: "RING_BUILD_TRANSFER" });
    const summary = requests[0]?.summary;
    if (summary === undefined) throw new Error("approval not requested");
    return summary;
  }

  /** An entry of `amount` into an anonymous ring out of nine default notes of 1000. */
  async function anonymousEntry(amount: bigint) {
    const keypair = spendingKeypair();
    const wallet = ringUtxoWallet(
      keypair,
      Array.from({ length: 9 }, () => [1_000n, undefined] as const),
    );
    const { approve, requests } = recordingApproval();
    const error: unknown = await prepareRingEntryRelay({
      client: await approvalClient(keypair, "anonymous"),
      ringProgramId: RING,
      wallet,
      keys: localKeys(keypair),
      approve,
      amount,
      anonymous: {
        quote: { feePayer: PAYER, validUntilSlot: 1n },
        nullifierKey: keypair.nullifierKey(),
        signer: signingKeySpendSigner(SigningKey.fromEd25519Bytes(filled(42))),
        history: ViewingHistory.create(keypair.shieldedAddress().viewingPublicKey, 0n),
      },
    }).catch((cause: unknown) => cause);
    return { error, requests };
  }

  it("funds an anonymous ring's entry from at most eight default notes, the entry key's bound", async () => {
    const eight = await anonymousEntry(8_000n);
    expect(eight.requests.map((request) => request.intent)).toMatchObject([
      { kind: "ringEntry", amount: 8_000n },
    ]);
    const nine = await anonymousEntry(8_001n);
    expect(nine.error).toMatchObject({
      code: "RING_BUILD_ENTRY",
      causeCode: "RING_TOO_MANY_INPUTS",
    });
    expect(nine.requests).toEqual([]);
  });

  it("names the whole default UTXO crossing into the ring, change included", async () => {
    const summary = await capturedSummary([[40n, undefined]], 25n, "default");
    expect(summary).toContain("ring entry of 25 SOL");
    expect(summary).toContain("moves 40 SOL of default UTXOs into the ring");
  });

  it("counts only the default share of mixed funding", async () => {
    const summary = await capturedSummary(
      [
        [30n, undefined],
        [10n, RING],
      ],
      35n,
      "ring-or-default",
    );
    expect(summary).toContain("ring entry of 35 SOL");
    expect(summary).toContain("moves 30 SOL of default UTXOs into the ring");
  });

  it("stays a transfer with no crossing clause on ring-only funding", async () => {
    const summary = await capturedSummary([[40n, RING]], 25n, "ring");
    expect(summary).toContain("ring transfer of 25 SOL");
    expect(summary).not.toContain("default UTXOs");
  });
});
