import { ShieldedKeypair, SigningKey, type ShieldedAddress } from "@heliuslabs/spr/keypair";
import { LocalKeys, type ProofService } from "@heliuslabs/spr/client";
import { SHIELDED_POOL_PROGRAM_ID, treeAddress } from "@heliuslabs/spr/internal";
import { type Bytes32 } from "@heliuslabs/spr/interface";
import { Data, SOL_MINT, Utxo, Wallet, AssetRegistry } from "@heliuslabs/spr/transaction";
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
  createRingTransferSubmission,
  prepareRingEntryRelay,
  selectRingInputs,
} from "../../../src/operations/payments/transfer.js";
import { treeAccount } from "../../../../../zolana/sdk-libs/ts/test/helpers/tree-account.js";
import { ringTransferClient } from "../../helpers/clients.js";
import { trackingTree } from "../../helpers/member-registry.js";
import {
  ringPolicyData,
  sppRingRegistration,
  trackingAuthorizations,
  trackingRegistryAccount,
} from "../../helpers/ring-accounts.js";
import { TRACKING_REVISION, trackingEntry } from "../../helpers/ring-pipeline.js";
import { signingKeySpendSigner } from "../../../src/operations/payments/anonymous.js";
import type { RingMode } from "../../../src/protocol/codec/ring-codecs.js";
import { ringPolicyPda } from "../../../src/protocol/pda/index.js";
import { zeroKeyNullifier } from "../../../src/state/exposed-notes.js";

const TREE = treeAddress(0);
const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const RECIPIENT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const RING = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");
const TRACKING = address("Cura111111111111111111111111111111111111111");

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
        maxInputs: INPUT_CAP,
      }),
    ).toThrow("RING_INSUFFICIENT_BALANCE");
    const selected = selectRingInputs({
      wallet: wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 15n,
      inputs: "ring-or-default",
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
        maxInputs: INPUT_CAP,
      }),
    ).toThrow("RING_INSUFFICIENT_BALANCE");
  });

  it("selects the largest default note and returns change", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [40n, undefined],
      [15n, undefined],
      [10n, undefined],
      [40n, RING],
      [15n, RING],
      [10n, RING],
    ]);
    const amounts = (inputs: "ring" | "default" | "entry") =>
      selectRingInputs({
        wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 25n,
        inputs,
        maxInputs: INPUT_CAP,
      }).map((entry) => [entry.utxo.amount, entry.utxo.ringProgramId]);
    expect(amounts("default")).toEqual([[40n, undefined]]);
    expect(amounts("entry")).toEqual(amounts("default"));
    expect(amounts("ring")).toEqual([[40n, RING]]);
  });

  it("pays ten from six on each of two trees", () => {
    const second = treeAddress(1);
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [6n, RING],
      [6n, RING, second],
    ]);
    const selected = selectRingInputs({
      wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 10n,
      inputs: "ring",
      maxInputs: INPUT_CAP,
    });
    expect(selected.map((entry) => entry.outputContext.tree).sort()).toEqual([TREE, second].sort());
  });

  it("selects larger notes across trees before smaller notes on one tree", () => {
    const second = treeAddress(1);
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [6n, RING],
      [6n, RING, second],
      [4n, RING, second],
    ]);
    const selected = selectRingInputs({
      wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 10n,
      inputs: "ring",
      maxInputs: INPUT_CAP,
    });
    expect(selected.map((entry) => entry.outputContext.tree)).toEqual([TREE, second]);
  });

  it("refuses a spend only three trees cover", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [4n, RING],
      [4n, RING, treeAddress(1)],
      [4n, RING, treeAddress(2)],
    ]);
    expect(() =>
      selectRingInputs({
        wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 10n,
        inputs: "ring",
        maxInputs: INPUT_CAP,
      }),
    ).toThrow("RING_TOO_MANY_INPUT_TREES");
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
        maxInputs: INPUT_CAP,
      }),
    ).toThrow("RING_INSUFFICIENT_BALANCE");
  });
});

describe("ring approval summary", () => {
  /** An active ring holding `enrolled`, a build past its approval stops at the prover. */
  async function approvalClient(
    enrolled: readonly ShieldedAddress[],
    mode: RingMode = "confidential",
  ) {
    const tracked = trackingTree(enrolled.map((owner) => trackingEntry(owner)));
    const authorizations = await trackingAuthorizations(TRACKING, enrolled);
    const [ring, bump] = await ringPolicyPda(RING);
    const [ringAuth, registration] = await sppRingRegistration({
      authority: PAYER,
      ringProgramId: RING,
    });
    return ringTransferClient({
      tree: TREE,
      getAccount: async (address: Address) =>
        address === ring
          ? { owner: RING, lamports: 1n, data: ringPolicyData({ bump, mode, tracking: TRACKING }) }
          : address === ringAuth
            ? registration
            : address === TRACKING
              ? trackingRegistryAccount({
                  root: tracked.root,
                  revision: TRACKING_REVISION,
                  nextIndex: tracked.nextIndex,
                  auditorPubkey: new Uint8Array(33),
                })
              : address === TREE
                ? {
                    owner: SHIELDED_POOL_PROGRAM_ID,
                    lamports: 1n,
                    data: treeAccount({
                      stateCursor: 0,
                      written: 0,
                      nullifierCursor: 0n,
                      treeId: 0,
                    }),
                  }
                : authorizations.get(address),
      getTrackingRecordPool: async (request) => tracked.pool(request.members, request.openings),
    });
  }
  /** An entry of 25 from one default note of 40, the approval stops it before the prover. */
  async function entryOf25From40(approve: RingApprovalHandler) {
    const keypair = spendingKeypair();
    return buildRingEntryTransaction({
      client: await approvalClient([keypair.shieldedAddress()]),
      ringProgramId: RING,
      wallet: ringUtxoWallet(keypair, [[40n, undefined]]),
      keys: localKeys(keypair),
      approve,
      feePayer: keypair.shieldedAddress().solanaAddress(),
      amount: 25n,
    });
  }

  it("approves all 40 an entry of 25 moves into the ring, its change included", async () => {
    const { approve, requests } = recordingApproval();
    await expect(entryOf25From40(approve)).rejects.toMatchObject({
      code: "RING_BUILD_ENTRY",
      cause: { message: expect.stringContaining("proveRingTransact must not be called") },
    });
    expect(requests.map((request) => request.summary)).toEqual([
      `ring entry of 40 SOL into ring ${RING}, 15 SOL of it as change`,
    ]);
    expect(requests[0]?.intent).toMatchObject({ kind: "ringEntry", amount: 40n });
  });

  it("refuses an approval of the 25 alone while the 15 change enters the ring", async () => {
    const approvedShort: RingApprovalHandler = (request) =>
      approveRingUnattended({
        ...request,
        intent: { kind: "ringEntry", ringProgramId: RING, asset: SOL_MINT, amount: 25n },
      });
    await expect(entryOf25From40(approvedShort)).rejects.toMatchObject({
      code: "RING_BUILD_ENTRY",
      causeCode: "RING_INTENT_MISMATCH",
    });
  });

  it("proves a ring transfer of ten from six on each of two trees", async () => {
    const keypair = spendingKeypair();
    const second = treeAddress(1);
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const client = await approvalClient([keypair.shieldedAddress(), recipient]);
    const first = await client.getAccount(TREE);
    if (first === undefined) throw new Error("tree 0 published");
    const data = first.data.slice();
    new DataView(data.buffer).setUint16(2, 1, true);
    let proved: readonly number[] | undefined;
    await expect(
      buildRingTransferTransaction({
        client: {
          ...client,
          getAccount: async (address: Address) =>
            address === second ? { ...first, data } : client.getAccount(address),
          proveRingTransact: async (inputs) => {
            proved = inputs.inputTreeIds();
            throw new Error("stopped at the prover");
          },
          proveRing: async () => {
            throw new Error("stopped at the prover");
          },
        },
        ringProgramId: RING,
        wallet: ringUtxoWallet(keypair, [
          [6n, RING],
          [6n, RING, second],
        ]),
        keys: localKeys(keypair),
        feePayer: keypair.shieldedAddress().solanaAddress(),
        recipient,
        amount: 10n,
      }),
    ).rejects.toMatchObject({ cause: { message: "stopped at the prover" } });
    expect(proved).toEqual([0, 1]);
  });

  it.each(["confidential", "anonymous"] as const)(
    "never selects a zero-key note on the public owner route of a %s ring",
    async (mode) => {
      const keypair = spendingKeypair();
      const recipient = ShieldedKeypair.generate().shieldedAddress();
      const wallet = ringUtxoWallet(keypair, [
        [6n, RING],
        [25n, RING],
      ]);
      const [keyed, zero] = wallet.utxos();
      if (keyed === undefined || zero === undefined) throw new Error("two notes");
      wallet._replace({
        utxos: [
          keyed,
          { ...zero, nullifier: zeroKeyNullifier(zero.outputContext.hash, zero.utxo.blinding) },
        ],
        transactions: [],
        nullifiers: new Set(),
      });
      await expect(
        createRingTransferSubmission({
          client: await approvalClient([keypair.shieldedAddress(), recipient], mode),
          ringProgramId: RING,
          wallet,
          keys: localKeys(keypair),
          feePayer: keypair.shieldedAddress().solanaAddress(),
          recipient,
          amount: 10n,
          spendPublic: { wallet: keypair.shieldedAddress().solanaAddress(), reply: null },
        }),
      ).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_UNFUNDED_PAST_EXPOSURE",
      });
    },
  );

  async function capturedSummary(
    utxos: readonly (readonly [bigint, Address | undefined])[],
    amount: bigint,
    inputs: "ring" | "ring-or-default" | "default",
  ): Promise<string> {
    const keypair = spendingKeypair();
    const wallet = ringUtxoWallet(keypair, utxos);
    const { approve, requests } = recordingApproval();
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    await expect(
      buildRingTransferTransaction({
        client: await approvalClient([keypair.shieldedAddress(), recipient]),
        ringProgramId: RING,
        wallet,
        keys: localKeys(keypair),
        approve,
        feePayer: keypair.shieldedAddress().solanaAddress(),
        recipient,
        amount,
        inputs,
      }),
    ).rejects.toMatchObject({ code: "RING_BUILD_TRANSFER" });
    const summary = requests[0]?.summary;
    if (summary === undefined) throw new Error("approval not requested");
    return summary;
  }

  async function anonymousEntry(amount: bigint, notes: number) {
    const keypair = spendingKeypair();
    const wallet = ringUtxoWallet(
      keypair,
      Array.from({ length: notes }, () => [1_000n, undefined] as const),
    );
    const { approve, requests } = recordingApproval();
    const error: unknown = await prepareRingEntryRelay({
      client: await approvalClient([keypair.shieldedAddress()], "anonymous"),
      ringProgramId: RING,
      wallet,
      keys: localKeys(keypair),
      approve,
      amount,
      anonymous: {
        quote: { feePayer: PAYER, validUntilSlot: 1n },
        nullifierKey: keypair.nullifierKey(),
        signer: signingKeySpendSigner(SigningKey.fromEd25519Bytes(filled(42))),
      },
    }).catch((cause: unknown) => cause);
    return { error, requests };
  }

  it("types out a confidential entry relay, its in-proof owner refuses every default note", async () => {
    const keypair = spendingKeypair();
    const { approve, requests } = recordingApproval();
    await expect(
      prepareRingEntryRelay({
        client: await approvalClient([keypair.shieldedAddress()]),
        ringProgramId: RING,
        wallet: ringUtxoWallet(keypair, [[40n, undefined]]),
        keys: localKeys(keypair),
        approve,
        amount: 25n,
        // @ts-expect-error An entry relays on an anonymous ring alone.
        confidential: {
          quote: { feePayer: PAYER, validUntilSlot: 1n },
          nullifierKey: keypair.nullifierKey(),
          signer: signingKeySpendSigner(SigningKey.fromEd25519Bytes(filled(42))),
        },
      }),
    ).rejects.toMatchObject({
      code: "RING_BUILD_ENTRY",
      causeCode: "RING_IN_PROOF_DEFAULT_RING_INPUT",
    });
    expect(requests).toEqual([]);
  });

  it("takes an SPL entry with two SPL returns to approval on the anonymous rail", async () => {
    const keypair = spendingKeypair();
    const mint = address("Mint111111111111111111111111111111111111111");
    const { approve, requests } = recordingApproval();
    await prepareRingEntryRelay({
      client: await approvalClient([keypair.shieldedAddress()], "anonymous"),
      ringProgramId: RING,
      wallet: fundedWallet(keypair, [40n], { asset: mint }),
      keys: localKeys(keypair),
      approve,
      asset: mint,
      amount: 25n,
      anonymous: {
        quote: { feePayer: PAYER, validUntilSlot: 1n },
        nullifierKey: keypair.nullifierKey(),
        signer: signingKeySpendSigner(SigningKey.fromEd25519Bytes(filled(42))),
      },
    }).catch((cause: unknown) => cause);
    expect(requests.map((request) => request.intent)).toMatchObject([
      { kind: "ringEntry", amount: 40n },
    ]);
  });

  it("funds an anonymous ring's entry from at most 8 default notes, the widest entry key", async () => {
    const widest = await anonymousEntry(8_000n, 9);
    expect(widest.requests.map((request) => request.intent)).toMatchObject([
      { kind: "ringEntry", amount: 8_000n },
    ]);
    const past = await anonymousEntry(8_001n, 9);
    expect(past.error).toMatchObject({
      code: "RING_BUILD_ENTRY",
      causeCode: "RING_TOO_MANY_INPUTS",
    });
    expect(past.requests).toEqual([]);
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
