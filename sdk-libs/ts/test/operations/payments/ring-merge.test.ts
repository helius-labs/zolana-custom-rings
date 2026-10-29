import { bn254 } from "@noble/curves/bn254.js";
import {
  AccountRole,
  address,
  decompileTransactionMessage,
  getCompiledTransactionMessageDecoder,
  getTransactionSize,
  type Transaction,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { ClientError, LocalKeys, mergeProverRequestBody } from "@heliuslabs/zolana/client";
import { type RingMemberRecordResult } from "../../../src/rpc/ports.js";
import type {
  MergeAssembler,
  ProofService,
  WalletKeys,
  NonInclusionProof,
  SpendProof,
} from "@heliuslabs/zolana/client";
import {
  bigintToBytes,
  assembleMergeWithProofs,
  prepareProverMerge,
  compressG2,
  hashBytes,
  encodeMergeTransactInstructionData,
  Reader,
  addressBytes,
  treeAddress,
  mergeDummyNullifier,
  mergeOutputBlinding,
  mergeOutputKey,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import { MAX_MERGE_INPUTS, InstructionTag } from "@heliuslabs/zolana/interface";
import type {
  Address,
  Bytes32,
  Bytes64,
  Bytes128,
  MergeTransactInstructionData,
} from "@heliuslabs/zolana/interface";
import { mergePrivateTxBlinding, ShieldedKeypair, X25519Keypair } from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  SOL_MINT,
  Data,
  Merge,
  PreparedMerge,
  privateTxHash,
  ProofInputUtxo,
  Utxo,
  approveUnattended,
  intentHash,
  Wallet,
} from "@heliuslabs/zolana/transaction";
import type { RingMemberProofRequest, RingSecretProver } from "../../../src/rpc/ports.js";
import type { RingProofRequest } from "../../../src/rpc/prover/ring.js";
import {
  ringAuthAddress,
  ringCoSignerAddress,
  ringConfigPda,
  ringMemberRegistryPda,
} from "../../../src/protocol/pda/index.js";
import {
  RING_COSIGN_TRANSFERS,
  type RingCoSigner,
} from "../../../src/protocol/codec/ring-codecs.js";
import {
  MAX_RING_MERGE_INPUTS,
  buildRingMergeTransaction,
  ringMergeInstruction,
} from "../../../src/operations/payments/merge.js";
import {
  mergeDisclosureFieldCount,
  openRingMergeDisclosure,
  readRingMergeDisclosure,
  ringMergeAnonymousPublicInputHash,
  type RingMergeDisclosureRequest,
} from "../../../src/crypto/audit/merge-disclosure.js";
import { escrowKeyHash } from "../../../src/protocol/membership/member-opening.js";
import { ListId, recordBit } from "../../../src/protocol/membership/policy.js";
import { BLOCKHASH } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { stateTree } from "../../helpers/state-tree.js";
import { recordTree, type FixtureRecord } from "../../helpers/member-registry.js";
import {
  memberRegistryData,
  ownedAccount,
  ringCoSignerAccount,
  ringProgramConfigData,
} from "../../helpers/ring-accounts.js";
import { decompressG2 } from "../../../src/protocol/codec/codecs.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
/** The registry's newest root sits at this history slot. */
const ROOT_SLOT = 3;
/** Pays an anonymous ring's merge, the hidden owner signs nothing public. */
const RELAYER = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
function field(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}
await initializePoseidon();
const owner = ShieldedKeypair.generate();
const mergeAuditor = X25519Keypair.generate();
const OWNER_MEMBER = owner.signingPublicKey().ownerProofInputHash();
const SEALED_CIPHERTEXT = field(0x5e);

/** The owner's record escrowing `nullifierPk`, or holding no key on an anonymous ring. */
function ownerRecord(escrow: "own" | "foreign" | "none"): FixtureRecord {
  if (escrow === "none") return { member: OWNER_MEMBER, lists: 0n };
  const nullifierPk = escrow === "own" ? owner.nullifierPublicKey() : field(77);
  return {
    member: OWNER_MEMBER,
    lists: recordBit(ListId.escrow),
    escrowKey: escrowKeyHash({ nullifierPk, ciphertext: SEALED_CIPHERTEXT }),
    sealed: {
      owner: owner.shieldedAddress().solanaAddress(),
      nullifierPk,
      ephemeralPublicKey: mergeAuditor.publicKey(),
      ciphertext: SEALED_CIPHERTEXT,
    },
  };
}

function input(
  amount: bigint,
  ringProgramId: Address = RING,
  data = new Data(),
  ringDataHash?: Bytes32,
): ProofInputUtxo {
  return ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: owner.signingPublicKey(),
      asset: SOL_MINT,
      amount,
      blinding: field(Number(amount)),
      ringProgramId,
      data,
    }),
    owner,
    ringDataHash === undefined ? {} : { ringDataHash },
    7,
  );
}
function merge(
  inputs: readonly ProofInputUtxo[],
  outputTreeId = 7,
  outputDataHash?: Bytes32,
): Merge {
  const first = inputs[0];
  if (first === undefined) throw new Error("empty fixture");
  const key = owner.nullifierKey();
  try {
    return new Merge({
      address: owner.shieldedAddress(),
      inputs,
      outputTreeId,
      ring: { programId: RING, ...(outputDataHash === undefined ? {} : { outputDataHash }) },
      outputBlinding: mergeOutputBlinding(key, first.nullifier()),
      privateTxBlinding: mergePrivateTxBlinding(key, first.nullifier()),
      dummyNullifiers: PreparedMerge.dummySlots(inputs.length).map((slot) =>
        mergeDummyNullifier(key, first.nullifier(), slot),
      ),
      outputKey: mergeOutputKey(key, first.nullifier()),
    });
  } finally {
    key.destroy();
  }
}
function nonInclusion(leaf: Bytes32): NonInclusionProof {
  return {
    leaf,
    merkleContext: { tree: treeAddress(7), treeType: 1 },
    path: Array.from({ length: 40 }, () => field(0)),
    lowElement: field(0),
    lowElementIndex: 0n,
    highElement: field(255),
    highElementIndex: 1n,
    root: field(2),
    rootSeq: 1n,
    rootIndex: 0,
  };
}
/** The spends as the leaves of one tree, in order. */
function spendProofs(spends: readonly ProofInputUtxo[]): SpendProof[] {
  const state = stateTree(spends.map((spend) => spend.hash()));
  return spends.map((spend, index) => ({
    state: {
      leaf: spend.hash(),
      merkleContext: { tree: treeAddress(7), treeType: 0 },
      path: state.path(index),
      leafIndex: BigInt(index),
      root: state.root,
      rootSeq: 1n,
      rootIndex: 0,
    },
    nullifier: nonInclusion(spend.nullifier()),
  }));
}

function ringWallet(amounts: readonly bigint[], hashes: readonly Bytes32[] = []): Wallet {
  const wallet = new Wallet({ identity: owner.shieldedAddress(), registry: new AssetRegistry() });
  wallet._replace({
    utxos: amounts.map((amount, index) => {
      const proof = input(amount, RING, new Data(), hashes[index]);
      return {
        utxo: proof.utxo,
        outputContext: {
          hash: proof.hash(),
          tree: treeAddress(7),
          treeId: 7,
          leafIndex: BigInt(index),
        },
        nullifier: proof.nullifier(),
        ...(proof.ringDataHash === undefined ? {} : { ringDataHash: proof.ringDataHash }),
        spent: false,
      };
    }),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}
function provenMerge(
  prepared: PreparedMerge,
  b: Bytes128 = new Uint8Array(128) as Bytes128,
): MergeTransactInstructionData {
  return prepareProverMerge(prepared, treeAddress(7))
    .finish({
      slot: { id: 7, utxoRoot: field(1), nullifierRoot: field(2) },
      utxoRootIndex: 0,
      nullifierRootIndex: 0,
    })
    .instructionData({ a: field(0), b, c: field(0) });
}
/** Rust `CustomRingMergeIxData::serialize`, the SPP body with `proof.b` compressed. */
function compactBody(data: MergeTransactInstructionData): Uint8Array {
  const body = encodeMergeTransactInstructionData(data);
  return Uint8Array.from([
    ...body.subarray(0, 40),
    ...compressG2(body.slice(40, 168) as Bytes128),
    ...body.subarray(168),
  ]);
}
/** A G2 point off the zero placeholder, its compression keeps a sign flag. */
function g2Point(): Bytes128 {
  const point = bn254.G2.Point.BASE.multiply(5n).toAffine();
  return Uint8Array.from(
    [point.x.c1, point.x.c0, point.y.c1, point.y.c0].flatMap((value) => [
      ...bigintToBytes(value, "g2"),
    ]),
  ) as Bytes128;
}
function zeroRingProof() {
  const zero = (length: number) => new Uint8Array(length);
  return {
    a: zero(64) as Bytes64,
    b: zero(128) as Bytes128,
    c: zero(64) as Bytes64,
    commitment: zero(64) as Bytes64,
    commitmentPok: zero(64) as Bytes64,
  };
}
function proofService(): ProofService {
  return { prove: vi.fn(), proveMerge: vi.fn() };
}

/** A key holder reached only through `WalletKeys`, the disclosure proof answered beside it. */
function remote(
  keys: LocalKeys,
  asked: RingMergeDisclosureRequest[] = [],
): WalletKeys & RingSecretProver {
  return {
    address: () => keys.address(),
    viewingPublicKeys: () => keys.viewingPublicKeys(),
    decrypt: (requests) => keys.decrypt(requests),
    derive: (requests) => keys.derive(requests),
    transactionKeys: (requests) => keys.transactionKeys(requests),
    prove: (inputs, context) => keys.prove(inputs, context),
    proveMerge: (inputs, context) => keys.proveMerge(inputs, context),
    proveRingWithSecret: async (request) => {
      asked.push(request);
      return zeroRingProof();
    },
  };
}

async function ringMergeParams({
  proveMerge,
  wallet,
  keys,
  proofDataSource,
  anonymous = true,
  escrow = anonymous ? "none" : "own",
  coSigner,
}: Readonly<{
  proveMerge: MergeAssembler["proveMerge"];
  wallet: Wallet;
  keys: WalletKeys & Partial<RingSecretProver>;
  proofDataSource: "client" | "prover";
  anonymous?: boolean;
  escrow?: "own" | "foreign" | "none";
  coSigner?: RingCoSigner;
}>) {
  const tree = recordTree([ownerRecord(escrow)]);
  const [config, configBump] = await ringConfigPda(RING);
  const [registry, registryBump] = await ringMemberRegistryPda(RING);
  return {
    client: {
      proofDataSource,
      tree: treeAddress(7),
      treeId: 7,
      getAccount: async (account: Address) => {
        if (coSigner !== undefined) {
          const [record, stored] = await ringCoSignerAccount(RING, coSigner);
          if (account === record) return stored;
        }
        if (account === config)
          return ownedAccount(
            RING,
            ringProgramConfigData({
              authority: RING,
              auditorPublicKey: mergeAuditor.publicKey().toBytes(),
              bump: configBump,
              hasPolicy: false,
              mode: anonymous ? "anonymous" : "confidentialEscrow",
              ...(coSigner === undefined ? {} : { coSigner }),
            }),
          );
        if (account === registry)
          return ownedAccount(
            RING,
            memberRegistryData({
              bump: registryBump,
              history: Array.from({ length: ROOT_SLOT + 1 }, (_, slot) =>
                slot === ROOT_SLOT ? { root: tree.root, applied: 4n, slot: 9n } : undefined,
              ),
              historyCursor: ROOT_SLOT,
              nextIndex: tree.nextIndex,
            }),
          );
        return undefined;
      },
      getRingMemberRecord: async (
        request: RingMemberProofRequest,
      ): Promise<RingMemberRecordResult> => ({
        context: { slot: 1n, blockTime: 1n },
        root: { root: tree.root, rootIndex: ROOT_SLOT, applied: 4n, nextIndex: tree.nextIndex },
        opening: tree.opening(request.member),
      }),
      getLatestBlockhash: async () => BLOCKHASH,
      proveMerge,
      proveRing: vi.fn<(request: RingProofRequest) => Promise<Uint8Array>>(),
    },
    ringProgramId: RING,
    wallet,
    keys,
    feePayer: anonymous ? RELAYER : owner.shieldedAddress().solanaAddress(),
  };
}

function ringCall(transaction: Transaction) {
  const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
  if (compiled.version !== 1) throw new Error("expected V1");
  const instruction = decompileTransactionMessage(compiled, {
    lastValidBlockHeight: 1n,
  }).instructions.find((candidate) => candidate.programAddress === RING);
  if (instruction?.data === undefined) throw new Error("no ring instruction");
  return instruction;
}

function ringInstruction(transaction: Transaction): Uint8Array {
  return Uint8Array.from(ringCall(transaction).data ?? []);
}

function ringAccounts(transaction: Transaction): readonly Address[] {
  return (ringCall(transaction).accounts ?? []).map((account) => account.address);
}

describe("ring merge", () => {
  it("refuses an escrow-mode merge before any selection, read or proof", async () => {
    const wallet = ringWallet([3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>();
    const local = LocalKeys.fromKeypair(owner, proofService());
    const derive = vi.spyOn(local, "derive");
    try {
      const params = await ringMergeParams({
        proveMerge,
        wallet,
        keys: local,
        proofDataSource: "client",
        anonymous: false,
      });
      const getRingMemberRecord = vi.fn(params.client.getRingMemberRecord);
      await expect(
        buildRingMergeTransaction({
          ...params,
          client: { ...params.client, getRingMemberRecord },
        }),
      ).rejects.toMatchObject({
        code: "RING_BUILD_MERGE",
        causeCode: "RING_ESCROW_MERGE_UNVERIFIED",
      });
      expect(proveMerge).not.toHaveBeenCalled();
      expect(getRingMemberRecord).not.toHaveBeenCalled();
      expect(derive).not.toHaveBeenCalled();
      expect(wallet._reservationEntries()).toHaveLength(0);
    } finally {
      local.destroy();
    }
  });

  it("refuses a forged output and retries a lagging prover indexer", async () => {
    const wallet = ringWallet([3n, 5n]);
    const answers: ("forged" | "lagging" | "proof")[] = ["forged", "lagging", "proof"];
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const answer = answers.shift();
      if (answer === "lagging") throw new ClientError("CLIENT_INDEXER_PROOF_DATA_NOT_READY");
      const data = provenMerge(prepared);
      return {
        data: answer === "forged" ? { ...data, outputUtxoHash: field(9) } : data,
        outputHash: data.outputUtxoHash,
      };
    });
    const local = LocalKeys.fromKeypair(owner, proofService());
    const keys = remote(local);
    const build = async (proofDataSource: "client" | "prover") =>
      buildRingMergeTransaction(
        await ringMergeParams({ proveMerge, wallet, keys, proofDataSource }),
      );
    try {
      await expect(build("client")).rejects.toMatchObject({
        code: "RING_BUILD_MERGE",
        causeCode: "RING_INTENT_MISMATCH",
      });
      await expect(build("prover")).resolves.toBeDefined();
      expect(proveMerge).toHaveBeenCalledTimes(3);
    } finally {
      local.destroy();
    }
  });

  it("caps custom merges at 49 before any read", async () => {
    const wallet = ringWallet(Array.from({ length: 50 }, (_, index) => BigInt(index + 1)));
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>();
    const keys = LocalKeys.fromKeypair(owner, proofService());
    const derive = vi.spyOn(keys, "derive");
    const params = await ringMergeParams({ proveMerge, wallet, keys, proofDataSource: "client" });
    const getAccount = vi.fn(params.client.getAccount);
    const build = (maxInputs: number) =>
      buildRingMergeTransaction({ ...params, client: { ...params.client, getAccount }, maxInputs });
    try {
      expect(MAX_RING_MERGE_INPUTS).toBe(49);
      for (const [maxInputs, causeCode] of [
        [50, "RING_TOO_MANY_INPUTS"],
        [1, "RING_NOTHING_TO_MERGE"],
        [2.5, "RING_NOTHING_TO_MERGE"],
        [Number.NaN, "RING_NOTHING_TO_MERGE"],
      ] as const) {
        await expect(build(maxInputs)).rejects.toMatchObject({
          code: "RING_BUILD_MERGE",
          causeCode,
        });
      }
      expect(proveMerge).not.toHaveBeenCalled();
      expect(derive).not.toHaveBeenCalled();
      expect(getAccount).not.toHaveBeenCalled();
      expect(wallet._reservationEntries()).toHaveLength(0);
    } finally {
      keys.destroy();
    }
  });

  it("demands the transfer co-signer and sizes the transaction with it before proving", async () => {
    const wallet = ringWallet(Array.from({ length: 24 }, (_, index) => BigInt(index + 1)));
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const data = provenMerge(prepared);
      return { data, outputHash: data.outputUtxoHash };
    });
    const local = LocalKeys.fromKeypair(owner, proofService());
    const cosigner = treeAddress(19);
    const params = await ringMergeParams({
      proveMerge,
      wallet,
      keys: remote(local),
      proofDataSource: "client",
      coSigner: { signer: cosigner, scope: RING_COSIGN_TRANSFERS },
    });
    const approve = vi.fn(approveUnattended);
    try {
      await expect(buildRingMergeTransaction({ ...params, maxInputs: 2 })).rejects.toMatchObject({
        code: "RING_BUILD_MERGE",
        causeCode: "RING_COSIGNER_REQUIRED",
      });
      const transaction = await buildRingMergeTransaction({
        ...params,
        maxInputs: 24,
        cosigner,
        approve,
      });
      expect(getTransactionSize(transaction)).toBeLessThanOrEqual(4096);
      expect(proveMerge).toHaveBeenCalledOnce();
      expect(approve).toHaveBeenCalledOnce();
      expect(wallet._reservationEntries()).toHaveLength(1);
    } finally {
      local.destroy();
    }
  });

  it.each([
    [2, 8],
    [8, 8],
    [9, 24],
    [24, 24],
    [25, 52],
    [52, 52],
  ])("preserves owner, asset, value and ring for %s fragmented inputs", (count, width) => {
    const inputs = Array.from({ length: count }, (_, index) => input(BigInt(index + 1)));
    const prepared = merge(inputs).prepare();
    expect(prepared.inputs).toHaveLength(width);
    expect(prepared.inputs.map((spend) => spend.isCompact())).toEqual(
      Array.from({ length: width }, (_, index) => index >= count),
    );
    expect(provenMerge(prepared).nullifiers).toHaveLength(count);
    expect(prepared.output.amount).toBe(BigInt((count * (count + 1)) / 2));
    expect(prepared.output.asset).toBe(SOL_MINT);
    expect(prepared.output.ringProgramId).toBe(RING);
    expect(prepared.output.ownerAddress?.toBytes()).toEqual(owner.shieldedAddress().toBytes());
    expect(prepared.outputTreeId).toBe(7);
  });

  it.each([2, 25, 52])("zeroes padding in the private tx hash of a %i-input merge", (count) => {
    const inputs = Array.from({ length: count }, (_, index) => input(BigInt(index + 1)));
    const prepared = merge(inputs).prepare();
    const assembly = assembleMergeWithProofs(
      prepared,
      spendProofs(inputs),
      treeAddress(7),
      prepared.dummyNullifiers().map(nonInclusion),
    );
    expect(assembly.privateTxHash).toEqual(
      privateTxHash({
        inputHashes: prepared.inputs.map((spend) =>
          spend.isDummy() ? (new Uint8Array(32) as Bytes32) : spend.hash(),
        ),
        outputHashes: [assembly.outputHash],
        blinding: prepared.privateTxBlinding(),
      }),
    );
  });

  it("binds a separate output tree and a zero output ring data hash", () => {
    const inputs = [input(3n), input(5n)];
    const prepared = merge(inputs, 9).prepare();
    const assembly = assembleMergeWithProofs(
      prepared,
      spendProofs(inputs),
      treeAddress(7),
      prepared.dummyNullifiers().map(nonInclusion),
    );
    expect(mergeProverRequestBody(assembly.proverInputs)).toMatchObject({
      circuitType: "merge-ring",
    });
    expect(assembly.proverInputs.ringProgramId).not.toBe(0n);
    expect(assembly.proverInputs.outputRingDataHash).toBe(0n);
    expect(assembly.outputHash).toEqual(prepared.output.hash(9));
    expect(assembly.outputHash).not.toEqual(prepared.output.hash(7));
  });

  it("refuses foreign rings, owner data, and more than 52 inputs", () => {
    expect(() => merge([input(3n), input(5n, treeAddress(1))])).toThrow(
      "TRANSACTION_MERGE_INPUT_RING_MISMATCH",
    );
    expect(() =>
      merge([input(3n, RING, new Data([{ kind: "utxoData", bytes: Uint8Array.of(1) }]))]),
    ).toThrow("TRANSACTION_MERGE_INPUT_HAS_DATA");
    expect(() =>
      merge(Array.from({ length: MAX_MERGE_INPUTS + 1 }, (_, index) => input(BigInt(index + 1)))),
    ).toThrow("TRANSACTION_TOO_MANY_INPUTS");
  });

  it("keeps the ordinary merge rail closed to ring notes", () => {
    expect(() => Merge.fromKeypair(owner, [input(3n)])).toThrow(
      "TRANSACTION_MERGE_INPUT_RING_MISMATCH",
    );
  });

  it("compresses proof b and places the registry and the co-signer ahead of SPP's accounts", async () => {
    const inputs = [input(3n), input(5n)];
    const data = provenMerge(merge(inputs).prepare(), g2Point());
    const cosigner = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
    const instruction = await ringMergeInstruction({
      ringProgramId: RING,
      inputTree: treeAddress(7),
      outputTree: treeAddress(7),
      payer: owner.shieldedAddress().solanaAddress(),
      cosigner,
      outputRingDataHash: field(4),
      registryRootIndex: 11,
      data,
    });
    const bytes = instruction.data ?? new Uint8Array();
    expect(instruction.programAddress).toBe(RING);
    expect(bytes[0]).toBe(InstructionTag.ringMergeTransact);
    expect(bytes[1]).toBe(11);
    expect(bytes.slice(2, 34)).toEqual(field(4));
    expect(bytes[34]).toBe(0);
    const body = bytes.slice(35);
    expect(body).toEqual(compactBody(data));
    expect(body.length).toBe(encodeMergeTransactInstructionData(data).length - 64);
    expect(decompressG2(body.slice(40, 104) as Bytes64)).toEqual(data.proof.b);
    const [config] = await ringConfigPda(RING);
    const [registry] = await ringMemberRegistryPda(RING);
    expect(instruction.accounts?.slice(0, 4)).toEqual([
      { address: config, role: AccountRole.READONLY },
      { address: registry, role: AccountRole.READONLY },
      { address: await ringCoSignerAddress(RING, cosigner), role: AccountRole.READONLY },
      { address: cosigner, role: AccountRole.READONLY_SIGNER },
    ]);
    expect(instruction.accounts?.[6]).toEqual({
      address: await ringAuthAddress(RING),
      role: AccountRole.READONLY,
    });
    expect(instruction.accounts).toHaveLength(10 + inputs.length);
    const without = await ringMergeInstruction({
      ringProgramId: RING,
      inputTree: treeAddress(7),
      outputTree: treeAddress(7),
      payer: owner.shieldedAddress().solanaAddress(),
      outputRingDataHash: field(4),
      registryRootIndex: 11,
      data,
    });
    expect(without.accounts?.slice(2)).toEqual(instruction.accounts?.slice(4));
  });

  it("binds ring identity and destination into approval", () => {
    const intent = {
      kind: "ringMerge" as const,
      ringProgramId: RING,
      outputTree: treeAddress(7),
      asset: SOL_MINT,
      numInputs: 2,
      mergedAmount: 8n,
    };
    expect(intentHash(intent)).not.toEqual(
      intentHash({ ...intent, ringProgramId: treeAddress(1) }),
    );
    expect(intentHash(intent)).not.toEqual(intentHash({ ...intent, outputTree: treeAddress(9) }));
  });
});

describe("anonymous ring merge", () => {
  it("proves the disclosure at a remote key holder and ships it in the instruction", async () => {
    const wallet = ringWallet([3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const data = provenMerge(prepared);
      return { data, outputHash: data.outputUtxoHash };
    });
    const local = LocalKeys.fromKeypair(owner, proofService());
    const asked: RingMergeDisclosureRequest[] = [];
    const keys = remote(local, asked);
    try {
      const transaction = await buildRingMergeTransaction(
        await ringMergeParams({
          proveMerge,
          wallet,
          keys,
          proofDataSource: "client",
          anonymous: true,
        }),
      );
      const [request] = asked;
      if (request?.kind !== "anonymousMerge") throw new Error("no disclosure request");
      expect(request).not.toHaveProperty("nullifierSecret");
      // The sealing secrets are wiped once the proof is back.
      expect(request.ephSk.every((byte) => byte === 0)).toBe(true);
      expect(request.disclosureKey.every((byte) => byte === 0)).toBe(true);
      expect(request).toMatchObject({
        ringProgramId: hashBytes(addressBytes(RING)),
        ownerKey: owner.signingPublicKey().ed25519(),
      });
      expect(request).not.toHaveProperty("memberRegistryRoot");
      expect(request).not.toHaveProperty("memberRecord");
      expect(request.inputs).toHaveLength(8);

      const data = ringInstruction(transaction);
      expect(data[0]).toBe(InstructionTag.ringMergeTransact);
      expect(data[1]).toBe(0);
      const [config] = await ringConfigPda(RING);
      expect(ringAccounts(transaction).slice(0, 2)).toEqual([config, treeAddress(7)]);
      const disclosure = readRingMergeDisclosure(new Reader(data.slice(34)));
      if (disclosure === undefined) throw new Error("no disclosure");
      expect(disclosure.proof).toEqual(new Uint8Array(192));
      expect(disclosure.fields).toHaveLength(mergeDisclosureFieldCount(8));
      const prepared = proveMerge.mock.calls[0]?.[0].prepared;
      if (prepared === undefined) throw new Error("no merge");
      const spp = provenMerge(prepared);
      expect(data.slice(34 + 1 + 192 + 33 + 32 + 1 + 32 * 13)).toEqual(compactBody(spp));
      expect(
        ringMergeAnonymousPublicInputHash({
          partyIdentities: request.partyIdentities,
          privateTxHash: spp.privateTxHash,
          outputUtxoHash: spp.outputUtxoHash,
          firstNullifier: spp.nullifiers[0]!,
          ringId: hashBytes(addressBytes(RING)) as Bytes32,
          auditorPublicKey: mergeAuditor.publicKey(),
          disclosure,
          salt: prepared.outputCiphertextSalt(),
        }),
      ).toEqual(request.publicInputHash);
      const opened = openRingMergeDisclosure(
        mergeAuditor,
        disclosure,
        prepared.outputCiphertextSalt(),
      );
      expect(opened.amount).toBe(8n);
      expect(opened.mint).toBe(SOL_MINT);
      expect(opened.nullifierPublicKey).toEqual(owner.nullifierPublicKey());
      expect(opened.inputCommitments.slice(0, 2)).toEqual(
        prepared.inputs.slice(0, 2).map((spend) => spend.hash()),
      );
    } finally {
      local.destroy();
    }
  });

  it("refuses a merge the hidden owner pays or co-signs before any proof", async () => {
    const wallet = ringWallet([3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>();
    const local = LocalKeys.fromKeypair(owner, proofService());
    const hidden = owner.shieldedAddress().solanaAddress();
    try {
      for (const coSigned of [false, true]) {
        const params = await ringMergeParams({
          proveMerge,
          wallet,
          keys: local,
          proofDataSource: "client",
          anonymous: true,
          ...(coSigned ? { coSigner: { signer: hidden, scope: RING_COSIGN_TRANSFERS } } : {}),
        });
        await expect(
          buildRingMergeTransaction({
            ...params,
            ...(coSigned ? { cosigner: hidden } : { feePayer: hidden }),
          }),
        ).rejects.toMatchObject({
          code: "RING_BUILD_MERGE",
          causeCode: "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
        });
      }
      expect(proveMerge).not.toHaveBeenCalled();
      expect(wallet._reservationEntries()).toHaveLength(0);
    } finally {
      local.destroy();
    }
  });

  it("refuses a 52-slot anonymous merge before any read or proof", async () => {
    const wallet = ringWallet(Array.from({ length: 25 }, (_, index) => BigInt(index + 1)));
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>();
    const local = LocalKeys.fromKeypair(owner, proofService());
    const derive = vi.spyOn(local, "derive");
    const keys = remote(local);
    const proveRingWithSecret = vi.spyOn(keys, "proveRingWithSecret");
    try {
      const params = await ringMergeParams({
        proveMerge,
        wallet,
        keys,
        proofDataSource: "client",
        anonymous: true,
      });
      const getRingMemberRecord = vi.fn(params.client.getRingMemberRecord);
      await expect(
        buildRingMergeTransaction({
          ...params,
          client: { ...params.client, getRingMemberRecord },
          maxInputs: 49,
        }),
      ).rejects.toMatchObject({
        code: "RING_BUILD_MERGE",
        causeCode: "RING_ANONYMOUS_MERGE_TOO_WIDE",
      });
      expect(proveMerge).not.toHaveBeenCalled();
      expect(proveRingWithSecret).not.toHaveBeenCalled();
      expect(getRingMemberRecord).not.toHaveBeenCalled();
      expect(derive).not.toHaveBeenCalled();
      expect(wallet._reservationEntries()).toHaveLength(0);
    } finally {
      local.destroy();
    }
  });
});
