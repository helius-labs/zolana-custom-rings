import { longestFitting } from "../../../src/operations/payments/merge.js";
import { encodeBase58 } from "@heliuslabs/spr/internal";
import { fitsOneTransaction, transactionSize } from "../../../src/operations/workflow/compile.js";
import { bn254 } from "@noble/curves/bn254.js";
import {
  AccountRole,
  address,
  decompileTransactionMessage,
  getProgramDerivedAddress,
  getCompiledTransactionMessageDecoder,
  getTransactionSize,
  type Transaction,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { ClientError, LocalKeys, mergeProverRequestBody } from "@heliuslabs/spr/client";
import type {
  MergeAssembler,
  ProofService,
  WalletKeys,
  NonInclusionProof,
  SpendProof,
} from "@heliuslabs/spr/client";
import {
  bigintToBytes,
  bytesToBigInt,
  assembleMergeWithProofs,
  prepareProverMerge,
  compressG2,
  hashBytes,
  encodeMergeTransactInstructionData,
  addressBytes,
  treeAddress,
  mergeDummyNullifier,
  mergeOutputBlinding,
  mergeOutputKey,
  ZERO_32,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import { initializePoseidon } from "@heliuslabs/spr";
import { MAX_MERGE_INPUTS } from "@heliuslabs/spr/interface";
import type {
  Address,
  Bytes32,
  Bytes33,
  Bytes64,
  Bytes128,
  MergeTransactInstructionData,
  RequestContext,
} from "@heliuslabs/spr/interface";
import {
  mergePrivateTxBlinding,
  NullifierKey,
  type Bytes31,
  ShieldedKeypair,
  ViewingKey,
  X25519Keypair,
} from "@heliuslabs/spr/keypair";
import { ShieldedPda } from "@heliuslabs/spr/program";
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
  assetField,
} from "@heliuslabs/spr/transaction";
import type { MergeProofRequest, RingProofRequest } from "../../../src/rpc/prover/ring.js";
import { ringAuthAddress, ringPolicyPda } from "../../../src/protocol/pda/index.js";
import { LocalRingKeys, ringWalletKeys, type RingKeys } from "../../../src/state/ring-keys.js";
import { extended } from "../../../src/operations/workflow/extended.js";
import type { RingMode } from "../../../src/protocol/codec/ring-codecs.js";
import {
  MAX_RING_MERGE_INPUTS,
  buildRingMergeTransaction,
  ringMergeInstruction,
} from "../../../src/index.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import { RecordKind } from "../../../src/protocol/codec/audit-stream.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../../../src/protocol/proof/custom-ring-proof.js";
import {
  decodeRingMergeRequest,
  MergeRingAuthority,
  mergePublicInputHash,
  nullifierKeyMergeSealer,
  openMergeRecord,
  type RingMergeDisclosureRequest,
  type RingMergeSealer,
} from "../../../src/crypto/audit/merge-disclosure.js";
import { AnonymousSync } from "../../../src/state/anonymous-sync.js";
import { AnonymousWallet } from "../../../src/state/anonymous-wallet.js";
import { ViewingHistory } from "../../../src/state/viewing-history.js";
import { checkRetainedEntries } from "../../../src/operations/workflow/submission.js";
import { zeroKeyNullifier } from "../../../src/state/exposed-notes.js";
import type { TrackingOpeningsRequest } from "../../../src/protocol/indexer/tracking-codec.js";
import type { TrackingEntry } from "../../../src/protocol/membership/tracking.js";
import type { RingMergeTransactionParams } from "../../../src/operations/payments/merge.js";
import { BLOCKHASH } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { stateTree } from "../../helpers/state-tree.js";
import { notImplemented } from "../../helpers/clients.js";
import { trackingTree } from "../../helpers/member-registry.js";
import {
  ownedAccount,
  ringPolicyData,
  trackingRegistryAccount,
} from "../../helpers/ring-accounts.js";
import {
  PROOF_SERVICE,
  TRACKING_REVISION,
  trackingEntry,
  walletKeys,
} from "../../helpers/ring-pipeline.js";
import { decompressG2 } from "../../../src/protocol/codec/codecs.js";
import { OPENING_RECORD_LEN } from "../../../src/protocol/codec/ring-disclosure-layout.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
/** Rust `WIDEST_MERGE`, the keyed merge one v1 transaction carries. */
const WIDEST_MERGE = 45;
/** Rust `WIDEST_ZERO_KEY_MERGE`, the owner signature and account narrow it. */
const WIDEST_ZERO_KEY_MERGE = 44;
/** Pays every merge, the merge circuit refuses the owner as payer. */
const RELAYER = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
function field(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}
await initializePoseidon();
const owner = ShieldedKeypair.generate();
const RECORDS = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
const TRACKING = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
const mergeAuditor = X25519Keypair.generate();
const OWNER_MEMBER = owner.signingPublicKey().ownerProofInputHash();
const PROOF = new Uint8Array(CUSTOM_RING_PROOF_LENGTH).fill(7);

function ownerRows(enrolled: "own" | "foreign" | "none") {
  if (enrolled === "none") return [];
  const row = trackingEntry(owner.shieldedAddress());
  return [enrolled === "own" ? row : { ...row, nullifierPk: field(77) }];
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
function proofService(): ProofService {
  return { prove: vi.fn(), proveMerge: vi.fn() };
}

/** A key holder reached only through `WalletKeys` and its merge sealer. */
function remote(
  keys: LocalKeys,
  asked: RingMergeDisclosureRequest[] = [],
  proven: MergeProofRequest[] = [],
): WalletKeys & RingMergeSealer {
  const sealer = nullifierKeyMergeSealer({
    nullifierKey: owner.nullifierKey(),
    prover: {
      proveRing: async (request) => {
        if (request.kind === "merge") proven.push(request);
        return PROOF;
      },
    },
  });
  return {
    address: () => keys.address(),
    viewingPublicKeys: () => keys.viewingPublicKeys(),
    decrypt: (requests) => keys.decrypt(requests),
    derive: (requests) => keys.derive(requests),
    transactionKeys: (requests) => keys.transactionKeys(requests),
    prove: (inputs, context) => keys.prove(inputs, context),
    proveMerge: (inputs, context) => keys.proveMerge(inputs, context),
    sealRingMerge: (request, context) => {
      asked.push(request);
      return sealer.sealRingMerge(request, context);
    },
  };
}

function zeroKeyWallet(
  owner: Pick<ShieldedKeypair, "signingPublicKey" | "shieldedAddress">,
  amounts: readonly bigint[],
): Wallet {
  const utxos = amounts.map((amount) => {
    const utxo = new Utxo({
      owner: owner.signingPublicKey(),
      asset: SOL_MINT,
      amount,
      blinding: field(Number(amount)),
      ringProgramId: RING,
    });
    const hash = utxo.proofInput(ZERO_NULLIFIER_PK, 7).hash();
    return { utxo, hash, nullifier: zeroKeyNullifier(hash, utxo.blinding) };
  });
  const wallet = new Wallet({ identity: owner.shieldedAddress(), registry: new AssetRegistry() });
  wallet._replace({
    utxos: utxos.map(({ utxo, hash, nullifier }, index) => ({
      utxo,
      outputContext: { hash, tree: treeAddress(7), treeId: 7, leafIndex: BigInt(index) },
      nullifier,
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

/** A program's PDA owner with role keys and no signing secret. */
async function pdaOwner(): Promise<ShieldedPda> {
  const [pda] = await getProgramDerivedAddress({ programAddress: RING, seeds: ["owner"] });
  return ShieldedPda.withViewingKey(
    pda,
    NullifierKey.fromSecret(new Uint8Array(31).fill(3) as Bytes31),
    ViewingKey.generate(),
  );
}

function pdaKeys(holder: ShieldedPda): LocalKeys & RingKeys {
  const viewing = holder.viewingKey();
  const nullifierKey = holder.nullifierKey();
  try {
    const roles = { address: holder.shieldedAddress(), viewingKeys: [viewing], nullifierKey };
    return ringWalletKeys(
      LocalKeys.fromKeys(roles, PROOF_SERVICE),
      LocalRingKeys.fromKeys({ ...roles, listRoot: viewing }),
    );
  } finally {
    viewing.destroy();
    nullifierKey.destroy();
  }
}

async function ringMergeParams({
  proveMerge,
  wallet,
  keys,
  proofDataSource,
  anonymous = true,
  mode = anonymous ? "anonymous" : "confidential",
  enrolled = "own",
  rows = ownerRows(enrolled),
}: Readonly<{
  proveMerge: MergeAssembler["proveMerge"];
  wallet: Wallet;
  keys: RingMergeTransactionParams["keys"];
  proofDataSource: "client" | "prover";
  anonymous?: boolean;
  mode?: RingMode;
  enrolled?: "own" | "foreign" | "none";
  /** Tracking rows of an owner other than the shared fixture owner. */
  rows?: readonly TrackingEntry[];
}>) {
  const tracked = trackingTree(rows);
  const [policy, policyBump] = await ringPolicyPda(RING);
  return {
    client: {
      proofDataSource,
      tree: treeAddress(7),
      treeId: 7,
      getAccount: async (account: Address) => {
        if (account === policy)
          return ownedAccount(
            RING,
            ringPolicyData({
              bump: policyBump,
              auditorPublicKey: mergeAuditor.publicKey().toBytes(),
              mode,
              records: RECORDS,
              tracking: TRACKING,
            }),
          );
        if (account === TRACKING)
          return trackingRegistryAccount({
            root: tracked.root,
            revision: TRACKING_REVISION,
            nextIndex: tracked.nextIndex,
            auditorPubkey: mergeAuditor.publicKey().toBytes(),
          });
        return undefined;
      },
      getStorageMemberOpenings: vi.fn(notImplemented("getStorageMemberOpenings")),
      getTrackingOpenings: vi.fn(async (request: TrackingOpeningsRequest) => ({
        slot: 1n,
        root: tracked.root,
        revision: TRACKING_REVISION,
        openings: request.members.map((member) => tracked.opening(member)),
      })),
      getLatestBlockhash: async () => BLOCKHASH,
      proveMerge,
      proveRing: vi.fn(async (_request: RingProofRequest) => PROOF),
    },
    ringProgramId: RING,
    wallet,
    keys,
    feePayer: RELAYER,
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
  it.each([false, true])(
    "refuses unchecked recovery notes before a merge proof with zero key %s",
    async (mergeZeroKey) => {
      const wallet = mergeZeroKey ? zeroKeyWallet(owner, [3n, 5n]) : ringWallet([3n, 5n]);
      const keys = walletKeys(owner);
      const tracked = AnonymousWallet.create(
        wallet,
        ViewingHistory.create(owner.viewingPublicKey(), 0n).withRing(RING),
      );
      const empty = async () => ({
        context: { slot: 100n, blockTime: 0n },
        data: [],
        paginationToken: null,
      });
      const source = {
        getEncryptedUtxosByTags: empty,
        getShieldedTransactionsByTags: empty,
        getShieldedTransactionsByNullifiers: empty,
      };
      try {
        const retained = wallet.utxos();
        expect(() => checkRetainedEntries(wallet, retained)).not.toThrow();
        const sync = AnonymousSync.create(keys, wallet.registry).withScanLimits({ maxPages: 1 });
        await tracked.absorb(await sync.fetchWallet(source, tracked));
        expect(tracked.recoveryCoverage().status).toBe("Paused");
        expect(tracked.notes().map((note) => tracked.noteState(note))).toEqual([
          "pendingSpendCheck",
          "pendingSpendCheck",
        ]);
        expect(tracked.balances().get(SOL_MINT)).toBeUndefined();
        expect(tracked.exposedNotes()).toEqual([]);
        const proveMerge = vi.fn<MergeAssembler["proveMerge"]>();
        const params = await ringMergeParams({
          proveMerge,
          wallet,
          keys,
          proofDataSource: "client",
          anonymous: false,
        });
        const build = mergeZeroKey
          ? buildRingMergeTransaction({ ...params, mergeZeroKey: true })
          : buildRingMergeTransaction(params);
        await expect(build).rejects.toMatchObject({
          code: "RING_BUILD_MERGE",
          causeCode: "RING_SYNC_INCOMPLETE",
        });
        expect(proveMerge).not.toHaveBeenCalled();
        expect(params.client.proveRing).not.toHaveBeenCalled();
        expect(wallet._reservationEntries()).toHaveLength(0);
        expect(() => checkRetainedEntries(wallet, retained)).toThrow("RING_SYNC_INCOMPLETE");
        await tracked.absorb(await sync.fetchWallet(source, tracked));
        expect(tracked.recoveryCoverage().status).toBe("Paused");
        expect(() => checkRetainedEntries(wallet, retained)).not.toThrow();
        expect(tracked.notes().map((note) => tracked.noteState(note))).toEqual(
          Array(2).fill(mergeZeroKey ? "exposedIfSpent" : "spendable"),
        );
        expect(tracked.balances().get(SOL_MINT)).toEqual(
          mergeZeroKey
            ? { spendable: 0n, exposedIfSpent: 8n }
            : { spendable: 8n, exposedIfSpent: 0n },
        );
      } finally {
        keys.destroy();
      }
    },
  );

  it("proves a merge under the owner's tracking row", async () => {
    const wallet = ringWallet([3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const data = provenMerge(prepared);
      return { data, outputHash: data.outputUtxoHash };
    });
    const local = LocalKeys.fromKeypair(owner, proofService());
    const asked: RingMergeDisclosureRequest[] = [];
    const keys = remote(local, asked);
    try {
      const params = await ringMergeParams({
        proveMerge,
        wallet,
        keys,
        proofDataSource: "client",
        anonymous: false,
      });
      const transaction = await buildRingMergeTransaction(params);
      expect(params.client.getTrackingOpenings).toHaveBeenCalledTimes(1);
      const [request] = asked;
      if (request?.kind !== "merge") throw new Error("no disclosure request");
      expect(request.trackingRoot).toEqual(trackingTree(ownerRows("own")).root);
      expect(request.nullifierPk).toEqual(owner.nullifierPublicKey());
      expect(request.tracking?.kind).toBe("present");
      if (request.tracking?.kind !== "present") throw new Error("no tracking row");
      expect(request.tracking.record.nullifierPk).toEqual(owner.nullifierPublicKey());
      const merged = decodeRingMergeRequest(ringInstruction(transaction).subarray(1));
      expect(merged.trackingRevision).toBe(TRACKING_REVISION);
      expect(merged.authority).toBe(MergeRingAuthority.ring);
    } finally {
      local.destroy();
    }
  });

  it("refuses a merge of an owner off its tracking row before any proof", async () => {
    for (const [enrolled, causeCode] of [
      ["foreign", "RING_ADDRESS_MISMATCH"],
      ["none", "RING_RECIPIENT_NOT_ENROLLED"],
    ] as const) {
      const wallet = ringWallet([3n, 5n]);
      const proveMerge = vi.fn<MergeAssembler["proveMerge"]>();
      const local = LocalKeys.fromKeypair(owner, proofService());
      const keys = remote(local);
      const sealRingMerge = vi.spyOn(keys, "sealRingMerge");
      try {
        const params = await ringMergeParams({
          proveMerge,
          wallet,
          keys,
          proofDataSource: "client",
          anonymous: false,
          enrolled,
        });
        await expect(buildRingMergeTransaction(params)).rejects.toMatchObject({
          code: "RING_BUILD_MERGE",
          causeCode,
        });
        expect(proveMerge).not.toHaveBeenCalled();
        expect(sealRingMerge).not.toHaveBeenCalled();
        expect(wallet._reservationEntries()).toHaveLength(0);
      } finally {
        local.destroy();
      }
    }
  });

  it("reads no record and names only the tracking registry, a merge runs no rules", async () => {
    const wallet = ringWallet([3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const data = provenMerge(prepared);
      return { data, outputHash: data.outputUtxoHash };
    });
    const local = LocalKeys.fromKeypair(owner, proofService());
    try {
      const params = await ringMergeParams({
        proveMerge,
        wallet,
        keys: remote(local),
        proofDataSource: "client",
        anonymous: false,
        mode: "confidential",
      });
      const transaction = await buildRingMergeTransaction(params);
      expect(params.client.getStorageMemberOpenings).not.toHaveBeenCalled();
      const [ring] = await ringPolicyPda(RING);
      expect(ringAccounts(transaction).slice(0, 3)).toEqual([ring, TRACKING, treeAddress(7)]);
      expect(ringAccounts(transaction)).not.toContain(RECORDS);
    } finally {
      local.destroy();
    }
  });

  it("trims past the address ceiling under the byte limit", async () => {
    const account = (seed: number) => {
      const bytes = new Uint8Array(32).fill(0xaa);
      new DataView(bytes.buffer).setUint32(0, seed);
      return encodeBase58(bytes) as Address;
    };
    const discard = vi.fn();
    const fitted = await longestFitting({
      count: 52,
      minimum: 2,
      prepare: async (count) => ({
        programAddress: account(2),
        accounts: Array.from({ length: count + 12 }, (_, seed) => ({
          address: account(100 + seed),
          role: AccountRole.WRITABLE,
        })),
      }),
      fits: async (instruction) => {
        const size = transactionSize({
          feePayer: account(1),
          instructions: [instruction],
          computeUnitLimit: 1_000_000,
        });
        expect(size.bytes).toBeLessThan(4096);
        return fitsOneTransaction(size);
      },
      discard,
    });
    expect(fitted.count).toBe(50);
    expect(discard).toHaveBeenCalledTimes(2);
  });

  it("trims a zero-key merge to its narrower width, Rust `WIDEST_ZERO_KEY_MERGE`", async () => {
    const owner = ShieldedKeypair.generate();
    const wallet = zeroKeyWallet(
      owner,
      Array.from({ length: 52 }, (_, index) => BigInt(index + 1)),
    );
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const data = provenMerge(prepared);
      return { data, outputHash: data.outputUtxoHash };
    });
    const params = await ringMergeParams({
      proveMerge,
      wallet,
      keys: walletKeys(owner),
      proofDataSource: "client",
      anonymous: false,
      enrolled: "none",
    });
    const transaction = await buildRingMergeTransaction({
      ...params,
      mergeZeroKey: true,
      maxInputs: 52,
    });
    expect(getTransactionSize(transaction)).toBeLessThanOrEqual(4096);
    const [reservation] = wallet._reservationEntries();
    expect(reservation?.utxoHashes).toHaveLength(WIDEST_ZERO_KEY_MERGE);
  });

  it("publishes the owner of a zero-key merge under a zero root and reads no row", async () => {
    const wallet = zeroKeyWallet(owner, [3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared, keys }) => {
      const { payload } = prepareProverMerge(prepared, treeAddress(7)).inputs;
      expect(payload.mergeSeed ?? 0n).not.toBe(0n);
      expect(payload.publishedOwner).toBe(
        bytesToBigInt(owner.signingPublicKey().ownerProofInputHash()),
      );
      expect(payload.userNullifierSecret).toBe(0n);
      await expect(
        keys.proveMerge({
          ...payload,
          treeSlots: [],
          publicInputHash: payload.privateTxHash,
        } as never),
      ).rejects.toThrow("unused proof service");
      const data = provenMerge(prepared);
      return { data, outputHash: data.outputUtxoHash };
    });
    const params = await ringMergeParams({
      proveMerge,
      wallet,
      keys: walletKeys(owner),
      proofDataSource: "client",
      anonymous: false,
      enrolled: "none",
    });
    const transaction = await buildRingMergeTransaction({ ...params, mergeZeroKey: true });
    expect(params.client.getStorageMemberOpenings).not.toHaveBeenCalled();
    expect(params.client.getTrackingOpenings).not.toHaveBeenCalled();
    const request = params.client.proveRing.mock.calls[0]?.[0];
    if (request?.kind !== "merge") throw new Error("no disclosure request");
    expect(request.trackingRoot).toEqual(ZERO_32);
    expect(request.nullifierPk).toEqual(ZERO_NULLIFIER_PK);
    expect(request).not.toHaveProperty("tracking");
    const merged = decodeRingMergeRequest(ringInstruction(transaction).subarray(1));
    expect(merged.trackingRevision).toBe(0n);
    expect(merged.authority).toBe(MergeRingAuthority.ownerSigned);
    expect(request.publicInputHash).toEqual(
      mergePublicInputHash({
        outputUtxoHash: request.outputUtxoHash,
        firstNullifier: request.firstNullifier,
        ringId: request.ringProgramId,
        auditorPubkey: mergeAuditor.publicKey().toBytes(),
        ephemeralPublicKey: merged.sealed.ephemeralPublicKey,
        ciphertext: merged.sealed.ciphertext,
        payer: request.payer,
        publishedOwner: OWNER_MEMBER,
        trackingRoot: ZERO_32,
      }),
    );
    const accounts = ringAccounts(transaction);
    const [ring] = await ringPolicyPda(RING);
    expect(accounts.slice(0, 2)).toEqual([ring, TRACKING]);
    // `[ring, tracking]` ahead of SPP's list, Rust `RING_MERGE_OWNER_INDEX` 6.
    expect(accounts[2 + 6]).toBe(owner.shieldedAddress().solanaAddress());
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

  it("caps ring merges at the widest SPP merge before any read", async () => {
    const wallet = ringWallet(Array.from({ length: 50 }, (_, index) => BigInt(index + 1)));
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>();
    const keys = LocalKeys.fromKeypair(owner, proofService());
    const derive = vi.spyOn(keys, "derive");
    const params = await ringMergeParams({ proveMerge, wallet, keys, proofDataSource: "client" });
    const getAccount = vi.fn(params.client.getAccount);
    const build = (maxInputs: number) =>
      buildRingMergeTransaction({ ...params, client: { ...params.client, getAccount }, maxInputs });
    try {
      expect(MAX_RING_MERGE_INPUTS).toBe(52);
      for (const [maxInputs, causeCode] of [
        [53, "RING_TOO_MANY_INPUTS"],
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

  it("trims to the longest prefix one transaction carries, Rust `FittedMerge`", async () => {
    const wallet = ringWallet(Array.from({ length: 52 }, (_, index) => BigInt(index + 1)));
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const data = provenMerge(prepared);
      return { data, outputHash: data.outputUtxoHash };
    });
    const local = LocalKeys.fromKeypair(owner, proofService());
    const params = await ringMergeParams({
      proveMerge,
      wallet,
      keys: remote(local),
      proofDataSource: "client",
    });
    const approve = vi.fn(approveUnattended);
    try {
      const transaction = await buildRingMergeTransaction({
        ...params,
        maxInputs: WIDEST_MERGE + 1,
        approve,
      });
      expect(getTransactionSize(transaction)).toBeLessThanOrEqual(4096);
      expect(proveMerge).toHaveBeenCalledOnce();
      expect(approve).toHaveBeenCalledOnce();
      const [reservation] = wallet._reservationEntries();
      expect(reservation?.utxoHashes).toHaveLength(WIDEST_MERGE);
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

  it("compresses proof b and places the ring policy and the tracking registry ahead of SPP's accounts", async () => {
    const inputs = [input(3n), input(5n)];
    const data = provenMerge(merge(inputs).prepare(), g2Point());
    const sealed = {
      proof: PROOF,
      ephemeralPublicKey: new Uint8Array(33).fill(1) as Bytes33,
      ciphertext: new Uint8Array(OPENING_RECORD_LEN).fill(2),
    };
    const payer = owner.shieldedAddress().solanaAddress();
    const instruction = await ringMergeInstruction({
      ringProgramId: RING,
      inputTree: treeAddress(7),
      outputTree: treeAddress(7),
      payer,
      outputRingDataHash: field(4),
      sealed,
      tracking: TRACKING,
      trackingRevision: 11n,
      data,
    });
    const bytes = instruction.data ?? new Uint8Array();
    expect(instruction.programAddress).toBe(RING);
    expect(bytes[0]).toBe(RingInstructionTag.merge);
    expect(bytes.slice(1, 9)).toEqual(Uint8Array.of(11, 0, 0, 0, 0, 0, 0, 0));
    expect(bytes.slice(9, 41)).toEqual(field(4));
    const request = decodeRingMergeRequest(bytes.subarray(1));
    expect(request.authority).toBe(MergeRingAuthority.ring);
    expect(request.sealed).toEqual(sealed);
    const body = request.compactBody;
    expect(body).toEqual(compactBody(data));
    expect(body.length).toBe(encodeMergeTransactInstructionData(data).length - 64);
    expect(decompressG2(body.slice(40, 104) as Bytes64)).toEqual(data.proof.b);
    const [ring] = await ringPolicyPda(RING);
    expect(instruction.accounts?.slice(0, 2)).toEqual([
      { address: ring, role: AccountRole.READONLY },
      { address: TRACKING, role: AccountRole.READONLY },
    ]);
    expect(instruction.accounts?.[4]).toEqual({
      address: await ringAuthAddress(RING),
      role: AccountRole.READONLY,
    });
    expect(instruction.accounts?.[5]).toEqual({
      address: payer,
      role: AccountRole.WRITABLE_SIGNER,
    });
    expect(instruction.accounts).toHaveLength(8 + inputs.length);
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
  it("proves the sealed record at a remote key holder and ships it in the instruction", async () => {
    const wallet = ringWallet([3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const data = provenMerge(prepared);
      return { data, outputHash: data.outputUtxoHash };
    });
    const local = LocalKeys.fromKeypair(owner, proofService());
    const asked: RingMergeDisclosureRequest[] = [];
    const proven: MergeProofRequest[] = [];
    const keys = remote(local, asked, proven);
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
      const [sealing] = asked;
      if (sealing === undefined) throw new Error("no disclosure request");
      // The seed stays at the holder.
      expect(sealing).not.toHaveProperty("seed");
      const [request] = proven;
      if (request === undefined) throw new Error("no merge proof request");
      // The sealing secrets are wiped once the proof is back.
      expect(request.ephSk.every((byte) => byte === 0)).toBe(true);
      expect(request.seed.every((byte) => byte === 0)).toBe(true);
      expect(request).toMatchObject({
        ringProgramId: hashBytes(addressBytes(RING)),
        ownerKey: owner.signingPublicKey().ed25519(),
        ownerPkHash: OWNER_MEMBER,
        asset: assetField(SOL_MINT),
      });

      const data = ringInstruction(transaction);
      expect(data[0]).toBe(RingInstructionTag.merge);
      const merged = decodeRingMergeRequest(data.subarray(1));
      expect(merged.trackingRevision).toBe(TRACKING_REVISION);
      expect(merged.sealed.proof).toEqual(PROOF);
      const [ring] = await ringPolicyPda(RING);
      expect(ringAccounts(transaction).slice(0, 3)).toEqual([ring, TRACKING, treeAddress(7)]);
      const prepared = proveMerge.mock.calls[0]?.[0].prepared;
      if (prepared === undefined) throw new Error("no merge");
      const spp = provenMerge(prepared);
      expect(merged.compactBody).toEqual(compactBody(spp));
      expect(
        mergePublicInputHash({
          outputUtxoHash: spp.outputUtxoHash,
          firstNullifier: spp.nullifiers[0]!,
          ringId: hashBytes(addressBytes(RING)) as Bytes32,
          auditorPubkey: mergeAuditor.publicKey().toBytes(),
          ephemeralPublicKey: merged.sealed.ephemeralPublicKey,
          ciphertext: merged.sealed.ciphertext,
          payer: request.payer,
          publishedOwner: ZERO_32,
          trackingRoot: request.trackingRoot,
        }),
      ).toEqual(request.publicInputHash);
      const opened = openMergeRecord(mergeAuditor, merged.sealed);
      expect(opened.record).toEqual({
        kind: RecordKind.ring,
        amount: 8n,
        ownerKey: owner.signingPublicKey().ed25519(),
        mint: SOL_MINT,
        nullifierPk: owner.nullifierPublicKey(),
      });
      const secret = owner.nullifierKey().secretBytes();
      expect(opened.secret).toEqual(Uint8Array.of(0, ...secret));
    } finally {
      local.destroy();
    }
  });

  it("refuses a merge the hidden owner pays before any proof", async () => {
    const wallet = ringWallet([3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>();
    const local = LocalKeys.fromKeypair(owner, proofService());
    const hidden = owner.shieldedAddress().solanaAddress();
    try {
      // The merge circuit keeps a keyed owner off the payer on every ring.
      for (const anonymous of [true, false]) {
        const params = await ringMergeParams({
          proveMerge,
          wallet,
          keys: local,
          proofDataSource: "client",
          anonymous,
        });
        await expect(
          buildRingMergeTransaction({ ...params, feePayer: hidden }),
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
});

describe("PDA owner merge", () => {
  it("merges a PDA's zero-key notes, the PDA signs as the published owner", async () => {
    const holder = await pdaOwner();
    const pda = holder.shieldedAddress().solanaAddress();
    const wallet = zeroKeyWallet(holder, [3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const data = provenMerge(prepared);
      return { data, outputHash: data.outputUtxoHash };
    });
    const params = await ringMergeParams({
      proveMerge,
      wallet,
      keys: pdaKeys(holder),
      proofDataSource: "client",
      enrolled: "none",
    });
    const transaction = await buildRingMergeTransaction({ ...params, mergeZeroKey: true });
    const request = params.client.proveRing.mock.calls[0]?.[0];
    if (request?.kind !== "merge") throw new Error("no disclosure request");
    expect(request.ownerKey).toEqual(addressBytes(pda));
    const merged = decodeRingMergeRequest(ringInstruction(transaction).subarray(1));
    expect(merged.authority).toBe(MergeRingAuthority.ownerSigned);
    expect(request.publicInputHash).toEqual(
      mergePublicInputHash({
        outputUtxoHash: request.outputUtxoHash,
        firstNullifier: request.firstNullifier,
        ringId: request.ringProgramId,
        auditorPubkey: mergeAuditor.publicKey().toBytes(),
        ephemeralPublicKey: merged.sealed.ephemeralPublicKey,
        ciphertext: merged.sealed.ciphertext,
        payer: request.payer,
        publishedOwner: holder.signingPublicKey().ownerProofInputHash(),
        trackingRoot: ZERO_32,
      }),
    );
    expect(openMergeRecord(mergeAuditor, merged.sealed).record.ownerKey).toEqual(addressBytes(pda));
    // The owning program signs the owner account through CPI, Rust `RING_MERGE_OWNER_INDEX` 6.
    expect(ringCall(transaction).accounts?.[2 + 6]).toEqual({
      address: pda,
      role: AccountRole.READONLY_SIGNER,
    });
  });

  it("merges a PDA's keyed notes under its tracking row with no owner signer", async () => {
    const holder = await pdaOwner();
    const owner = holder.shieldedAddress();
    const wallet = new Wallet({ identity: owner, registry: new AssetRegistry() });
    wallet._replace({
      utxos: [3n, 5n].map((amount, index) => {
        const proof = ProofInputUtxo.fromKeypair(
          new Utxo({
            owner: owner.signingPublicKey,
            asset: SOL_MINT,
            amount,
            blinding: field(Number(amount)),
            ringProgramId: RING,
          }),
          holder,
          {},
          7,
        );
        return {
          utxo: proof.utxo,
          outputContext: {
            hash: proof.hash(),
            tree: treeAddress(7),
            treeId: 7,
            leafIndex: BigInt(index),
          },
          nullifier: proof.nullifier(),
          spent: false,
        };
      }),
      transactions: [],
      nullifiers: new Set(),
    });
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const data = provenMerge(prepared);
      return { data, outputHash: data.outputUtxoHash };
    });
    const keys = pdaKeys(holder);
    const asked: RingMergeDisclosureRequest[] = [];
    const sealer = nullifierKeyMergeSealer({
      nullifierKey: holder.nullifierKey(),
      prover: { proveRing: async () => PROOF },
    });
    const transaction = await buildRingMergeTransaction(
      await ringMergeParams({
        proveMerge,
        wallet,
        keys: extended(keys, {
          sealRingMerge: (request: RingMergeDisclosureRequest, context?: RequestContext) => {
            asked.push(request);
            return sealer.sealRingMerge(request, context);
          },
        }),
        proofDataSource: "client",
        rows: [trackingEntry(owner)],
      }),
    );
    const pda = addressBytes(owner.solanaAddress());
    expect(asked[0]?.ownerKey).toEqual(pda);
    const merged = decodeRingMergeRequest(ringInstruction(transaction).subarray(1));
    expect(merged.authority).toBe(MergeRingAuthority.ring);
    expect(openMergeRecord(mergeAuditor, merged.sealed).record.ownerKey).toEqual(pda);
    expect(ringAccounts(transaction)).not.toContain(owner.solanaAddress());
  });

  it("refuses a PDA paying its keyed merge and a zero-key merge another account signs", async () => {
    const holder = await pdaOwner();
    const pda = holder.shieldedAddress().solanaAddress();
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>();
    const params = await ringMergeParams({
      proveMerge,
      wallet: zeroKeyWallet(holder, [3n, 5n]),
      keys: pdaKeys(holder),
      proofDataSource: "client",
    });
    await expect(buildRingMergeTransaction({ ...params, feePayer: pda })).rejects.toMatchObject({
      code: "RING_BUILD_MERGE",
      causeCode: "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
    });
    await expect(
      buildRingMergeTransaction({ ...params, mergeZeroKey: true, ownerSigner: RELAYER }),
    ).rejects.toMatchObject({ code: "RING_BUILD_MERGE", causeCode: "RING_MERGE_OWNER_MISMATCH" });
    expect(proveMerge).not.toHaveBeenCalled();
  });
});
