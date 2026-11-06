import { bn254 } from "@noble/curves/bn254.js";
import { AccountRole, getAddressDecoder, type Address, type Instruction } from "@solana/kit";
import { expect } from "vitest";

import {
  type RingRecordReader,
  type StorageMemberOpenings,
  type StorageRecordPool,
  type TrackingReader,
} from "../../src/rpc/ports.js";
import type {
  AnonymousRingTransactInput,
  ChainReader,
  PreparedOwnerSignature,
  ProofAuthority,
  ProofService,
  ProvenAnonymousRingTransact,
  ProvenRingTransact,
  RpcAccount,
} from "@heliuslabs/spr/client";
import {
  encodeRingTransactInstructionData,
  type RingTransactInstructionData,
} from "../../src/protocol/proof/circuit.js";
import {
  prepareTransfer,
  SYSTEM_PROGRAM,
  encodeBase58,
  nullifierPdaAddress,
  treeAddress,
  checkedBytes,
  concatBytes,
  ZERO_32,
} from "@heliuslabs/spr/internal";
import { LocalKeys } from "@heliuslabs/spr/client";
import {
  SHIELDED_POOL_PROGRAM_ID,
  DEFAULT_TREE_ID,
  TRANSACTION_SIZE_LIMIT,
} from "@heliuslabs/spr/interface";
import type { Bytes32, Bytes128, TransactProof } from "@heliuslabs/spr/interface";
import {
  randomBlinding,
  ViewingKey,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/spr/keypair";
import type { ShieldedAddress, ShieldedKeypair } from "@heliuslabs/spr/keypair";
import {
  AssetRegistry,
  SOL_MINT,
  type SppProofInputs,
  ProofInputUtxo,
  Utxo,
} from "@heliuslabs/spr/transaction";
import type { RingProofRequest } from "../../src/rpc/prover/ring.js";
import { ringAuthAddress, ringPolicyAddress, ringPolicyPda } from "../../src/protocol/pda/index.js";
import {
  openOutputSlot,
  openRingDisclosure,
  type RingDisclosure,
} from "../../src/crypto/audit/ring-disclosure.js";
import { DUMMY_RECORD, RecordKind } from "../../src/protocol/codec/audit-stream.js";
import { RECIPIENT_KEY_LEN } from "../../src/protocol/codec/ring-disclosure-layout.js";
import { ringIdField, txKeySlotSecret } from "../../src/crypto/derivation/ring-stream.js";
import { RingInstructionTag, ringComputeUnitLimit } from "../../src/operations/management/admin.js";
import type {
  RingCoSigner,
  RingMode,
  RingSourceSlot,
} from "../../src/protocol/codec/ring-codecs.js";
import type {
  ProvenRingTransfer,
  RingTransactionFrame,
} from "../../src/operations/workflow/pipeline.js";
import type { RingTransferApproval } from "../../src/operations/payments/transfer-rails.js";
import {
  LIST_IDS,
  policySourceOwners,
  policyTableHash,
  referencedLists,
  buildRuleTable,
  type ListId,
  type RuleTable,
} from "../../src/protocol/membership/policy.js";
import {
  ringTransferStatement,
  signerBinding,
  transferStatementHash,
} from "../../src/protocol/proof/statement.js";
import type { TransferProofRequest } from "../../src/proof/transfer-proof.js";
import { RingTransactData, type RingRail } from "../../src/protocol/transaction/transact.js";

import {
  matchesPage,
  transactionsPage,
} from "../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { treeAccount } from "../../../../zolana/sdk-libs/ts/test/helpers/tree-account.js";
import { confirmedAccountReads } from "./clients.js";
import type { TrackingEntry } from "../../src/protocol/membership/tracking.js";
import { recordTree, trackingTree, type FixtureRecord } from "./member-registry.js";
import {
  ownedAccount,
  ringCoSignerAccount,
  ringPolicyData,
  sppRingRegistration,
  storageRegistryAccount,
  trackingAuthorizationAccount,
  trackingRegistryAccount,
} from "./ring-accounts.js";
import { settlementAccounts } from "../../src/protocol/transaction/spp.js";
import { checkTransactionFits } from "../../src/operations/workflow/compile.js";
import { openRecipientNote, ringOutputBlinding } from "../../src/crypto/derivation/blinding.js";
import { LocalRingKeys, ringWalletKeys, type RingKeys } from "../../src/state/ring-keys.js";
import { x25519FromU } from "../../src/crypto/keys/x25519.js";

export const TREE_ID = DEFAULT_TREE_ID;
export const TREE = treeAddress(TREE_ID);
/** Distinct, a swapped own and curator revision fails the asserts. */
export const OWN_REVISION = 7n;
export const CURATOR_REVISION = 11n;
export const TRACKING_REVISION = 9n;
const addressDecoder = getAddressDecoder();

export function randomAddress(): Address {
  return addressDecoder.decode(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

export function filled(byte: number): Bytes32 {
  return new Uint8Array(32).fill(byte) as Bytes32;
}

/** A field element below every modulus, `value` in the last byte. */
export function small(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}

export function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function itemAt<T>(values: readonly T[], index: number): T {
  const value = values[index];
  if (value === undefined) throw new Error(`no item at ${String(index)}`);
  return value;
}

/** Matches a `RingError` or `WalletError` by code and, when given, by details. */
export function ringError(code: string, details?: Readonly<Record<string, unknown>>): unknown {
  return expect.objectContaining(
    details === undefined ? { code } : { code, details: expect.objectContaining(details) },
  );
}

/** A ring and the curator ring a source of it may name, as the chain and Photon hold them. */
export interface RingFixtureOptions {
  readonly mode?: RingMode;
  readonly table?: RuleTable;
  readonly records?: readonly FixtureRecord[];
  readonly coSigner?: RingCoSigner;
  readonly delegate?: Address;
  /** The lists a second ring's registry serves. */
  readonly curator?: Readonly<{
    lists: readonly ListId[];
    records: readonly FixtureRecord[];
  }>;
  readonly slot?: bigint;
  readonly registration?: Readonly<{ activated: boolean; paused: boolean }>;
}

export function trackingEntry(owner: ShieldedAddress, listTag: Bytes32 = ZERO_32): TrackingEntry {
  return {
    member: owner.signingPublicKey.ownerProofInputHash(),
    nullifierPk: owner.nullifierPublicKey,
    ctHash: filled(0x11),
    listTag,
  };
}

/** The pinned rails beside SPP's anonymous one, where an in-proof owner also proves. */
export type SppCircuit =
  | NonNullable<Parameters<typeof prepareTransfer>[1]>
  | Readonly<{
      kind: "ringAnonymous";
      ring: Address;
      owner: PreparedOwnerSignature;
    }>;

export interface SppCall {
  readonly proofInputs: SppProofInputs;
  readonly circuit: SppCircuit;
  readonly authority: ProofAuthority;
  readonly payload: ReturnType<typeof prepareTransfer>["inputs"]["payload"];
  /** Present exactly on SPP's anonymous rail. */
  readonly owner?: PreparedOwnerSignature;
  readonly data: RingTransactInstructionData;
}

/** A pinned rail's proof never carries the anonymous selector. */
function pinnedRail(
  proven: Omit<ProvenRingTransact, "data"> & Readonly<{ data: RingTransactInstructionData }>,
): ProvenRingTransact {
  const { circuit } = proven.data;
  if (circuit.kind === "anonymousRingEddsa" || circuit.kind === "ringAuthorityExit")
    throw new Error("ring selector on a pinned rail");
  return { ...proven, data: { ...proven.data, circuit } };
}

/** A ring the chain, Photon and the prover serve from memory, every proof request recorded. */
export async function ringFixture(options: RingFixtureOptions = {}) {
  const ringProgramId = randomAddress();
  const auditor = X25519Keypair.generate();
  const authority = randomAddress();
  const accounts = new Map<Address, RpcAccount>();
  const ownRecords = new Map(
    (options.records ?? []).map((record) => [hex(record.member), record] as const),
  );
  let ownTree = recordTree([...ownRecords.values()]);
  const [ringAuth, registration] = await sppRingRegistration({
    authority,
    ringProgramId,
    ...options.registration,
  });
  accounts.set(ringAuth, registration);
  accounts.set(
    TREE,
    ownedAccount(
      SHIELDED_POOL_PROGRAM_ID,
      treeAccount({ stateCursor: 0, written: 0, nullifierCursor: 0n, treeId: TREE_ID }),
    ),
  );
  if (options.coSigner !== undefined)
    accounts.set(...(await ringCoSignerAccount(ringProgramId, options.coSigner)));
  const ownRegistry = randomAddress();
  const trackingRegistry = randomAddress();
  const enrolled = new Map<string, TrackingEntry>();
  let tracked = trackingTree();
  const publishTracking = (): void => {
    tracked = trackingTree([...enrolled.values()]);
    accounts.set(
      trackingRegistry,
      trackingRegistryAccount({
        root: tracked.root,
        revision: TRACKING_REVISION,
        nextIndex: tracked.nextIndex,
        auditorPubkey: auditor.publicKey().toBytes(),
      }),
    );
  };
  publishTracking();
  const trees = new Map<
    Address,
    Readonly<{ tree: ReturnType<typeof recordTree>; revision: bigint }>
  >();
  trees.set(ownRegistry, { tree: ownTree, revision: OWN_REVISION });
  let curatorRegistry: Address | undefined;
  let curatorTree: ReturnType<typeof recordTree> | undefined;
  if (options.curator !== undefined) {
    curatorRegistry = randomAddress();
    curatorTree = recordTree(options.curator.records);
    trees.set(curatorRegistry, {
      tree: curatorTree,
      revision: CURATOR_REVISION,
    });
  }
  const config = {
    roles: { admin: authority },
    auditorPublicKey: auditor.publicKey().toBytes(),
    mode: options.mode ?? "confidential",
    tracking: trackingRegistry,
    ...(options.coSigner === undefined ? {} : { coSigner: options.coSigner }),
    ...(options.delegate === undefined ? {} : { delegate: options.delegate }),
  } as const;
  const [ringAddress, ringBump] = await ringPolicyPda(ringProgramId);
  // Every anonymous transfer opens the sender in the ring's records.
  if (
    options.table !== undefined ||
    options.records !== undefined ||
    options.mode === "anonymous"
  ) {
    const table = options.table ?? buildRuleTable({ rules: [] });
    const referenced = referencedLists(table.rules);
    const shared = options.curator?.lists ?? [];
    const sources: RingSourceSlot[] = LIST_IDS.map((listId) =>
      referenced.includes(listId)
        ? {
            listId,
            registry:
              shared.includes(listId) && curatorRegistry !== undefined
                ? curatorRegistry
                : ZERO_ADDRESS,
          }
        : { listId: 0, registry: ZERO_ADDRESS },
    );
    accounts.set(
      ringAddress,
      ownedAccount(
        ringProgramId,
        ringPolicyData({
          bump: ringBump,
          ...config,
          records: ownRegistry,
          ...(options.table === undefined
            ? {}
            : {
                policyHash: policyTableHash(table, policySourceOwners(sources)),
                sources,
                table,
                generation: 1,
              }),
        }),
      ),
    );
    accounts.set(
      ownRegistry,
      storageRegistryAccount([{ hash: ownTree.root, revision: OWN_REVISION, expiresAt: 0n }]),
    );
    if (curatorRegistry !== undefined && curatorTree !== undefined)
      accounts.set(
        curatorRegistry,
        storageRegistryAccount([
          { hash: curatorTree.root, revision: CURATOR_REVISION, expiresAt: 0n },
        ]),
      );
  } else {
    accounts.set(
      ringAddress,
      ownedAccount(ringProgramId, ringPolicyData({ bump: ringBump, ...config })),
    );
  }
  // Authorization writes derive a PDA, `getAccount` waits for each before it reads.
  const authorizations: Promise<void>[] = [];
  /** Applies the owner's enrollment, a repeat rotates its authorization's viewing key. */
  const enroll = (owner: ShieldedAddress, listTag: Bytes32 = ZERO_32): void => {
    const entry = trackingEntry(owner, listTag);
    enrolled.set(hex(entry.member), entry);
    publishTracking();
    authorizations.push(
      trackingAuthorizationAccount({
        registry: trackingRegistry,
        owner: owner.solanaAddress(),
        nullifierPk: entry.nullifierPk,
        listTag,
        viewingU: owner.viewingPublicKey.u(),
      }).then(([at, account]) => void accounts.set(at, account)),
    );
  };
  const slot = options.slot ?? 1n;
  const context = Object.freeze({ slot, blockTime: 0n });
  const ringRequests: RingProofRequest[] = [];
  const sppCalls: SppCall[] = [];
  let proofs = 0;
  const treeAt = (registry: Address, expectedRoot: Bytes32) => {
    const served = trees.get(registry);
    if (served === undefined || hex(served.tree.root) !== hex(expectedRoot))
      throw new Error("openings under an unknown root");
    return served;
  };
  const reader: Pick<ChainReader, "getAccount"> &
    Pick<RingRecordReader, "getStorageMemberOpenings" | "getStorageRecordPool"> &
    Pick<TrackingReader, "getTrackingOpenings" | "getTrackingRecordPool"> = {
    getAccount: async (address) => {
      await Promise.all(authorizations);
      return accounts.get(address);
    },
    getStorageMemberOpenings: async (request): Promise<StorageMemberOpenings> => {
      const { tree, revision } = treeAt(request.registry, request.expectedRoot);
      return {
        context,
        root: { root: tree.root, revision, nextIndex: tree.nextIndex },
        openings: request.members.map((member) => tree.opening(member)),
      };
    },
    getStorageRecordPool: async (request): Promise<StorageRecordPool> => {
      const { tree, revision } = treeAt(request.registry, request.expectedRoot);
      return {
        context,
        root: { root: tree.root, revision, nextIndex: tree.nextIndex },
        ...tree.pool(request.members, request.openings),
      };
    },
    getTrackingOpenings: async (request) => {
      if (hex(request.expectedRoot) !== hex(tracked.root))
        throw new Error("tracking openings under an unknown root");
      return {
        slot,
        root: tracked.root,
        revision: TRACKING_REVISION,
        openings: request.members.map((member) => tracked.opening(member)),
      };
    },
    getTrackingRecordPool: async (request) => {
      if (hex(request.expectedRoot) !== hex(tracked.root))
        throw new Error("tracking pool under an unknown root");
      return tracked.pool(request.members, request.openings);
    },
  };
  const spp = (
    proofInputs: SppProofInputs,
    circuit: SppCircuit,
    authority: ProofAuthority,
  ): Omit<ProvenRingTransact, "data"> & Readonly<{ data: RingTransactInstructionData }> => {
    const prepared = prepareTransfer(
      proofInputs,
      circuit.kind === "ringAnonymous" ? { kind: "ring", ring: circuit.ring } : circuit,
    );
    const complete = prepared.finish(
      proofInputs.inputTreeIds().map((treeId, index) => ({
        treeId,
        slot: {
          id: treeId,
          utxoRoot: small(0x31 + index),
          nullifierRoot: small(0x41 + index),
        },
        utxoRootIndex: 7 + index,
        nullifierRootIndex: 9 + index,
      })),
    );
    const pinned = complete.withProof(SPP_PROOF);
    const data: RingTransactInstructionData =
      circuit.kind === "ringAnonymous"
        ? {
            ...pinned,
            circuit: {
              kind: "anonymousRingEddsa",
              inputs: pinned.circuit.inputs,
              outputs: pinned.circuit.outputs,
              publicAssetSlots: pinned.circuit.publicAssetSlots,
              proofData: {
                bsb22Commitment: {
                  commitment: filled(0x51),
                  commitmentPok: filled(0x52),
                },
                // The hidden owner's key opens a default-ring spend.
                ...(proofInputs.inputUtxos.some(
                  (spent) => !spent.isDummy() && spent.utxo.ringProgramId === undefined,
                )
                  ? { defaultOwnerTag: circuit.owner.ownerPublicKey }
                  : {}),
              },
            },
          }
        : pinned;
    sppCalls.push({
      proofInputs,
      circuit,
      authority,
      payload: prepared.inputs.payload,
      ...(circuit.kind === "ringAnonymous" ? { owner: circuit.owner } : {}),
      data,
    });
    return { data, roots: complete.roots };
  };
  const client = {
    tree: TREE,
    treeId: TREE_ID,
    ...reader,
    solanaRpc: confirmedAccountReads(reader.getAccount),
    proveRing: async (request: RingProofRequest): Promise<Uint8Array> => {
      ringRequests.push(structuredClone(request));
      proofs += 1;
      return new Uint8Array(192).fill(proofs);
    },
    proveRingTransact: async (proofInputs: SppProofInputs, ring: Address, keys: ProofAuthority) =>
      pinnedRail(spp(proofInputs, { kind: "ring", ring }, keys)),
    proveRingAuthorityTransact: async (
      proofInputs: SppProofInputs,
      ring: Address,
      keys: ProofAuthority,
    ) => pinnedRail(spp(proofInputs, { kind: "ringAuthority", ring }, keys)),
    proveAnonymousRingTransact: async (
      input: AnonymousRingTransactInput,
    ): Promise<ProvenAnonymousRingTransact> => {
      if ("sign" in input.owner) throw new Error("the rail signs before the proof request");
      const proven = spp(
        input.proofInputs,
        {
          kind: "ringAnonymous",
          ring: input.ringProgramId,
          owner: input.owner,
        },
        input.keys,
      );
      const { circuit } = proven.data;
      if (circuit.kind !== "anonymousRingEddsa") throw new Error("not an anonymous rail circuit");
      return { ...proven, data: { ...proven.data, circuit }, ownerSigners: [] };
    },
    getShieldedTransactionsByTags: async () => transactionsPage(),
    getShieldedTransactionsByNullifiers: async () => transactionsPage(),
    getEncryptedUtxosByTags: async () => matchesPage(),
  };
  return {
    ringProgramId,
    auditor,
    authority,
    trackingRegistry,
    get trackingTree() {
      return tracked;
    },
    accounts,
    client,
    ringRequests,
    sppCalls,
    enroll,
    get ownTree() {
      return ownTree;
    },
    ...(options.coSigner === undefined ? {} : { coSigner: options.coSigner.signer }),
    ownRegistry,
    ...(curatorRegistry === undefined ? {} : { curatorRegistry }),
    ...(curatorTree === undefined ? {} : { curatorTree }),
  };
}

export type Fixture = Awaited<ReturnType<typeof ringFixture>>;

/** Never consulted, every proof here is a stub. */
export const PROOF_SERVICE: ProofService = {
  prove: async () => {
    throw new Error("unused proof service");
  },
  proveMerge: async () => {
    throw new Error("unused proof service");
  },
};

export function walletKeys(keypair: ShieldedKeypair): LocalKeys & RingKeys {
  return ringWalletKeys(
    LocalKeys.fromKeypair(keypair, PROOF_SERVICE),
    LocalRingKeys.fromKeypair(keypair),
  );
}

/** A spendable note of `keypair` in `ring`, or in the default ring without one. */
export function noteInput(
  keypair: ShieldedKeypair,
  amount: bigint,
  ring?: Address,
  asset: Address = SOL_MINT,
): ProofInputUtxo {
  return ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: keypair.signingPublicKey(),
      asset,
      amount,
      blinding: randomBlinding(),
      ...(ring === undefined ? {} : { ringProgramId: ring }),
    }),
    keypair,
    {},
    TREE_ID,
  );
}

/** The BN254 G2 generator, the SPP proof `b` the stub proves with must lie on the curve. */
const G2 = bn254.G2.Point.BASE.toAffine();
export const SPP_PROOF: TransactProof = Object.freeze({
  a: filled(0x0a),
  b: checkedBytes<Bytes128>(
    Uint8Array.from(
      [G2.x.c1, G2.x.c0, G2.y.c1, G2.y.c0].flatMap((value) =>
        Array.from(Buffer.from(value.toString(16).padStart(64, "0"), "hex")),
      ),
    ),
    128,
    "b",
  ),
  c: filled(0x0c),
});

export const ZERO_ADDRESS = encodeBase58(new Uint8Array(32));

/** The instruction parses back to its data, and the program's expansion reproduces what SPP proved. */
export async function expanded(fixture: Fixture, proven: ProvenRingTransfer, rail: RingRail) {
  const instruction = await proven.instruction();
  expect(instruction.data?.[0]).toBe(
    rail === "delegate" ? RingInstructionTag.authorityTransfer : RingInstructionTag.transfer,
  );
  const bytes = instruction.data?.subarray(1) ?? new Uint8Array();
  const data = RingTransactData.parse(bytes, rail);
  expect(hex(RingTransactData.encode(data))).toBe(hex(bytes));
  const call = fixture.sppCalls.at(-1);
  if (call === undefined) throw new Error("no SPP proof");
  const config = { auditorPubkey: fixture.auditor.publicKey().toBytes() };
  expect(hex(encodeRingTransactInstructionData(RingTransactData.expand(data, config)))).toBe(
    hex(encodeRingTransactInstructionData(call.data)),
  );
  expect(
    RingTransactData.externalDataHash(
      data,
      config,
      call.proofInputs.externalData.interfaceTransfers.map(settlementAccounts),
    ),
  ).toEqual(call.proofInputs.externalData.hash());
  return { instruction, data, call };
}

type AccountEntry = Readonly<{ address: Address; role: AccountRole }>;

/**
 * Rust `TransactAccounts::instruction`, the ring prefix then SPP's own list, every transfer here
 * spending from and landing in `TREE`.
 */
export async function checkAccounts(
  instruction: Instruction,
  expected: Readonly<{
    fixture: Fixture;
    data: RingTransactData;
    /** The live registries before the tracking registry, `ringRegistrySlots` order. */
    registries?: readonly Address[];
    /** After the registries, the co-signers, delegate and anchor tree in order. */
    prefix: readonly AccountEntry[];
    payer: Address;
    ownerSigners?: readonly Address[];
    settlement?: readonly AccountEntry[];
  }>,
): Promise<void> {
  const { fixture } = expected;
  const readonly = (address: Address): AccountEntry => ({
    address,
    role: AccountRole.READONLY,
  });
  const writable = (address: Address): AccountEntry => ({
    address,
    role: AccountRole.WRITABLE,
  });
  const nullifiers = await Promise.all(
    expected.data.nullifiers.map((nullifier) => nullifierPdaAddress(TREE, nullifier)),
  );
  expect(
    instruction.accounts?.map((account) => ({
      address: account.address,
      role: account.role,
    })),
  ).toEqual([
    readonly(await ringPolicyAddress(fixture.ringProgramId)),
    ...(expected.registries ?? []).map(readonly),
    readonly(fixture.trackingRegistry),
    ...expected.prefix,
    { address: expected.payer, role: AccountRole.WRITABLE_SIGNER },
    writable(TREE),
    readonly(SHIELDED_POOL_PROGRAM_ID),
    readonly(SYSTEM_PROGRAM),
    readonly(await ringAuthAddress(fixture.ringProgramId)),
    writable(TREE),
    ...nullifiers.map(writable),
    ...(expected.ownerSigners ?? []).map((address) => ({
      address,
      role: AccountRole.READONLY_SIGNER,
    })),
    ...(expected.settlement ?? []),
  ]);
}

/** Every output's blinding is SPP's TXOB of the proof's blinding seed. */
export function checkRingBlindings(call: SppCall, data: RingTransactData): void {
  const firstNullifier = RingTransactData.firstNullifier(data);
  call.proofInputs.outputs.forEach((output, outputIndex) => {
    if (output.isCompact()) return;
    expect(output.blinding).toEqual(
      ringOutputBlinding({
        firstNullifier,
        blindingSeed: call.proofInputs.blindingSeed,
        outputIndex,
      }),
    );
  });
}

/** The owner run the statement binds, the request pads it to the key's `S`. */
export function bindingSigners(request: TransferProofRequest): readonly Bytes32[] {
  return request.signers.slice(0, request.signerCount);
}

/** The own pool subjects of the first `count` sender rows, each owner's public lookup key. */
export function screenedMembers(request: TransferProofRequest, count: number): readonly Bytes32[] {
  return request.senderEntries
    .slice(0, count)
    .map((entry) => itemAt(request.ownPool.subjects, entry.own).member);
}

/** The one ring request, its statement the program rebuilds from the parsed data and the values the request binds. */
export function checkTransferProof(fixture: Fixture, data: RingTransactData): TransferProofRequest {
  const request = fixture.ringRequests.find((candidate) => candidate.kind === "transfer");
  if (request?.kind !== "transfer") throw new Error("no transfer request");
  expect(request.publicInputHash).toEqual(
    transferStatementHash(
      ringTransferStatement(data, {
        ringId: ringIdField(fixture.ringProgramId),
        auditorPubkey: fixture.auditor.publicKey().toBytes(),
        sender: request.sender,
        partyIdentities: request.partyIdentities,
        signers: signerBinding(bindingSigners(request), request.inputs.length),
        roots: {
          policyHash: request.policyHash,
          ownRoot: request.ownRoot,
          curatorRoot: request.curatorRoot,
          trackingRoot: request.trackingRoot,
        },
        publicAssets: request.publicAssets,
        publicAmounts: request.publicAmounts,
        publicGross: request.publicGross,
        withdrawalHash: request.withdrawalHash,
      }),
    ),
  );
  expect(request.layout).toEqual(RingTransactData.auditLayout(data));
  expect(request.approvalMask).toBe(data.approval);
  return request;
}

/** The auditor recovers the transaction key and each slot's key from the stream, then reads each published slot's note from its record. */
export function checkDisclosure(
  fixture: Fixture,
  call: SppCall,
  data: RingTransactData,
): RingDisclosure {
  const disclosure = openRingDisclosure(fixture.auditor, {
    layout: RingTransactData.streamLayout(data),
    message: {
      ephemeralPublicKey: x25519FromU(data.txViewingU),
      envelope: data.envelope,
      recipientKeys: data.outputs.map((_, slot) =>
        data.recipientKeys.subarray(slot * RECIPIENT_KEY_LEN, (slot + 1) * RECIPIENT_KEY_LEN),
      ),
    },
    salt: data.salt,
  });
  const txKey = ViewingKey.fromBytes(disclosure.envelope.txViewingSecret.slice() as Bytes32);
  expect(txKey.publicKey().u()).toEqual(data.txViewingU);
  const published = call.proofInputs.outputs.filter((output) => !output.isCompact());
  expect(disclosure.recipientKeys).toHaveLength(published.length);
  data.outputs.forEach((wire, index) => {
    const secret = txKeySlotSecret({
      txViewingKey: txKey,
      recipientViewingKey: x25519FromU(itemAt(disclosure.recipientKeys, index)),
      salt: data.salt,
      outputIndex: index,
      firstNullifier: RingTransactData.firstNullifier(data),
    });
    const { record } = openOutputSlot(secret, wire.record);
    const output = itemAt(published, index);
    const owner = output.ownerAddress;
    if (owner === undefined || output.isDummy()) {
      expect(record).toEqual(DUMMY_RECORD);
      return;
    }
    expect(record).toEqual({
      kind: output.ringProgramId === undefined ? RecordKind.exit : RecordKind.ring,
      amount: output.amount,
      ownerKey: owner.signingPublicKey.confidentialViewTag(),
      mint: output.asset,
      nullifierPk: owner.nullifierPublicKey,
      blinding: output.blinding,
    });
  });
  txKey.destroy();
  return disclosure;
}

/** A recipient slot opens to the committed note under the slot secret the recipient's keys answer, `undefined` for another recipient's slot. */
export async function openDelivered(
  input: Readonly<{
    fixture: Fixture;
    keys: RingKeys;
    recipient: X25519PublicKey;
    call: SppCall;
    data: RingTransactData;
    slotIndex: number;
  }>,
) {
  const { call, data, slotIndex } = input;
  const [slotSecret] = await input.keys.ringDeliverySecrets([
    {
      viewingPublicKey: input.recipient,
      txViewingPublicKey: X25519PublicKey.fromBytes(call.data.txViewingPk),
      salt: data.salt,
      outputIndex: slotIndex,
      firstNullifier: RingTransactData.firstNullifier(data),
    },
  ]);
  const wire = data.outputs[slotIndex];
  if (slotSecret === undefined || wire?.body.kind !== "recipient")
    throw new Error("no recipient slot");
  const owner = input.keys.address();
  // Another key's secret decrypts noise the record codec refuses, as a reader skips the slot.
  let opened: ReturnType<typeof openOutputSlot>;
  try {
    opened = openOutputSlot(slotSecret, concatBytes(wire.record, wire.body.payload));
  } catch {
    return undefined;
  }
  return openRecipientNote(
    {
      owner: {
        signingPublicKey: owner.signingPublicKey,
        nullifierPublicKey: owner.nullifierPublicKey,
      },
      ring: input.fixture.ringProgramId,
      treeId: call.proofInputs.outputTreeId,
      commitment: wire.hash,
      assets: new AssetRegistry(),
    },
    opened,
  );
}

/** A setup instruction of `length` data bytes ahead of the ring instruction. */
function padding(length: number): Instruction {
  return { programAddress: PADDING_PROGRAM, data: new Uint8Array(length) };
}

const PADDING_PROGRAM = randomAddress();

/**
 * The transfer `prove` builds fits beside the setup instruction that fills its transaction, and one
 * more setup byte or a priority fee refuses it before approval and any proof.
 */
export async function checkFrameCounted(
  fixture: Fixture,
  input: Readonly<{
    payer: Address;
    prove: (approval: RingTransferApproval) => Promise<ProvenRingTransfer>;
  }>,
): Promise<void> {
  const proofs = () => fixture.ringRequests.length + fixture.sppCalls.length;
  const approvals: number[] = [];
  const approval = (transaction: RingTransactionFrame): RingTransferApproval => ({
    transaction,
    approve: async () => {
      approvals.push(proofs());
    },
  });
  const instruction = await (await input.prove(approval({}))).instruction();
  const fits = (length: number): boolean => {
    try {
      checkTransactionFits({
        feePayer: input.payer,
        setupInstructions: [padding(length)],
        instructions: [instruction],
        computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.transfer),
      });
      return true;
    } catch {
      return false;
    }
  };
  let [filling, overflow] = [0, TRANSACTION_SIZE_LIMIT];
  while (overflow - filling > 1) {
    const middle = Math.floor((filling + overflow) / 2);
    if (fits(middle)) filling = middle;
    else overflow = middle;
  }
  const before = proofs();
  for (const transaction of [
    { setupInstructions: [padding(overflow)] },
    { setupInstructions: [padding(filling)], priorityFeeLamports: 1n },
  ])
    await expect(input.prove(approval(transaction))).rejects.toMatchObject({
      code: "RING_TRANSFER_TOO_WIDE",
    });
  expect(proofs()).toBe(before);
  await input.prove(approval({ setupInstructions: [padding(filling)] }));
  expect(approvals).toEqual([0, before]);
}
