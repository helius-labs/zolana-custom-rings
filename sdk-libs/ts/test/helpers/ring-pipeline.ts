import { bn254 } from "@noble/curves/bn254.js";
import { AccountRole, getAddressDecoder, type Address, type Instruction } from "@solana/kit";
import { expect } from "vitest";

import {
  type RingRecordReader,
  type StorageMemberOpenings,
  type StorageRecordPool,
} from "../../src/rpc/ports.js";
import type {
  ChainReader,
  ProofAuthority,
  ProofService,
  ProvenRingTransact,
  RpcAccount,
} from "@heliuslabs/zolana/client";
import type {
  AnonymousRingTransactProofInput,
  HiddenOwnerAuthorization,
} from "../../src/rpc/ports.js";
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
} from "@heliuslabs/zolana/internal";
import { LocalKeys } from "@heliuslabs/zolana/client";
import {
  SHIELDED_POOL_PROGRAM_ID,
  DEFAULT_TREE_ID,
  TRANSACTION_SIZE_LIMIT,
} from "@heliuslabs/zolana/interface";
import type { Bytes32, Bytes128, TransactProof } from "@heliuslabs/zolana/interface";
import {
  randomBlinding,
  ViewingKey,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import type { ShieldedAddress, ShieldedKeypair } from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  SOL_MINT,
  assetField,
  type SppProofInputs,
  ProofInputUtxo,
  Utxo,
} from "@heliuslabs/zolana/transaction";
import type { RingProofRequest } from "../../src/rpc/prover/ring.js";
import {
  ringAuthAddress,
  ringConfigAddress,
  ringConfigPda,
  ringPolicyPda,
} from "../../src/protocol/pda/index.js";
import { openTransactionViewingSecret } from "../../src/crypto/audit/audit.js";
import { openRingDisclosure, type RingDisclosure } from "../../src/crypto/audit/ring-disclosure.js";
import { ringIdField } from "../../src/crypto/derivation/ring-stream.js";
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
import { auditStatementHash, ringAuditStatement } from "../../src/protocol/proof/statement.js";
import { RingTransactData, type RingRail } from "../../src/protocol/transaction/transact.js";

import {
  matchesPage,
  transactionsPage,
} from "../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { recordTree, type FixtureRecord } from "./member-registry.js";
import {
  ownedAccount,
  ringCoSignerAccount,
  ringPolicyData,
  ringProgramConfigData,
  sppRingRegistration,
} from "./ring-accounts.js";
import { settlementAccounts } from "../../src/protocol/transaction/spp.js";
import { checkTransactionFits } from "../../src/operations/workflow/compile.js";
import { ringOutputBlinding, openRingDelivery } from "../../src/crypto/derivation/blinding.js";
import { LocalRingKeys, ringWalletKeys, type RingKeys } from "../../src/state/ring-keys.js";
import { x25519FromU } from "../../src/crypto/keys/x25519.js";
import { notImplemented } from "./clients.js";

export const TREE_ID = DEFAULT_TREE_ID;
export const TREE = treeAddress(TREE_ID);
/** Distinct, a swapped own and curator revision fails the asserts. */
export const OWN_REVISION = 7n;
export const CURATOR_REVISION = 11n;
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
  readonly curator?: Readonly<{ lists: readonly ListId[]; records: readonly FixtureRecord[] }>;
  readonly slot?: bigint;
  readonly registration?: Readonly<{ activated: boolean; paused: boolean }>;
}

/** The pinned rails beside the anonymous one a ring client proves. */
export type SppCircuit =
  | NonNullable<Parameters<typeof prepareTransfer>[1]>
  | Readonly<{
      kind: "ringAnonymous";
      ring: Address;
      owner: HiddenOwnerAuthorization;
      exitTokenOwner?: Address;
    }>;

export interface SppCall {
  readonly proofInputs: SppProofInputs;
  readonly circuit: SppCircuit;
  readonly authority: ProofAuthority;
  readonly payload: ReturnType<typeof prepareTransfer>["inputs"]["payload"];
  /** Present exactly on the anonymous rail. */
  readonly owner?: HiddenOwnerAuthorization;
  readonly exitTokenOwner?: Address;
  readonly data: RingTransactInstructionData;
}

/** A pinned rail's proof never carries the anonymous selector. */
function pinnedRail(
  proven: Omit<ProvenRingTransact, "data"> & Readonly<{ data: RingTransactInstructionData }>,
): ProvenRingTransact {
  const { circuit } = proven.data;
  if (circuit.kind === "anonymousRingEddsa") throw new Error("anonymous selector on a pinned rail");
  return { ...proven, data: { ...proven.data, circuit } };
}

/** A ring the chain, Photon and the prover serve from memory, every proof request recorded. */
export async function ringFixture(options: RingFixtureOptions = {}) {
  const ringProgramId = randomAddress();
  const auditor = X25519Keypair.generate();
  const authority = randomAddress();
  const accounts = new Map<Address, RpcAccount>();
  const ownTree = recordTree(options.records ?? []);
  const hasPolicy = options.table !== undefined;
  const [configAddress, configBump] = await ringConfigPda(ringProgramId);
  accounts.set(
    configAddress,
    ownedAccount(
      ringProgramId,
      ringProgramConfigData({
        authority,
        auditorPublicKey: auditor.publicKey().toBytes(),
        bump: configBump,
        hasPolicy,
        mode: options.mode ?? "confidential",
        ...(options.coSigner === undefined ? {} : { coSigner: options.coSigner }),
        ...(options.delegate === undefined ? {} : { delegate: options.delegate }),
      }),
    ),
  );
  const [ringAuth, registration] = await sppRingRegistration({
    authority,
    ringProgramId,
    ...options.registration,
  });
  accounts.set(ringAuth, registration);
  if (options.coSigner !== undefined)
    accounts.set(...(await ringCoSignerAccount(ringProgramId, options.coSigner)));
  const ownRegistry = randomAddress();
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
    trees.set(curatorRegistry, { tree: curatorTree, revision: CURATOR_REVISION });
  }
  if (options.table !== undefined || options.records !== undefined) {
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
    const [address, bump] = await ringPolicyPda(ringProgramId);
    accounts.set(
      address,
      ownedAccount(
        ringProgramId,
        ringPolicyData({
          bump,
          records: ownRegistry,
          policyHash: policyTableHash(table, policySourceOwners(sources)),
          sources,
          table,
          generation: 1,
          ownRoots: {
            registry: ownRegistry,
            roots: [{ hash: ownTree.root, revision: OWN_REVISION, expiresAt: 0n }],
          },
          ...(curatorRegistry === undefined || curatorTree === undefined
            ? {}
            : {
                curatorRoots: {
                  registry: curatorRegistry,
                  roots: [{ hash: curatorTree.root, revision: CURATOR_REVISION, expiresAt: 0n }],
                },
              }),
        }),
      ),
    );
  }
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
    Pick<RingRecordReader, "getStorageMemberOpenings" | "getStorageRecordPool"> = {
    getAccount: async (address) => accounts.get(address),
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
        slot: { id: treeId, utxoRoot: small(0x31 + index), nullifierRoot: small(0x41 + index) },
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
                bsb22Commitment: { commitment: filled(0x51), commitmentPok: filled(0x52) },
                // The hidden owner's key opens a default-ring spend.
                ...(proofInputs.inputUtxos.some(
                  (spent) => !spent.isDummy() && spent.utxo.ringProgramId === undefined,
                )
                  ? { defaultOwnerTag: circuit.owner.publicKey }
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
      ...(circuit.kind === "ringAnonymous" && circuit.exitTokenOwner !== undefined
        ? { exitTokenOwner: circuit.exitTokenOwner }
        : {}),
      data,
    });
    return { data, roots: complete.roots };
  };
  const client = {
    tree: TREE,
    treeId: TREE_ID,
    ...reader,
    proveRing: async (request: RingProofRequest): Promise<Uint8Array> => {
      ringRequests.push(structuredClone(request));
      proofs += 1;
      return new Uint8Array(192).fill(proofs);
    },
    proveRingTransact: async (proofInputs: SppProofInputs, ring: Address, keys: ProofAuthority) =>
      pinnedRail(spp(proofInputs, { kind: "ring", ring }, keys)),
    proveRingConfidentialEddsaTransact: notImplemented("proveRingConfidentialEddsaTransact"),
    proveRingAuthorityTransact: async (
      proofInputs: SppProofInputs,
      ring: Address,
      keys: ProofAuthority,
    ) => pinnedRail(spp(proofInputs, { kind: "ringAuthority", ring }, keys)),
    proveAnonymousRingTransact: async (input: AnonymousRingTransactProofInput) =>
      spp(
        input.proofInputs,
        {
          kind: "ringAnonymous",
          ring: input.ringProgramId,
          owner: input.owner,
          ...(input.exitTokenOwner === undefined ? {} : { exitTokenOwner: input.exitTokenOwner }),
        },
        input.keys,
      ),
    getShieldedTransactionsByTags: async () => transactionsPage(),
    getShieldedTransactionsByNullifiers: async () => transactionsPage(),
    getEncryptedUtxosByTags: async () => matchesPage(),
  };
  return {
    ringProgramId,
    auditor,
    authority,
    /** `ConfidentialEscrow` mode escrows every output nullifier key. */
    keyEscrow: options.mode === "confidentialEscrow",
    accounts,
    client,
    ringRequests,
    sppCalls,
    ownTree,
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
    /** After the config, the policy, co-signer, delegate and anchor tree in order. */
    prefix: readonly AccountEntry[];
    payer: Address;
    ownerSigners?: readonly Address[];
    settlement?: readonly AccountEntry[];
  }>,
): Promise<void> {
  const { fixture } = expected;
  const readonly = (address: Address): AccountEntry => ({ address, role: AccountRole.READONLY });
  const writable = (address: Address): AccountEntry => ({ address, role: AccountRole.WRITABLE });
  const nullifiers = await Promise.all(
    expected.data.nullifiers.map((nullifier) => nullifierPdaAddress(TREE, nullifier)),
  );
  expect(
    instruction.accounts?.map((account) => ({ address: account.address, role: account.role })),
  ).toEqual([
    readonly(await ringConfigAddress(fixture.ringProgramId)),
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

/** The audit request proves the statement the program rebuilds from the parsed data. */
export function checkAudit(
  fixture: Fixture,
  data: RingTransactData,
  binding: Readonly<{ kind: RingProofRequest["kind"] }>,
): void {
  const audit = fixture.ringRequests.find((request) => request.kind.endsWith("Audit"));
  expect(audit?.kind).toBe(binding.kind);
  expect(audit?.publicInputHash).toEqual(
    auditStatementHash(
      ringAuditStatement(data, {
        ringId: ringIdField(fixture.ringProgramId),
        auditorPubkey: fixture.auditor.publicKey().toBytes(),
        keyEscrow: fixture.keyEscrow,
        partyIdentities:
          audit?.kind === "anonymousAudit"
            ? audit.partyIdentities
            : [
                new Uint8Array(32) as Bytes32,
                new Uint8Array(32) as Bytes32,
                new Uint8Array(32) as Bytes32,
              ],
      }),
    ),
  );
  expect(audit === undefined ? undefined : "layout" in audit ? audit.layout : undefined).toEqual(
    RingTransactData.auditLayout(data),
  );
}

/**
 * The auditor recovers the transaction key from the envelope and opens every published slot to the
 * output SPP proves. A change slot's key is the sender's ring change key, the caller checks it.
 */
export function checkDisclosure(
  fixture: Fixture,
  call: SppCall,
  data: RingTransactData,
  sender: ShieldedAddress,
): RingDisclosure {
  const txViewingSecret = openTransactionViewingSecret(fixture.auditor, {
    ephemeralPublicKey: x25519FromU(data.ephU),
    sealed: data.sealed,
  });
  const txKey = ViewingKey.fromBytes(txViewingSecret);
  expect(txKey.publicKey().u()).toEqual(data.txViewingU);
  txKey.destroy();
  const exits = data.outputs.map((output) => output.kind === "exit");
  const disclosure = openRingDisclosure(
    { txViewingSecret, salt: data.salt },
    { layout: RingTransactData.disclosureLayout(data), fields: data.disclosure, exits },
  );
  txViewingSecret.fill(0);
  // SeedOut opens the disclosure exactly beside an exit.
  expect(disclosure.seedOut).toEqual(
    exits.includes(true) ? call.proofInputs.outputBlindingSeed() : undefined,
  );
  const escrowed = disclosure.kind !== "anonymous" && disclosure.layout.keyEscrow;
  const published = call.proofInputs.outputs;
  expect(disclosure.outputs).toHaveLength(published.length);
  disclosure.outputs.forEach((opened, index) => {
    const output = itemAt(published, index);
    const owner = output.ownerAddress;
    if (owner === undefined) {
      expect(opened).toEqual({ kind: "dummy" });
      return;
    }
    const exit = exits[index] === true;
    const nullifierPk = escrowed ? undefined : owner.nullifierPublicKey;
    const ownerKey = owner.signingPublicKey.confidentialViewTag();
    const asset = assetField(output.asset);
    if (exit) expect(opened).toEqual({ kind: "exit", nullifierPk, asset, amount: output.amount });
    else if (disclosure.kind === "delivered")
      expect(opened).toEqual({ kind: "ring", nullifierPk, ownerKey });
    else
      expect(opened).toEqual({ kind: "ring", nullifierPk, ownerKey, asset, amount: output.amount });
  });
  if (disclosure.kind === "anonymous") {
    const spent = call.proofInputs.inputUtxos.filter((input) => !input.isCompact());
    expect(disclosure.inputs).toEqual(
      disclosure.layout.key.kind === "entry"
        ? {
            kind: "openings",
            senderKey: sender.signingPublicKey.confidentialViewTag(),
            senderNullifierPk: sender.nullifierPublicKey,
            inputs: spent.map((input) =>
              input.isDummy()
                ? undefined
                : {
                    asset: assetField(input.utxo.asset),
                    amount: input.utxo.amount,
                    blinding: input.utxo.blinding,
                  },
            ),
          }
        : {
            kind: "commitments",
            first: spent[0]?.hash(),
            prefixes: spent
              .slice(1)
              .map((input) =>
                input.isDummy()
                  ? undefined
                  : BigInt(`0x${Buffer.from(input.hash().subarray(0, 16)).toString("hex")}`),
              ),
          },
    );
  }
  return disclosure;
}

/**
 * A delivered slot opens to the committed note under the slot secret the recipient's keys answer,
 * `undefined` for another recipient's slot.
 */
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
  const firstNullifier = RingTransactData.firstNullifier(data);
  const [slotSecret] = await input.keys.ringDeliverySecrets([
    {
      viewingPublicKey: input.recipient,
      txViewingPublicKey: X25519PublicKey.fromBytes(call.data.txViewingPk),
      salt: data.salt,
      outputIndex: slotIndex,
      firstNullifier,
    },
  ]);
  const wire = data.outputs[slotIndex];
  if (slotSecret === undefined || wire?.kind !== "delivered") throw new Error("no delivered slot");
  const owner = input.keys.address();
  return openRingDelivery(
    { ring: input.fixture.ringProgramId },
    {
      body: wire.body,
      slotSecret,
      owner: {
        signingPublicKey: owner.signingPublicKey,
        nullifierPublicKey: owner.nullifierPublicKey,
      },
      commitment: wire.hash,
      treeId: call.proofInputs.outputTreeId,
    },
    new AssetRegistry(),
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
