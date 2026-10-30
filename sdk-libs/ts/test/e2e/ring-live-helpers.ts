// Shared by the ring live suites, the harness ring pins the released rows.
import { readFile } from "node:fs/promises";

import { ed25519 } from "@noble/curves/ed25519.js";
import {
  createKeyPairSignerFromBytes,
  createSolanaRpc,
  generateKeyPairSigner,
  getBase58Encoder,
  lamports,
  type Address,
  type Instruction,
  type KeyPairSigner,
} from "@solana/kit";

import type { CustomRingClient } from "../../src/rpc/client.js";
import {
  compileUnsignedTransaction,
  setRingActivationInstruction,
} from "@heliuslabs/zolana/internal";
import { ClientError } from "@heliuslabs/zolana/client";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import { LocalKeys, ShieldedKeypair, SigningKey, Wallet, type Bytes32 } from "@heliuslabs/zolana";
import type { MemberRecord } from "../../src/protocol/membership/member-registry.js";
import {
  ListId,
  memberOfTag,
  recordBit,
  verifyRecordOpening,
  type Member,
  type RuleTable,
} from "../../src/ring/advanced.js";
import {
  AuthorityListWrite,
  RecordApplication,
  RingError,
  RingInstructionTag,
  RingProgramBinary,
  RingRpc,
  buildRingCreatePolicyTransaction,
  checkedReaderKey,
  createMemberRegistryInstruction,
  createRingConfigInstruction,
  deployRingProgram,
  fetchRingMemberRegistry,
  fetchRingProgramConfig,
  grantReadAccessInstruction,
  initSppRingConfigInstruction,
  listWrite,
  LocalRingKeys,
  messageSignerReader,
  registryCurrentRoot,
  ringAuthAddress,
  ringComputeUnitLimit,
  ringWalletKeys,
  syncRingWallet,
  createKitRingSubmissionTransport,
  type RingReadTarget,
  type RingTransactionSubmission,
} from "../../src/ring/index.js";
import type { RingSubmissionTransport } from "../../src/rpc/ports.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "../../src/rpc/projection.js";
import {
  currentSlot,
  liveHarness,
  signSendAndConfirm,
  waitForSignature,
  type Actor,
} from "./live-helpers.js";

export function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`the ring live test requires ${name}`);
  return value;
}

export async function freshActor(client: CustomRingClient): Promise<Actor> {
  const seed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(seed);
  const signer = await createKeyPairSignerFromBytes(
    Uint8Array.of(...seed, ...ed25519.getPublicKey(seed)),
  );
  const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed as Bytes32));
  return {
    signer,
    keypair,
    wallet: new Wallet({ identity: keypair.shieldedAddress() }),
    keys: LocalKeys.fromKeypair(keypair, client.proofService),
  };
}

export async function airdrop(client: CustomRingClient, recipient: Address): Promise<void> {
  const signature = await client.solanaRpc
    .requestAirdrop(recipient, lamports(5_000_000_000n))
    .send();
  await waitForSignature(client.solanaRpc, signature);
}

export async function keypairSignerFromFile(path: string): Promise<KeyPairSigner> {
  const bytes = Uint8Array.from(JSON.parse(await readFile(path, "utf8")) as number[]);
  return createKeyPairSignerFromBytes(bytes);
}

/** A proof-carrying ring instruction declares its tag's budget, any other the default, the first signer pays. */
export async function sendInstruction(
  client: CustomRingClient,
  instruction: Instruction,
  signer: KeyPairSigner | readonly [KeyPairSigner, ...KeyPairSigner[]],
  computeUnitLimit = 200_000,
): Promise<void> {
  const signers = "address" in signer ? [signer] : signer;
  const lifetime = await client.getLatestBlockhash();
  const transaction = compileUnsignedTransaction({
    feePayer: signers[0].address,
    lifetime,
    computeUnitLimit,
    instructions: [instruction],
  });
  await signSendAndConfirm(client, transaction, signers);
}

/** A ring deployed from `RING_PROGRAM_SO`, only a policy kind pins a table. */
export type FreshRing = Readonly<{
  program: KeyPairSigner;
  authority: KeyPairSigner;
  /** A derived-mode ring rpc releases the key once the program exists. */
  auditor: X25519PublicKey | Readonly<{ releasedBy: RingRpc }>;
  /** Lets the delegate rail transact. */
  authorityTransact: boolean;
}> &
  (
    | Readonly<{ kind: "auditOnly" | "anonymous" }>
    | Readonly<{ kind: "policy" | "anonymousPolicy"; table: RuleTable }>
  );

/** Deploys, configures, registers with the pool and activates `ring` in the order the program demands. */
export async function createRing(client: CustomRingClient, ring: FreshRing): Promise<void> {
  const { program, authority } = ring;
  const ringProgramId = program.address;
  const table = "table" in ring ? ring.table : undefined;
  await deployRingProgram({
    client,
    ringProgramId,
    program,
    payer: authority,
    authority,
    binary: RingProgramBinary.parse(new Uint8Array(await readFile(requiredEnv("RING_PROGRAM_SO")))),
  });
  const { auditor } = ring;
  const auditorPublicKey =
    "releasedBy" in auditor
      ? (
          await auditor.releasedBy.createAuditorKey({
            ringProgramId,
            genesisHash: (await ringReadTarget(auditor.releasedBy, ringProgramId)).cluster,
            authority,
          })
        ).auditorPublicKey
      : auditor;
  await sendInstruction(
    client,
    await createRingConfigInstruction({
      ringProgramId,
      payer: authority,
      authority,
      auditorPublicKey,
      kind: ring.kind,
    }),
    authority,
  );
  // The policy table lives in the member registry, the registry precedes it.
  await sendInstruction(
    client,
    await createMemberRegistryInstruction({ ringProgramId, payer: authority, authority }),
    authority,
  );
  if (table !== undefined)
    await signSendAndConfirm(
      client,
      await buildRingCreatePolicyTransaction({
        client,
        ringProgramId,
        authority: authority.address,
        table,
      }),
      [authority],
    );
  await sendInstruction(
    client,
    await initSppRingConfigInstruction({
      ringProgramId,
      payer: authority,
      authority,
      config: await fetchRingProgramConfig(client, ringProgramId),
    }),
    authority,
  );
  // Localnet snapshots require the fixed public governance seed.
  const governanceSeed = new TextEncoder().encode("zolana localnet snapshot authori");
  const governance = await createKeyPairSignerFromBytes(
    Uint8Array.of(...governanceSeed, ...ed25519.getPublicKey(governanceSeed)),
  );
  await airdrop(client, governance.address);
  await sendInstruction(
    client,
    await setRingActivationInstruction({
      authority: governance,
      ringConfig: await ringAuthAddress(ringProgramId),
      activated: true,
      ringAuthorityTransactIsEnabled: ring.authorityTransact,
    }),
    governance,
  );
}

export interface ReadableRing {
  readonly client: CustomRingClient;
  readonly ringProgramId: Address;
  readonly authority: KeyPairSigner;
  readonly ringRpc: RingRpc;
  readonly target: RingReadTarget;
}

export async function readableRing(
  kind:
    | Readonly<{ kind: "auditOnly" | "anonymous" }>
    | Readonly<{ kind: "anonymousPolicy"; table: RuleTable }>,
): Promise<ReadableRing> {
  const { client } = await liveHarness("client");
  const ringRpc = new RingRpc(requiredEnv("RING_RPC_URL"), { allowInsecureHttp: true });
  if ((await ringRpc.health()).mode !== "derived")
    throw new Error("the ring suites need a ring rpc that derives each ring's auditor key");
  const authority = (await freshActor(client)).signer;
  const program = await generateKeyPairSigner();
  const ringProgramId = program.address;
  for (let i = 0; i < 6; i++) await airdrop(client, authority.address);
  await createRing(client, {
    program,
    authority,
    auditor: { releasedBy: ringRpc },
    authorityTransact: false,
    ...kind,
  });
  // Reads are grant only, the ring authority included.
  await sendInstruction(
    client,
    await grantReadAccessInstruction({
      ringProgramId,
      payer: authority,
      authority,
      reader: checkedReaderKey(authority.address),
    }),
    authority,
  );
  const target = await ringReadTarget(ringRpc, ringProgramId);
  return { client, ringProgramId, authority, ringRpc, target };
}

export function ringHoldings(actor: Actor, ringProgramId: Address): bigint {
  return actor.wallet
    .utxos()
    .filter((entry) => !entry.spent && entry.utxo.ringProgramId === ringProgramId)
    .reduce((total, entry) => total + entry.utxo.amount, 0n);
}

export function auditedRingAmounts(
  item: Awaited<ReturnType<typeof waitForAudited>>,
): readonly bigint[] {
  return item.outputs
    .flatMap(({ opening }) => (opening.kind === "ring" ? [opening.utxo.amount] : []))
    .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
}

export async function sync(client: CustomRingClient, actor: Actor): Promise<void> {
  await syncRingWallet({
    client,
    wallet: actor.wallet,
    keys: ringWalletKeys(actor.keys, LocalRingKeys.fromKeypair(actor.keypair)),
    config: { requireSlot: await currentSlot(client) },
  });
}

/** The harness ring rpc beside the localnet, its health names the key the harness started it with. */
export async function ringReadTarget(
  ringRpc: RingRpc,
  ringProgramId: Address,
): Promise<RingReadTarget> {
  const genesis = await createSolanaRpc(requiredEnv("ZOLANA_LOCALNET_URL")).getGenesisHash().send();
  return {
    cluster: getBase58Encoder().encode(genesis) as Bytes32,
    service: (await ringRpc.health()).servicePublicKey,
    ringProgramId,
  };
}

/** The indexer and the ring RPC lag behind confirmation, so the view is polled. */
export async function waitForAudited(
  ringRpc: RingRpc,
  target: RingReadTarget,
  signer: KeyPairSigner,
  signature: string,
) {
  for (let attempt = 0; attempt < 120; attempt++) {
    const view = await ringRpc.getDecryptedTransactions({
      target,
      signer: messageSignerReader(signer),
    });
    const item = view.items.find((entry) => entry.signature === signature);
    if (item !== undefined) return item;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`transaction ${signature} did not reach the ring view`);
}

export type ListState = "active" | "cleared";

/** A member's record under the registry's newest root, `undefined` for an absent member. */
export interface IndexedRecord {
  readonly member: Member;
  readonly root: Bytes32;
  readonly nextIndex: number;
  readonly record: MemberRecord | undefined;
}

/** The record Photon serves, authenticated against the root the registry account holds. */
export async function indexedRecord(
  client: CustomRingClient,
  ringProgramId: Address,
  member: Member,
): Promise<IndexedRecord> {
  const registry = await fetchRingMemberRegistry(client, ringProgramId);
  const { root } = registryCurrentRoot(registry);
  const read = await client.getRingMemberRecord({
    ringProgramId,
    member,
    expectedRoot: root,
    expectedNextIndex: registry.nextIndex,
  });
  return {
    member,
    root,
    nextIndex: registry.nextIndex,
    record: verifyRecordOpening(read.opening, root, member),
  };
}

/** Retries `read` while the indexer's registry projection lags the chain. */
export async function indexedKeys<T>(read: () => Promise<T>): Promise<T> {
  const lagging: ReadonlySet<string> = MEMBER_REGISTRY_PROJECTION_ERRORS;
  const deadline = Date.now() + 120_000;
  for (;;) {
    try {
      return await read();
    } catch (cause) {
      // The ring indexer refuses under the RingError's own code.
      const codes =
        cause instanceof ClientError
          ? [cause.code]
          : cause instanceof RingError
            ? [cause.code, cause.causeCode]
            : [];
      if (!codes.some((code) => code !== undefined && lagging.has(code)) || Date.now() > deadline)
        throw cause;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
}

/** Polls until the registry holds `bit` in the wanted state, the indexer lags the chain. */
async function awaitLists(
  client: CustomRingClient,
  ringProgramId: Address,
  member: Member,
  bit: bigint,
  wanted: boolean,
): Promise<IndexedRecord> {
  for (let attempt = 0; attempt < 240; attempt++) {
    const read = await indexedKeys(() => indexedRecord(client, ringProgramId, member));
    if ((((read.record?.lists ?? 0n) & bit) !== 0n) === wanted) return read;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("member list update not indexed");
}

export type ListWriteOutcome =
  | Readonly<{ kind: "transaction"; member: Member }>
  | (Readonly<{ kind: "unchanged" }> & IndexedRecord);

/** Lands one authority write unless the bit already holds, then authenticates it against the registry root. */
export async function writeList(
  client: CustomRingClient,
  ringProgramId: Address,
  authority: KeyPairSigner,
  input: Readonly<{ listId: ListId; tag: Uint8Array; state: ListState }>,
): Promise<ListWriteOutcome> {
  const member = memberOfTag(input.tag);
  const bit = recordBit(input.listId);
  const wanted = input.state === "active";
  const current = await indexedKeys(() => indexedRecord(client, ringProgramId, member));
  if ((((current.record?.lists ?? 0n) & bit) !== 0n) === wanted)
    return { kind: "unchanged", ...current };
  const proven = await new AuthorityListWrite({
    ringProgramId,
    authority: authority.address,
  })
    .withWrite(member, listWrite(wanted ? { set: [input.listId] } : { clear: [input.listId] }))
    .prove(client);
  await sendInstruction(
    client,
    proven.instruction,
    authority,
    ringComputeUnitLimit(RingInstructionTag.authorityWriteRecords),
  );
  await awaitLists(client, ringProgramId, member, bit, wanted);
  return { kind: "transaction", member };
}

/** Applies every queued member write once the queue is due, `payer` signs the application. */
export async function applyQueuedWrites(
  client: CustomRingClient,
  ringProgramId: Address,
  payer: KeyPairSigner,
): Promise<void> {
  const application = new RecordApplication(ringProgramId);
  for (let attempt = 0; attempt < 600; attempt++) {
    const proven = await application.prove(client);
    if (proven !== undefined) {
      await sendInstruction(
        client,
        proven.instruction,
        payer,
        ringComputeUnitLimit(RingInstructionTag.applyRecords),
      );
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("the record queue never became due");
}

/** Puts every party on the allow list in one authority write. */
export async function enrolInAllow(
  client: CustomRingClient,
  ringProgramId: Address,
  authority: KeyPairSigner,
  parties: readonly Actor[],
): Promise<void> {
  const bit = recordBit(ListId.allow);
  const members = parties.map((party) =>
    memberOfTag(party.keypair.shieldedAddress().confidentialViewTag()),
  );
  let write = new AuthorityListWrite({
    ringProgramId,
    authority: authority.address,
  });
  for (const member of members) {
    const current = await indexedKeys(() => indexedRecord(client, ringProgramId, member));
    if (((current.record?.lists ?? 0n) & bit) === 0n)
      write = write.withWrite(member, listWrite({ set: [ListId.allow] }));
  }
  if (write.writes().length === 0) return;
  await sendInstruction(
    client,
    (await write.prove(client)).instruction,
    authority,
    ringComputeUnitLimit(RingInstructionTag.authorityWriteRecords),
  );
  for (const member of members) await awaitLists(client, ringProgramId, member, bit, true);
}

export async function settle(
  submission: RingTransactionSubmission,
  client: CustomRingClient,
  signers: readonly KeyPairSigner[],
) {
  return settleWithTransport(submission, createKitRingSubmissionTransport(client, signers));
}

export async function settleWithTransport(
  submission: RingTransactionSubmission,
  transport: RingSubmissionTransport,
) {
  const deadline = Date.now() + 180_000;
  for (;;) {
    const result = await submission.send(transport);
    if (result.kind === "confirmed") return result;
    if (result.kind === "failed") throw new Error(`ring transaction failed (${result.signature})`);
    if (Date.now() > deadline) throw new Error(`ring transaction unresolved (${result.signature})`);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}
