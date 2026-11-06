/** The sealed transfer `RelayIntent.proofInputs` carries, Rust `RelayProofInputs` in wincode. */
import {
  BLINDING_LENGTH,
  Reader,
  SALT_LENGTH,
  SHIELDED_ADDRESS_LENGTH,
  Writer,
  X25519_PUBLIC_KEY_LENGTH,
  addressBytes,
  byteVector,
  concatBytes,
  encodeBase58,
  encodeData,
  equalBytes,
  isZero,
  readData,
  splInterfaceWithBump,
  writeTransactOutput,
  sha256,
} from "@heliuslabs/spr/internal";
import {
  TransactWithdrawal,
  type Address,
  type Bytes16,
  type Bytes31,
  type Bytes32,
  type OwnerTag,
  type TransactOutput,
} from "@heliuslabs/spr/interface";
import {
  NullifierKey,
  ShieldedAddress,
  ViewingKey,
  X25519PublicKey,
  ShieldedPublicKey,
} from "@heliuslabs/spr/keypair";
import {
  ProofInputUtxo,
  Utxo,
  createExternalData,
  createProofOutput,
  type AssetRegistry,
  type ExternalData,
  type ProofOutputUtxo,
  type SettlementTransfer,
} from "@heliuslabs/spr/transaction";

import { AnonymousPlan } from "../../operations/payments/output-rail.js";
import type { CoOwner } from "../../operations/payments/ring-spend.js";
import type { RingListSalt } from "../../proof/policy-proof.js";
import { RingError } from "../error.js";

/** Rust `RelayRail`. */
export type RelayRail =
  | Readonly<{ kind: "anonymous"; plan: AnonymousPlan; exitTokenOwner?: Address }>
  | Readonly<{ kind: "confidential" }>
  | Readonly<{ kind: "delegate"; delegate: Address; plan?: AnonymousPlan }>
  /** Spends no note, `plan` exactly on an anonymous ring. */
  | Readonly<{ kind: "deposit"; plan?: AnonymousPlan }>;

/** One interface transfer's accounts, Rust `TransactInterfaceTransferAccounts`, a SOL deposit's `recipient` is its funder. */
export type RelayLegAccounts =
  | TransactWithdrawal
  | Readonly<{
      kind: "splDeposit";
      mint: Address;
      splTokenInterface: Address;
      tokenAuthority: Address;
      userTokenAccount: Address;
      tokenProgram: Address;
    }>;

/** Rust `RelayProofInputs`. */
export interface RelayProofInputs {
  readonly rail: RelayRail;
  readonly ringProgramId: Address;
  /** Owns every real input `coOwners` does not. */
  readonly sender: ShieldedAddress;
  readonly nullifierKey: NullifierKey;
  readonly txViewingKey: ViewingKey;
  readonly inputs: readonly ProofInputUtxo[];
  /** One per input slot, read on spends only. */
  readonly leafIndexes: readonly bigint[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly externalData: ExternalData;
  /** One per interface transfer. */
  readonly interfaceTransferAccounts: readonly RelayLegAccounts[];
  readonly blindingSeed: Bytes32;
  readonly outputTreeId: number;
  /** The owner sealed under the wide key, the relayer proves on it. */
  readonly wideOwners: boolean;
  readonly assets: AssetRegistry;
  /** Encoding drops the sender's, Ring RPC derives it from `nullifierKey`. */
  readonly listSalts: readonly RingListSalt[];
  /** The public co-owners whose keys the seal holds, encoding sends only those a spend names. */
  readonly coOwners: readonly CoOwner[];
  /** The relayer rebuilds the totals and proves their digest under it, Rust `approval_blinder`. */
  readonly approvalBlinder?: Bytes32;
}

export function writeRelayListSalts(
  writer: Writer,
  salts: readonly RingListSalt[],
  sender: ShieldedAddress,
): Writer {
  const senderOwner = sender.signingPublicKey.ownerProofInputHash();
  const sent = salts.filter(({ owner, salt }) => !isZero(salt) && !equalBytes(owner, senderOwner));
  writer.u8(sent.length, "listSalts.length");
  for (const { owner, salt } of sent)
    writer.bytes(owner, 32, "listSalts.owner").bytes(salt, 32, "listSalts.salt");
  return writer;
}

/** The caller wipes the returned bytes, they hold every secret of the transfer. */
export function encodeRelayProofInputs(value: RelayProofInputs): Uint8Array {
  const writer = new Writer();
  writeRail(writer, value.rail);
  const nullifierSecret = value.nullifierKey.secretBytes();
  const txViewingSecret = value.txViewingKey.secretBytes();
  try {
    if (!equalBytes(value.nullifierKey.publicKey(), value.sender.nullifierPublicKey))
      throw refused("nullifierKey");
    writer
      .bytes(addressBytes(value.ringProgramId), 32, "ringProgramId")
      .bytes(value.sender.toBytes(), undefined, "sender")
      .bytes(nullifierSecret, BLINDING_LENGTH, "nullifierSecret")
      .bytes(txViewingSecret, 32, "txViewingSecret");
  } finally {
    nullifierSecret.fill(0);
    txViewingSecret.fill(0);
  }
  writer.u8(value.inputs.length, "inputs.length");
  // 1. Each spend matches its owner by address and nullifier key, the co-owner secrets below follow the match.
  const spending = new Set(
    value.inputs.map((input, index) => writeInput(writer, { input, index, value })),
  );
  writer.u8(value.outputs.length, "outputs.length");
  value.outputs.forEach((output, index) => writeOutput(writer, output, index, value.assets));
  writeExternalData(writer, value.externalData, value.interfaceTransferAccounts);
  writer.bytes(value.blindingSeed, 32, "blindingSeed").u16(value.outputTreeId, "outputTreeId");
  // 2. A held co-owner no spend names keeps its nullifier secret from the relayer.
  const disclosed = value.coOwners.filter((coOwner) => spending.has(coOwner));
  writeRelayListSalts(writer, value.listSalts, value.sender)
    .u8(value.wideOwners ? 1 : 0, "wideOwners")
    .u8(disclosed.length, "coOwners.length");
  for (const { owner, nullifierKey } of disclosed) {
    const secret = nullifierKey.secretBytes();
    writer
      .bytes(addressBytes(owner), 32, "coOwner.owner")
      .bytes(secret, BLINDING_LENGTH, "coOwner.nullifierSecret");
    secret.fill(0);
  }
  if (value.approvalBlinder === undefined) writer.u8(0, "approvalBlinder");
  else writer.u8(1, "approvalBlinder").bytes(value.approvalBlinder, 32, "approvalBlinder");
  return writer.finish();
}

/** Rust `RelayMergeInputs`, Ring RPC derives the merged note from the nullifier key. */
export interface RelayMergeInputs {
  readonly ringProgramId: Address;
  /** Owns every input. */
  readonly sender: ShieldedAddress;
  readonly nullifierKey: NullifierKey;
  readonly inputs: readonly ProofInputUtxo[];
  /** One per input. */
  readonly leafIndexes: readonly bigint[];
  readonly assets: AssetRegistry;
}

const DEPOSIT_REQUEST_DOMAIN = new TextEncoder().encode("zolana/ring-rpc-relay-deposit");

/** Rust `ProofInputBytes::deposit_request_digest`, the funder signs it over a deposit rail's bytes. */
export function depositRequestDigest(encoded: Uint8Array): Bytes32 {
  return sha256(concatBytes(DEPOSIT_REQUEST_DOMAIN, encoded)) as Bytes32;
}

const MERGE_REQUEST_DOMAIN = new TextEncoder().encode("zolana/ring-rpc-relay-merge");

/** Rust `ProofInputBytes::merge_request_digest`, over the bytes `encodeRelayMergeInputs` returns. */
export function mergeRequestDigest(encoded: Uint8Array): Bytes32 {
  return sha256(concatBytes(MERGE_REQUEST_DOMAIN, encoded)) as Bytes32;
}

/** The caller wipes the returned bytes, they hold the nullifier secret. */
export function encodeRelayMergeInputs(value: RelayMergeInputs): Uint8Array {
  const writer = new Writer();
  const nullifierSecret = value.nullifierKey.secretBytes();
  try {
    if (!equalBytes(value.nullifierKey.publicKey(), value.sender.nullifierPublicKey))
      throw refused("nullifierKey");
    writer
      .bytes(addressBytes(value.ringProgramId), 32, "ringProgramId")
      .bytes(value.sender.toBytes(), undefined, "sender")
      .bytes(nullifierSecret, BLINDING_LENGTH, "nullifierSecret");
  } finally {
    nullifierSecret.fill(0);
  }
  writer.u8(value.inputs.length, "inputs.length");
  value.inputs.forEach((input, index) =>
    writeSpend(writer, {
      input,
      index,
      leafIndex: value.leafIndexes[index],
      sender: value.sender,
      coOwners: [],
      assets: value.assets,
    }),
  );
  return writer.finish();
}

/** Rust `RelayProofInputs::decode`, every input hash and nullifier derived again from its opening. */
export async function decodeRelayProofInputs(
  bytes: Uint8Array,
  assets: AssetRegistry,
): Promise<RelayProofInputs> {
  const reader = new WireReader(bytes);
  const rail = readRail(reader);
  const ringProgramId = reader.address("ringProgramId");
  const sender = ShieldedAddress.fromBytes(reader.bytes(SHIELDED_ADDRESS_LENGTH, "sender"));
  const nullifierKey = NullifierKey.fromSecret(
    reader.bytes(BLINDING_LENGTH, "nullifierSecret") as Bytes31,
  );
  const txViewingKey = ViewingKey.fromBytes(reader.hash("txViewingSecret"));
  if (!equalBytes(nullifierKey.publicKey(), sender.nullifierPublicKey))
    throw refused("nullifierKey");
  const leafIndexes: bigint[] = [];
  const unresolved = reader.list("inputs", () => {
    const { input, leafIndex } = readInput(reader, sender, nullifierKey);
    leafIndexes.push(leafIndex);
    return input;
  });
  const outputs = reader.list("outputs", () => readOutput(reader));
  const external = readExternalData(reader);
  const blindingSeed = reader.hash("blindingSeed");
  const outputTreeId = reader.u16("outputTreeId");
  const listSalts = reader.list("listSalts", () =>
    Object.freeze({ owner: reader.hash("listSalts.owner"), salt: reader.hash("listSalts.salt") }),
  );
  const wideOwners = reader.u8("wideOwners") === 1;
  const coOwners = reader.list("coOwners", () =>
    Object.freeze({
      owner: reader.address("coOwner.owner"),
      nullifierKey: NullifierKey.fromSecret(
        reader.bytes(BLINDING_LENGTH, "coOwner.nullifierSecret") as Bytes31,
      ),
    }),
  );
  const approvalBlinder = readApprovalBlinder(reader);
  reader.done();
  const inputs = unresolved.map((input) => input(coOwners));
  const legs = await Promise.all(external.legs.map(settlementLeg));
  const externalData = createExternalData({
    ...external.fields,
    interfaceTransfers: legs.map((leg) => leg.transfer),
  });
  return Object.freeze({
    rail,
    ringProgramId,
    sender,
    nullifierKey,
    txViewingKey,
    inputs,
    leafIndexes,
    outputs,
    externalData,
    interfaceTransferAccounts: legs.map((leg) => leg.accounts),
    blindingSeed,
    outputTreeId,
    wideOwners,
    assets,
    listSalts,
    coOwners,
    ...(approvalBlinder === undefined ? {} : { approvalBlinder }),
  });
}

/** A wincode `Option`, any tag past one is not a canonical frame. */
function readApprovalBlinder(reader: WireReader): Bytes32 | undefined {
  const tag = reader.u8("approvalBlinder");
  if (tag > 1) throw refused("approvalBlinder", tag);
  return tag === 1 ? reader.hash("approvalBlinder") : undefined;
}

function writeRail(writer: Writer, rail: RelayRail): void {
  switch (rail.kind) {
    case "anonymous": {
      writer.u8(0, "rail");
      writePlan(writer, rail.plan);
      writer.option(rail.exitTokenOwner, (output, owner) =>
        output.bytes(addressBytes(owner), 32, "exitTokenOwner"),
      );
      return;
    }
    case "confidential":
      writer.u8(1, "rail");
      return;
    case "delegate":
      writer.u8(2, "rail").bytes(addressBytes(rail.delegate), 32, "delegate");
      writer.option(rail.plan, writePlan);
      return;
    case "deposit":
      writer.u8(3, "rail").option(rail.plan, writePlan);
      return;
  }
}

function writePlan(writer: Writer, plan: AnonymousPlan): void {
  writer.u8(plan.payments.length, "plan.payments.length");
  for (const payment of plan.payments)
    writer.bytes(payment.recipient.toBytes(), X25519_PUBLIC_KEY_LENGTH, "plan.payment.recipient");
  for (const preimage of plan.dummyPreimages()) writer.bytes(preimage, 32, "plan.dummyPreimage");
}

/** A spend of the sender or a held co-owner, a dummy or compact padding, the service derives hash and nullifier. */
function writeInput(
  writer: Writer,
  slot: Readonly<{ input: ProofInputUtxo; index: number; value: RelayProofInputs }>,
): CoOwner | undefined {
  const { input, index, value } = slot;
  if (input.isAddress() || input.cacheSlot !== undefined) throw refused("input", index);
  if (input.isCompact()) {
    writer.u8(2, "input").u16(input.treeId, "input.treeId");
    return undefined;
  }
  if (input.isDummy()) {
    writer.u8(1, "input").bytes(input.utxo.blinding, 32, "input.blinding");
    writer.u16(input.treeId, "input.treeId");
    return undefined;
  }
  writer.u8(0, "input");
  return writeSpend(writer, {
    input,
    index,
    leafIndex: value.leafIndexes[index],
    sender: value.sender,
    coOwners: value.coOwners,
    assets: value.assets,
  });
}

/** Rust `SpendWire`, refused unless the sender or a held co-owner spends it at a named leaf. */
function writeSpend(
  writer: Writer,
  spend: Readonly<{
    input: ProofInputUtxo;
    index: number;
    leafIndex: bigint | undefined;
    sender: ShieldedAddress;
    coOwners: readonly CoOwner[];
    assets: AssetRegistry;
  }>,
): CoOwner | undefined {
  const { input, index, leafIndex, sender, assets } = spend;
  if (
    input.isAddress() ||
    input.cacheSlot !== undefined ||
    input.isCompact() ||
    input.isDummy() ||
    leafIndex === undefined
  )
    throw refused("input", index);
  const spentBySender =
    input.utxo.owner.equals(sender.signingPublicKey) &&
    equalBytes(input.nullifierPublicKey, sender.nullifierPublicKey);
  const coOwner = spentBySender
    ? undefined
    : spend.coOwners.find(
        ({ owner, nullifierKey }) =>
          equalBytes(addressBytes(owner), input.utxo.owner.confidentialViewTag()) &&
          equalBytes(nullifierKey.publicKey(), input.nullifierPublicKey),
      );
  if (!spentBySender && coOwner === undefined) throw refused("input", index);
  const { utxo } = input;
  writer
    .bytes(addressBytes(utxo.asset), 32, "input.asset")
    .u64(assets.assetId(utxo.asset), "input.assetId")
    .u64(utxo.amount, "input.amount")
    .bytes(utxo.blinding, 32, "input.blinding");
  optionalAddress(writer, utxo.ringProgramId, "input.ringProgramId");
  writer.bytes(encodeData(utxo.data));
  optionalHash(writer, input.dataHash, "input.dataHash");
  optionalHash(writer, input.ringDataHash, "input.ringDataHash");
  writer.u16(input.treeId, "input.treeId").u64(leafIndex, "input.leafIndex");
  optionalAddress(writer, coOwner?.owner, "input.coOwner");
  return coOwner;
}

function writeOutput(
  writer: Writer,
  output: ProofOutputUtxo,
  index: number,
  assets: AssetRegistry,
): void {
  if (output.cacheSlot !== undefined) throw refused("cachedOutput", index);
  writer
    .bytes(addressBytes(output.asset), 32, "output.asset")
    .u64(assets.assetId(output.asset), "output.assetId")
    .u64(output.amount, "output.amount")
    .bytes(output.blinding, 32, "output.blinding");
  optionalAddress(writer, output.ringProgramId, "output.ringProgramId");
  optionalHash(writer, output.ringDataHash, "output.ringDataHash");
  optionalHash(writer, output.dataHash, "output.dataHash");
  writer.option(output.ownerAddress, (out, owner) => out.bytes(owner.toBytes()));
  optionalHash(writer, output.ownerTag, "output.ownerTag");
  writer.bytes(encodeData(output.data)).bool(output.compact === true, "output.compact");
}

function writeExternalData(
  writer: Writer,
  external: ExternalData,
  accounts: readonly RelayLegAccounts[],
): void {
  if (external.interfaceTransfers.length !== accounts.length)
    throw refused("settlement", Math.min(external.interfaceTransfers.length, accounts.length));
  writer
    .u8(external.instructionDiscriminator, "instructionDiscriminator")
    .u64(external.expiryUnixTs, "expiryUnixTs")
    .u8(external.interfaceTransfers.length, "legs.length");
  external.interfaceTransfers.forEach((transfer, index) =>
    writeLeg(writer, { transfer, index, accounts: accounts[index] }),
  );
  optionalHash(writer, external.dataHash, "dataHash");
  optionalHash(writer, external.ringDataHash, "ringDataHash");
  writer
    .bytes(external.txViewingPublicKey.toBytes(), X25519_PUBLIC_KEY_LENGTH, "txViewingPk")
    .bytes(external.salt, SALT_LENGTH, "salt")
    .u8(external.outputs.length, "outputs.length");
  for (const output of external.outputs) writeTransactOutput(writer, output);
  writer.u8(external.resolvedOwnerTags.length, "resolvedOwnerTags.length");
  for (const tag of external.resolvedOwnerTags) writer.bytes(tag, 32, "resolvedOwnerTag");
  writer.u8(external.messages.length, "messages.length");
  for (const message of external.messages) {
    writer.bytes(message.viewTag, 32, "message.viewTag");
    byteVector(writer, message.data, "message.data");
  }
}

/** Each leg carries the accounts the decoder derives again, Rust `legs`. */
function writeLeg(
  writer: Writer,
  leg: Readonly<{
    transfer: SettlementTransfer;
    index: number;
    accounts: RelayLegAccounts | undefined;
  }>,
): void {
  const { transfer, index, accounts } = leg;
  if (transfer.kind === "sol") {
    if (accounts?.kind !== "sol" || accounts.recipient !== transfer.userSolAccount)
      throw refused("settlement", index);
    writer
      .u8(transfer.isDeposit ? LegTag.solDeposit : LegTag.sol, "leg")
      .u64(transfer.amount, "leg.amount")
      .bytes(addressBytes(transfer.userSolAccount), 32, "leg.user");
    return;
  }
  if (transfer.isDeposit) {
    if (
      accounts?.kind !== "splDeposit" ||
      accounts.mint !== transfer.mint ||
      accounts.userTokenAccount !== transfer.tokenAccount
    )
      throw refused("settlement", index);
    writer
      .u8(LegTag.splDeposit, "leg")
      .bytes(addressBytes(transfer.mint), 32, "leg.mint")
      .u64(transfer.amount, "leg.amount")
      .bytes(addressBytes(accounts.tokenAuthority), 32, "leg.tokenAuthority")
      .bytes(addressBytes(transfer.tokenAccount), 32, "leg.userTokenAccount")
      .bytes(addressBytes(accounts.tokenProgram), 32, "leg.tokenProgram");
    return;
  }
  if (
    accounts?.kind !== "spl" ||
    accounts.mint !== transfer.mint ||
    accounts.recipientTokenAccount !== transfer.tokenAccount
  )
    throw refused("settlement", index);
  writer
    .u8(LegTag.spl, "leg")
    .bytes(addressBytes(transfer.mint), 32, "leg.mint")
    .u64(transfer.amount, "leg.amount")
    .bytes(addressBytes(transfer.tokenAccount), 32, "leg.userTokenAccount")
    .bytes(addressBytes(accounts.tokenProgram), 32, "leg.tokenProgram");
}

function optionalHash(writer: Writer, hash: Bytes32 | undefined, name: string): void {
  writer.option(hash, (out, value) => out.bytes(value, 32, name));
}

function optionalAddress(writer: Writer, address: Address | undefined, name: string): void {
  writer.option(address, (out, value) => out.bytes(addressBytes(value), 32, name));
}

function refused(reason: string, index?: number): RingError {
  return new RingError("RING_RELAY_PROOF_INPUTS", {
    details: { reason, ...(index === undefined ? {} : { index }) },
  });
}

class WireReader extends Reader {
  hash(name: string): Bytes32 {
    return this.bytes(32, name) as Bytes32;
  }

  address(name: string): Address {
    return encodeBase58(this.bytes(32, name));
  }

  byteVector(name: string): Uint8Array {
    return this.bytes(this.u16(`${name}.length`), name);
  }

  list<T>(name: string, read: () => T): T[] {
    return Array.from({ length: this.u8(`${name}.length`) }, read);
  }
}

function readPlan(reader: WireReader): AnonymousPlan {
  const payments = reader.list("plan.payments", () => ({
    recipient: X25519PublicKey.fromBytes(
      reader.bytes(X25519_PUBLIC_KEY_LENGTH, "plan.payment.recipient"),
    ),
    // A reply already sits sealed in the external data, the wire carries no plaintext.
    reply: null,
  }));
  const dummyPreimages = AnonymousPlan.create()
    .dummyPreimages()
    .map(() => reader.hash("plan.dummyPreimage"));
  return AnonymousPlan.fromDummyPreimages(payments, dummyPreimages);
}

function readRail(reader: WireReader): RelayRail {
  const tag = reader.u8("rail");
  switch (tag) {
    case 0: {
      const plan = readPlan(reader);
      const exitTokenOwner = reader.option("exitTokenOwner", () =>
        reader.address("exitTokenOwner"),
      );
      return Object.freeze({
        kind: "anonymous",
        plan,
        ...(exitTokenOwner === undefined ? {} : { exitTokenOwner }),
      });
    }
    case 1:
      return Object.freeze({ kind: "confidential" });
    case 2: {
      const delegate = reader.address("delegate");
      const plan = reader.option("plan", () => readPlan(reader));
      return Object.freeze({ kind: "delegate", delegate, ...(plan === undefined ? {} : { plan }) });
    }
    case 3: {
      const plan = reader.option("plan", () => readPlan(reader));
      return Object.freeze({ kind: "deposit", ...(plan === undefined ? {} : { plan }) });
    }
    default:
      throw refused("rail", tag);
  }
}

/** A co-owner's key follows the inputs on the wire, each spend resolves once the keys are read. */
function readInput(
  reader: WireReader,
  sender: ShieldedAddress,
  nullifierKey: NullifierKey,
): Readonly<{ input: (coOwners: readonly CoOwner[]) => ProofInputUtxo; leafIndex: bigint }> {
  const tag = reader.u8("input");
  if (tag === 2) {
    const compact = ProofInputUtxo.compact(reader.u16("input.treeId"));
    return { input: () => compact, leafIndex: 0n };
  }
  if (tag === 1) {
    const blinding = reader.hash("input.blinding");
    const dummy = ProofInputUtxo.dummy(blinding, reader.u16("input.treeId"));
    return { input: () => dummy, leafIndex: 0n };
  }
  if (tag !== 0) throw refused("input", tag);
  const asset = reader.address("input.asset");
  reader.u64("input.assetId");
  const amount = reader.u64("input.amount");
  const blinding = reader.hash("input.blinding");
  const ringProgramId = reader.option("input.ringProgramId", () =>
    reader.address("input.ringProgramId"),
  );
  const data = readData(reader, "input.data");
  const dataHash = reader.option("input.dataHash", () => reader.hash("input.dataHash"));
  const ringDataHash = reader.option("input.ringDataHash", () => reader.hash("input.ringDataHash"));
  const treeId = reader.u16("input.treeId");
  const leafIndex = reader.u64("input.leafIndex");
  const named = reader.option("input.coOwner", () => reader.address("input.coOwner"));
  const input = (coOwners: readonly CoOwner[]): ProofInputUtxo => {
    const held = coOwners.find((coOwner) => coOwner.owner === named);
    if (named !== undefined && held === undefined) throw refused("input", tag);
    const key = held?.nullifierKey ?? nullifierKey;
    const utxo = new Utxo({
      owner:
        named === undefined
          ? sender.signingPublicKey
          : ShieldedPublicKey.fromEd25519(addressBytes(named) as Bytes32),
      asset,
      amount,
      blinding,
      data,
      ...(ringProgramId === undefined ? {} : { ringProgramId }),
    });
    const nullifierPublicKey = key.publicKey();
    const utxoHash = utxo.proofInput(nullifierPublicKey, treeId, dataHash, ringDataHash).hash();
    return new ProofInputUtxo({
      utxo,
      nullifierPublicKey,
      nullifier: utxo.nullifier(utxoHash, key),
      treeId,
      ...(dataHash === undefined ? {} : { dataHash }),
      ...(ringDataHash === undefined ? {} : { ringDataHash }),
    });
  };
  return { input, leafIndex };
}

function readOutput(reader: WireReader): ProofOutputUtxo {
  const asset = reader.address("output.asset");
  reader.u64("output.assetId");
  const amount = reader.u64("output.amount");
  const blinding = reader.hash("output.blinding");
  const ringProgramId = reader.option("output.ringProgramId", () =>
    reader.address("output.ringProgramId"),
  );
  const ringDataHash = reader.option("output.ringDataHash", () =>
    reader.hash("output.ringDataHash"),
  );
  const dataHash = reader.option("output.dataHash", () => reader.hash("output.dataHash"));
  const ownerAddress = reader.option("output.ownerAddress", () =>
    ShieldedAddress.fromBytes(reader.bytes(SHIELDED_ADDRESS_LENGTH, "output.ownerAddress")),
  );
  const ownerTag = reader.option("output.ownerTag", () => reader.hash("output.ownerTag"));
  const data = readData(reader, "output.data");
  const compact = reader.bool("output.compact");
  return createProofOutput({
    asset,
    amount,
    blinding,
    data,
    ...(ringProgramId === undefined ? {} : { ringProgramId }),
    ...(ringDataHash === undefined ? {} : { ringDataHash }),
    ...(dataHash === undefined ? {} : { dataHash }),
    ...(ownerAddress === undefined ? {} : { ownerAddress }),
    ...(ownerTag === undefined ? {} : { ownerTag }),
    ...(compact ? { compact } : {}),
  });
}

/** Every field but the interface transfers, whose SPL legs derive their interface account. */
function readExternalData(reader: WireReader): Readonly<{
  fields: Omit<Parameters<typeof createExternalData>[0], "interfaceTransfers">;
  legs: readonly LegWire[];
}> {
  const instructionDiscriminator = reader.u8("instructionDiscriminator");
  const expiryUnixTs = reader.u64("expiryUnixTs");
  const legs = reader.list("legs", () => readLeg(reader));
  const dataHash = reader.option("dataHash", () => reader.hash("dataHash"));
  const ringDataHash = reader.option("ringDataHash", () => reader.hash("ringDataHash"));
  const txViewingPublicKey = X25519PublicKey.fromBytes(
    reader.bytes(X25519_PUBLIC_KEY_LENGTH, "txViewingPk"),
  );
  const salt = reader.bytes(SALT_LENGTH, "salt") as Bytes16;
  const outputs = reader.list("outputs", (): TransactOutput => {
    const utxoHash = reader.hash("output.utxoHash");
    const ownerTag = readOwnerTag(reader);
    const data = reader.option("output.data", () => reader.byteVector("output.data"));
    return { utxoHash, ownerTag, ...(data === undefined ? {} : { data }) };
  });
  const resolvedOwnerTags = reader.list("resolvedOwnerTags", () => reader.hash("resolvedOwnerTag"));
  const messages = reader.list("messages", () => ({
    viewTag: reader.hash("message.viewTag"),
    data: reader.byteVector("message.data"),
  }));
  return {
    fields: {
      instructionDiscriminator,
      expiryUnixTs,
      ...(dataHash === undefined ? {} : { dataHash }),
      ...(ringDataHash === undefined ? {} : { ringDataHash }),
      txViewingPublicKey,
      salt,
      outputs,
      resolvedOwnerTags,
      messages,
    },
    legs,
  };
}

function readOwnerTag(reader: WireReader): OwnerTag {
  const kind = reader.u8("ownerTag");
  if (kind === 0) return { kind: "inline", value: reader.hash("ownerTag.value") };
  if (kind === 1) return { kind: "account", index: reader.u8("ownerTag.index") };
  throw refused("ownerTag", kind);
}

/** Rust `LegWire` in tag order. */
const LegTag = Object.freeze({ sol: 0, spl: 1, solDeposit: 2, splDeposit: 3 } as const);

/** Rust `LegWire`. */
type LegWire =
  | Readonly<{ kind: "sol"; isDeposit: boolean; amount: bigint; user: Address }>
  | Readonly<{
      kind: "spl";
      mint: Address;
      amount: bigint;
      userTokenAccount: Address;
      tokenProgram: Address;
    }>
  | Readonly<{
      kind: "splDeposit";
      mint: Address;
      amount: bigint;
      tokenAuthority: Address;
      userTokenAccount: Address;
      tokenProgram: Address;
    }>;

function readLeg(reader: WireReader): LegWire {
  const tag = reader.u8("leg");
  switch (tag) {
    case LegTag.sol:
    case LegTag.solDeposit:
      return {
        kind: "sol",
        isDeposit: tag === LegTag.solDeposit,
        amount: reader.u64("leg.amount"),
        user: reader.address("leg.user"),
      };
    case LegTag.spl:
      return {
        kind: "spl",
        mint: reader.address("leg.mint"),
        amount: reader.u64("leg.amount"),
        userTokenAccount: reader.address("leg.userTokenAccount"),
        tokenProgram: reader.address("leg.tokenProgram"),
      };
    case LegTag.splDeposit:
      return {
        kind: "splDeposit",
        mint: reader.address("leg.mint"),
        amount: reader.u64("leg.amount"),
        tokenAuthority: reader.address("leg.tokenAuthority"),
        userTokenAccount: reader.address("leg.userTokenAccount"),
        tokenProgram: reader.address("leg.tokenProgram"),
      };
    default:
      throw refused("leg", tag);
  }
}

/** Rust `LegWire::settlement`. */
async function settlementLeg(
  wire: LegWire,
): Promise<Readonly<{ transfer: SettlementTransfer; accounts: RelayLegAccounts }>> {
  if (wire.kind === "sol")
    return {
      transfer: {
        kind: "sol",
        isDeposit: wire.isDeposit,
        amount: wire.amount,
        userSolAccount: wire.user,
      },
      accounts: TransactWithdrawal.sol({ recipient: wire.user }),
    };
  const [splTokenInterface, splInterfaceBump] = await splInterfaceWithBump(wire.mint);
  const transfer: SettlementTransfer = {
    kind: "spl",
    mint: wire.mint,
    isDeposit: wire.kind === "splDeposit",
    amount: wire.amount,
    tokenAccount: wire.userTokenAccount,
    splInterfaceBump,
  };
  return {
    transfer,
    accounts:
      wire.kind === "splDeposit"
        ? Object.freeze({
            kind: "splDeposit",
            mint: wire.mint,
            splTokenInterface,
            tokenAuthority: wire.tokenAuthority,
            userTokenAccount: wire.userTokenAccount,
            tokenProgram: wire.tokenProgram,
          })
        : TransactWithdrawal.spl({
            mint: wire.mint,
            splTokenInterface,
            recipientTokenAccount: wire.userTokenAccount,
            tokenProgram: wire.tokenProgram,
          }),
  };
}
