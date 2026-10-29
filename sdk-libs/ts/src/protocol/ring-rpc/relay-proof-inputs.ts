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
  encodeBase58,
  encodeData,
  equalBytes,
  readData,
  splInterfaceWithBump,
  writeTransactOutput,
} from "@heliuslabs/zolana/internal";
import {
  TransactWithdrawal,
  type Address,
  type Bytes16,
  type Bytes31,
  type Bytes32,
  type OwnerTag,
  type TransactOutput,
} from "@heliuslabs/zolana/interface";
import {
  NullifierKey,
  ShieldedAddress,
  ViewingKey,
  X25519PublicKey,
  type ViewTag,
} from "@heliuslabs/zolana/keypair";
import {
  ProofInputUtxo,
  Utxo,
  createExternalData,
  createProofOutput,
  type AssetRegistry,
  type ExternalData,
  type ProofOutputUtxo,
  type SettlementTransfer,
} from "@heliuslabs/zolana/transaction";

import { AnonymousPlan } from "../../operations/payments/output-rail.js";
import { RingError } from "../error.js";

/** Rust `RelayRail`. */
export type RelayRail =
  | Readonly<{ kind: "anonymous"; plan: AnonymousPlan; exitTokenOwner?: Address }>
  | Readonly<{ kind: "confidential" }>
  | Readonly<{ kind: "delegate"; delegate: Address }>;

/** Rust `RelayProofInputs`. */
export interface RelayProofInputs {
  readonly rail: RelayRail;
  readonly ringProgramId: Address;
  /** Owns every real input. */
  readonly sender: ShieldedAddress;
  readonly nullifierKey: NullifierKey;
  readonly txViewingKey: ViewingKey;
  /** Opens the auditor message of `externalData` with the auditor public key alone. */
  readonly auditEphemeralKey: Bytes32;
  readonly inputs: readonly ProofInputUtxo[];
  /** One per input slot, read on spends only. */
  readonly leafIndexes: readonly bigint[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly externalData: ExternalData;
  /** The accounts of the one withdrawal leg. */
  readonly withdrawal?: TransactWithdrawal;
  readonly blindingSeed: Bytes32;
  readonly outputTreeId: number;
  readonly assets: AssetRegistry;
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
      .bytes(txViewingSecret, 32, "txViewingSecret")
      .bytes(value.auditEphemeralKey, 32, "auditEphemeralKey");
  } finally {
    nullifierSecret.fill(0);
    txViewingSecret.fill(0);
  }
  writer.u8(value.inputs.length, "inputs.length");
  value.inputs.forEach((input, index) => writeInput(writer, { input, index, value }));
  writer.u8(value.outputs.length, "outputs.length");
  value.outputs.forEach((output, index) => writeOutput(writer, output, index, value.assets));
  writeExternalData(writer, value.externalData, value.withdrawal);
  return writer
    .bytes(value.blindingSeed, 32, "blindingSeed")
    .u16(value.outputTreeId, "outputTreeId")
    .finish();
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
      assets: value.assets,
    }),
  );
  return writer.finish();
}

/** Rust `RelayProofInputs::decode`, every input hash and nullifier derived again from its opening. */
export async function decodeRelayProofInputs(
  bytes: Uint8Array,
  assets: AssetRegistry,
): Promise<RelayProofInputs & Readonly<{ withdrawals: readonly TransactWithdrawal[] }>> {
  const reader = new WireReader(bytes);
  const rail = readRail(reader);
  const ringProgramId = reader.address("ringProgramId");
  const sender = ShieldedAddress.fromBytes(reader.bytes(SHIELDED_ADDRESS_LENGTH, "sender"));
  const nullifierKey = NullifierKey.fromSecret(
    reader.bytes(BLINDING_LENGTH, "nullifierSecret") as Bytes31,
  );
  const txViewingKey = ViewingKey.fromBytes(reader.hash("txViewingSecret"));
  const auditEphemeralKey = reader.hash("auditEphemeralKey");
  if (!equalBytes(nullifierKey.publicKey(), sender.nullifierPublicKey))
    throw refused("nullifierKey");
  const leafIndexes: bigint[] = [];
  const inputs = reader.list("inputs", () => {
    const { input, leafIndex } = readInput(reader, sender, nullifierKey);
    leafIndexes.push(leafIndex);
    return input;
  });
  const outputs = reader.list("outputs", () => readOutput(reader));
  const external = readExternalData(reader);
  const blindingSeed = reader.hash("blindingSeed");
  const outputTreeId = reader.u16("outputTreeId");
  reader.done();
  const legs = await Promise.all(external.legs.map(withdrawalLeg));
  const externalData = createExternalData({
    ...external.fields,
    interfaceTransfers: legs.map((leg) => leg.transfer),
  });
  const withdrawals = legs.map((leg) => leg.withdrawal);
  return Object.freeze({
    rail,
    ringProgramId,
    sender,
    nullifierKey,
    txViewingKey,
    auditEphemeralKey,
    inputs,
    leafIndexes,
    outputs,
    externalData,
    ...(withdrawals[0] === undefined ? {} : { withdrawal: withdrawals[0] }),
    withdrawals,
    blindingSeed,
    outputTreeId,
    assets,
  });
}

function writeRail(writer: Writer, rail: RelayRail): void {
  switch (rail.kind) {
    case "anonymous": {
      writer.u8(0, "rail").bytes(rail.plan.senderTag, 32, "plan.senderTag");
      writer.u8(rail.plan.payments.length, "plan.payments.length");
      for (const payment of rail.plan.payments)
        writer
          .bytes(payment.recipient.toBytes(), X25519_PUBLIC_KEY_LENGTH, "plan.payment.recipient")
          .bytes(payment.tag, 32, "plan.payment.tag");
      for (const tag of rail.plan.dummyTags()) writer.bytes(tag, 32, "plan.dummyTag");
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
      return;
  }
}

/** A spend of the sender, a dummy or compact padding, the service derives hash and nullifier. */
function writeInput(
  writer: Writer,
  slot: Readonly<{ input: ProofInputUtxo; index: number; value: RelayProofInputs }>,
): void {
  const { input, index, value } = slot;
  if (input.isAddress() || input.cacheSlot !== undefined) throw refused("input", index);
  if (input.isCompact()) {
    writer.u8(2, "input").u16(input.treeId, "input.treeId");
    return;
  }
  if (input.isDummy()) {
    writer.u8(1, "input").bytes(input.utxo.blinding, 32, "input.blinding");
    writer.u16(input.treeId, "input.treeId");
    return;
  }
  writer.u8(0, "input");
  writeSpend(writer, {
    input,
    index,
    leafIndex: value.leafIndexes[index],
    sender: value.sender,
    assets: value.assets,
  });
}

/** Rust `SpendWire`, refused unless it is a spend of the sender with a named leaf. */
function writeSpend(
  writer: Writer,
  spend: Readonly<{
    input: ProofInputUtxo;
    index: number;
    leafIndex: bigint | undefined;
    sender: ShieldedAddress;
    assets: AssetRegistry;
  }>,
): void {
  const { input, index, leafIndex, sender, assets } = spend;
  if (
    input.isAddress() ||
    input.cacheSlot !== undefined ||
    input.isCompact() ||
    input.isDummy() ||
    !input.utxo.owner.equals(sender.signingPublicKey) ||
    leafIndex === undefined
  )
    throw refused("input", index);
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
  withdrawal: TransactWithdrawal | undefined,
): void {
  writer
    .u8(external.instructionDiscriminator, "instructionDiscriminator")
    .u64(external.expiryUnixTs, "expiryUnixTs")
    .u8(external.interfaceTransfers.length, "withdrawals.length");
  external.interfaceTransfers.forEach((transfer, index) =>
    writeWithdrawal(writer, { transfer, index, withdrawal }),
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

/** Each leg a withdrawal whose accounts the decoder derives again. */
function writeWithdrawal(
  writer: Writer,
  leg: Readonly<{
    transfer: SettlementTransfer;
    index: number;
    withdrawal: TransactWithdrawal | undefined;
  }>,
): void {
  const { transfer, index, withdrawal } = leg;
  if (transfer.isDeposit || index > 0 || withdrawal === undefined)
    throw refused("settlement", index);
  if (transfer.kind === "sol" && withdrawal.kind === "sol") {
    if (withdrawal.recipient !== transfer.userSolAccount) throw refused("settlement", index);
    writer
      .u8(0, "withdrawal")
      .u64(transfer.amount, "withdrawal.amount")
      .bytes(addressBytes(transfer.userSolAccount), 32, "withdrawal.recipient");
    return;
  }
  if (
    transfer.kind !== "spl" ||
    withdrawal.kind !== "spl" ||
    withdrawal.mint !== transfer.mint ||
    withdrawal.recipientTokenAccount !== transfer.tokenAccount
  )
    throw refused("settlement", index);
  writer
    .u8(1, "withdrawal")
    .bytes(addressBytes(transfer.mint), 32, "withdrawal.mint")
    .u64(transfer.amount, "withdrawal.amount")
    .bytes(addressBytes(transfer.tokenAccount), 32, "withdrawal.userTokenAccount")
    .bytes(addressBytes(withdrawal.tokenProgram), 32, "withdrawal.tokenProgram");
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

function readRail(reader: WireReader): RelayRail {
  const tag = reader.u8("rail");
  switch (tag) {
    case 0: {
      const senderTag = reader.hash("plan.senderTag");
      const payments = reader.list("plan.payments", () => ({
        recipient: X25519PublicKey.fromBytes(
          reader.bytes(X25519_PUBLIC_KEY_LENGTH, "plan.payment.recipient"),
        ),
        tag: reader.hash("plan.payment.tag") as ViewTag,
      }));
      const dummyTags = AnonymousPlan.create(senderTag)
        .dummyTags()
        .map(() => reader.hash("plan.dummyTag") as ViewTag);
      const exitTokenOwner = reader.option("exitTokenOwner", () =>
        reader.address("exitTokenOwner"),
      );
      return Object.freeze({
        kind: "anonymous",
        plan: AnonymousPlan.fromTags(senderTag as ViewTag, payments, dummyTags),
        ...(exitTokenOwner === undefined ? {} : { exitTokenOwner }),
      });
    }
    case 1:
      return Object.freeze({ kind: "confidential" });
    case 2:
      return Object.freeze({ kind: "delegate", delegate: reader.address("delegate") });
    default:
      throw refused("rail", tag);
  }
}

function readInput(
  reader: WireReader,
  sender: ShieldedAddress,
  nullifierKey: NullifierKey,
): Readonly<{ input: ProofInputUtxo; leafIndex: bigint }> {
  const tag = reader.u8("input");
  if (tag === 2)
    return { input: ProofInputUtxo.compact(reader.u16("input.treeId")), leafIndex: 0n };
  if (tag === 1) {
    const blinding = reader.hash("input.blinding");
    return { input: ProofInputUtxo.dummy(blinding, reader.u16("input.treeId")), leafIndex: 0n };
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
  const utxo = new Utxo({
    owner: sender.signingPublicKey,
    asset,
    amount,
    blinding,
    data,
    ...(ringProgramId === undefined ? {} : { ringProgramId }),
  });
  const nullifierPublicKey = nullifierKey.publicKey();
  const utxoHash = utxo.proofInput(nullifierPublicKey, treeId, dataHash, ringDataHash).hash();
  return {
    input: new ProofInputUtxo({
      utxo,
      nullifierPublicKey,
      nullifier: utxo.nullifier(utxoHash, nullifierKey),
      treeId,
      ...(dataHash === undefined ? {} : { dataHash }),
      ...(ringDataHash === undefined ? {} : { ringDataHash }),
    }),
    leafIndex,
  };
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
  legs: readonly WithdrawalWire[];
}> {
  const instructionDiscriminator = reader.u8("instructionDiscriminator");
  const expiryUnixTs = reader.u64("expiryUnixTs");
  const legs = reader.list("withdrawals", () => readWithdrawal(reader));
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

/** Rust `WithdrawalWire`. */
type WithdrawalWire =
  | Readonly<{ kind: "sol"; amount: bigint; recipient: Address }>
  | Readonly<{
      kind: "spl";
      mint: Address;
      amount: bigint;
      userTokenAccount: Address;
      tokenProgram: Address;
    }>;

function readWithdrawal(reader: WireReader): WithdrawalWire {
  const tag = reader.u8("withdrawal");
  if (tag === 0)
    return {
      kind: "sol",
      amount: reader.u64("withdrawal.amount"),
      recipient: reader.address("withdrawal.recipient"),
    };
  if (tag !== 1) throw refused("withdrawal", tag);
  return {
    kind: "spl",
    mint: reader.address("withdrawal.mint"),
    amount: reader.u64("withdrawal.amount"),
    userTokenAccount: reader.address("withdrawal.userTokenAccount"),
    tokenProgram: reader.address("withdrawal.tokenProgram"),
  };
}

/** Rust `WithdrawalWire::legs`. */
async function withdrawalLeg(
  wire: WithdrawalWire,
): Promise<Readonly<{ transfer: SettlementTransfer; withdrawal: TransactWithdrawal }>> {
  if (wire.kind === "sol")
    return {
      transfer: {
        kind: "sol",
        isDeposit: false,
        amount: wire.amount,
        userSolAccount: wire.recipient,
      },
      withdrawal: TransactWithdrawal.sol({ recipient: wire.recipient }),
    };
  const [splTokenInterface, splInterfaceBump] = await splInterfaceWithBump(wire.mint);
  return {
    transfer: {
      kind: "spl",
      mint: wire.mint,
      isDeposit: false,
      amount: wire.amount,
      tokenAccount: wire.userTokenAccount,
      splInterfaceBump,
    },
    withdrawal: TransactWithdrawal.spl({
      mint: wire.mint,
      splTokenInterface,
      recipientTokenAccount: wire.userTokenAccount,
      tokenProgram: wire.tokenProgram,
    }),
  };
}
