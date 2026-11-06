import { RingInstructionTag } from "./instruction-tag.js";
import { getBase58Encoder } from "@solana/kit";

import {
  runKitRpc,
  type SolanaRpc,
  wireDecoder,
  Reader,
  Writer,
  addressBytes,
  encodeBase58,
  treeAddress,
  equalBytes,
  encodeMergeOutputData,
} from "@heliuslabs/spr/internal";
import {
  MAX_CACHE_WRITES,
  INPUT_TREES,
  InstructionTag,
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
} from "@heliuslabs/spr/interface";
import type { IndexedShieldedTransaction } from "@heliuslabs/spr/transaction";
import { X25519PublicKey } from "@heliuslabs/spr/keypair";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
  InterfaceTransfer,
  RequestContext,
  Signature,
} from "@heliuslabs/spr/interface";
import { SOL_MINT } from "@heliuslabs/spr/transaction";
import type { AuditStreamLayout } from "../codec/ring-disclosure-layout.js";

import { RingError } from "../error.js";
import {
  decodeRingMergeRequest,
  forwardedMergeData,
  sppMergeBody,
  type MergeRingAuthority,
  type SealedMergeRecord,
} from "../../crypto/audit/merge-disclosure.js";
import { RingTransactData, landedRingRail, type RingRail } from "./transact.js";
import { readMergeData, writeInterfaceTransfer } from "../codec/codecs.js";

const base58Encoder = getBase58Encoder();

/** Mirrors Rust `ConfirmedEventKind`, the confirmed instruction selects it, never indexer metadata. */
export type ConfirmedEventKind = "transfer" | "merge";

/** Rust `RingOrigin` after `bind_transaction`, the indexed event bound to its confirmed instruction. */
export type ConfirmedRingTransaction =
  | Readonly<{
      kind: "transfer";
      transaction: IndexedShieldedTransaction;
      /** Rust `ConfirmedEvent::input_tree_ids`, an input spent from a tree other than the output tree has no id. */
      inputTreeIds: readonly (number | undefined)[];
      /** The layout the ring program verified the audit proof under, read from its confirmed instruction. */
      layout: AuditStreamLayout;
      rail: RingRail;
      /** The statement's bit, the sealed `R` is zero. */
      noSpend: boolean;
      hasData: boolean;
      entry: boolean;
    }>
  | Readonly<{
      kind: "merge";
      transaction: IndexedShieldedTransaction;
      /** The record whose proof the direct ring caller verified. */
      sealedRecord: Pick<SealedMergeRecord, "ephemeralPublicKey" | "ciphertext">;
      authority: MergeRingAuthority;
    }>;

/** Mirrors Rust `TransactionOrigin`, an unknown signature is an error, never absent. */
export interface TransactionOrigin {
  /** Binds indexed data to the exact confirmed transfer or merge. Other-ring events return undefined. */
  confirmedTransaction(
    transaction: IndexedShieldedTransaction,
    ring: Address,
    context?: RequestContext,
  ): Promise<ConfirmedRingTransaction | undefined>;
}

/** Tag 57's record, its forwarded bytes the SPP data the program verified. */
function confirmedMergeRecordOf(
  found: TrustedEvent,
): Pick<Extract<ConfirmedRingTransaction, { kind: "merge" }>, "sealedRecord" | "authority"> {
  const wrapper = found.wrapper;
  if (
    found.source.data[0] !== InstructionTag.ringMergeTransact ||
    wrapper?.data[0] !== RingInstructionTag.merge
  )
    throw invalid("merge.instruction");
  const request = decodeRingMergeRequest(wrapper.data.subarray(1));
  const forwarded = forwardedMergeData(
    request,
    sppMergeBody(request.compactBody),
    InstructionTag.ringMergeTransact,
  );
  if (!equalBytes(forwarded, found.source.data)) throw invalid("merge.sealedRecord");
  const { ephemeralPublicKey, ciphertext } = request.sealed;
  return {
    sealedRecord: Object.freeze({ ephemeralPublicKey, ciphertext }),
    authority: request.authority,
  };
}

export interface OriginInstruction {
  readonly programId: Address;
  /** 1 for an outer instruction, absent when the RPC reports none. */
  readonly stackHeight?: number;
  readonly accounts: readonly Address[];
  readonly data: Uint8Array;
}

/** Mirrors Rust `InstructionGroup`, one outer instruction with its inner instructions in execution order. */
export interface OriginInstructionGroup {
  readonly outer: OriginInstruction;
  readonly inner: readonly OriginInstruction[];
}

/** Mirrors Rust `RingWithdrawal`, one public settlement leg out of the ring. */
export interface RingWithdrawal {
  /** Checked at execution, read from confirmed policy metadata. */
  readonly screenedOwner?: Address;
  /** The wallet of a SOL leg, the credited token account of an SPL leg. */
  readonly recipient: Address;
  readonly asset: Address;
  readonly amount: bigint;
}

/**
 * Mirrors Rust `ORIGIN_TRANSACTION_CONFIG`. A transact is a version 1
 * transaction, and an RPC allowed a lower version answers the read with an
 * unsupported-version error instead of the transaction.
 */
export const ORIGIN_TRANSACTION_CONFIG = Object.freeze({
  encoding: "json",
  commitment: "confirmed",
  maxSupportedTransactionVersion: 1,
} as const);

/**
 * Mirrors Rust `ring_instructions_in`. `ring_transact` needs the ring's
 * `ring_auth` PDA as signer, so only a pool instruction whose direct caller is
 * `ring` belongs to the ring.
 */
export function ringInstructionsIn(
  groups: readonly OriginInstructionGroup[],
  ring: Address,
): readonly OriginInstruction[] {
  return Object.freeze(
    instructionAncestry(groups)
      .filter(
        ({ instruction, parent }) =>
          instruction.programId === SHIELDED_POOL_PROGRAM_ID && parent?.programId === ring,
      )
      .map(({ instruction }) => instruction),
  );
}

/** Mirrors Rust `ring_invoked_in`. */
export function ringInvokedIn(groups: readonly OriginInstructionGroup[], ring: Address): boolean {
  return ringInstructionsIn(groups, ring).length > 0;
}

interface TrustedEvent {
  readonly source: OriginInstruction;
  readonly event: OriginInstruction;
  readonly wrapper: OriginInstruction | undefined;
}

function ringEventIn(
  groups: readonly OriginInstructionGroup[],
  eventIndex: number,
  ring: Address,
): TrustedEvent | undefined {
  if (!Number.isInteger(eventIndex) || eventIndex < 0 || eventIndex > 0xffff)
    throw invalid("eventIndex");
  const found = trustedEvents(groups)[eventIndex];
  if (found === undefined) throw invalid("eventIndex");
  return found.wrapper?.programId === ring ? found : undefined;
}

/** One checked execution stack owns direct caller and exact self-CPI event attribution. */
function instructionAncestry(groups: readonly OriginInstructionGroup[]): readonly Readonly<{
  instruction: OriginInstruction;
  parent: OriginInstruction | undefined;
  grandparent: OriginInstruction | undefined;
}>[] {
  const ancestry = [];
  for (const group of groups) {
    const stack = [group.outer];
    for (const instruction of group.inner) {
      const height = instruction.stackHeight;
      if (height === undefined)
        throw new RingError("RING_ORIGIN_STACK", {
          details: { reason: "missing stack height" },
        });
      if (!Number.isInteger(height) || height < 2 || height > stack.length + 1)
        throw new RingError("RING_ORIGIN_STACK", {
          details: { reason: "no parent", height },
        });
      stack.length = height - 1;
      ancestry.push({
        instruction,
        parent: stack[height - 2],
        grandparent: stack[height - 3],
      });
      stack.push(instruction);
    }
  }
  return ancestry;
}

function trustedEvents(groups: readonly OriginInstructionGroup[]): readonly TrustedEvent[] {
  const events: TrustedEvent[] = [];
  for (const { instruction, parent, grandparent } of instructionAncestry(groups)) {
    if (
      instruction.programId === SHIELDED_POOL_PROGRAM_ID &&
      instruction.data[0] === InstructionTag.emitEvent &&
      parent?.programId === SHIELDED_POOL_PROGRAM_ID &&
      isEventSourceTag(parent.data[0])
    )
      events.push({ source: parent, event: instruction, wrapper: grandparent });
  }
  return events;
}

function isEventSourceTag(value: number | undefined): boolean {
  return (
    value === InstructionTag.deposit ||
    value === InstructionTag.ringDeposit ||
    value === InstructionTag.transact ||
    value === InstructionTag.ringTransact ||
    value === InstructionTag.ringAuthorityTransact ||
    value === InstructionTag.mergeTransact ||
    value === InstructionTag.ringMergeTransact
  );
}

/**
 * Mirrors Rust `ring_withdrawals_of`. One settlement account group per interface
 * transfer sits in transfer order before the cache accounts a cached selector
 * appends: the cache, then its signing writer when the selector writes.
 */
export function ringWithdrawalsOf(
  instructions: readonly OriginInstruction[],
): readonly RingWithdrawal[] {
  const withdrawals: RingWithdrawal[] = [];
  for (const instruction of instructions) {
    const settlement = settlementDataOf(instruction);
    if (settlement === undefined) continue;
    const { transfers, cacheAccountCount } = settlement;
    const total = transfers.reduce((sum, transfer) => sum + settlementWidth(transfer), 0);
    let at = instruction.accounts.length - cacheAccountCount - total;
    if (at < 0) throw invalid("settlementAccounts");
    for (const transfer of transfers) {
      const width = settlementWidth(transfer);
      const leg = withdrawalLeg(transfer, instruction.accounts.slice(at, at + width));
      at += width;
      if (leg !== undefined) withdrawals.push(leg);
    }
  }
  return Object.freeze(withdrawals);
}

/**
 * Mirrors Rust `ConfirmedInstructionGroups::try_from` over a
 * `getTransaction` JSON result.
 */
export function confirmedInstructionGroups(
  transaction: unknown,
): readonly OriginInstructionGroup[] {
  const wire = record(transaction, "transaction");
  const encoded = record(wire["transaction"], "transaction.transaction");
  const message = record(encoded["message"], "transaction.transaction.message");
  const meta = record(wire["meta"], "transaction.meta");
  if (meta["err"] !== null) throw invalid("meta.err");
  const accountKeys = messageAccountKeys(message, meta);
  const groups = list(message["instructions"], "message.instructions").map(
    (instruction, index): { outer: OriginInstruction; inner: OriginInstruction[] } => ({
      outer: parsed(accountKeys, instruction, `message.instructions[${index}]`),
      inner: [],
    }),
  );
  // Rust refuses a transaction without `innerInstructions`, the walk would miss every CPI.
  const innerGroups = list(meta["innerInstructions"], "meta.innerInstructions");
  innerGroups.forEach((entry, groupIndex) => {
    const path = `meta.innerInstructions[${groupIndex}]`;
    const innerGroup = record(entry, path);
    const outerIndex = innerGroup["index"];
    const group = typeof outerIndex === "number" ? groups[outerIndex] : undefined;
    if (group === undefined) throw invalid(`${path}.index`);
    group.inner = list(innerGroup["instructions"], `${path}.instructions`).map(
      (instruction, index): OriginInstruction => {
        const instructionPath = `${path}.instructions[${index}]`;
        const height = record(instruction, instructionPath)["stackHeight"];
        return {
          ...parsed(accountKeys, instruction, instructionPath),
          ...(height === undefined || height === null ? {} : { stackHeight: stackHeight(height) }),
        };
      },
    );
  });
  return groups.map((group) =>
    Object.freeze({
      outer: Object.freeze(group.outer),
      inner: Object.freeze(group.inner),
    }),
  );
}

/** Static keys, then the loaded writable and readonly addresses, the order instruction indexes count in. */
function messageAccountKeys(
  message: Readonly<Record<string, unknown>>,
  meta: Readonly<Record<string, unknown>>,
): readonly Address[] {
  const statics = addresses(message["accountKeys"], "message.accountKeys");
  const lookups = message["addressTableLookups"];
  const tables =
    lookups === undefined || lookups === null
      ? []
      : list(lookups, "message.addressTableLookups").map((lookup, index) =>
          record(lookup, `message.addressTableLookups[${index}]`),
        );
  const loaded = meta["loadedAddresses"];
  if (loaded === undefined || loaded === null) {
    if (tables.length > 0) throw invalid("meta.loadedAddresses");
    return statics;
  }
  const loadedRecord = record(loaded, "meta.loadedAddresses");
  const writable = addresses(loadedRecord["writable"], "meta.loadedAddresses.writable");
  const readonly = addresses(loadedRecord["readonly"], "meta.loadedAddresses.readonly");
  const indexes = (key: "writableIndexes" | "readonlyIndexes") =>
    tables.reduce(
      (count, table, index) =>
        count + list(table[key], `message.addressTableLookups[${index}].${key}`).length,
      0,
    );
  // Each lookup index loads one address, any other count names accounts no lookup loaded.
  if (
    writable.length !== indexes("writableIndexes") ||
    readonly.length !== indexes("readonlyIndexes")
  )
    throw invalid("meta.loadedAddresses");
  return [...statics, ...writable, ...readonly];
}

/** The public settlement legs a confirmed transaction paid out of `ring`. */
export function confirmedRingWithdrawals(
  transaction: unknown,
  ring: Address,
): readonly RingWithdrawal[] {
  const groups = confirmedInstructionGroups(transaction);
  return Object.freeze(
    instructionAncestry(groups).flatMap(({ instruction, parent }) => {
      if (parent?.programId !== ring || instruction.programId !== SHIELDED_POOL_PROGRAM_ID)
        return [];
      const withdrawals = ringWithdrawalsOf([instruction]);
      if (withdrawals.length === 0) return withdrawals;
      const source = settlementDataOf(instruction);
      if (source === undefined) return withdrawals;
      const frame = screenedFrame(parent.data, source.anonymous);
      if (frame === undefined) return withdrawals;
      const encodeLegs = (legs: readonly InterfaceTransfer[]) => {
        const writer = new Writer();
        for (const leg of legs) writeInterfaceTransfer(writer, leg);
        return writer.finish();
      };
      if (!equalBytes(encodeLegs(frame.interfaceTransfers), encodeLegs(source.transfers)))
        throw invalid("withdrawal.transfers");
      let index = 0;
      const bound = withdrawals.map((leg) => {
        const raw = leg.asset === SOL_MINT ? undefined : frame.splWithdrawalOwners[index++];
        if (leg.asset !== SOL_MINT && raw === undefined) throw invalid("withdrawal.owner");
        return Object.freeze({
          ...leg,
          screenedOwner: raw === undefined ? leg.recipient : encodeBase58(raw),
        });
      });
      if (index !== frame.splWithdrawalOwners.length) throw invalid("withdrawal.owner");
      return bound;
    }),
  );
}

/** The frame's owner section, `undefined` on a frame that carries none. */
function screenedFrame(
  instruction: Uint8Array,
  sppAnonymous: boolean,
):
  | Readonly<{
      interfaceTransfers: readonly InterfaceTransfer[];
      splWithdrawalOwners: readonly Bytes32[];
    }>
  | undefined {
  const tag = instruction[0];
  if (tag !== RingInstructionTag.transfer && tag !== RingInstructionTag.authorityTransfer)
    return undefined;
  const frame = RingTransactData.parse(
    instruction.subarray(1),
    landedRingRail(instruction, sppAnonymous),
  );
  return frame.ownRevision === undefined ? undefined : frame;
}

/**
 * The signer that owns one of the transaction's outputs, so the one that spent.
 * Slot position says nothing, a full spend leaves no change.
 */
export function senderOf(
  signers: readonly Address[],
  ownerTags: readonly (Address | undefined)[],
): Address | undefined {
  const owned = new Set(ownerTags.filter((tag): tag is Address => tag !== undefined));
  return signers.find((signer) => owned.has(signer));
}

/** Mirrors the Rust `TransactionOrigin` impl for `SolanaRpc`, one read per signature. */
export class RpcTransactionOrigin implements TransactionOrigin {
  readonly #rpc: SolanaRpc;
  readonly #transactions = new Map<Signature, Promise<unknown>>();
  static readonly #MAX_TRANSACTIONS = 4096;

  constructor(rpc: SolanaRpc) {
    this.#rpc = rpc;
  }

  async confirmedTransaction(
    transaction: IndexedShieldedTransaction,
    ring: Address,
    context?: RequestContext,
  ): Promise<ConfirmedRingTransaction | undefined> {
    const confirmed = await this.#transaction(transaction.txSignature, context);
    return bindConfirmedTransaction(confirmed, transaction, ring);
  }

  #transaction(signature: Signature, context?: RequestContext): Promise<unknown> {
    // A caller's cancellation or timeout must not govern another caller's read.
    if (context?.signal !== undefined || context?.timeoutMs !== undefined)
      return this.#fetch(signature, context);
    const known = this.#transactions.get(signature);
    if (known !== undefined) return known;
    const pending = this.#fetch(signature, context).catch((error: unknown) => {
      if (this.#transactions.get(signature) === pending) this.#transactions.delete(signature);
      throw error;
    });
    if (this.#transactions.size >= RpcTransactionOrigin.#MAX_TRANSACTIONS) {
      const oldest = this.#transactions.keys().next().value;
      if (oldest !== undefined) this.#transactions.delete(oldest);
    }
    this.#transactions.set(signature, pending);
    return pending;
  }

  async #fetch(signature: Signature, context?: RequestContext): Promise<unknown> {
    let transaction: unknown;
    try {
      transaction = await runKitRpc("getTransaction", context, (abortSignal) =>
        this.#rpc.getTransaction(signature, ORIGIN_TRANSACTION_CONFIG).send({ abortSignal }),
      );
    } catch (cause) {
      throw new RingError("RING_ORIGIN_UNAVAILABLE", {
        details: { transactionId: signature },
        cause,
      });
    }
    if (transaction === null || transaction === undefined)
      throw new RingError("RING_ORIGIN_UNAVAILABLE", {
        details: { transactionId: signature },
      });
    const wire = record(transaction, "transaction");
    const encoded = record(wire["transaction"], "transaction.transaction");
    if (list(encoded["signatures"], "signatures")[0] !== signature)
      throw new RingError("RING_ORIGIN_UNAVAILABLE", {
        details: { transactionId: signature, reason: "another transaction" },
      });
    return transaction;
  }
}

interface ConfirmedEventData extends Pick<
  ConfirmedTransferData,
  "outputs" | "messages" | "nullifiers"
> {
  readonly kind: ConfirmedEventKind;
  /** SPP proved the transfer on the anonymous rail. */
  readonly anonymous?: boolean;
  readonly txViewingPk?: Bytes33;
  readonly salt?: Bytes16;
  readonly outputTree: Address;
  readonly firstLeaf: bigint;
  /** The tree each input of a transfer spends from. */
  readonly inputTrees: readonly Address[];
}

/** The compact transfer and merge events carry the execution-assigned tree positions. */
function readEventLocation(
  event: Reader,
): Readonly<{ trees: readonly Address[]; outputTree: Address; firstLeaf: bigint }> {
  const count = event.u32("event.inputTrees.length");
  if (count < 1 || count > INPUT_TREES) throw invalid("event.inputTrees.length");
  const trees = Array.from({ length: count }, () => {
    const tree = encodeBase58(event.bytes(32, "event.inputTree"));
    event.u64("event.inputTree.firstInputQueueSeq");
    return tree;
  });
  return {
    trees,
    outputTree: encodeBase58(event.bytes(32, "event.outputTree")),
    firstLeaf: event.u64("event.firstOutputLeafIndex"),
  };
}

/** Mirrors spr_event_parser::reconstruct_general_event without trusting indexer fields. */
function readConfirmedEvent(
  source: OriginInstruction,
  emitted: OriginInstruction,
): ConfirmedEventData | undefined {
  const event = new Reader(emitted.data.slice(1));
  const kind = event.u8("event.kind");
  const tag = source.data[0];
  if (tag === InstructionTag.ringTransact || tag === InstructionTag.ringAuthorityTransact) {
    if (kind !== 2) throw invalid("event.kind");
    const data = readTransferData(new Reader(source.data.slice(1)), source.accounts);
    const { trees, outputTree, firstLeaf } = readEventLocation(event);
    event.done();
    const inputTrees = data.inputTreeIndexes.map((index) => {
      const tree = trees[index];
      if (tree === undefined) throw invalid("input.treeIndex");
      return tree;
    });
    return { ...data, outputTree, firstLeaf, kind: "transfer", inputTrees };
  }
  if (tag === InstructionTag.ringMergeTransact) {
    if (kind !== 3) throw invalid("event.kind");
    const data = new Reader(source.data.slice(1));
    const ringDataHash = data.bytes(32, "merge.ringDataHash") as Bytes32;
    data.u8("merge.authority");
    const merge = readMergeData(data);
    data.done();
    const { salt, ciphertext } = merge.outputEncryption;
    const payload = encodeMergeOutputData({ ringDataHash, salt, ciphertext });
    const { outputTree, firstLeaf } = readEventLocation(event);
    const viewTag = event.bytes(32, "merge.viewTag") as Bytes32;
    event.done();
    return {
      outputTree,
      firstLeaf,
      kind: "merge",
      inputTrees: [],
      nullifiers: merge.nullifiers,
      messages: [],
      outputs: [{ hash: merge.outputUtxoHash, viewTag, payload }],
    };
  }
  return undefined;
}

/** Reconstructs the exact indexed view from its successful SPP source and self-CPI event. */
function bindConfirmedTransaction(
  confirmed: unknown,
  indexed: IndexedShieldedTransaction,
  ring: Address,
): ConfirmedRingTransaction | undefined {
  if (indexed.eventIndex === undefined) throw invalid("eventIndex");
  const groups = confirmedInstructionGroups(confirmed);
  const found = ringEventIn(groups, indexed.eventIndex, ring);
  if (found === undefined) return undefined;
  try {
    const data = readConfirmedEvent(found.source, found.event);
    if (data === undefined) return undefined;
    const { outputTree, firstLeaf } = data;
    const rawSlot = record(confirmed, "transaction")["slot"];
    // Solana Kit promotes RPC u64 values to bigint. Raw JSON fixtures use number/string.
    const slot = typeof rawSlot === "bigint" ? rawSlot : integer(rawSlot, "slot");
    if (slot < 0n || slot > 0xffff_ffff_ffff_ffffn) throw invalid("slot");
    if (
      indexed.slot !== slot ||
      indexed.proofless ||
      indexed.ringProgramId !== ring ||
      (data.txViewingPk === undefined
        ? indexed.txViewingPublicKey !== undefined
        : indexed.txViewingPublicKey === undefined ||
          !equalBytes(indexed.txViewingPublicKey.toBytes(), data.txViewingPk)) ||
      (indexed.salt === undefined
        ? data.salt?.some((byte) => byte !== 0) === true
        : data.salt === undefined || !equalBytes(indexed.salt, data.salt)) ||
      indexed.nullifiers.length !== data.nullifiers.length ||
      indexed.nullifiers.some(
        (nullifier, index) => !equalBytes(nullifier, data.nullifiers[index]!),
      ) ||
      indexed.messages.length !== data.messages.length ||
      indexed.messages.some((message, index) => {
        const expected = data.messages[index]!;
        return (
          !equalBytes(message.viewTag, expected.viewTag) || !equalBytes(message.data, expected.data)
        );
      }) ||
      indexed.outputSlots.length !== data.outputs.length
    )
      throw invalid("indexedTransfer");
    const outputSlots = data.outputs.map((output, index) => {
      const published = indexed.outputSlots[index]!;
      const treeId = published.outputContext.treeId;
      const leafIndex = firstLeaf + BigInt(index);
      if (
        treeId === undefined ||
        treeAddress(treeId) !== outputTree ||
        leafIndex > 0xffff_ffff_ffff_ffffn ||
        published.outputContext.tree !== outputTree ||
        published.outputContext.leafIndex !== leafIndex ||
        !equalBytes(published.outputContext.hash, output.hash) ||
        !equalBytes(published.viewTag, output.viewTag) ||
        !equalBytes(published.payload, output.payload)
      )
        throw invalid("indexedTransfer.output");
      return Object.freeze({
        viewTag: output.viewTag,
        payload: output.payload,
        outputContext: Object.freeze({
          tree: outputTree,
          treeId,
          leafIndex,
          hash: output.hash,
        }),
      });
    });
    const transaction: IndexedShieldedTransaction = Object.freeze({
      slot,
      txSignature: indexed.txSignature,
      eventIndex: indexed.eventIndex,
      ringProgramId: ring,
      proofless: false,
      ...(data.txViewingPk === undefined
        ? {}
        : { txViewingPublicKey: X25519PublicKey.fromBytes(data.txViewingPk) }),
      ...(data.salt === undefined ? {} : { salt: data.salt }),
      outputSlots: Object.freeze(outputSlots),
      messages: Object.freeze(data.messages),
      nullifiers: Object.freeze(data.nullifiers),
    });
    if (data.kind === "merge") {
      return Object.freeze({
        kind: data.kind,
        transaction,
        ...confirmedMergeRecordOf(found),
      });
    }
    // Rust `ConfirmedEvent::input_tree_ids`, the event names any other tree by its account alone.
    const outputTreeId = outputSlots[0]?.outputContext.treeId;
    const inputTreeIds = Object.freeze(
      data.inputTrees.map((tree) => (tree === outputTree ? outputTreeId : undefined)),
    );
    const sppAnonymous = data.anonymous === true;
    const published = { outputs: outputSlots.length, inputs: data.nullifiers.length };
    return Object.freeze({
      kind: data.kind,
      transaction,
      inputTreeIds,
      ...boundFrame(found.wrapper?.data, sppAnonymous, published),
    });
  } catch (cause) {
    if (cause instanceof RingError) throw cause;
    throw new RingError("RING_ORIGIN_DECODE", {
      details: { path: "confirmedTransaction" },
      cause,
    });
  }
}

interface PublishedCounts {
  readonly outputs: number;
  readonly inputs: number;
}

/** The frame of the ring's own `Transfer` or `AuthorityTransfer`, the one the program verified. */
function boundFrame(
  instruction: Uint8Array | undefined,
  sppAnonymous: boolean,
  published: PublishedCounts,
): Pick<
  Extract<ConfirmedRingTransaction, { kind: "transfer" }>,
  "layout" | "rail" | "noSpend" | "hasData" | "entry"
> {
  const tag = instruction?.[0];
  if (
    instruction === undefined ||
    (tag !== RingInstructionTag.transfer && tag !== RingInstructionTag.authorityTransfer)
  )
    throw invalid("transfer.instruction");
  const rail = landedRingRail(instruction, sppAnonymous);
  const data = RingTransactData.parse(instruction.subarray(1), rail);
  if (data.outputs.length !== published.outputs || data.nullifiers.length !== published.inputs)
    throw invalid("transfer.instruction");
  return {
    layout: RingTransactData.streamLayout(data),
    rail,
    noSpend: data.noSpend,
    hasData: data.hasData,
    entry: data.entry,
  };
}

/** Mirrors Rust `InterfaceTransfer::settlement_account_count`, the accounts `append_interface_transfer_accounts` adds. */
function settlementWidth(transfer: InterfaceTransfer): number {
  return transfer.kind === "splDeposit" || transfer.kind === "splWithdrawal" ? 5 : 2;
}

/** A deposit settles value into the pool and names no recipient. */
function withdrawalLeg(
  transfer: InterfaceTransfer,
  group: readonly Address[],
): RingWithdrawal | undefined {
  if (transfer.kind === "solWithdrawal") {
    const recipient = group[1];
    if (group[0] !== SOL_INTERFACE || recipient === undefined) throw invalid("settlementAccounts");
    return Object.freeze({
      recipient,
      asset: SOL_MINT,
      amount: transfer.amount,
    });
  }
  if (transfer.kind === "splWithdrawal") {
    const asset = group[1];
    const recipient = group[3];
    if (group[0] !== SHIELDED_POOL_CPI_AUTHORITY || asset === undefined) {
      throw invalid("settlementAccounts");
    }
    if (recipient === undefined) throw invalid("settlementAccounts");
    return Object.freeze({ recipient, asset, amount: transfer.amount });
  }
  return undefined;
}

/**
 * Only the transfer list and the number of trailing cache accounts, 0, 1 or 2,
 * are returned from the instruction data.
 */
function settlementDataOf(
  instruction: OriginInstruction,
):
  | { transfers: readonly InterfaceTransfer[]; cacheAccountCount: number; anonymous: boolean }
  | undefined {
  const tag = instruction.data[0];
  if (tag !== InstructionTag.ringTransact && tag !== InstructionTag.ringAuthorityTransact)
    return undefined;
  try {
    return readTransferData(new Reader(instruction.data.slice(1)), instruction.accounts);
  } catch (cause) {
    throw new RingError("RING_ORIGIN_DECODE", {
      details: { path: "ringTransact" },
      cause,
    });
  }
}

interface ConfirmedTransferData {
  transfers: readonly InterfaceTransfer[];
  cacheAccountCount: number;
  txViewingPk: Bytes33;
  salt: Bytes16;
  outputs: readonly Readonly<{
    hash: Bytes32;
    viewTag: Bytes32;
    payload: Uint8Array;
  }>[];
  messages: readonly Readonly<{ viewTag: Bytes32; data: Uint8Array }>[];
  nullifiers: readonly Bytes32[];
  /** Per input, its position in the event's input trees. */
  inputTreeIndexes: readonly number[];
  anonymous: boolean;
}

/** One parser owns both settlement extraction and audited transfer authentication. */
function readTransferData(reader: Reader, accounts: readonly Address[]): ConfirmedTransferData {
  reader.u64("expiryUnixTs");
  const txViewingPk = reader.bytes(33, "txViewingPk") as Bytes33;
  const salt = reader.bytes(16, "salt") as Bytes16;
  const count = reader.u8("interfaceTransfers.length");
  const transfers = Array.from({ length: count }, () => readInterfaceTransfer(reader));
  reader.option("dataHash", (input) => input.bytes(32, "dataHash"));
  reader.option("ringDataHash", (input) => input.bytes(32, "ringDataHash"));
  const outputs = Array.from({ length: reader.u8("outputs.length") }, () => {
    const hash = reader.bytes(32, "output.utxoHash") as Bytes32;
    const ownerKind = reader.u8("output.ownerTag.kind");
    if (ownerKind !== 0 && ownerKind !== 1) throw invalid("output.ownerTag.kind");
    let viewTag: Bytes32;
    if (ownerKind === 0) viewTag = reader.bytes(32, "output.ownerTag") as Bytes32;
    else {
      const account = accounts[reader.u8("output.ownerTag.index")];
      if (account === undefined) throw invalid("output.ownerTag.account");
      viewTag = addressBytes(account) as Bytes32;
    }
    const payload = reader.option("output.data", (input) =>
      input.bytes(input.u16("output.data.length"), "output.data"),
    );
    return { hash, viewTag, payload: payload ?? new Uint8Array() };
  });
  const messages = Array.from({ length: reader.u8("messages.length") }, () => ({
    viewTag: reader.bytes(32, "message.viewTag") as Bytes32,
    data: reader.bytes(reader.u16("message.data.length"), "message.data"),
  }));
  reader.bytes(32, "privateTxHash");
  // CircuitId's u16 tags and payloads match the Rust wire format.
  const circuit = reader.u16("circuit.kind");
  if (
    circuit !== 1 &&
    circuit !== 2 &&
    circuit !== 3 &&
    circuit !== 5 &&
    circuit !== 6 &&
    circuit !== 9
  ) {
    throw invalid("circuit.kind");
  }
  reader.bytes(3, "circuit.shape");
  if (circuit === 3 || circuit === 6) {
    reader.bytes(64, "circuit.bsb22Commitment");
    const present = reader.bool("circuit.defaultOwnerTag.present");
    const tag = reader.bytes(32, "circuit.defaultOwnerTag");
    if (!present && tag.some((byte) => byte !== 0)) throw invalid("circuit.defaultOwnerTag");
  }
  const hasCache = circuit === 5 || circuit === 6;
  let cacheAccountCount = 0;
  if (hasCache) {
    const reads = reader.u64("circuit.cacheAccess.readBitmap");
    const firstWrite = reader.bytes(2, "circuit.cacheAccess.writeSlots[0]");
    reader.bytes(2 * (MAX_CACHE_WRITES - 1), "circuit.cacheAccess.writeSlots");
    const writes = firstWrite.some((byte) => byte !== 0xff);
    cacheAccountCount = (reads === 0n ? 0 : 1) + (writes ? 2 : 0);
  }
  reader.bytes(192, "proof");
  const inputs = Array.from({ length: reader.u8("inputs.length") }, () => ({
    nullifier: reader.bytes(32, "input.nullifier") as Bytes32,
    treeIndex: reader.u8("input.treeIndex"),
  }));
  reader.bytes(reader.u8("treeContexts.length") * 4, "treeContexts");
  reader.done();
  return {
    transfers,
    cacheAccountCount,
    txViewingPk,
    salt,
    outputs,
    messages,
    nullifiers: inputs.map((input) => input.nullifier),
    inputTreeIndexes: inputs.map((input) => input.treeIndex),
    anonymous: circuit === 3 || circuit === 6,
  };
}

function readInterfaceTransfer(reader: Reader): InterfaceTransfer {
  const kind = reader.u8("interfaceTransfer.kind");
  const amount = reader.u64("interfaceTransfer.amount");
  switch (kind) {
    case 0:
      return { kind: "solDeposit", amount };
    case 1:
      return { kind: "solWithdrawal", amount };
    case 2:
    case 3:
      return {
        kind: kind === 2 ? "splDeposit" : "splWithdrawal",
        amount,
        splInterfaceBump: reader.u8("interfaceTransfer.splInterfaceBump"),
      };
    default:
      throw invalid("interfaceTransfer.kind");
  }
}

function parsed(
  accountKeys: readonly Address[],
  instruction: unknown,
  path: string,
): OriginInstruction {
  const fields = record(instruction, path);
  const accounts = list(fields["accounts"], `${path}.accounts`).map((index, at) => {
    const account = typeof index === "number" ? accountKeys[index] : undefined;
    if (account === undefined) throw invalid(`${path}.accounts[${at}]`);
    return account;
  });
  return {
    programId: programId(accountKeys, instruction, path),
    accounts,
    data: bytes(fields, path),
  };
}

function bytes(fields: Record<string, unknown>, path: string): Uint8Array {
  const data = fields["data"];
  if (typeof data !== "string") throw invalid(`${path}.data`);
  try {
    return new Uint8Array(base58Encoder.encode(data));
  } catch (cause) {
    throw new RingError("RING_ORIGIN_DECODE", {
      details: { path: `${path}.data` },
      cause,
    });
  }
}

function programId(accountKeys: readonly Address[], instruction: unknown, path: string): Address {
  const index = record(instruction, path)["programIdIndex"];
  const id = typeof index === "number" ? accountKeys[index] : undefined;
  if (id === undefined) throw invalid(`${path}.programIdIndex`);
  return id;
}

function stackHeight(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new RingError("RING_ORIGIN_STACK", {
      details: { reason: "invalid stack height" },
    });
  }
  return value;
}

function addresses(value: unknown, path: string): Address[] {
  return list(value, path).map((entry, index) => decodeAddress(entry, `${path}[${index}]`));
}

function invalid(path: string): RingError {
  return new RingError("RING_ORIGIN_DECODE", { details: { path } });
}

const { record, list, integer, address: decodeAddress } = wireDecoder(invalid);
