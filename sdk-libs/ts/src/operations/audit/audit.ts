import { readRingHistory, scanLimits } from "../../rpc/history.js";
import type { IndexerReader, KitRpcAccess } from "@heliuslabs/spr/client";
import {
  addressBytes,
  hashBytes,
  solanaOwnerIdentity,
  ZERO_32,
  ZERO_NULLIFIER_PK,
  equalBytes,
  bytesKey,
  isCanonicalField,
  poseidon,
} from "@heliuslabs/spr/internal";
import { initializePoseidon } from "@heliuslabs/spr";
import type {
  Address,
  Bytes16,
  Bytes32,
  RequestContext,
  Signature,
} from "@heliuslabs/spr/interface";
import {
  ownerHash,
  type ViewingKey,
  type X25519Keypair,
  type X25519PublicKey,
} from "@heliuslabs/spr/keypair";
import type { IndexedShieldedTransaction, OutputContext } from "@heliuslabs/spr/transaction";
import {
  decodeAuditEnvelope,
  RecordKind,
  type AuditEnvelope,
  type EntryRecord,
} from "../../protocol/codec/audit-stream.js";
import {
  recipientKeyRegion,
  STREAM_FIRST_COUNTER,
  type AuditStreamLayout,
} from "../../protocol/codec/ring-disclosure-layout.js";
import {
  saltedAuditorSchedule,
  auditorViewTag,
  openTransactionViewingSecret,
  parseAuditorMessage,
  type AuditorMessage,
} from "../../crypto/audit/audit.js";
import {
  canonicalViewingKey,
  openOutputSlot,
  type OpenedOutput,
} from "../../crypto/audit/ring-disclosure.js";
import { ringIdField, txKeySlotSecret } from "../../crypto/derivation/ring-stream.js";
import { x25519FromU } from "../../crypto/keys/x25519.js";
import { ringBodyOutput } from "../../protocol/transaction/output.js";

import { RingError } from "../../protocol/error.js";
import { zeroKeyNullifier } from "../../state/exposed-notes.js";
import type { SkippedRingTransaction } from "../../rpc/ring-rpc.js";
import {
  RpcTransactionOrigin,
  type ConfirmedRingTransaction,
  type TransactionOrigin,
} from "../../protocol/transaction/origin.js";
import { isAnonymousFrame, type RingRail } from "../../protocol/transaction/transact.js";
import { RowOrigins, rowEventIndex } from "./row-origins.js";
import { openRingMerge } from "./audit-merge.js";
import { ringBlindingSeed, ringOutputBlinding } from "../../crypto/derivation/blinding.js";
import { dummyUtxoHash, fieldUtxoHash } from "../../protocol/membership/utxo-hash.js";
import { outputTreeId } from "../../protocol/membership/trees.js";

/**
 * Rust `AuditedUtxo`, a proven record under its published commitment. The ring proof binds every
 * record field to the commitment, the payload alone supplies the data hashes and no proof reads it.
 */
export interface AuditedUtxo {
  /** The raw Solana key whose owner identity the commitment binds. */
  readonly ownerKey: Bytes32;
  readonly nullifierPk: Bytes32;
  /** `hashBytes(mint)`. */
  readonly asset: Bytes32;
  /** Absent until the asset registry knows the asset. */
  readonly mint?: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  /** Absent with `ringDataHash` while no payload rebuilt the published commitment. */
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
}

/** The owner tag a ring output was published under, Rust `RingOwnerTag`. */
export type RingOwnerTag =
  /** The recipient key's u on the delivered rails. */
  | Readonly<{ kind: "recipient"; u: Bytes32 }>
  /** A view tag the anonymous proof leaves free. */
  | Readonly<{ kind: "view"; tag: Bytes32 }>;

/** Rust `OutputOpening`. */
export type OutputOpening =
  | Readonly<{ kind: "ring"; utxo: AuditedUtxo; ownerTag: RingOwnerTag }>
  /** A default-ring UTXO, its owner the published owner tag. */
  | Readonly<{ kind: "exit"; utxo: AuditedUtxo }>
  | Readonly<{ kind: "dummy" }>;

/** Rust `AuditedOutput`, one published slot opened from its proven record. */
export interface AuditedRingOutput {
  readonly slotIndex: number;
  readonly outputContext: OutputContext;
  readonly opening: OutputOpening;
}

/**
 * Rust `OutputPayloadErrorKind`. `disclosure` and `commitment` leave the slot unopened, `payload`
 * keeps the record in `outputs` without its data hashes.
 */
export type OutputPayloadErrorKind = "disclosure" | "commitment" | "payload";

export interface OutputPayloadError {
  readonly slotIndex: number;
  readonly kind: OutputPayloadErrorKind;
}

/** The owner of note 0 on an anonymous frame or under entry evidence. */
export interface AuditedSender {
  readonly ownerKey: Bytes32;
  /** Spent UTXO 0's key, absent when that UTXO is a deposit. */
  readonly nullifierPk?: Bytes32;
}

/** A known ring note, `AuditedInput.hash` its commitment. */
export interface AuditedInputOpening {
  readonly asset: Bytes32;
  readonly mint?: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
}

/** Rust `AuditedEntryInput`, the proof binds every field to `commitment`. */
export interface AuditedEntryInput {
  /** The raw Solana key whose owner identity the commitment binds. */
  readonly ownerKey: Bytes32;
  readonly nullifierPk: Bytes32;
  /** `hashBytes(mint)`. */
  readonly asset: Bytes32;
  readonly mint: Address;
  readonly amount: bigint;
  readonly commitment: Bytes32;
}

/** One published nullifier as the auditor's own index places it, no stream names its class. */
export type InputOpening =
  | (Readonly<{ kind: "opened" }> & AuditedInputOpening)
  /** No known note answers, a note the auditor lacks, an address or padding. */
  | Readonly<{ kind: "unresolved" }>;

export interface AuditedInput {
  readonly nullifier: Bytes32;
  /** The commitment of an opened note, absent while unresolved. */
  readonly hash?: Bytes32;
  readonly opening: InputOpening;
}

/** Rust `AuditedTransaction`. */
export interface AuditedRingTransaction {
  readonly signature: Signature;
  readonly slot: bigint;
  /** Checked against the key the auditor envelope seals. */
  readonly txViewingPublicKey: X25519PublicKey;
  /** Published order, a slot whose record did not open sits in `payloadErrors` instead. */
  readonly outputs: readonly AuditedRingOutput[];
  readonly payloadErrors: readonly OutputPayloadError[];
  /** One per published slot, a payload error names its slot here. */
  readonly outputCommitments: readonly Bytes32[];
  /** The owner of note 0, absent off an anonymous or entry frame and while the auditor lacks that note. */
  readonly sender?: AuditedSender;
  /** One per published nullifier, notes, addresses and padding alike. */
  readonly inputs: readonly AuditedInput[];
  /** The default-ring notes among the `R` spent notes, in note order. */
  readonly entries: readonly AuditedEntryInput[];
}

/** Rust `UtxoOwner`. */
export type UtxoOwner =
  | Readonly<{ kind: "keyed"; nullifierPk: Bytes32 }>
  /** A deposit capsule discloses the owner hash alone. */
  | Readonly<{ kind: "deposited"; ownerHash: Bytes32 }>;

/** A UTXO an earlier audit opened, a later disclosure names it by its hash. */
export interface KnownUtxo extends Omit<AuditedUtxo, "nullifierPk"> {
  readonly owner: UtxoOwner;
  readonly treeId: number;
}

/** Rust `CreatedUtxo`. */
/** Rust `CreatedUtxo`. */
export interface CreatedRingUtxo {
  readonly commitment: Bytes32;
  readonly slotIndex: number;
  readonly utxo: KnownUtxo;
}

/** A known UTXO under its commitment. */
export interface KnownNote {
  readonly commitment: Bytes32;
  readonly utxo: KnownUtxo;
}

/** UTXOs the auditor opened before. */
export interface KnownUtxos {
  utxo(commitment: Bytes32): KnownUtxo | undefined;
  /** A real input resolves by its nullifier alone. */
  byNullifier?(nullifier: Bytes32): KnownNote | undefined;
}

/** An enrolled key's secret, right aligned, read to derive and never held. */
export interface NullifierSecrets {
  secret(nullifierPk: Bytes32): Bytes32 | undefined;
}

export interface KnownUtxoIndexOptions {
  readonly fallback?: KnownUtxos;
  readonly secrets?: NullifierSecrets;
}

export class KnownUtxoIndex implements KnownUtxos {
  readonly #utxos = new Map<string, KnownUtxo>();
  readonly #notes = new Map<string, KnownNote>();
  /** Notes under a key whose secret is not yet readable. */
  readonly #waiting = new Map<string, KnownNote>();
  readonly #fallback: KnownUtxos | undefined;
  readonly #secrets: NullifierSecrets | undefined;

  constructor(
    utxos: Iterable<Readonly<{ commitment: Bytes32; utxo: KnownUtxo }>> = [],
    options: KnownUtxoIndexOptions = {},
  ) {
    this.#fallback = options.fallback;
    this.#secrets = options.secrets;
    for (const { commitment, utxo } of utxos) this.insert(commitment, utxo);
  }

  /** A later opening of a known commitment replaces it only to name its mint. */
  insert(commitment: Bytes32, utxo: KnownUtxo): void {
    const key = bytesKey(commitment);
    const kept = this.#utxos.get(key);
    if (kept !== undefined && (kept.mint !== undefined || utxo.mint === undefined)) return;
    this.#utxos.set(key, utxo);
    if (!this.#indexNote({ commitment, utxo })) this.#waiting.set(key, { commitment, utxo });
  }

  /** A late key recomputes its owner's notes. */
  reindexSecrets(): void {
    for (const [key, note] of this.#waiting) if (this.#indexNote(note)) this.#waiting.delete(key);
  }

  utxo(commitment: Bytes32): KnownUtxo | undefined {
    return this.#utxos.get(bytesKey(commitment)) ?? this.#fallback?.utxo(commitment);
  }

  byNullifier(nullifier: Bytes32): KnownNote | undefined {
    return this.#notes.get(bytesKey(nullifier)) ?? this.#fallback?.byNullifier?.(nullifier);
  }

  /** False while the owner's secret is unreadable, a `deposited` owner names no key and stays out. */
  #indexNote(note: KnownNote): boolean {
    const { commitment, utxo } = note;
    if (utxo.owner.kind !== "keyed") return true;
    const { nullifierPk } = utxo.owner;
    if (equalBytes(nullifierPk, ZERO_NULLIFIER_PK)) {
      this.#notes.set(bytesKey(zeroKeyNullifier(commitment, utxo.blinding)), note);
      return true;
    }
    const secret = this.#secrets?.secret(nullifierPk);
    if (secret === undefined) return false;
    this.#notes.set(bytesKey(poseidon([commitment, utxo.blinding, secret])), note);
    return true;
  }
}

export interface RingAuditPage {
  readonly transactions: readonly AuditedRingTransaction[];
  /** Landed rows that fail to decode or fail their audit, each opens nothing. */
  readonly skipped: readonly SkippedRingTransaction[];
  /** Set only when the page cap stopped the scan. */
  readonly nextCursor?: string;
}

export type RingAuditReader = KitRpcAccess & Pick<IndexerReader, "getShieldedTransactionsByTags">;

const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 32;

/** The program keeps the auditor's message last, a sender bundle before it may carry any tag. */
export function auditorMessage(
  transaction: IndexedShieldedTransaction,
  auditorPublicKey: X25519PublicKey,
): Uint8Array {
  const message = transaction.messages.at(-1);
  if (message === undefined || !equalBytes(message.viewTag, auditorViewTag(auditorPublicKey)))
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "missing" },
    });
  return message.data;
}

/** The envelope's key alone, a full audit reads it from `openAuditEnvelope`. */
export function recoverTransactionViewingKey(
  auditor: X25519Keypair,
  message: AuditorMessage,
  salt: Bytes16,
): ViewingKey {
  return canonicalViewingKey(openTransactionViewingSecret(auditor, message, salt));
}

export interface TransactionAuditInput {
  readonly auditor: X25519Keypair;
  readonly transaction: IndexedShieldedTransaction;
  /** The layout the ring program verified the audit proof under, `ConfirmedRingTransaction` reads it. */
  readonly layout: AuditStreamLayout;
  readonly rail: RingRail;
  /** The statement's bit, refused unless it reads `R == 0`. */
  readonly noSpend: boolean;
  readonly knownUtxos?: KnownUtxos;
}

export interface OpenedRingAudit {
  readonly audited: AuditedRingTransaction;
  /** `R`, the spent notes, the completeness check on the auditor's own classification. */
  readonly realInputs: number;
}

/** Mirrors Rust `TransactionAudit::run`, every published commitment rebuilt from the stream. */
export function auditRingTransaction(input: TransactionAuditInput): AuditedRingTransaction {
  return openRingTransfer(input).audited;
}

/** Reads the stream and the frame alone, no registry names a mint. */
export function openRingTransfer(input: TransactionAuditInput): OpenedRingAudit {
  const { layout, auditor, transaction } = input;
  const unsealed = (reason: string): RingError =>
    new RingError("RING_AUDIT_UNSEALED", {
      details: { reason, transactionId: transaction.txSignature },
    });
  const txViewingPublicKey = transaction.txViewingPublicKey;
  if (txViewingPublicKey === undefined) throw unsealed("txViewingPk");
  const salt = transaction.salt;
  if (salt === undefined) throw unsealed("salt");
  const ring = transaction.ringProgramId;
  if (ring === undefined) throw unsealed("ringProgramId");
  const firstNullifier = transaction.nullifiers[0];
  if (firstNullifier === undefined) throw unsealed("nullifier");
  if (
    layout.outputs !== transaction.outputSlots.length ||
    layout.inputs !== transaction.nullifiers.length
  )
    throw auditRefusal("layout");
  // A slot without a ring body is an exit, its record the next one in the auditor message.
  const exits = transaction.outputSlots.map((slot) => ringBodyOutput(slot.payload) === undefined);
  const message = parsedMessage(
    auditorMessage(transaction, auditor.publicKey()),
    layout,
    exits.filter(Boolean).length,
  );
  const schedule = saltedAuditorSchedule(auditor, message.ephemeralPublicKey, salt);
  const envelopePlain = schedule.apply(STREAM_FIRST_COUNTER, message.envelope);
  let envelope: AuditEnvelope | undefined;
  let txKey: ViewingKey | undefined;
  let blindingSeed: Bytes32 | undefined;
  try {
    envelope = decodedEnvelope(envelopePlain, layout);
    const { realInputs } = envelope;
    checkEnvelope(envelope, input.noSpend);
    txKey = canonicalViewingKey(envelope.txViewingSecret.slice() as Bytes32);
    // The proof binds the envelope to the published key, a mismatch is a forged message.
    if (!txKey.publicKey().equals(txViewingPublicKey))
      throw new RingError("RING_AUDIT_KEY_MISMATCH", {
        details: { transactionId: transaction.txSignature },
      });
    blindingSeed = ringBlindingSeed(envelope.txViewingSecret, salt);
    const seed = blindingSeed;
    const key = txKey;
    const exitRecords = message.exitRecords[Symbol.iterator]();
    const reader: SlotReader = {
      ringId: ringIdField(ring),
      anonymous: isAnonymousFrame(input.rail),
      // `V_i` from the stream, `CRDS_i` from `tx_viewing_sk`, the record from the slot data or, on
      // an exit, from the auditor message in slot order.
      open: (slot, payload) => {
        const recipientKey = schedule.apply(
          recipientKeyRegion(layout, slot).startCounter,
          message.recipientKeys[slot] ?? EMPTY,
        ) as Bytes32;
        const body =
          exits[slot] === true ? exitRecords.next().value : ringBodyOutput(payload)?.body;
        return body === undefined
          ? undefined
          : openedSlot({ txKey: key, recipientKey, salt, slot, firstNullifier, body });
      },
      dummyBlinding: (outputIndex) =>
        ringOutputBlinding({ firstNullifier, blindingSeed: seed, outputIndex }),
    };
    const outputs: AuditedRingOutput[] = [];
    const payloadErrors: OutputPayloadError[] = [];
    transaction.outputSlots.forEach((output, slotIndex) => {
      const opened = openSlot(reader, slotIndex, output);
      if (opened.ok)
        outputs.push(
          Object.freeze({
            slotIndex,
            outputContext: output.outputContext,
            opening: opened.opening,
          }),
        );
      if (!opened.ok || opened.payload === false)
        payloadErrors.push(Object.freeze({ slotIndex, kind: opened.ok ? "payload" : opened.kind }));
    });
    // The auditor's own index places each nullifier, the stream names none.
    const inputs = transaction.nullifiers.map((nullifier) =>
      resolvedInput(nullifier, input.knownUtxos),
    );
    const entries = entryInputs(envelope);
    const sender = senderOf(input.rail, envelope, entries, inputs, input.knownUtxos);
    return Object.freeze({
      realInputs,
      audited: Object.freeze({
        signature: transaction.txSignature,
        slot: transaction.slot,
        txViewingPublicKey,
        outputs: Object.freeze(outputs),
        payloadErrors: Object.freeze(payloadErrors),
        outputCommitments: Object.freeze(
          transaction.outputSlots.map((slot) => slot.outputContext.hash),
        ),
        ...(sender === undefined ? {} : { sender }),
        inputs: Object.freeze(inputs),
        entries,
      }),
    });
  } finally {
    envelopePlain.fill(0);
    envelope?.txViewingSecret.fill(0);
    blindingSeed?.fill(0);
    txKey?.destroy();
    schedule.destroy();
  }
}

/** Every opened UTXO by its hash, Rust `AuditedTransaction::utxos`. */
export function auditedUtxos(transaction: AuditedRingTransaction): readonly CreatedRingUtxo[] {
  return transaction.outputs.flatMap((output) =>
    output.opening.kind === "dummy"
      ? []
      : [
          Object.freeze({
            commitment: output.outputContext.hash,
            slotIndex: output.slotIndex,
            utxo: openedUtxo(output.opening.utxo, outputTreeId(output.outputContext)),
          }),
        ],
  );
}

/** Rust `KnownUtxo::opened`. */
export function openedUtxo(utxo: AuditedUtxo, treeId: number): KnownUtxo {
  const { nullifierPk, ...fields } = utxo;
  return Object.freeze({
    ...fields,
    owner: Object.freeze({ kind: "keyed", nullifierPk }),
    treeId,
  });
}

/** Rust `KnownUtxo::commitment`, `ringId` zero for a default-ring UTXO, `undefined` without the data hashes. */
export function knownUtxoHash(utxo: KnownUtxo, ringId: Bytes32): Bytes32 | undefined {
  if (utxo.dataHash === undefined || utxo.ringDataHash === undefined) return undefined;
  return fieldUtxoHash({
    owner: knownUtxoOwnerHash(utxo),
    assetField: utxo.asset,
    amount: utxo.amount,
    blinding: utxo.blinding,
    treeId: utxo.treeId,
    dataHash: utxo.dataHash,
    ringDataHash: utxo.ringDataHash,
    ringId,
  });
}

export function knownUtxoOwnerHash(utxo: Pick<KnownUtxo, "ownerKey" | "owner">): Bytes32 {
  return utxo.owner.kind === "keyed"
    ? (ownerHash(solanaOwnerIdentity(utxo.ownerKey), utxo.owner.nullifierPk) as Bytes32)
    : utxo.owner.ownerHash;
}

/** Rust `AuditedTransaction::has_unknown_assets`, a registry refresh may name the mint, a delivered slot opens only after it. */
export function hasUnknownAssets(transaction: AuditedRingTransaction): boolean {
  return (
    auditedUtxos(transaction).some(({ utxo }) => utxo.mint === undefined) ||
    transaction.inputs.some(
      (input) => input.opening.kind === "opened" && input.opening.mint === undefined,
    )
  );
}

/** Mirrors Rust `RingScan::audit`, each tagged event attributed through its confirmed call stack. */
export async function auditRing(
  input: Readonly<{
    client: RingAuditReader;
    auditor: X25519Keypair;
    ringProgramId: Address;
    /** A key's secret read to resolve a spend, a zero key needs none. */
    secrets?: NullifierSecrets;
    /** UTXOs opened outside the scan, earlier pages and `createdRingUtxos` among them. */
    knownUtxos?: KnownUtxos;
    origin?: TransactionOrigin;
    cursor?: string;
    pageSize?: number;
    maxPages?: number;
  }>,
  context?: RequestContext,
): Promise<RingAuditPage> {
  await initializePoseidon();
  const rows = new RowOrigins(
    input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
    input.ringProgramId,
    context,
  );
  const history: ConfirmedRingTransaction[] = [];
  const { nextCursor } = await readRingHistory(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      rows,
      limits: scanLimits({
        pageSize: input.pageSize ?? DEFAULT_PAGE_SIZE,
        maxPages: input.maxPages ?? DEFAULT_MAX_PAGES,
      }),
      ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
    },
    (confirmed) => history.push(confirmed),
    context,
  );
  const known = new KnownUtxoIndex([], {
    ...(input.knownUtxos === undefined ? {} : { fallback: input.knownUtxos }),
    ...(input.secrets === undefined ? {} : { secrets: input.secrets }),
  });
  const transactions = auditConfirmedRingHistory({
    auditor: input.auditor,
    ringProgramId: input.ringProgramId,
    history,
    rows,
    known,
  });
  return Object.freeze({
    transactions,
    skipped: Object.freeze(rows.skipped),
    ...(nextCursor === undefined ? {} : { nextCursor }),
  });
}

/** An input a later row opens resolves on the last pass. */
export function auditConfirmedRingHistory(
  input: Readonly<{
    auditor: X25519Keypair;
    ringProgramId: Address;
    history: readonly ConfirmedRingTransaction[];
    rows: RowOrigins;
    known: KnownUtxoIndex;
  }>,
): readonly AuditedRingTransaction[] {
  const { known, rows } = input;
  for (const confirmed of input.history) {
    rows.attempt(confirmed.transaction, () => {
      if (confirmed.kind === "merge") {
        const merge = openRingMerge({
          confirmed,
          eventIndex: rowEventIndex(confirmed.transaction),
          auditor: input.auditor,
        });
        // The record's seed rebuilt the published commitment, the full opening needs no input history.
        known.insert(
          merge.outputContext.hash,
          openedUtxo(merge.utxo, outputTreeId(merge.outputContext)),
        );
      }
    });
  }
  const opened: { audited: AuditedRingTransaction; senderNamed: boolean }[] = [];
  for (const confirmed of input.history) {
    if (confirmed.kind !== "transfer") continue;
    const audited = rows.attempt(confirmed.transaction, () =>
      auditRingTransaction({
        auditor: input.auditor,
        transaction: confirmed.transaction,
        layout: confirmed.layout,
        rail: confirmed.rail,
        noSpend: confirmed.noSpend,
        knownUtxos: known,
      }),
    );
    if (audited === undefined) continue;
    for (const { commitment, utxo } of auditedUtxos(audited)) known.insert(commitment, utxo);
    opened.push({ audited, senderNamed: isAnonymousFrame(confirmed.rail) });
  }
  return Object.freeze(
    opened.map(({ audited, senderNamed }) => {
      const inputs = Object.freeze(
        audited.inputs.map((spent) =>
          spent.opening.kind === "unresolved" ? resolvedInput(spent.nullifier, known) : spent,
        ),
      );
      const sender = senderNamed
        ? (audited.sender ?? senderOfKnown(inputs, known))
        : audited.sender;
      return Object.freeze({ ...audited, ...(sender === undefined ? {} : { sender }), inputs });
    }),
  );
}

/** A count off the input map, a default bit off a note or an opening off a default bit. */
function decodedEnvelope(plaintext: Uint8Array, layout: AuditStreamLayout): AuditEnvelope {
  try {
    return decodeAuditEnvelope(plaintext, layout);
  } catch (cause) {
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "envelope" }, cause });
  }
}

function parsedMessage(data: Uint8Array, layout: AuditStreamLayout, exits: number): AuditorMessage {
  try {
    return parseAuditorMessage(data, layout, exits);
  } catch (cause) {
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "malformed", length: data.length },
      cause,
    });
  }
}

/** The statement's `no_spend` bit reads `R == 0`, the decoder refused every other count. */
function checkEnvelope(envelope: AuditEnvelope, noSpend: boolean): void {
  if (noSpend !== (envelope.realInputs === 0)) throw auditRefusal("no spend");
}

function auditRefusal(reason: string): RingError {
  return new RingError("RING_AUDIT_MESSAGE", { details: { reason } });
}

interface SlotReader {
  readonly ringId: Bytes32;
  readonly anonymous: boolean;
  /** `undefined` on a body that does not open, the frame or the key being malformed. */
  open(slot: number, payload: Uint8Array): OpenedOutput | undefined;
  dummyBlinding(outputIndex: number): Bytes32;
}

type SlotOpening =
  /** `payload` is false while the payload rebuilt no commitment, the record still stands. */
  | Readonly<{ ok: true; opening: OutputOpening; payload: boolean }>
  | Readonly<{ ok: false; kind: OutputPayloadErrorKind }>;

/** `V_i` must be a contributory key, the proof refuses any other. */
function openedSlot(
  input: Readonly<{
    txKey: ViewingKey;
    recipientKey: Bytes32;
    salt: Bytes16;
    slot: number;
    firstNullifier: Bytes32;
    body: Uint8Array;
  }>,
): OpenedOutput | undefined {
  let secret: Bytes32 | undefined;
  try {
    secret = txKeySlotSecret({
      txViewingKey: input.txKey,
      recipientViewingKey: x25519FromU(input.recipientKey),
      salt: input.salt,
      outputIndex: input.slot,
      firstNullifier: input.firstNullifier,
    });
    return openOutputSlot(secret, input.body);
  } catch {
    return undefined;
  } finally {
    secret?.fill(0);
  }
}

/**
 * The ring proof binds every record field to the slot's published commitment, so a verified frame's
 * record stands whatever its payload holds. The payload's data hashes join the opening only when they
 * rebuild that commitment, else the slot reports a payload error beside its record. Spend tracing
 * reads the published commitment, the record's blinding and the owner's secret, never the data hashes.
 */
function openSlot(
  reader: SlotReader,
  slot: number,
  output: IndexedShieldedTransaction["outputSlots"][number],
): SlotOpening {
  const context = output.outputContext;
  const treeId = outputTreeId(context);
  const opened = reader.open(slot, output.payload);
  if (opened === undefined) return DISCLOSURE;
  const { record, payload } = opened;
  // 1. A dummy's commitment is fixed by its derived blinding alone.
  if (record.kind === RecordKind.dummy)
    return equalBytes(dummyUtxoHash(treeId, reader.dummyBlinding(slot)), context.hash)
      ? Object.freeze({ ok: true, opening: DUMMY, payload: true })
      : COMMITMENT;
  // 2. The proof holds both record fields canonical.
  if (!isCanonicalField(record.nullifierPk) || !isCanonicalField(record.blinding))
    throw auditRefusal("record field");
  const recorded: AuditedUtxo = Object.freeze({
    ownerKey: record.ownerKey,
    nullifierPk: record.nullifierPk,
    asset: hashBytes(addressBytes(record.mint, "mint")) as Bytes32,
    mint: record.mint,
    amount: record.amount,
    blinding: record.blinding,
  });
  // 3. The payload is unproven, its hashes join only when they rebuild the commitment. An exit's data
  // sits in its scheme 3 body, sealed to its owner alone.
  const data = payload?.data ?? EMPTY;
  // Rust `first_chunk`, data shorter than a hash reads a zero hash.
  const dataHash = data.length < 32 ? ZERO_32 : (data.slice(0, 32) as Bytes32);
  const ringDataHash = payload?.ringDataHash ?? ZERO_32;
  const ringNote = record.kind === RecordKind.ring;
  const withData = Object.freeze({ ...recorded, dataHash, ringDataHash });
  const rebuilds =
    isCanonicalField(dataHash) &&
    isCanonicalField(ringDataHash) &&
    equalBytes(
      knownUtxoHash(openedUtxo(withData, treeId), ringNote ? reader.ringId : ZERO_32) ?? EMPTY,
      context.hash,
    );
  const utxo = rebuilds ? withData : recorded;
  return Object.freeze({
    ok: true,
    payload: rebuilds,
    opening: ringNote
      ? Object.freeze({
          kind: "ring",
          utxo,
          ownerTag: Object.freeze(
            reader.anonymous
              ? { kind: "view", tag: output.viewTag }
              : { kind: "recipient", u: output.viewTag },
          ),
        })
      : Object.freeze({ kind: "exit", utxo }),
  });
}

function resolvedInput(nullifier: Bytes32, known: KnownUtxos | undefined): AuditedInput {
  const note = known?.byNullifier?.(nullifier);
  return note === undefined
    ? Object.freeze({ nullifier, opening: UNRESOLVED })
    : Object.freeze({
        nullifier,
        hash: note.commitment,
        opening: ringInput(note.utxo),
      });
}

/** The default-ring notes in note order, each bit names one of the `R` notes. */
function entryInputs(envelope: AuditEnvelope): readonly AuditedEntryInput[] {
  const { evidence } = envelope;
  if (evidence.kind !== "entry") return Object.freeze([]);
  return Object.freeze(
    evidence.inputs.flatMap((entry, note) =>
      ((evidence.defaultNoteBits >> BigInt(note)) & 1n) === 1n ? [entryInput(entry)] : [],
    ),
  );
}

/** The proof binds every field to the spent note's commitment. */
function entryInput(entry: EntryRecord): AuditedEntryInput {
  if (!isCanonicalField(entry.nullifierPk) || !isCanonicalField(entry.inputCommitment))
    throw auditRefusal("entry evidence");
  return Object.freeze({
    ownerKey: entry.ownerKey,
    nullifierPk: entry.nullifierPk,
    asset: hashBytes(addressBytes(entry.mint, "mint")) as Bytes32,
    mint: entry.mint,
    amount: entry.amount,
    commitment: entry.inputCommitment,
  });
}

/** The owner of note 0 on an anonymous frame or under entry evidence, absent while its note is unknown. */
function senderOf(
  rail: RingRail,
  envelope: AuditEnvelope,
  entries: readonly AuditedEntryInput[],
  inputs: readonly AuditedInput[],
  known: KnownUtxos | undefined,
): AuditedSender | undefined {
  const { evidence } = envelope;
  if (evidence.kind === "entry" && (evidence.defaultNoteBits & 1n) === 1n) {
    const entry = entries[0];
    return entry === undefined
      ? undefined
      : Object.freeze({ ownerKey: entry.ownerKey, nullifierPk: entry.nullifierPk });
  }
  return isAnonymousFrame(rail) || evidence.kind === "entry"
    ? senderOfKnown(inputs, known)
    : undefined;
}

function senderOfKnown(
  inputs: readonly AuditedInput[],
  known: KnownUtxos | undefined,
): AuditedSender | undefined {
  const hash = inputs[0]?.hash;
  const utxo = hash === undefined ? undefined : known?.utxo(hash);
  return utxo === undefined
    ? undefined
    : Object.freeze({
        ownerKey: utxo.ownerKey,
        ...(utxo.owner.kind === "keyed" ? { nullifierPk: utxo.owner.nullifierPk } : {}),
      });
}

function ringInput(utxo: KnownUtxo): InputOpening {
  return Object.freeze({
    kind: "opened",
    asset: utxo.asset,
    ...(utxo.mint === undefined ? {} : { mint: utxo.mint }),
    amount: utxo.amount,
    blinding: utxo.blinding,
  });
}

const DUMMY: OutputOpening = Object.freeze({ kind: "dummy" });
const UNRESOLVED: InputOpening = Object.freeze({ kind: "unresolved" });
const EMPTY = new Uint8Array();
const DISCLOSURE: SlotOpening = Object.freeze({ ok: false, kind: "disclosure" });
const COMMITMENT: SlotOpening = Object.freeze({ ok: false, kind: "commitment" });
