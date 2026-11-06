import type { IndexerReader, KitRpcAccess } from "@heliuslabs/spr/client";
import { initializePoseidon } from "@heliuslabs/spr";
import {
  addressBytes,
  isCanonicalField,
  hashBytes,
  mergePaddedInputCount,
  equalBytes,
  MERGE_OUTPUT_BODY_LENGTH,
  readMergeOutputBody,
  ZERO_32,
} from "@heliuslabs/spr/internal";
import {
  seededMergeDummyNullifier,
  seededMergeOutputBlinding,
} from "../../crypto/derivation/merge-seed.js";
import type { Address, Bytes32, RequestContext, Signature } from "@heliuslabs/spr/interface";
import type { X25519Keypair } from "@heliuslabs/spr/keypair";
import type { OutputContext } from "@heliuslabs/spr/transaction";

import { openMergeRecord, type MergeRingAuthority } from "../../crypto/audit/merge-disclosure.js";
import { ringIdField } from "../../crypto/derivation/ring-stream.js";
import { RecordKind } from "../../protocol/codec/audit-stream.js";
import { RingError } from "../../protocol/error.js";
import { outputTreeId } from "../../protocol/membership/trees.js";
import {
  RpcTransactionOrigin,
  type ConfirmedRingTransaction,
  type TransactionOrigin,
} from "../../protocol/transaction/origin.js";
import { readRingHistory, scanLimits } from "../../rpc/history.js";
import type { SkippedRingTransaction } from "../../rpc/ring-rpc.js";
import {
  knownUtxoHash,
  openedUtxo,
  type AuditedUtxo,
  type KnownNote,
  type KnownUtxos,
} from "./audit.js";
import { RowOrigins } from "./row-origins.js";

export type RingMergeAuditReader = KitRpcAccess &
  Pick<IndexerReader, "getShieldedTransactionsByTags">;

/** `Observed` of a merge nullifier, padding is known from the seed alone. */
export type MergeNullifierClass =
  | Readonly<{ kind: "padding" }>
  | Readonly<{ kind: "resolved"; note: KnownNote }>
  | Readonly<{ kind: "unresolvedReal" }>;

export interface MergeNullifierRow {
  readonly nullifier: Bytes32;
  readonly state: MergeNullifierClass;
}

/** A tag 57 merge, its record opens the output and its nullifiers mark inputs. */
export interface OpenedRingMerge {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly outputContext: OutputContext;
  readonly utxo: AuditedUtxo;
  readonly authority: MergeRingAuthority;
  readonly nullifiers: readonly MergeNullifierRow[];
}

export interface RingMergeAuditPage {
  readonly merges: readonly OpenedRingMerge[];
  /** Rows that do not decode or fail their record, each opens nothing. */
  readonly skipped: readonly SkippedRingTransaction[];
  /** Set only when the page cap stopped the history scan. */
  readonly nextCursor?: string;
}

/** Rust `MergeAudit`. */
export async function auditRingMerges(
  input: Readonly<{
    client: RingMergeAuditReader;
    ringProgramId: Address;
    auditor: X25519Keypair;
    origin?: TransactionOrigin;
    cursor?: string;
    pageSize?: number;
    maxPages?: number;
    /** A nullifier no known note answers reads `unresolvedReal`. */
    knownUtxos?: KnownUtxos;
  }>,
  context?: RequestContext,
): Promise<RingMergeAuditPage> {
  await initializePoseidon();
  const rows = new RowOrigins(
    input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
    input.ringProgramId,
    context,
  );
  const merges: OpenedRingMerge[] = [];
  const seen = new Set<string>();
  const { nextCursor } = await readRingHistory(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      rows,
      ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
      limits: scanLimits(input),
    },
    (confirmed, eventIndex) => {
      const { transaction } = confirmed;
      if (confirmed.kind !== "merge") return;
      const event = `${transaction.txSignature}:${String(eventIndex)}`;
      if (seen.has(event))
        throw new RingError("RING_RPC", {
          details: { reason: "duplicate merge" },
        });
      seen.add(event);
      const merge = rows.attempt(transaction, () =>
        openRingMerge({
          confirmed,
          eventIndex,
          auditor: input.auditor,
          ...(input.knownUtxos === undefined ? {} : { known: input.knownUtxos }),
        }),
      );
      if (merge !== undefined) merges.push(merge);
    },
    context,
  );
  return Object.freeze({
    merges: Object.freeze(merges),
    skipped: Object.freeze(rows.skipped),
    ...(nextCursor === undefined ? {} : { nextCursor }),
  });
}

/** Rebuilds the output from the record under `Poseidon(TMOB, seed, n0)`, the seed is wiped once read. */
export function openRingMerge(
  input: Readonly<{
    confirmed: Extract<ConfirmedRingTransaction, { kind: "merge" }>;
    eventIndex: number;
    auditor: X25519Keypair;
    known?: KnownUtxos;
  }>,
): OpenedRingMerge {
  const { confirmed, eventIndex, known } = input;
  const { transaction } = confirmed;
  const slot = transaction.outputSlots[0];
  const firstNullifier = transaction.nullifiers[0];
  const body = slot === undefined ? undefined : readMergeOutputBody(slot.payload);
  const ringDataHash = body?.ringDataHash;
  const ring = transaction.ringProgramId;
  if (
    slot === undefined ||
    firstNullifier === undefined ||
    ring === undefined ||
    transaction.outputSlots.length !== 1 ||
    mergePaddedInputCount(transaction.nullifiers.length) === undefined ||
    ringDataHash === undefined ||
    body?.encrypted.length !== MERGE_OUTPUT_BODY_LENGTH ||
    !isCanonicalField(firstNullifier) ||
    !isCanonicalField(slot.outputContext.hash) ||
    !isCanonicalField(ringDataHash)
  )
    throw new RingError("RING_ORIGIN_DECODE", {
      details: { reason: "ring merge output" },
    });
  const { record, secret: seed } = openMergeRecord(input.auditor, confirmed.sealedRecord);
  try {
    if (
      record.kind !== RecordKind.ring ||
      !isCanonicalField(record.nullifierPk) ||
      !isCanonicalField(seed)
    )
      throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "merge record" } });
    const utxo: AuditedUtxo = Object.freeze({
      ownerKey: record.ownerKey,
      nullifierPk: record.nullifierPk,
      asset: hashBytes(addressBytes(record.mint, "mint")) as Bytes32,
      mint: record.mint,
      amount: record.amount,
      blinding: seededMergeOutputBlinding(seed, firstNullifier),
      dataHash: ZERO_32,
      ringDataHash,
    });
    const rebuilt = knownUtxoHash(
      openedUtxo(utxo, outputTreeId(slot.outputContext)),
      ringIdField(ring),
    );
    if (!equalBytes(rebuilt, slot.outputContext.hash))
      throw new RingError("RING_AUDIT_OUTPUT_MISMATCH", { details: { reason: "merge record" } });
    return Object.freeze({
      slot: transaction.slot,
      signature: transaction.txSignature,
      eventIndex,
      outputContext: slot.outputContext,
      utxo,
      authority: confirmed.authority,
      nullifiers: Object.freeze(
        transaction.nullifiers.map((nullifier, position) =>
          Object.freeze({
            nullifier,
            state: classifyMergeNullifier({
              seed,
              firstNullifier,
              nullifier,
              position,
              ...(known === undefined ? {} : { known }),
            }),
          }),
        ),
      ),
    });
  } finally {
    seed.fill(0);
  }
}

/** Padding is `Poseidon(TMDN, seed, n0, i)`, a real spend never reads as it. */
export function classifyMergeNullifier(
  input: Readonly<{
    seed: Bytes32;
    firstNullifier: Bytes32;
    nullifier: Bytes32;
    position: number;
    known?: KnownUtxos;
  }>,
): MergeNullifierClass {
  const { seed, firstNullifier, nullifier, position, known } = input;
  if (equalBytes(seededMergeDummyNullifier(seed, firstNullifier, position), nullifier))
    return PADDING;
  const note = known?.byNullifier?.(nullifier);
  return note === undefined ? UNRESOLVED_REAL : Object.freeze({ kind: "resolved", note });
}

const PADDING: MergeNullifierClass = Object.freeze({ kind: "padding" });
const UNRESOLVED_REAL: MergeNullifierClass = Object.freeze({ kind: "unresolvedReal" });
