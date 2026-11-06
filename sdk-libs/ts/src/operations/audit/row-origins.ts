import type { Address } from "@solana/kit";

import type { RequestContext } from "@heliuslabs/spr/interface";
import { KeypairError } from "@heliuslabs/spr/keypair";
import { TransactionError, type IndexedShieldedTransaction } from "@heliuslabs/spr/transaction";

import { RingKeyError } from "../../crypto/error.js";
import { RingError } from "../../protocol/error.js";
import type {
  ConfirmedRingTransaction,
  TransactionOrigin,
} from "../../protocol/transaction/origin.js";
import type { SkippedRingTransaction } from "../../rpc/ring-rpc.js";

/** `test-vectors/audit/row-dispositions.json`, `retry` keeps the reader's position and `invalid` passes a row that never opens. */
export const AUDIT_FAILURE_DISPOSITIONS = Object.freeze({
  transport: "retry",
  originUnavailable: "retry",
  invalidStackHeight: "retry",
  missingAuditorMessage: "retry",
  indexerResponse: "retry",
  originDecode: "invalid",
  transactData: "invalid",
  eventMismatch: "invalid",
  viewingKeyMismatch: "invalid",
  nonCanonicalViewingKey: "invalid",
  keyMaterial: "invalid",
  auditData: "invalid",
} as const);

/** Rust `AuditFailureKind`. */
export type AuditFailureKind = keyof typeof AUDIT_FAILURE_DISPOSITIONS;

/** Rust `RowDisposition`. */
export type RowDisposition = (typeof AUDIT_FAILURE_DISPOSITIONS)[AuditFailureKind];

/** Rust `AuditError::disposition`. */
export function rowDisposition(error: unknown): RowDisposition {
  return AUDIT_FAILURE_DISPOSITIONS[auditFailureKind(error)];
}

/** Rust `AuditError::kind`, an error it cannot place keeps the reader's position. */
export function auditFailureKind(error: unknown): AuditFailureKind {
  if (error instanceof KeypairError) return "keyMaterial";
  if (error instanceof RingKeyError)
    return error.code.startsWith("KEYPAIR_DISCLOSURE") ? "auditData" : "keyMaterial";
  if (error instanceof TransactionError) return "auditData";
  if (!(error instanceof RingError)) return "transport";
  switch (error.code) {
    case "RING_ORIGIN_UNAVAILABLE":
      return "originUnavailable";
    case "RING_ORIGIN_STACK":
      return "invalidStackHeight";
    case "RING_RPC":
    case "RING_HISTORY_PAGE_INVALID":
    case "RING_HISTORY_CURSOR_INVALID":
    case "RING_RECOVERY_INCOMPLETE":
    case "RING_MEMBER_REGISTRY_INVALID":
      return "indexerResponse";
    case "RING_ORIGIN_DECODE":
      return String(error.details?.["path"]).startsWith("indexedTransfer")
        ? "eventMismatch"
        : "originDecode";
    case "RING_TRANSACT_DATA_INVALID":
      return "transactData";
    case "RING_AUDIT_KEY_MISMATCH":
      return "viewingKeyMismatch";
    case "RING_AUDIT_NONCANONICAL_KEY":
      return "nonCanonicalViewingKey";
    case "RING_AUDIT_MESSAGE":
      return error.details?.["reason"] === "missing" ? "missingAuditorMessage" : "auditData";
    case "RING_AUDIT_UNSEALED":
    case "RING_AUDIT_OUTPUT_MISMATCH":
    case "RING_INVALID_LENGTH":
    case "RING_NULLIFIER_KEY_MISMATCH":
    case "RING_RECOVERY_PROGRESS_MISMATCH":
      return "auditData";
    default:
      return "transport";
  }
}

/** Rust `RowOrigins`, a row that fails opens nothing and stays listed for the caller. */
export class RowOrigins {
  readonly skipped: SkippedRingTransaction[] = [];

  constructor(
    private readonly origin: TransactionOrigin,
    private readonly ring: Address,
    private readonly context: RequestContext | undefined,
  ) {}

  /** `undefined` for a row of another event or one now in `skipped`. */
  async read(row: IndexedShieldedTransaction): Promise<ConfirmedRingTransaction | undefined> {
    rowEventIndex(row);
    try {
      return await this.origin.confirmedTransaction(row, this.ring, this.context);
    } catch (error) {
      this.skip(row, error);
      return undefined;
    }
  }

  /** `undefined` once `row` is in `skipped`. */
  attempt<T>(row: IndexedShieldedTransaction, open: () => T): T | undefined {
    try {
      return open();
    } catch (error) {
      this.skip(row, error);
      return undefined;
    }
  }

  private skip(row: IndexedShieldedTransaction, error: unknown): void {
    if (rowDisposition(error) === "retry") throw error;
    this.skipped.push(
      Object.freeze({
        slot: row.slot,
        signature: row.txSignature,
        eventIndex: rowEventIndex(row),
        reason: "invalidAuditData",
      }),
    );
  }
}

export function rowEventIndex(row: IndexedShieldedTransaction): number {
  if (row.eventIndex === undefined)
    throw new RingError("RING_RPC", { details: { reason: "missing event index" } });
  return row.eventIndex;
}
