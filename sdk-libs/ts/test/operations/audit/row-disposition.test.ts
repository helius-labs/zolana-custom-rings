import { describe, expect, it } from "vitest";

import vector from "../../../../../test-vectors/audit/row-dispositions.json" with { type: "json" };
import { KeypairError } from "@heliuslabs/spr/keypair";
import { TransactionError } from "@heliuslabs/spr/transaction";

import { RingKeyError } from "../../../src/crypto/error.js";
import {
  AUDIT_FAILURE_DISPOSITIONS,
  auditFailureKind,
  rowDisposition,
  type AuditFailureKind,
} from "../../../src/operations/audit/row-origins.js";
import { RingError, type RingErrorCode } from "../../../src/protocol/error.js";

const ring = (code: RingErrorCode, details?: Record<string, unknown>) =>
  new RingError(code, details === undefined ? undefined : { details });

const FAILURES: Readonly<Record<AuditFailureKind, unknown>> = {
  transport: ring("RING_RPC_TRANSPORT"),
  originUnavailable: ring("RING_ORIGIN_UNAVAILABLE"),
  invalidStackHeight: ring("RING_ORIGIN_STACK"),
  missingAuditorMessage: ring("RING_AUDIT_MESSAGE", { reason: "missing" }),
  indexerResponse: ring("RING_HISTORY_PAGE_INVALID"),
  originDecode: ring("RING_ORIGIN_DECODE", { path: "eventIndex" }),
  transactData: ring("RING_TRANSACT_DATA_INVALID"),
  eventMismatch: ring("RING_ORIGIN_DECODE", { path: "indexedTransfer.output" }),
  viewingKeyMismatch: ring("RING_AUDIT_KEY_MISMATCH"),
  nonCanonicalViewingKey: ring("RING_AUDIT_NONCANONICAL_KEY"),
  keyMaterial: new KeypairError("KEYPAIR_INVALID_SECRET_KEY"),
  auditData: ring("RING_AUDIT_MESSAGE", { reason: "malformed" }),
};

describe("row dispositions (test-vectors/audit/row-dispositions.json)", () => {
  it("names every shared kind with its shared disposition", () => {
    expect(
      Object.fromEntries(vector.cases.map(({ kind, disposition }) => [kind, disposition])),
    ).toEqual(AUDIT_FAILURE_DISPOSITIONS);
  });

  it.each(vector.cases)("maps a $kind failure to $disposition", ({ kind, disposition }) => {
    const failure = FAILURES[kind as AuditFailureKind];
    expect(auditFailureKind(failure)).toBe(kind);
    expect(rowDisposition(failure)).toBe(disposition);
  });
});

describe("auditFailureKind", () => {
  it.each<readonly [RingErrorCode, AuditFailureKind]>([
    ["RING_RPC", "indexerResponse"],
    ["RING_RECOVERY_INCOMPLETE", "indexerResponse"],
    ["RING_MEMBER_REGISTRY_INVALID", "indexerResponse"],
    ["RING_RPC_RATE_LIMITED", "transport"],
    ["RING_RPC_REFUSED", "transport"],
    ["RING_AUDIT_UNSEALED", "auditData"],
    ["RING_AUDIT_OUTPUT_MISMATCH", "auditData"],
    ["RING_INVALID_LENGTH", "auditData"],
    ["RING_NULLIFIER_KEY_MISMATCH", "auditData"],
  ])("places %s as %s", (code, kind) => {
    expect(auditFailureKind(ring(code))).toBe(kind);
  });

  it("splits a disclosure refusal from other key material", () => {
    expect(auditFailureKind(new RingKeyError("KEYPAIR_DISCLOSURE_FIELD"))).toBe("auditData");
    expect(auditFailureKind(new RingKeyError("KEYPAIR_INVALID_LENGTH"))).toBe("keyMaterial");
    expect(auditFailureKind(new TransactionError("TRANSACTION_INVALID_LENGTH"))).toBe("auditData");
  });

  it("holds the reader's position on an error it cannot place", () => {
    for (const unknown of [new TypeError("undefined"), undefined, ring("RING_PAUSED")])
      expect(rowDisposition(unknown)).toBe("retry");
  });
});
