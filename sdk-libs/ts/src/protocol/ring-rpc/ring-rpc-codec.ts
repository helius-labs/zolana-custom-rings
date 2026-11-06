import { getBase64Decoder } from "@solana/kit";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { RingError } from "../error.js";
import { getBase58Decoder } from "@solana/kit";

import { U64_MAX, indexerCodec, indexerScalars } from "@heliuslabs/spr/internal";
import type { indexerTypes } from "@heliuslabs/spr/internal";
import type { ShieldedAddress } from "@heliuslabs/spr/keypair";

import { encodeMintPolicy } from "../indexer/indexer-codec.js";
import type {
  AuthorityTransfer,
  AuthorityPayment,
  PolicyAuthorityAuth,
  CreateRecordsRegistryRequest,
  GetPendingListApprovalsRequest,
  MergeSettings,
  PendingListApproval,
  PendingListApprovalsPage,
  GetListSaltRequest,
  PrepareAuthorityTransferRequest,
  PrepareRelayRequest,
  RecordsRegistry,
  RecordUpdateEntry,
  RecordUpdateStatus,
  RefuseListApprovalRequest,
  RelayIntent,
  RelayQuote,
  RelayQuoteRequest,
  RelayStatus,
  RelayStep,
  ReaderGrantAction,
  SetMergeSettingsRequest,
  SetReaderGrantRequest,
  SubmitRecordUpdateRequest,
  SubmitRelayRequest,
  TokenAccountSetup,
} from "./ring-rpc-types.js";

const { object, toWireInteger, wireInteger } = indexerCodec;
const { checkedAddress, checkedBase64, checkedHash, checkedSignature, schemaFailure } =
  indexerScalars;

type WireObject = Record<string, unknown>;
type Hash = indexerTypes.Hash;

const base58 = getBase58Decoder();

const RELAY_OPERATIONS = [
  "anonymous",
  "confidential",
  "delegate",
  "deposit",
  "merge",
  "enroll",
] as const;

function toU64(value: bigint, path: string): number {
  return toWireInteger(value, path, 0n, U64_MAX);
}

function u64(value: unknown, path: string): bigint {
  return wireInteger(value, path, 0n, U64_MAX);
}

function text(value: unknown, path: string): string {
  if (typeof value !== "string")
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", path, "a string", value);
  return value;
}

/** Rust `GetRelayQuoteRequest`. */
export function encodeRelayQuoteRequest(value: RelayQuoteRequest): WireObject {
  if (!RELAY_OPERATIONS.includes(value.operation))
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_TYPE",
      "operation",
      "a relay operation",
      value.operation,
    );
  return { ring: checkedAddress(value.ring, "ring"), operation: value.operation };
}

/** Rust `RelayQuote`. */
export function decodeRelayQuote(value: unknown): RelayQuote {
  const row = object(value, "$", ["feePayer", "validUntilSlot"]);
  return {
    feePayer: checkedAddress(row["feePayer"], "feePayer"),
    validUntilSlot: u64(row["validUntilSlot"], "validUntilSlot"),
  };
}

/** Rust `PrepareRelayRequest`, its serialization byte for byte. */
export function encodePrepareRelayRequest(value: PrepareRelayRequest): WireObject {
  return {
    ring: checkedAddress(value.ring, "ring"),
    quote: {
      feePayer: checkedAddress(value.quote.feePayer, "quote.feePayer"),
      validUntilSlot: toU64(value.quote.validUntilSlot, "quote.validUntilSlot"),
    },
    intent: encodeRelayIntent(value.intent),
    ...(value.coSigners === undefined || value.coSigners.length === 0
      ? {}
      : {
          coSigners: value.coSigners.map((signer, index) =>
            checkedAddress(signer, `coSigners[${index}]`),
          ),
        }),
  };
}

function encodeRelayIntent(intent: RelayIntent): WireObject {
  const proofInputs = checkedBase64(intent.proofInputs, "intent.proofInputs");
  switch (intent.operation) {
    case "anonymous":
    case "confidential":
      return {
        operation: intent.operation,
        proofInputs,
        ownerSignature: checkedSignature(intent.ownerSignature, "intent.ownerSignature"),
        ...encodeTokenAccountSetup(intent.tokenAccountSetup),
      };
    case "enroll":
    case "merge":
      return {
        operation: intent.operation,
        proofInputs,
        ownerSignature: checkedSignature(intent.ownerSignature, "intent.ownerSignature"),
      };
    case "delegate":
      return {
        operation: intent.operation,
        proofInputs,
        delegateSignature: checkedSignature(intent.delegateSignature, "intent.delegateSignature"),
        ...encodeTokenAccountSetup(intent.tokenAccountSetup),
      };
    case "deposit":
      return {
        operation: intent.operation,
        proofInputs,
        depositorSignature: checkedSignature(
          intent.depositorSignature,
          "intent.depositorSignature",
        ),
      };
  }
}

/** Rust skips an empty list, a retry hashes to the same relay. */
function encodeTokenAccountSetup(setup: readonly TokenAccountSetup[] | undefined): WireObject {
  if (setup === undefined || setup.length === 0) return {};
  return {
    tokenAccountSetup: setup.map((entry, index) => ({
      owner: checkedAddress(entry.owner, `intent.tokenAccountSetup[${index}].owner`),
      mint: checkedAddress(entry.mint, `intent.tokenAccountSetup[${index}].mint`),
    })),
  };
}

/** Rust `RelayStep`. */
export function decodeRelayStep(value: unknown): RelayStep {
  const step = object(value, "$", ["step", "relayId", "message"])["step"];
  if (step === "submitted") {
    const row = object(value, "$", ["step", "relayId"]);
    return { step, relayId: checkedHash(row["relayId"], "relayId") };
  }
  if (step === "signMessage") {
    const row = object(value, "$", ["step", "relayId", "message"]);
    return {
      step,
      relayId: checkedHash(row["relayId"], "relayId"),
      message: checkedBase64(row["message"], "message"),
    };
  }
  return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", "step", "a relay step", step);
}

/** Rust `SubmitRelayRequest`. */
export function encodeSubmitRelayRequest(value: SubmitRelayRequest): WireObject {
  return {
    relayId: checkedHash(value.relayId, "relayId"),
    signer: checkedAddress(value.signer, "signer"),
    signature: checkedSignature(value.signature, "signature"),
  };
}

/** Rust `GetRelayStatusRequest`. */
export function encodeRelayStatusRequest(relayId: Hash): WireObject {
  return { relayId: checkedHash(relayId, "relayId") };
}

/** Rust `RelayStatus`. */
export function decodeRelayStatus(value: unknown): RelayStatus {
  const status = object(value, "$", ["status", "signature", "slot", "reason"])["status"];
  switch (status) {
    case "awaitingSignature":
      object(value, "$", ["status"]);
      return { status };
    case "sent": {
      const row = object(value, "$", ["status", "signature"]);
      return { status, signature: checkedSignature(row["signature"], "signature") };
    }
    case "confirmed": {
      const row = object(value, "$", ["status", "signature", "slot"]);
      return {
        status,
        signature: checkedSignature(row["signature"], "signature"),
        slot: u64(row["slot"], "slot"),
      };
    }
    case "failed": {
      const row = object(value, "$", ["status", "reason"]);
      return { status, reason: text(row["reason"], "reason") };
    }
    default:
      return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", "status", "a relay status", status);
  }
}

/** Rust `SubmitRecordUpdateRequest`. */
export function encodeSubmitRecordUpdateRequest(value: SubmitRecordUpdateRequest): WireObject {
  return {
    registry: checkedAddress(value.registry, "registry"),
    update: {
      genesisHash: checkedHash(value.update.genesisHash, "update.genesisHash"),
      ring: checkedAddress(value.update.ring, "update.ring"),
      entries: value.update.entries.map((entry, index) =>
        encodeRecordUpdateEntry(entry, `update.entries[${String(index)}]`),
      ),
      validUntilSlot: toU64(value.update.validUntilSlot, "update.validUntilSlot"),
      ...((value.update.awaitedLists ?? 0n) === 0n
        ? {}
        : { awaitedLists: toU64(value.update.awaitedLists ?? 0n, "update.awaitedLists") }),
    },
    signer: checkedAddress(value.signer, "signer"),
    signature: checkedSignature(value.signature, "signature"),
  };
}

function encodeRecordUpdateEntry(entry: RecordUpdateEntry, path: string): WireObject {
  switch (entry.kind) {
    case "write":
      return {
        kind: entry.kind,
        mintPolicy: encodeMintPolicy(entry.mintPolicy),
        member: checkedHash(entry.member, `${path}.member`),
        mask: toU64(entry.mask, `${path}.mask`),
        value: toU64(entry.value, `${path}.value`),
      };
    case "walletGrant":
      if (entry.access !== "granted" && entry.access !== "revoked")
        return schemaFailure(
          "INDEXER_SCHEMA_INVALID_TYPE",
          `${path}.access`,
          "a reader access",
          entry.access,
        );
      return {
        kind: entry.kind,
        wallet: checkedHash(entry.wallet, `${path}.wallet`),
        reader: checkedHash(entry.reader, `${path}.reader`),
        access: entry.access,
      };
  }
}

/** Rust `SubmitRecordUpdateResponse`, the update id. */
export function decodeSubmitRecordUpdate(value: unknown): Hash {
  return checkedHash(object(value, "$", ["updateId"])["updateId"], "updateId");
}

/** Rust `GetRecordUpdateStatusRequest`. */
export function encodeRecordUpdateStatusRequest(updateId: Hash): WireObject {
  return { updateId: checkedHash(updateId, "updateId") };
}

/** Rust `RecordUpdateStatus`. */
export function decodeRecordUpdateStatus(value: unknown): RecordUpdateStatus {
  const status = object(value, "$", ["status", "signature", "revision", "reason"])["status"];
  switch (status) {
    case "pendingListApproval":
    case "queued":
      object(value, "$", ["status"]);
      return { status };
    case "submitted": {
      const row = object(value, "$", ["status", "signature"]);
      return { status, signature: checkedSignature(row["signature"], "signature") };
    }
    case "applied": {
      const row = object(value, "$", ["status", "signature", "revision"]);
      return {
        status,
        signature: checkedSignature(row["signature"], "signature"),
        revision: u64(row["revision"], "revision"),
      };
    }
    case "refused": {
      const row = object(value, "$", ["status", "reason"]);
      return { status, reason: text(row["reason"], "reason") };
    }
    default:
      return schemaFailure(
        "INDEXER_SCHEMA_INVALID_TYPE",
        "status",
        "a record update status",
        status,
      );
  }
}

/** Rust `SetMergeSettingsRequest`. */
export function encodeSetMergeSettingsRequest(value: SetMergeSettingsRequest): WireObject {
  return {
    ring: checkedAddress(value.ring, "ring"),
    owner: checkedAddress(value.owner, "owner"),
    settings: encodeMergeSettings(value.settings),
    timestamp: toU64(value.timestamp, "timestamp"),
    nonce: checkedBase64(value.nonce, "nonce"),
    signature: checkedSignature(value.signature, "signature"),
  };
}

/** Rust `MergeSettings`. */
export function encodeMergeSettings(value: MergeSettings): WireObject {
  return {
    mint: checkedAddress(value.mint, "settings.mint"),
    targetNoteCount: toWireInteger(
      BigInt(value.targetNoteCount),
      "settings.targetNoteCount",
      0n,
      0xffff_ffffn,
    ),
    minAverageAmount: toU64(value.minAverageAmount, "settings.minAverageAmount"),
  };
}

/** Rust `SetMergeSettingsResponse`. */
export function decodeMergeSettings(value: unknown): MergeSettings {
  const row = object(value, "$", ["mint", "targetNoteCount", "minAverageAmount"]);
  return {
    mint: checkedAddress(row["mint"], "mint"),
    targetNoteCount: Number(
      wireInteger(row["targetNoteCount"], "targetNoteCount", 0n, 0xffff_ffffn),
    ),
    minAverageAmount: u64(row["minAverageAmount"], "minAverageAmount"),
  };
}

/** Rust `GetPendingListApprovalsRequest`. */
export function encodeGetPendingListApprovalsRequest(
  value: GetPendingListApprovalsRequest,
): WireObject {
  return {
    ring: checkedAddress(value.ring, "ring"),
    registry: checkedAddress(value.registry, "registry"),
    ...(value.cursor === undefined ? {} : { cursor: checkedHash(value.cursor, "cursor") }),
    auth: encodePolicyAuthorityAuth(value.auth),
  };
}

/** Rust `RefuseListApprovalRequest`. */
export function encodeRefuseListApprovalRequest(value: RefuseListApprovalRequest): WireObject {
  return {
    ring: checkedAddress(value.ring, "ring"),
    registry: checkedAddress(value.registry, "registry"),
    updateId: checkedHash(value.updateId, "updateId"),
    auth: encodePolicyAuthorityAuth(value.auth),
  };
}

/** Rust `CreateRecordsRegistryRequest`. */
export function encodeCreateRecordsRegistryRequest(
  value: CreateRecordsRegistryRequest,
): WireObject {
  return {
    ring: checkedAddress(value.ring, "ring"),
    auth: encodePolicyAuthorityAuth(value.auth),
  };
}

/** Rust `CreateRecordsRegistryResponse`. */
export function decodeRecordsRegistry(value: unknown): RecordsRegistry {
  const row = object(value, "$", ["registry", "storageAuthority"]);
  return {
    registry: checkedAddress(row["registry"], "registry"),
    storageAuthority: checkedAddress(row["storageAuthority"], "storageAuthority"),
  };
}

/** Rust `GetPendingListApprovalsResponse`, oldest first. */
export function decodePendingListApprovalsPage(value: unknown): PendingListApprovalsPage {
  const page = object(value, "$", ["pending", "nextCursor"]);
  const pending = page["pending"];
  if (!Array.isArray(pending))
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", "pending", "an array", pending);
  const rows = pending.map((entry: unknown, index): PendingListApproval => {
    const path = `pending[${String(index)}]`;
    const row = object(entry, path, [
      "updateId",
      "wallet",
      "member",
      "awaitedLists",
      "validUntilSlot",
    ]);
    return {
      updateId: checkedHash(row["updateId"], `${path}.updateId`),
      wallet: checkedAddress(row["wallet"], `${path}.wallet`),
      member: checkedHash(row["member"], `${path}.member`),
      awaitedLists: u64(row["awaitedLists"], `${path}.awaitedLists`),
      validUntilSlot: u64(row["validUntilSlot"], `${path}.validUntilSlot`),
    };
  });
  const nextCursor = page["nextCursor"];
  return nextCursor === undefined
    ? { pending: rows }
    : { pending: rows, nextCursor: checkedHash(nextCursor, "nextCursor") };
}

function encodePolicyAuthorityAuth(value: PolicyAuthorityAuth): WireObject {
  return {
    authority: checkedAddress(value.authority, "auth.authority"),
    timestamp: toU64(value.timestamp, "auth.timestamp"),
    nonce: checkedBase64(value.nonce, "auth.nonce"),
    signature: checkedSignature(value.signature, "auth.signature"),
  };
}

/** Rust `SerializableShieldedAddress`, the base58 text of `ShieldedAddress::to_bytes`. */
export function shieldedAddressText(address: ShieldedAddress): string {
  return base58.decode(address.toBytes());
}

/** Rust `PrepareAuthorityTransferRequest`, its serialization byte for byte. */
export function encodePrepareAuthorityTransferRequest(
  value: PrepareAuthorityTransferRequest,
): WireObject {
  return {
    ring: checkedAddress(value.ring, "ring"),
    delegate: checkedAddress(value.delegate, "delegate"),
    transfer: encodeAuthorityTransfer(value.transfer),
    txViewingKey: getBase64Decoder().decode(checkedTxKey(value.txViewingKey)),
    timestamp: toU64(value.timestamp, "timestamp"),
    nonce: checkedBase64(value.nonce, "nonce"),
    signature: checkedSignature(value.signature, "signature"),
  };
}

/** Rust `GetListSaltRequest`, its serialization byte for byte. */
export function encodeGetListSaltRequest(value: GetListSaltRequest): WireObject {
  return {
    ring: checkedAddress(value.ring, "ring"),
    writer: checkedAddress(value.writer, "writer"),
    owner: checkedAddress(value.owner, "owner"),
    timestamp: toU64(value.timestamp, "timestamp"),
    nonce: checkedBase64(value.nonce, "nonce"),
    signature: checkedSignature(value.signature, "signature"),
  };
}

function checkedTxKey(key: Bytes32): Bytes32 {
  if (key.length !== 32) throw new RingError("RING_RPC", { details: { path: "txViewingKey" } });
  return key;
}

function encodeAuthorityPayment(payment: AuthorityPayment, path: string): WireObject {
  return {
    recipient: shieldedAddressText(payment.recipient),
    mint: checkedAddress(payment.mint, `${path}.mint`),
    amount: toU64(payment.amount, `${path}.amount`),
  };
}

function encodeAuthorityTransfer(value: AuthorityTransfer): WireObject {
  return {
    sources: value.sources.map(shieldedAddressText),
    payments: value.payments.map((payment, index) =>
      encodeAuthorityPayment(payment, `transfer.payments[${index}]`),
    ),
    exits: value.exits.map((exit, index) =>
      encodeAuthorityPayment(exit, `transfer.exits[${index}]`),
    ),
    withdrawals: value.withdrawals.map((withdrawal, index) => ({
      recipient: checkedAddress(withdrawal.recipient, `transfer.withdrawals[${index}].recipient`),
      mint: checkedAddress(withdrawal.mint, `transfer.withdrawals[${index}].mint`),
      amount: toU64(withdrawal.amount, `transfer.withdrawals[${index}].amount`),
      ...(withdrawal.tokenProgram === undefined
        ? {}
        : {
            tokenProgram: checkedAddress(
              withdrawal.tokenProgram,
              `transfer.withdrawals[${index}].tokenProgram`,
            ),
          }),
    })),
  };
}

/** Rust `SetReaderGrantRequest`, its serialization byte for byte. */
export function encodeSetReaderGrantRequest(value: SetReaderGrantRequest): WireObject {
  return {
    ring: checkedAddress(value.ring, "ring"),
    ...(value.wallet === undefined ? {} : { wallet: checkedAddress(value.wallet, "wallet") }),
    reader: checkedBase64(value.reader, "reader"),
    action: readerGrantAction(value.action, "action"),
    timestamp: toU64(value.timestamp, "timestamp"),
    nonce: checkedBase64(value.nonce, "nonce"),
    signature: checkedSignature(value.signature, "signature"),
  };
}

/** Rust `SetReaderGrantResponse`, the action the service holds after the write. */
export function decodeReaderGrantAction(value: unknown): ReaderGrantAction {
  return readerGrantAction(value, "$");
}

function readerGrantAction(value: unknown, path: string): ReaderGrantAction {
  if (value !== "grant" && value !== "revoke")
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", path, "grant or revoke", value);
  return value;
}
