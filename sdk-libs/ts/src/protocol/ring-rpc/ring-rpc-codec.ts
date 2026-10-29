import { getBase58Decoder } from "@solana/kit";

import { U64_MAX, indexerCodec, indexerScalars } from "@heliuslabs/zolana/internal";
import type { indexerTypes } from "@heliuslabs/zolana/internal";
import type { ShieldedAddress } from "@heliuslabs/zolana/keypair";

import { encodeMintPolicy } from "../indexer/indexer-codec.js";
import type {
  AuthorityTransfer,
  ConfigAuthorityAuth,
  CreateRecordsRegistryRequest,
  GetPendingEnrolmentsRequest,
  MergeSettings,
  PendingEnrolment,
  PendingEnrolmentsPage,
  PrepareAuthorityTransferRequest,
  PrepareRelayRequest,
  RecordsRegistry,
  RecordUpdateEntry,
  RecordUpdateStatus,
  RefuseEnrolmentRequest,
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

const RELAY_OPERATIONS = ["anonymous", "confidential", "delegate", "deposit", "merge"] as const;

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
    case "delegate":
      return {
        operation: intent.operation,
        proofInputs,
        ...encodeTokenAccountSetup(intent.tokenAccountSetup),
      };
    case "deposit":
    case "merge":
      return { operation: intent.operation, proofInputs };
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
    case "escrow":
      return {
        kind: entry.kind,
        member: checkedHash(entry.member, `${path}.member`),
        nullifierPk: checkedHash(entry.nullifierPk, `${path}.nullifierPk`),
        ephPk: checkedBase64(entry.ephPk, `${path}.ephPk`),
        ciphertext: checkedBase64(entry.ciphertext, `${path}.ciphertext`),
        proof: checkedBase64(entry.proof, `${path}.proof`),
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
    case "awaitingAuthority":
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

/** Rust `GetPendingEnrolmentsRequest`. */
export function encodeGetPendingEnrolmentsRequest(value: GetPendingEnrolmentsRequest): WireObject {
  return {
    ring: checkedAddress(value.ring, "ring"),
    ...(value.cursor === undefined ? {} : { cursor: checkedHash(value.cursor, "cursor") }),
    auth: encodeConfigAuthorityAuth(value.auth),
  };
}

/** Rust `RefuseEnrolmentRequest`. */
export function encodeRefuseEnrolmentRequest(value: RefuseEnrolmentRequest): WireObject {
  return {
    ring: checkedAddress(value.ring, "ring"),
    updateId: checkedHash(value.updateId, "updateId"),
    auth: encodeConfigAuthorityAuth(value.auth),
  };
}

/** Rust `CreateRecordsRegistryRequest`. */
export function encodeCreateRecordsRegistryRequest(
  value: CreateRecordsRegistryRequest,
): WireObject {
  return {
    ring: checkedAddress(value.ring, "ring"),
    auth: encodeConfigAuthorityAuth(value.auth),
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

/** Rust `GetPendingEnrolmentsResponse`, oldest first. */
export function decodePendingEnrolmentsPage(value: unknown): PendingEnrolmentsPage {
  const page = object(value, "$", ["enrolments", "nextCursor"]);
  const enrolments = page["enrolments"];
  if (!Array.isArray(enrolments))
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", "enrolments", "an array", enrolments);
  const rows = enrolments.map((entry: unknown, index): PendingEnrolment => {
    const path = `enrolments[${String(index)}]`;
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
    ? { enrolments: rows }
    : { enrolments: rows, nextCursor: checkedHash(nextCursor, "nextCursor") };
}

function encodeConfigAuthorityAuth(value: ConfigAuthorityAuth): WireObject {
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
    timestamp: toU64(value.timestamp, "timestamp"),
    nonce: checkedBase64(value.nonce, "nonce"),
    signature: checkedSignature(value.signature, "signature"),
  };
}

function encodeAuthorityTransfer(value: AuthorityTransfer): WireObject {
  return {
    source: shieldedAddressText(value.source),
    mint: checkedAddress(value.mint, "transfer.mint"),
    payments: value.payments.map((payment, index) => ({
      recipient: shieldedAddressText(payment.recipient),
      amount: toU64(payment.amount, `transfer.payments[${index}].amount`),
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
