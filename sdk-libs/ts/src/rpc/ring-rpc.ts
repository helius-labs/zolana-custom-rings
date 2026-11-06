import { ViewingKey } from "@heliuslabs/spr/keypair";
import { checkedApiKey, serviceUrl } from "@heliuslabs/spr/internal";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  createSignableMessage,
  getBase58Decoder,
  getBase64Decoder,
  type MessagePartialSigner,
} from "@solana/kit";

import type {
  Address,
  Bytes32,
  Bytes33,
  Bytes64,
  RequestContext,
  Signature,
} from "@heliuslabs/spr/interface";
import { initializePoseidon } from "@heliuslabs/spr";
import {
  isCanonicalField,
  postJsonRpc,
  TransportFailure,
  checkedEndpoint,
  checkedFetch,
  wireDecoder,
  addressBytes,
  copyBytes,
  sha256,
  concatBytes,
  ZERO_32,
  equalBytes,
  assetField,
  indexerScalars,
  type indexerTypes,
} from "@heliuslabs/spr/internal";
import { MAX_MERGE_INPUTS } from "@heliuslabs/spr/interface";
import { X25519PublicKey, KeypairError } from "@heliuslabs/spr/keypair";
import { ringIdField } from "../crypto/derivation/ring-stream.js";
import {
  snapshotPages,
  SNAPSHOT_CURSOR_LENGTH,
  SNAPSHOT_CURSOR_VERSION,
} from "./wallet-snapshot.js";

import {
  knownUtxoHash,
  type AuditedUtxo,
  type KnownUtxo,
  type OutputOpening,
  type OutputPayloadError,
  type OutputPayloadErrorKind,
} from "../operations/audit/audit.js";
import { RingError } from "../protocol/error.js";
import { ringRecordsAddress } from "../protocol/pda/index.js";
import {
  checkedReaderKey,
  readerKeyBytes,
  readerKeyFromBytes,
  type ReaderKey,
} from "../operations/management/reader-access.js";
import { verifyRecordUpdate } from "../protocol/ring-rpc/record-update.js";
import {
  decodeMergeSettings,
  decodePendingListApprovalsPage,
  decodeRecordsRegistry,
  decodeRecordUpdateStatus,
  decodeRelayQuote,
  decodeRelayStatus,
  decodeReaderGrantAction,
  decodeRelayStep,
  decodeSubmitRecordUpdate,
  encodeCreateRecordsRegistryRequest,
  encodeGetPendingListApprovalsRequest,
  encodeGetListSaltRequest,
  encodeMergeSettings,
  encodePrepareAuthorityTransferRequest,
  encodePrepareRelayRequest,
  encodeRecordUpdateStatusRequest,
  encodeRefuseListApprovalRequest,
  encodeRelayQuoteRequest,
  encodeRelayStatusRequest,
  encodeSetMergeSettingsRequest,
  encodeSetReaderGrantRequest,
  encodeSubmitRecordUpdateRequest,
  encodeSubmitRelayRequest,
  shieldedAddressText,
} from "../protocol/ring-rpc/ring-rpc-codec.js";
import {
  RingRpcMethod,
  type AuthorityTransfer,
  type PolicyAuthorityAuth,
  type CreateRecordsRegistryRequest,
  type GetPendingListApprovalsRequest,
  type PendingListApprovalsPage,
  type GetListSaltRequest,
  type MergeSettings,
  type PrepareAuthorityTransferRequest,
  type PrepareRelayRequest,
  type ReaderGrantAction,
  type RecordsRegistry,
  type RecordUpdateStatus,
  type RefuseListApprovalRequest,
  type RelayQuote,
  type RelayQuoteRequest,
  type RelayStatus,
  type RelayStep,
  type SetMergeSettingsRequest,
  type SetReaderGrantRequest,
  type SubmitRecordUpdateRequest,
  type SubmitRelayRequest,
} from "../protocol/ring-rpc/ring-rpc-types.js";
import { ringRpcRefusalName } from "../protocol/ring-rpc/ring-rpc-refusal.js";
import { InputClass, InputMap } from "../protocol/codec/audit-stream.js";

type Hash = indexerTypes.Hash;

const base58Decoder = getBase58Decoder();
const base64Decoder = getBase64Decoder();
const encoder = new TextEncoder();

const RING_RPC_TIMEOUT_MS = 30_000;
const RING_RPC_MAX_REQUEST_BYTES = 1024 * 1024;
const RING_RPC_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

/** `reader` is the 34-byte scheme-tagged key of `readerKeyBytes`, a P-256 reader signs through WebAuthn only. */
export interface RingReadSigner {
  readonly reader: Uint8Array;
  sign(message: Uint8Array): Promise<Uint8Array | WebAuthnSignature>;
}

/** Mirrors Rust `WebAuthnAssertion` plus the DER signature. */
export interface WebAuthnSignature {
  readonly signature: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly clientDataJSON: Uint8Array;
}

const READ_DOMAIN = "zolana/ring-rpc-read";
const AUDITOR_KEY_DOMAIN = "zolana/ring-auditor-key";
const AUDITOR_KEY_REQUEST_DOMAIN = "zolana/ring-rpc-auditor-key-request";
const AUDITED_UTXOS_DOMAIN = "zolana/ring-rpc-audited-utxos";
const AUTHORITY_TRANSFER_DOMAIN = "zolana/ring-rpc-authority-transfer";
const LIST_SALT_DOMAIN = "zolana/ring-rpc-list-salt";
const MERGE_SETTINGS_DOMAIN = "zolana/ring-rpc-merge-settings";
const POLICY_AUTHORITY_DOMAIN = "zolana/ring-rpc-policy-authority";
const READER_GRANT_DOMAIN = "zolana/ring-rpc-reader-grant";
const WALLET_STATUS_DOMAIN = "zolana/ring-rpc-wallet-status";
const SPEND_COVERAGE_DOMAIN = "zolana/ring-rpc-spend-coverage";
/** Rust `AUDIT_PAGE_LIMIT`. */
export const RING_READ_PAGE_LIMIT = 100n;
/** Rust `AUDITED_UTXOS_LIMIT`, the UTXO hashes one read names. */
export const RING_AUDITED_UTXOS_LIMIT = 100;
/** Rust `AUDIT_CURSOR_LIMIT`. */
export const RING_READ_CURSOR_LIMIT = 256;

/** Rust `PagedRead`, the paged read a reader's signature authorizes. */
export type RingPagedRead = "getDecryptedTransactions" | "getWalletActivity" | "getAuditedMerges";

/** Rust `ReadTarget`, one ring behind one ring rpc on one cluster, every signed read names all three. */
export interface RingReadTarget {
  /** The genesis hash. */
  readonly cluster: Bytes32;
  /** The service key the caller pinned, never one the service reports. */
  readonly service: Address;
  readonly ringProgramId: Address;
}

/** Rust `ReadTarget::lines`. */
function targetLines(target: RingReadTarget): readonly string[] {
  return [
    `cluster: ${base58Decoder.decode(target.cluster)}`,
    `service: ${target.service}`,
    `ring: ${target.ringProgramId}`,
  ];
}

/** Rust `wallet_line`, no line for a ring-wide request. */
function walletLines(wallet: Address | undefined): readonly string[] {
  return wallet === undefined ? [] : [`wallet: ${wallet}`];
}

function checkedReadTarget(target: RingReadTarget): RingReadTarget {
  addressBytes(target.service, "service");
  addressBytes(target.ringProgramId, "ringProgramId");
  return Object.freeze({
    cluster: copyBytes(target.cluster, 32, "cluster") as Bytes32,
    service: target.service,
    ringProgramId: target.ringProgramId,
  });
}

/** Mirrors Rust `ReadAttestation::message`. */
export function ringReadAttestation(
  input: Readonly<{
    method: RingPagedRead;
    target: RingReadTarget;
    timestamp: bigint;
    nonce: Bytes32;
    cursor?: Uint8Array;
    limit?: bigint;
    wallet?: Address;
  }>,
): Uint8Array {
  const cursor = input.cursor === undefined ? "" : base64Decoder.decode(input.cursor);
  return encoder.encode(
    [
      READ_DOMAIN,
      `method: ${input.method}`,
      ...targetLines(input.target),
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
      `limit: ${input.limit ?? 0n}`,
      `cursor: ${cursor}`,
      ...walletLines(input.wallet),
    ].join("\n"),
  );
}

export interface WalletStatusAttestationInput {
  readonly target: RingReadTarget;
  readonly wallet: Address;
  readonly timestamp: bigint;
  readonly nonce: Bytes32;
  readonly cursor?: Uint8Array;
}

export function walletStatusAttestation(input: WalletStatusAttestationInput): Uint8Array {
  return walletSnapshotMessage({ ...input, domain: WALLET_STATUS_DOMAIN });
}

export function walletSnapshotReleaseAttestation(
  input: WalletStatusAttestationInput & Readonly<{ cursor: Uint8Array }>,
): Uint8Array {
  return walletSnapshotMessage({
    ...input,
    domain: "zolana/ring-rpc-wallet-snapshot-release",
  });
}

function walletSnapshotMessage(
  input: WalletStatusAttestationInput & Readonly<{ domain: string }>,
): Uint8Array {
  return encoder.encode(
    [
      input.domain,
      ...targetLines(input.target),
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
      `wallet: ${input.wallet}`,
      `cursor: ${input.cursor === undefined ? "" : base64Decoder.decode(input.cursor)}`,
    ].join("\n"),
  );
}

export interface DelegateNotesAttestationInput {
  readonly target: RingReadTarget;
  readonly delegate: Address;
  readonly owner: Address;
  readonly timestamp: bigint;
  readonly nonce: Bytes32;
  readonly cursor?: Uint8Array;
}

export function delegateNotesAttestation(input: DelegateNotesAttestationInput): Uint8Array {
  return delegateSnapshotMessage({ ...input, domain: "zolana/ring-rpc-delegate-notes" });
}

export function delegateSnapshotReleaseAttestation(
  input: DelegateNotesAttestationInput & Readonly<{ cursor: Uint8Array }>,
): Uint8Array {
  return delegateSnapshotMessage({
    ...input,
    domain: "zolana/ring-rpc-delegate-snapshot-release",
  });
}

function delegateSnapshotMessage(
  input: DelegateNotesAttestationInput & Readonly<{ domain: string }>,
): Uint8Array {
  return encoder.encode(
    [
      input.domain,
      ...targetLines(input.target),
      `delegate: ${input.delegate}`,
      `owner: ${input.owner}`,
      `cursor: ${input.cursor === undefined ? "" : base64Decoder.decode(input.cursor)}`,
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
    ].join("\n"),
  );
}

/** Mirrors Rust `SpendCoverageAttestation::message`. */
export function spendCoverageAttestation(
  input: Readonly<{
    target: RingReadTarget;
    authority: Address;
    timestamp: bigint;
    nonce: Bytes32;
    cursor?: Uint8Array;
  }>,
): Uint8Array {
  return encoder.encode(
    [
      SPEND_COVERAGE_DOMAIN,
      ...targetLines(input.target),
      `authority: ${input.authority}`,
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
      `cursor: ${input.cursor === undefined ? "" : base64Decoder.decode(input.cursor)}`,
    ].join("\n"),
  );
}

/** Mirrors Rust `AuditedUtxosAttestation::message`, the digest binds every requested hash in order. */
export function auditedUtxosAttestation(
  input: Readonly<{
    target: RingReadTarget;
    timestamp: bigint;
    nonce: Bytes32;
    utxoHashes: readonly Bytes32[];
    wallet?: Address;
  }>,
): Uint8Array {
  const joined = new Uint8Array(32 * input.utxoHashes.length);
  input.utxoHashes.forEach((utxoHash, index) => joined.set(utxoHash, 32 * index));
  return encoder.encode(
    [
      AUDITED_UTXOS_DOMAIN,
      ...targetLines(input.target),
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
      `utxos: ${base64Decoder.decode(sha256(joined))}`,
      ...walletLines(input.wallet),
    ].join("\n"),
  );
}

/** Mirrors Rust `AuditorKeyStatement::message`, bound to the cluster and the nonce of the request it answers. */
export function auditorKeyStatement(
  input: Readonly<{
    cluster: Bytes32;
    ringProgramId: Address;
    auditorPublicKey: X25519PublicKey;
    nonce: Bytes32;
  }>,
): Uint8Array {
  return concatBytes(
    encoder.encode(AUDITOR_KEY_DOMAIN),
    copyBytes(input.cluster, 32, "cluster"),
    addressBytes(input.ringProgramId, "ringProgramId"),
    input.auditorPublicKey.toBytes(),
    copyBytes(input.nonce, 32, "nonce"),
  );
}

/** Mirrors Rust `AuditorKeyAttestation::bytes`, the genesis hash pins the cluster. */
export function auditorKeyRequestAttestation(
  input: Readonly<{
    genesisHash: Bytes32;
    ringProgramId: Address;
    timestamp: bigint;
    nonce: Bytes32;
  }>,
): Uint8Array {
  return encoder.encode(
    [
      AUDITOR_KEY_REQUEST_DOMAIN,
      `genesis: ${base58Decoder.decode(input.genesisHash)}`,
      `ring: ${input.ringProgramId}`,
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
    ].join("\n"),
  );
}

/** Mirrors Rust `AuthorityTransferAttestation::message`, one `payment:` line per payment in order. */
export function authorityTransferAttestation(
  input: Readonly<{
    target: RingReadTarget;
    delegate: Address;
    transfer: AuthorityTransfer;
    timestamp: bigint;
    nonce: Bytes32;
  }>,
): Uint8Array {
  return encoder.encode(
    [
      AUTHORITY_TRANSFER_DOMAIN,
      ...targetLines(input.target),
      `delegate: ${input.delegate}`,
      ...input.transfer.sources.map((source) => `source: ${shieldedAddressText(source)}`),
      ...(
        [
          ["payment", input.transfer.payments],
          ["exit", input.transfer.exits],
        ] as const
      ).flatMap(([kind, outputs]) =>
        outputs.map(
          (output) =>
            `${kind}: ${shieldedAddressText(output.recipient)} ${output.mint} ${output.amount}`,
        ),
      ),
      ...input.transfer.withdrawals.map(
        (withdrawal) =>
          `withdrawal: ${withdrawal.recipient} ${withdrawal.mint} ${withdrawal.amount} ${withdrawal.tokenProgram ?? "-"}`,
      ),
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
    ].join("\n"),
  );
}

/** Mirrors Rust `AuthorityTransferRequest`, the ring delegate signs it. */
export class RingAuthorityTransferRequest {
  readonly #target: RingReadTarget;
  readonly #transfer: AuthorityTransfer;
  #timestamp?: bigint;
  #txViewingKey?: Bytes32;

  private constructor(target: RingReadTarget, transfer: AuthorityTransfer) {
    this.#target = checkedReadTarget(target);
    this.#transfer = transfer;
  }

  static forTransfer(
    target: RingReadTarget,
    transfer: AuthorityTransfer,
  ): RingAuthorityTransferRequest {
    return new RingAuthorityTransferRequest(target, transfer);
  }

  /** Unix seconds, the RPC rejects a clock more than its skew away. */
  at(timestamp: bigint): this {
    this.#timestamp = checkedUnixTimestamp(timestamp, "timestamp");
    return this;
  }

  /** A fresh key when absent. */
  withTxViewingKey(txViewingKey: Bytes32): this {
    this.#txViewingKey = txViewingKey;
    return this;
  }

  async sign(delegate: MessagePartialSigner): Promise<PrepareAuthorityTransferRequest> {
    const timestamp = timestampOrNow(this.#timestamp);
    const nonce = freshNonce();
    const signature = await signMessage(
      delegate,
      authorityTransferAttestation({
        target: this.#target,
        delegate: delegate.address,
        transfer: this.#transfer,
        timestamp,
        nonce,
      }),
    );
    return Object.freeze({
      ring: this.#target.ringProgramId,
      delegate: delegate.address,
      transfer: this.#transfer,
      txViewingKey: this.#txViewingKey ?? freshTxViewingKey(),
      timestamp,
      nonce: base64Decoder.decode(nonce) as indexerTypes.Base64String,
      signature: base58Decoder.decode(signature) as Signature,
    });
  }
}

function freshTxViewingKey(): Bytes32 {
  const key = ViewingKey.generate();
  const secret = key.secretBytes();
  key.destroy();
  return secret;
}

/** Mirrors Rust `ListSaltAttestation::message`. */
export function listSaltAttestation(
  input: Readonly<{
    target: RingReadTarget;
    writer: Address;
    owner: Address;
    timestamp: bigint;
    nonce: Bytes32;
  }>,
): Uint8Array {
  return encoder.encode(
    [
      LIST_SALT_DOMAIN,
      ...targetLines(input.target),
      `writer: ${input.writer}`,
      `owner: ${input.owner}`,
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
    ].join("\n"),
  );
}

/** Mirrors Rust `ListSaltRequest`, a writer of the ring's salted lists signs it. */
export class RingListSaltRequest {
  readonly #target: RingReadTarget;
  readonly #owner: Address;
  #timestamp?: bigint;

  private constructor(target: RingReadTarget, owner: Address) {
    this.#target = checkedReadTarget(target);
    this.#owner = owner;
  }

  static forOwner(target: RingReadTarget, owner: Address): RingListSaltRequest {
    return new RingListSaltRequest(target, owner);
  }

  /** Unix seconds, the RPC rejects a clock more than its skew away. */
  at(timestamp: bigint): this {
    this.#timestamp = checkedUnixTimestamp(timestamp, "timestamp");
    return this;
  }

  async sign(writer: MessagePartialSigner): Promise<GetListSaltRequest> {
    const timestamp = timestampOrNow(this.#timestamp);
    const nonce = freshNonce();
    const signature = await signMessage(
      writer,
      listSaltAttestation({
        target: this.#target,
        writer: writer.address,
        owner: this.#owner,
        timestamp,
        nonce,
      }),
    );
    return Object.freeze({
      ring: this.#target.ringProgramId,
      writer: writer.address,
      owner: this.#owner,
      timestamp,
      nonce: base64Decoder.decode(nonce) as indexerTypes.Base64String,
      signature: base58Decoder.decode(signature) as Signature,
    });
  }
}

/** Rust `ListPendingApprovals`, `RefuseListApproval` or `CreateRecords`, the action the policy authority signs. */
export type PolicyAuthorityAction =
  | Readonly<{ kind: "list"; registry: Address; cursor?: Hash }>
  | Readonly<{ kind: "refuse"; registry: Address; updateId: Hash }>
  | Readonly<{ kind: "createRecords" }>;

export type ListApprovalTarget = RingReadTarget & Readonly<{ registry: Address }>;

/** Mirrors Rust `PolicyAuthorityAttestation::message`. */
export function policyAuthorityAttestation(
  input: Readonly<{
    target: RingReadTarget;
    authority: Address;
    action: PolicyAuthorityAction;
    timestamp: bigint;
    nonce: Bytes32;
  }>,
): Uint8Array {
  const action = policyAuthorityActionLine(input.action);
  return encoder.encode(
    [
      POLICY_AUTHORITY_DOMAIN,
      ...targetLines(input.target),
      `authority: ${input.authority}`,
      `action: ${action}`,
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
    ].join("\n"),
  );
}

function policyAuthorityActionLine(action: PolicyAuthorityAction): string {
  switch (action.kind) {
    case "refuse":
      return `refuse ${address(action.registry, "registry")} ${indexerScalars.checkedHash(action.updateId, "updateId")}`;
    case "createRecords":
      return "create records";
    case "list":
      return action.cursor === undefined
        ? `list ${address(action.registry, "registry")}`
        : `list ${address(action.registry, "registry")} after ${indexerScalars.checkedHash(action.cursor, "cursor")}`;
  }
}

/** Rust `GetPendingListApprovalsRequest::read` signed by the policy authority, the page after `cursor`. */
export async function signPendingListApprovalsRequest(
  target: ListApprovalTarget,
  authority: MessagePartialSigner,
  cursor?: Hash,
  timestamp?: bigint,
): Promise<GetPendingListApprovalsRequest> {
  const checked = checkedReadTarget(target);
  const registry = address(target.registry, "registry");
  const action = { kind: "list" as const, registry, ...(cursor === undefined ? {} : { cursor }) };
  return Object.freeze({
    ring: checked.ringProgramId,
    registry,
    ...(cursor === undefined ? {} : { cursor }),
    auth: await policyAuthorityAuth(checked, authority, action, timestamp),
  });
}

/** Rust `RefuseListApprovalRequest::refusal` signed by the policy authority. */
export async function signRefuseListApprovalRequest(
  target: ListApprovalTarget,
  authority: MessagePartialSigner,
  updateId: Hash,
  timestamp?: bigint,
): Promise<RefuseListApprovalRequest> {
  const checked = checkedReadTarget(target);
  const registry = address(target.registry, "registry");
  return Object.freeze({
    ring: checked.ringProgramId,
    registry,
    updateId,
    auth: await policyAuthorityAuth(
      checked,
      authority,
      { kind: "refuse", registry, updateId },
      timestamp,
    ),
  });
}

/** Rust `CreateRecordsRegistryRequest::create` signed by the policy authority, or the upgrade authority before `Initialize`. */
export async function signCreateRecordsRegistryRequest(
  target: RingReadTarget,
  authority: MessagePartialSigner,
  timestamp?: bigint,
): Promise<CreateRecordsRegistryRequest> {
  const checked = checkedReadTarget(target);
  return Object.freeze({
    ring: checked.ringProgramId,
    auth: await policyAuthorityAuth(checked, authority, { kind: "createRecords" }, timestamp),
  });
}

async function policyAuthorityAuth(
  target: RingReadTarget,
  authority: MessagePartialSigner,
  action: PolicyAuthorityAction,
  timestamp: bigint | undefined,
): Promise<PolicyAuthorityAuth> {
  const signedAt = timestampOrNow(
    timestamp === undefined ? undefined : checkedUnixTimestamp(timestamp, "timestamp"),
  );
  const nonce = freshNonce();
  const signature = await signMessage(
    authority,
    policyAuthorityAttestation({
      target,
      authority: authority.address,
      action,
      timestamp: signedAt,
      nonce,
    }),
  );
  return Object.freeze({
    authority: authority.address,
    timestamp: signedAt,
    nonce: base64Decoder.decode(nonce) as indexerTypes.Base64String,
    signature: base58Decoder.decode(signature) as Signature,
  });
}

/** Rust `ReaderGrantAttestation` without its target, a ring-wide grant names no `wallet`. */
export interface RingReaderGrant {
  readonly wallet?: Address;
  readonly reader: ReaderKey;
  readonly action: ReaderGrantAction;
}

/** Mirrors Rust `ReaderGrantAttestation::message`. */
export function readerGrantAttestation(
  input: RingReaderGrant & Readonly<{ target: RingReadTarget; timestamp: bigint; nonce: Bytes32 }>,
): Uint8Array {
  return encoder.encode(
    [
      READER_GRANT_DOMAIN,
      ...targetLines(input.target),
      ...walletLines(input.wallet),
      `reader: ${base64Decoder.decode(readerKeyBytes(checkedReaderKey(input.reader)))}`,
      `action: ${input.action}`,
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
    ].join("\n"),
  );
}

/** Mirrors Rust `ReaderGrantRequest`, the service takes a ring-wide grant only from the ring's policy authority. */
export class RingReaderGrantRequest {
  readonly #target: RingReadTarget;
  readonly #grant: RingReaderGrant;
  #timestamp?: bigint;

  private constructor(target: RingReadTarget, grant: RingReaderGrant) {
    this.#target = checkedReadTarget(target);
    if (grant.wallet !== undefined) addressBytes(grant.wallet, "wallet");
    this.#grant = Object.freeze({
      ...grant,
      reader: checkedReaderKey(grant.reader),
    });
  }

  static forGrant(target: RingReadTarget, grant: RingReaderGrant): RingReaderGrantRequest {
    return new RingReaderGrantRequest(target, grant);
  }

  /** Unix seconds, the RPC rejects a clock more than its skew away. */
  at(timestamp: bigint): this {
    this.#timestamp = checkedUnixTimestamp(timestamp, "timestamp");
    return this;
  }

  async sign(signer: MessagePartialSigner): Promise<SetReaderGrantRequest> {
    const { wallet, reader, action } = this.#grant;
    if (wallet !== undefined && signer.address !== wallet) throw invalidRequest("signer");
    const timestamp = timestampOrNow(this.#timestamp);
    const nonce = freshNonce();
    const signature = await signMessage(
      signer,
      readerGrantAttestation({
        target: this.#target,
        ...this.#grant,
        timestamp,
        nonce,
      }),
    );
    return Object.freeze({
      ring: this.#target.ringProgramId,
      ...(wallet === undefined ? {} : { wallet }),
      reader: base64Decoder.decode(readerKeyBytes(reader)) as indexerTypes.Base64String,
      action,
      timestamp,
      nonce: base64Decoder.decode(nonce) as indexerTypes.Base64String,
      signature: base58Decoder.decode(signature) as Signature,
    });
  }
}

/** Mirrors Rust `MergeSettingsAttestation::message`. */
export function mergeSettingsAttestation(
  input: Readonly<{
    target: RingReadTarget;
    owner: Address;
    settings: MergeSettings;
    timestamp: bigint;
    nonce: Bytes32;
  }>,
): Uint8Array {
  return encoder.encode(
    [
      MERGE_SETTINGS_DOMAIN,
      ...targetLines(input.target),
      `owner: ${input.owner}`,
      `mint: ${input.settings.mint}`,
      `target notes: ${input.settings.targetNoteCount}`,
      `minimum average: ${input.settings.minAverageAmount}`,
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
    ].join("\n"),
  );
}

/** Mirrors Rust `MergeSettingsRequest`, the signer is the owner whose notes Ring RPC merges. */
export class RingMergeSettingsRequest {
  readonly #target: RingReadTarget;
  readonly #settings: MergeSettings;
  #timestamp?: bigint;

  private constructor(target: RingReadTarget, settings: MergeSettings) {
    this.#target = checkedReadTarget(target);
    // The wire codec refuses a value the Rust request cannot carry before any signature.
    encodeMergeSettings(settings);
    this.#settings = Object.freeze({ ...settings });
  }

  /** A zero `targetNoteCount` stops managed merges of the mint. */
  static forSettings(target: RingReadTarget, settings: MergeSettings): RingMergeSettingsRequest {
    return new RingMergeSettingsRequest(target, settings);
  }

  /** Unix seconds, the RPC rejects a clock more than its skew away. */
  at(timestamp: bigint): this {
    this.#timestamp = checkedUnixTimestamp(timestamp, "timestamp");
    return this;
  }

  async sign(owner: MessagePartialSigner): Promise<SetMergeSettingsRequest> {
    const timestamp = timestampOrNow(this.#timestamp);
    const nonce = freshNonce();
    const signature = await signMessage(
      owner,
      mergeSettingsAttestation({
        target: this.#target,
        owner: owner.address,
        settings: this.#settings,
        timestamp,
        nonce,
      }),
    );
    return Object.freeze({
      ring: this.#target.ringProgramId,
      owner: owner.address,
      settings: this.#settings,
      timestamp,
      nonce: base64Decoder.decode(nonce) as indexerTypes.Base64String,
      signature: base58Decoder.decode(signature) as Signature,
    });
  }
}

export function messageSignerReader(signer: MessagePartialSigner): RingReadSigner {
  return Object.freeze({
    reader: readerKeyBytes(checkedReaderKey(signer.address)),
    sign: (message: Uint8Array) => signMessage(signer, message),
  });
}

/** Mirrors Rust `GetDecryptedTransactionsRequest` after `ReadRequest::sign`. */
export interface SignedRingRead {
  readonly method: RingPagedRead;
  readonly ringProgramId: Address;
  readonly cursor?: Uint8Array;
  readonly limit?: bigint;
  /** Narrows the read to the wallet's rows. */
  readonly wallet?: Address;
  readonly reader: Uint8Array;
  readonly timestamp: bigint;
  readonly nonce: Bytes32;
  readonly signature: Uint8Array | WebAuthnSignature;
}

/** Mirrors Rust `ReadRequest`, every signature draws its own nonce. */
export class RingReadRequest {
  readonly #method: RingPagedRead;
  readonly #target: RingReadTarget;
  #cursor?: Uint8Array;
  #limit?: bigint;
  #wallet?: Address;
  #timestamp?: bigint;

  private constructor(method: RingPagedRead, target: RingReadTarget) {
    this.#method = method;
    this.#target = checkedReadTarget(target);
  }

  static decryptedTransactions(target: RingReadTarget): RingReadRequest {
    return new RingReadRequest("getDecryptedTransactions", target);
  }

  static walletActivity(target: RingReadTarget, wallet: Address): RingReadRequest {
    return new RingReadRequest("getWalletActivity", target).withWallet(wallet);
  }

  static auditedMerges(target: RingReadTarget): RingReadRequest {
    return new RingReadRequest("getAuditedMerges", target);
  }

  withCursor(cursor: Uint8Array): this {
    this.#cursor = new Uint8Array(checkedReadCursor(cursor));
    return this;
  }

  withLimit(limit: bigint): this {
    this.#limit = checkedReadLimit(limit);
    return this;
  }

  withWallet(wallet: Address): this {
    addressBytes(wallet, "wallet");
    this.#wallet = wallet;
    return this;
  }

  /** Unix seconds, the RPC rejects a clock more than its skew away. */
  at(timestamp: bigint): this {
    this.#timestamp = checkedUnixTimestamp(timestamp, "timestamp");
    return this;
  }

  async sign(signer: RingReadSigner): Promise<SignedRingRead> {
    const timestamp = timestampOrNow(this.#timestamp);
    const nonce = freshNonce();
    const signature = await signer.sign(
      ringReadAttestation({
        method: this.#method,
        target: this.#target,
        timestamp,
        nonce,
        ...(this.#cursor === undefined ? {} : { cursor: this.#cursor }),
        ...(this.#limit === undefined ? {} : { limit: this.#limit }),
        ...(this.#wallet === undefined ? {} : { wallet: this.#wallet }),
      }),
    );
    return Object.freeze({
      method: this.#method,
      ringProgramId: this.#target.ringProgramId,
      ...(this.#cursor === undefined ? {} : { cursor: this.#cursor }),
      ...(this.#limit === undefined ? {} : { limit: this.#limit }),
      ...(this.#wallet === undefined ? {} : { wallet: this.#wallet }),
      reader: signer.reader,
      timestamp,
      nonce,
      signature,
    });
  }
}

/** Mirrors Rust `GetAuditedUtxosRequest` after `AuditedUtxosRequest::sign`. */
export interface SignedAuditedUtxosRead {
  readonly ringProgramId: Address;
  /** Answers come back in the same order. */
  readonly utxoHashes: readonly Bytes32[];
  /** Narrows the read to the wallet's notes. */
  readonly wallet?: Address;
  readonly reader: Uint8Array;
  readonly timestamp: bigint;
  readonly nonce: Bytes32;
  readonly signature: Uint8Array | WebAuthnSignature;
}

/** Mirrors Rust `AuditedUtxosRequest`, one to `RING_AUDITED_UTXOS_LIMIT` hashes. */
export class RingAuditedUtxosRequest {
  readonly #target: RingReadTarget;
  readonly #utxoHashes: readonly Bytes32[];
  #wallet?: Address;
  #timestamp?: bigint;

  private constructor(target: RingReadTarget, utxoHashes: readonly Bytes32[]) {
    this.#target = checkedReadTarget(target);
    this.#utxoHashes = utxoHashes;
  }

  static read(target: RingReadTarget, utxoHashes: readonly Bytes32[]): RingAuditedUtxosRequest {
    return new RingAuditedUtxosRequest(target, checkedUtxoHashes(utxoHashes));
  }

  withWallet(wallet: Address): this {
    addressBytes(wallet, "wallet");
    this.#wallet = wallet;
    return this;
  }

  /** Unix seconds, the RPC rejects a clock more than its skew away. */
  at(timestamp: bigint): this {
    this.#timestamp = checkedUnixTimestamp(timestamp, "timestamp");
    return this;
  }

  async sign(signer: RingReadSigner): Promise<SignedAuditedUtxosRead> {
    const timestamp = timestampOrNow(this.#timestamp);
    const nonce = freshNonce();
    const signature = await signer.sign(
      auditedUtxosAttestation({
        target: this.#target,
        timestamp,
        nonce,
        utxoHashes: this.#utxoHashes,
        ...(this.#wallet === undefined ? {} : { wallet: this.#wallet }),
      }),
    );
    return Object.freeze({
      ringProgramId: this.#target.ringProgramId,
      utxoHashes: this.#utxoHashes,
      ...(this.#wallet === undefined ? {} : { wallet: this.#wallet }),
      reader: signer.reader,
      timestamp,
      nonce,
      signature,
    });
  }
}

/** Mirrors Rust `CreateAuditorKeyRequest` after `AuditorKeyRequest::sign`. */
export interface SignedAuditorKeyRequest {
  readonly ringProgramId: Address;
  readonly authority: Address;
  readonly genesisHash: Bytes32;
  readonly timestamp: bigint;
  readonly nonce: Bytes32;
  readonly signature: Bytes64;
}

/** Mirrors Rust `AuditorKeyRequest`. */
export class RingAuditorKeyRequest {
  readonly #ringProgramId: Address;
  readonly #genesisHash: Bytes32;
  #timestamp?: bigint;

  private constructor(ringProgramId: Address, genesisHash: Bytes32) {
    this.#ringProgramId = ringProgramId;
    this.#genesisHash = genesisHash;
  }

  static forRing(ringProgramId: Address, genesisHash: Bytes32): RingAuditorKeyRequest {
    return new RingAuditorKeyRequest(
      ringProgramId,
      copyBytes(genesisHash, 32, "genesisHash") as Bytes32,
    );
  }

  /** Unix seconds, the RPC rejects a clock more than its skew away. */
  at(timestamp: bigint): this {
    this.#timestamp = checkedUnixTimestamp(timestamp, "timestamp");
    return this;
  }

  async sign(authority: MessagePartialSigner): Promise<SignedAuditorKeyRequest> {
    const timestamp = timestampOrNow(this.#timestamp);
    const nonce = freshNonce();
    const signature = await signMessage(
      authority,
      auditorKeyRequestAttestation({
        genesisHash: this.#genesisHash,
        ringProgramId: this.#ringProgramId,
        timestamp,
        nonce,
      }),
    );
    return Object.freeze({
      ringProgramId: this.#ringProgramId,
      authority: authority.address,
      genesisHash: this.#genesisHash,
      timestamp,
      nonce,
      signature,
    });
  }
}

export type RingKeyMode = "local" | "derived";

export interface RingRpcHealth {
  readonly mode: RingKeyMode;
  readonly servicePublicKey: Address;
}

/** Mirrors Rust `CreateAuditorKeyResponse`, the signature covers `auditorKeyAttestation`. */
export interface RingAuditorKey {
  readonly ringProgramId: Address;
  readonly auditorPublicKey: X25519PublicKey;
  readonly auditorViewTag: Bytes32;
  readonly servicePublicKey: Address;
  readonly signature: Uint8Array;
}

/** Value entering a ring, which carries no auditor message. */
export interface RingDeposit {
  readonly signature: Signature;
  readonly slot: bigint;
  /** The owner tag of the UTXO the deposit created. */
  readonly depositor: Address;
  readonly asset: Address;
  readonly amount: bigint;
}

/** One page of ring deposits. The cursor is opaque, pass it back to reach older history. */
export interface RingDepositsPage {
  readonly deposits: readonly RingDeposit[];
  readonly cursor?: Uint8Array;
  /** The oldest slot this page examined, so a caller can merge the stream with an audit read by slot. */
  readonly oldestSlot?: bigint;
}

/** Mirrors Rust `RingState`. */
export type RingState = "served" | "foreignAuditor" | "uninitialized";

/** Mirrors Rust `RingActivation`, SPP's gate on every operational ring instruction. */
export interface RingActivation {
  readonly activated: boolean;
  readonly paused: boolean;
}

/** Mirrors Rust `RingStatusResponse`, unsigned and only what the chain publishes. */
export interface RingStatus {
  readonly ringProgramId: Address;
  readonly state: RingState;
  /** The key the ring account names, absent before `Initialize`. */
  readonly configAuditorPublicKey?: X25519PublicKey;
  readonly servicePublicKey: Address;
  /** Absent until SPP holds a config for the ring. */
  readonly activation?: RingActivation;
}

/** Mirrors Rust `DecryptedOutputContext`, the tree is the canonical PDA of `treeId`. */
export interface DecryptedOutputContext {
  readonly treeId: number;
  readonly leafIndex: bigint;
  readonly hash: Bytes32;
}

/** Mirrors Rust `DecryptedOutput`, a slot whose rebuilt opening reaches its published commitment. */
export interface DecryptedRingOutput {
  readonly slotIndex: number;
  readonly outputContext: DecryptedOutputContext;
  readonly opening: OutputOpening;
}

/** A public settlement leg. Value left the ring to a plain account. */
export interface DecryptedRingWithdrawal {
  readonly screenedOwner?: Address;
  /** A token account for an SPL leg, a wallet for a SOL leg. */
  readonly recipient: Address;
  /** The mint of an SPL leg or the native SOL mint. */
  readonly asset: Address;
  readonly amount: bigint;
}

export interface DecryptedRingDefaultInput {
  readonly utxo: AuditedUtxo;
  /** Absent without the input's tree id. */
  readonly commitment?: Bytes32;
}

/** Nullifier index names the spent note. */
export interface DecryptedRingInput {
  readonly nullifier: Bytes32;
  /** Rust `DecryptedInputClass`, an address spends no note. */
  readonly class: InputClass;
  readonly defaultInput?: DecryptedRingDefaultInput;
}

/** Mirrors Rust `DecryptedTransaction`. */
export interface DecryptedRingTransaction {
  readonly slot: bigint;
  readonly signature: Signature;
  /** Ordinal of the confirmed SPP event within this Solana transaction. */
  readonly eventIndex: number;
  readonly txViewingPublicKey: X25519PublicKey;
  /** Published order, every slot sits here or in `payloadErrors` exactly once. */
  readonly outputs: readonly DecryptedRingOutput[];
  readonly payloadErrors: readonly OutputPayloadError[];
  /** `R`, spent notes among the published inputs. */
  readonly realInputs: number;
  /** One per published nullifier, empty when the service omits them. */
  readonly inputs: readonly DecryptedRingInput[];
  readonly nullifiers: readonly Bytes32[];
  /** The input owners of a confidential transfer, by owner signature or in proof. */
  readonly spenders: readonly Address[];
  /** Required signers, fee payer first. */
  readonly signers: readonly Address[];
  /** Empty when nothing left the ring. */
  readonly withdrawals: readonly DecryptedRingWithdrawal[];
}

export type {
  AuditedInput,
  AuditedInputOpening,
  AuditedSender,
  AuditedUtxo,
  InputOpening,
  InputRing,
  KnownUtxo,
  OutputOpening,
  OutputPayloadError,
  OutputPayloadErrorKind,
} from "../operations/audit/audit.js";

/** Mirrors Rust `SkippedReason`. */
export type SkippedReason = "missingAuditorMessage" | "invalidAuditData";

const SKIPPED_REASONS: readonly SkippedReason[] = Object.freeze([
  "missingAuditorMessage",
  "invalidAuditData",
]);

export interface SkippedRingTransaction {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly reason: SkippedReason;
}

export interface DecryptedRingTransactionsPage {
  readonly slot: bigint;
  readonly blockTime: bigint;
  readonly items: readonly DecryptedRingTransaction[];
  readonly skipped: readonly SkippedRingTransaction[];
  readonly cursor?: Uint8Array;
}

/** Mirrors Rust `WalletView`, the sender is the anonymous sender or a confidential spender. */
export type RingWalletView =
  | {
      readonly role: "sender";
      readonly inputs: readonly DecryptedRingInput[];
      readonly outputs: readonly DecryptedRingOutput[];
      readonly withdrawals: readonly DecryptedRingWithdrawal[];
    }
  | {
      readonly role: "recipient";
      readonly outputs: readonly DecryptedRingOutput[];
      readonly withdrawals: readonly DecryptedRingWithdrawal[];
    };

/** `spent` takes precedence over `exposedIfSpent`, `unknown` never counts as unspent. */
export type RingWalletNoteStatus = "spent" | "unspent" | "unknown" | "exposedIfSpent";

/** Mirrors Rust `WalletNote`, a full opening rebuilds a note whose body was unusable. */
export interface RingWalletNote {
  readonly utxoHash: Bytes32;
  readonly status: RingWalletNoteStatus;
  /** Absent on a deposit whose capsule discloses the owner hash alone. */
  readonly nullifierPk?: Bytes32;
  readonly asset: Bytes32;
  readonly mint?: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
  readonly treeId: number;
  readonly leafIndex: bigint;
  readonly slot: bigint;
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly slotIndex: number;
}

export interface RingWalletBalance {
  readonly asset: Bytes32;
  readonly mint?: Address;
  readonly amount: bigint;
}

export type RingWalletEnrollment = "notEnrolled" | "pending" | "pendingPastCapacity" | "applied";

export interface RingWalletStatusQuery {
  readonly target: RingReadTarget;
  readonly signer: RingReadSigner;
  readonly wallet: Address;
  readonly cursor?: Uint8Array;
  readonly timestamp?: bigint;
}

export interface RingDelegateNotesQuery {
  readonly target: RingReadTarget;
  readonly delegate: MessagePartialSigner;
  readonly owner: Address;
  readonly cursor?: Uint8Array;
  readonly timestamp?: bigint;
}

export interface RingDelegateNotesPage {
  readonly nullifierSecret?: Bytes32;
  readonly status: RingWalletStatusPage;
}

/** Mirrors Rust `GetWalletStatusResponse`, it names nothing about any other transaction. */
export interface RingWalletStatusPage {
  readonly enrollment: RingWalletEnrollment;
  readonly snapshotExpiresAt?: bigint;
  /** Only an unreadable stream holds it back. */
  readonly historyThrough: bigint;
  /** `unspent` notes alone, over every page. */
  readonly balances: readonly RingWalletBalance[];
  readonly notes: readonly RingWalletNote[];
  readonly cursor?: Uint8Array;
}

export interface RingSpendCoverageFrame {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly eventIndex: number;
}

export interface RingSpendCoverageRow {
  readonly nullifier: Bytes32;
  readonly frame: RingSpendCoverageFrame;
}

/** Mirrors Rust `GetSpendCoverageResponse`, the one surface that names an unresolved spend. */
export interface RingSpendCoverage {
  /** Absent inside a paged read. */
  readonly positionSlot?: bigint;
  readonly historyThrough: bigint;
  readonly totals?: RingSpendCoverageTotals;
  readonly unresolvedReal: readonly RingSpendCoverageRow[];
  readonly unreadable: readonly RingSpendCoverageFrame[];
  readonly integrityFaults: readonly RingSpendCoverageRow[];
  readonly cursor?: Uint8Array;
}

export interface RingSpendCoverageTotals {
  readonly observed: bigint;
  readonly padding: bigint;
  readonly address: bigint;
  readonly external: bigint;
  readonly resolved: bigint;
}

/** Mirrors Rust `WalletActivity`. */
export interface RingWalletActivity {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly view: RingWalletView;
}

export interface RingWalletActivityPage {
  readonly slot: bigint;
  readonly blockTime: bigint;
  readonly items: readonly RingWalletActivity[];
  readonly cursor?: Uint8Array;
}

/** Mirrors Rust `AuditedMergeRecord`, an audit record of inherited fields and no wallet opening. */
export interface AuditedRingMerge {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly outputCommitment: Bytes32;
  readonly ownerKey: Bytes32;
  readonly asset: Bytes32;
  readonly mint: Address;
  readonly amount: bigint;
  readonly realNullifiers: readonly Bytes32[];
}

/** Mirrors Rust `GetAuditedMergesResponse`. */
export interface AuditedMergesPage {
  readonly slot: bigint;
  readonly blockTime: bigint;
  readonly opened: readonly AuditedRingMerge[];
  readonly cursor?: Uint8Array;
}

/** Mirrors Rust `AuditedUtxoView`, a UTXO the auditor opened and the slot that created it. */
export interface RingAuditedUtxo {
  readonly utxoHash: Bytes32;
  readonly utxo: KnownUtxo;
  readonly slot: bigint;
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly slotIndex: number;
}

export interface RingAuditedUtxosPage {
  readonly slot: bigint;
  readonly blockTime: bigint;
  /** In request order, `undefined` for a UTXO the service has not opened. */
  readonly utxos: readonly (RingAuditedUtxo | undefined)[];
}

export interface RingRpcOptions {
  readonly fetch?: typeof globalThis.fetch;
  /** Even loopback needs it for plain HTTP. */
  readonly allowInsecureHttp?: boolean;
  /** Gateway API key. Supply it here or in the URL's `api-key` query parameter, never both. */
  readonly apiKey?: string;
}

/**
 * Ring RPC over HTTPS. Pass a service base URL, such as `https://host/v1/zolana/ring`;
 * each call appends its method name. API keys are omitted from {@link RingRpc.url}.
 * Signed reader and authority requests still require their own authorization.
 */
export class RingRpc {
  readonly #url: URL;
  readonly #apiKey?: string;
  readonly #fetch: typeof globalThis.fetch;

  constructor(url: string | URL, options?: RingRpcOptions) {
    try {
      const keyed = checkedApiKey(
        checkedEndpoint(url, {
          field: "url",
          ...(options?.allowInsecureHttp === undefined
            ? {}
            : { allowInsecureHttp: options.allowInsecureHttp }),
        }),
        options?.apiKey,
      );
      this.#url = keyed.endpoint;
      if (keyed.apiKey !== undefined) this.#apiKey = keyed.apiKey;
      this.#fetch = checkedFetch(options?.fetch);
    } catch (error) {
      if (!(error instanceof TransportFailure)) throw error;
      throw new RingError("RING_RPC_CONFIG", { details: { ...error.facts } });
    }
  }

  get url(): string {
    return this.#url.href;
  }

  async health(context?: RequestContext): Promise<RingRpcHealth> {
    const wire = record(await this.#call("health", undefined, context), "result");
    const mode = wire["mode"];
    if (mode !== "local" && mode !== "derived") throw invalid("result.mode");
    return Object.freeze({
      mode,
      servicePublicKey: address(wire["servicePubkey"], "result.servicePubkey"),
    });
  }

  /** Verified under the pinned `servicePublicKey` before the key is returned. */
  async createAuditorKey(
    input: Readonly<{
      ringProgramId: Address;
      genesisHash: Bytes32;
      /** The upgrade authority, or the policy authority after `Initialize`. */
      authority: MessagePartialSigner;
      /** Confirmed out of band, never read from the service. */
      servicePublicKey: Address;
      timestamp?: bigint;
    }>,
    context?: RequestContext,
  ): Promise<RingAuditorKey> {
    let request = RingAuditorKeyRequest.forRing(input.ringProgramId, input.genesisHash);
    if (input.timestamp !== undefined) request = request.at(input.timestamp);
    return this.createAuditorKeySigned(
      await request.sign(input.authority),
      input.servicePublicKey,
      context,
    );
  }

  /** Refused unless the pinned `servicePublicKey` signed the answer. */
  async createAuditorKeySigned(
    request: SignedAuditorKeyRequest,
    servicePublicKey: Address,
    context?: RequestContext,
  ): Promise<RingAuditorKey> {
    const checked = checkedSignedAuditorKeyRequest(request);
    const pinned = requestAddress(servicePublicKey, "servicePublicKey");
    const wire = record(
      await this.#call(
        "createAuditorKey",
        {
          ringProgramId: checked.ringProgramId,
          auth: {
            authority: checked.authority,
            genesisHash: base58Decoder.decode(checked.genesisHash),
            ...authWire(checked),
          },
        },
        context,
      ),
      "result",
    );
    const key = base64(wire["auditorPubkey"], "result.auditorPubkey");
    if (key.length !== 33) throw invalid("result.auditorPubkey");
    const auditorPublicKey = X25519PublicKey.fromBytes(key as Bytes33);
    if (address(wire["servicePubkey"], "result.servicePubkey") !== pinned) {
      throw new RingError("RING_RPC", {
        details: {
          method: "createAuditorKey",
          reason: "service key is not the pinned key",
        },
      });
    }
    const signature = base58(wire["signature"], "result.signature");
    const ring = address(wire["ringProgramId"], "result.ringProgramId");
    if (ring !== checked.ringProgramId) throw invalid("result.ringProgramId");
    const attested = ed25519.verify(
      signature,
      auditorKeyStatement({
        cluster: checked.genesisHash,
        ringProgramId: ring,
        auditorPublicKey,
        nonce: checked.nonce,
      }),
      addressBytes(pinned, "servicePublicKey"),
    );
    if (!attested) {
      throw new RingError("RING_RPC", {
        details: {
          method: "createAuditorKey",
          reason: "attestation signature is invalid",
        },
      });
    }
    return Object.freeze({
      ringProgramId: ring,
      auditorPublicKey,
      auditorViewTag: hash(wire["auditorViewTag"], "result.auditorViewTag"),
      servicePublicKey: pinned,
      signature,
    });
  }

  /**
   * Deposits publish their asset and amount, so this read is unsigned.
   * `limit` counts signatures examined, so an empty page can still carry a cursor over older history.
   */
  async ringDeposits(
    input: Readonly<{
      ringProgramId: Address;
      limit?: number;
      cursor?: Uint8Array;
    }>,
    context?: RequestContext,
  ): Promise<RingDepositsPage> {
    const wire = record(
      await this.#call(
        "ringDeposits",
        {
          ringProgramId: input.ringProgramId,
          ...(input.limit === undefined ? {} : { limit: input.limit }),
          ...(input.cursor === undefined ? {} : { cursor: base64Decoder.decode(input.cursor) }),
        },
        context,
      ),
      "result",
    );
    const cursor = wire["cursor"];
    const oldestSlot = wire["oldestSlot"];
    return Object.freeze({
      deposits: Object.freeze(
        list(wire["deposits"], "result.deposits").map((entry) => {
          const deposit = record(entry, "result.deposits");
          return Object.freeze({
            signature: signature(deposit["signature"], "deposits.signature"),
            slot: integer(deposit["slot"], "deposits.slot"),
            depositor: address(deposit["depositor"], "deposits.depositor"),
            asset: address(deposit["asset"], "deposits.asset"),
            amount: integer(deposit["amount"], "deposits.amount"),
          });
        }),
      ),
      ...(cursor === undefined || cursor === null
        ? {}
        : { cursor: base64(cursor, "result.cursor") }),
      ...(oldestSlot === undefined || oldestSlot === null
        ? {}
        : { oldestSlot: integer(oldestSlot, "result.oldestSlot") }),
    });
  }

  /** Whether this service can open the ring, before a read is attempted. */
  async ringStatus(ringProgramId: Address, context?: RequestContext): Promise<RingStatus> {
    const wire = record(await this.#call("ringStatus", { ringProgramId }, context), "result");
    const state = string(wire["state"], "result.state");
    if (state !== "served" && state !== "foreignAuditor" && state !== "uninitialized") {
      throw invalid("result.state");
    }
    const ring = address(wire["ringProgramId"], "result.ringProgramId");
    if (ring !== ringProgramId) throw invalid("result.ringProgramId");
    const config = wire["configAuditorPubkey"];
    const activation = wire["activation"];
    return Object.freeze({
      ringProgramId: ring,
      state,
      ...(absent(config)
        ? {}
        : {
            configAuditorPublicKey: x25519Key(config, "result.configAuditorPubkey"),
          }),
      servicePublicKey: address(wire["servicePubkey"], "result.servicePubkey"),
      ...(absent(activation) ? {} : { activation: decodeActivation(activation) }),
    });
  }

  /** Refused before sending unless the signature verifies, the service must answer the same id. */
  async submitRecordUpdate(
    request: SubmitRecordUpdateRequest,
    context?: RequestContext,
  ): Promise<Hash> {
    const id = indexerScalars.hash(verifyRecordUpdate(request));
    const wire = await this.#call(
      RingRpcMethod.submitRecordUpdate,
      encodeSubmitRecordUpdateRequest(request),
      context,
    );
    if (decodeSubmitRecordUpdate(wire) !== id) throw invalid("result.updateId");
    return id;
  }

  async getRecordUpdateStatus(
    updateId: Hash,
    context?: RequestContext,
  ): Promise<RecordUpdateStatus> {
    return decodeRecordUpdateStatus(
      await this.#call(
        RingRpcMethod.getRecordUpdateStatus,
        encodeRecordUpdateStatusRequest(updateId),
        context,
      ),
    );
  }

  /** One page of the ring's updates pending list approval, oldest first. */
  async getPendingListApprovals(
    request: GetPendingListApprovalsRequest,
    context?: RequestContext,
  ): Promise<PendingListApprovalsPage> {
    return decodePendingListApprovalsPage(
      await this.#call(
        RingRpcMethod.getPendingListApprovals,
        encodeGetPendingListApprovalsRequest(request),
        context,
      ),
    );
  }

  async refuseListApproval(
    request: RefuseListApprovalRequest,
    context?: RequestContext,
  ): Promise<RecordUpdateStatus> {
    return decodeRecordUpdateStatus(
      await this.#call(
        RingRpcMethod.refuseListApproval,
        encodeRefuseListApprovalRequest(request),
        context,
      ),
    );
  }

  /** Idempotent, the ring's records under the service's storage authority. */
  async createRecordsRegistry(
    request: CreateRecordsRegistryRequest,
    context?: RequestContext,
  ): Promise<RecordsRegistry> {
    const records = decodeRecordsRegistry(
      await this.#call(
        RingRpcMethod.createRecordsRegistry,
        encodeCreateRecordsRegistryRequest(request),
        context,
      ),
    );
    if (records.registry !== (await ringRecordsAddress(request.ring, records.storageAuthority))) {
      throw new RingError("RING_RPC", {
        details: {
          method: RingRpcMethod.createRecordsRegistry,
          reason: "registry is not the ring records under storageAuthority",
        },
      });
    }
    return records;
  }

  /** Each page is signed again, the attestation binds the nonce, the cursor and the time. */
  async getDecryptedTransactions(
    input: Readonly<{
      target: RingReadTarget;
      signer: RingReadSigner;
      cursor?: Uint8Array;
      limit?: bigint;
      timestamp?: bigint;
    }>,
    context?: RequestContext,
  ): Promise<DecryptedRingTransactionsPage> {
    let request = RingReadRequest.decryptedTransactions(input.target);
    if (input.cursor !== undefined) request = request.withCursor(input.cursor);
    if (input.limit !== undefined) request = request.withLimit(input.limit);
    if (input.timestamp !== undefined) request = request.at(input.timestamp);
    return this.readSigned(await request.sign(input.signer), context);
  }

  /** The wallet's own part of each transaction it spends in or receives an output in. */
  async getWalletActivity(
    input: Readonly<{
      target: RingReadTarget;
      signer: RingReadSigner;
      wallet: Address;
      cursor?: Uint8Array;
      limit?: bigint;
      timestamp?: bigint;
    }>,
    context?: RequestContext,
  ): Promise<RingWalletActivityPage> {
    let request = RingReadRequest.walletActivity(input.target, input.wallet);
    if (input.cursor !== undefined) request = request.withCursor(input.cursor);
    if (input.limit !== undefined) request = request.withLimit(input.limit);
    if (input.timestamp !== undefined) request = request.at(input.timestamp);
    return this.readSignedWalletActivity(await request.sign(input.signer), context);
  }

  /** The wallet's notes and balance as of the slot the operator verified. */
  async getWalletStatus(
    input: RingWalletStatusQuery,
    context?: RequestContext,
  ): Promise<RingWalletStatusPage> {
    const wire = await this.#walletSnapshotCall({ input, method: "getWalletStatus", context });
    return decodeWalletStatus(record(wire, "result"));
  }

  async releaseWalletSnapshot(
    input: RingWalletStatusQuery & Readonly<{ cursor: Uint8Array }>,
    context?: RequestContext,
  ): Promise<void> {
    const released = await this.#walletSnapshotCall({
      input,
      method: "releaseWalletSnapshot",
      context,
    });
    if (released !== true) throw invalid("result");
  }

  walletStatusPages(
    input: Omit<RingWalletStatusQuery, "cursor" | "timestamp">,
    context?: RequestContext,
  ): AsyncGenerator<RingWalletStatusPage, void> {
    return snapshotPages({
      read: (cursor) =>
        this.getWalletStatus({ ...input, ...(cursor === undefined ? {} : { cursor }) }, context),
      status: (page) => page,
      release: (cursor, cleanup) => this.releaseWalletSnapshot({ ...input, cursor }, cleanup),
      ...(context === undefined ? {} : { context }),
    });
  }

  async getDelegateNotes(
    input: RingDelegateNotesQuery,
    context?: RequestContext,
  ): Promise<RingDelegateNotesPage> {
    const wire = record(
      await this.#delegateSnapshotCall({ input, method: "getDelegateNotes", context }),
      "result",
    );
    return Object.freeze({
      ...(wire["nullifierSecret"] == null
        ? {}
        : { nullifierSecret: hash(wire["nullifierSecret"], "nullifierSecret") }),
      status: decodeWalletStatus(record(wire["status"], "status")),
    });
  }

  async releaseDelegateSnapshot(
    input: RingDelegateNotesQuery & Readonly<{ cursor: Uint8Array }>,
    context?: RequestContext,
  ): Promise<void> {
    const released = await this.#delegateSnapshotCall({
      input,
      method: "releaseDelegateSnapshot",
      context,
    });
    if (released !== true) throw invalid("result");
  }

  delegateNotesPages(
    input: Omit<RingDelegateNotesQuery, "cursor" | "timestamp">,
    context?: RequestContext,
  ): AsyncGenerator<RingDelegateNotesPage, void> {
    return snapshotPages({
      read: (cursor) =>
        this.getDelegateNotes({ ...input, ...(cursor === undefined ? {} : { cursor }) }, context),
      status: (page) => page.status,
      release: (cursor, cleanup) => this.releaseDelegateSnapshot({ ...input, cursor }, cleanup),
      ...(context === undefined ? {} : { context }),
    });
  }

  /** The ring authority's read of unresolved spends, no wallet read carries them. */
  async getSpendCoverage(
    input: Readonly<{
      target: RingReadTarget;
      authority: MessagePartialSigner;
      timestamp?: bigint;
      cursor?: Uint8Array;
    }>,
    context?: RequestContext,
  ): Promise<RingSpendCoverage> {
    const target = checkedReadTarget(input.target);
    const timestamp = timestampOrNow(input.timestamp);
    const nonce = freshNonce();
    const cursor = input.cursor === undefined ? undefined : checkedReadCursor(input.cursor);
    const signed = await signMessage(
      input.authority,
      spendCoverageAttestation({
        target,
        authority: input.authority.address,
        timestamp,
        nonce,
        ...(cursor === undefined ? {} : { cursor }),
      }),
    );
    const wire = record(
      await this.#call(
        "getSpendCoverage",
        {
          ring: target.ringProgramId,
          authority: input.authority.address,
          timestamp: Number(timestamp),
          nonce: base64Decoder.decode(nonce),
          ...(cursor === undefined ? {} : { cursor: base64Decoder.decode(cursor) }),
          signature: base58Decoder.decode(signed),
        },
        context,
      ),
      "result",
    );
    return decodeSpendCoverage(wire);
  }

  /** The UTXOs the service opened, signed over the requested hashes. */
  async getAuditedUtxos(
    input: Readonly<{
      target: RingReadTarget;
      utxoHashes: readonly Bytes32[];
      signer: RingReadSigner;
      wallet?: Address;
      timestamp?: bigint;
    }>,
    context?: RequestContext,
  ): Promise<RingAuditedUtxosPage> {
    let request = RingAuditedUtxosRequest.read(input.target, input.utxoHashes);
    if (input.wallet !== undefined) request = request.withWallet(input.wallet);
    if (input.timestamp !== undefined) request = request.at(input.timestamp);
    return this.readSignedUtxos(await request.sign(input.signer), context);
  }

  /** Rust `GetAuditedUtxosResponse::known_utxos`, an answer is used only where it rebuilds its requested hash. */
  async readSignedUtxos(
    read: SignedAuditedUtxosRead,
    context?: RequestContext,
  ): Promise<RingAuditedUtxosPage> {
    await initializePoseidon();
    const { utxoHashes, ...auth } = exactRequestRecord(
      read,
      SIGNED_UTXOS_FIELDS,
      SIGNED_UTXOS_REQUIRED_FIELDS,
      "request",
    );
    const hashes = checkedUtxoHashes(utxoHashes);
    const checked = checkedReadAuth(auth);
    const wire = record(
      await this.#call(
        "getAuditedUtxos",
        {
          ...signedReadParams(checked),
          utxoHashes: hashes.map((utxoHash) => base58Decoder.decode(utxoHash)),
        },
        context,
      ),
      "result",
    );
    const wireContext = record(wire["context"], "result.context");
    const utxos = list(record(wire["value"], "result.value")["utxos"], "result.value.utxos");
    if (utxos.length !== hashes.length) throw invalid("result.value.utxos");
    const ringId = ringIdField(checked.ringProgramId);
    return Object.freeze({
      slot: integer(wireContext["slot"], "result.context.slot"),
      blockTime: signedInteger(wireContext["blockTime"], "result.context.blockTime"),
      utxos: Object.freeze(
        utxos.map((entry, index) => {
          if (entry === null) return undefined;
          const path = `result.value.utxos[${index}]`;
          const item = record(entry, path);
          const utxoHash = hash(item["utxoHash"], `${path}.utxoHash`);
          const utxo = decodeKnownUtxo(record(item["utxo"], `${path}.utxo`), `${path}.utxo`);
          // The ring's UTXO or a default-ring one the ring spent, any other opening is not this hash's.
          if (
            !equalBytes(utxoHash, hashes[index] ?? new Uint8Array()) ||
            ![ringId, ZERO_32].some((ring) => equalBytes(knownUtxoHash(utxo, ring), utxoHash))
          )
            throw invalid(`${path}.utxo`);
          return Object.freeze({
            utxoHash,
            utxo,
            slot: u64(item["slot"], `${path}.slot`),
            signature: signature(item["txSignature"], `${path}.txSignature`),
            eventIndex: u16(item["eventIndex"], `${path}.eventIndex`),
            slotIndex: u32(item["slotIndex"], `${path}.slotIndex`),
          });
        }),
      ),
    });
  }

  /** Merge records require finalized execution. */
  async getAuditedMerges(
    input: Readonly<{
      target: RingReadTarget;
      signer: RingReadSigner;
      cursor?: Uint8Array;
      limit?: bigint;
      wallet?: Address;
      timestamp?: bigint;
    }>,
    context?: RequestContext,
  ): Promise<AuditedMergesPage> {
    let request = RingReadRequest.auditedMerges(input.target);
    if (input.cursor !== undefined) request = request.withCursor(input.cursor);
    if (input.limit !== undefined) request = request.withLimit(input.limit);
    if (input.wallet !== undefined) request = request.withWallet(input.wallet);
    if (input.timestamp !== undefined) request = request.at(input.timestamp);
    return this.readSignedMerges(await request.sign(input.signer), context);
  }

  async readSignedMerges(
    read: SignedRingRead,
    context?: RequestContext,
  ): Promise<AuditedMergesPage> {
    const checked = checkedSignedRead(read, "getAuditedMerges");
    const wire = record(
      await this.#call("getAuditedMerges", signedReadParams(checked), context),
      "result",
    );
    const wireContext = record(wire["context"], "result.context");
    const value = exactRecord(
      wire["value"],
      AUDITED_MERGES_PAGE_FIELDS,
      AUDITED_MERGES_PAGE_FIELDS,
      "result.value",
    );
    const cursor = readResponseCursor(value["cursor"], checked);
    const opened = list(value["opened"], "result.value.opened");
    if (opened.length > Number(checked.limit ?? RING_READ_PAGE_LIMIT))
      throw invalid("result.value");
    return Object.freeze({
      slot: integer(wireContext["slot"], "result.context.slot"),
      blockTime: signedInteger(wireContext["blockTime"], "result.context.blockTime"),
      opened: Object.freeze(
        opened.map((entry, index) => decodeAuditedMerge(entry, `result.value.opened[${index}]`)),
      ),
      ...(cursor === undefined ? {} : { cursor }),
    });
  }

  async readSigned(
    read: SignedRingRead,
    context?: RequestContext,
  ): Promise<DecryptedRingTransactionsPage> {
    const checked = checkedSignedRead(read, "getDecryptedTransactions");
    const wire = record(
      await this.#call("getDecryptedTransactions", signedReadParams(checked), context),
      "result",
    );
    const wireContext = record(wire["context"], "result.context");
    const value = record(wire["value"], "result.value");
    const cursor = readResponseCursor(value["cursor"], checked);
    const items = list(value["items"], "result.value.items");
    const skipped = list(value["skipped"], "result.value.skipped");
    if (items.length + skipped.length > Number(checked.limit ?? RING_READ_PAGE_LIMIT))
      throw invalid("result.value");
    return Object.freeze({
      slot: integer(wireContext["slot"], "result.context.slot"),
      blockTime: signedInteger(wireContext["blockTime"], "result.context.blockTime"),
      items: Object.freeze(
        items.map((item, index) => decodeTransaction(record(item, `result.value.items[${index}]`))),
      ),
      skipped: Object.freeze(
        skipped.map((entry, index) =>
          decodeSkipped(record(entry, `result.value.skipped[${index}]`)),
        ),
      ),
      ...(cursor === undefined ? {} : { cursor }),
    });
  }

  async readSignedWalletActivity(
    read: SignedRingRead,
    context?: RequestContext,
  ): Promise<RingWalletActivityPage> {
    const checked = checkedSignedRead(read, "getWalletActivity");
    const wire = record(
      await this.#call("getWalletActivity", signedReadParams(checked), context),
      "result",
    );
    const wireContext = record(wire["context"], "result.context");
    const value = record(wire["value"], "result.value");
    const cursor = readResponseCursor(value["cursor"], checked);
    const items = list(value["items"], "result.value.items");
    if (items.length > Number(checked.limit ?? RING_READ_PAGE_LIMIT)) throw invalid("result.value");
    return Object.freeze({
      slot: integer(wireContext["slot"], "result.context.slot"),
      blockTime: signedInteger(wireContext["blockTime"], "result.context.blockTime"),
      items: Object.freeze(
        items.map((item, index) =>
          decodeWalletActivity(record(item, `result.value.items[${index}]`)),
        ),
      ),
      ...(cursor === undefined ? {} : { cursor }),
    });
  }

  async getRelayQuote(request: RelayQuoteRequest, context?: RequestContext): Promise<RelayQuote> {
    return decodeRelayQuote(
      await this.#call(RingRpcMethod.getRelayQuote, encodeRelayQuoteRequest(request), context),
    );
  }

  async prepareRelay(request: PrepareRelayRequest, context?: RequestContext): Promise<RelayStep> {
    return decodeRelayStep(
      await this.#call(RingRpcMethod.prepareRelay, encodePrepareRelayRequest(request), context),
    );
  }

  /** `undefined` while the owner has no tracking row. */
  async getListSalt(
    request: GetListSaltRequest,
    context?: RequestContext,
  ): Promise<Bytes32 | undefined> {
    const wire = exactRecord(
      await this.#call(RingRpcMethod.getListSalt, encodeGetListSaltRequest(request), context),
      LIST_SALT_FIELDS,
      NO_FIELDS,
      "result",
    );
    return absent(wire["listSalt"]) ? undefined : hash(wire["listSalt"], "result.listSalt");
  }

  async prepareAuthorityTransfer(
    request: PrepareAuthorityTransferRequest,
    context?: RequestContext,
  ): Promise<RelayStep> {
    return decodeRelayStep(
      await this.#call(
        RingRpcMethod.prepareAuthorityTransfer,
        encodePrepareAuthorityTransferRequest(request),
        context,
      ),
    );
  }

  async submitRelay(request: SubmitRelayRequest, context?: RequestContext): Promise<RelayStatus> {
    return decodeRelayStatus(
      await this.#call(RingRpcMethod.submitRelay, encodeSubmitRelayRequest(request), context),
    );
  }

  async getRelayStatus(
    relayId: RelayStep["relayId"],
    context?: RequestContext,
  ): Promise<RelayStatus> {
    return decodeRelayStatus(
      await this.#call(RingRpcMethod.getRelayStatus, encodeRelayStatusRequest(relayId), context),
    );
  }

  /** A request from `RingReaderGrantRequest.sign`, answered with the action the service now holds. */
  async setReaderGrant(
    request: SetReaderGrantRequest,
    context?: RequestContext,
  ): Promise<ReaderGrantAction> {
    return decodeReaderGrantAction(
      await this.#call(RingRpcMethod.setReaderGrant, encodeSetReaderGrantRequest(request), context),
    );
  }

  /** A request from `RingMergeSettingsRequest.sign`, answered with the settings the service stored. */
  async setMergeSettings(
    request: SetMergeSettingsRequest,
    context?: RequestContext,
  ): Promise<MergeSettings> {
    return decodeMergeSettings(
      await this.#call(
        RingRpcMethod.setMergeSettings,
        encodeSetMergeSettingsRequest(request),
        context,
      ),
    );
  }

  // `params` is the request object, not a positional list.
  async #walletSnapshotCall({
    input,
    method,
    context,
  }: Readonly<{
    input: RingWalletStatusQuery;
    method: "getWalletStatus" | "releaseWalletSnapshot";
    context: RequestContext | undefined;
  }>): Promise<unknown> {
    const target = checkedReadTarget(input.target);
    addressBytes(input.wallet, "wallet");
    const cursor = input.cursor === undefined ? undefined : checkedSnapshotCursor(input.cursor);
    const timestamp = timestampOrNow(input.timestamp);
    const nonce = freshNonce();
    const attestation = {
      target,
      wallet: input.wallet,
      timestamp,
      nonce,
      ...(cursor === undefined ? {} : { cursor }),
    };
    let message: Uint8Array;
    if (method === "getWalletStatus") {
      message = walletStatusAttestation(attestation);
    } else {
      if (cursor === undefined) throw invalidRequest("cursor");
      message = walletSnapshotReleaseAttestation({ ...attestation, cursor });
    }
    const signature = await input.signer.sign(message);
    return this.#call(
      method,
      signedReadParams({
        ringProgramId: target.ringProgramId,
        wallet: input.wallet,
        reader: input.signer.reader,
        timestamp,
        nonce,
        signature,
        ...(cursor === undefined ? {} : { cursor }),
      }),
      context,
    );
  }

  async #delegateSnapshotCall({
    input,
    method,
    context,
  }: Readonly<{
    input: RingDelegateNotesQuery;
    method: "getDelegateNotes" | "releaseDelegateSnapshot";
    context: RequestContext | undefined;
  }>): Promise<unknown> {
    const target = checkedReadTarget(input.target);
    addressBytes(input.owner, "owner");
    const cursor = input.cursor === undefined ? undefined : checkedSnapshotCursor(input.cursor);
    const timestamp = timestampOrNow(input.timestamp);
    const nonce = freshNonce();
    const attestation = {
      target,
      delegate: input.delegate.address,
      owner: input.owner,
      timestamp,
      nonce,
      ...(cursor === undefined ? {} : { cursor }),
    };
    let message: Uint8Array;
    if (method === "getDelegateNotes") {
      message = delegateNotesAttestation(attestation);
    } else {
      if (cursor === undefined) throw invalidRequest("cursor");
      message = delegateSnapshotReleaseAttestation({ ...attestation, cursor });
    }
    const signature = await signMessage(input.delegate, message);
    return this.#call(
      method,
      {
        ring: target.ringProgramId,
        delegate: input.delegate.address,
        owner: input.owner,
        timestamp: Number(timestamp),
        nonce: base64Decoder.decode(nonce),
        signature: base58Decoder.decode(signature),
        ...(cursor === undefined ? {} : { cursor: base64Decoder.decode(cursor) }),
      },
      context,
    );
  }

  async #call(
    method: string,
    params: Readonly<Record<string, unknown>> | undefined,
    context: RequestContext | undefined,
  ): Promise<unknown> {
    try {
      return await postJsonRpc(
        {
          fetch: this.#fetch,
          url: serviceUrl(this.#url, method, this.#apiKey),
          rpcMethod: method,
          params,
          id: 1,
          maxRequestBytes: RING_RPC_MAX_REQUEST_BYTES,
          maxResponseBytes: RING_RPC_MAX_RESPONSE_BYTES,
        },
        { timeoutMs: RING_RPC_TIMEOUT_MS, ...context },
      );
    } catch (error) {
      if (!(error instanceof TransportFailure)) throw error;
      const refusal = error.kind === "rpc" ? ringRpcRefusalName(error.facts["rpcCode"]) : undefined;
      if (refusal !== undefined)
        throw new RingError("RING_RPC_REFUSED", {
          details: { method, refusal, ...error.facts },
        });
      const status = error.kind === "http" ? error.facts["status"] : undefined;
      // Ring RPC answers -32250 to -32253 with 429 and -32254 with 401.
      if (status === 429)
        throw new RingError("RING_RPC_RATE_LIMITED", {
          details: { method, ...error.facts },
        });
      if (status === 401)
        throw new RingError("RING_RPC_CONFIG", {
          details: { method, field: "apiKey", ...error.facts },
        });
      const code =
        error.kind === "envelope" || error.kind === "missingResult" || error.kind === "rpc"
          ? "RING_RPC"
          : error.kind === "context" || error.kind === "config"
            ? "RING_RPC_CONFIG"
            : "RING_RPC_TRANSPORT";
      throw new RingError(code, { details: { method, ...error.facts } });
    }
  }
}

/** Minted once per request. */
function freshNonce(): Bytes32 {
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  return nonce as Bytes32;
}

function timestampOrNow(timestamp: bigint | undefined): bigint {
  return timestamp ?? BigInt(Math.floor(Date.now() / 1000));
}

function authWire(
  auth: Readonly<{ timestamp: bigint; nonce: Bytes32; signature: Uint8Array }>,
): Readonly<{ timestamp: number; nonce: string; signature: string }> {
  return {
    timestamp: Number(auth.timestamp),
    nonce: base64Decoder.decode(auth.nonce),
    signature: base64Decoder.decode(auth.signature),
  };
}

function signedReadParams(
  checked: ReadAuth & Partial<Pick<SignedRingRead, "cursor" | "limit">>,
): Record<string, unknown> {
  const { signature } = checked;
  return {
    ringProgramId: checked.ringProgramId,
    ...(checked.cursor === undefined ? {} : { cursor: base64Decoder.decode(checked.cursor) }),
    ...(checked.limit === undefined ? {} : { limit: Number(checked.limit) }),
    ...(checked.wallet === undefined ? {} : { wallet: checked.wallet }),
    auth: {
      reader: base64Decoder.decode(checked.reader),
      ...authWire({
        timestamp: checked.timestamp,
        nonce: checked.nonce,
        signature: signature instanceof Uint8Array ? signature : signature.signature,
      }),
      ...(signature instanceof Uint8Array
        ? {}
        : {
            webauthn: {
              authenticatorData: base64Decoder.decode(signature.authenticatorData),
              clientDataJson: base64Decoder.decode(signature.clientDataJSON),
            },
          }),
    },
  };
}

/** A response cursor must be usable for the next signed page. */
function readResponseCursor(
  value: unknown,
  request: Readonly<{ cursor?: Uint8Array | undefined }>,
  path = "result.value.cursor",
): Uint8Array | undefined {
  if (value === null) return undefined;
  if (value === undefined) throw invalid(path);
  const cursor = base64(value, path);
  if (
    cursor.length === 0 ||
    cursor.length > RING_READ_CURSOR_LIMIT ||
    (request.cursor !== undefined && equalBytes(cursor, request.cursor))
  )
    throw invalid(path);
  return cursor;
}

/** One Ed25519 signature from a kit message signer over the raw bytes. */
export async function signMessage(
  signer: MessagePartialSigner,
  message: Uint8Array,
): Promise<Bytes64> {
  const [signatures] = await signer.signMessages([createSignableMessage(message)]);
  const signature = signatures?.[signer.address];
  if (signature === undefined) {
    throw new RingError("RING_RPC", {
      details: { reason: "signer returned no signature" },
    });
  }
  return copyBytes(signature, 64, "signature") as Bytes64;
}

/** Structure only, the openings stay as the service rebuilt them. */
function decodeTransaction(wire: Record<string, unknown>): DecryptedRingTransaction {
  const outputs = decodeOutputs(wire["outputs"]);
  const payloadErrors = decodePayloadErrors(wire["payloadErrors"]);
  checkSlotCoverage([
    ...outputs.map((output) => output.slotIndex),
    ...payloadErrors.map((error) => error.slotIndex),
  ]);
  const nullifiers = list(wire["nullifiers"], "nullifiers").map((nullifier, index) =>
    hash(nullifier, `nullifiers[${index}]`),
  );
  const inputs = absent(wire["inputs"])
    ? []
    : list(wire["inputs"], "inputs").map((entry, index) =>
        decodeInput(record(entry, `inputs[${index}]`), `inputs[${index}]`),
      );
  if (
    inputs.length !== 0 &&
    (inputs.length !== nullifiers.length ||
      inputs.some((input, index) => !equalBytes(input.nullifier, nullifiers[index]!)))
  )
    throw invalid("inputs");
  const realInputs = wire["realInputs"];
  if (typeof realInputs !== "number" || !Number.isInteger(realInputs) || realInputs < 0)
    throw invalid("realInputs");
  if (realInputs > nullifiers.length) throw invalid("realInputs");
  if (inputs.length !== 0 && !canonicalClasses(inputs, realInputs)) throw invalid("inputs");
  return Object.freeze({
    slot: integer(wire["slot"], "slot"),
    signature: signature(wire["txSignature"], "txSignature"),
    eventIndex: u16(wire["eventIndex"], "eventIndex"),
    txViewingPublicKey: x25519Key(wire["txViewingPk"], "txViewingPk"),
    outputs,
    payloadErrors,
    realInputs,
    inputs: Object.freeze(inputs),
    nullifiers: Object.freeze(nullifiers),
    spenders: Object.freeze(
      absent(wire["spenders"])
        ? []
        : list(wire["spenders"], "spenders").map((key, index) =>
            address(key, `spenders[${index}]`),
          ),
    ),
    signers: Object.freeze(
      list(wire["signers"], "signers").map((key, index) => address(key, `signers[${index}]`)),
    ),
    withdrawals: decodeWithdrawals(wire["withdrawals"]),
  });
}

function decodeWalletActivity(wire: Record<string, unknown>): RingWalletActivity {
  const view = record(wire["view"], "view");
  const outputs = decodeOutputs(view["outputs"], "view.outputs");
  const withdrawals = decodeWithdrawals(view["withdrawals"], "view.withdrawals");
  let decoded: RingWalletView;
  if (view["role"] === "sender") {
    decoded = Object.freeze({
      role: "sender",
      inputs: Object.freeze(
        list(view["inputs"], "view.inputs").map((entry, index) =>
          decodeInput(record(entry, `view.inputs[${index}]`), `view.inputs[${index}]`),
        ),
      ),
      outputs,
      withdrawals,
    });
  } else if (view["role"] === "recipient" && outputs.length > 0) {
    decoded = Object.freeze({ role: "recipient", outputs, withdrawals });
  } else {
    throw invalid("view.role");
  }
  return Object.freeze({
    slot: integer(wire["slot"], "slot"),
    signature: signature(wire["txSignature"], "txSignature"),
    eventIndex: u16(wire["eventIndex"], "eventIndex"),
    view: decoded,
  });
}

const WALLET_NOTE_STATUSES: readonly RingWalletNoteStatus[] = [
  "spent",
  "unspent",
  "unknown",
  "exposedIfSpent",
];

function decodeWalletStatus(wire: Record<string, unknown>): RingWalletStatusPage {
  const cursor = wire["cursor"];
  const enrollment = wire["enrollment"];
  if (
    enrollment !== "notEnrolled" &&
    enrollment !== "pending" &&
    enrollment !== "pendingPastCapacity" &&
    enrollment !== "applied"
  ) {
    throw invalid("enrollment");
  }
  return Object.freeze({
    enrollment,
    ...(wire["snapshotExpiresAt"] == null
      ? {}
      : { snapshotExpiresAt: integer(wire["snapshotExpiresAt"], "snapshotExpiresAt") }),
    historyThrough: integer(wire["historyThrough"], "historyThrough"),
    balances: Object.freeze(
      list(wire["balances"], "balances").map((entry, index) => {
        const path = `balances[${index}]`;
        const row = record(entry, path);
        return Object.freeze({
          asset: hash(row["asset"], `${path}.asset`),
          ...(row["mint"] == null ? {} : { mint: address(row["mint"], `${path}.mint`) }),
          amount: integer(row["amount"], `${path}.amount`),
        });
      }),
    ),
    notes: Object.freeze(
      list(wire["notes"], "notes").map((entry, index) =>
        decodeWalletNote(record(entry, `notes[${index}]`), `notes[${index}]`),
      ),
    ),
    ...(cursor == null ? {} : { cursor: checkedSnapshotCursor(base64(cursor, "cursor")) }),
  });
}

function decodeWalletNote(row: Record<string, unknown>, path: string): RingWalletNote {
  const status = WALLET_NOTE_STATUSES.find((known) => known === row["status"]);
  if (status === undefined) throw invalid(`${path}.status`);
  return Object.freeze({
    utxoHash: hash(row["utxoHash"], `${path}.utxoHash`),
    status,
    ...(row["nullifierPk"] == null
      ? {}
      : { nullifierPk: hash(row["nullifierPk"], `${path}.nullifierPk`) }),
    asset: hash(row["asset"], `${path}.asset`),
    ...(row["mint"] == null ? {} : { mint: address(row["mint"], `${path}.mint`) }),
    amount: integer(row["amount"], `${path}.amount`),
    blinding: hash(row["blinding"], `${path}.blinding`),
    dataHash: hash(row["dataHash"], `${path}.dataHash`),
    ringDataHash: hash(row["ringDataHash"], `${path}.ringDataHash`),
    treeId: u16(row["treeId"], `${path}.treeId`),
    leafIndex: integer(row["leafIndex"], `${path}.leafIndex`),
    slot: integer(row["slot"], `${path}.slot`),
    signature: signature(row["txSignature"], `${path}.txSignature`),
    eventIndex: u16(row["eventIndex"], `${path}.eventIndex`),
    slotIndex: u32(row["slotIndex"], `${path}.slotIndex`),
  });
}

function decodeSpendCoverage(wire: Record<string, unknown>): RingSpendCoverage {
  const frame = (value: unknown, path: string): RingSpendCoverageFrame => {
    const row = record(value, path);
    return Object.freeze({
      slot: integer(row["slot"], `${path}.slot`),
      signature: signature(row["txSignature"], `${path}.txSignature`),
      eventIndex: u16(row["eventIndex"], `${path}.eventIndex`),
    });
  };
  const rows = (name: string): readonly RingSpendCoverageRow[] =>
    Object.freeze(
      list(wire[name], name).map((entry, index) => {
        const path = `${name}[${index}]`;
        const row = record(entry, path);
        return Object.freeze({
          nullifier: hash(row["nullifier"], `${path}.nullifier`),
          frame: frame(row["frame"], `${path}.frame`),
        });
      }),
    );
  const totals = wire["totals"] == null ? undefined : record(wire["totals"], "totals");
  return Object.freeze({
    ...(wire["positionSlot"] == null
      ? {}
      : { positionSlot: integer(wire["positionSlot"], "positionSlot") }),
    historyThrough: integer(wire["historyThrough"], "historyThrough"),
    ...(totals === undefined
      ? {}
      : {
          totals: Object.freeze({
            observed: integer(totals["observed"], "totals.observed"),
            padding: integer(totals["padding"], "totals.padding"),
            address: integer(totals["address"], "totals.address"),
            external: integer(totals["external"], "totals.external"),
            resolved: integer(totals["resolved"], "totals.resolved"),
          }),
        }),
    unresolvedReal: rows("unresolvedReal"),
    unreadable: Object.freeze(
      list(wire["unreadable"], "unreadable").map((entry, index) =>
        frame(entry, `unreadable[${index}]`),
      ),
    ),
    integrityFaults: rows("integrityFaults"),
    ...(wire["cursor"] == null
      ? {}
      : { cursor: checkedReadCursor(base64(wire["cursor"], "cursor")) }),
  });
}

function decodeOutputs(value: unknown, path = "outputs"): readonly DecryptedRingOutput[] {
  return Object.freeze(
    list(value, path).map((entry, index) =>
      decodeOutput(record(entry, `${path}[${index}]`), `${path}[${index}]`),
    ),
  );
}

function decodePayloadErrors(
  value: unknown,
  path = "payloadErrors",
): readonly OutputPayloadError[] {
  return Object.freeze(
    list(value, path).map((entry, index) => {
      const error = record(entry, `${path}[${index}]`);
      return Object.freeze({
        slotIndex: u32(error["slotIndex"], `${path}[${index}].slotIndex`),
        kind: payloadErrorKind(error["kind"], `${path}[${index}].kind`),
      });
    }),
  );
}

function decodeWithdrawals(
  value: unknown,
  path = "withdrawals",
): readonly DecryptedRingWithdrawal[] {
  return Object.freeze(
    list(value, path).map((entry, index) => {
      const legPath = `${path}[${index}]`;
      const leg = record(entry, legPath);
      return Object.freeze({
        ...(leg["screenedOwner"] === undefined
          ? {}
          : {
              screenedOwner: address(leg["screenedOwner"], `${legPath}.screenedOwner`),
            }),
        recipient: address(leg["recipient"], `${legPath}.recipient`),
        asset: address(leg["asset"], `${legPath}.asset`),
        amount: u64(leg["amount"], `${legPath}.amount`),
      });
    }),
  );
}

/** Rust `TransactionAudit` records every published slot as an output or as one payload error. */
function checkSlotCoverage(indexes: readonly number[]): void {
  const seen = new Set(indexes);
  if (seen.size !== indexes.length || indexes.some((index) => index >= indexes.length))
    throw invalid("payloadErrors");
}

function decodeOutput(wire: Record<string, unknown>, path: string): DecryptedRingOutput {
  const context = record(wire["outputContext"], `${path}.outputContext`);
  const treeId = u32(context["treeId"], `${path}.outputContext.treeId`);
  if (treeId > 0xffff) throw invalid(`${path}.outputContext.treeId`);
  const kind = wire["kind"];
  const utxo = wire["utxo"];
  const tag = wire["tag"];
  let opening: OutputOpening;
  if (kind === "ring" && !absent(utxo) && !absent(tag)) {
    opening = Object.freeze({
      kind,
      utxo: decodeDecryptedUtxo(record(utxo, `${path}.utxo`), `${path}.utxo`),
      ownerTag: Object.freeze({ kind: "view", tag: hash(tag, `${path}.tag`) }),
    });
  } else if (kind === "exit" && !absent(utxo) && absent(tag)) {
    opening = Object.freeze({
      kind,
      utxo: decodeDecryptedUtxo(record(utxo, `${path}.utxo`), `${path}.utxo`),
    });
  } else if (kind === "dummy" && absent(utxo) && absent(tag)) {
    opening = Object.freeze({ kind });
  } else {
    throw invalid(`${path}.kind`);
  }
  return Object.freeze({
    slotIndex: u32(wire["slotIndex"], `${path}.slotIndex`),
    outputContext: Object.freeze({
      treeId,
      leafIndex: u64(context["leafIndex"], `${path}.outputContext.leafIndex`),
      hash: hash(context["hash"], `${path}.outputContext.hash`),
    }),
    opening,
  });
}

function decodeDecryptedUtxo(wire: Record<string, unknown>, path: string): AuditedUtxo {
  return Object.freeze({
    ...utxoFields(wire, path, hash),
    nullifierPk: hash(wire["nullifierPk"], `${path}.nullifierPk`),
  });
}

/** Rust `DecryptedKnownUtxo`, exactly one of `nullifierPk` and `ownerHash`, the latter for a deposited UTXO. */
function decodeKnownUtxo(wire: Record<string, unknown>, path: string): KnownUtxo {
  const nullifierPk = wire["nullifierPk"];
  const ownerHash = wire["ownerHash"];
  if (absent(nullifierPk) === absent(ownerHash)) throw invalid(`${path}.ownerHash`);
  const fields = utxoFields(wire, path, canonicalHash);
  // The commitment binds the asset field alone, a named mint must derive it.
  if (fields.mint !== undefined && !equalBytes(assetField(fields.mint), fields.asset))
    throw invalid(`${path}.mint`);
  return Object.freeze({
    ...fields,
    owner: absent(ownerHash)
      ? Object.freeze({
          kind: "keyed",
          nullifierPk: canonicalHash(nullifierPk, `${path}.nullifierPk`),
        })
      : Object.freeze({
          kind: "deposited",
          ownerHash: canonicalHash(ownerHash, `${path}.ownerHash`),
        }),
    treeId: u16(wire["treeId"], `${path}.treeId`),
  });
}

function utxoFields(
  wire: Record<string, unknown>,
  path: string,
  field: (input: unknown, path: string) => Bytes32,
): Omit<AuditedUtxo, "nullifierPk"> {
  const mint = wire["mint"];
  return {
    ownerKey: hash(wire["ownerKey"], `${path}.ownerKey`),
    asset: field(wire["asset"], `${path}.asset`),
    ...(absent(mint) ? {} : { mint: address(mint, `${path}.mint`) }),
    amount: u64(wire["amount"], `${path}.amount`),
    blinding: field(wire["blinding"], `${path}.blinding`),
    dataHash: field(wire["dataHash"], `${path}.dataHash`),
    ringDataHash: field(wire["ringDataHash"], `${path}.ringDataHash`),
  };
}

/** A BN254 scalar the reader hashes, a non-canonical encoding is malformed. */
function canonicalHash(input: unknown, path: string): Bytes32 {
  const bytes = hash(input, path);
  if (!isCanonicalField(bytes)) throw invalid(path);
  return bytes;
}

/** Notes and addresses before the dummy suffix, the notes counting `R`. */
function canonicalClasses(inputs: readonly DecryptedRingInput[], realInputs: number): boolean {
  try {
    return (
      InputMap.fromClasses(
        inputs.map((input) => input.class),
        inputs.length,
      ).noteCount === realInputs
    );
  } catch {
    return false;
  }
}

function decodeInput(value: Record<string, unknown>, path: string): DecryptedRingInput {
  const wire = exactRecord(value, INPUT_FIELDS, INPUT_REQUIRED_FIELDS, path);
  const inputClass = wire["class"];
  if (!INPUT_CLASSES.has(inputClass as InputClass)) throw invalid(`${path}.class`);
  const nullifier = hash(wire["nullifier"], `${path}.nullifier`);
  if (absent(wire["defaultInput"]))
    return Object.freeze({ nullifier, class: inputClass as InputClass });
  // A default-ring note is a spent note, an address or padding opens nothing.
  if (inputClass !== InputClass.note) throw invalid(`${path}.defaultInput`);
  const defaultInput = record(wire["defaultInput"], `${path}.defaultInput`);
  return Object.freeze({
    nullifier,
    class: InputClass.note,
    defaultInput: Object.freeze({
      utxo: decodeDecryptedUtxo(
        record(defaultInput["utxo"], `${path}.defaultInput.utxo`),
        `${path}.defaultInput.utxo`,
      ),
      ...(absent(defaultInput["commitment"])
        ? {}
        : { commitment: hash(defaultInput["commitment"], `${path}.defaultInput.commitment`) }),
    }),
  });
}

function decodeAuditedMerge(value: unknown, path: string): AuditedRingMerge {
  const wire = exactRecord(value, AUDITED_MERGE_FIELDS, AUDITED_MERGE_REQUIRED_FIELDS, path);
  const asset = canonicalHash(wire["asset"], `${path}.asset`);
  const realNullifiers = absent(wire["realNullifiers"])
    ? []
    : mergeCommitments(wire["realNullifiers"], `${path}.realNullifiers`);
  return Object.freeze({
    ...mergeRow(wire, path),
    ownerKey: hash(wire["ownerKey"], `${path}.ownerKey`),
    asset,
    mint: namedMint(wire, asset, path),
    amount: u64(wire["amount"], `${path}.amount`),
    realNullifiers,
  });
}

/** The commitment binds the asset field alone, a named mint must derive it. */
function namedMint(wire: Record<string, unknown>, asset: Bytes32, path: string): Address {
  const mint = address(wire["mint"], `${path}.mint`);
  if (!equalBytes(assetField(mint), asset)) throw invalid(`${path}.mint`);
  return mint;
}

function mergeCommitments(value: unknown, path: string): readonly Bytes32[] {
  const commitments = list(value, path);
  if (commitments.length > MAX_MERGE_INPUTS) throw invalid(path);
  return Object.freeze(
    commitments.map((commitment, index) => canonicalHash(commitment, `${path}[${index}]`)),
  );
}

function mergeRow(
  wire: Record<string, unknown>,
  path: string,
): Pick<AuditedRingMerge, "slot" | "signature" | "eventIndex" | "outputCommitment"> {
  return {
    slot: u64(wire["slot"], `${path}.slot`),
    signature: signature(wire["txSignature"], `${path}.txSignature`),
    eventIndex: u16(wire["eventIndex"], `${path}.eventIndex`),
    outputCommitment: canonicalHash(wire["outputCommitment"], `${path}.outputCommitment`),
  };
}

/** Rust `OutputPayloadErrorKind` as the ring rpc serializes it. */
export const RING_PAYLOAD_ERROR_KINDS: readonly OutputPayloadErrorKind[] = Object.freeze([
  "disclosure",
  "commitment",
]);

function payloadErrorKind(value: unknown, path: string): OutputPayloadErrorKind {
  const kind = RING_PAYLOAD_ERROR_KINDS.find((candidate) => candidate === value);
  if (kind === undefined) throw invalid(path);
  return kind;
}

function decodeActivation(value: unknown): RingActivation {
  const wire = record(value, "result.activation");
  const flag = (name: string): boolean => {
    const field = wire[name];
    if (typeof field !== "boolean") throw invalid(`result.activation.${name}`);
    return field;
  };
  return Object.freeze({
    activated: flag("activated"),
    paused: flag("paused"),
  });
}

function absent(value: unknown): boolean {
  return value === undefined || value === null;
}

/** A slot index, rejected outside the u32 range. */
function u32(value: unknown, path: string): number {
  const decoded = integer(value, path);
  if (decoded < 0n || decoded > 0xffff_ffffn) throw invalid(path);
  return Number(decoded);
}

/** An SPP event ordinal cannot exceed the indexer's u16 wire range. */
function u16(value: unknown, path: string): number {
  const decoded = integer(value, path);
  if (decoded < 0n || decoded > 0xffffn) throw invalid(path);
  return Number(decoded);
}

function u64(value: unknown, path: string): bigint {
  const decoded = integer(value, path);
  if (decoded < 0n || decoded > 0xffff_ffff_ffff_ffffn) throw invalid(path);
  return decoded;
}

function decodeSkipped(wire: Record<string, unknown>): SkippedRingTransaction {
  const reason = SKIPPED_REASONS.find((candidate) => candidate === wire["reason"]);
  if (reason === undefined) throw invalid("reason");
  return Object.freeze({
    slot: integer(wire["slot"], "slot"),
    signature: signature(wire["txSignature"], "txSignature"),
    eventIndex: u16(wire["eventIndex"], "eventIndex"),
    reason,
  });
}

function invalid(path: string): RingError {
  return new RingError("RING_RPC", {
    details: { reason: "invalid response", path },
  });
}

const { record, list, string, address, signature, signedInteger, integer, base64, base58 } =
  wireDecoder(invalid);

function invalidRequest(field: string): RingError {
  return new RingError("RING_RPC", {
    details: { reason: "invalid request", field },
  });
}

const { address: requestAddress, record: requestRecord } = wireDecoder(invalidRequest);

function exactRequestRecord(
  value: unknown,
  allowed: ReadonlySet<string>,
  required: ReadonlySet<string>,
  field: string,
): Record<string, unknown> {
  return exactFields(requestRecord(value, field), allowed, required, invalidRequest, field);
}

/** Rust `deny_unknown_fields` on a response. */
function exactRecord(
  value: unknown,
  allowed: ReadonlySet<string>,
  required: ReadonlySet<string>,
  path: string,
): Record<string, unknown> {
  return exactFields(record(value, path), allowed, required, invalid, path);
}

function exactFields(
  candidate: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  required: ReadonlySet<string>,
  refuse: (field: string) => RingError,
  field: string,
): Record<string, unknown> {
  const invalidField = Reflect.ownKeys(candidate).find(
    (key) => typeof key !== "string" || !allowed.has(key),
  );
  if (invalidField !== undefined) throw refuse(`${field}.shape`);
  const missing = [...required].find((key) => !Object.hasOwn(candidate, key));
  if (missing !== undefined) throw refuse(`${field}.${missing}`);
  return candidate;
}

function requestBytes(value: unknown, length: number, field: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) throw invalidRequest(field);
  return new Uint8Array(value);
}

function checkedSnapshotCursor(cursor: unknown): Uint8Array {
  const checked = checkedReadCursor(cursor);
  if (checked.length !== SNAPSHOT_CURSOR_LENGTH || checked[0] !== SNAPSHOT_CURSOR_VERSION)
    throw invalidRequest("cursor");
  return checked;
}

function checkedReadCursor(cursor: unknown): Uint8Array {
  if (
    !(cursor instanceof Uint8Array) ||
    cursor.length === 0 ||
    cursor.length > RING_READ_CURSOR_LIMIT
  ) {
    throw new RingError("RING_READ_CURSOR", {
      details: { length: cursor instanceof Uint8Array ? cursor.length : -1 },
    });
  }
  return new Uint8Array(cursor);
}

/** One to `RING_AUDITED_UTXOS_LIMIT` 32-byte hashes. */
function checkedUtxoHashes(value: unknown): readonly Bytes32[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > RING_AUDITED_UTXOS_LIMIT ||
    !value.every((entry) => entry instanceof Uint8Array && entry.length === 32)
  )
    throw new RingError("RING_READ_LIMIT", {
      details: {
        name: "utxoHashes",
        length: Array.isArray(value) ? value.length : -1,
      },
    });
  return Object.freeze(value.map((entry: Uint8Array) => new Uint8Array(entry) as Bytes32));
}

function checkedReadLimit(limit: unknown): bigint {
  if (typeof limit !== "bigint" || limit < 1n || limit > RING_READ_PAGE_LIMIT) {
    throw new RingError("RING_READ_LIMIT", {
      details: { limit: String(limit) },
    });
  }
  return limit;
}

/** Bounded to the safe integer range, `Number` in the wire encoding stays exact. */
function checkedUnixTimestamp(value: unknown, field: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw invalidRequest(field);
  }
  return value;
}

const SIGNED_READ_FIELDS = new Set([
  "method",
  "ringProgramId",
  "cursor",
  "limit",
  "wallet",
  "reader",
  "timestamp",
  "nonce",
  "signature",
]);
const SIGNED_READ_REQUIRED_FIELDS = new Set([
  "method",
  "ringProgramId",
  "reader",
  "timestamp",
  "nonce",
  "signature",
]);
const SIGNED_UTXOS_REQUIRED_FIELDS = new Set([
  "ringProgramId",
  "utxoHashes",
  "reader",
  "timestamp",
  "nonce",
  "signature",
]);
const SIGNED_UTXOS_FIELDS = new Set([...SIGNED_UTXOS_REQUIRED_FIELDS, "wallet"]);
const WEBAUTHN_FIELDS = new Set(["signature", "authenticatorData", "clientDataJSON"]);
const INPUT_REQUIRED_FIELDS = new Set(["nullifier", "class"]);
const INPUT_CLASSES: ReadonlySet<InputClass> = new Set(Object.values(InputClass));
const INPUT_FIELDS = new Set([...INPUT_REQUIRED_FIELDS, "defaultInput"]);
const LIST_SALT_FIELDS = new Set(["listSalt"]);
const NO_FIELDS = new Set<string>();
const AUDITED_MERGES_PAGE_FIELDS = new Set(["opened", "cursor"]);
const AUDITED_MERGE_REQUIRED_FIELDS = new Set([
  "slot",
  "txSignature",
  "eventIndex",
  "outputCommitment",
  "ownerKey",
  "asset",
  "mint",
  "amount",
]);
const AUDITED_MERGE_FIELDS = new Set([...AUDITED_MERGE_REQUIRED_FIELDS, "realNullifiers"]);
const SIGNED_AUDITOR_FIELDS = new Set([
  "ringProgramId",
  "authority",
  "genesisHash",
  "timestamp",
  "nonce",
  "signature",
]);

function checkedReaderBytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 34) {
    throw new RingError("RING_READER_KEY", {
      details: { length: value instanceof Uint8Array ? value.length : -1 },
    });
  }
  const reader = new Uint8Array(value);
  try {
    readerKeyFromBytes(reader);
  } catch (cause) {
    if (cause instanceof RingError) throw cause;
    throw new RingError("RING_READER_KEY", { cause });
  }
  return reader;
}

function checkedSignedRead(value: unknown, method: RingPagedRead): SignedRingRead {
  const read = exactRequestRecord(
    value,
    SIGNED_READ_FIELDS,
    SIGNED_READ_REQUIRED_FIELDS,
    "request",
  );
  if (read["method"] !== method) throw invalidRequest("method");
  // Rust `ReadScope`, a full transaction page is ring wide and wallet activity names its wallet.
  if (
    method !== "getAuditedMerges" &&
    (method === "getWalletActivity") !== (read["wallet"] !== undefined)
  )
    throw invalidRequest("wallet");
  const cursor = read["cursor"] === undefined ? undefined : checkedReadCursor(read["cursor"]);
  const limit = read["limit"] === undefined ? undefined : checkedReadLimit(read["limit"]);
  return Object.freeze({
    method,
    ...checkedReadAuth(read),
    ...(cursor === undefined ? {} : { cursor }),
    ...(limit === undefined ? {} : { limit }),
  });
}

type ReadAuth = Omit<SignedRingRead, "method" | "cursor" | "limit">;

function checkedReadAuth(read: Readonly<Record<string, unknown>>): ReadAuth {
  const ringProgramId = requestAddress(read["ringProgramId"], "ringProgramId");
  const wallet =
    read["wallet"] === undefined ? {} : { wallet: requestAddress(read["wallet"], "wallet") };
  const reader = checkedReaderBytes(read["reader"]);
  const nonce = requestBytes(read["nonce"], 32, "nonce") as Bytes32;
  const timestamp = checkedUnixTimestamp(read["timestamp"], "timestamp");
  const signature = read["signature"];
  if (signature instanceof Uint8Array) {
    return Object.freeze({
      ringProgramId,
      ...wallet,
      reader,
      nonce,
      timestamp,
      signature: requestBytes(signature, 64, "signature"),
    });
  }
  const webauthn = exactRequestRecord(signature, WEBAUTHN_FIELDS, WEBAUTHN_FIELDS, "signature");
  if (!(webauthn["signature"] instanceof Uint8Array) || webauthn["signature"].length === 0) {
    throw invalidRequest("signature");
  }
  const authenticatorData = webauthn["authenticatorData"];
  if (!(authenticatorData instanceof Uint8Array) || authenticatorData.length < 37) {
    throw invalidRequest("authenticatorData");
  }
  const clientDataJSON = webauthn["clientDataJSON"];
  if (!(clientDataJSON instanceof Uint8Array) || clientDataJSON.length === 0) {
    throw invalidRequest("clientDataJSON");
  }
  return Object.freeze({
    ringProgramId,
    ...wallet,
    reader,
    nonce,
    timestamp,
    signature: Object.freeze({
      signature: new Uint8Array(webauthn["signature"]),
      authenticatorData: new Uint8Array(authenticatorData),
      clientDataJSON: new Uint8Array(clientDataJSON),
    }),
  });
}

function checkedSignedAuditorKeyRequest(value: unknown): SignedAuditorKeyRequest {
  const request = exactRequestRecord(
    value,
    SIGNED_AUDITOR_FIELDS,
    SIGNED_AUDITOR_FIELDS,
    "request",
  );
  return Object.freeze({
    ringProgramId: requestAddress(request["ringProgramId"], "ringProgramId"),
    authority: requestAddress(request["authority"], "authority"),
    genesisHash: requestBytes(request["genesisHash"], 32, "genesisHash") as Bytes32,
    nonce: requestBytes(request["nonce"], 32, "nonce") as Bytes32,
    signature: requestBytes(request["signature"], 64, "signature") as Bytes64,
    timestamp: checkedUnixTimestamp(request["timestamp"], "timestamp"),
  });
}

function hash(value: unknown, path: string): Bytes32 {
  const bytes = base58(value, path);
  if (bytes.length !== 32) throw invalid(path);
  return bytes as Bytes32;
}

function x25519Key(value: unknown, path: string): X25519PublicKey {
  const bytes = base64(value, path);
  if (bytes.length !== 33) throw invalid(path);
  try {
    return X25519PublicKey.fromBytes(bytes as Bytes33);
  } catch (cause) {
    if (!(cause instanceof KeypairError)) throw cause;
    throw invalid(path);
  }
}
