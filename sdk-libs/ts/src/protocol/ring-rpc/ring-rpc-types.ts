import type { Bytes32 } from "@heliuslabs/spr/interface";
import type { Address, Signature } from "@heliuslabs/spr/interface";
import type { indexerTypes } from "@heliuslabs/spr/internal";
import type { ShieldedAddress } from "@heliuslabs/spr/keypair";

import type { MintPolicy } from "../membership/mint-policy.js";

type Hash = indexerTypes.Hash;
type Base64String = indexerTypes.Base64String;

/** Rust `zolana_ring_client::rpc` method names. */
export const RingRpcMethod = Object.freeze({
  getRelayQuote: "getRelayQuote",
  prepareRelay: "prepareRelay",
  submitRelay: "submitRelay",
  getRelayStatus: "getRelayStatus",
  submitRecordUpdate: "submitRecordUpdate",
  getRecordUpdateStatus: "getRecordUpdateStatus",
  setMergeSettings: "setMergeSettings",
  prepareAuthorityTransfer: "prepareAuthorityTransfer",
  getListSalt: "getListSalt",
  getPendingListApprovals: "getPendingListApprovals",
  refuseListApproval: "refuseListApproval",
  createRecordsRegistry: "createRecordsRegistry",
  setReaderGrant: "setReaderGrant",
} as const);
export type RingRpcMethod = (typeof RingRpcMethod)[keyof typeof RingRpcMethod];

/** Rust `RelayOperation`. */
export type RelayOperation =
  | "anonymous"
  | "confidential"
  | "delegate"
  | "deposit"
  | "merge"
  | "enroll";

/** Rust `GetRelayQuoteRequest`. */
export interface RelayQuoteRequest {
  readonly ring: Address;
  readonly operation: RelayOperation;
}

/** Rust `RelayQuote`. */
export interface RelayQuote {
  readonly feePayer: Address;
  readonly validUntilSlot: bigint;
}

/** Rust `TokenAccountSetup`, the fee payer creates the associated token account a withdrawal of `mint` pays. */
export interface TokenAccountSetup {
  readonly owner: Address;
  readonly mint: Address;
}

/** Rust `RelayIntent`, `proofInputs` without Merkle paths or record openings. */
export type RelayIntent =
  | Readonly<{
      operation: "anonymous" | "confidential";
      proofInputs: Base64String;
      /** Raw Ed25519 over `SppProofInputs::message_hash`. */
      ownerSignature: Signature;
      tokenAccountSetup?: readonly TokenAccountSetup[];
    }>
  | Readonly<{
      operation: "delegate";
      proofInputs: Base64String;
      /** The ring delegate's Ed25519 over `SppProofInputs::message_hash`. */
      delegateSignature: Signature;
      tokenAccountSetup?: readonly TokenAccountSetup[];
    }>
  /** `proofInputs` is a Rust `RelayProofInputs` on the deposit rail, the depositor signs its digest here and its legs later. */
  | Readonly<{ operation: "deposit"; proofInputs: Base64String; depositorSignature: Signature }>
  /** `proofInputs` is a Rust `RelayMergeInputs`, the owner signs its digest here. */
  | Readonly<{ operation: "merge"; proofInputs: Base64String; ownerSignature: Signature }>
  /** `proofInputs` is a Rust `RelayEnrollInputs`, the owner signs its digest here and the returned message later. */
  | Readonly<{ operation: "enroll"; proofInputs: Base64String; ownerSignature: Signature }>;

/** Rust `PrepareRelayRequest`. */
export interface PrepareRelayRequest {
  readonly ring: Address;
  readonly quote: RelayQuote;
  readonly intent: RelayIntent;
  /** In run order, absent names the service alone. */
  readonly coSigners?: readonly Address[];
}

/** Rust `RelayStep`, `message` the v1 message the wallet signs for `submitRelay`. */
export type RelayStep =
  | Readonly<{ step: "submitted"; relayId: Hash }>
  | Readonly<{ step: "signMessage"; relayId: Hash; message: Base64String }>;

/** Rust `SubmitRelayRequest`. */
export interface SubmitRelayRequest {
  readonly relayId: Hash;
  readonly signer: Address;
  readonly signature: Signature;
}

/** Rust `RelayStatus`. */
export type RelayStatus =
  | Readonly<{ status: "awaitingSignature" }>
  | Readonly<{ status: "sent"; signature: Signature }>
  | Readonly<{ status: "confirmed"; signature: Signature; slot: bigint }>
  | Readonly<{ status: "failed"; reason: string }>;

/** Rust `RecordUpdateEntry`. */
export type RecordUpdateEntry =
  | Readonly<{
      kind: "write";
      mintPolicy: MintPolicy | null;
      member: Hash;
      mask: bigint;
      value: bigint;
    }>
  | Readonly<{
      kind: "walletGrant";
      wallet: Hash;
      reader: Hash;
      access: ReaderAccess;
    }>;

/** Rust `ReaderAccess`, the `reader` bit a wallet grant sets or clears. */
export type ReaderAccess = "granted" | "revoked";

/** Rust `RecordUpdate`, the signed content. */
export interface RecordUpdate {
  /** The writer refuses another cluster's genesis hash. */
  readonly genesisHash: Hash;
  readonly ring: Address;
  readonly entries: readonly RecordUpdateEntry[];
  readonly validUntilSlot: bigint;
  /** Record bits of the authority lists the update waits for, absent or zero for none. */
  readonly awaitedLists?: bigint;
}

/** Rust `SubmitRecordUpdateRequest`, the signature covers `RecordUpdateStatement::hash`. */
export interface SubmitRecordUpdateRequest {
  readonly registry: Address;
  readonly update: RecordUpdate;
  readonly signer: Address;
  readonly signature: Signature;
}

/** Rust `RecordUpdateStatus`. */
export type RecordUpdateStatus =
  | Readonly<{ status: "pendingListApproval" }>
  | Readonly<{ status: "queued" }>
  | Readonly<{ status: "submitted"; signature: Signature }>
  | Readonly<{ status: "applied"; signature: Signature; revision: bigint }>
  | Readonly<{ status: "refused"; reason: string }>;

/** Rust `PolicyAuthorityAuth`. */
export interface PolicyAuthorityAuth {
  readonly authority: Address;
  readonly timestamp: bigint;
  readonly nonce: Base64String;
  readonly signature: Signature;
}

/** Rust `GetPendingListApprovalsRequest`, `cursor` is the last update of the previous page. */
export interface GetPendingListApprovalsRequest {
  readonly ring: Address;
  readonly registry: Address;
  readonly cursor?: Hash;
  readonly auth: PolicyAuthorityAuth;
}

/** Rust `RefuseListApprovalRequest`. */
export interface RefuseListApprovalRequest {
  readonly ring: Address;
  readonly registry: Address;
  readonly updateId: Hash;
  readonly auth: PolicyAuthorityAuth;
}

/** Rust `CreateRecordsRegistryRequest`, signed by the policy authority or, before `Initialize`, the upgrade authority. */
export interface CreateRecordsRegistryRequest {
  readonly ring: Address;
  readonly auth: PolicyAuthorityAuth;
}

/** Rust `CreateRecordsRegistryResponse`, `registry` is the ring's records under `storageAuthority`. */
export interface RecordsRegistry {
  readonly registry: Address;
  readonly storageAuthority: Address;
}

/** Rust `GetPendingListApprovalsResponse`, oldest first, `nextCursor` absent on the last page. */
export interface PendingListApprovalsPage {
  readonly pending: readonly PendingListApproval[];
  readonly nextCursor?: Hash;
}

/** Rust `PendingListApproval`, `member` is the record an approval writes. */
export interface PendingListApproval {
  readonly updateId: Hash;
  readonly wallet: Address;
  readonly member: Hash;
  readonly awaitedLists: bigint;
  readonly validUntilSlot: bigint;
}

/** Rust `ReaderGrantAction`. */
export type ReaderGrantAction = "grant" | "revoke";

/** Rust `SetReaderGrantRequest`, signed by `wallet` or, without one, by the ring's policy authority. */
export interface SetReaderGrantRequest {
  readonly ring: Address;
  readonly wallet?: Address;
  /** The 34-byte tagged reader key. */
  readonly reader: Base64String;
  readonly action: ReaderGrantAction;
  readonly timestamp: bigint;
  readonly nonce: Base64String;
  readonly signature: Signature;
}

/** Rust `MergeSettings`. */
export interface MergeSettings {
  readonly mint: Address;
  readonly targetNoteCount: number;
  readonly minAverageAmount: bigint;
}

/** Rust `SetMergeSettingsRequest`. */
export interface SetMergeSettingsRequest {
  readonly ring: Address;
  readonly owner: Address;
  readonly settings: MergeSettings;
  readonly timestamp: bigint;
  readonly nonce: Base64String;
  readonly signature: Signature;
}

/** Rust `AuthorityPayment`. */
export interface AuthorityPayment {
  readonly recipient: ShieldedAddress;
  readonly mint: Address;
  readonly amount: bigint;
}

export interface AuthorityWithdrawal {
  readonly recipient: Address;
  readonly mint: Address;
  readonly amount: bigint;
  readonly tokenProgram?: Address;
}

/** Rust `AuthorityTransfer`, change returns to an input's owner. */
export interface AuthorityTransfer {
  readonly sources: readonly ShieldedAddress[];
  readonly payments: readonly AuthorityPayment[];
  readonly exits: readonly AuthorityPayment[];
  readonly withdrawals: readonly AuthorityWithdrawal[];
}

/** Rust `GetListSaltRequest`. */
export interface GetListSaltRequest {
  readonly ring: Address;
  readonly writer: Address;
  readonly owner: Address;
  readonly timestamp: bigint;
  readonly nonce: Base64String;
  readonly signature: Signature;
}

/** Rust `PrepareAuthorityTransferRequest`, answered with a `signMessage` step until the delegate signs. */
export interface PrepareAuthorityTransferRequest {
  readonly ring: Address;
  readonly delegate: Address;
  readonly transfer: AuthorityTransfer;
  /** The delegate picks it, the frame's proof binds each record to it. */
  readonly txViewingKey: Bytes32;
  readonly timestamp: bigint;
  readonly nonce: Base64String;
  readonly signature: Signature;
}
