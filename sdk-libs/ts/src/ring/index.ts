export type { ErrorEnvelope } from "@heliuslabs/zolana";
export {
  decodeRingDepositOutput,
  decodeRingDepositPlaintext,
  encodeRingDepositPlaintext,
} from "../protocol/codec/ring-deposit-plaintext.js";
export type {
  RingDepositOutput,
  RingDepositPlaintext,
} from "../protocol/codec/ring-deposit-plaintext.js";
export { ringTransactAccounts } from "@heliuslabs/zolana/interface";
export {
  RING_ERROR_CODES,
  RingError,
  RingProgramError,
  StorageProgramError,
  wrapRingError,
} from "../protocol/error.js";
export type { RingErrorCode, RingProgramErrorName } from "../protocol/error.js";

export {
  ringAuthAddress,
  ringCoSignerAddress,
  ringConfigAddress,
  ringMemberRegistryAddress,
  ringPolicyAddress,
  ringRecordQueueAddress,
} from "../protocol/pda/index.js";
export {
  APPLY_DELAY_SLOTS,
  AUTHORITY_RESERVED_LEAVES,
  CUSTOM_RING_PROOF_LENGTH,
  DEFAULT_INSERT_FEE,
  GRACE_SLOTS,
  MEMBER_QUEUE_LIMIT,
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_SCOPE_MASK,
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  checkedCustomRingProof,
  decodeRingCoSigner,
  decodeRingMemberRegistry,
  decodeRingPolicy,
  decodeRingProgramConfig,
  decodeRingRecordQueue,
  queueAdmitsMemberWrite,
  queueApplyDue,
  queueChainTail,
  mirrorCurrentRoot,
  mirrorRoot,
  queuePending,
  registryCurator,
  registryCuratorRoot,
  registryCurrentRoot,
  registryOwnRoot,
} from "../protocol/codec/ring-codecs.js";
export type {
  RingCoSigner,
  RingMemberRegistry,
  RingMode,
  RingPolicy,
  RingProgramConfig,
  RingQueueCheckpoint,
  RingRecordQueue,
  RingRootEntry,
  RingSourceSlot,
  RootMirror,
  RootMirrorKind,
  StorageRegistryRoot,
} from "../protocol/codec/ring-codecs.js";
export {
  BPF_LOADER_UPGRADEABLE_ID,
  fetchCuratorRegistry,
  fetchRingCoSignerRecord,
  fetchRingMemberRegistry,
  fetchRingPolicy,
  fetchRingProgramConfig,
  fetchRingRecordQueue,
  requireActiveRing,
  ringProgramDataAddress,
} from "../protocol/membership/config.js";
export { ringRole, type RingRole } from "../protocol/membership/role.js";
export { listRegisteredRings, type RegisteredRing } from "../rpc/ring-directory.js";
export { ringTreeIdResolver } from "../protocol/membership/trees.js";

export {
  RingInstructionTag,
  clearRingCoSignerInstruction,
  createMemberRegistryInstruction,
  createRingConfigInstruction,
  createRingPolicyInstruction,
  initSppRingConfigInstruction,
  ringComputeUnitLimit,
  setRingAuthorityInstruction,
  setRingCoSignerInstruction,
  setRingDelegateInstruction,
  setRingInsertFeeInstruction,
  setRingPausedInstruction,
  setRingPolicyRulesInstruction,
  setRingPolicySourceInstruction,
  syncRootsInstruction,
} from "../operations/management/admin.js";
export type {
  RingKind,
  RingPolicySourceOwner,
  RingPolicyTableInput,
  RingSharedSource,
} from "../operations/management/admin.js";
export {
  buildRingCreatePolicyTransaction,
  buildRingSetPolicyRulesTransaction,
  buildRingSetPolicySourceTransaction,
} from "../operations/management/policy-admin.js";
export type {
  RingCreatePolicyTransactionParams,
  RingPolicyAdminClient,
  RingSetPolicyRulesTransactionParams,
  RingSetPolicySourceTransactionParams,
} from "../operations/management/policy-admin.js";
export {
  CLOCK_SYSVAR,
  RENT_SYSVAR,
  RingProgramBinary,
  closeBufferInstruction,
  decodeRingProgramData,
  deployRingProgram,
  deployWithMaxDataLenInstruction,
  extendProgramInstruction,
  fetchRingProgramData,
  initializeBufferInstruction,
  setUpgradeAuthorityInstruction,
  upgradeInstruction,
  verifyRingProgram,
  writeBufferInstruction,
} from "../protocol/transaction/program.js";
export type {
  RingProgramData,
  RingProgramDeployClient,
  RingProgramDeployOutcome,
  RingProgramDeployParams,
} from "../protocol/transaction/program.js";

export {
  AUTHORITY_WRITABLE_LISTS,
  AuthorityListWrite,
  MEMBER_WRITABLE_LISTS,
  RecordApplication,
  feeAccounts,
  listWrite,
  memberListWriteInstruction,
} from "../operations/management/record-writes.js";
export type {
  ListWrite,
  ProvenRecordWrite,
  RecordQueueBinding,
  RingRecordApplicationClient,
  RingRecordWriteClient,
} from "../operations/management/record-writes.js";
export {
  AuthorityRecordUpdate,
  WalletRecordUpdate,
} from "../operations/management/record-updates.js";
export type { EscrowEntry, RecordUpdateTarget } from "../operations/management/record-updates.js";
export type {
  ReaderAccess,
  RecordUpdate,
  RecordUpdateEntry,
  RecordUpdateStatus,
  SubmitRecordUpdateRequest,
} from "../protocol/ring-rpc/ring-rpc-types.js";
export { MemberOpeningRead } from "../protocol/membership/member-opening.js";
export type { EscrowedRecord } from "../protocol/membership/member-opening.js";
export { checkEscrowedRecipients, readMemberRecords } from "../rpc/registered-record.js";
export type { RingRecordReadClient } from "../rpc/registered-record.js";
export {
  NF_KEY_ENC_INFO,
  KeyRegistration,
  NullifierKeyEscrow,
  RegisterKey,
  fetchRingSealedKey,
  openNullifierKey,
  openRingSealedKey,
  sealNullifierKey,
} from "../operations/management/register-key.js";
export type {
  KeyEscrowAuthority,
  KeyEscrowRequest,
  NullifierKeyEnvelope,
  ProvenEscrow,
  ProvenKeyRegistration,
  RingKeyRegistrationClient,
  RingSealedKeyClient,
  RingSealedKeyEntry,
  SealedNullifierKey,
} from "../operations/management/register-key.js";

export {
  PreparedRingDeposit,
  RING_DEPOSIT_COMPUTE_UNIT_LIMIT,
  buildRingDepositTransaction,
} from "../operations/payments/deposit.js";
export type {
  PreparedRingDepositRelay,
  ProvenRingDeposit,
  RingDepositClient,
  RingDepositParams,
  RingDepositRecipient,
  RingDepositRelayParams,
} from "../operations/payments/deposit.js";
export { ringDepositInstruction } from "../protocol/transaction/deposit-instruction.js";
export {
  customRingDepositPayload,
  decryptRingDepositUtxo,
} from "../protocol/transaction/deposit-payload.js";
export {
  openRingDepositOpening,
  ringDepositContextHash,
  ringDepositPublicInputHash,
  sealRingDepositOpenings,
} from "../proof/deposit-audit.js";
export type { RingDepositOpening } from "../proof/deposit-audit.js";

export {
  messageSignerSpendSigner,
  signingKeySpendSigner,
} from "../operations/payments/anonymous.js";
export {
  PENDING_RETENTION,
  StreamCounter,
  TAG_GAP,
  TransferTagging,
  VIEWING_HISTORY_VERSION,
  ViewingHistory,
  ViewingKeyEntry,
} from "../state/viewing-history.js";
export type {
  AdvancedTag,
  Counterparty,
  EntryStream,
  FirstContact,
  FirstContactPairing,
  PaymentRecipient,
  PaymentTag,
  TagSelection,
  TransferTags,
} from "../state/viewing-history.js";
export { AnonymousSync, TAGS_PER_REQUEST } from "../state/anonymous-sync.js";
export type {
  AnonymousRingUtxo,
  AnonymousScan,
  AnonymousStream,
  AnonymousSyncClient,
  SentCheck,
  SentPayment,
} from "../state/anonymous-sync.js";
export type { TaggedPayment } from "../operations/payments/output-rail.js";
export { openRingNotes, syncRingWallet } from "../state/ring-sync.js";
export type { RingNotes, RingSyncClient } from "../state/ring-sync.js";
export { LocalRingKeys, isRingKeys, ringWalletKeys } from "../state/ring-keys.js";
export type {
  RingDeliveryRequest,
  RingKeys,
  SharedTagPair,
  SharedTagsRequest,
  ViewTagRequest,
  ViewTagStream,
} from "../state/ring-keys.js";
export { approveRingUnattended, ringIntentHash } from "../protocol/transaction/intent.js";
export type {
  RingAnonymousTransferIntent,
  RingApprovalHandler,
  RingApprovalRequest,
  RingTransactionIntent,
} from "../protocol/transaction/intent.js";
export type { AnonymousPayment, AnonymousSpendSigner } from "../operations/payments/anonymous.js";
export {
  AnonymousTransfer,
  CustomRingTransfer,
  DelegateTransfer,
} from "../operations/payments/transfer-rails.js";
export type {
  AnonymousTransferClient,
  CustomRingTransferClient,
  CustomRingTransferInput,
  DelegateOutput,
  DelegateTransferClient,
  DelegateTransferInput,
  PreparedRingRelay,
  RingRelayInput,
} from "../operations/payments/transfer-rails.js";
export {
  PendingRelaySignature,
  PreparedAuthorityTransfer,
  PreparedRelay,
  relayId,
  submittedRelay,
} from "../rpc/relay.js";
export type { RelaySent, RingAuthorityRelayClient, RingRelayClient } from "../rpc/relay.js";
export type {
  AuthorityPayment,
  AuthorityTransfer,
  PrepareAuthorityTransferRequest,
  PrepareRelayRequest,
  RelayIntent,
  RelayOperation,
  RelayQuote,
  RelayStatus,
  RelayStep,
  TokenAccountSetup,
} from "../protocol/ring-rpc/ring-rpc-types.js";
export { ProvenRingTransfer, ringTransactInstruction } from "../operations/workflow/pipeline.js";
export type {
  AnonymousSpendValues,
  RingBoundState,
  RingProvingClient,
  RingTransactAccounts,
} from "../operations/workflow/pipeline.js";
export type { BoundPolicy, BoundRoot } from "../proof/policy-proof.js";
export {
  buildRingEntryTransaction,
  buildRingExitTransaction,
  buildRingTransferTransaction,
  buildRingWithdrawalTransaction,
  createRingEntrySubmission,
  createRingExitSubmission,
  createRingTransferSubmission,
  createRingWithdrawalSubmission,
  prepareRingEntryRelay,
  prepareRingExitRelay,
  prepareRingTransferRelay,
  prepareRingWithdrawalRelay,
} from "../operations/payments/transfer.js";
export type {
  AnonymousRingSpend,
  RingRelaySpendParams,
  RingEntryTransactionParams,
  RingExitTransactionParams,
  RingSpendParams,
  RingTransferClient,
  RingTransferTransactionParams,
  RingWithdrawalTransactionParams,
} from "../operations/payments/transfer.js";
export {
  buildRingDelegateRecoveredTransaction,
  buildRingDelegateTransferTransaction,
  createRingDelegateRecoveredSubmission,
  createRingDelegateSubmission,
} from "../operations/management/delegate.js";
export type {
  RingDelegateRecoveredClient,
  RingDelegateRecoveredParams,
  RingDelegateTransferClient,
  RingDelegateTransferParams,
} from "../operations/management/delegate.js";
export {
  MAX_RING_MERGE_INPUTS,
  RING_MERGE_COMPUTE_UNIT_LIMIT,
  buildRingMergeTransaction,
  createRingMergeSubmission,
  prepareRingMergeRelay,
  ringMergeInstruction,
} from "../operations/payments/merge.js";
export type {
  RingMergeRelayParams,
  RingMergeTransactionParams,
} from "../operations/payments/merge.js";
export type { RingMergeClient } from "../rpc/ports.js";
export {
  RingTransactionSubmission,
  createKitRingSubmissionTransport,
  reconcileRingSubmissions,
} from "../operations/workflow/submission.js";
export type {
  ReservationHold,
  RingSubmissionAttempt,
  RingSubmissionBuild,
  RingSubmissionResult,
} from "../operations/workflow/submission.js";

export {
  KnownUtxoIndex,
  auditRing,
  auditRingTransaction,
  auditedUtxos,
  auditorMessage,
  hasUnknownAssets,
  knownUtxoHash,
  openedUtxo,
  recoverTransactionViewingKey,
} from "../operations/audit/audit.js";
export { inputPrefix } from "../crypto/audit/ring-disclosure.js";
export type { InputPrefix } from "../crypto/audit/ring-disclosure.js";
export type {
  AuditedInput,
  AuditedInputOpening,
  AuditedRingOutput,
  AuditedRingTransaction,
  AuditedSender,
  AuditedUtxo,
  CreatedRingUtxo,
  EscrowedKeys,
  InputOpening,
  InputRing,
  KnownUtxo,
  KnownUtxos,
  OutputOpening,
  RingOwnerTag,
  OutputPayloadError,
  OutputPayloadErrorKind,
  RingAuditPage,
  RingAuditReader,
  UtxoOwner,
} from "../operations/audit/audit.js";
export { auditRingMerges } from "../operations/audit/audit-merge.js";
export { createdRingUtxos, scanCreatedRingUtxos } from "../operations/workflow/created-utxos.js";
export type { CreatedRingUtxosPage } from "../operations/workflow/created-utxos.js";
export type {
  AuditedRingMerge,
  MergeKeys,
  RingMergeAuditPage,
  RingMergeAuditReader,
  UnresolvedRingMerge,
} from "../operations/audit/audit-merge.js";
export {
  mergeDisclosureFieldCount,
  openRingMergeDisclosure,
  ringMergePublicInputHash,
} from "../crypto/audit/merge-disclosure.js";
export type { RingMergeDisclosure, RingMergeOpening } from "../crypto/audit/merge-disclosure.js";
export { recoverRingMemberNotes } from "../operations/workflow/recover.js";
export type {
  RecoveredRingNotes,
  RingRecoveryClient,
  RingRecoveryParams,
} from "../operations/workflow/recover.js";
export {
  ConfirmedDeposit,
  ORIGIN_TRANSACTION_CONFIG,
  RpcTransactionOrigin,
  confirmedInstructionGroups,
  confirmedRingWithdrawals,
  ringInstructionsIn,
  ringInvokedIn,
  ringWithdrawalsOf,
  senderOf,
} from "../protocol/transaction/origin.js";
export type {
  ConfirmedEventKind,
  ConfirmedRingTransaction,
  OriginInstruction,
  OriginInstructionGroup,
  RingWithdrawal,
  TransactionOrigin,
} from "../protocol/transaction/origin.js";
export {
  RING_AUDITED_UTXOS_LIMIT,
  RING_PAYLOAD_ERROR_KINDS,
  RING_READ_CURSOR_LIMIT,
  RING_READ_PAGE_LIMIT,
  RingAuditedUtxosRequest,
  RingAuditorKeyRequest,
  RingAuthorityTransferRequest,
  RingReadRequest,
  RingRpc,
  auditedUtxosAttestation,
  auditorKeyStatement,
  authorityTransferAttestation,
  auditorKeyRequestAttestation,
  messageSignerReader,
  ringReadAttestation,
} from "../rpc/ring-rpc.js";
export type {
  AuditedMergesPage,
  DecryptedOutputContext,
  DecryptedRingOutput,
  DecryptedRingTransaction,
  DecryptedRingTransactionsPage,
  DecryptedRingWithdrawal,
  RingActivation,
  RingAuditedUtxo,
  RingAuditedUtxosPage,
  RingAuditorKey,
  RingDeposit,
  RingDepositsPage,
  RingKeyMode,
  RingPagedRead,
  RingReadSigner,
  RingReadTarget,
  RingRegistryStatus,
  RingRpcHealth,
  RingRpcOptions,
  RingState,
  RingStatus,
  SignedAuditedUtxosRead,
  SignedAuditorKeyRequest,
  SignedRingRead,
  SkippedReason,
  SkippedRingTransaction,
  WebAuthnSignature,
} from "../rpc/ring-rpc.js";
export {
  P256ReaderKey,
  checkedReaderKey,
  decodeReadAccessRecord,
  fetchReaderGrant,
  grantReadAccessInstruction,
  parseReaderKey,
  readAccessRecordAddress,
  readerKeyBytes,
  readerKeyEquals,
  readerKeyFromBytes,
  readerKeyToString,
  revokeReadAccessInstruction,
} from "../operations/management/reader-access.js";
export type { ReadAccessRecord, ReaderKey } from "../operations/management/reader-access.js";
export { createPasskey, passkeyReader, type Passkey } from "../crypto/keys/passkey.js";
