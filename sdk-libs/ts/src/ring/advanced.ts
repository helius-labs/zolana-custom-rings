/** Circuit-facing codecs, registry proofs, and policy primitives. */
export {
  AUDIT_ENC_INFO,
  AUDITOR_MESSAGE_PREFIX_LENGTH,
  auditSharedSecret,
  auditorMessageData,
  auditorViewTag,
  maskDisclosure,
  packDisclosure,
  parseAuditorMessage,
  unmaskDisclosure,
  unpackDisclosure,
} from "../crypto/audit/audit.js";
export type { AuditorMessage, DisclosurePad } from "../crypto/audit/audit.js";
export {
  ANONYMOUS_AUDIT_CLASSES,
  ANONYMOUS_ENTRY_CLASS,
  ANONYMOUS_ENTRY_OUTPUTS,
  ANONYMOUS_MAX_INPUTS,
  ANONYMOUS_SLOT_BYTES,
  DELIVERED_AUDIT_CAPACITIES,
  DELIVERED_SLOT_BYTES,
  DENSE_DELIVERED_SLOT_BYTES,
  DISCLOSURE_CHUNK_BYTES,
  DISCLOSURE_INPUT_AMOUNT_BYTES,
  DISCLOSURE_SENDER_KEY_BYTES,
  INPUT_PREFIX_BITS,
  INPUT_PREFIX_BYTES,
  anonymousAuditClass,
  anonymousAuditKey,
  anonymousFields,
  anonymousKeyClass,
  auditLayoutValue,
  deliveredFields,
  disclosureFieldCount,
  packedChunks,
} from "../protocol/codec/ring-disclosure-layout.js";
export type {
  AnonymousAuditKey,
  AnonymousFields,
  AnonymousInputFields,
  AnonymousLayout,
  AnonymousSpend,
  AuditLayout,
  DeliveredFields,
  DeliveredLayout,
  DisclosureLayout,
  FieldRange,
} from "../protocol/codec/ring-disclosure-layout.js";
export {
  anonymousCommitments,
  decodeDisclosure,
  disclosureFields,
  disclosureLayout,
  inputPrefixPair,
  openRingDisclosure,
  sealRingDisclosure,
  splitInputPrefixPair,
} from "../crypto/audit/ring-disclosure.js";
export type {
  AnonymousInputOpening,
  AnonymousInputs,
  AnonymousOutputOpening,
  DeliveredOutputOpening,
  DisclosureKey,
  DummySlot,
  PublishedOutputs,
  RingDisclosure,
} from "../crypto/audit/ring-disclosure.js";
export {
  deliveredSlotSecret,
  ringIdField,
  senderCommitment,
} from "../crypto/derivation/ring-stream.js";
export type { DeliveredSlot } from "../crypto/derivation/ring-stream.js";
export {
  RING_DELIVERED_BODY_LEN,
  anonymousRecipientOutputBody,
  anonymousSenderOutputBody,
  openDeliveredBody,
  RingScheme,
  sealDeliveredBody,
  type DeliveredBodyOpening,
} from "../protocol/transaction/output.js";
export {
  DUMMY_RECIPIENT_VIEWING_PK,
  RECIPIENT_BODY_LEN,
  isDummyRecipient,
  listedRecipients,
  openRecipient,
  rebuilds,
  senderChange,
  type AnonymousOutput,
} from "../protocol/codec/anonymous-body.js";
export {
  decodeAnonymousRecipient,
  decodeAnonymousSender,
  encodeAnonymousRecipient,
  encodeAnonymousSender,
  type AnonymousRecipientPlaintext,
  type AnonymousSenderPlaintext,
  type UnverifiedRecipientPlaintext,
  type UnverifiedSenderPlaintext,
  type VerifiedRecipientPlaintext,
  type VerifiedSenderPlaintext,
} from "../protocol/codec/anonymous-plaintext.js";
export {
  OutputBlindings,
  openRingDelivery,
  ringBlindingSeed,
  ringOutputBlinding,
  type RingDeliveredNote,
  type RingDeliveryOpening,
  type RingDeliverySlot,
  type RingNoteOwner,
} from "../crypto/derivation/blinding.js";

export {
  PLAIN_GROTH16_PROOF_LENGTH,
  RingTransactData,
  outputBodyHash,
  outputRecipientKeyFields,
  ringDisclosureLayout,
  ringRail,
  ringRailOf,
  ringSppInputs,
  ringTransactOutput,
  taggedX25519,
} from "../protocol/transaction/transact.js";
export {
  encodeRingTransactInstructionData,
  type AnonymousRingEddsaCircuit,
  type RingCircuitId,
  type RingTransactInstructionData,
} from "../protocol/proof/circuit.js";
export type {
  AnonymousProofData,
  InputTrees,
  PolicyProof,
  RingOutput,
  RingRail,
  RingTransactConfig,
  SenderBundle,
} from "../protocol/transaction/transact.js";
export {
  applyRecordsStatementElements,
  applyRecordsStatementHash,
  auditStatementElements,
  auditStatementHash,
  policyStatementElements,
  policyStatementHash,
  registerKeyStatementElements,
  registerKeyStatementHash,
  ringAuditStatement,
} from "../protocol/proof/statement.js";
export type {
  ApplyRecordsStatement,
  AuditBinding,
  AuditHead,
  AuditKind,
  AuditStatement,
  PolicyKey,
  PolicyStatement,
  RegisterKeyStatement,
} from "../protocol/proof/statement.js";
export { depositStatementElements } from "../proof/deposit-audit.js";
export type { DepositStatement } from "../proof/deposit-audit.js";
export type { EncodedRuleTable } from "../protocol/codec/ring-codecs.js";

export {
  FIELD_MAX,
  MEMBER_REGISTRY_EMPTY_ROOT,
  SENTINEL_RECORD,
  applyRecordsStatement,
  checkMember,
  escrowEntry,
  escrowKeyHash,
  memberRecordHash,
  queueChain,
  queueEntryHash,
  quadPathRoot,
  replayRecordWrites,
  verifyRecordOpening,
} from "../protocol/membership/member-opening.js";
export type { EscrowKey } from "../protocol/membership/member-opening.js";
export { readRegisteredRecord, type RegisteredRecord } from "../rpc/registered-record.js";
export { nextScanCursor } from "../operations/audit/audit.js";
export { openDisclosedMerge } from "../operations/audit/audit-merge.js";
export { recoverMergeOpening, type MergeAuditorOpening } from "../operations/audit/audit-merge.js";

export {
  AUDITED_RING_DEPOSIT_TAG,
  RING_DEPOSIT_AUDIT_SLOTS,
  RING_DEPOSIT_OPENING_LENGTH,
  RING_DEPOSIT_OPENING_OWNER_KEY_OFFSET,
  encodeRingDepositCapsule,
  readRingDepositCapsule,
  type RingDepositCapsule,
} from "../protocol/codec/deposit-capsule.js";
export {
  ringDepositSpp,
  type RingDepositSpp,
} from "../protocol/transaction/deposit-instruction.js";

export {
  LIST_IDS,
  ListId,
  POLICY_TABLE_VERSION,
  admitTransfer,
  buildRuleTable,
  checkedListId,
  decodeRule,
  decodeRuleTable,
  encodeRule,
  encodeRuleTable,
  listIdFromByte,
  listSet,
  listWriter,
  memberOfAsset,
  memberOfIdentity,
  memberOfTag,
  pinnedPolicy,
  policySourceOwners,
  policyTableFields,
  policyTableHash,
  policyTableProofInputs,
  recordBit,
  referencedLists,
  ruleAlternatives,
  walletGrantMember,
} from "../protocol/membership/policy.js";
export {
  recordUpdateQueueEntry,
  recordUpdateStatementHash,
  signRecordUpdate,
  verifyRecordUpdate,
} from "../protocol/ring-rpc/record-update.js";
export type { UnsignedRecordUpdate } from "../protocol/ring-rpc/record-update.js";
export type {
  ListWriter,
  Member,
  OutflowLimit,
  OutputSubjects,
  PinnedPolicy,
  PolicySource,
  RecordLists,
  Rule,
  RuleAlternative,
  RuleGuard,
  RuleMode,
  RuleRefusal,
  RuleSource,
  RuleSubject,
  RuleTable,
  RuleTableInput,
  TransferSubject,
  TransferSubjects,
} from "../protocol/membership/policy.js";

export { EMPTY_MINT_POLICY, type MintPolicy } from "../protocol/membership/mint-policy.js";
