/** The message a wallet signs for Ring RPC, checked against the request the wallet made, Rust `relay_message`. */
import {
  type AccountMeta,
  type Address,
  decompileTransactionMessage,
  getBase58Decoder,
  getCompiledTransactionMessageDecoder,
  getCompiledTransactionMessageEncoder,
  isSignerRole,
  isWritableRole,
  type TransactionMessageBytes,
  type TransactionPartialSigner,
} from "@solana/kit";

import type {
  Bytes32,
  RequestContext,
  RingAssetDeposit,
  Signature,
} from "@heliuslabs/zolana/interface";
import { equalBytes, LOADED_ACCOUNTS_DATA_SIZE_LIMIT } from "@heliuslabs/zolana/internal";

import { ringComputeUnitLimit } from "../operations/management/admin.js";
import { RingError } from "../protocol/error.js";
import { ringPolicyAddress } from "../protocol/pda/index.js";
import type {
  PrepareAuthorityTransferRequest,
  RelayQuote,
} from "../protocol/ring-rpc/ring-rpc-types.js";
import {
  AUDITED_DEPOSIT_PREFIX_LENGTH,
  ringDepositSpp,
  type RingDepositSpp,
} from "../protocol/transaction/deposit-instruction.js";
import { RingInstructionTag } from "../protocol/transaction/instruction-tag.js";
import { RingTransactData } from "../protocol/transaction/transact.js";

const base58 = getBase58Decoder();
const VERIFIED = Symbol("verified relay message");
const ZERO = new Uint8Array(32);
const MAX_SIGNATURES = 12;
const MAX_INSTRUCTIONS = 64;

/** Rust `MessageMismatch`, the variant names the shared vectors carry. */
export type RelayMessageMismatch =
  | "Undecodable"
  | "NotV1"
  | "FeePayer"
  | "Budget"
  | "Instructions"
  | "Program"
  | "Data"
  | "Accounts"
  | "Recipients"
  | "Unrequested"
  | "Signer";

/** Rust `ExpectedDeposit`, built from the depositor's own request. */
export interface ExpectedDeposit {
  readonly kind: "deposit";
  readonly ring: Address;
  readonly policy: Address;
  readonly feePayer: Address;
  readonly depositor: Address;
  /** The SPP deposit the ring forwards unchanged. */
  readonly spp: RingDepositSpp;
}

/** Rust `ExpectedDelegate`, owner identities in payment order. */
export interface ExpectedDelegate {
  readonly kind: "delegate";
  readonly ring: Address;
  readonly policy: Address;
  readonly feePayer: Address;
  readonly delegate: Address;
  readonly source: Bytes32;
  readonly payees: readonly Bytes32[];
}

export type ExpectedRelayMessage = ExpectedDeposit | ExpectedDelegate;

/** Rust `VerifiedMessage`, only a check builds one. */
export class VerifiedRelayMessage {
  readonly signer: Address;
  readonly #bytes: Uint8Array;

  /** @internal */
  constructor(token: typeof VERIFIED, signer: Address, bytes: Uint8Array) {
    if (token !== VERIFIED) throw mismatch("Unrequested");
    this.signer = signer;
    this.#bytes = bytes;
    Object.freeze(this);
  }

  async sign(signer: TransactionPartialSigner, context?: RequestContext): Promise<Signature> {
    if (signer.address !== this.signer) throw mismatch("Signer");
    const transaction = {
      messageBytes: this.#bytes as unknown as TransactionMessageBytes,
      signatures: {},
    } as unknown as Parameters<TransactionPartialSigner["signTransactions"]>[0][number];
    const [signatures] = await signer.signTransactions(
      [transaction],
      context?.signal === undefined ? undefined : { abortSignal: context.signal },
    );
    const signature = signatures?.[signer.address];
    if (signature === undefined) throw mismatch("Signer");
    return base58.decode(signature) as Signature;
  }
}

export async function expectedDeposit(
  input: Readonly<{
    ringProgramId: Address;
    feePayer: Address;
    tree: Address;
    depositor: Address;
    deposit: RingAssetDeposit;
  }>,
): Promise<ExpectedDeposit> {
  const [policy, spp] = await Promise.all([
    ringPolicyAddress(input.ringProgramId),
    ringDepositSpp({
      ringProgramId: input.ringProgramId,
      tree: input.tree,
      depositor: input.depositor,
      deposits: [input.deposit],
    }),
  ]);
  return Object.freeze({
    kind: "deposit",
    ring: input.ringProgramId,
    policy,
    feePayer: input.feePayer,
    depositor: input.depositor,
    spp,
  });
}

export async function expectedDelegate(
  request: PrepareAuthorityTransferRequest,
  quote: RelayQuote,
): Promise<ExpectedDelegate> {
  const { transfer } = request;
  return Object.freeze({
    kind: "delegate",
    ring: request.ring,
    policy: await ringPolicyAddress(request.ring),
    feePayer: quote.feePayer,
    delegate: request.delegate,
    source: transfer.source.signingPublicKey.ownerProofInputHash(),
    payees: Object.freeze(
      transfer.payments.map((payment) => payment.recipient.signingPublicKey.ownerProofInputHash()),
    ),
  });
}

export function checkRelayMessage(
  expected: ExpectedRelayMessage,
  message: Uint8Array,
): VerifiedRelayMessage {
  return expected.kind === "deposit"
    ? checkDepositMessage(expected, message)
    : checkDelegateMessage(expected, message);
}

/** Rust `ExpectedDeposit::check`, every SPP byte and account is the depositor's. */
export function checkDepositMessage(
  expected: ExpectedDeposit,
  message: Uint8Array,
): VerifiedRelayMessage {
  const envelope: Envelope = {
    ...expected,
    signer: expected.depositor,
    tag: RingInstructionTag.deposit,
  };
  const instruction = open(envelope, message);
  const { data, accounts } = instruction;
  if (
    data[0] !== RingInstructionTag.deposit ||
    !equalBytes(data.subarray(AUDITED_DEPOSIT_PREFIX_LENGTH), expected.spp.data)
  )
    throw mismatch("Data");
  const split = accounts.length - expected.spp.accounts.length;
  if (
    split < 0 ||
    !sameAccounts(accounts.slice(split), expected.spp.accounts) ||
    !readsOnly(envelope, accounts.slice(0, split))
  )
    throw mismatch("Accounts");
  return new VerifiedRelayMessage(VERIFIED, envelope.signer, message);
}

/** Rust `ExpectedDelegate::check`, outputs are hidden and the check binds each published owner. */
export function checkDelegateMessage(
  expected: ExpectedDelegate,
  message: Uint8Array,
): VerifiedRelayMessage {
  const envelope: Envelope = {
    ...expected,
    signer: expected.delegate,
    tag: RingInstructionTag.authorityTransfer,
  };
  const { data, accounts } = open(envelope, message);
  if (data[0] !== RingInstructionTag.authorityTransfer) throw mismatch("Data");
  const recipients = withMismatch("Data", () => {
    const parsed = RingTransactData.parse(data.subarray(1), "delegate");
    if (parsed.interfaceTransfers.length !== 0) throw mismatch("Data");
    return RingTransactData.policyRecipients(parsed);
  });
  if (recipients.length < expected.payees.length) throw mismatch("Recipients");
  const paysEachPayee = expected.payees.every((payee, slot) =>
    equalBytes(recipients[slot] as Uint8Array, payee),
  );
  // Change returns to the source, a zero slot is padding.
  const returnsChange = recipients
    .slice(expected.payees.length)
    .every((slot) => equalBytes(slot, expected.source) || equalBytes(slot, ZERO));
  if (!paysEachPayee || !returnsChange) throw mismatch("Recipients");
  const named = accounts.filter((meta) => meta.address === expected.delegate);
  const signsOnce =
    named.length === 1 &&
    named.every((meta) => isSignerRole(meta.role) && !isWritableRole(meta.role));
  if (!signsOnce || !readsOnly(envelope, accounts.slice(0, 1))) throw mismatch("Accounts");
  return new VerifiedRelayMessage(VERIFIED, envelope.signer, message);
}

export function mismatch(reason: RelayMessageMismatch): RingError {
  return new RingError("RING_RELAY_MESSAGE_INVALID", { details: { mismatch: reason } });
}

interface Envelope {
  readonly ring: Address;
  readonly policy: Address;
  readonly feePayer: Address;
  readonly signer: Address;
  readonly tag: RingInstructionTag;
}

interface RingInstruction {
  readonly data: Uint8Array;
  readonly accounts: readonly AccountMeta[];
}

/** One canonical v1 message the quoted fee payer pays, holding only the ring instruction. */
function open(envelope: Envelope, bytes: Uint8Array): RingInstruction {
  const compiled = withMismatch("Undecodable", () =>
    getCompiledTransactionMessageDecoder().decode(bytes),
  );
  if (compiled.version !== 1) throw mismatch("NotV1");
  const canonical = withMismatch(
    "Undecodable",
    () => new Uint8Array(getCompiledTransactionMessageEncoder().encode(compiled)),
  );
  // Mirrors Rust `v1::Message::validate`, the vectors pin both on the same verdict.
  const { header, staticAccounts, instructionHeaders } = compiled;
  if (
    !equalBytes(canonical, bytes) ||
    new Set(staticAccounts).size !== staticAccounts.length ||
    header.numSignerAccounts > MAX_SIGNATURES ||
    header.numReadonlySignerAccounts >= header.numSignerAccounts ||
    instructionHeaders.length > MAX_INSTRUCTIONS ||
    instructionHeaders.some((instruction) => instruction.programAccountIndex === 0)
  )
    throw mismatch("Undecodable");
  const message = withMismatch("Undecodable", () =>
    decompileTransactionMessage(
      compiled as Parameters<typeof decompileTransactionMessage>[0] & { version: 1 },
    ),
  );
  if (message.feePayer.address !== envelope.feePayer || envelope.feePayer === envelope.signer)
    throw mismatch("FeePayer");
  const config = message.config ?? {};
  const withinBudget =
    config.computeUnitLimit !== undefined &&
    config.computeUnitLimit <= ringComputeUnitLimit(envelope.tag) &&
    config.loadedAccountsDataSizeLimit !== undefined &&
    config.loadedAccountsDataSizeLimit <= LOADED_ACCOUNTS_DATA_SIZE_LIMIT &&
    config.heapSize === undefined;
  if (!withinBudget) throw mismatch("Budget");
  const [instruction, ...rest] = message.instructions;
  if (instruction === undefined || rest.length !== 0) throw mismatch("Instructions");
  if (instruction.programAddress !== envelope.ring) throw mismatch("Program");
  return {
    data: new Uint8Array(instruction.data ?? []),
    accounts: instruction.accounts ?? [],
  };
}

/** The ring account first, then read only accounts that never name the signer. */
function readsOnly(envelope: Envelope, prefix: readonly AccountMeta[]): boolean {
  const [ring, ...rest] = prefix;
  return (
    ring !== undefined &&
    ring.address === envelope.policy &&
    !isSignerRole(ring.role) &&
    !isWritableRole(ring.role) &&
    rest.every((meta) => !isWritableRole(meta.role) && meta.address !== envelope.signer)
  );
}

function sameAccounts(found: readonly AccountMeta[], expected: readonly AccountMeta[]): boolean {
  return (
    found.length === expected.length &&
    found.every(
      (meta, index) =>
        meta.address === expected[index]?.address && meta.role === expected[index]?.role,
    )
  );
}

function withMismatch<T>(reason: RelayMessageMismatch, run: () => T): T {
  try {
    return run();
  } catch (error) {
    if (error instanceof RingError && error.code === "RING_RELAY_MESSAGE_INVALID") throw error;
    throw mismatch(reason);
  }
}
