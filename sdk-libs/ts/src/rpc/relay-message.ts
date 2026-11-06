/** The message a wallet signs for Ring RPC, checked against the request the wallet made, Rust `relay_message`. */
import {
  type AccountMeta,
  type Address,
  address,
  decompileTransactionMessage,
  getBase58Decoder,
  getBase58Encoder,
  getCompiledTransactionMessageDecoder,
  getCompiledTransactionMessageEncoder,
  type Instruction,
  isSignerRole,
  isWritableRole,
  type TransactionMessageBytes,
  type TransactionPartialSigner,
} from "@solana/kit";

import { getCreateAssociatedTokenAccountInstructionAsync } from "@heliuslabs/spr/instructions";
import {
  NO_CACHE_WRITES,
  SOL_INTERFACE,
  SHIELDED_POOL_CPI_AUTHORITY,
} from "@heliuslabs/spr/interface";
import { getAssociatedTokenAddress } from "@heliuslabs/spr/addresses";
import type {
  Bytes32,
  RequestContext,
  InterfaceTransfer,
  Signature,
} from "@heliuslabs/spr/interface";
import { confidentialSlotTag } from "../crypto/derivation/ring-stream.js";
import {
  addressBytes,
  encodeBase58,
  equalBytes,
  isCanonicalField,
  isZero,
  U64_MAX,
  LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
  splInterfaceWithBump,
} from "@heliuslabs/spr/internal";
import {
  ShieldedPublicKey,
  type NullifierKey,
  type ShieldedAddress,
  type X25519PublicKey,
} from "@heliuslabs/spr/keypair";
import { ProofInputUtxo, Utxo, SOL_MINT, type WalletUtxo } from "@heliuslabs/spr/transaction";

import { ringComputeUnitLimit } from "../operations/management/admin.js";
import { RingError } from "../protocol/error.js";
import {
  openingTotals,
  type ApprovalOpening,
  type OutputTotalsOpening,
  type PublicTotalsOpening,
} from "../protocol/membership/approval-totals.js";
import type { OwnerDebit } from "../protocol/membership/owner-debits.js";
import { memberOfAsset } from "../protocol/membership/policy.js";
import { signerDataCountAt } from "../protocol/membership/signer-data-counts.js";
import { ringAuthAddress, ringPolicyAddress, STORAGE_PROGRAM_ID } from "../protocol/pda/index.js";
import {
  ENROLL_COMPUTE_UNITS,
  enrollRequestDigest,
  relayEnrollInstruction,
  type RelayEnrollInputs,
} from "../protocol/ring-rpc/relay-enroll-inputs.js";
import type {
  AuthorityWithdrawal,
  PrepareAuthorityTransferRequest,
  RelayQuote,
} from "../protocol/ring-rpc/ring-rpc-types.js";
import { RingInstructionTag } from "../protocol/transaction/instruction-tag.js";
import {
  isAnonymousFrame,
  RingTransactData,
  ringRailOf,
  type FrameExtensions,
  type RingRail,
} from "../protocol/transaction/transact.js";
import type { RingPolicy } from "../protocol/codec/ring-codecs.js";
import { RecordKind, type AuditRecord } from "../protocol/codec/audit-stream.js";
import {
  canonicalViewingKey,
  openSealedDisclosure,
  type RingDisclosure,
} from "../crypto/audit/ring-disclosure.js";
import { x25519FromU } from "../crypto/keys/x25519.js";
import { rawJson } from "../protocol/codec/raw-json.js";
import { N_PUBLIC_SLOTS } from "../protocol/transaction/spp.js";

const base58 = getBase58Decoder();
const VERIFIED = Symbol("verified relay message");
const MAX_SIGNATURES = 12;
const MAX_INSTRUCTIONS = 64;
/** Rust `RING_TRANSACT_RING_CONFIG_INDEX`, the ring auth PDA's place in SPP's account list. */
const RING_TRANSACT_RING_CONFIG_INDEX = 4;

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
  | "TransactionKey"
  | "ApprovalMaskUnaccepted"
  | "MissingApprovalDigest"
  | "FalseApprovalOpening"
  | "ApprovalOpeningLayout"
  | "ZeroApprovalBlinder"
  | "ReusedApprovalBlinder"
  | "ApprovalOverLimit"
  | "DataOutputCount"
  | "FunderLegs"
  | "SpendsUnnamedNote"
  | "SpendsUnrequestedNote"
  | "Unrequested"
  | "Signer";

export type DelegateRingConfig = Pick<RingPolicy, "mode" | "auditorPublicKey">;

/** Rust `AllowedNullifiers`, filled only by `admit`. */
export class AllowedNullifiers {
  readonly #sources = new Set<string>();
  readonly #nullifiers = new Set<string>();

  /** Rust `AllowedNullifiers::admit`, admits nothing of `source` when one opening fails. */
  admit(
    source: Readonly<{ address: ShieldedAddress; nullifierKey: NullifierKey }>,
    notes: readonly ProofInputUtxo[],
  ): this {
    const { address, nullifierKey } = source;
    if (!equalBytes(nullifierKey.publicKey(), address.nullifierPublicKey))
      throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
    const owner = address.signingPublicKey.confidentialViewTag();
    const nullifiers = notes.map((note, index) => {
      // 1. Owner and key are opening fields the rebuilt hash commits, so the match binds the note.
      if (
        !equalBytes(note.utxo.owner.confidentialViewTag(), owner) ||
        !equalBytes(note.nullifierPublicKey, address.nullifierPublicKey)
      )
        throw delegateSourceRefusal("foreignNote", index);
      // 2. Rebuilt, not read, any carried nullifier passes under the shared zero key.
      const hashes = {
        ...(note.dataHash === undefined ? {} : { dataHash: note.dataHash }),
        ...(note.ringDataHash === undefined ? {} : { ringDataHash: note.ringDataHash }),
      };
      const rebuilt = ProofInputUtxo.fromNullifierKey(note.utxo, nullifierKey, hashes, note.treeId);
      if (!equalBytes(rebuilt.nullifier(), note.nullifier()))
        throw delegateSourceRefusal("unboundOpening", index);
      return rebuilt.nullifier();
    });
    this.#sources.add(encodeBase58(address.toBytes()));
    for (const nullifier of nullifiers) this.#nullifiers.add(encodeBase58(nullifier));
    return this;
  }

  /** Rust `AllowedNullifiers::check_sources`. */
  checkSources(requested: readonly ShieldedAddress[]): void {
    const named = new Set(requested.map((address) => encodeBase58(address.toBytes())));
    const same =
      named.size === this.#sources.size && [...named].every((source) => this.#sources.has(source));
    if (!same) throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "sources" } });
  }

  /** The published nullifiers at note positions, an address or a dummy spends no note. */
  spendsOnly(notes: Iterable<Bytes32>): boolean {
    for (const nullifier of notes) if (!this.#nullifiers.has(encodeBase58(nullifier))) return false;
    return true;
  }
}

function delegateSourceRefusal(reason: "foreignNote" | "unboundOpening", index: number): RingError {
  return new RingError("RING_DELEGATE_INVALID", { details: { reason, index } });
}

interface ExpectedOwner {
  readonly ownerKey: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly viewingU: Bytes32;
}

interface ExpectedPayment {
  readonly kind: typeof RecordKind.ring | typeof RecordKind.exit;
  readonly owner: ExpectedOwner;
  readonly mint: Address;
  readonly amount: bigint;
}

interface ExpectedWithdrawal {
  readonly transfer: InterfaceTransfer;
  readonly accounts: readonly Address[];
}

/** Rust `ExpectedDelegate`. */
export interface ExpectedDelegate {
  readonly kind: "delegate";
  readonly ring: Address;
  readonly policy: Address;
  readonly feePayer: Address;
  readonly delegate: Address;
  /** The frame the ring's mode fixes. */
  readonly rail: RingRail;
  readonly auditor: X25519PublicKey;
  readonly txViewingKey: Bytes32;
  /** Change returns to an input's owner. */
  readonly sources: readonly ExpectedOwner[];
  readonly payments: readonly ExpectedPayment[];
  readonly withdrawals: readonly ExpectedWithdrawal[];
  /** Every note of each requested source, a note Ring RPC selects outside it is refused. */
  readonly allowed: AllowedNullifiers;
}

/** Holds no transaction key, no other slot opens to the signer. */
export interface RelayTransferTerms {
  readonly ring: Address;
  readonly feePayer: Address;
  readonly signer: Address;
  readonly slots: readonly SlotOpening[];
  /** The signer's notes the transfer spends. */
  readonly nullifiers: readonly Bytes32[];
  /** The token accounts the fee payer creates ahead of the ring instruction. */
  readonly setup: readonly TokenAccountCreate[];
}

/** What one public funder agrees to, its own deposit legs alone and no slot or note. */
export interface RelayFunderTerms {
  readonly ring: Address;
  readonly feePayer: Address;
  readonly signer: Address;
  readonly legs: readonly FundedLeg[];
  /** The token accounts the fee payer creates ahead of the ring instruction. */
  readonly setup: readonly TokenAccountCreate[];
}

/** No `mint` on SOL. */
export interface FundedLeg {
  readonly mint?: Address;
  readonly amount: bigint;
}

export interface SlotOpening {
  readonly slot: number;
  readonly owner: Address;
  readonly nullifierPk: Bytes32;
  readonly mint: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly treeId: number;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
}

export interface TokenAccountCreate {
  readonly owner: Address;
  readonly mint: Address;
  readonly tokenProgram: Address;
}

export interface ExpectedPublicOwner {
  readonly kind: "publicOwner";
  readonly terms: RelayTransferTerms;
  readonly policy: Address;
  /** Finds SPP's account list inside the ring instruction's. */
  readonly ringAuth: Address;
  readonly setup: readonly Instruction[];
  /** From the ring account, a frame read under the wrong rail proves nothing. */
  readonly rail: RingRail;
  readonly knownNullifiers: readonly Bytes32[];
}

/** One public funder reading the frame's deposit legs against its terms, Rust `ExpectedFunder`. */
export interface ExpectedFunder {
  readonly kind: "funder";
  readonly terms: RelayFunderTerms;
  readonly policy: Address;
  readonly ringAuth: Address;
  readonly setup: readonly Instruction[];
  readonly rail: RingRail;
}

/** The sealing wallet hands each owner its terms and signs nothing itself. */
export interface ExpectedSealed {
  readonly kind: "sealed";
  readonly terms: readonly RelayTransferTerms[];
  /** One per key funding a deposit leg, the payer and an owner of the run left out. */
  readonly funders?: readonly RelayFunderTerms[];
  /** The opening of the frame's digest, handed to an outside co-signer. */
  readonly approval?: ApprovalOpening;
  readonly chargedOutflows: readonly OwnerDebit[];
}

/** An outside co-signer reads the proven bits or the totals, never a slot, Rust `CoSignerRule`. */
export type CoSignerRule =
  /** The proven mask alone, no opening and no digest. */
  | Readonly<{ kind: "threshold"; accepts: number }>
  | Readonly<{ kind: "exact"; approval: ExactApproval }>;

export interface ExactApproval {
  readonly opening: ApprovalOpening;
  /** An asset the totals name with no limit here is refused. */
  readonly limits: readonly ApprovalLimit[];
  /** The blinders of its earlier attempts, the only record of reuse the SDK has. */
  readonly seenBlinders: readonly Bytes32[];
}

/**
 * `peak` bounds one owner's outflow, `outflow` the sum over owners, `gross` each public row's
 * withdrawals with no deposit subtracted.
 */
export interface ApprovalLimit {
  readonly mint: Address;
  readonly peak: bigint;
  readonly outflow: bigint;
  readonly gross: bigint;
}

/** A co-signer the frame names, what it signs is the rule it holds, Rust `ExpectedCoSigner`. */
export interface ExpectedCoSigner {
  readonly kind: "coSigner";
  readonly ring: Address;
  readonly ringAuth: Address;
  readonly policy: Address;
  readonly feePayer: Address;
  readonly signer: Address;
  /** From the ring account, a frame read under the wrong rail proves nothing. */
  readonly rail: RingRail;
  readonly setup: readonly Instruction[];
  readonly rule: CoSignerRule;
}

export interface ExpectedEnroll {
  readonly kind: "enroll";
  readonly feePayer: Address;
  readonly policy: Address;
  readonly inputs: RelayEnrollInputs;
  readonly accounts: readonly AccountMeta[];
}

export type ExpectedRelayMessage =
  | ExpectedDelegate
  | ExpectedSealed
  | ExpectedPublicOwner
  | ExpectedFunder
  | ExpectedCoSigner
  | ExpectedEnroll;

type ExpectedFrame = ExpectedDelegate | ExpectedPublicOwner | ExpectedFunder | ExpectedCoSigner;

/** Rust `VerifiedMessage`, only a check builds one, over the private copy that check read. */
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
      // A kit keypair signs only an address the transaction lists.
      signatures: { [signer.address]: null },
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

/** Rust `RequestedAuthorityTransfer`, the delegate's ask and the notes its own openings allow. */
export interface RequestedAuthorityTransfer {
  readonly request: PrepareAuthorityTransferRequest;
  readonly quote: RelayQuote;
  /** The auditor key and the rail come from the ring account. */
  readonly config: DelegateRingConfig;
  readonly allowed: AllowedNullifiers;
}

export async function expectedDelegate({
  request,
  quote,
  config,
  allowed,
}: RequestedAuthorityTransfer): Promise<ExpectedDelegate> {
  const { transfer } = request;
  allowed.checkSources(transfer.sources);
  return Object.freeze({
    kind: "delegate",
    ring: request.ring,
    policy: await ringPolicyAddress(request.ring),
    feePayer: quote.feePayer,
    delegate: request.delegate,
    rail: ringRailOf(RingInstructionTag.authorityTransfer, config.mode),
    auditor: config.auditorPublicKey,
    txViewingKey: request.txViewingKey,
    sources: Object.freeze(transfer.sources.map(expectedOwner)),
    payments: Object.freeze(
      [
        ...transfer.payments.map((payment) => ({ kind: RecordKind.ring, payment })),
        ...transfer.exits.map((payment) => ({ kind: RecordKind.exit, payment })),
      ].map(({ kind, payment }) =>
        Object.freeze({
          kind,
          owner: expectedOwner(payment.recipient),
          mint: payment.mint,
          amount: payment.amount,
        }),
      ),
    ),
    withdrawals: Object.freeze(await Promise.all(transfer.withdrawals.map(expectedWithdrawal))),
    allowed,
  });
}

async function expectedWithdrawal(withdrawal: AuthorityWithdrawal): Promise<ExpectedWithdrawal> {
  const { mint, recipient, amount, tokenProgram } = withdrawal;
  if (mint === SOL_MINT) {
    if (tokenProgram !== undefined) throw mismatch("Data");
    return Object.freeze({
      transfer: { kind: "solWithdrawal" as const, amount },
      accounts: Object.freeze([SOL_INTERFACE, recipient]),
    });
  }
  if (tokenProgram === undefined) throw mismatch("Data");
  const [vault, bump] = await splInterfaceWithBump(mint);
  const tokenAccount = await getAssociatedTokenAddress(recipient, mint, tokenProgram);
  return Object.freeze({
    transfer: { kind: "splWithdrawal" as const, amount, splInterfaceBump: bump },
    accounts: Object.freeze([SHIELDED_POOL_CPI_AUTHORITY, mint, vault, tokenAccount, tokenProgram]),
  });
}

function expectedOwner(address: ShieldedAddress): ExpectedOwner {
  return Object.freeze({
    ownerKey: address.signingPublicKey.confidentialViewTag(),
    nullifierPk: address.nullifierPublicKey,
    viewingU: address.viewingPublicKey.u(),
  });
}

/** Rust's serde JSON byte for byte, an amount past the safe integers stays exact. */
export function encodeRelayTransferTerms(terms: RelayTransferTerms): string {
  return JSON.stringify({
    ring: terms.ring,
    feePayer: terms.feePayer,
    signer: terms.signer,
    slots: terms.slots.map((opening) => ({
      slot: opening.slot,
      owner: opening.owner,
      nullifierPk: encodeBase58(opening.nullifierPk),
      mint: opening.mint,
      amount: rawJson(opening.amount.toString()),
      blinding: encodeBase58(opening.blinding),
      treeId: opening.treeId,
      dataHash: encodeBase58(opening.dataHash),
      ringDataHash: encodeBase58(opening.ringDataHash),
    })),
    nullifiers: terms.nullifiers.map(encodeBase58),
    setup: terms.setup,
  });
}

/** An amount past the safe integers stays exact, Serde refuses `7.0` and `-0` for an integer. */
function parseWire(json: string): unknown {
  return JSON.parse(json, (key: string, value: unknown, context?: { source?: string }) => {
    if (typeof value !== "number") return value;
    if (!/^(0|[1-9][0-9]*)$/.test(context?.source ?? "")) throw mismatch("Undecodable");
    return key === "amount" ? BigInt(context?.source ?? "") : value;
  }) as unknown;
}

function decodeTokenAccountCreate(entry: unknown): TokenAccountCreate {
  const create = fields(entry, ["owner", "mint", "tokenProgram"]);
  return Object.freeze({
    owner: address(create["owner"] as string),
    mint: address(create["mint"] as string),
    tokenProgram: address(create["tokenProgram"] as string),
  });
}

export function decodeRelayTransferTerms(json: string): RelayTransferTerms {
  return withMismatch("Undecodable", () => {
    const wire = parseWire(json);
    const row = fields(wire, ["ring", "feePayer", "signer", "slots", "nullifiers", "setup"]);
    return Object.freeze({
      ring: address(row["ring"] as string),
      feePayer: address(row["feePayer"] as string),
      signer: address(row["signer"] as string),
      slots: (row["slots"] as readonly unknown[]).map(decodeSlotOpening),
      nullifiers: (row["nullifiers"] as readonly unknown[]).map(hash32),
      setup: (row["setup"] as readonly unknown[]).map(decodeTokenAccountCreate),
    });
  });
}

/** Rust's serde JSON byte for byte, `mint` is null on SOL. */
export function encodeRelayFunderTerms(terms: RelayFunderTerms): string {
  return JSON.stringify({
    ring: terms.ring,
    feePayer: terms.feePayer,
    signer: terms.signer,
    legs: terms.legs.map((leg) => ({
      mint: leg.mint ?? null,
      amount: rawJson(leg.amount.toString()),
    })),
    setup: terms.setup,
  });
}

export function decodeRelayFunderTerms(json: string): RelayFunderTerms {
  return withMismatch("Undecodable", () => {
    const row = fields(parseWire(json), ["ring", "feePayer", "signer", "legs", "setup"]);
    return Object.freeze({
      ring: address(row["ring"] as string),
      feePayer: address(row["feePayer"] as string),
      signer: address(row["signer"] as string),
      legs: (row["legs"] as readonly unknown[]).map(decodeFundedLeg),
      setup: (row["setup"] as readonly unknown[]).map(decodeTokenAccountCreate),
    });
  });
}

/** Serde reads an absent `Option` as `None`. */
function decodeFundedLeg(entry: unknown): FundedLeg {
  const named = typeof entry === "object" && entry !== null && "mint" in entry;
  const leg = fields(entry, named ? ["mint", "amount"] : ["amount"]);
  const mint = leg["mint"] ?? undefined;
  return Object.freeze({
    ...(mint === undefined ? {} : { mint: address(mint as string) }),
    amount: u64Amount(leg["amount"]),
  });
}

function decodeSlotOpening(value: unknown): SlotOpening {
  const row = fields(value, [
    "slot",
    "owner",
    "nullifierPk",
    "mint",
    "amount",
    "blinding",
    "treeId",
    "dataHash",
    "ringDataHash",
  ]);
  return Object.freeze({
    slot: integer(row["slot"], 0xffff_ffff),
    owner: address(row["owner"] as string),
    nullifierPk: hash32(row["nullifierPk"]),
    mint: address(row["mint"] as string),
    amount: u64Amount(row["amount"]),
    blinding: hash32(row["blinding"]),
    treeId: integer(row["treeId"], 0xffff),
    dataHash: hash32(row["dataHash"]),
    ringDataHash: hash32(row["ringDataHash"]),
  });
}

/** Rust `deny_unknown_fields` with every field required. */
function fields(value: unknown, names: readonly string[]): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null) throw mismatch("Undecodable");
  const present = Object.keys(value);
  if (present.length !== names.length || !names.every((name) => present.includes(name)))
    throw mismatch("Undecodable");
  return value as Readonly<Record<string, unknown>>;
}

function hash32(value: unknown): Bytes32 {
  const bytes = new Uint8Array(getBase58Encoder().encode(value as string));
  if (bytes.length !== 32) throw mismatch("Undecodable");
  return bytes as Bytes32;
}

function integer(value: unknown, limit: number): number {
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > limit)
    throw mismatch("Undecodable");
  return value as number;
}

function u64Amount(value: unknown): bigint {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX) throw mismatch("Undecodable");
  return value;
}

/** Rust serde JSON byte for byte, `RelayTransferTerms` hands nothing of it over. */
export function encodeApprovalOpening(opening: ApprovalOpening): string {
  return JSON.stringify({
    blinder: encodeBase58(opening.blinder),
    outputs: opening.outputs.map((slot) => ({
      asset: encodeBase58(slot.asset),
      peak: slot.peak,
      chargedOutflow: slot.chargedOutflow,
    })),
    public: opening.public.map((slot) => ({
      asset: encodeBase58(slot.asset),
      peak: slot.peak,
      outflow: slot.outflow,
      gross: slot.gross,
    })),
  });
}

export function decodeApprovalOpening(json: string): ApprovalOpening {
  return withMismatch("Undecodable", () => decodedApprovalOpening(JSON.parse(json)));
}

/** Rust `deny_unknown_fields`, an amount reads as text and is parsed at the check. */
function decodedApprovalOpening(wire: unknown): ApprovalOpening {
  const row = fields(wire, ["blinder", "outputs", "public"]);
  return Object.freeze({
    blinder: hash32(row["blinder"]),
    outputs: Object.freeze(
      (row["outputs"] as readonly unknown[]).map((entry): OutputTotalsOpening => {
        const slot = fields(entry, ["asset", "peak", "chargedOutflow"]);
        return Object.freeze({
          asset: hash32(slot["asset"]),
          peak: text(slot["peak"]),
          chargedOutflow: text(slot["chargedOutflow"]),
        });
      }),
    ),
    public: Object.freeze(
      (row["public"] as readonly unknown[]).map((entry): PublicTotalsOpening => {
        const slot = fields(entry, ["asset", "peak", "outflow", "gross"]);
        return Object.freeze({
          asset: hash32(slot["asset"]),
          peak: text(slot["peak"]),
          outflow: text(slot["outflow"]),
          gross: text(slot["gross"]),
        });
      }),
    ),
  });
}

function text(value: unknown): string {
  if (typeof value !== "string") throw mismatch("Undecodable");
  return value;
}

/** The ring account and the creates a relay puts ahead of the ring instruction. */
async function frameSetup(
  ring: Address,
  feePayer: Address,
  creates: readonly TokenAccountCreate[],
): Promise<Readonly<{ policy: Address; setup: readonly Instruction[] }>> {
  const [policy, setup] = await Promise.all([
    ringPolicyAddress(ring),
    Promise.all(
      creates.map((create) =>
        getCreateAssociatedTokenAccountInstructionAsync({
          payer: feePayer,
          owner: create.owner,
          mint: create.mint,
          tokenProgram: create.tokenProgram,
        }),
      ),
    ),
  ]);
  return { policy, setup: Object.freeze(setup) };
}

export async function expectedPublicOwner(
  input: Readonly<{
    terms: RelayTransferTerms;
    config: DelegateRingConfig;
    knownNotes: readonly Pick<WalletUtxo, "nullifier">[];
  }>,
): Promise<ExpectedPublicOwner> {
  const { terms, config } = input;
  return Object.freeze({
    kind: "publicOwner",
    terms,
    ringAuth: await ringAuthAddress(terms.ring),
    ...(await frameSetup(terms.ring, terms.feePayer, terms.setup)),
    rail: ringRailOf(RingInstructionTag.transfer, config.mode),
    knownNullifiers: Object.freeze(input.knownNotes.map((note) => note.nullifier)),
  });
}

export async function expectedFunder(
  input: Readonly<{ terms: RelayFunderTerms; config: Pick<RingPolicy, "mode"> }>,
): Promise<ExpectedFunder> {
  const { terms, config } = input;
  return Object.freeze({
    kind: "funder",
    terms,
    ringAuth: await ringAuthAddress(terms.ring),
    ...(await frameSetup(terms.ring, terms.feePayer, terms.setup)),
    rail: ringRailOf(RingInstructionTag.transfer, config.mode),
  });
}

export async function expectedCoSigner(
  input: Readonly<{
    ring: Address;
    feePayer: Address;
    signer: Address;
    config: Pick<RingPolicy, "mode">;
    setup: readonly TokenAccountCreate[];
    rule: CoSignerRule;
  }>,
): Promise<ExpectedCoSigner> {
  return Object.freeze({
    kind: "coSigner",
    ring: input.ring,
    ringAuth: await ringAuthAddress(input.ring),
    feePayer: input.feePayer,
    signer: input.signer,
    ...(await frameSetup(input.ring, input.feePayer, input.setup)),
    rail: ringRailOf(RingInstructionTag.transfer, input.config.mode),
    rule: input.rule,
  });
}

export function checkRelayMessage(
  expected: ExpectedRelayMessage,
  message: Uint8Array,
  signer: Address,
): VerifiedRelayMessage {
  const snapshot = message.slice();
  if (expected.kind === "enroll") return checkEnrollSnapshot(expected, snapshot);
  if (expected.kind === "sealed") throw mismatch("Unrequested");
  const envelope = frameEnvelope(expected, signer, frameTag(expected));
  const { data, accounts } = open(envelope, snapshot);
  checkFrame(expected, signer, data, accounts);
  return new VerifiedRelayMessage(VERIFIED, envelope.signer, snapshot);
}

export async function expectedEnroll(
  inputs: RelayEnrollInputs,
  feePayer: Address,
): Promise<ExpectedEnroll> {
  const [policy, proved] = await Promise.all([
    ringPolicyAddress(inputs.ringProgramId),
    relayEnrollInstruction(inputs, feePayer),
  ]);
  return Object.freeze({
    kind: "enroll",
    feePayer,
    policy,
    inputs,
    accounts: proved.accounts ?? [],
  });
}

function checkEnrollSnapshot(expected: ExpectedEnroll, message: Uint8Array): VerifiedRelayMessage {
  const envelope: Envelope = {
    program: STORAGE_PROGRAM_ID,
    policy: expected.policy,
    units: ENROLL_COMPUTE_UNITS,
    feePayer: expected.feePayer,
    signer: expected.inputs.owner,
    setup: [],
  };
  const { data, accounts } = open(envelope, message);
  if (!sameAccounts(accounts, expected.accounts)) throw mismatch("Accounts");
  const signed = enrollRequestDigest({ ...expected.inputs, instructionData: data });
  if (!equalBytes(signed, enrollRequestDigest(expected.inputs))) throw mismatch("Data");
  return new VerifiedRelayMessage(VERIFIED, envelope.signer, message);
}

function frameTag(expected: ExpectedFrame): RingInstructionTag {
  return expected.kind === "delegate"
    ? RingInstructionTag.authorityTransfer
    : RingInstructionTag.transfer;
}

function frameEnvelope(
  expected: ExpectedFrame,
  signer: Address,
  tag: RingInstructionTag,
): Envelope {
  if (expected.kind === "delegate")
    return {
      program: expected.ring,
      policy: expected.policy,
      units: ringComputeUnitLimit(tag),
      feePayer: expected.feePayer,
      signer: expected.delegate,
      setup: [],
    };
  if (expected.kind === "coSigner") {
    if (expected.signer !== signer) throw mismatch("Unrequested");
    return {
      program: expected.ring,
      policy: expected.policy,
      units: ringComputeUnitLimit(tag),
      feePayer: expected.feePayer,
      signer,
      setup: expected.setup,
    };
  }
  const { terms, policy, setup } = expected;
  if (terms.signer !== signer) throw mismatch("Unrequested");
  return {
    program: terms.ring,
    policy,
    units: ringComputeUnitLimit(tag),
    feePayer: terms.feePayer,
    signer,
    setup,
  };
}

function checkFrame(
  expected: ExpectedFrame,
  signer: Address,
  data: Uint8Array,
  accounts: readonly AccountMeta[],
): void {
  const tag = frameTag(expected);
  if (data[0] !== tag) throw mismatch("Data");
  const frame = withMismatch("Data", () => RingTransactData.parse(data.subarray(1), expected.rail));
  if (expected.kind === "funder") {
    checkFundedLegs(expected, frame, accounts);
    if (!readsOnly(frameEnvelope(expected, signer, tag), accounts.slice(0, 1)))
      throw mismatch("Accounts");
    return;
  }
  if (expected.kind === "delegate") checkMoved(expected, frame, accounts);
  else if (expected.kind === "coSigner") checkCoSignerRule(expected.rule, frame);
  else checkOpenings(expected, frame, accounts);
  const envelope = frameEnvelope(expected, signer, tag);
  const named = accounts.filter((meta) => meta.address === envelope.signer);
  const signsOnce =
    named.length === 1 &&
    named.every((meta) => isSignerRole(meta.role) && !isWritableRole(meta.role));
  if (!signsOnce || !readsOnly(envelope, accounts.slice(0, 1))) throw mismatch("Accounts");
  // The rule reads an approval and nothing else. A signature named in SPP's list also moves the
  // key's own funds or authorizes its notes and data outputs, none of it in the rule.
  if (expected.kind === "coSigner") {
    const spp = ringAuthSlot(expected.ringAuth, accounts) - RING_TRANSACT_RING_CONFIG_INDEX;
    if (accounts.slice(spp).some((meta) => meta.address === envelope.signer))
      throw mismatch("Accounts");
  }
}

/** The proof binds each record to its slot under the key the frame publishes. */
function checkMoved(
  expected: ExpectedDelegate,
  frame: RingTransactData,
  accounts: readonly AccountMeta[],
): void {
  // Owner tags alone, the message holds no blinding, a hidden frame's tags bind nothing.
  checkTransactionKey(expected.txViewingKey, frame);
  if (frame.hasData) throw mismatch("Data");
  checkWithdrawals(expected, frame, accounts);
  const { records, envelope } = openStream(expected.txViewingKey, expected.auditor, frame);
  // 2. Matching outputs bind no input, each proven note position answers to the requested openings.
  if (!expected.allowed.spendsOnly(frame.nullifiers.slice(0, envelope.realInputs)))
    throw mismatch("SpendsUnrequestedNote");
  // 3. Each live record pays one requested payment or returns change to a requested source.
  const owns = (owner: ExpectedOwner, record: AuditRecord): boolean =>
    equalBytes(record.ownerKey, owner.ownerKey) &&
    equalBytes(record.nullifierPk, owner.nullifierPk);
  const unpaid = [...expected.payments];
  records.forEach((record, slot) => {
    if (record.kind === RecordKind.dummy) return;
    const paid = unpaid.findIndex(
      (payment) =>
        record.kind === payment.kind &&
        record.mint === payment.mint &&
        record.amount === payment.amount &&
        owns(payment.owner, record),
    );
    if (paid < 0) {
      if (
        record.kind !== RecordKind.ring ||
        !expected.sources.some((source) => owns(source, record))
      )
        throw mismatch("Recipients");
      return;
    }
    const payment = unpaid[paid];
    // Rust `swap_remove`, the order decides the equal payment a later record takes.
    unpaid[paid] = unpaid[unpaid.length - 1] as ExpectedPayment;
    unpaid.pop();
    const tag = frame.outputs[slot]?.ownerTag;
    const expectedTag =
      payment?.kind === RecordKind.exit
        ? payment.owner.ownerKey
        : payment !== undefined && !isAnonymousFrame(frame.rail)
          ? confidentialSlotTag(payment.owner.viewingU)
          : undefined;
    if (expectedTag !== undefined && (tag === undefined || !equalBytes(tag, expectedTag)))
      throw mismatch("Recipients");
  });
  if (unpaid.length !== 0) throw mismatch("Recipients");
}

function checkWithdrawals(
  expected: ExpectedDelegate,
  frame: RingTransactData,
  accounts: readonly AccountMeta[],
): void {
  const window = settlementWindow(frame, accounts);
  const unpaid = [...expected.withdrawals];
  let at = window.start;
  for (const transfer of frame.interfaceTransfers) {
    const group = accounts.slice(at, at + SETTLEMENT_ACCOUNTS[transfer.kind]);
    at += group.length;
    const paid = unpaid.findIndex((withdrawal) => {
      const wanted = withdrawal.transfer;
      return (
        transfer.kind === wanted.kind &&
        transfer.amount === wanted.amount &&
        (transfer.kind !== "splWithdrawal" ||
          (wanted.kind === "splWithdrawal" &&
            transfer.splInterfaceBump === wanted.splInterfaceBump)) &&
        withdrawal.accounts.length === group.length &&
        withdrawal.accounts.every((address, index) => group[index]?.address === address)
      );
    });
    if (paid < 0) throw mismatch("Data");
    unpaid.splice(paid, 1);
  }
  if (unpaid.length !== 0) throw mismatch("Data");
}

function checkTransactionKey(txViewingKey: Bytes32, frame: RingTransactData): void {
  const key = withMismatch("TransactionKey", () =>
    canonicalViewingKey(txViewingKey.slice() as Bytes32),
  );
  const published = key.publicKey().u();
  key.destroy();
  if (!equalBytes(frame.txViewingU, published)) throw mismatch("TransactionKey");
}

function openStream(
  txViewingKey: Bytes32,
  auditor: X25519PublicKey,
  frame: RingTransactData,
): RingDisclosure {
  return withMismatch("Data", () => {
    const opened = openSealedDisclosure(txViewingKey, auditor, {
      layout: RingTransactData.streamLayout(frame),
      salt: frame.salt,
      message: {
        ephemeralPublicKey: x25519FromU(frame.txViewingU),
        envelope: frame.envelope,
        records: frame.outputs.map((output) => output.record),
      },
    });
    const { envelope } = opened;
    canonicalViewingKey(envelope.txViewingSecret.slice() as Bytes32).destroy();
    envelope.txViewingSecret.fill(0);
    if (
      envelope.evidence.kind === "entry" &&
      !envelope.evidence.inputs.every(
        (input) =>
          isCanonicalField(input.nullifierPk) &&
          isCanonicalField(input.blinding) &&
          isCanonicalField(input.dataHash) &&
          isCanonicalField(input.ringDataHash),
      )
    )
      throw mismatch("Data");
    return opened;
  });
}

/** The signer's openings stay selective, the proof supplies only how many data outputs exist. */
function checkOpenings(
  expected: ExpectedPublicOwner,
  frame: RingTransactData,
  accounts: readonly AccountMeta[],
): void {
  const { terms, knownNullifiers } = expected;
  if (terms.slots.length === 0 && terms.nullifiers.length === 0) throw mismatch("Unrequested");
  // 1. Each opening rebuilds the commitment published at its slot and names the signer. Past the
  // loop a slot index stands for one real output of the signer, so the count below cannot read
  // another owner's slot or a preimage the sender made up.
  for (const opening of terms.slots) {
    const published = frame.outputs[opening.slot];
    if (
      published === undefined ||
      opening.owner !== terms.signer ||
      !equalBytes(
        // An exit commits no ring, a ring id here would refuse every exit the owner holds.
        withMismatch("Recipients", () =>
          openingHash(opening, published.body.kind === "exit" ? undefined : terms.ring),
        ),
        published.hash,
      )
    )
      throw mismatch("Recipients");
  }
  // 2. The circuit counts the live slots the signer owns with a nonzero `data_hash`, per entry of
  // the run `signers.Chain` binds. Equality with the distinct opened slots closes the omission step
  // 1 leaves open, a second data output the sender keeps out of the terms. Slots dedupe a repeated
  // opening, the filter keeps an ordinary payment from standing in for a data output, and
  // `ringDataHash` stays outside since SPP asks no owner signature for it. A member past the last
  // packed entry reads zero and the circuit holds it to no data output.
  const opened = new Set(
    terms.slots.filter((opening) => !isZero(opening.dataHash)).map((opening) => opening.slot),
  ).size;
  const proved = signerDataCountAt(
    frame.extensions.signerDataCounts ?? 0n,
    signerRunEntry(expected, frame, accounts),
  );
  if (opened !== proved) throw mismatch("DataOutputCount");
  const among = (list: readonly Uint8Array[], nullifier: Uint8Array): boolean =>
    list.some((held) => equalBytes(held, nullifier));
  // 3. A named note the wallet cannot place means no list stood behind the check.
  if (
    !terms.nullifiers.every(
      (named) => among(frame.nullifiers, named) && among(knownNullifiers, named),
    )
  )
    throw mismatch("Data");
  if (
    frame.nullifiers.some(
      (spent) => among(knownNullifiers, spent) && !among(terms.nullifiers, spent),
    )
  )
    throw mismatch("SpendsUnnamedNote");
}

function checkCoSignerRule(rule: CoSignerRule, frame: RingTransactData): void {
  if (rule.kind === "exact") {
    checkExactApproval(rule.approval, frame);
    return;
  }
  if ((frame.approval & ~rule.accepts) !== 0) throw mismatch("ApprovalMaskUnaccepted");
}

/**
 * The digest binds the totals, the limits then read them with no slot opened. A ring with no own
 * registry runs no outflow section and its circuit refuses a nonzero digest, such a frame reads as
 * `MissingApprovalDigest` and exact approval stays out of reach there, the proven bits remain the
 * only rule a co-signer can apply to it.
 */
function checkExactApproval(exact: ExactApproval, frame: RingTransactData): void {
  const { opening, limits, seenBlinders } = exact;
  const digest = frame.extensions.approvalTotals;
  if (digest === undefined) throw mismatch("MissingApprovalDigest");
  // 1. The chain hashes a flat run of three fields per output and four per public slot with no
  // length in it, so `4a` more output rows and `3a` fewer public rows rebuild the same digest with
  // every column shifted. Only the key's exact counts make the limits below read a peak as a peak,
  // and they hold ahead of hashing since the rows come from the sealing wallet.
  if (opening.outputs.length !== frame.nOut || opening.public.length !== N_PUBLIC_SLOTS)
    throw mismatch("ApprovalOpeningLayout");
  // 2. The circuit accepts any blinder, and a zero one lets anyone test guessed totals against the
  // public digest. Freshness and hiding rest on the reader's refusal alone.
  if (isZero(opening.blinder)) throw mismatch("ZeroApprovalBlinder");
  if (seenBlinders.some((seen) => equalBytes(seen, opening.blinder)))
    throw mismatch("ReusedApprovalBlinder");
  // 3. Rust's hasher errors at or past the modulus. A value the TS hasher reduced would open the
  // digest under a blinder `seenBlinders` does not hold, so each input is held canonical here.
  const totals = openingTotals(opening);
  if (
    totals === undefined ||
    !isCanonicalField(opening.blinder) ||
    ![...totals.outputs, ...totals.publicSlots].every((slot) => isCanonicalField(slot.asset)) ||
    !equalBytes(
      withMismatch("FalseApprovalOpening", () => totals.commitment(opening.blinder)),
      digest,
    )
  )
    throw mismatch("FalseApprovalOpening");
  // 4. The commitment bound `totals`, every nonzero asset they name now needs a limit.
  for (const slot of [...totals.outputs, ...totals.publicSlots]) {
    if (isZero(slot.asset)) continue;
    const limit = withMismatch("ApprovalOverLimit", () =>
      limits.find((entry) => equalBytes(memberOfAsset(entry.mint), slot.asset)),
    );
    // A deposit the sender funds offsets its own withdrawal in peak and outflow, a public row's
    // gross alone shows what leaves through it.
    if (
      limit === undefined ||
      totals.publicSlots.some(
        (row) => equalBytes(row.asset, slot.asset) && row.gross > limit.gross,
      ) ||
      totals.peakOf(slot.asset) > limit.peak ||
      totals.outflowOf(slot.asset) > limit.outflow
    )
      throw mismatch("ApprovalOverLimit");
  }
}

/**
 * The signer's entry in the run the program hashes into `signers.Chain`. The ring auth PDA finds
 * SPP's list with no read of the registries or co-signers ahead of it, since the program refuses a
 * second copy anywhere in that list and neither a registry slot nor a signer slot can hold the PDA.
 * A misplaced run would read another signer's count, the same window the program takes closes that.
 * The counts index the run `SignerSet` keeps, first occurrences only, a raw position past a repeat
 * reads another entry and lets a signer pass over its own omitted output.
 */
function signerRunEntry(
  expected: ExpectedPublicOwner,
  frame: RingTransactData,
  accounts: readonly AccountMeta[],
): number {
  const ringAuth = ringAuthSlot(expected.ringAuth, accounts);
  const trees = frame.inputTrees.kind === "one" ? 1 : 2;
  const start = ringAuth + 1 + trees + frame.nullifiers.length;
  const window = accounts.slice(start, settlementWindow(frame, accounts).start);
  const first = window.findIndex((meta) => meta.address === expected.terms.signer);
  if (first < 0) throw mismatch("Accounts");
  // SPP and `SignerSet::new` deduplicate the window by first occurrence and the counts index that
  // run. Under `[X, X, V]` a raw position reads V past its entry, finds zero, and V signs for a data
  // output its terms leave out. The program accepts a repeat, so none is refused.
  return new Set(window.slice(0, first).map((meta) => meta.address)).size;
}

/** The one ring auth PDA the program admits in SPP's list. */
function ringAuthSlot(ringAuth: Address, accounts: readonly AccountMeta[]): number {
  const copies = accounts.flatMap((meta, at) => (meta.address === ringAuth ? [at] : []));
  const [slot] = copies;
  if (slot === undefined || copies.length !== 1 || slot < RING_TRANSACT_RING_CONFIG_INDEX)
    throw mismatch("Accounts");
  return slot;
}

/** The settlement groups end ahead of the cached selector's accounts, Rust `settlement_accounts`. */
function settlementWindow(
  frame: RingTransactData,
  accounts: readonly AccountMeta[],
): Readonly<{ start: number; end: number }> {
  const end = accounts.length - cacheAccountCount(frame.extensions.cache);
  const start =
    end -
    frame.interfaceTransfers.reduce(
      (total, transfer) => total + SETTLEMENT_ACCOUNTS[transfer.kind],
      0,
    );
  if (start < 0) throw mismatch("Accounts");
  return { start, end };
}

/** The signature authorizes every position naming the key, so the check holds both sides. */
function checkFundedLegs(
  expected: ExpectedFunder,
  frame: RingTransactData,
  accounts: readonly AccountMeta[],
): void {
  const { terms } = expected;
  if (terms.legs.length === 0) throw mismatch("Unrequested");
  const spp = ringAuthSlot(expected.ringAuth, accounts) - RING_TRANSACT_RING_CONFIG_INDEX;
  const window = settlementWindow(frame, accounts);
  if (window.start < spp) throw mismatch("Accounts");
  // 1. The legs of the frame that take the key as funder match the terms exactly, a leg the sender
  // adds would draw funds the signer never agreed to.
  const unfunded = [...terms.legs];
  let funded = 0;
  let at = window.start;
  for (const transfer of frame.interfaceTransfers) {
    const group = accounts.slice(at, at + SETTLEMENT_ACCOUNTS[transfer.kind]);
    at += SETTLEMENT_ACCOUNTS[transfer.kind];
    const position = FUNDER_POSITION[transfer.kind];
    if (position === undefined || group[position]?.address !== terms.signer) continue;
    const mintAt = MINT_POSITION[transfer.kind];
    const mint = mintAt === undefined ? undefined : group[mintAt]?.address;
    const held = unfunded.findIndex((leg) => leg.mint === mint && leg.amount === transfer.amount);
    if (held < 0) throw mismatch("FunderLegs");
    unfunded.splice(held, 1);
    funded += 1;
  }
  if (unfunded.length !== 0) throw mismatch("FunderLegs");
  // 2. Past the legs the key appears nowhere. A run entry would authorize its data outputs and spent
  // notes under one signature, the sharper authority the terms never name.
  const named = accounts.filter((meta) => meta.address === terms.signer);
  if (named.length !== funded || !named.every((meta) => isSignerRole(meta.role)))
    throw mismatch("Accounts");
}

export function openingHash(opening: SlotOpening, ring: Address | undefined): Bytes32 {
  return new Utxo({
    owner: ShieldedPublicKey.fromEd25519(addressBytes(opening.owner) as Bytes32),
    asset: opening.mint,
    amount: opening.amount,
    blinding: opening.blinding,
    ...(ring === undefined ? {} : { ringProgramId: ring }),
  })
    .proofInput(opening.nullifierPk, opening.treeId, opening.dataHash, opening.ringDataHash)
    .hash();
}

export function mismatch(reason: RelayMessageMismatch): RingError {
  return new RingError("RING_RELAY_MESSAGE_INVALID", { details: { mismatch: reason } });
}

interface Envelope {
  readonly program: Address;
  readonly policy: Address;
  readonly units: number;
  readonly feePayer: Address;
  readonly signer: Address;
  /** Ahead of the ring instruction, exactly these. */
  readonly setup: readonly Instruction[];
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
    config.computeUnitLimit <= envelope.units &&
    config.loadedAccountsDataSizeLimit !== undefined &&
    config.loadedAccountsDataSizeLimit <= LOADED_ACCOUNTS_DATA_SIZE_LIMIT &&
    config.heapSize === undefined;
  if (!withinBudget) throw mismatch("Budget");
  const instruction = message.instructions.at(-1);
  const leading = message.instructions.slice(0, -1);
  if (instruction === undefined) throw mismatch("Instructions");
  // In named order, an omitted create costs the signer nothing, a transfer to a missing account only fails.
  let next = 0;
  const sameSetup = leading.every((found) => {
    const accounts = found.accounts ?? [];
    for (; next < envelope.setup.length; next += 1) {
      const named = envelope.setup[next]!;
      const namedAccounts = named.accounts ?? [];
      if (
        found.programAddress === named.programAddress &&
        equalBytes(new Uint8Array(found.data ?? []), new Uint8Array(named.data ?? [])) &&
        accounts.length === namedAccounts.length &&
        accounts.every((meta, at) => meta.address === namedAccounts[at]?.address)
      ) {
        next += 1;
        return true;
      }
    }
    return false;
  });
  if (!sameSetup) throw mismatch("Instructions");
  if (instruction.programAddress !== envelope.program) throw mismatch("Program");
  return {
    data: new Uint8Array(instruction.data ?? []),
    accounts: instruction.accounts ?? [],
  };
}

/**
 * Rust `Envelope::reads_only`. The ring account first, then accounts that never name the signer and
 * compile writable only where the forwarded list writes the same address.
 */
function readsOnly(
  envelope: Envelope,
  prefix: readonly AccountMeta[],
  forwarded: readonly AccountMeta[] = [],
): boolean {
  const [ring, ...rest] = prefix;
  const forwardedWrite = (meta: AccountMeta): boolean =>
    forwarded.some((spp) => spp.address === meta.address && isWritableRole(spp.role));
  return (
    ring !== undefined &&
    ring.address === envelope.policy &&
    !isSignerRole(ring.role) &&
    !isWritableRole(ring.role) &&
    rest.every(
      (meta) =>
        (!isWritableRole(meta.role) || forwardedWrite(meta)) && meta.address !== envelope.signer,
    )
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

/** Rust `InterfaceTransfer::settlement_account_count`. */
const SETTLEMENT_ACCOUNTS: Readonly<Record<InterfaceTransfer["kind"], number>> = Object.freeze({
  solDeposit: 2,
  solWithdrawal: 2,
  splDeposit: 5,
  splWithdrawal: 5,
});

/** Rust `funder_account_position`, a withdrawal names no funder. */
const FUNDER_POSITION: Readonly<Partial<Record<InterfaceTransfer["kind"], number>>> = Object.freeze(
  { solDeposit: 1, splDeposit: 2 },
);

/** Rust `InterfaceTransfer::mint_account_position`, a SOL leg names no mint. */
const MINT_POSITION: Readonly<Partial<Record<InterfaceTransfer["kind"], number>>> = Object.freeze({
  splDeposit: 0,
  splWithdrawal: 1,
});

/** The read cache then the write cache and its writer, Rust `settlement_accounts`. */
function cacheAccountCount(cache: FrameExtensions["cache"]): number {
  if (cache === undefined) return 0;
  const [none] = NO_CACHE_WRITES;
  const [first] = cache.writeSlots;
  const writes = first !== undefined && (first.output !== none?.output || first.slot !== none.slot);
  return (cache.readBitmap !== 0n ? 1 : 0) + (writes ? 2 : 0);
}
