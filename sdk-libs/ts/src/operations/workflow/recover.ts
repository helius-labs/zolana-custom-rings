import type { Address } from "@solana/kit";

import { initializePoseidon } from "@heliuslabs/spr";
import type { IndexerReader } from "@heliuslabs/spr/client";
import { PAGE_LIMIT, ZERO_NULLIFIER_PK, bytesKey, equalBytes } from "@heliuslabs/spr/internal";
import type { Bytes32, RequestContext } from "@heliuslabs/spr/interface";
import { ownerHash } from "@heliuslabs/spr/keypair";
import type { NullifierKey, ShieldedAddress, X25519Keypair } from "@heliuslabs/spr/keypair";
import type {
  AssetRegistry,
  IndexedShieldedTransaction,
  OutputContext,
  WalletUtxo,
} from "@heliuslabs/spr/transaction";
import { Utxo } from "@heliuslabs/spr/transaction";

import { nextHistoryToken } from "../../rpc/history.js";
import {
  KnownUtxoIndex,
  auditConfirmedRingHistory,
  knownUtxoOwnerHash,
  openedUtxo,
  type KnownUtxo,
  type RingAuditReader,
} from "../audit/audit.js";
import { RingError } from "../../protocol/error.js";
import { RowOrigins } from "../audit/row-origins.js";
import { readRingPages, scanLimits } from "../../rpc/history.js";
import type { SkippedRingTransaction } from "../../rpc/ring-rpc.js";
import {
  RpcTransactionOrigin,
  type ConfirmedRingTransaction,
  type TransactionOrigin,
} from "../../protocol/transaction/origin.js";
import { outputTreeId } from "../../protocol/membership/trees.js";
import { zeroKeyNullifier } from "../../state/exposed-notes.js";

export type RingRecoveryClient = RingAuditReader;

export const RECOVERY_INPUT_SAMPLE_LIMIT = 64;

/** Mirrors Rust `MemberRecovery`, a source member's notes from the auditor's view and its nullifier key. */
export interface RingRecoveryParams {
  readonly client: RingRecoveryClient;
  readonly ringProgramId: Address;
  readonly auditor: X25519Keypair;
  readonly source: ShieldedAddress;
  readonly nullifierKey: NullifierKey;
  readonly assets: AssetRegistry;
  readonly origin?: TransactionOrigin;
  readonly pageSize?: number;
  /** Pages one call reads before it pauses. */
  readonly maxPages?: number;
  /** Continues after the last page it covers. */
  readonly progress?: RingRecoveryProgress;
}

/** Mirrors Rust `RecoveryStep`. */
export type RingRecoveryStep =
  | Readonly<{ kind: "complete"; notes: RecoveredRingNotes }>
  | Readonly<{ kind: "paused"; progress: RingRecoveryProgress }>;

// Set in the static block of `RingRecoveryProgress`, no other code reads its state.
let pausedAt: (cursor: string, member: Bytes32, state: RecoveryState) => RingRecoveryProgress;
let resumedState: (progress: RingRecoveryProgress, member: Bytes32) => RecoveryState;

/** Mirrors Rust `RecoveryProgress`, `cursor` prints as Rust `HistoryCursor` and no resume changes its state. */
export class RingRecoveryProgress {
  /** The source's owner hash, the ring stays bound through `cursor`. */
  readonly member: Bytes32;
  readonly #state: RecoveryState;

  private constructor(
    readonly cursor: string,
    member: Bytes32,
    state: RecoveryState,
  ) {
    this.member = Uint8Array.from(member) as Bytes32;
    this.#state = state;
    Object.freeze(this);
  }

  static {
    pausedAt = (cursor, member, state) => new RingRecoveryProgress(cursor, member, state);
    resumedState = (progress, member) => {
      if (!equalBytes(progress.member, member))
        throw new RingError("RING_RECOVERY_PROGRESS_MISMATCH");
      return progress.#state;
    };
  }
}

/** Mirrors Rust `RecoveredNotes`, verified unspent notes with the coverage left unresolved. */
export interface RecoveredRingNotes {
  readonly notes: readonly WalletUtxo[];
  /** Commitments that cannot yet become spendable notes, unknown mints among them. */
  readonly unopened: readonly Bytes32[];
  /** Verified mints missing from the asset registry, their notes stay in `unopened`. */
  readonly unknownMints: readonly Address[];
  /** First unmatched nullifiers, limited by `RECOVERY_INPUT_SAMPLE_LIMIT`. */
  readonly unseenInputs: readonly Bytes32[];
  readonly unseenInputCount: bigint;
}

/** Applies each closed slot as its page lands and pauses at the page cap. */
export async function recoverRingMemberNotes(
  input: RingRecoveryParams,
  context?: RequestContext,
): Promise<RingRecoveryStep> {
  await initializePoseidon();
  if (!equalBytes(input.nullifierKey.publicKey(), input.source.nullifierPublicKey))
    throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
  const member = input.source.ownerHash();
  let state = input.progress === undefined ? EMPTY_STATE : resumedState(input.progress, member);
  const origin = input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc);
  const rows = new RowOrigins(origin, input.ringProgramId, context);
  // 1. One page at a time, the cursor names the last row read and the next call starts after it.
  const reach = await readRingPages(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      limits: scanLimits({
        pageSize: input.pageSize ?? Number(PAGE_LIMIT),
        maxPages: input.maxPages,
      }),
      ...(input.progress === undefined ? {} : { cursor: input.progress.cursor }),
    },
    async (page) => {
      const read = [...state.openSlot];
      for (const indexed of page) {
        const confirmed = await rows.read(indexed);
        if (confirmed !== undefined) read.push(confirmed);
      }
      refuseSkipped(rows.skipped);
      const { closed, open } = closeSlots(read);
      state = applyRows(input, state, closed, rows).settle(open);
    },
    context,
  );
  // 2. A page with more holds the last slot back, the terminal page closes it.
  if (reach.nextCursor !== undefined) {
    return Object.freeze({ kind: "paused", progress: pausedAt(reach.nextCursor, member, state) });
  }
  state = applyRows(input, state, state.openSlot, rows).settle([]);
  return Object.freeze({
    kind: "complete",
    notes: Object.freeze({
      notes: Object.freeze([...state.candidates]),
      unopened: Object.freeze(state.unresolved.map(({ commitment }) => commitment)),
      unknownMints: Object.freeze([...state.unknownMints]),
      unseenInputs: Object.freeze([...state.unseenInputs]),
      unseenInputCount: state.unseenInputCount,
    }),
  });
}

/** Sizes a paused recovery holds, kept out of the package index. */
export function retainedRecovery(progress: RingRecoveryProgress) {
  const state = resumedState(progress, progress.member);
  return Object.freeze({
    notes: state.candidates.length + state.unresolved.length,
    claimed: state.claimed.size,
    unseenInputs: state.unseenInputs.length,
    openSlot: state.openSlot.length,
  });
}

interface Unresolved {
  readonly commitment: Bytes32;
  readonly nullifier: Bytes32;
}

/** Mirrors Rust `RecoveryState`, a batch never writes it and no ring opening outlives the batch. */
interface RecoveryState {
  readonly candidates: readonly WalletUtxo[];
  /** Source commitments without a spendable opening, with their nullifiers. */
  readonly unresolved: readonly Unresolved[];
  /** Every source commitment claimed, spent ones too, a row served again adds no note. */
  readonly claimed: ReadonlySet<string>;
  readonly unknownMints: ReadonlySet<Address>;
  readonly unseenInputs: readonly Bytes32[];
  readonly unseenInputCount: bigint;
  /** The indexer orders one slot by signature, a later row of the slot can create the note an earlier row spends. */
  readonly openSlot: readonly ConfirmedRingTransaction[];
}

const EMPTY_STATE: RecoveryState = Object.freeze({
  candidates: Object.freeze([]),
  unresolved: Object.freeze([]),
  claimed: new Set<string>(),
  unknownMints: new Set<Address>(),
  unseenInputs: Object.freeze([]),
  unseenInputCount: 0n,
  openSlot: Object.freeze([]),
});

/** A row left unread can hold a source note or its spend, Rust `refuse_skipped`. */
function refuseSkipped(skipped: readonly SkippedRingTransaction[]): void {
  const row = skipped[0];
  if (row !== undefined)
    throw new RingError("RING_RECOVERY_INCOMPLETE", {
      details: {
        reason: "skipped row",
        transactionId: row.signature,
        eventIndex: row.eventIndex,
      },
    });
}

/** Holds back the highest slot read, a later page can add rows to it. */
function closeSlots(rows: readonly ConfirmedRingTransaction[]): Readonly<{
  closed: ConfirmedRingTransaction[];
  open: ConfirmedRingTransaction[];
}> {
  const last = rows.reduce<bigint | undefined>(
    (max, { transaction }) =>
      max === undefined || transaction.slot > max ? transaction.slot : max,
    undefined,
  );
  if (last === undefined) return { closed: [], open: [] };
  return {
    closed: rows.filter(({ transaction }) => transaction.slot < last),
    open: rows.filter(({ transaction }) => transaction.slot >= last),
  };
}

/** Rows of closed slots, every note one of them spends opens in them or in an earlier batch. */
function applyRows(
  input: RingRecoveryParams,
  before: RecoveryState,
  batch: readonly ConfirmedRingTransaction[],
  rows: RowOrigins,
): BatchNotes {
  const found = new BatchNotes(before);
  // 1. Every row is a transfer or a merge, a deposit lands as a transfer output.
  const audited = auditConfirmedRingHistory({
    auditor: input.auditor,
    ringProgramId: input.ringProgramId,
    history: batch,
    rows,
    known: found.openings,
  });
  refuseSkipped(rows.skipped);
  // 2. Outputs before spends, the batch's merges and inputs need the notes they consume.
  for (const transaction of audited) {
    for (const { nullifier, opening } of transaction.inputs)
      // Rust `InputOpening::Real`, a batch opening never hides a spend, the result stays the same at any page size.
      if (
        opening.kind === "unresolvedReal" ||
        (opening.kind === "opened" && opening.ring?.kind === "ring")
      )
        found.realInputs.push(nullifier);
    // An unopened slot could hide a source UTXO.
    const [unopened] = transaction.payloadErrors;
    if (unopened !== undefined)
      throw new RingError("RING_AUDIT_OUTPUT_MISMATCH", {
        details: { reason: "unopened", slotIndex: unopened.slotIndex },
      });
    for (const { opening, outputContext } of transaction.outputs)
      if (opening.kind === "ring")
        keepSourceNote(
          input,
          found,
          openedUtxo(opening.utxo, outputTreeId(outputContext)),
          outputContext,
        );
  }
  // The audit opened every merge from its sealed record, a skipped one refused above.
  for (const confirmed of batch) {
    const slot = confirmed.kind === "merge" ? confirmed.transaction.outputSlots[0] : undefined;
    const opening = slot === undefined ? undefined : found.openings.utxo(slot.outputContext.hash);
    if (slot !== undefined && opening !== undefined)
      keepSourceNote(input, found, opening, slot.outputContext);
  }
  // 3. A later batch never creates a note an earlier batch spends, the spent notes leave the state.
  found.spend(batch.flatMap(({ transaction }) => transaction.nullifiers));
  return found;
}

/** One batch's finds over the state before it, settled into the next state once the batch closes. */
class BatchNotes {
  readonly candidates: WalletUtxo[] = [];
  readonly unresolved: Unresolved[] = [];
  readonly unknownMints = new Set<Address>();
  readonly realInputs: Bytes32[] = [];
  readonly openings = new KnownUtxoIndex();
  readonly #claimed = new Set<string>();
  #spent: ReadonlySet<string> = new Set();

  constructor(readonly before: RecoveryState) {}

  /** `false` when the commitment was already claimed. */
  claim(commitment: Bytes32): boolean {
    if (this.seen(commitment)) return false;
    this.#claimed.add(bytesKey(commitment));
    return true;
  }

  seen(commitment: Bytes32): boolean {
    const key = bytesKey(commitment);
    return this.before.claimed.has(key) || this.#claimed.has(key);
  }

  unresolve(commitment: Bytes32, nullifier: Bytes32): void {
    this.unresolved.push(Object.freeze({ commitment, nullifier }));
  }

  spend(nullifiers: readonly Bytes32[]): void {
    this.#spent = new Set(nullifiers.map(bytesKey));
  }

  /** The next state, sharing each collection of `before` the batch leaves unchanged. */
  settle(openSlot: readonly ConfirmedRingTransaction[]): RecoveryState {
    const { before } = this;
    const live = ({ nullifier }: Readonly<{ nullifier: Bytes32 }>) =>
      !this.#spent.has(bytesKey(nullifier));
    // Rust `Found::nullifiers`, a member note answers its input even when the batch spends it.
    const notes = [
      ...before.candidates,
      ...this.candidates,
      ...before.unresolved,
      ...this.unresolved,
    ];
    const held = new Set(notes.map(({ nullifier }) => bytesKey(nullifier)));
    const unseen = this.realInputs.filter((nullifier) => !held.has(bytesKey(nullifier)));
    return Object.freeze({
      candidates: carried(before.candidates, this.candidates, live),
      unresolved: carried(before.unresolved, this.unresolved, live),
      claimed: united(before.claimed, this.#claimed),
      unknownMints: united(before.unknownMints, this.unknownMints),
      unseenInputs: carried(
        before.unseenInputs,
        unseen.slice(0, RECOVERY_INPUT_SAMPLE_LIMIT - before.unseenInputs.length),
      ),
      unseenInputCount: before.unseenInputCount + BigInt(unseen.length),
      openSlot: Object.freeze([...openSlot]),
    });
  }
}

/** `before` itself while the batch adds nothing and drops nothing. */
function carried<T>(
  before: readonly T[],
  added: readonly T[],
  live: (item: T) => boolean = () => true,
): readonly T[] {
  if (added.length === 0 && before.every(live)) return before;
  return Object.freeze([...before, ...added].filter(live));
}

function united<T>(before: ReadonlySet<T>, added: ReadonlySet<T>): ReadonlySet<T> {
  return added.size === 0 ? before : new Set([...before, ...added]);
}

/** A ring note the audit opened, kept when the source's signing key owns it under its nullifier key or the zero key. */
function keepSourceNote(
  input: Pick<RingRecoveryParams, "source" | "nullifierKey" | "assets" | "ringProgramId">,
  found: BatchNotes,
  opening: KnownUtxo,
  outputContext: OutputContext,
): void {
  const nullifierPk = sourceNullifierPk(input.source, knownUtxoOwnerHash(opening));
  if (nullifierPk === undefined || !found.claim(outputContext.hash)) return;
  const nullifier = sourceNullifier(input, nullifierPk, outputContext.hash, opening.blinding);
  const mint = registeredMint(input.assets, opening.mint);
  if (mint === undefined) {
    // Ownership and spentness stay known, without a registered mint the note stays unspendable.
    if (opening.mint !== undefined) found.unknownMints.add(opening.mint);
    found.unresolve(outputContext.hash, nullifier);
    return;
  }
  const opened = sourceWalletUtxo(input, {
    utxo: new Utxo({
      owner: input.source.signingPublicKey,
      asset: mint,
      amount: opening.amount,
      blinding: opening.blinding,
      ringProgramId: input.ringProgramId,
    }),
    nullifierPk,
    outputContext,
    hashes: { dataHash: opening.dataHash, ringDataHash: opening.ringDataHash },
  });
  if (opened.opens) found.candidates.push(opened.utxo);
  else found.unresolve(outputContext.hash, opened.utxo.nullifier);
}

/** The key a source note sits under, `undefined` for another owner. */
function sourceNullifierPk(source: ShieldedAddress, owner: Bytes32): Bytes32 | undefined {
  if (equalBytes(owner, source.ownerHash())) return source.nullifierPublicKey;
  const zeroKeyOwner = ownerHash(source.signingPublicKey.ownerProofInputHash(), ZERO_NULLIFIER_PK);
  return equalBytes(owner, zeroKeyOwner) ? (ZERO_NULLIFIER_PK as Bytes32) : undefined;
}

/** A zero-key note's nullifier needs no secret, anyone with the opening derives it. */
function sourceNullifier(
  input: Pick<RingRecoveryParams, "nullifierKey">,
  nullifierPk: Bytes32,
  commitment: Bytes32,
  blinding: Bytes32,
): Bytes32 {
  return equalBytes(nullifierPk, ZERO_NULLIFIER_PK)
    ? zeroKeyNullifier(commitment, blinding)
    : input.nullifierKey.nullifier(commitment, blinding);
}

/** Rust `SourceMember::wallet_utxo`, the UTXO at `outputContext` and whether it reproduces the leaf. */
function sourceWalletUtxo(
  input: Pick<RingRecoveryParams, "nullifierKey">,
  candidate: Readonly<{
    utxo: Utxo;
    nullifierPk: Bytes32;
    outputContext: OutputContext;
    hashes: Readonly<{ dataHash?: Bytes32; ringDataHash?: Bytes32 }>;
  }>,
): Readonly<{ utxo: WalletUtxo; opens: boolean }> {
  const { utxo, nullifierPk, outputContext } = candidate;
  const dataHash = nonZero(candidate.hashes.dataHash);
  const ringDataHash = nonZero(candidate.hashes.ringDataHash);
  const walletUtxo: WalletUtxo = Object.freeze({
    utxo,
    outputContext,
    nullifier: sourceNullifier(input, nullifierPk, outputContext.hash, utxo.blinding),
    ...(dataHash === undefined ? {} : { dataHash }),
    ...(ringDataHash === undefined ? {} : { ringDataHash }),
    spent: false,
  });
  const commitment = utxo.hash(nullifierPk, outputTreeId(outputContext), dataHash, ringDataHash);
  return Object.freeze({
    utxo: walletUtxo,
    opens: equalBytes(commitment, outputContext.hash),
  });
}

/** Every transaction spending one of `nullifiers`, `budget` bounds the queries. */
export async function spendingTransactions(
  client: Pick<IndexerReader, "getShieldedTransactionsByNullifiers">,
  nullifiers: readonly Bytes32[],
  budget: { remaining: number },
  context: RequestContext | undefined,
): Promise<readonly IndexedShieldedTransaction[]> {
  const transactions: IndexedShieldedTransaction[] = [];
  for (let start = 0; start < nullifiers.length; start += Number(PAGE_LIMIT)) {
    const batch = nullifiers.slice(start, start + Number(PAGE_LIMIT));
    let token: string | undefined;
    for (;;) {
      if (budget.remaining <= 0) throw new RingError("RING_RECOVERY_INCOMPLETE");
      budget.remaining--;
      const page = await client.getShieldedTransactionsByNullifiers(
        {
          nullifiers: batch,
          ...(token === undefined ? {} : { paginationToken: token }),
        },
        undefined,
        context,
      );
      transactions.push(...page.data.flatMap((item) => item.events));
      const next = nextHistoryToken(token, page);
      if (next === undefined) break;
      token = next;
    }
  }
  return transactions;
}

/** The mint the registry knows, `undefined` for an absent or unregistered one. */
export function registeredMint(
  assets: AssetRegistry,
  mint: Address | undefined,
): Address | undefined {
  if (mint === undefined) return undefined;
  try {
    assets.assetId(mint);
    return mint;
  } catch {
    return undefined;
  }
}

function nonZero(hash: Bytes32 | undefined): Bytes32 | undefined {
  return hash === undefined || hash.every((byte) => byte === 0) ? undefined : hash;
}
