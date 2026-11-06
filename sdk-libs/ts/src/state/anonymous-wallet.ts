/** One document holds a wallet's scan progress and everything it covers, one write stores both. */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { bytesKey, U64_MAX } from "@heliuslabs/spr/internal";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/spr/interface";
import { X25519PublicKey, type ViewTag } from "@heliuslabs/spr/keypair";
import type { Wallet, WalletUtxo } from "@heliuslabs/spr/transaction";

import { RingError } from "../protocol/error.js";
import { exactlyOne, unseen } from "./batch.js";
import { mintBalances, noteState, type MintBalance, type NoteState } from "./exposed-notes.js";
import { consumeScan, type AnonymousScan } from "./anonymous-sync.js";
import type { RingKeys } from "./ring-keys.js";
import { RingWallet, type NoteCommit, type NoteDelta } from "./ring-wallet.js";
import {
  recoveryAllows,
  recoverySessionJson,
  restoreRecoverySession,
  type RecoverySession,
  type RecoveryCoverage,
  type RecoveryWallet,
} from "./recovery-session.js";
import { parseExact, senderStream, ViewingHistory } from "./viewing-history.js";

/** A reply read from a note, what a sender wrote about itself and nothing the proof binds. */
export interface PendingClaim {
  readonly utxoHash: Bytes32;
  readonly claimedViewingKey: X25519PublicKey;
  readonly claimedOwnerKey: Bytes32;
  readonly claimedNullifierPk: Bytes32;
}

/** What one confidential sync stores beside its notes, Rust `ScanCommit`. */
export interface ConfidentialCommit extends NoteDelta {
  /** The held keys the sync read and the slot their tag reads are complete through. */
  readonly tagPosition?: Readonly<{ keys: readonly X25519PublicKey[]; afterSlot: bigint }>;
  /** Stored retries whose spend row the sync read again. */
  readonly retried: readonly Bytes32[];
}

export type AnonymousNoteState = NoteState | "pendingSpendCheck";

export class AnonymousWallet {
  readonly #notes: RingWallet;
  #history: ViewingHistory;
  #claims: readonly PendingClaim[];
  #recovery: RecoverySession | null;
  #revision: bigint;
  #recoveryFloor: bigint;
  /** Written by a Rust sync for a merge whose output named an unregistered mint, each confidential sync reads the spend again. */
  #mergeRetries: ReadonlyMap<string, Bytes32>;

  private constructor(
    fields: Readonly<{
      notes: RingWallet;
      history: ViewingHistory;
      claims: readonly PendingClaim[];
      mergeRetries: readonly Bytes32[];
      recovery?: RecoverySession | null;
      revision?: bigint;
      recoveryFloor?: bigint;
    }>,
  ) {
    this.#notes = fields.notes;
    this.#history = fields.history;
    this.#claims = fields.claims;
    this.#recovery = fields.recovery ?? null;
    this.#revision = fields.revision ?? 0n;
    this.#recoveryFloor = fields.recoveryFloor ?? 0n;
    if (this.#recovery !== null) {
      const held = new Set(
        [...this.#notes.wallet.utxos(), ...this.#notes.pendingOpenings()].map((note) =>
          bytesToHex(note.nullifier),
        ),
      );
      if (
        this.#recovery.owner !== bytesToHex(this.#notes.wallet.identity.toBytes()) ||
        [
          ...this.#recovery.queue,
          ...this.#recovery.checked,
          ...(this.#recovery.active?.nullifiers ?? []),
        ].some((key) => !held.has(key))
      )
        throw invalid("recovery session names another wallet");
    }
    if ("recoveryCoverage" in this.#notes.wallet)
      throw invalid("wallet already has a recovery owner");
    Object.defineProperty(this.#notes.wallet, "recoveryCoverage", {
      value: () => this.recoveryCoverage(),
    });
    this.#mergeRetries = new Map(
      fields.mergeRetries.map((nullifier) => [bytesKey(nullifier), nullifier]),
    );
  }

  static create(wallet: Wallet, history: ViewingHistory): AnonymousWallet {
    return new AnonymousWallet({
      notes: RingWallet.create(wallet),
      history,
      claims: [],
      mergeRetries: [],
    });
  }

  /** Holds the notes and spends, a transfer selects from it. */
  get wallet(): RecoveryWallet {
    return this.#notes.wallet as RecoveryWallet;
  }

  recoveryCoverage(): RecoveryCoverage {
    return Object.freeze({
      status: this.#recovery === null ? "Complete" : "Paused",
      targetSlot: this.#recovery?.targetSlot ?? null,
      checkedNullifiers: new Set(this.#recovery?.checked ?? []),
    });
  }

  _recoveryState(): Readonly<{
    session: RecoverySession | null;
    revision: bigint;
    coreRevision: number;
  }> {
    return {
      session: structuredClone(this.#recovery),
      revision: this.#revision,
      coreRevision: this.wallet._revision,
    };
  }

  _recoveryMinimumSlot(wallet: Wallet = this.wallet): bigint {
    let floor = this.#recoveryFloor;
    const observe = (slot: bigint) => {
      if (slot > floor) floor = slot;
    };
    for (const entry of this.#history.entries) {
      observe(entry.tagPosition ?? 0n);
      for (const position of entry.ringPositions()) observe(position.afterSlot ?? 0n);
    }
    for (const stream of ["transactions", "proofless", "nullifiers"] as const)
      for (const [, slot] of wallet._checkpointEntries(stream)) observe(slot);
    for (const transaction of wallet.privateTransactions()) observe(transaction.id.slot);
    return floor;
  }

  history(): ViewingHistory {
    return this.#history;
  }

  notes(): readonly WalletUtxo[] {
    return this.wallet.utxos();
  }

  noteState(note: WalletUtxo): AnonymousNoteState {
    if (!note.spent && !recoveryAllows(this.recoveryCoverage(), note, bytesKey(note.nullifier)))
      return "pendingSpendCheck";
    return noteState(note);
  }

  /** Unspent zero-key notes, only a public spend naming the wallet takes one. */
  exposedNotes(): readonly WalletUtxo[] {
    return this.#coveredNotes().filter((note) => noteState(note) === "exposedIfSpent");
  }

  balances(): ReadonlyMap<Address, MintBalance> {
    return mintBalances(this.#coveredNotes());
  }

  /** Stored and unspendable, the next absorb or `promotePending` moves each once its mint registers. */
  pendingOpenings(): readonly WalletUtxo[] {
    return this.#notes.pendingOpenings();
  }

  /** Replies the wallet has not confirmed, none reads as a verified sender. */
  pendingClaims(): readonly PendingClaim[] {
    return this.#claims;
  }

  /** The wallet's own decision to trust a claimed sender, nothing else confirms one. */
  confirmClaim(claimed: X25519PublicKey): void {
    if (!this.#claims.some((claim) => claim.claimedViewingKey.equals(claimed)))
      throw new RingError("RING_UNKNOWN_SENDER_CLAIM");
    this.#history = this.#history.withConfirmedSender(claimed);
    this.#claims = this.#claims.filter((claim) => !claim.claimedViewingKey.equals(claimed));
    this.#revision += 1n;
  }

  /** Takes a scan's notes, spends, claims and progress together and consumes it. */
  async absorb(scan: AnonymousScan): Promise<void> {
    return this.wallet._withSyncLock(async () => {
      const recovery = consumeScan(scan, this.#history, this);
      if (recovery === undefined && this.#recovery !== null)
        throw new RingError("RING_SCAN_HISTORY_CHANGED");
      const claimed = new Set(this.#claims.map((claim) => bytesKey(claim.utxoHash)));
      const claims = scan.senderClaims
        .filter((claim) => unseen(claimed, bytesKey(claim.utxoHash)))
        .map(({ utxoHash, claim: { claimed: reply } }): PendingClaim =>
          Object.freeze({
            utxoHash,
            claimedViewingKey: reply.viewingKey,
            claimedOwnerKey: reply.ownerKey,
            claimedNullifierPk: reply.nullifierPk,
          }),
        );
      const history = this.#history._withScanProgress(scan.history);
      this.#notes._absorb(
        {
          notes: [...scan.utxos, ...scan.pendingOpenings],
          spentNullifiers: scan.spentNullifiers,
        },
        this.wallet,
        (commit) => this.wallet._replace({ ...this.wallet._state(), ...commit }),
      );
      this.#claims = [...this.#claims, ...claims];
      this.#history = history;
      const observed = scan.targetSlot ?? scan.observedSlot;
      if (observed > this.#recoveryFloor) this.#recoveryFloor = observed;
      if (recovery !== undefined) this.#recovery = recovery;
      this.#revision += 1n;
    });
  }

  /** @internal */
  _mergeRetries(): readonly Bytes32[] {
    return [...this.#mergeRetries.values()];
  }

  /**
   * @internal Lands one confidential sync, the caller holds the sync lock.
   *
   * `write` stores the wallet fields and the core checkpoints, a refusal there leaves the positions and retries unmoved.
   */
  _absorbConfidential(
    commit: ConfidentialCommit,
    base: Wallet,
    write: (fields: NoteCommit) => void,
  ): void {
    if (
      this.#recovery !== null &&
      (commit.tagPosition !== undefined ||
        (this.#recovery.targetSlot !== null &&
          this._recoveryMinimumSlot(base) > this.#recovery.targetSlot))
    )
      throw new RingError("RING_SYNC_INCOMPLETE");
    this.#notes._absorb(commit, base, write);
    this.#revision += 1n;
    const { tagPosition } = commit;
    if (tagPosition !== undefined)
      this.#history = this.#history._withTagPosition(tagPosition.keys, tagPosition.afterSlot);
    // A retry leaves only once the indexer returned its spend row, a lagging indexer keeps it stored.
    const retries = new Map(this.#mergeRetries);
    for (const nullifier of commit.retried) retries.delete(bytesKey(nullifier));
    this.#mergeRetries = retries;
  }

  /** Moves each pending note whose mint now registers into the spendable notes, the moved ones returned. */
  promotePending(): Promise<readonly WalletUtxo[]> {
    return this.#notes.promotePending();
  }

  /** Only raises a tag counter or adds a key. */
  updateHistory(updated: ViewingHistory): void {
    if (!updated._progressMatches(this.#history)) throw new RingError("RING_SCAN_PROGRESS_MOVED");
    this.#history = updated;
    this.#revision += 1n;
  }

  /** The current key's next sender tag, concurrent callers never share one. */
  takeSenderTag(keys: RingKeys, context?: RequestContext): Promise<ViewTag> {
    return this.#takeTag(keys, context);
  }

  /** A holder failure burns the index. */
  async #takeTag(keys: RingKeys, context: RequestContext | undefined): Promise<ViewTag> {
    const current = this.#history.current();
    const { index, counter } = current.tx.takeNext();
    this.#history = this.#history.withEntry(
      this.#history.entries.length - 1,
      current.withTxCounter(counter),
    );
    this.#revision += 1n;
    return exactlyOne(
      await keys.viewTags(
        [{ viewingPublicKey: current.viewingPublicKey, stream: senderStream(index) }],
        context,
      ),
    );
  }

  /** Its notes open the wallet's funds, store it as key material under one atomic replace. */
  toJson(): string {
    const claims = this.#claims.map((claim) => ({
      utxoHash: bytesToHex(claim.utxoHash),
      claimedViewingKey: bytesToHex(claim.claimedViewingKey.toBytes()),
      claimedOwnerKey: bytesToHex(claim.claimedOwnerKey),
      claimedNullifierPk: bytesToHex(claim.claimedNullifierPk),
    }));
    const { wallet, pending } = this.#notes._documentFields();
    return (
      `{"history":${this.#history.toJson()},` +
      `"wallet":${JSON.stringify(wallet)},` +
      `"pending":${JSON.stringify(pending)},` +
      `"claims":${JSON.stringify(claims)},` +
      `"mergeRetries":${JSON.stringify([...this.#mergeRetries.keys()].sort())},` +
      `"revision":"${this.#revision}","recoveryFloor":"${this.#recoveryFloor}","recovery":${recoverySessionJson(this.#recovery)}}`
    );
  }

  static fromJson(text: string): AnonymousWallet {
    const stored = document(parseExact(text));
    const { history, wallet, pending, claims, mergeRetries } = stored;
    const known = [
      "history",
      "wallet",
      "pending",
      "claims",
      "mergeRetries",
      "recovery",
      "revision",
      "recoveryFloor",
    ];
    if (Object.keys(stored).some((key) => !known.includes(key)))
      throw invalid("the document names other fields");
    if (!Array.isArray(claims)) throw invalid("claims is not a list");
    if (!Array.isArray(mergeRetries)) throw invalid("mergeRetries is not a list");
    return new AnonymousWallet({
      notes: RingWallet._fromDocument(wallet, pending),
      history: ViewingHistory._fromValue(history),
      claims: claims.map(storedClaim),
      mergeRetries: mergeRetries.map(field),
      recovery: restoreRecoverySession(stored.recovery),
      revision: storedRevision(stored.revision),
      recoveryFloor: storedRecoveryFloor(stored.recoveryFloor),
    });
  }
  #coveredNotes(): readonly WalletUtxo[] {
    const coverage = this.recoveryCoverage();
    return this.wallet
      .utxos()
      .filter((note) => recoveryAllows(coverage, note, bytesKey(note.nullifier)));
  }
}

function storedClaim(value: unknown): PendingClaim {
  const claim = document(value);
  try {
    return Object.freeze({
      utxoHash: field(claim["utxoHash"]),
      claimedViewingKey: X25519PublicKey.fromBytes(hexToBytes(String(claim["claimedViewingKey"]))),
      claimedOwnerKey: field(claim["claimedOwnerKey"]),
      claimedNullifierPk: field(claim["claimedNullifierPk"]),
    });
  } catch (cause) {
    if (cause instanceof RingError) throw cause;
    throw invalid("a claimed viewing key is not tagged");
  }
}

function field(value: unknown): Bytes32 {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value))
    throw invalid("a stored value is not 32 hex bytes");
  return hexToBytes(value) as Bytes32;
}

function document(value: unknown): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw invalid("is not an object");
  return value as Readonly<Record<string, unknown>>;
}

function invalid(reason: string): RingError {
  return new RingError("RING_WALLET_DOCUMENT", { details: { reason } });
}

function storedRevision(value: unknown): bigint {
  if (value === undefined) return 0n;
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value))
    throw invalid("invalid wallet revision");
  return BigInt(value);
}

function storedRecoveryFloor(value: unknown): bigint {
  const floor = storedRevision(value);
  if (floor > U64_MAX) throw invalid("invalid recovery floor");
  return floor;
}
