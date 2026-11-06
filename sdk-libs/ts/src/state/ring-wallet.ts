/**
 * A wallet's notes beside the opened notes whose mint the registry lacks, one reducer for both wallet modes.
 *
 * Read `RingWallet._absorb` first. `AnonymousWallet` holds one and calls it from both sync modes with their own cursor write.
 */
import { bytesKey } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import {
  deserializeWallet,
  serializeWallet,
  Wallet,
  type AssetRegistry,
  type WalletUtxo,
} from "@heliuslabs/spr/transaction";

import { registeredMint } from "../operations/workflow/recover.js";
import { RingError } from "../protocol/error.js";
import { unseen } from "./batch.js";

/** The notes one scan opened and the spends it read. */
export interface NoteDelta {
  /** Registered or not, the reducer sorts them. */
  readonly notes: readonly WalletUtxo[];
  readonly spentNullifiers: Iterable<Bytes32>;
}

/** The wallet fields a commit stores beside its scan cursor. */
export interface NoteCommit {
  readonly utxos: readonly WalletUtxo[];
  readonly nullifiers: ReadonlySet<string>;
}

/** A transfer never selects a note before its mint registers. */
export function isPendingNote(assets: AssetRegistry, note: WalletUtxo): boolean {
  return registeredMint(assets, note.utxo.asset) === undefined;
}

export class RingWallet {
  /** Holds the spendable notes and spends, a transfer selects from it. */
  readonly wallet: Wallet;
  readonly #pending: Wallet;

  private constructor(wallet: Wallet, pending: Wallet) {
    this.wallet = wallet;
    this.#pending = pending;
  }

  static create(wallet: Wallet): RingWallet {
    return new RingWallet(
      wallet,
      new Wallet({ identity: wallet.identity, registry: wallet.registry }),
    );
  }

  /** Stored and unspendable, the sync that sees the mint registered moves each without a rescan. */
  pendingOpenings(): readonly WalletUtxo[] {
    return this.#pending.utxos();
  }

  /** The pending notes the wallet's registry now names, moved into the spendable notes. */
  promotePending(): Promise<readonly WalletUtxo[]> {
    return this.wallet._withSyncLock(async () =>
      this._absorb({ notes: [], spentNullifiers: [] }, this.wallet, (commit) =>
        this.wallet._replace({ ...this.wallet._state(), ...commit }),
      ),
    );
  }

  /**
   * Lands a delta on `base` and returns the pending notes it promoted. The caller holds the sync lock.
   *
   * `base` is the wallet or a staged copy holding newer core rows, its registry decides every note.
   * `write` stores the wallet fields and the cursor together. A refusal there leaves both wallets unchanged.
   */
  _absorb(
    delta: NoteDelta,
    base: Wallet,
    write: (commit: NoteCommit) => void,
  ): readonly WalletUtxo[] {
    const state = base._state();
    const assets = base.registry;
    const pendingState = this.#pending._state();
    // 1. A note already held, spendable or pending, keeps its first opening.
    const held = new Set(
      [...state.utxos, ...pendingState.utxos].map((note) => bytesKey(note.outputContext.hash)),
    );
    const fresh = delta.notes.filter((note) => unseen(held, bytesKey(note.outputContext.hash)));
    // 2. One registry decides for old and new notes, a late registration promotes with no rescan.
    const nullifiers = new Set([...state.nullifiers, ...[...delta.spentNullifiers].map(bytesKey)]);
    const marked = (note: WalletUtxo): WalletUtxo =>
      !note.spent && nullifiers.has(bytesKey(note.nullifier)) ? { ...note, spent: true } : note;
    const waiting = [...pendingState.utxos, ...fresh];
    const pending = waiting.filter((note) => isPendingNote(assets, note)).map(marked);
    const promoted = pendingState.utxos.filter((note) => !isPendingNote(assets, note));
    const utxos = [...state.utxos, ...waiting.filter((note) => !isPendingNote(assets, note))].map(
      marked,
    );
    // 3. The wallet write may refuse, the pending write after it cannot, its hashes are distinct.
    write({ utxos, nullifiers });
    this.#pending._replace({ ...pendingState, utxos: pending });
    return promoted;
  }

  /** @internal */
  _documentFields(): Readonly<{ wallet: string; pending: string }> {
    return { wallet: serializeWallet(this.wallet), pending: serializeWallet(this.#pending) };
  }

  /** @internal Promotion moves pending notes into the wallet, both must hold one identity. */
  static _fromDocument(wallet: unknown, pending: unknown): RingWallet {
    if (typeof wallet !== "string" || typeof pending !== "string")
      throw invalid("wallet or pending is not a stored wallet");
    const notes = deserializeWallet(wallet);
    const waiting = deserializeWallet(pending);
    if (bytesKey(notes.identity.toBytes()) !== bytesKey(waiting.identity.toBytes()))
      throw invalid("pending notes name another identity");
    return new RingWallet(notes, waiting);
  }
}

function invalid(reason: string): RingError {
  return new RingError("RING_WALLET_DOCUMENT", { details: { reason } });
}
