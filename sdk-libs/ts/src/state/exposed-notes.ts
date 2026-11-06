/** Zero-key notes stay readable and recorded, no automatic path spends one. */
import type { Address } from "@solana/kit";

import { equalBytes } from "@heliuslabs/spr/internal";
import type { Bytes31, Bytes32 } from "@heliuslabs/spr/interface";
import { NullifierKey } from "@heliuslabs/spr/keypair";
import type { WalletUtxo } from "@heliuslabs/spr/transaction";

/** `exposedIfSpent` publishes the owner on a spend, `spent` takes precedence over it. */
export type NoteState = "spendable" | "exposedIfSpent" | "spent";

export interface MintBalance {
  readonly spendable: bigint;
  readonly exposedIfSpent: bigint;
}

const ZERO_NULLIFIER_KEY = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);

/** Needs no holder, anyone who knows the opening computes it. */
export function zeroKeyNullifier(utxoHash: Bytes32, blinding: Bytes32): Bytes32 {
  return ZERO_NULLIFIER_KEY.nullifier(utxoHash, blinding);
}

export function isZeroKeyNote(
  note: Pick<WalletUtxo, "utxo" | "outputContext" | "nullifier">,
): boolean {
  return equalBytes(note.nullifier, zeroKeyNullifier(note.outputContext.hash, note.utxo.blinding));
}

export function noteState(note: WalletUtxo): NoteState {
  if (note.spent) return "spent";
  return isZeroKeyNote(note) ? "exposedIfSpent" : "spendable";
}

export function mintBalances(notes: readonly WalletUtxo[]): ReadonlyMap<Address, MintBalance> {
  const balances = new Map<Address, MintBalance>();
  for (const note of notes) {
    const state = noteState(note);
    if (state === "spent") continue;
    const held = balances.get(note.utxo.asset) ?? { spendable: 0n, exposedIfSpent: 0n };
    balances.set(note.utxo.asset, {
      spendable: held.spendable + (state === "spendable" ? note.utxo.amount : 0n),
      exposedIfSpent: held.exposedIfSpent + (state === "exposedIfSpent" ? note.utxo.amount : 0n),
    });
  }
  return balances;
}
