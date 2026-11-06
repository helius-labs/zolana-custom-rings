import type { ChainReader, TreeContext } from "@heliuslabs/spr/client";
import {
  equalBytes,
  bytesKey,
  selectUtxos,
  ZERO_NULLIFIER_PK,
  type SpendPolicy,
  type SpendSelectionErrors,
} from "@heliuslabs/spr/internal";
import {
  MAX_INPUT_TREES,
  type Address,
  type Bytes32,
  type RequestContext,
} from "@heliuslabs/spr/interface";
import type { ShieldedAddress } from "@heliuslabs/spr/keypair";
import { ProofInputUtxo } from "@heliuslabs/spr/transaction";
import type { Wallet, WalletUtxo } from "@heliuslabs/spr/transaction";

import { recoveryAllows, type RecoveryWallet } from "../../state/recovery-session.js";
import { RingError } from "../../protocol/error.js";
import { ringTreeIdResolver } from "../../protocol/membership/trees.js";

export interface Cover {
  readonly asset: Address;
  readonly amount: bigint;
}

export function selectFunding(
  input: Readonly<{
    wallet: Wallet;
    covers: readonly Cover[];
    policy: Omit<SpendPolicy, "tree">;
    maxTrees?: number;
  }>,
): readonly WalletUtxo[] {
  const { wallet, covers, policy, maxTrees = MAX_INPUT_TREES } = input;
  const multipleTrees = (treeCount: number) =>
    new RingError("RING_TOO_MANY_INPUT_TREES", { details: { treeCount, maximum: maxTrees } });
  const entries: WalletUtxo[] = [];
  for (const cover of covers) {
    entries.push(
      ...selectCoveredUtxos({
        wallet,
        asset: cover.asset,
        target: { kind: "cover", amount: cover.amount },
        policy: {
          ...policy,
          maxInputs: policy.maxInputs - entries.length,
          tree: { kind: "infer", maxTrees },
          errors: {
            ...policy.errors,
            multipleTrees: ({ treeCount }) => multipleTrees(treeCount),
          },
        },
      }).entries,
    );
  }
  const treeCount = new Set(entries.map((entry) => entry.outputContext.tree)).size;
  if (treeCount > maxTrees) throw multipleTrees(treeCount);
  return entries;
}

export function selectCoveredUtxos(
  input: Parameters<typeof selectUtxos>[0],
): ReturnType<typeof selectUtxos> {
  const coverage = recoveryCoverage(input.wallet);
  if (coverage === undefined || coverage.status === "Complete") return selectUtxos(input);
  return selectUtxos({
    ...input,
    policy: {
      ...input.policy,
      eligible: (note) =>
        input.policy.eligible(note) && recoveryAllows(coverage, note, bytesKey(note.nullifier)),
      errors: {
        ...input.policy.errors,
        insufficient: () => new RingError("RING_SYNC_INCOMPLETE"),
        tooFewUtxos: () => new RingError("RING_SYNC_INCOMPLETE"),
      },
    },
  });
}

export function checkSpendCoverage(wallet: Wallet, entries: readonly WalletUtxo[]): void {
  const coverage = recoveryCoverage(wallet);
  if (coverage === undefined || coverage.status === "Complete") return;
  if (entries.some((note) => !recoveryAllows(coverage, note, bytesKey(note.nullifier))))
    throw new RingError("RING_SYNC_INCOMPLETE");
}

/** Proof inputs at each note's own tree, a second tree's id read once from its account. */
export async function ringProofInputs(
  entries: readonly WalletUtxo[],
  ownerOf: (entry: WalletUtxo) => ShieldedAddress,
  client: TreeContext & Pick<ChainReader, "getAccount">,
  context?: RequestContext,
): Promise<readonly ProofInputUtxo[]> {
  const treeId = ringTreeIdResolver(client, [client], context);
  return Promise.all(
    entries.map(async (entry) => {
      const tree = entry.outputContext.tree;
      return ringProofInput(entry, ownerOf(entry), { tree, treeId: await treeId(tree) });
    }),
  );
}

/** A note spends at its own tree, the stored nullifier was derived for that tree. */
export function ringProofInput(
  entry: WalletUtxo,
  owner: ShieldedAddress,
  client: TreeContext,
): ProofInputUtxo {
  if (entry.outputContext.tree !== client.tree) {
    throw new RingError("RING_TREE_MISMATCH", {
      details: { tree: entry.outputContext.tree, clientTree: client.tree },
    });
  }
  return new ProofInputUtxo({
    utxo: entry.utxo,
    nullifierPublicKey: noteNullifierPublicKey(entry, owner, client.treeId),
    nullifier: entry.nullifier,
    treeId: client.treeId,
    ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
    ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
  });
}

/** The zero key on a note a program owner's sender named, the note holds no key of its own. */
export function noteNullifierPublicKey(
  entry: WalletUtxo,
  owner: ShieldedAddress,
  treeId: number,
): Bytes32 {
  const rebuilds = (key: Bytes32): boolean =>
    equalBytes(
      entry.utxo.proofInput(key, treeId, entry.dataHash, entry.ringDataHash).hash(),
      entry.outputContext.hash,
    );
  return !rebuilds(owner.nullifierPublicKey) && rebuilds(ZERO_NULLIFIER_PK)
    ? ZERO_NULLIFIER_PK
    : owner.nullifierPublicKey;
}

export function ringIntentMismatch(field: string): RingError {
  return new RingError("RING_INTENT_MISMATCH", { details: { field } });
}

/** @internal */
export const ringSelectionErrors: SpendSelectionErrors = {
  insufficient: ({ asset, requested, available }) =>
    new RingError("RING_INSUFFICIENT_BALANCE", {
      details: { asset, requested: requested.toString(), available: available.toString() },
    }),
  tooManyInputs: ({ eligible, max }) =>
    new RingError("RING_TOO_MANY_INPUTS", { details: { selected: eligible, maximum: max } }),
  overflow: ({ available }) =>
    new RingError("RING_SELECTED_BALANCE_OVERFLOW", {
      details: { available: available.toString() },
    }),
};

function recoveryCoverage(wallet: Wallet) {
  return "recoveryCoverage" in wallet && typeof wallet.recoveryCoverage === "function"
    ? (wallet as RecoveryWallet).recoveryCoverage()
    : undefined;
}
