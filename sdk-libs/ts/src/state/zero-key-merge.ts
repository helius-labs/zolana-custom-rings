/** A zero-key merge opens from the owner's viewing key alone, it needs no input history. */
import {
  bytesKey,
  decryptMergeOutput,
  equalBytes,
  readMergeOutputBody,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import {
  seededMergeOutputBlinding,
  seededMergeOutputKey,
} from "../crypto/derivation/merge-seed.js";
import type { Bytes32, RequestContext } from "@heliuslabs/spr/interface";
import type { ShieldedAddress, X25519PublicKey } from "@heliuslabs/spr/keypair";
import {
  Utxo,
  type IndexedShieldedTransaction,
  type WalletUtxo,
} from "@heliuslabs/spr/transaction";

import { answered } from "./batch.js";
import { zeroKeyNullifier } from "./exposed-notes.js";
import { decoded } from "./batch.js";
import { isRingMergeRow } from "./ring-sync.js";
import type { RingKeys } from "./ring-keys.js";

export interface OpenedZeroKeyMerge {
  readonly utxo: WalletUtxo;
  readonly row: IndexedShieldedTransaction;
  readonly position: number;
  readonly viewingPublicKey: X25519PublicKey;
}

/** Rotated keys are tried in turn, a seed no held key derives leaves the note to `OwnerGrant`. */
export async function openZeroKeyMerges(
  input: Readonly<{
    keys: Pick<RingKeys, "mergeSeeds" | "viewingPublicKeys">;
    owner: ShieldedAddress;
    rows: readonly IndexedShieldedTransaction[];
  }>,
  context?: RequestContext,
): Promise<readonly OpenedZeroKeyMerge[]> {
  const ownerTag = input.owner.signingPublicKey.ownerProofInputHash();
  const sites = input.rows.filter(isRingMergeRow).flatMap((row) => {
    const firstNullifier = row.nullifiers[0];
    const ring = row.ringProgramId;
    if (firstNullifier === undefined || ring === undefined) return [];
    return row.outputSlots.flatMap((slot, position) =>
      equalBytes(slot.viewTag, ownerTag) ? [{ row, position, slot, firstNullifier, ring }] : [],
    );
  });
  if (sites.length === 0) return [];
  const opened: OpenedZeroKeyMerge[] = [];
  const openedHashes = new Set<string>();
  for (const viewingPublicKey of input.keys.viewingPublicKeys()) {
    const unopened = sites.filter(
      ({ slot }) => !openedHashes.has(bytesKey(slot.outputContext.hash)),
    );
    if (unopened.length === 0) break;
    const seeds = await input.keys.mergeSeeds(
      unopened.map(({ ring, firstNullifier }) => ({
        viewingPublicKey,
        ringProgramId: ring,
        firstNullifier,
      })),
      context,
    );
    for (const [site, seed] of answered(unopened, seeds)) {
      try {
        const utxo = decoded(() => noteOf({ ...site, seed, owner: input.owner }));
        if (utxo === undefined) continue;
        openedHashes.add(bytesKey(utxo.outputContext.hash));
        opened.push({ utxo, row: site.row, position: site.position, viewingPublicKey });
      } finally {
        seed.fill(0);
      }
    }
  }
  return Object.freeze(opened);
}

function noteOf(
  input: Readonly<{
    slot: IndexedShieldedTransaction["outputSlots"][number];
    firstNullifier: Bytes32;
    ring: NonNullable<IndexedShieldedTransaction["ringProgramId"]>;
    seed: Bytes32;
    owner: ShieldedAddress;
  }>,
): WalletUtxo | undefined {
  const { slot, firstNullifier, ring, seed, owner } = input;
  const { hash, tree, treeId, leafIndex } = slot.outputContext;
  const body = readMergeOutputBody(slot.payload);
  if (body === undefined || treeId === undefined) return undefined;
  const key = seededMergeOutputKey(seed, firstNullifier);
  try {
    const plaintext = decryptMergeOutput(body.encrypted, key);
    const blinding = seededMergeOutputBlinding(seed, firstNullifier);
    const utxo = new Utxo({
      owner: owner.signingPublicKey,
      asset: plaintext.mint,
      amount: plaintext.amount,
      blinding,
      ringProgramId: ring,
    });
    const rebuilt = utxo.hash(ZERO_NULLIFIER_PK as Bytes32, treeId, undefined, body.ringDataHash);
    if (!equalBytes(rebuilt, hash)) return undefined;
    return Object.freeze({
      utxo,
      outputContext: Object.freeze({ hash, tree, leafIndex }),
      nullifier: zeroKeyNullifier(hash, blinding),
      spent: false,
      ...(body.ringDataHash === undefined ? {} : { ringDataHash: body.ringDataHash }),
    });
  } finally {
    key.fill(0);
  }
}
