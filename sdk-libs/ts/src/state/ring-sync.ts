/** Ring notes of scheme 10 and ring deposits opened into a wallet, the pinned zolana sync drops them, Rust `zolana_ring_client::confidential`. */
import { syncWallet, WalletError, type SyncReport, type SyncWalletInput } from "@heliuslabs/zolana";
import type { IndexerReader } from "@heliuslabs/zolana/client";
import { bytesKey, equalBytes, fetchSplAssetRegistrations } from "@heliuslabs/zolana/internal";
import type { Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import type { ShieldedAddress, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  decryptTransactions,
  Wallet,
  type AssetRegistry,
  type IndexedShieldedTransaction,
  type ShieldedKeys,
  type WalletUtxo,
} from "@heliuslabs/zolana/transaction";

import { deliveredOutput } from "../protocol/transaction/output.js";
import { customRingDepositPayload } from "../protocol/transaction/deposit-payload.js";
import { nextScanCursor } from "../operations/audit/audit.js";
import { openRingDelivery } from "../crypto/derivation/blinding.js";
import { registeredMint, spendingTransactions } from "../operations/workflow/recover.js";
import { outputTreeId } from "../protocol/membership/trees.js";
import { isRingKeys, type RingKeys } from "./ring-keys.js";
import { openRingDeposit, type RingDepositNote } from "./ring-deposit.js";
import { unseen } from "./batch.js";
import type { RingDeliveredNote } from "../crypto/derivation/blinding.js";

export interface RingNotes {
  readonly utxos: readonly WalletUtxo[];
  /** Slots sent to a held key that no registered mint rebuilds, the caller registers mints and opens again. */
  readonly pending: number;
}

/** Every note is unspent, scheme 10 opens only under keys that are also `RingKeys`, a malformed audit capsule skips its deposit. */
export async function openRingNotes(
  input: Readonly<{
    keys: ShieldedKeys;
    assets: AssetRegistry;
    transactions: readonly IndexedShieldedTransaction[];
  }>,
  context?: RequestContext,
): Promise<RingNotes> {
  const deposits = await ringDeposits(input, context);
  const notes = deposits.notes;
  let pending = deposits.pending;
  for (const tx of input.transactions) {
    const { ringProgramId: ring, txViewingPublicKey, salt } = tx;
    if (ring === undefined || txViewingPublicKey === undefined || salt === undefined) continue;
    for (const [slotIndex, slot] of tx.outputSlots.entries()) {
      const site: Site = { tx, ring, txViewingPublicKey, salt, slotIndex, slot };
      const opened = await openSlot(input, site, context);
      if (opened === PENDING) pending += 1;
      else if (opened !== undefined) notes.push(opened);
    }
  }
  const nullifiers =
    notes.length === 0
      ? []
      : await input.keys.derive(
          notes.map(({ utxo, utxoHash }) => ({
            kind: "nullifier",
            utxoHash,
            blinding: utxo.blinding,
          })),
          context,
        );
  if (nullifiers.length !== notes.length) throw new WalletError("WALLET_KEYS_BATCH_MISMATCH");
  return Object.freeze({
    utxos: Object.freeze(
      notes.map(({ utxoHash, slot, ...note }, index) =>
        Object.freeze({
          ...note,
          outputContext: Object.freeze({
            hash: utxoHash,
            tree: slot.outputContext.tree,
            leafIndex: slot.outputContext.leafIndex,
          }),
          nullifier: nullifiers[index] as Bytes32,
          spent: false,
        }),
      ),
    ),
    pending,
  });
}

/** `syncWallet`, then the ring notes it drops and the ring merges spending them, each read spent once a spend of it is indexed. */
export async function syncRingWallet(
  input: SyncWalletInput & Readonly<{ client: RingSyncClient }>,
  context?: RequestContext,
): Promise<SyncReport> {
  const report = await syncWallet(input, context);
  const { wallet, keys, client } = input;
  const tags = keys.viewingPublicKeys().map((key) => key.u());
  // Scheme 11 slots publish under the owner's own key.
  const ownerTag = keys.address().signingPublicKey.confidentialViewTag();
  const transactions = [
    ...(await taggedTransactions(client, [...tags, ownerTag], context)),
    ...(await taggedDeposits(client, tags, context)),
  ];
  const open = () => openRingNotes({ keys, assets: wallet.registry, transactions }, context);
  let notes = await open();
  const { solanaRpc, commitment } = client;
  if (notes.pending > 0 && solanaRpc !== undefined && commitment !== undefined) {
    for (const { assetId, mint } of await fetchSplAssetRegistrations(
      { solanaRpc, commitment },
      context,
    ))
      wallet.ensureAsset(assetId, mint);
    notes = await open();
  }
  await wallet._withSyncLock(async () => {
    const state = wallet._state();
    const held = new Set(state.utxos.map((entry) => bytesKey(entry.outputContext.hash)));
    const unheld = (entry: WalletUtxo): boolean => unseen(held, bytesKey(entry.outputContext.hash));
    const fresh = notes.utxos.filter(unheld);
    if (fresh.length === 0) return;
    const owner = keys.address();
    const budget = { remaining: Number.MAX_SAFE_INTEGER };
    const spends: IndexedShieldedTransaction[] = [];
    for (let frontier = fresh; frontier.length > 0;) {
      const read = await spendingTransactions(
        client,
        frontier.map((entry) => entry.nullifier),
        budget,
        context,
      );
      spends.push(...read);
      const merged = await openRingMerges(
        { keys, owner, assets: wallet.registry, spends: read },
        context,
      );
      frontier = merged.utxos.filter(unheld);
      fresh.push(...frontier);
    }
    const nullifiers = new Set(state.nullifiers);
    for (const spend of [...transactions, ...spends])
      for (const nullifier of spend.nullifiers) nullifiers.add(bytesKey(nullifier));
    wallet._replace({
      ...state,
      utxos: [
        ...state.utxos,
        ...fresh.map((entry) => ({ ...entry, spent: nullifiers.has(bytesKey(entry.nullifier)) })),
      ],
      nullifiers,
    });
  });
  return report;
}

export type RingSyncClient = SyncWalletInput["client"] &
  Pick<IndexerReader, "getShieldedTransactionsByNullifiers" | "getShieldedTransactionsByTags">;

interface Site {
  readonly tx: IndexedShieldedTransaction;
  readonly ring: NonNullable<IndexedShieldedTransaction["ringProgramId"]>;
  readonly txViewingPublicKey: X25519PublicKey;
  readonly salt: NonNullable<IndexedShieldedTransaction["salt"]>;
  readonly slotIndex: number;
  readonly slot: IndexedShieldedTransaction["outputSlots"][number];
}

type Note = RingDeliveredNote & Omit<RingDepositNote, "utxo"> & Readonly<{ slot: Site["slot"] }>;

const PENDING = Symbol("pending");

/** The ring merges among `spends` and the notes they open to `owner`, Rust `RingMerges`. */
export async function openRingMerges(
  input: Readonly<{
    keys: ShieldedKeys;
    owner: ShieldedAddress;
    assets: AssetRegistry;
    spends: readonly IndexedShieldedTransaction[];
  }>,
  context: RequestContext | undefined,
): Promise<
  Readonly<{ merges: readonly IndexedShieldedTransaction[]; utxos: readonly WalletUtxo[] }>
> {
  const merges = input.spends.filter(
    (tx) =>
      tx.ringProgramId !== undefined &&
      !tx.proofless &&
      tx.txViewingPublicKey === undefined &&
      tx.salt === undefined,
  );
  if (merges.length === 0) return { merges, utxos: [] };
  const opened = new Wallet({ identity: input.owner, registry: input.assets });
  await decryptTransactions({ wallet: opened, keys: input.keys, transactions: merges, context });
  return { merges, utxos: opened._state().utxos };
}

/** Deposits of any ring, Rust `DepositOpener::open_held`, one of an unregistered mint is pending. */
async function ringDeposits(
  input: Readonly<{
    keys: ShieldedKeys;
    assets: AssetRegistry;
    transactions: readonly IndexedShieldedTransaction[];
  }>,
  context: RequestContext | undefined,
): Promise<Readonly<{ notes: Note[]; pending: number }>> {
  const owner = input.keys.address();
  const held = input.keys.viewingPublicKeys();
  const notes: Note[] = [];
  let pending = 0;
  const seen = new Set<string>();
  for (const tx of input.transactions)
    for (const slot of tx.outputSlots) {
      const viewingPublicKey = held.find((key) => equalBytes(key.u(), slot.viewTag));
      if (viewingPublicKey === undefined || seen.has(bytesKey(slot.outputContext.hash))) continue;
      const opened = await openRingDeposit(
        {
          keys: input.keys,
          owner,
          viewingPublicKey,
          outputSlot: slot,
          depositPayload: customRingDepositPayload,
        },
        context,
      );
      if (opened === undefined) continue;
      seen.add(bytesKey(slot.outputContext.hash));
      if (registeredMint(input.assets, opened.utxo.asset) === undefined) pending += 1;
      else notes.push({ ...opened, utxoHash: slot.outputContext.hash, slot });
    }
  return { notes, pending };
}

/** `undefined` for a slot sent to no held key. */
async function openSlot(
  input: Readonly<{ keys: ShieldedKeys; assets: AssetRegistry }>,
  site: Site,
  context: RequestContext | undefined,
): Promise<Note | typeof PENDING | undefined> {
  const delivered = deliveredOutput(site.slot.payload, site.slot.viewTag);
  if (delivered === undefined || !isRingKeys(input.keys)) return undefined;
  return deliveredNote({ keys: input.keys, assets: input.assets }, site, delivered, context);
}

/** The slot secret keys the body, the asset is the registered mint that rebuilds the commitment. */
async function deliveredNote(
  input: Readonly<{ keys: RingKeys; assets: AssetRegistry }>,
  site: Site,
  delivered: Readonly<{ u: Bytes32; body: Uint8Array }>,
  context: RequestContext | undefined,
): Promise<Note | typeof PENDING | undefined> {
  const { body } = delivered;
  const viewingPublicKey = input.keys
    .viewingPublicKeys()
    .find((key) => equalBytes(key.u(), delivered.u));
  const firstNullifier = site.tx.nullifiers[0];
  if (viewingPublicKey === undefined || firstNullifier === undefined) return undefined;
  const slotSecret = await opened(context, async () => {
    const [secret] = await input.keys.ringDeliverySecrets(
      [
        {
          viewingPublicKey,
          txViewingPublicKey: site.txViewingPublicKey,
          salt: site.salt,
          outputIndex: site.slotIndex,
          firstNullifier,
        },
      ],
      context,
    );
    return secret;
  });
  if (slotSecret === undefined) return undefined;
  const owner = input.keys.address();
  const note = openRingDelivery(
    { ring: site.ring },
    {
      body,
      slotSecret,
      owner: {
        signingPublicKey: owner.signingPublicKey,
        nullifierPublicKey: owner.nullifierPublicKey,
      },
      commitment: site.slot.outputContext.hash,
      treeId: outputTreeId(site.slot.outputContext),
    },
    input.assets,
  );
  return note === undefined ? PENDING : Object.freeze({ ...note, slot: site.slot });
}

/** A body that fails to open is another key's or malformed, an abort still stops the sync. */
async function opened<T>(
  context: RequestContext | undefined,
  open: () => Promise<T | undefined>,
): Promise<T | undefined> {
  try {
    return await open();
  } catch (error) {
    if (context?.signal?.aborted === true) throw error;
    return undefined;
  }
}

/** The deposits under one of `tags`, one proofless transaction per deposited output. */
async function taggedDeposits(
  client: Pick<IndexerReader, "getEncryptedUtxosByTags">,
  tags: readonly Bytes32[],
  context: RequestContext | undefined,
): Promise<readonly IndexedShieldedTransaction[]> {
  const deposits: IndexedShieldedTransaction[] = [];
  let cursor: Uint8Array | undefined;
  for (;;) {
    const page = await client.getEncryptedUtxosByTags(
      { tags: [...tags], ...(cursor === undefined ? {} : { cursor }) },
      undefined,
      context,
    );
    for (const match of page.matches)
      deposits.push({
        slot: match.slot,
        txSignature: match.txSignature,
        outputSlots: [match.outputSlot],
        messages: [],
        nullifiers: [],
        proofless: true,
      });
    cursor = nextScanCursor(cursor, page);
    if (cursor === undefined) return deposits;
  }
}

async function taggedTransactions(
  client: Pick<IndexerReader, "getShieldedTransactionsByTags">,
  tags: readonly Bytes32[],
  context: RequestContext | undefined,
): Promise<readonly IndexedShieldedTransaction[]> {
  const transactions: IndexedShieldedTransaction[] = [];
  let cursor: Uint8Array | undefined;
  for (;;) {
    const page = await client.getShieldedTransactionsByTags(
      { tags: [...tags], ...(cursor === undefined ? {} : { cursor }) },
      undefined,
      context,
    );
    transactions.push(...page.transactions);
    cursor = nextScanCursor(cursor, page);
    if (cursor === undefined) return transactions;
  }
}
