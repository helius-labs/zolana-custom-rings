import type { Commitment } from "@solana/kit";
import { DEFAULT_TREE_ID } from "@heliuslabs/zolana/interface";
import { treeAddress } from "@heliuslabs/zolana/internal";
import { BLOCKHASH, solanaRpcReads } from "../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import type { RingAuditReader } from "../../src/operations/audit/audit.js";
import type { RingTransferClient } from "../../src/operations/payments/transfer.js";

const TREE_ID = DEFAULT_TREE_ID;
const TREE = treeAddress(TREE_ID);

function notImplemented(member: string): () => never {
  return () => {
    throw new Error(`fake client member ${member} must not be called`);
  };
}

export function ringTransferClient(
  overrides: Partial<RingTransferClient> = {},
): RingTransferClient {
  return {
    tree: TREE,
    treeId: TREE_ID,
    getLatestBlockhash: async () => BLOCKHASH,
    getAccount: async () => undefined,
    getRingMemberOpenings: notImplemented("getRingMemberOpenings"),
    getRingRecordPool: notImplemented("getRingRecordPool"),
    proveRing: notImplemented("proveRing"),
    proveRingTransact: notImplemented("proveRingTransact"),
    proveAnonymousRingTransact: notImplemented("proveAnonymousRingTransact"),
    ...overrides,
  };
}

export function ringAuditReader(
  input: Readonly<{
    getShieldedTransactionsByTags: RingAuditReader["getShieldedTransactionsByTags"];
    solanaRpc?: object;
    commitment?: Commitment;
  }>,
): RingAuditReader {
  return {
    getShieldedTransactionsByTags: input.getShieldedTransactionsByTags,
    solanaRpc: solanaRpcReads(input.solanaRpc ?? {}),
    commitment: input.commitment ?? "confirmed",
  };
}
