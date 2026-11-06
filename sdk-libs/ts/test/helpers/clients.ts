import { getBase64Decoder, type Address, type Commitment } from "@solana/kit";
import { DEFAULT_TREE_ID } from "@heliuslabs/spr/interface";
import { treeAddress } from "@heliuslabs/spr/internal";
import type { SprClient } from "@heliuslabs/spr/client";
import { BLOCKHASH, solanaRpcReads } from "../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import type { RingAuditReader } from "../../src/operations/audit/audit.js";
import type { RingTransferClient } from "../../src/operations/payments/transfer.js";

const TREE_ID = DEFAULT_TREE_ID;
const TREE = treeAddress(TREE_ID);

export function notImplemented(member: string): () => never {
  return () => {
    throw new Error(`fake client member ${member} must not be called`);
  };
}

/** A fake's account read, `lamports` reads zero when it leaves them out. */
type FakeAccountRead = (
  address: Address,
) => Promise<Readonly<{ owner: Address; data: Uint8Array; lamports?: bigint }> | undefined>;

/** Kit `getAccountInfo` over a fake's `getAccount`, any commitment but `confirmed` throws. */
export function confirmedAccountReads(
  getAccount: FakeAccountRead,
  reads: object = {},
): SprClient["solanaRpc"] {
  return solanaRpcReads({
    ...reads,
    getAccountInfo: (address: Address, config: Readonly<{ commitment?: Commitment }>) => ({
      send: async () => {
        if (config.commitment !== "confirmed") throw new Error(`read at ${config.commitment}`);
        const account = await getAccount(address);
        return {
          value:
            account === undefined
              ? null
              : {
                  owner: account.owner,
                  lamports: account.lamports ?? 0n,
                  data: [getBase64Decoder().decode(account.data), "base64"],
                },
        };
      },
    }),
  });
}

/** `client` with a kit reader over its own `getAccount`, beside the kit reads it already fakes. */
export function withConfirmedReads<
  C extends { readonly getAccount: FakeAccountRead; readonly solanaRpc?: object },
>(client: C): C & Pick<SprClient, "solanaRpc"> {
  return { ...client, solanaRpc: confirmedAccountReads(client.getAccount, client.solanaRpc) };
}

export function ringTransferClient(
  overrides: Partial<RingTransferClient> = {},
): RingTransferClient {
  const getAccount = overrides.getAccount ?? (async () => undefined);
  return {
    tree: TREE,
    treeId: TREE_ID,
    getLatestBlockhash: async () => BLOCKHASH,
    getAccount,
    solanaRpc: confirmedAccountReads(getAccount),
    getStorageRecordPool: notImplemented("getStorageRecordPool"),
    getTrackingRecordPool: notImplemented("getTrackingRecordPool"),
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
