import { getBase64Decoder, getU64Encoder, type Base64EncodedBytes } from "@solana/kit";
import { ClientError, type KitRpcAccess } from "@heliuslabs/spr/client";
import {
  decodeSplAssetCounter,
  decodeSplAssetRegistry,
  FIRST_ASSET_ID,
  SHIELDED_POOL_PROGRAM_ID,
  StateDiscriminator,
  type RequestContext,
} from "@heliuslabs/spr/interface";
import {
  runKitRpc,
  splAssetCounterAddress,
  splAssetRegistryAddress,
  U64_MAX,
  unsignedBigint,
  wireDecoder,
} from "@heliuslabs/spr/internal";
import { AssetRegistry, Mint, SOL_ASSET_ID, SOL_MINT } from "@heliuslabs/spr/transaction";

export const COMPACT_ASSET_LOOKUP_BUDGET = 32;

/** Rust `SplAssetRegistry::asset_id`. */
export const SPL_ASSET_REGISTRY_ASSET_ID_OFFSET = 40n;

export type CompactAssetResolution =
  | Readonly<{ kind: "foreign" }>
  | Readonly<{ kind: "resolved"; mint: Mint }>
  | Readonly<{ kind: "paused" }>;

export interface CompactAssetRead {
  readonly client: Pick<KitRpcAccess, "solanaRpc">;
  readonly targetSlot: bigint;
}

const base64Decoder = getBase64Decoder();
const u64Encoder = getU64Encoder();
const sol = Mint.fromRegistry(new AssetRegistry(), SOL_MINT);

export class CompactAssetResolver {
  readonly #client: CompactAssetRead["client"];
  readonly #targetSlot: bigint;
  readonly #nextId: bigint;
  readonly #cache = new Map<bigint, Mint>();
  #remaining = COMPACT_ASSET_LOOKUP_BUDGET;

  private constructor(input: CompactAssetRead, nextId: bigint) {
    this.#client = input.client;
    this.#targetSlot = input.targetSlot;
    this.#nextId = nextId;
  }

  static async open(
    input: CompactAssetRead,
    context?: RequestContext,
  ): Promise<CompactAssetResolver> {
    const { client, targetSlot } = input;
    unsignedBigint(targetSlot, U64_MAX, "targetSlot");
    const address = await splAssetCounterAddress();
    const response = await runKitRpc("getAccountInfo", context, (abortSignal) =>
      client.solanaRpc
        .getAccountInfo(address, {
          commitment: "confirmed",
          minContextSlot: targetSlot,
          encoding: "base64",
        })
        .send({ abortSignal }),
    );
    const data = accountBytes(
      contextValue(response, targetSlot, "getAccountInfo"),
      "getAccountInfo",
    );
    let nextId: bigint;
    try {
      nextId = decodeSplAssetCounter(data).nextId;
    } catch {
      throw invalid("getAccountInfo", "asset counter");
    }
    if (nextId < FIRST_ASSET_ID) throw invalid("getAccountInfo", "asset counter");
    return new CompactAssetResolver({ client, targetSlot }, nextId);
  }

  async resolve(assetId: bigint, context?: RequestContext): Promise<CompactAssetResolution> {
    unsignedBigint(assetId, U64_MAX, "assetId");
    if (assetId === SOL_ASSET_ID) return { kind: "resolved", mint: sol };
    if (assetId < FIRST_ASSET_ID || assetId >= this.#nextId) return { kind: "foreign" };
    const cached = this.#cache.get(assetId);
    if (cached !== undefined) return { kind: "resolved", mint: cached };
    if (this.#remaining === 0) return { kind: "paused" };
    this.#remaining--;
    const response = await runKitRpc("getProgramAccounts", context, (abortSignal) =>
      this.#client.solanaRpc
        .getProgramAccounts(SHIELDED_POOL_PROGRAM_ID, {
          commitment: "confirmed",
          minContextSlot: this.#targetSlot,
          encoding: "base64",
          withContext: true,
          filters: [
            {
              memcmp: {
                offset: 0n,
                encoding: "base64",
                bytes: base64Decoder.decode(
                  Uint8Array.of(StateDiscriminator.splAssetRegistry),
                ) as Base64EncodedBytes,
              },
            },
            {
              memcmp: {
                offset: SPL_ASSET_REGISTRY_ASSET_ID_OFFSET,
                encoding: "base64",
                bytes: base64Decoder.decode(u64Encoder.encode(assetId)) as Base64EncodedBytes,
              },
            },
          ],
        })
        .send({ abortSignal }),
    );
    const decode = wireDecoder((path) => invalid("getProgramAccounts", path));
    const entries = decode.list(
      contextValue(response, this.#targetSlot, "getProgramAccounts"),
      "value",
    );
    if (entries.length !== 1) {
      throw invalid("getProgramAccounts", "asset registry");
    }
    const entry = decode.record(entries[0], "value[0]");
    const address = decode.address(entry.pubkey, "value[0].pubkey");
    const data = accountBytes(entry.account, "getProgramAccounts");
    let registry: ReturnType<typeof decodeSplAssetRegistry>;
    try {
      registry = decodeSplAssetRegistry(data);
    } catch {
      throw invalid("getProgramAccounts", "asset registry");
    }
    if (
      registry.assetId !== assetId ||
      registry.mint === SOL_MINT ||
      address !== (await splAssetRegistryAddress(registry.mint)) ||
      (this.#cache.has(assetId) && this.#cache.get(assetId)?.asset !== registry.mint) ||
      this.#containsOtherMint(assetId, registry.mint)
    ) {
      throw invalid("getProgramAccounts", "asset registry");
    }
    const assets = new AssetRegistry([[assetId, registry.mint]]);
    const mint = Mint.fromRegistry(assets, registry.mint);
    this.#cache.set(assetId, mint);
    return { kind: "resolved", mint };
  }

  get targetSlot(): bigint {
    return this.#targetSlot;
  }

  get remainingLookups(): number {
    return this.#remaining;
  }

  #containsOtherMint(assetId: bigint, mint: Mint["asset"]): boolean {
    for (const [knownId, known] of this.#cache) {
      if (knownId !== assetId && known.asset === mint) return true;
    }
    return false;
  }
}

function invalid(method: string, path: string): ClientError {
  return new ClientError("CLIENT_INVALID_RPC_RESPONSE", { details: { method, path } });
}

function contextValue(response: unknown, targetSlot: bigint, method: string): unknown {
  const decode = wireDecoder((path) => invalid(method, path));
  const root = decode.record(response, "result");
  const context = decode.record(root.context, "context");
  if (typeof context.slot !== "bigint" || context.slot < targetSlot || context.slot > U64_MAX) {
    throw invalid(method, "context.slot");
  }
  return root.value;
}

function accountBytes(value: unknown, method: string): Uint8Array {
  const decode = wireDecoder((path) => invalid(method, path));
  const account = decode.record(value, "account");
  if (decode.address(account.owner, "account.owner") !== SHIELDED_POOL_PROGRAM_ID) {
    throw invalid(method, "account.owner");
  }
  const data = decode.list(account.data, "account.data");
  if (data.length !== 2 || data[1] !== "base64") throw invalid(method, "account.data");
  return decode.base64(data[0], "account.data[0]");
}
