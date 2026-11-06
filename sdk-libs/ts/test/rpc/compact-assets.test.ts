import {
  address,
  getAddressDecoder,
  getAddressEncoder,
  getBase64Decoder,
  getBase64Encoder,
  getU64Decoder,
  getU64Encoder,
  SolanaError,
  SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND,
  type Address,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";
import {
  decodeSplAssetRegistry,
  SHIELDED_POOL_PROGRAM_ID,
  StateDiscriminator,
} from "@heliuslabs/spr/interface";
import { splAssetCounterAddress, splAssetRegistryAddress } from "@heliuslabs/spr/internal";
import { SOL_MINT } from "@heliuslabs/spr/transaction";
import { kitReads } from "../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import {
  COMPACT_ASSET_LOOKUP_BUDGET,
  CompactAssetResolver,
  SPL_ASSET_REGISTRY_ASSET_ID_OFFSET,
} from "../../src/rpc/compact-assets.js";

const mint = address("54XGz8UVJaGpwba1nxsNC4AfVZ6Uiue6J9cymVSv2Qpu");
const base64Decoder = getBase64Decoder();
const base64Encoder = getBase64Encoder();
const addressEncoder = getAddressEncoder();
const u64Encoder = getU64Encoder();
const u64Decoder = getU64Decoder();

function account(data: Uint8Array, owner: Address = SHIELDED_POOL_PROGRAM_ID) {
  return {
    data: [base64Decoder.decode(data), "base64"] as const,
    executable: false,
    lamports: 1n,
    owner,
    rentEpoch: 0n,
    space: BigInt(data.length),
  };
}

function counter(nextId: bigint) {
  return account(
    Uint8Array.from([
      StateDiscriminator.splAssetCounter,
      ...new Uint8Array(7),
      ...u64Encoder.encode(nextId),
    ]),
  );
}

async function registration(assetId: bigint, mintAddress: Address = mint) {
  return {
    pubkey: await splAssetRegistryAddress(mintAddress),
    account: account(
      Uint8Array.from([
        StateDiscriminator.splAssetRegistry,
        ...new Uint8Array(7),
        ...addressEncoder.encode(mintAddress),
        ...u64Encoder.encode(assetId),
      ]),
    ),
  };
}

type RegistryEntry = Awaited<ReturnType<typeof registration>>;
type Filter = Readonly<{ memcmp: Readonly<{ offset: bigint; bytes: string }> }>;

function reader(registryRead: (assetId: bigint) => Promise<readonly RegistryEntry[]>) {
  const getAccountInfo = vi.fn((address: Address, config: object) => ({
    send: async () => {
      expect(address).toBe(await splAssetCounterAddress());
      expect(config).toMatchObject({ commitment: "confirmed", minContextSlot: 99n });
      return { context: { slot: 99n }, value: counter(100n) };
    },
  }));
  const getProgramAccounts = vi.fn(
    (program: Address, config: Readonly<{ filters: readonly Filter[] }>) => ({
      send: async () => {
        expect(program).toBe(SHIELDED_POOL_PROGRAM_ID);
        expect(config).toMatchObject({
          commitment: "confirmed",
          minContextSlot: 99n,
          withContext: true,
        });
        const filter = config.filters.find(
          (filter) => filter.memcmp.offset === SPL_ASSET_REGISTRY_ASSET_ID_OFFSET,
        );
        if (filter === undefined) throw new Error("asset filter absent");
        const assetId = u64Decoder.decode(base64Encoder.encode(filter.memcmp.bytes));
        return { context: { slot: 99n }, value: await registryRead(assetId) };
      },
    }),
  );
  return {
    client: kitReads({ solanaRpc: { getAccountInfo, getProgramAccounts } }),
    getAccountInfo,
    getProgramAccounts,
  };
}

describe("compact asset resolution", () => {
  it("filters on the asset id offset the registry decoder reads", async () => {
    const data = new Uint8Array(base64Encoder.encode((await registration(7n)).account.data[0]));
    const offset = Number(SPL_ASSET_REGISTRY_ASSET_ID_OFFSET);
    expect(u64Decoder.decode(data.subarray(offset, offset + 8))).toBe(7n);
    expect(decodeSplAssetRegistry(data).assetId).toBe(7n);
  });

  it("rejects impossible IDs without registry reads and caches authenticated results", async () => {
    const rpc = reader(async (assetId) => [await registration(assetId)]);
    const resolver = await CompactAssetResolver.open({ client: rpc.client, targetSlot: 99n });
    expect(await resolver.resolve(0n)).toEqual({ kind: "foreign" });
    expect(await resolver.resolve(100n)).toEqual({ kind: "foreign" });
    expect(await resolver.resolve(0xffff_ffff_ffff_ffffn)).toEqual({ kind: "foreign" });
    expect(await resolver.resolve(1n)).toMatchObject({
      kind: "resolved",
      mint: { asset: SOL_MINT },
    });
    expect(rpc.getProgramAccounts).not.toHaveBeenCalled();
    const resolved = await resolver.resolve(2n);
    expect(resolved).toMatchObject({ kind: "resolved", mint: { asset: mint, assetId: 2n } });
    expect(await resolver.resolve(2n)).toEqual(resolved);
    expect(rpc.getProgramAccounts).toHaveBeenCalledTimes(1);
    expect(resolver.remainingLookups).toBe(COMPACT_ASSET_LOOKUP_BUDGET - 1);
  });

  it("treats a missing allocated mapping as inconsistent", async () => {
    const rpc = reader(async () => []);
    const resolver = await CompactAssetResolver.open({ client: rpc.client, targetSlot: 99n });
    await expect(resolver.resolve(2n)).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
    });
    expect(resolver.remainingLookups).toBe(COMPACT_ASSET_LOOKUP_BUDGET - 1);
  });

  it.each(["owner", "pda", "id", "duplicate"])("refuses a forged registry %s", async (field) => {
    const rpc = reader(async (assetId) => {
      const row = await registration(field === "id" ? assetId + 1n : assetId);
      if (field === "owner") row.account.owner = SOL_MINT;
      if (field === "pda") row.pubkey = SOL_MINT;
      return field === "duplicate" ? [row, row] : [row];
    });
    const resolver = await CompactAssetResolver.open({ client: rpc.client, targetSlot: 99n });
    await expect(resolver.resolve(2n)).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
    });
  });

  it("pauses without another network read when the lookup budget is empty", async () => {
    const rpc = reader(async (assetId) => {
      const bytes = new Uint8Array(32).fill(7);
      bytes.set(u64Encoder.encode(assetId));
      return [await registration(assetId, getAddressDecoder().decode(bytes))];
    });
    const resolver = await CompactAssetResolver.open({ client: rpc.client, targetSlot: 99n });
    for (let index = 0; index < COMPACT_ASSET_LOOKUP_BUDGET; index++) {
      expect(await resolver.resolve(BigInt(index + 2))).toMatchObject({ kind: "resolved" });
    }
    expect(await resolver.resolve(99n)).toEqual({ kind: "paused" });
    expect(await resolver.resolve(2n)).toMatchObject({ kind: "resolved" });
    expect(rpc.getProgramAccounts).toHaveBeenCalledTimes(COMPACT_ASSET_LOOKUP_BUDGET);
  });

  it("preserves source failure without caching absence", async () => {
    let unavailable = true;
    const rpc = reader(async (assetId) => {
      if (unavailable) {
        throw new SolanaError(SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND, {
          __serverMessage: "unavailable",
        });
      }
      return [await registration(assetId)];
    });
    const resolver = await CompactAssetResolver.open({ client: rpc.client, targetSlot: 99n });
    await expect(resolver.resolve(2n)).rejects.toMatchObject({
      code: "CLIENT_UNSUPPORTED_RPC_METHOD",
    });
    unavailable = false;
    expect(await resolver.resolve(2n)).toMatchObject({ kind: "resolved" });
    expect(rpc.getProgramAccounts).toHaveBeenCalledTimes(2);
  });

  it.each(["missing", "owner", "range", "slot"])("refuses an invalid counter %s", async (field) => {
    const value = counter(field === "range" ? 1n : 2n);
    if (field === "owner") value.owner = SOL_MINT;
    const client = kitReads({
      solanaRpc: {
        getAccountInfo: () => ({
          send: async () => ({
            context: { slot: field === "slot" ? 98n : 99n },
            value: field === "missing" ? null : value,
          }),
        }),
      },
    });
    await expect(CompactAssetResolver.open({ client, targetSlot: 99n })).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
    });
  });
});
