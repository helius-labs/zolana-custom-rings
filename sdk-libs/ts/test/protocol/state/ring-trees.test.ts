import { describe, expect, it, vi } from "vitest";

import { treeAddress } from "@heliuslabs/spr/internal";
import { SHIELDED_POOL_PROGRAM_ID } from "@heliuslabs/spr/interface";
import type { RpcAccount } from "@heliuslabs/spr/client";
import { ringTreeIdResolver } from "../../../src/protocol/membership/trees.js";
import { ownedAccount } from "../../helpers/ring-accounts.js";
import { treeAccount } from "../../../../../zolana/sdk-libs/ts/test/helpers/tree-account.js";

function treeWithId(treeId: number): RpcAccount {
  return ownedAccount(
    SHIELDED_POOL_PROGRAM_ID,
    treeAccount({ stateCursor: 1, written: 2, nullifierCursor: 3n, treeId }),
  );
}

describe("ringTreeIdResolver", () => {
  it("reads a tree again after a failed read", async () => {
    const tree = treeAddress(2);
    const getAccount = vi
      .fn<(address: string) => Promise<RpcAccount | undefined>>()
      .mockRejectedValueOnce(new Error("rpc down"))
      .mockResolvedValue(treeWithId(2));
    const resolve = ringTreeIdResolver({ getAccount }, []);
    await expect(resolve(tree)).rejects.toThrow("rpc down");
    await expect(resolve(tree)).resolves.toBe(2);
    await expect(resolve(tree)).resolves.toBe(2);
    expect(getAccount).toHaveBeenCalledTimes(2);
  });

  it("does not share a cancellable lookup between callers", async () => {
    const tree = treeAddress(2);
    const pending: Array<(account: RpcAccount) => void> = [];
    const getAccount = vi.fn(() => new Promise<RpcAccount>((resolve) => pending.push(resolve)));
    const controller = new AbortController();
    const resolve = ringTreeIdResolver({ getAccount }, [], { signal: controller.signal });
    const first = resolve(tree);
    const second = resolve(tree);
    expect(getAccount).toHaveBeenCalledTimes(2);
    pending[0]?.(treeWithId(2));
    pending[1]?.(treeWithId(2));
    await expect(first).resolves.toBe(2);
    await expect(second).resolves.toBe(2);
    await expect(resolve(tree)).resolves.toBe(2);
    expect(getAccount).toHaveBeenCalledTimes(2);
  });

  it("does not share a deadline-bound lookup between callers", async () => {
    const tree = treeAddress(2);
    const pending: Array<(account: RpcAccount) => void> = [];
    const getAccount = vi.fn(() => new Promise<RpcAccount>((resolve) => pending.push(resolve)));
    const resolve = ringTreeIdResolver({ getAccount }, [], { timeoutMs: 1000 });
    const first = resolve(tree);
    const second = resolve(tree);
    expect(getAccount).toHaveBeenCalledTimes(2);
    pending[0]?.(treeWithId(2));
    pending[1]?.(treeWithId(2));
    await expect(first).resolves.toBe(2);
    await expect(second).resolves.toBe(2);
  });
});
