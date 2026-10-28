import { WalletError } from "@heliuslabs/zolana";

/** A key holder answers each batch with exactly one value per request. */
export function exactlyOne<T>(values: readonly T[]): T {
  const [value] = values;
  if (values.length !== 1 || value === undefined)
    throw new WalletError("WALLET_KEYS_BATCH_MISMATCH");
  return value;
}

/** Each request beside the one value the key holder answered for it. */
export function answered<R, V>(
  requests: readonly R[],
  values: readonly V[],
): readonly (readonly [R, V])[] {
  if (values.length !== requests.length) throw new WalletError("WALLET_KEYS_BATCH_MISMATCH");
  return values.map((value, at) => {
    const request = requests[at];
    if (request === undefined) throw new WalletError("WALLET_KEYS_BATCH_MISMATCH");
    return [request, value] as const;
  });
}

/** `seen` takes `key`, `false` when it already held it. */
export function unseen(seen: Set<string>, key: string): boolean {
  if (seen.has(key)) return false;
  seen.add(key);
  return true;
}
