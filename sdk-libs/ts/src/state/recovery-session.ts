import { address } from "@solana/kit";
import { U64_MAX, PAGE_LIMIT } from "@heliuslabs/spr/internal";
import type { Wallet, WalletUtxo } from "@heliuslabs/spr/transaction";
import { RingError } from "../protocol/error.js";
import { ViewingHistory } from "./viewing-history.js";

export const RECOVERY_DIAGNOSTIC_SAMPLES = 64;

export interface RecoveryCoverage {
  readonly status: "Paused" | "Complete";
  readonly targetSlot: bigint | null;
  readonly checkedNullifiers: ReadonlySet<string>;
}

export interface RecoveryWallet extends Wallet {
  recoveryCoverage(): RecoveryCoverage;
}

export interface RecoveryPage {
  limit: number;
  token: string | null;
  workOffset: number;
}

export interface RecoveryRing extends RecoveryPage {
  kind: "ring";
  ring: string;
  keys: string[];
  afterSlot: bigint | null;
}

export type RecoveryTask = RecoveryRing;

export interface RecoverySession {
  version: 1;
  owner: string;
  keys: string[];
  mode: "tagHints" | "everySite";
  rescan: boolean;
  senderFastPath: boolean;
  ring: string | null;
  history: string;
  targetSlot: bigint | null;
  tasks: RecoveryTask[];
  task: number;
  queue: string[];
  checked: string[];
  active: (RecoveryPage & { nullifiers: string[] }) | null;
  unopenedCount: bigint;
  unopenedSamples: string[];
}

export function recoverySessionJson(session: RecoverySession | null): string {
  return JSON.stringify(session, (_, value: unknown) =>
    typeof value === "bigint" ? value.toString() : value,
  );
}

export function restoreRecoverySession(value: unknown): RecoverySession | null {
  if (value === null || value === undefined) return null;
  const stored = record(value);
  if (stored.version !== 1 && stored.version !== 1n) throw invalid();
  const mode = stored.mode;
  if (mode !== "tagHints" && mode !== "everySite") throw invalid();
  if (typeof stored.rescan !== "boolean" || typeof stored.senderFastPath !== "boolean")
    throw invalid();
  const history = string(stored.history);
  ViewingHistory.fromJson(history);
  const keys = strings(stored.keys).map(key);
  const tasks = list(stored.tasks).map(task);
  const cursor = integer(stored.task);
  if (cursor > tasks.length || keys.length === 0 || new Set(keys).size !== keys.length)
    throw invalid();
  const active = stored.active === null ? null : record(stored.active);
  const samples = strings(stored.unopenedSamples).map(hash);
  if (
    samples.length > RECOVERY_DIAGNOSTIC_SAMPLES ||
    u64(stored.unopenedCount) < BigInt(samples.length)
  )
    throw invalid();
  const session: RecoverySession = {
    version: 1,
    owner: string(stored.owner),
    keys,
    mode,
    rescan: stored.rescan === true,
    senderFastPath: stored.senderFastPath === true,
    ring: stored.ring === null ? null : address(string(stored.ring)),
    history,
    targetSlot: optionalSlot(stored.targetSlot),
    tasks,
    task: cursor,
    queue: strings(stored.queue).map(hash),
    checked: strings(stored.checked).map(hash),
    active:
      active === null
        ? null
        : {
            ...page(active),
            nullifiers: strings(active.nullifiers).map(hash),
          },
    unopenedCount: u64(stored.unopenedCount),
    unopenedSamples: samples,
  };
  if (
    session.active !== null &&
    (session.active.nullifiers.length === 0 ||
      session.active.nullifiers.length > Number(PAGE_LIMIT) ||
      session.active.workOffset !== 0)
  )
    throw invalid();
  const queued = [...session.queue, ...session.checked, ...(session.active?.nullifiers ?? [])];
  if (new Set(queued).size !== queued.length) throw invalid();
  if (
    session.targetSlot === null &&
    (session.task !== 0 || session.active !== null || session.checked.length !== 0)
  )
    throw invalid();
  for (const item of tasks) {
    if (
      item.keys.length === 0 ||
      new Set(item.keys).size !== item.keys.length ||
      (session.mode === "everySite" && item.ring !== session.ring) ||
      item.keys.some((held) => !keys.includes(held))
    )
      throw invalid();
  }
  return session;
}

export function recoveryAllows(
  coverage: RecoveryCoverage,
  note: WalletUtxo,
  nullifier: string,
): boolean {
  return (
    !note.spent && (coverage.status === "Complete" || coverage.checkedNullifiers.has(nullifier))
  );
}

function task(value: unknown): RecoveryTask {
  const stored = record(value);
  if (stored.kind !== "ring") throw invalid();
  return {
    ...page(stored),
    kind: "ring",
    ring: address(string(stored.ring)),
    keys: strings(stored.keys).map(key),
    afterSlot: optionalSlot(stored.afterSlot),
  };
}

function page(stored: Record<string, unknown>): RecoveryPage {
  const limit = integer(stored.limit);
  if (limit < 1 || limit > Number(PAGE_LIMIT)) throw invalid();
  return {
    limit,
    token: stored.token === null ? null : string(stored.token),
    workOffset: integer(stored.workOffset),
  };
}

function optionalSlot(value: unknown): bigint | null {
  return value === null ? null : u64(value);
}

function u64(value: unknown): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) throw invalid();
  const parsed = BigInt(value);
  if (parsed > U64_MAX) throw invalid();
  return parsed;
}

function integer(value: unknown): number {
  const parsed = typeof value === "bigint" ? Number(value) : value;
  if (typeof parsed !== "number" || !Number.isSafeInteger(parsed) || parsed < 0) throw invalid();
  return parsed;
}

function strings(value: unknown): string[] {
  return list(value).map(string);
}
function list(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw invalid();
  return value;
}
function string(value: unknown): string {
  if (typeof value !== "string") throw invalid();
  return value;
}
function hash(value: unknown): string {
  const parsed = string(value);
  if (!/^[0-9a-f]{64}$/.test(parsed)) throw invalid();
  return parsed;
}
function key(value: unknown): string {
  const parsed = string(value);
  if (!/^[0-9a-f]{66}$/.test(parsed)) throw invalid();
  return parsed;
}
function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalid();
  return value as Record<string, unknown>;
}
function invalid(): RingError {
  return new RingError("RING_WALLET_DOCUMENT", { details: { reason: "invalid recovery session" } });
}
