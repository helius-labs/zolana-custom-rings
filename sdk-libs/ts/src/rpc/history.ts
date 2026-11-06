/** A ring's history read in order, each event bound to its confirmed transaction, Rust `pages`. */
import type { Address } from "@solana/kit";

import {
  ClientError,
  type IndexerReader,
  type IndexerRpcConfig,
  type PaginationToken,
} from "@heliuslabs/spr/client";
import { PAGE_LIMIT } from "@heliuslabs/spr/internal";
import type { RequestContext } from "@heliuslabs/spr/interface";
import type { IndexedShieldedTransaction } from "@heliuslabs/spr/transaction";

import { rowEventIndex, type RowOrigins } from "../operations/audit/row-origins.js";
import { RingError } from "../protocol/error.js";
import type { ConfirmedRingTransaction } from "../protocol/transaction/origin.js";

export interface ScanLimits {
  readonly pageSize: number;
  readonly maxPages: number;
}

const DEFAULT_PAGE_SIZE = 1000;
const DEFAULT_MAX_PAGES = 32;

/** The query a cursor belongs to beside its ring. */
export type HistoryStream = "tags" | "ring";

/** A bare token skips another query's rows before its position. */
export function historyCursor(
  ring: Address,
  stream: HistoryStream,
  token: PaginationToken,
): string {
  return `${ring}:${stream}:${token}`;
}

/** Refused under another ring or stream. */
export function historyCursorToken(
  cursor: string | undefined,
  ring: Address,
  stream: HistoryStream,
): PaginationToken | undefined {
  if (cursor === undefined) return undefined;
  const prefix = `${ring}:${stream}:`;
  if (typeof cursor !== "string" || !cursor.startsWith(prefix))
    throw new RingError("RING_HISTORY_CURSOR_INVALID");
  return cursor.slice(prefix.length);
}

/** The next request's token, `undefined` past a terminal page, a token that repeats never ends. */
export function nextHistoryToken(
  previous: PaginationToken | undefined,
  page: Readonly<{ paginationToken: PaginationToken | null }>,
): PaginationToken | undefined {
  const token = page.paginationToken;
  if (token === null) return undefined;
  if (token === previous) throw new RingError("RING_HISTORY_PAGE_INVALID");
  return token;
}

/** A limit outside its range is refused before any read. */
export function scanLimits(
  input: Readonly<{
    pageSize?: number | undefined;
    maxPages?: number | undefined;
  }>,
): ScanLimits {
  const pageSize = input.pageSize ?? DEFAULT_PAGE_SIZE;
  const maxPages = input.maxPages ?? DEFAULT_MAX_PAGES;
  for (const [name, value, limit] of [
    ["pageSize", pageSize, Number(PAGE_LIMIT)],
    ["maxPages", maxPages, Number.MAX_SAFE_INTEGER],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1 || value > limit)
      throw new RingError("RING_RPC", {
        details: { reason: "invalid scan limit", name, value },
      });
  }
  return Object.freeze({ pageSize, maxPages });
}

/** Retries at half on a page too large, the same token loses no row. */
export class HalvingPageLimit {
  #limit: number;

  constructor(limit: number) {
    this.#limit = limit;
  }

  get value(): number {
    return this.#limit;
  }

  async read<T>(fetch: (limit: number) => Promise<T>): Promise<T> {
    for (;;) {
      try {
        return await fetch(this.#limit);
      } catch (error) {
        const tooLarge =
          error instanceof ClientError && error.code === "CLIENT_INDEXER_RESPONSE_TOO_LARGE";
        if (!tooLarge || this.#limit === 1) throw error;
        this.#limit = Math.floor(this.#limit / 2);
      }
    }
  }
}

/** Rust `HistoryPosition`. */
export interface RingHistoryReach {
  /** Set only when the page cap stopped the read. */
  readonly nextCursor?: string;
  /** The final page's snapshot slot, set only past a terminal page, stored in the write of the notes it covers. */
  readonly checkpoint?: bigint;
}

/** A bad row lands in `rows`, a resumed `cursor` takes the same `afterSlot`. */
export function readRingHistory(
  input: RingPagesInput & Readonly<{ rows: RowOrigins }>,
  visit: (confirmed: ConfirmedRingTransaction, eventIndex: number) => void,
  context: RequestContext | undefined,
): Promise<RingHistoryReach> {
  return readRingPages(
    input,
    async (rows) => {
      for (const indexed of rows) {
        const confirmed = await input.rows.read(indexed);
        if (confirmed !== undefined)
          input.rows.attempt(indexed, () => visit(confirmed, rowEventIndex(indexed)));
      }
    },
    context,
  );
}

export interface RingPagesInput {
  readonly client: Pick<IndexerReader, "getShieldedTransactionsByTags">;
  readonly ringProgramId: Address;
  readonly cursor?: string;
  /** Strictly past it, never derived from a row or a token. */
  readonly afterSlot?: bigint;
  readonly limits: ScanLimits;
  readonly config?: IndexerRpcConfig;
}

/** Each page's rows of the ring in order, a page the source refuses stops the read with no checkpoint. */
export async function readRingPages(
  input: RingPagesInput,
  visit: (rows: readonly IndexedShieldedTransaction[]) => Promise<void>,
  context: RequestContext | undefined,
): Promise<RingHistoryReach> {
  const { pageSize, maxPages } = input.limits;
  let token = historyCursorToken(input.cursor, input.ringProgramId, "ring");
  const followed = new Set<PaginationToken>();
  const pageLimit = new HalvingPageLimit(pageSize);
  for (let page = 0; page < maxPages; page++) {
    const paginationToken = token === undefined ? {} : { paginationToken: token };
    const response = await pageLimit.read((limit) =>
      input.client.getShieldedTransactionsByTags(
        {
          tags: [],
          ringProgramId: input.ringProgramId,
          limit,
          ...paginationToken,
          ...(input.afterSlot === undefined ? {} : { filters: { slot: { gt: input.afterSlot } } }),
        },
        input.config,
        context,
      ),
    );
    if (response.data.length > pageLimit.value) throw new RingError("RING_HISTORY_PAGE_INVALID");
    await visit(
      response.data
        .flatMap((item) => item.events)
        .filter((indexed) => indexed.ringProgramId === input.ringProgramId),
    );
    const next = nextHistoryToken(token, response);
    if (next === undefined) return Object.freeze({ checkpoint: response.context.slot });
    if (followed.has(next)) throw new RingError("RING_HISTORY_PAGE_INVALID");
    followed.add(next);
    token = next;
  }
  return Object.freeze(
    token === undefined ? {} : { nextCursor: historyCursor(input.ringProgramId, "ring", token) },
  );
}
