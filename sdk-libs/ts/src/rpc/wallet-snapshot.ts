import { equalBytes } from "@heliuslabs/spr/internal";
import type { RequestContext } from "@heliuslabs/spr/interface";

import { RingError } from "../protocol/error.js";
import type { RingWalletStatusPage } from "./ring-rpc.js";

export const SNAPSHOT_CURSOR_LENGTH = 129;
export const SNAPSHOT_CURSOR_VERSION = 2;
const SNAPSHOT_POSITION_OFFSET = SNAPSHOT_CURSOR_LENGTH - 32;

interface SnapshotReader<Page> {
  readonly read: (cursor?: Uint8Array) => Promise<Page>;
  readonly status: (page: Page) => RingWalletStatusPage;
  readonly release: (cursor: Uint8Array, context?: RequestContext) => Promise<void>;
  readonly context?: RequestContext;
}

export async function* snapshotPages<Page>(
  reader: SnapshotReader<Page>,
): AsyncGenerator<Page, void> {
  let cursor: Uint8Array | undefined;
  let releaseCursor: Uint8Array | undefined;
  let captured:
    | Pick<RingWalletStatusPage, "historyThrough" | "enrollment" | "snapshotExpiresAt">
    | undefined;
  let readFailure: { error: unknown } | undefined;
  try {
    do {
      const page = await reader.read(cursor);
      const status = reader.status(page);
      if (status.cursor !== undefined) {
        if (
          status.snapshotExpiresAt === undefined ||
          status.cursor.length !== SNAPSHOT_CURSOR_LENGTH ||
          status.cursor[0] !== SNAPSHOT_CURSOR_VERSION ||
          (releaseCursor !== undefined &&
            (!equalBytes(
              releaseCursor.subarray(0, SNAPSHOT_POSITION_OFFSET),
              status.cursor.subarray(0, SNAPSHOT_POSITION_OFFSET),
            ) ||
              !advances(releaseCursor, status.cursor)))
        ) {
          throw inconsistentPage();
        }
      }
      if (captured === undefined) {
        if (status.snapshotExpiresAt !== undefined && status.cursor === undefined) {
          throw inconsistentPage();
        }
        captured = {
          historyThrough: status.historyThrough,
          enrollment: status.enrollment,
          ...(status.snapshotExpiresAt === undefined
            ? {}
            : { snapshotExpiresAt: status.snapshotExpiresAt }),
        };
      } else if (
        status.historyThrough !== captured.historyThrough ||
        status.snapshotExpiresAt !== captured.snapshotExpiresAt ||
        status.enrollment !== captured.enrollment ||
        status.balances.length !== 0
      ) {
        throw inconsistentPage();
      }
      cursor = status.cursor === undefined ? undefined : new Uint8Array(status.cursor);
      if (cursor !== undefined) releaseCursor = new Uint8Array(cursor);
      yield page;
    } while (cursor !== undefined);
  } catch (error) {
    readFailure = { error };
    throw error;
  } finally {
    await release();
  }

  async function release(): Promise<void> {
    if (releaseCursor !== undefined) {
      const context =
        reader.context?.timeoutMs === undefined
          ? undefined
          : { timeoutMs: reader.context.timeoutMs };
      try {
        await reader.release(releaseCursor, context);
      } catch (error) {
        if (readFailure !== undefined) {
          throw new AggregateError(
            [readFailure.error, error],
            "wallet snapshot read and release failed",
          );
        }
        throw error;
      }
    }
  }
}

function inconsistentPage(): RingError {
  return new RingError("RING_RPC", {
    details: { reason: "wallet snapshot page is inconsistent" },
  });
}

function advances(previous: Uint8Array, next: Uint8Array): boolean {
  for (let index = SNAPSHOT_POSITION_OFFSET; index < SNAPSHOT_CURSOR_LENGTH; index++) {
    const prior = previous[index]!;
    const current = next[index]!;
    if (prior !== current) return prior < current;
  }
  return false;
}
