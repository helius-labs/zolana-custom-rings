/** The scan's candidate step over plain bytes, a `Worker` runs it as the key's holder. */
import { initializePoseidon } from "@heliuslabs/spr";
import type { Bytes16, Bytes32 } from "@heliuslabs/spr/interface";
import { ViewingKey, X25519PublicKey } from "@heliuslabs/spr/keypair";

import { RingError } from "../protocol/error.js";
import {
  ViewingKeyHolder,
  type RingKeys,
  type RingTagFrame,
  type RingTagProbe,
} from "./ring-keys.js";

/** A tag frame that survives a structured clone, the worker's one key implied. */
export interface PlainTagFrame {
  readonly txViewingKey: Uint8Array;
  readonly salt: Bytes16;
  readonly firstNullifier: Bytes32;
  readonly probes: readonly RingTagProbe[];
}

export interface ScanWorkerRequest {
  readonly viewingSecret: Bytes32;
  readonly frames: readonly PlainTagFrame[];
}

/** Per frame one answer per probe, the slot secret on a match. */
export type ScanWorkerReply = readonly (readonly (Bytes32 | undefined)[])[];

/** A failure carries its error code alone, never a message or a stack. */
export type ScanWorkerResponse =
  | Readonly<{ ok: true; matches: ScanWorkerReply }>
  | Readonly<{ ok: false; code: string }>;

export function plainTagFrame(frame: RingTagFrame): PlainTagFrame {
  return {
    txViewingKey: frame.txViewingPublicKey.toBytes(),
    salt: frame.salt,
    firstNullifier: frame.firstNullifier,
    probes: frame.probes,
  };
}

/** Never rejects, a sync waiting on the worker gets an answer to every message. */
export async function scanWorkerResponse(request: ScanWorkerRequest): Promise<ScanWorkerResponse> {
  try {
    return Object.freeze({ ok: true, matches: await answerScanRequest(request) });
  } catch (cause) {
    return Object.freeze({ ok: false, code: failureCode(cause) });
  }
}

/** Wipes the request's secret on every path. */
export async function answerScanRequest(request: ScanWorkerRequest): Promise<ScanWorkerReply> {
  let holder: ViewingKeyHolder | undefined;
  try {
    await initializePoseidon();
    const key = ViewingKey.fromBytes(request.viewingSecret);
    const viewingPublicKey = key.publicKey();
    holder = new ViewingKeyHolder([key]);
    return await holder.ringTagMatches(
      request.frames.map((frame) => ({
        viewingPublicKey,
        txViewingPublicKey: X25519PublicKey.fromBytes(frame.txViewingKey),
        salt: frame.salt,
        firstNullifier: frame.firstNullifier,
        probes: frame.probes,
      })),
    );
  } finally {
    holder?.destroy();
    request.viewingSecret?.fill(0);
  }
}

/** Sends a sync's tag test to `ask`, a sync names one viewing key per call. */
export function scanWorkerMatcher(
  ask: (
    viewingPublicKey: X25519PublicKey,
    frames: readonly PlainTagFrame[],
  ) => Promise<ScanWorkerResponse>,
): Pick<RingKeys, "ringTagMatches"> {
  return {
    ringTagMatches: async (frames) => {
      const [first] = frames;
      if (first === undefined) return [];
      const response = await ask(first.viewingPublicKey, frames.map(plainTagFrame));
      if (!response.ok)
        throw new RingError("RING_SCAN_WORKER_FAILED", { details: { code: response.code } });
      return response.matches;
    },
  };
}

function failureCode(cause: unknown): string {
  const code = (cause as { code?: unknown } | null | undefined)?.code;
  return typeof code === "string" && /^[A-Z0-9_]+$/.test(code) ? code : "UNKNOWN";
}
