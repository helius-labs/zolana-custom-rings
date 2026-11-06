import { describe, expect, it, vi } from "vitest";

import { ZERO_NULLIFIER_PK } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";

import { NoteLedger } from "../../src/state/anonymous-sync.js";
import { ScanWallet } from "../helpers/ring-scan.js";

// Counts every hash comparison and every hash key the ledger takes.
vi.mock("@heliuslabs/spr/internal", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@heliuslabs/spr/internal")>();
  return { ...actual, bytesKey: vi.fn(actual.bytesKey), equalBytes: vi.fn(actual.equalBytes) };
});
const { bytesKey, equalBytes } = vi.mocked(await import("@heliuslabs/spr/internal"));

const NOTES = 10_000;

function hashOf(index: number): Bytes32 {
  const hash = new Uint8Array(32);
  new DataView(hash.buffer).setUint32(28, index);
  return hash as Bytes32;
}

describe("NoteLedger", () => {
  it("admits 10,000 unique notes with one lookup each and refuses each again", () => {
    const owner = new ScanWallet(1);
    const ledger = new NoteLedger(owner.keys, []);
    const viewingPublicKey = owner.keypair.viewingPublicKey();
    const notes = Array.from({ length: NOTES }, (_, index) => ({
      outputContext: { hash: hashOf(index) },
      nullifierPublicKey: ZERO_NULLIFIER_PK as Bytes32,
      order: { slot: BigInt(index), signature: new Uint8Array(64), position: 0 },
    }));
    bytesKey.mockClear();
    equalBytes.mockClear();

    let admitted = 0;
    for (const note of notes) {
      if (ledger.isFound(note.outputContext.hash)) continue;
      ledger.keep(note as never, viewingPublicKey, { kind: "fullScan" });
      admitted += 1;
    }
    expect(admitted).toBe(NOTES);
    // One key to look up and one to record per note, no scan over the notes kept.
    expect(bytesKey).toHaveBeenCalledTimes(2 * NOTES);
    expect(equalBytes).not.toHaveBeenCalled();

    expect(notes.filter((note) => !ledger.isFound(note.outputContext.hash))).toEqual([]);
    expect(bytesKey).toHaveBeenCalledTimes(3 * NOTES);
  });
});
