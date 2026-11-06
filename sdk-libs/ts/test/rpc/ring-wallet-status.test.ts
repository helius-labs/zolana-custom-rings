import { address, getBase58Decoder, generateKeyPairSigner, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes31, Bytes32 } from "@heliuslabs/spr/interface";
import { ZERO_NULLIFIER_PK } from "@heliuslabs/spr/internal";
import { NullifierKey } from "@heliuslabs/spr/keypair";

import {
  RingRpc,
  spendCoverageAttestation,
  walletStatusAttestation,
  walletSnapshotReleaseAttestation,
  delegateNotesAttestation,
  delegateSnapshotReleaseAttestation,
  type RingReadSigner,
  type RingReadTarget,
  delegateNoteKey,
} from "../../src/rpc/ring-rpc.js";

const base58 = getBase58Decoder();
const addressOf = (value: number): Address =>
  base58.decode(new Uint8Array(32).fill(value)) as Address;
const hashOf = (value: number): string => base58.decode(new Uint8Array(32).fill(value));
const SIGNATURE = base58.decode(new Uint8Array(64).fill(9));
const NONCE = new Uint8Array(32).fill(4) as Bytes32;
const TARGET: RingReadTarget = {
  cluster: new Uint8Array(32).fill(1) as Bytes32,
  service: addressOf(2),
  ringProgramId: addressOf(7),
};
const WALLET = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TARGET_LINES = `cluster: ${hashOf(1)}\nservice: ${addressOf(2)}\nring: ${addressOf(7)}`;
const NONCE_BASE64 = Buffer.from(NONCE).toString("base64");

function capture(result: unknown) {
  const bodies: Record<string, unknown>[] = [];
  const rpc = new RingRpc("http://ring.example", {
    allowInsecureHttp: true,
    fetch: (async (_input: URL | string, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch,
  });
  return { rpc, bodies };
}

const reader: RingReadSigner = {
  reader: Uint8Array.of(1, 0, ...new Uint8Array(32).fill(3)),
  sign: async () => new Uint8Array(64).fill(8),
};

function noteWire(status: string, overrides: Readonly<Record<string, unknown>> = {}) {
  return {
    utxoHash: hashOf(0x11),
    status,
    nullifierPk: hashOf(0x12),
    asset: hashOf(0x13),
    amount: 500,
    blinding: hashOf(0x14),
    dataHash: hashOf(0),
    ringDataHash: hashOf(0),
    treeId: 3,
    leafIndex: 77,
    slot: 40,
    txSignature: SIGNATURE,
    eventIndex: 2,
    slotIndex: 1,
    ...overrides,
  };
}

describe("wallet status attestation", () => {
  it("writes the lines Rust `WalletStatusAttestation::message` writes", () => {
    const message = walletStatusAttestation({
      target: TARGET,
      wallet: WALLET,
      timestamp: 1_700_000_000n,
      nonce: NONCE,
    });
    expect(new TextDecoder().decode(message)).toBe(
      `zolana/ring-rpc-wallet-status\n${TARGET_LINES}\ntimestamp: 1700000000\nnonce: ${NONCE_BASE64}\nwallet: ${WALLET}\ncursor: `,
    );
  });

  it("writes the lines Rust `SpendCoverageAttestation::message` writes", () => {
    const message = spendCoverageAttestation({
      target: TARGET,
      authority: WALLET,
      timestamp: 1_700_000_000n,
      nonce: NONCE,
    });
    expect(new TextDecoder().decode(message)).toBe(
      `zolana/ring-rpc-spend-coverage\n${TARGET_LINES}\nauthority: ${WALLET}\ntimestamp: 1700000000\nnonce: ${NONCE_BASE64}\ncursor: `,
    );
  });
});

describe("getWalletStatus", () => {
  const page = {
    historyThrough: 41,
    enrollment: "applied",
    balances: [{ asset: hashOf(0x13), amount: 500 }],
    notes: [
      noteWire("unspent"),
      noteWire("spent"),
      noteWire("unknown"),
      noteWire("exposedIfSpent", { nullifierPk: undefined }),
    ],
    cursor: null,
  };

  it("reads each status and sends the wallet under a reader's signature", async () => {
    const { rpc, bodies } = capture(page);
    const status = await rpc.getWalletStatus({ target: TARGET, signer: reader, wallet: WALLET });
    expect(status.historyThrough).toBe(41n);
    expect(status.notes.map((note) => note.status)).toEqual([
      "unspent",
      "spent",
      "unknown",
      "exposedIfSpent",
    ]);
    expect(status.notes[3]?.nullifierPk).toBeUndefined();
    expect(status.balances).toEqual([{ asset: new Uint8Array(32).fill(0x13), amount: 500n }]);
    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(bodies[0]?.["method"]).toBe("getWalletStatus");
    expect(params["wallet"]).toBe(WALLET);
    expect(params["ringProgramId"]).toBe(TARGET.ringProgramId);
  });

  it("keeps the refusal when a wallet snapshot expires", async () => {
    const rpc = new RingRpc("http://ring.example", {
      allowInsecureHttp: true,
      fetch: (async () =>
        new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            error: {
              code: -32172,
              message: "wallet snapshot expired",
            },
          }),
          { headers: { "content-type": "application/json" } },
        )) as typeof globalThis.fetch,
    });
    await expect(
      rpc.getWalletStatus({
        target: TARGET,
        signer: reader,
        wallet: WALLET,
        cursor: new Uint8Array(129).fill(2),
      }),
    ).rejects.toMatchObject({
      code: "RING_RPC_REFUSED",
      details: { refusal: "walletSnapshotExpired", rpcCode: -32172 },
    });
  });

  it("refuses a status it does not know, never reading it as unspent", async () => {
    const { rpc } = capture({ ...page, notes: [noteWire("resolved")] });
    await expect(
      rpc.getWalletStatus({ target: TARGET, signer: reader, wallet: WALLET }),
    ).rejects.toMatchObject({ code: "RING_RPC" });
  });
});

describe("getSpendCoverage", () => {
  it("accepts a continuation without totals", async () => {
    const { rpc, bodies } = capture({
      historyThrough: 11,
      unclassified: [],
      unreadable: [],
      integrityFaults: [],
    });
    const authority = await generateKeyPairSigner();
    const coverage = await rpc.getSpendCoverage({
      target: TARGET,
      authority,
      cursor: new Uint8Array([4, 5]),
    });
    expect(coverage).not.toHaveProperty("totals");
    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(params["cursor"]).toBe(Buffer.from([4, 5]).toString("base64"));
  });

  it("reads the operator's rows under the authority's signature", async () => {
    const frame = { slot: 9, txSignature: SIGNATURE, eventIndex: 0 };
    const { rpc, bodies } = capture({
      positionSlot: 12,
      historyThrough: 11,
      totals: { observed: 5, padding: 2, resolved: 1 },
      unclassified: [{ nullifier: hashOf(0x20), frame }],
      unreadable: [frame],
      integrityFaults: [],
      cursor: Buffer.from([1, 2, 3]).toString("base64"),
    });
    const authority = await generateKeyPairSigner();
    const coverage = await rpc.getSpendCoverage({ target: TARGET, authority });
    expect(coverage.unclassified[0]?.nullifier).toEqual(new Uint8Array(32).fill(0x20));
    expect(coverage.unreadable).toHaveLength(1);
    expect(coverage.positionSlot).toBe(12n);
    expect(coverage.totals).toEqual({
      observed: 5n,
      padding: 2n,
      resolved: 1n,
    });
    expect(coverage.cursor).toEqual(new Uint8Array([1, 2, 3]));
    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(bodies[0]?.["method"]).toBe("getSpendCoverage");
    expect(params["authority"]).toBe(authority.address);
    expect(params["ring"]).toBe(TARGET.ringProgramId);
    expect(params).not.toHaveProperty("cursor");
  });
});

function snapshotCursor(position: number): Uint8Array {
  const cursor = new Uint8Array(129).fill(2);
  cursor.fill(position, 97);
  return cursor;
}

function snapshotPage(cursor?: Uint8Array) {
  return {
    historyThrough: 41,
    enrollment: "applied",
    snapshotExpiresAt: 300,
    balances: [],
    notes: [],
    cursor: cursor === undefined ? null : Buffer.from(cursor).toString("base64"),
  };
}

function sequence(results: readonly unknown[]) {
  const bodies: Record<string, unknown>[] = [];
  const signals: (AbortSignal | null | undefined)[] = [];
  const rpc = new RingRpc("http://ring.example", {
    allowInsecureHttp: true,
    fetch: (async (_input: URL | string, init?: RequestInit) => {
      const result = results[bodies.length];
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      signals.push(init?.signal);
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch,
  });
  return { rpc, bodies, signals };
}

describe("wallet snapshots", () => {
  it("separates read and release signing domains", () => {
    const input = {
      target: TARGET,
      wallet: WALLET,
      timestamp: 1n,
      nonce: NONCE,
      cursor: snapshotCursor(1),
    };
    const release = new TextDecoder().decode(walletSnapshotReleaseAttestation(input));
    const read = new TextDecoder().decode(walletStatusAttestation(input));
    expect(release).toBe(
      read.replace("zolana/ring-rpc-wallet-status", "zolana/ring-rpc-wallet-snapshot-release"),
    );
    expect(walletSnapshotReleaseAttestation({ ...input, cursor: snapshotCursor(2) })).not.toEqual(
      walletSnapshotReleaseAttestation(input),
    );
  });

  it("releases after all pages are consumed", async () => {
    const { rpc, bodies } = sequence([snapshotPage(snapshotCursor(1)), snapshotPage(), true]);
    const pages = [];
    for await (const page of rpc.walletStatusPages({
      target: TARGET,
      wallet: WALLET,
      signer: reader,
    })) {
      pages.push(page);
    }
    expect(pages).toHaveLength(2);
    expect(pages[0]?.snapshotExpiresAt).toBe(300n);
    expect(bodies.map((body) => body["method"])).toEqual([
      "getWalletStatus",
      "getWalletStatus",
      "releaseWalletSnapshot",
    ]);
    const release = bodies[2]?.["params"] as Record<string, unknown>;
    expect(release["cursor"]).toBe(Buffer.from(snapshotCursor(1)).toString("base64"));
  });

  it("releases after a consumer stops with a separate cancellation context", async () => {
    const { rpc, bodies, signals } = sequence([snapshotPage(snapshotCursor(1)), true]);
    const abort = new AbortController();
    for await (const _page of rpc.walletStatusPages(
      { target: TARGET, wallet: WALLET, signer: reader },
      { signal: abort.signal },
    )) {
      abort.abort();
      break;
    }
    expect(bodies.map((body) => body["method"])).toEqual([
      "getWalletStatus",
      "releaseWalletSnapshot",
    ]);
    expect(signals[1]?.aborted ?? false).toBe(false);
  });

  it("refuses a changed capture and releases its original snapshot", async () => {
    const { rpc, bodies } = sequence([
      snapshotPage(snapshotCursor(1)),
      { ...snapshotPage(), historyThrough: 42 },
      true,
    ]);
    const pages = rpc.walletStatusPages({ target: TARGET, wallet: WALLET, signer: reader });
    await pages.next();
    await expect(pages.next()).rejects.toMatchObject({ code: "RING_RPC" });
    expect(bodies.at(-1)?.["method"]).toBe("releaseWalletSnapshot");
  });

  it("retains both failures if reading and releasing fail", async () => {
    const { rpc } = sequence([
      snapshotPage(snapshotCursor(1)),
      { ...snapshotPage(), historyThrough: 42 },
      false,
    ]);
    const pages = rpc.walletStatusPages({ target: TARGET, wallet: WALLET, signer: reader });
    await pages.next();
    await expect(pages.next()).rejects.toBeInstanceOf(AggregateError);
  });

  it("needs no release for a single page", async () => {
    const { snapshotExpiresAt: _, ...single } = snapshotPage();
    const { rpc, bodies } = sequence([single]);
    for await (const _page of rpc.walletStatusPages({
      target: TARGET,
      wallet: WALLET,
      signer: reader,
    })) {
    }
    expect(bodies.map((body) => body["method"])).toEqual(["getWalletStatus"]);
  });
});

describe("delegate snapshots", () => {
  it("binds the owner and cursor under a distinct release domain", () => {
    const input = {
      target: TARGET,
      delegate: WALLET,
      owner: addressOf(6),
      timestamp: 1n,
      nonce: NONCE,
      cursor: snapshotCursor(1),
    };
    expect(new TextDecoder().decode(delegateSnapshotReleaseAttestation(input))).toBe(
      new TextDecoder()
        .decode(delegateNotesAttestation(input))
        .replace("zolana/ring-rpc-delegate-notes", "zolana/ring-rpc-delegate-snapshot-release"),
    );
    expect(delegateSnapshotReleaseAttestation({ ...input, owner: addressOf(5) })).not.toEqual(
      delegateSnapshotReleaseAttestation(input),
    );
  });

  it("releases the delegate session when its iterator returns", async () => {
    const delegate = await generateKeyPairSigner();
    const { rpc, bodies } = sequence([
      { nullifierSecret: hashOf(12), status: snapshotPage(snapshotCursor(1)) },
      true,
    ]);
    const pages = rpc.delegateNotesPages({ target: TARGET, delegate, owner: WALLET });
    const first = await pages.next();
    expect(first.done).toBe(false);
    await pages.return();
    expect(bodies.map((body) => body["method"])).toEqual([
      "getDelegateNotes",
      "releaseDelegateSnapshot",
    ]);
    expect(bodies[1]?.["params"]).toEqual(expect.objectContaining({ owner: WALLET }));
  });
});

describe("delegate note keys", () => {
  it("opens each note under the key it commits, the zero key without a secret", () => {
    const registered = NullifierKey.fromSecret(new Uint8Array(31).fill(7) as Bytes31);
    const secret = new Uint8Array(32);
    secret.set(registered.secretBytes(), 1);
    const page = { nullifierSecret: secret as Bytes32 };
    const keyed = delegateNoteKey(page, { nullifierPk: registered.publicKey() });
    expect(keyed?.publicKey()).toEqual(registered.publicKey());
    expect(
      delegateNoteKey(page, { nullifierPk: ZERO_NULLIFIER_PK as Bytes32 })?.publicKey(),
    ).toEqual(ZERO_NULLIFIER_PK);
    // Any output key pays the owner, a key it never registered opens to no secret here.
    const foreign = NullifierKey.fromSecret(new Uint8Array(31).fill(8) as Bytes31).publicKey();
    expect(delegateNoteKey(page, { nullifierPk: foreign })).toBeUndefined();
    expect(delegateNoteKey({}, { nullifierPk: registered.publicKey() })).toBeUndefined();
    const padded = secret.slice() as Bytes32;
    padded[0] = 1;
    expect(
      delegateNoteKey({ nullifierSecret: padded }, { nullifierPk: registered.publicKey() }),
    ).toBeUndefined();
  });
});
