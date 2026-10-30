import { ed25519 } from "@noble/curves/ed25519.js";
import {
  address,
  generateKeyPairSigner,
  getAddressDecoder,
  getBase58Decoder,
  type Address,
  type MessagePartialSigner,
} from "@solana/kit";
import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import { solanaOwnerIdentity, addressBytes, sha256, ZERO_32 } from "@heliuslabs/zolana/internal";
import type { Bytes32, Bytes33, Bytes64 } from "@heliuslabs/zolana/interface";
import { ownerHash, X25519Keypair } from "@heliuslabs/zolana/keypair";
import { SOL_MINT, assetField } from "@heliuslabs/zolana/transaction";
import { ringIdField } from "../../../src/crypto/derivation/ring-stream.js";
import { knownUtxoHash, type KnownUtxo } from "../../../src/operations/audit/audit.js";
import { passkeyReader } from "../../../src/crypto/keys/passkey.js";
import { memberOfTag } from "../../../src/protocol/membership/policy.js";
import {
  P256ReaderKey,
  checkedReaderKey,
  parseReaderKey,
  readerKeyBytes,
  readerKeyEquals,
  readerKeyFromBytes,
  readerKeyToString,
  type ReaderKey,
} from "../../../src/operations/management/reader-access.js";
import {
  RING_AUDITED_UTXOS_LIMIT,
  RING_PAYLOAD_ERROR_KINDS,
  RingAuditedUtxosRequest,
  RingAuditorKeyRequest,
  RingReadRequest,
  RingRpc,
  auditedUtxosAttestation,
  auditorKeyRequestAttestation,
  auditorKeyStatement,
  messageSignerReader,
  ringReadAttestation,
  type RingReadTarget,
  type SignedAuditorKeyRequest,
  type SignedRingRead,
} from "../../../src/rpc/ring-rpc.js";

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function filled(byte: number, length: number): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

function addressOf(byte: number) {
  return getAddressDecoder().decode(filled(byte, 32));
}

function signatureOf(byte: number) {
  return getBase58Decoder().decode(filled(byte, 64));
}

function capturingFetch(result: unknown): {
  fetch: typeof globalThis.fetch;
  bodies: Record<string, unknown>[];
} {
  const bodies: Record<string, unknown>[] = [];
  const fetch = (async (_input: URL | string, init?: RequestInit) => {
    bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), {
      headers: { "content-type": "application/json" },
    });
  }) as typeof globalThis.fetch;
  return { fetch, bodies };
}

function rpcWith(result: unknown): RingRpc {
  return new RingRpc("http://ring.example", {
    fetch: capturingFetch(result).fetch,
    allowInsecureHttp: true,
  });
}

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const PAYER = address("k7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn");
/** Rust `rpc::tests::target`, the ring `[7; 32]` behind the service `[2; 32]` on the cluster `[1; 32]`. */
const VECTOR_TARGET: RingReadTarget = {
  cluster: filled(1, 32) as Bytes32,
  service: addressOf(2),
  ringProgramId: addressOf(7),
};
const RING_TARGET: RingReadTarget = { ...VECTOR_TARGET, ringProgramId: RING };
const JSON_HEADERS = { headers: { "content-type": "application/json" } };
// The P-256 key of the scalar [46; 32], its record printed by the Rust builders.
const P256_HEX = "02039b852db622408abe58a18c0f056631a6ca4b2cfeec198aae25017cad09d4e8";
const X25519_BASE64 = Buffer.from(
  X25519Keypair.fromBytes(new Uint8Array(32).fill(7)).publicKey().toBytes(),
).toString("base64");

/** One decrypted transaction as the Rust ring rpc serializes it, every field overridable. */
function decryptedItem(overrides: Readonly<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    slot: 8,
    txSignature: signatureOf(1),
    eventIndex: 0,
    txViewingPk: X25519_BASE64,
    outputs: [],
    payloadErrors: [],
    nullifiers: [],
    signers: [],
    withdrawals: [],
    ...overrides,
  };
}

function decryptedPage(items: readonly unknown[]) {
  return {
    context: { blockTime: 1_700_000_000, slot: 9 },
    value: { items, skipped: [], cursor: null },
  };
}

const anyReader = async () => messageSignerReader(await generateKeyPairSigner());

async function readItem(item: unknown) {
  const page = await rpcWith(decryptedPage([item])).getDecryptedTransactions({
    target: RING_TARGET,
    signer: await anyReader(),
  });
  return page.items[0]!;
}

/** The Rust `rpc/tests.rs` fixtures, the TypeScript decoder reads them byte for byte. */
function rustPage(name: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(new URL(`../../../../client/src/rpc/${name}`, import.meta.url), "utf8"),
  ) as Record<string, unknown>;
}

function rustItem(name: string): Record<string, unknown> {
  const value = rustPage(name)["value"] as { items: Record<string, unknown>[] };
  return structuredClone(value.items[0]!);
}

describe("ring status", () => {
  const configKey = X25519Keypair.fromBytes(new Uint8Array(32).fill(9)).publicKey();
  const status = (overrides: Readonly<Record<string, unknown>> = {}) => ({
    ringProgramId: addressOf(7),
    state: "served",
    configAuditorPubkey: Buffer.from(configKey.toBytes()).toString("base64"),
    servicePubkey: addressOf(22),
    activation: { activated: true, paused: false },
    ...overrides,
  });

  it("reads the config key and the activation", async () => {
    const read = await rpcWith(status()).ringStatus(addressOf(7));
    expect(read.state).toBe("served");
    expect(read.configAuditorPublicKey?.equals(configKey)).toBe(true);
    expect(read.servicePublicKey).toBe(addressOf(22));
    expect(read.activation).toEqual({ activated: true, paused: false });
  });

  it("leaves the config key and the activation absent before the ring creates them", async () => {
    const read = await rpcWith({
      ringProgramId: addressOf(7),
      state: "uninitialized",
      servicePubkey: addressOf(22),
    }).ringStatus(addressOf(7));
    expect(read.state).toBe("uninitialized");
    expect(read.configAuditorPublicKey).toBeUndefined();
    expect(read.activation).toBeUndefined();
  });

  it.each<readonly [string, Readonly<Record<string, unknown>>, string]>([
    ["another ring", { ringProgramId: addressOf(8) }, "result.ringProgramId"],
    ["a malformed service address", { servicePubkey: "not-base58!" }, "result.servicePubkey"],
    [
      "a non-boolean pause flag",
      { activation: { activated: true, paused: 1 } },
      "result.activation.paused",
    ],
  ])("refuses %s", async (_name, overrides, path) => {
    await expect(rpcWith(status(overrides)).ringStatus(addressOf(7))).rejects.toMatchObject({
      code: "RING_RPC",
      details: { path },
    });
  });
});

describe("ring rpc gateway", () => {
  const recording = () => {
    const calls: { url: URL; method: unknown }[] = [];
    const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
      const body: unknown = JSON.parse(String(init?.body));
      if (
        typeof body !== "object" ||
        body === null ||
        !("method" in body) ||
        typeof body.method !== "string"
      ) {
        throw new Error("expected a JSON-RPC method");
      }
      calls.push({ url: new URL(String(input)), method: body["method"] });
      const result =
        body["method"] === "health"
          ? { mode: "derived", servicePubkey: addressOf(22) }
          : { ringProgramId: addressOf(7), state: "uninitialized", servicePubkey: addressOf(22) };
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), JSON_HEADERS);
    });
    return { calls, fetch };
  };

  it("posts health and status on method paths with the key and endpoint query", async () => {
    const { calls, fetch } = recording();
    const rpc = new RingRpc("https://gateway.example/v1/zolana/ring/?tenant=alpha", {
      fetch,
      apiKey: "k+1",
    });

    await rpc.health();
    await rpc.ringStatus(addressOf(7));

    expect(calls.map(({ url }) => url.pathname)).toEqual([
      "/v1/zolana/ring/health",
      "/v1/zolana/ring/ringStatus",
    ]);
    expect(calls.map(({ method }) => method)).toEqual(["health", "ringStatus"]);
    for (const { url } of calls) {
      expect(url.searchParams.getAll("api-key")).toEqual(["k+1"]);
      expect(url.searchParams.get("tenant")).toBe("alpha");
    }
    expect(rpc.url).toBe("https://gateway.example/v1/zolana/ring/?tenant=alpha");
  });

  it("sends a key carried by the URL and keeps it off the reported URL", async () => {
    const { calls, fetch } = recording();
    const rpc = new RingRpc("https://gateway.example/v1/zolana/ring?api-key=k", { fetch });

    await rpc.health();

    expect(calls[0]?.url.searchParams.getAll("api-key")).toEqual(["k"]);
    expect(rpc.url).toBe("https://gateway.example/v1/zolana/ring");
  });

  it("leaves a caller's URL object carrying the key untouched", async () => {
    const { calls, fetch } = recording();
    const endpoint = new URL("https://gateway.example/v1/zolana/ring?api-key=k");
    const rpc = new RingRpc(endpoint, { fetch });

    await rpc.health();

    expect(endpoint.href).toBe("https://gateway.example/v1/zolana/ring?api-key=k");
    expect(rpc.url).toBe("https://gateway.example/v1/zolana/ring");
    expect(calls[0]?.url.href).toBe("https://gateway.example/v1/zolana/ring/health?api-key=k");
  });

  it("adds the key without re-encoding the endpoint's other parameters", async () => {
    const { calls, fetch } = recording();
    const endpoint = "https://gateway.example/v1/zolana/ring?flag&x=a%20b&y=~";
    const rpc = new RingRpc(endpoint, { fetch, apiKey: "k+1" });

    await rpc.health();

    expect(rpc.url).toBe(endpoint);
    expect(calls[0]?.url.href).toBe(
      "https://gateway.example/v1/zolana/ring/health?flag&x=a%20b&y=~&api-key=k%2B1",
    );
  });

  it("refuses an API key that is not a string", () => {
    expect(() => Reflect.construct(RingRpc, ["https://gateway.example", { apiKey: 1 }])).toThrow(
      expect.objectContaining({ code: "RING_RPC_CONFIG", details: { field: "apiKey" } }),
    );
  });

  it("removes an encoded URL key without rewriting the other query parameters", async () => {
    const { calls, fetch } = recording();
    const endpoint = new URL("https://gateway.example/ring?flag&api%2Dkey=k%2B1&x=a%20b&y=~");
    const original = endpoint.href;
    const rpc = new RingRpc(endpoint, { fetch });

    await rpc.health();

    expect(endpoint.href).toBe(original);
    expect(rpc.url).toBe("https://gateway.example/ring?flag&x=a%20b&y=~");
    expect(calls[0]?.url.href).toBe(
      "https://gateway.example/ring/health?flag&x=a%20b&y=~&api-key=k%2B1",
    );
  });

  it.each([
    ["https://gateway.example?api-key=leak1&api-key=leak2", undefined],
    ["https://gateway.example?api-key=leak1", "leak2"],
    ["https://gateway.example?api-key=", undefined],
    ["https://gateway.example", ""],
    ["https://gateway.example", "leak\nbreak"],
    ["https://gateway.example", "leak".repeat(1025)],
  ])(
    "refuses an API key that is duplicated, doubly sourced or malformed (%s, %j)",
    (url, apiKey) => {
      const error = (() => {
        try {
          new RingRpc(url, apiKey === undefined ? {} : { apiKey });
        } catch (cause) {
          return cause;
        }
        return undefined;
      })();

      expect(error).toMatchObject({ code: "RING_RPC_CONFIG", details: { field: "apiKey" } });
      expect(JSON.stringify(error)).not.toContain("leak");
    },
  );

  it("keeps the key out of a transport failure", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(() =>
      Promise.resolve(new Response("upstream down", { status: 502 })),
    );

    const error = await new RingRpc("https://gateway.example", { fetch, apiKey: "secret-key" })
      .health()
      .then(
        () => undefined,
        (cause: unknown) => cause,
      );

    expect(error).toMatchObject({ code: "RING_RPC_TRANSPORT" });
    expect(JSON.stringify(error)).not.toContain("secret-key");
  });

  it("names a rate limit and an unknown api key apart from a transport failure", async () => {
    const refusal = async (status: number) =>
      new RingRpc("https://gateway.example", {
        fetch: () => Promise.resolve(new Response("{}", { status })),
      })
        .health()
        .then(
          () => undefined,
          (cause: unknown) => cause,
        );

    expect(await refusal(429)).toMatchObject({ code: "RING_RPC_RATE_LIMITED" });
    expect(await refusal(401)).toMatchObject({
      code: "RING_RPC_CONFIG",
      details: { field: "apiKey" },
    });
  });
});

describe("ring deposits", () => {
  const queue = (results: readonly unknown[]) => {
    const bodies: Record<string, unknown>[] = [];
    let call = 0;
    const fetch = (async (_input: URL | string, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: 1, result: results[call++] }),
        JSON_HEADERS,
      );
    }) as typeof globalThis.fetch;
    return { bodies, fetch };
  };
  const deposit = (byte: number, slot: number) => ({
    signature: signatureOf(byte),
    slot,
    depositor: addressOf(byte),
    asset: "11111111111111111111111111111111",
    amount: byte,
  });

  it("pages the ring history until the cursor is absent", async () => {
    const { bodies, fetch } = queue([
      { deposits: [deposit(1, 9)], cursor: "AQID", oldestSlot: 9 },
      { deposits: [deposit(2, 4)], oldestSlot: 4 },
    ]);
    const rpc = new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    });

    const first = await rpc.ringDeposits({
      ringProgramId: addressOf(7),
      limit: 20,
    });
    expect(first.deposits).toHaveLength(1);
    expect(first.deposits[0]).toEqual({
      signature: signatureOf(1),
      slot: 9n,
      depositor: addressOf(1),
      asset: "11111111111111111111111111111111",
      amount: 1n,
    });
    expect(first.cursor).toEqual(Uint8Array.of(1, 2, 3));
    expect(first.oldestSlot).toBe(9n);

    const second = await rpc.ringDeposits({
      ringProgramId: addressOf(7),
      cursor: first.cursor as Uint8Array,
    });
    expect(second.deposits[0]?.slot).toBe(4n);
    expect(second.cursor).toBeUndefined();
    expect(second.oldestSlot).toBe(4n);

    expect(bodies[0]?.["params"]).toEqual({
      ringProgramId: addressOf(7),
      limit: 20,
    });
    expect(bodies[1]?.["params"]).toEqual({
      ringProgramId: addressOf(7),
      cursor: "AQID",
    });
  });

  it("keeps a cursor over a page whose signatures held no deposit", async () => {
    const { fetch } = queue([{ deposits: [], cursor: "BAUG", oldestSlot: 12 }]);

    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).ringDeposits({
      ringProgramId: addressOf(7),
    });

    expect(page.deposits).toEqual([]);
    expect(page.cursor).toEqual(Uint8Array.of(4, 5, 6));
    expect(page.oldestSlot).toBe(12n);
  });

  it("rejects a malformed deposit signature and depositor", async () => {
    const base = { slot: 1, asset: SOL_MINT, amount: 1 };
    await expect(
      rpcWith({
        deposits: [{ ...base, depositor: addressOf(1), signature: "1".repeat(87) }],
      }).ringDeposits({ ringProgramId: addressOf(7) }),
    ).rejects.toMatchObject({ code: "RING_RPC", details: { path: "deposits.signature" } });
    await expect(
      rpcWith({
        deposits: [{ ...base, depositor: "tooShort", signature: signatureOf(1) }],
      }).ringDeposits({ ringProgramId: addressOf(7) }),
    ).rejects.toMatchObject({ code: "RING_RPC", details: { path: "deposits.depositor" } });
  });

  it("leaves the oldest slot absent when the page examined nothing", async () => {
    const { fetch } = queue([{ deposits: [] }]);

    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).ringDeposits({
      ringProgramId: addressOf(7),
    });

    expect(page.cursor).toBeUndefined();
    expect(page.oldestSlot).toBeUndefined();
  });
});

describe("signed ring request validation", () => {
  const READER = readerKeyBytes(
    checkedReaderKey(getAddressDecoder().decode(ed25519.getPublicKey(filled(5, 32)))),
  );
  const WEBAUTHN = {
    signature: filled(1, 70),
    authenticatorData: filled(2, 37),
    clientDataJSON: filled(3, 12),
  };

  function signedRead(overrides: Partial<SignedRingRead> = {}): SignedRingRead {
    return {
      method: "getDecryptedTransactions",
      ringProgramId: RING,
      reader: READER,
      timestamp: 1n,
      nonce: filled(7, 32) as Bytes32,
      signature: filled(1, 64),
      ...overrides,
    };
  }

  function signedAuditorKey(
    overrides: Partial<SignedAuditorKeyRequest> = {},
  ): SignedAuditorKeyRequest {
    return {
      ringProgramId: RING,
      authority: PAYER,
      genesisHash: filled(2, 32) as Bytes32,
      timestamp: 1n,
      nonce: filled(3, 32) as Bytes32,
      signature: filled(4, 64) as Bytes64,
      ...overrides,
    };
  }

  function offlineRpc(): Readonly<{
    rpc: RingRpc;
    fetch: ReturnType<typeof vi.fn>;
  }> {
    const fetch = vi.fn<typeof globalThis.fetch>();
    return {
      rpc: new RingRpc("http://ring.example", {
        fetch,
        allowInsecureHttp: true,
      }),
      fetch,
    };
  }

  const readCases: readonly [string, Readonly<Record<string, unknown>>, string][] = [
    ["a malformed ring program id", { ringProgramId: "not-base58!" }, "RING_RPC"],
    ["another method's signature", { method: "getAuditedMerges" }, "RING_RPC"],
    ["no method", { method: undefined }, "RING_RPC"],
    ["a short reader key", { reader: filled(1, 33) }, "RING_READER_KEY"],
    ["an invalid P256 reader key", { reader: new Uint8Array(34) }, "RING_READER_KEY"],
    ["a short nonce", { nonce: filled(7, 31) }, "RING_RPC"],
    ["an empty cursor", { cursor: new Uint8Array(0) }, "RING_READ_CURSOR"],
    ["an oversized cursor", { cursor: new Uint8Array(257) }, "RING_READ_CURSOR"],
    ["a zero limit", { limit: 0n }, "RING_READ_LIMIT"],
    ["a limit over the page cap", { limit: 101n }, "RING_READ_LIMIT"],
    ["a negative timestamp", { timestamp: -1n }, "RING_RPC"],
    ["a timestamp past the safe range", { timestamp: 1n << 53n }, "RING_RPC"],
    ["a short ed25519 signature", { signature: filled(1, 63) }, "RING_RPC"],
    ["a null signature", { signature: null }, "RING_RPC"],
    ["an extra field", { extra: true }, "RING_RPC"],
    [
      "an empty webauthn signature",
      { signature: { ...WEBAUTHN, signature: new Uint8Array(0) } },
      "RING_RPC",
    ],
    [
      "short webauthn authenticator data",
      { signature: { ...WEBAUTHN, authenticatorData: filled(2, 36) } },
      "RING_RPC",
    ],
    [
      "empty webauthn client data",
      { signature: { ...WEBAUTHN, clientDataJSON: new Uint8Array(0) } },
      "RING_RPC",
    ],
  ];

  it.each(readCases)(
    "rejects a read with %s before any network call",
    async (_name, overrides, code) => {
      const { rpc, fetch } = offlineRpc();
      await expect(
        Reflect.apply(rpc.readSigned, rpc, [{ ...signedRead(), ...overrides }]),
      ).rejects.toMatchObject({ code });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  const auditorCases: readonly [string, Readonly<Record<string, unknown>>, string][] = [
    ["a malformed ring program id", { ringProgramId: "nope" }, "RING_RPC"],
    ["a malformed authority", { authority: "nope" }, "RING_RPC"],
    ["a short genesis hash", { genesisHash: filled(2, 31) }, "RING_RPC"],
    ["a short nonce", { nonce: filled(3, 31) }, "RING_RPC"],
    ["a short signature", { signature: filled(4, 63) }, "RING_RPC"],
    ["a timestamp past the safe range", { timestamp: 1n << 53n }, "RING_RPC"],
    ["an extra field", { extra: true }, "RING_RPC"],
  ];

  it.each(auditorCases)(
    "rejects an auditor key request with %s before any network call",
    async (_name, overrides, code) => {
      const { rpc, fetch } = offlineRpc();
      await expect(
        Reflect.apply(rpc.createAuditorKeySigned, rpc, [
          { ...signedAuditorKey(), ...overrides },
          PAYER,
        ]),
      ).rejects.toMatchObject({ code });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it("refuses a merge read signed for the transaction page before any network call", async () => {
    const { rpc, fetch } = offlineRpc();
    await expect(rpc.readSignedMerges(signedRead())).rejects.toMatchObject({
      code: "RING_RPC",
      details: { field: "method" },
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects non-object signed requests through Ring errors", async () => {
    const { rpc, fetch } = offlineRpc();
    await expect(Reflect.apply(rpc.readSigned, rpc, [null])).rejects.toMatchObject({
      code: "RING_RPC",
    });
    await expect(
      Reflect.apply(rpc.createAuditorKeySigned, rpc, [null, PAYER]),
    ).rejects.toMatchObject({
      code: "RING_RPC",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("requires signed fields to be own properties", async () => {
    const { rpc, fetch } = offlineRpc();
    await expect(
      Reflect.apply(rpc.readSigned, rpc, [Object.create(signedRead())]),
    ).rejects.toMatchObject({ code: "RING_RPC" });
    await expect(
      Reflect.apply(rpc.createAuditorKeySigned, rpc, [Object.create(signedAuditorKey()), PAYER]),
    ).rejects.toMatchObject({ code: "RING_RPC" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("accepts a well-formed signed read and a webauthn signature", async () => {
    const { fetch } = capturingFetch({
      context: { slot: 1, blockTime: 1 },
      value: { items: [], skipped: [], cursor: null },
    });
    const rpc = new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    });
    await rpc.readSigned(signedRead());
    await rpc.readSigned(signedRead({ signature: WEBAUTHN }));
  });

  it("refuses a missing audit cursor instead of treating the page as complete", async () => {
    const { fetch } = capturingFetch({
      context: { slot: 1, blockTime: 1 },
      value: { items: [], skipped: [] },
    });
    await expect(
      new RingRpc("http://ring.example", { fetch, allowInsecureHttp: true }).readSigned(
        signedRead(),
      ),
    ).rejects.toMatchObject({ code: "RING_RPC" });
  });
});

describe("ring audited merges", () => {
  it("reads signed audited merge pages and rejects malformed field values", async () => {
    await initializePoseidon();
    const ownerMember = getBase58Decoder().decode(memberOfTag(addressBytes(RING)));
    const value = {
      opened: [
        {
          txSignature: signatureOf(1),
          eventIndex: 2,
          outputCommitment: addressOf(3),
          ownerMember,
          ownerPubkey: RING,
          mint: SOL_MINT,
          amount: 7,
          blinding: addressOf(5),
          ringDataHash: addressOf(6),
          inputNullifiers: [addressOf(7), addressOf(8)],
          nullifier: addressOf(9),
        },
      ],
      unresolved: [
        { txSignature: signatureOf(10), eventIndex: 3, outputCommitment: addressOf(11) },
      ],
      cursor: "AQIE",
    };
    const merges = (body: unknown) => rpcWith({ context: { slot: 9, blockTime: 10 }, value: body });
    const reader = messageSignerReader(await generateKeyPairSigner());
    const page = await merges(value).getAuditedMerges({
      target: RING_TARGET,
      signer: reader,
      cursor: Uint8Array.of(1, 2, 3),
      limit: 5n,
      timestamp: 1_700_000_000n,
    });
    expect(page.cursor).toEqual(Uint8Array.of(1, 2, 4));
    expect(page.opened[0]).toMatchObject({
      signature: signatureOf(1),
      eventIndex: 2,
      amount: 7n,
      mint: SOL_MINT,
      ownerPublicKey: RING,
      inputNullifiers: [filled(7, 32), filled(8, 32)],
      keys: { kind: "escrowed", nullifier: filled(9, 32) },
    });
    expect(page.unresolved[0]).toMatchObject({ signature: signatureOf(10), eventIndex: 3 });
    await expect(
      merges({ ...value, cursor: "AQID" }).getAuditedMerges({
        target: RING_TARGET,
        signer: reader,
        cursor: Uint8Array.of(1, 2, 3),
      }),
    ).rejects.toMatchObject({ code: "RING_RPC" });
    await expect(
      merges(value).getAuditedMerges({ target: RING_TARGET, signer: reader, limit: 1n }),
    ).rejects.toMatchObject({ code: "RING_RPC" });
    // An anonymous merge discloses one spent commitment per circuit slot and no nullifier.
    const { nullifier: _escrowed, ...disclosed } = value.opened[0]!;
    const commitments = Array.from({ length: 8 }, (_, index) =>
      addressOf(index < 2 ? 20 + index : 0),
    );
    const anonymous = await merges({
      ...value,
      opened: [{ ...disclosed, inputCommitments: commitments }],
    }).getAuditedMerges({ target: RING_TARGET, signer: reader });
    const keys = anonymous.opened[0]?.keys;
    expect(keys?.kind).toBe("disclosed");
    expect(keys?.kind === "disclosed" && keys.inputCommitments).toHaveLength(8);
    // The program accepts a one-input merge.
    const single = await merges({
      ...value,
      opened: [{ ...value.opened[0]!, inputNullifiers: [addressOf(7)] }],
    }).getAuditedMerges({ target: RING_TARGET, signer: reader });
    expect(single.opened[0]?.inputNullifiers).toEqual([filled(7, 32)]);
    for (const bad of [
      { ...value, opened: [disclosed] },
      { ...value, opened: [{ ...value.opened[0]!, inputCommitments: commitments }] },
      { ...value, opened: [{ ...disclosed, inputCommitments: commitments.slice(0, 2) }] },
      { ...value, opened: [{ ...value.opened[0]!, inputNullifiers: [] }] },
      { ...value, opened: [{ ...value.opened[0]!, eventIndex: 65536 }] },
      { ...value, opened: [{ ...value.opened[0]!, ownerMember: addressOf(255) }] },
      { ...value, opened: [{ ...value.opened[0]!, ownerPubkey: addressOf(12) }] },
    ])
      await expect(
        merges(bad).getAuditedMerges({ target: RING_TARGET, signer: reader }),
      ).rejects.toMatchObject({ code: "RING_RPC" });
  });
});

/** The slot `index` of a wire item, a test edits it in place. */
function outputAt(item: Record<string, unknown>, index: number): Record<string, unknown> {
  return (item["outputs"] as Record<string, unknown>[])[index]!;
}
describe("ring reader keys", () => {
  const P256_UNCOMPRESSED =
    "04039b852db622408abe58a18c0f056631a6ca4b2cfeec198aae25017cad09d4e8e208b616e0dc5775a5d840775d38dafd4676da34100215e8be857bed2ba4ac30";
  // Rust `reader()`, the ed25519 key of the seed [23; 32].
  const ED25519 = address("4MfyR4G3NWfVRDWo6iNAHDBZqWMgwZX6FNtMqEW3a9JT");
  const KEYS = [
    {
      key: ED25519 as ReaderKey,
      bytes: `01${Buffer.from(ed25519.getPublicKey(filled(23, 32))).toString("hex")}00`,
    },
    {
      key: P256ReaderKey.fromBytes(hex(P256_HEX) as Bytes33) as ReaderKey,
      bytes: `00${P256_HEX}`,
    },
  ];

  it("encodes both key kinds like Rust `ReaderKey`", () => {
    for (const { key, bytes } of KEYS) {
      expect(Buffer.from(readerKeyBytes(key)).toString("hex")).toBe(bytes);
      expect(readerKeyEquals(parseReaderKey(readerKeyToString(key)), key)).toBe(true);
      expect(readerKeyEquals(readerKeyFromBytes(hex(bytes)), key)).toBe(true);
    }
    expect(P256ReaderKey.fromUncompressed(hex(P256_UNCOMPRESSED)).toBytes()).toEqual(hex(P256_HEX));
  });

  it("refuses keys that cannot sign a read like Rust `ReaderKey`", () => {
    const weak = new Uint8Array(32);
    weak[0] = 1;
    expect(() => checkedReaderKey(getAddressDecoder().decode(weak))).toThrow("RING_READER_KEY");
    weak[31] = 0x80;
    expect(() => checkedReaderKey(getAddressDecoder().decode(weak))).toThrow("RING_READER_KEY");
    const noncanonical = filled(0xff, 32);
    noncanonical[0] = 0xee;
    noncanonical[31] = 0x7f;
    expect(() => checkedReaderKey(getAddressDecoder().decode(noncanonical))).toThrow(
      "RING_READER_KEY",
    );
    const mixedTorsion = ed25519.Point.BASE.add(
      ed25519.Point.fromBytes(Uint8Array.of(...new Uint8Array(31), 0x80)),
    ).toBytes();
    expect(() => checkedReaderKey(getAddressDecoder().decode(mixedTorsion))).toThrow(
      "RING_READER_KEY",
    );
    const scheme = hex(`01${"17".repeat(32)}00`);
    scheme[0] = 2;
    expect(() => readerKeyFromBytes(scheme)).toThrow("RING_READER_KEY");
    expect(() => parseReaderKey("not-a-key")).toThrow("RING_READER_KEY");
    expect(() => parseReaderKey("04".repeat(33))).toThrow("RING_READER_KEY");
  });
});

describe("ring passkey", () => {
  it("signs through WebAuthn with the attestation hash as challenge", async () => {
    const passkey = {
      credentialId: filled(9, 16),
      publicKey: P256ReaderKey.fromBytes(
        hex("02039b852db622408abe58a18c0f056631a6ca4b2cfeec198aae25017cad09d4e8") as Bytes33,
      ),
    };
    let seen: PublicKeyCredentialRequestOptions | undefined;
    const navigatorStub = {
      credentials: {
        get: (options: CredentialRequestOptions) => {
          seen = options.publicKey;
          return Promise.resolve({
            response: {
              signature: filled(1, 70).buffer,
              authenticatorData: filled(2, 37).buffer,
              clientDataJSON: filled(3, 80).buffer,
            },
          });
        },
      },
    };
    vi.stubGlobal("navigator", navigatorStub);
    try {
      const message = filled(7, 40);
      const reader = passkeyReader(passkey);
      expect(reader.reader).toEqual(readerKeyBytes(passkey.publicKey));
      expect(reader.reader).toHaveLength(34);
      const signed = await reader.sign(message);
      expect(new Uint8Array(seen?.challenge as ArrayBuffer)).toEqual(sha256(message));
      expect(seen?.userVerification).toBe("required");
      expect(new Uint8Array(seen?.allowCredentials?.[0]?.id as ArrayBuffer)).toEqual(
        passkey.credentialId,
      );
      expect(signed).toEqual({
        signature: filled(1, 70),
        authenticatorData: filled(2, 37),
        clientDataJSON: filled(3, 80),
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("ring read attestation", () => {
  it("matches the Rust `read_attestation_is_stable` vector", () => {
    const message = ringReadAttestation({
      method: "getDecryptedTransactions",
      target: VECTOR_TARGET,
      timestamp: 1_700_000_000n,
      nonce: filled(4, 32) as Bytes32,
      cursor: Uint8Array.of(1, 2, 3),
      limit: 5n,
    });
    expect(new TextDecoder().decode(message)).toBe(
      "zolana/ring-rpc-read/v2\nmethod: getDecryptedTransactions\ncluster: 4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\nservice: 8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nlimit: 5\ncursor: AQID",
    );
  });

  it("matches the Rust `auditor_key_request_attestation_is_stable` vector", () => {
    const message = auditorKeyRequestAttestation({
      genesisHash: filled(9, 32) as Bytes32,
      ringProgramId: addressOf(5),
      timestamp: 1_700_000_000n,
      nonce: filled(7, 32) as Bytes32,
    });
    expect(new TextDecoder().decode(message)).toBe(
      "zolana/ring-rpc-auditor-key-request/v1\ngenesis: cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN\nring: LbUiWL3xVV8hTFYBVdbTNrpDo41NKS6o3LHHuDzjfcY\ntimestamp: 1700000000\nnonce: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
    );
  });

  it("omits limit and cursor as 0 and empty", () => {
    const message = ringReadAttestation({
      method: "getAuditedMerges",
      target: VECTOR_TARGET,
      timestamp: 1n,
      nonce: filled(4, 32) as Bytes32,
    });
    expect(new TextDecoder().decode(message)).toBe(
      "zolana/ring-rpc-read/v2\nmethod: getAuditedMerges\ncluster: 4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\nservice: 8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nlimit: 0\ncursor: ",
    );
  });

  it("signs the one method it reads and draws a fresh nonce per signature", async () => {
    const signer = await generateKeyPairSigner();
    const reader = messageSignerReader(signer);
    const request = RingReadRequest.decryptedTransactions(VECTOR_TARGET).at(1_700_000_000n);
    const first = await request.sign(reader);
    const attested = (method: "getDecryptedTransactions" | "getAuditedMerges") =>
      ringReadAttestation({
        method,
        target: VECTOR_TARGET,
        timestamp: 1_700_000_000n,
        nonce: first.nonce,
      });
    const verifies = (message: Uint8Array) =>
      ed25519.verify(first.signature as Uint8Array, message, addressBytes(signer.address));
    expect(first.method).toBe("getDecryptedTransactions");
    expect(verifies(attested("getDecryptedTransactions"))).toBe(true);
    expect(verifies(attested("getAuditedMerges"))).toBe(false);
    for (const elsewhere of [
      { ...VECTOR_TARGET, cluster: filled(9, 32) as Bytes32 },
      { ...VECTOR_TARGET, service: addressOf(9) },
    ])
      expect(
        verifies(
          ringReadAttestation({
            method: "getDecryptedTransactions",
            target: elsewhere,
            timestamp: 1_700_000_000n,
            nonce: first.nonce,
          }),
        ),
      ).toBe(false);
    expect((await RingReadRequest.auditedMerges(VECTOR_TARGET).sign(reader)).method).toBe(
      "getAuditedMerges",
    );
    expect((await request.sign(reader)).nonce).not.toEqual(first.nonce);
    const utxos = RingAuditedUtxosRequest.read(VECTOR_TARGET, [filled(1, 32) as Bytes32]);
    expect((await utxos.sign(reader)).nonce).not.toEqual((await utxos.sign(reader)).nonce);
    const auditorKey = RingAuditorKeyRequest.forRing(addressOf(7), filled(2, 32) as Bytes32);
    expect((await auditorKey.sign(signer)).nonce).not.toEqual(
      (await auditorKey.sign(signer)).nonce,
    );
  });

  it("bounds the cursor and the limit like Rust `ReadRequest`", () => {
    const request = RingReadRequest.decryptedTransactions(VECTOR_TARGET);
    expect(() => request.withCursor(new Uint8Array())).toThrow("RING_READ_CURSOR");
    expect(() => request.withCursor(new Uint8Array(257))).toThrow("RING_READ_CURSOR");
    expect(() => request.withLimit(0n)).toThrow("RING_READ_LIMIT");
    expect(() => request.withLimit(101n)).toThrow("RING_READ_LIMIT");
    expect(request.withCursor(new Uint8Array(256)).withLimit(100n)).toBe(request);
  });
});

describe("audited UTXO read", () => {
  const hashes = [filled(1, 32), filled(2, 32)] as Bytes32[];

  it("matches the Rust `audited_utxos_attestation_is_stable` vector", () => {
    const message = auditedUtxosAttestation({
      target: VECTOR_TARGET,
      timestamp: 1_700_000_000n,
      nonce: filled(4, 32) as Bytes32,
      utxoHashes: hashes,
    });
    expect(new TextDecoder().decode(message)).toBe(
      "zolana/ring-rpc-audited-utxos/v1\ncluster: 4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\nservice: 8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nutxos: +Biv03ptw7yS+0RzEBEncAbbTvpukCPNdGjAIzXSKk0=",
    );
  });

  it("names one to the limit of hashes like Rust `GetAuditedUtxosRequest::read`", () => {
    for (const count of [0, RING_AUDITED_UTXOS_LIMIT + 1])
      expect(() =>
        RingAuditedUtxosRequest.read(
          VECTOR_TARGET,
          Array.from({ length: count }, () => filled(1, 32) as Bytes32),
        ),
      ).toThrow("RING_READ_LIMIT");
    expect(() =>
      RingAuditedUtxosRequest.read(VECTOR_TARGET, [filled(1, 32 - 1) as Bytes32]),
    ).toThrow("RING_READ_LIMIT");
  });

  const keyed: KnownUtxo = {
    ownerKey: filled(3, 32) as Bytes32,
    owner: { kind: "keyed", nullifierPk: filled(4, 32) as Bytes32 },
    asset: filled(5, 32) as Bytes32,
    amount: 9n,
    blinding: filled(6, 32) as Bytes32,
    dataHash: ZERO_32,
    ringDataHash: ZERO_32,
    treeId: 4,
  };
  const deposited: KnownUtxo = {
    ...keyed,
    owner: { kind: "deposited", ownerHash: filled(8, 32) as Bytes32 },
    amount: 7n,
  };

  function wireUtxo(utxo: KnownUtxo): Record<string, unknown> {
    const owner =
      utxo.owner.kind === "keyed"
        ? { nullifierPk: getAddressDecoder().decode(utxo.owner.nullifierPk) }
        : { ownerHash: getAddressDecoder().decode(utxo.owner.ownerHash) };
    return {
      ownerKey: getAddressDecoder().decode(utxo.ownerKey),
      ...owner,
      asset: getAddressDecoder().decode(utxo.asset),
      amount: Number(utxo.amount),
      blinding: getAddressDecoder().decode(utxo.blinding),
      dataHash: getAddressDecoder().decode(utxo.dataHash),
      ringDataHash: getAddressDecoder().decode(utxo.ringDataHash),
      treeId: utxo.treeId,
      ...(utxo.mint === undefined ? {} : { mint: utxo.mint }),
    };
  }

  function view(utxoHash: Bytes32, utxo: Record<string, unknown>): Record<string, unknown> {
    return {
      utxoHash: getAddressDecoder().decode(utxoHash),
      utxo,
      slot: 12,
      txSignature: signatureOf(1),
      eventIndex: 2,
      slotIndex: 3,
    };
  }

  async function readUtxos(utxoHashes: readonly Bytes32[], utxos: readonly unknown[]) {
    const { fetch, bodies } = capturingFetch({
      context: { blockTime: 1_700_000_000, slot: 13 },
      value: { utxos },
    });
    const signer = await generateKeyPairSigner();
    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).getAuditedUtxos({
      target: VECTOR_TARGET,
      utxoHashes,
      signer: messageSignerReader(signer),
      timestamp: 1_700_000_000n,
    });
    return { page, bodies, signer };
  }

  it("signs the hashes it sends and opens an answer that rebuilds its hash under the ring or the default ring", async () => {
    await initializePoseidon();
    const ringId = ringIdField(addressOf(7));
    const keyedHash = knownUtxoHash(keyed, ringId);
    const depositHash = knownUtxoHash(deposited, ringId);
    const defaultHash = knownUtxoHash(keyed, ZERO_32);
    const requested = [keyedHash, depositHash, defaultHash, filled(2, 32) as Bytes32];
    const { page, bodies, signer } = await readUtxos(requested, [
      view(keyedHash, wireUtxo(keyed)),
      view(depositHash, wireUtxo(deposited)),
      view(defaultHash, wireUtxo(keyed)),
      null,
    ]);
    expect(page.slot).toBe(13n);
    expect(page.utxos.map((entry) => entry?.utxo)).toEqual([keyed, deposited, keyed, undefined]);
    expect(page.utxos[0]).toMatchObject({
      utxoHash: keyedHash,
      slot: 12n,
      eventIndex: 2,
      slotIndex: 3,
    });
    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(bodies[0]?.["method"]).toBe("getAuditedUtxos");
    expect(Object.keys(params).sort()).toEqual(["auth", "ringProgramId", "utxoHashes"]);
    expect(params["utxoHashes"]).toEqual(requested.map((hash) => getAddressDecoder().decode(hash)));
    const auth = params["auth"] as Record<string, unknown>;
    const nonce = Uint8Array.from(Buffer.from(auth["nonce"] as string, "base64")) as Bytes32;
    const signed = auditedUtxosAttestation({
      target: VECTOR_TARGET,
      timestamp: 1_700_000_000n,
      nonce,
      utxoHashes: requested,
    });
    expect(
      ed25519.verify(
        Buffer.from(auth["signature"] as string, "base64"),
        signed,
        addressBytes(signer.address),
      ),
    ).toBe(true);
  });

  it.each<readonly [string, (utxo: Record<string, unknown>) => void]>([
    ["another amount", (utxo) => (utxo["amount"] = 10)],
    ["another tree", (utxo) => (utxo["treeId"] = 5)],
    [
      "both a nullifier key and the owner hash it makes",
      (utxo) =>
        (utxo["ownerHash"] = getAddressDecoder().decode(
          ownerHash(solanaOwnerIdentity(filled(3, 32)), filled(4, 32)),
        )),
    ],
    ["neither a nullifier key nor an owner hash", (utxo) => delete utxo["nullifierPk"]],
    ["a tree id past u16", (utxo) => (utxo["treeId"] = 65_536)],
    ["a blinding outside the field", (utxo) => (utxo["blinding"] = addressOf(0xff))],
    ["a mint its asset field does not derive", (utxo) => (utxo["mint"] = addressOf(9))],
  ])("refuses an opening with %s", async (_name, edit) => {
    await initializePoseidon();
    const utxoHash = knownUtxoHash(keyed, ringIdField(addressOf(7)));
    const utxo = wireUtxo(keyed);
    edit(utxo);
    await expect(readUtxos([utxoHash], [view(utxoHash, utxo)])).rejects.toMatchObject({
      code: "RING_RPC",
    });
  });

  it("keeps the mint an opening's asset field derives from", async () => {
    await initializePoseidon();
    const minted: KnownUtxo = { ...keyed, asset: assetField(addressOf(9)), mint: addressOf(9) };
    const utxoHash = knownUtxoHash(minted, ringIdField(addressOf(7)));
    const { page } = await readUtxos([utxoHash], [view(utxoHash, wireUtxo(minted))]);
    expect(page.utxos[0]?.utxo).toEqual(minted);
  });

  it("refuses an answer at another position than its hash", async () => {
    await initializePoseidon();
    const ringId = ringIdField(addressOf(7));
    const first = knownUtxoHash(keyed, ringId);
    const second = knownUtxoHash(deposited, ringId);
    const answers = [view(first, wireUtxo(keyed)), view(second, wireUtxo(deposited))];
    for (const utxos of [[answers[0]], [null, answers[0]], [answers[1], answers[0]]])
      await expect(readUtxos([first, second], utxos)).rejects.toMatchObject({ code: "RING_RPC" });
  });
});

describe("ring read request", () => {
  it("sends the tagged reader key and the signature over the attestation", async () => {
    const delegate = await generateKeyPairSigner();
    const signerAddress = delegate.address;
    const seen: Uint8Array[] = [];
    const returnedSignatures: Uint8Array[] = [];
    const signer = {
      address: signerAddress,
      signMessages: async (messages) => {
        seen.push(...messages.map((message) => message.content));
        const signatures = await delegate.signMessages(messages);
        returnedSignatures.push(
          ...signatures.map((signature) => new Uint8Array(signature[signerAddress]!)),
        );
        return signatures;
      },
    } satisfies MessagePartialSigner;
    const reader = messageSignerReader(signer);
    expect(reader.reader).toEqual(readerKeyBytes(signerAddress));
    expect(reader.reader[0]).toBe(1);
    expect(reader.reader[33]).toBe(0);
    const { fetch, bodies } = capturingFetch({
      context: { blockTime: 1_700_000_000, slot: 9 },
      value: {
        items: [decryptedItem({ eventIndex: 3 })],
        skipped: [
          { slot: 7, txSignature: signatureOf(2), eventIndex: 4, reason: "invalidAuditData" },
        ],
        cursor: "AQIE",
      },
    });
    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).getDecryptedTransactions({
      target: VECTOR_TARGET,
      signer: reader,
      cursor: Uint8Array.of(1, 2, 3),
      limit: 5n,
      timestamp: 1_700_000_000n,
    });
    expect(page.slot).toBe(9n);
    expect(page.blockTime).toBe(1_700_000_000n);
    expect(page.cursor).toEqual(Uint8Array.of(1, 2, 4));
    expect(page.items[0]?.eventIndex).toBe(3);
    expect(page.skipped).toEqual([
      { slot: 7n, signature: signatureOf(2), eventIndex: 4, reason: "invalidAuditData" },
    ]);
    await expect(
      new RingRpc("http://ring.example", {
        fetch,
        allowInsecureHttp: true,
      }).getDecryptedTransactions({ target: VECTOR_TARGET, signer: reader, limit: 1n }),
    ).rejects.toMatchObject({ code: "RING_RPC" });
    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(Object.keys(params).sort()).toEqual(["auth", "cursor", "limit", "ringProgramId"]);
    const auth = params["auth"] as Record<string, unknown>;
    expect(Object.keys(auth).sort()).toEqual(["nonce", "reader", "signature", "timestamp"]);
    expect(auth["reader"]).toBe(Buffer.from(readerKeyBytes(signerAddress)).toString("base64"));
    expect(auth["signature"]).toBe(Buffer.from(returnedSignatures[0]!).toString("base64"));
    expect(auth["timestamp"]).toBe(1_700_000_000);
    const nonce = Buffer.from(auth["nonce"] as string, "base64");
    expect(nonce).toHaveLength(32);
    expect(params["ringProgramId"]).toBe(addressOf(7));
    expect(params["cursor"]).toBe("AQID");
    expect(params["limit"]).toBe(5);
    expect(new TextDecoder().decode(seen[0])).toBe(
      new TextDecoder().decode(
        ringReadAttestation({
          method: "getDecryptedTransactions",
          target: VECTOR_TARGET,
          timestamp: 1_700_000_000n,
          nonce: Uint8Array.from(nonce) as Bytes32,
          cursor: Uint8Array.of(1, 2, 3),
          limit: 5n,
        }),
      ),
    );
  });

  it("reads the confidential page the Rust ring rpc serializes", async () => {
    const { fetch } = capturingFetch(rustPage("decrypted_page.json"));
    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).getDecryptedTransactions({ target: RING_TARGET, signer: await anyReader() });
    expect(page.cursor).toEqual(Uint8Array.of(15));
    expect(page.skipped).toEqual([
      { slot: 40n, signature: signatureOf(14), eventIndex: 8, reason: "missingAuditorMessage" },
    ]);
    const item = page.items[0]!;
    expect(item.slot).toBe(42n);
    expect(item.signature).toBe(signatureOf(1));
    expect(item.eventIndex).toBe(7);
    expect(item.outputs.map((output) => [output.slotIndex, output.opening.kind])).toEqual([
      [0, "ring"],
      [1, "exit"],
      [2, "dummy"],
    ]);
    expect(item.outputs[0]).toEqual({
      slotIndex: 0,
      outputContext: { treeId: 4, leafIndex: 1n, hash: filled(0x40, 32) },
      opening: {
        kind: "ring",
        utxo: {
          ownerKey: filled(0x10, 32),
          nullifierPk: filled(0x11, 32),
          asset: filled(0x12, 32),
          mint: addressOf(4),
          amount: 16n,
          blinding: filled(0x13, 32),
          dataHash: filled(0x14, 32),
          ringDataHash: filled(0x15, 32),
        },
        ownerTag: { kind: "recipient", u: filled(6, 32) },
      },
    });
    const exit = item.outputs[1]!.opening;
    expect(exit.kind === "exit" && exit.utxo.mint).toBeUndefined();
    expect(item.payloadErrors).toEqual([{ slotIndex: 3, kind: "commitment" }]);
    expect(item.sender).toBeUndefined();
    expect(item.inputs).toEqual([]);
    expect(item.nullifiers).toEqual([filled(12, 32)]);
    expect(item.spenders).toEqual([addressOf(13)]);
    expect(item.signers).toEqual([addressOf(13)]);
    expect(item.withdrawals).toEqual([
      { recipient: addressOf(10), asset: addressOf(4), amount: 5n },
    ]);
  });

  it("reads the wallet activity the Rust ring rpc serializes for its sender and a recipient", async () => {
    const { fetch, bodies } = capturingFetch(rustPage("wallet_activity_page.json"));
    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).getWalletActivity({
      target: RING_TARGET,
      signer: await anyReader(),
      wallet: addressOf(0x50),
    });
    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(bodies[0]?.["method"]).toBe("getWalletActivity");
    expect(params["wallet"]).toBe(addressOf(0x50));
    const [sent, received] = page.items;
    if (sent?.view.role !== "sender") throw new Error("a sender view");
    expect(sent.view.inputs).toHaveLength(6);
    expect(sent.view.outputs.map((output) => output.slotIndex)).toEqual([0, 1, 2]);
    expect(received?.view).toEqual({
      role: "recipient",
      outputs: [sent.view.outputs[0]],
      withdrawals: [],
    });
  });

  it("reads the anonymous page with its sender, tags and every input ring kind", async () => {
    const item = await readItem(rustItem("decrypted_anonymous_page.json"));
    expect(item.sender).toEqual({ ownerKey: filled(0x50, 32), nullifierPk: filled(0x51, 32) });
    const ring = item.outputs[0]!.opening;
    expect(ring.kind === "ring" && ring.ownerTag).toEqual({ kind: "view", tag: filled(0x31, 32) });
    expect(item.inputs.map((input) => input.nullifier)).toEqual(item.nullifiers);
    expect(
      item.inputs.map(({ opening }) => (opening.kind === "opened" ? opening.ring : opening.kind)),
    ).toEqual([
      { kind: "ring", commitment: filled(0x62, 32) },
      { kind: "unresolved", ring: filled(0x72, 32), default: filled(0x73, 32) },
      { kind: "default", commitment: filled(0x82, 32) },
      undefined,
      "dummy",
      "ambiguous",
    ]);
    expect(item.inputs[3]?.opening).toMatchObject({ amount: 0x90n, mint: addressOf(4) });
    expect(item.inputs[5]?.opening).toEqual({
      kind: "ambiguous",
      candidates: [filled(0xa0, 32), filled(0xa1, 32)],
    });
  });

  it("reads a sender whose spent UTXO 0 is a deposit and refuses an output UTXO without its key", async () => {
    const deposited = rustItem("decrypted_anonymous_page.json");
    delete (deposited["sender"] as Record<string, unknown>)["nullifierPk"];
    expect((await readItem(deposited)).sender).toEqual({ ownerKey: filled(0x50, 32) });
    const keyless = rustItem("decrypted_anonymous_page.json");
    delete (outputAt(keyless, 0)["utxo"] as Record<string, unknown>)["nullifierPk"];
    await expect(readItem(keyless)).rejects.toMatchObject({ code: "RING_RPC" });
  });

  it.each<readonly [string, (item: Record<string, unknown>) => void, string]>([
    [
      "a slot opened twice",
      (item) => (item["payloadErrors"] = [{ slotIndex: 0, kind: "frame" }]),
      "payloadErrors",
    ],
    [
      "a gap in the published slots",
      (item) => (item["outputs"] = (item["outputs"] as unknown[]).slice(1)),
      "payloadErrors",
    ],
    [
      "a ring output without its view tag",
      (item) => delete outputAt(item, 0)["tag"],
      "outputs[0].kind",
    ],
    [
      "a ring output with a view tag and a recipient key",
      (item) => (outputAt(item, 0)["recipientU"] = addressOf(6)),
      "outputs[0].kind",
    ],
    [
      "an exit with a recipient key",
      (item) => (outputAt(item, 1)["recipientU"] = addressOf(6)),
      "outputs[1].kind",
    ],
    [
      "a dummy with a UTXO",
      (item) => (outputAt(item, 2)["utxo"] = outputAt(item, 1)["utxo"]),
      "outputs[2].kind",
    ],
    [
      "an unknown output kind",
      (item) => (outputAt(item, 2)["kind"] = "padding"),
      "outputs[2].kind",
    ],
    ["a tag without a hidden sender", (item) => delete item["sender"], "inputs"],
    [
      "an input per published nullifier missing",
      (item) => (item["inputs"] = (item["inputs"] as unknown[]).slice(1)),
      "inputs",
    ],
    [
      "an input under another nullifier",
      (item) => ((item["inputs"] as Record<string, unknown>[])[0]!["nullifier"] = addressOf(99)),
      "inputs",
    ],
    [
      "an anonymous ring output under a recipient key",
      (item) => {
        const output = outputAt(item, 0);
        delete output["tag"];
        output["recipientU"] = addressOf(6);
      },
      "outputs.tag",
    ],
    [
      "an ambiguous input with an opening",
      (item) => {
        const inputs = item["inputs"] as Record<string, unknown>[];
        inputs[5]!["opening"] = inputs[0]!["opening"];
      },
      "inputs[5].candidates",
    ],
    [
      "an empty candidate list",
      (item) => ((item["inputs"] as Record<string, unknown>[])[5]!["candidates"] = []),
      "inputs[5].candidates",
    ],
    [
      "an unknown input ring kind",
      (item) =>
        (((item["inputs"] as Record<string, unknown>[])[0]!["opening"] as Record<string, unknown>)[
          "ring"
        ] = { kind: "pool", commitment: addressOf(1) }),
      "inputs[0].opening.ring.kind",
    ],
    ["an event index past u16", (item) => (item["eventIndex"] = 65536), "eventIndex"],
  ])("refuses %s", async (_name, edit, path) => {
    const item = rustItem("decrypted_anonymous_page.json");
    edit(item);
    await expect(readItem(item)).rejects.toMatchObject({ code: "RING_RPC", details: { path } });
  });

  const RUST_PAYLOAD_ERRORS = JSON.parse(
    readFileSync(
      new URL("../../../../../test-vectors/rpc/ring_rpc_payload_errors.json", import.meta.url),
      "utf8",
    ),
  ) as { kinds: unknown; foreign_body_and_low_order_key: { slotIndex: number; kind: string }[] };

  /** A delivered transfer of six slots, the vector's slots failed and every other a dummy. */
  const erroredItem = (payloadErrors: readonly unknown[]) =>
    decryptedItem({
      outputs: [0, 1, 3, 4].map((slotIndex) => ({
        slotIndex,
        outputContext: { treeId: 4, leafIndex: slotIndex, hash: addressOf(0x40 + slotIndex) },
        kind: "dummy",
      })),
      payloadErrors,
    });

  it("reads every payload error kind the shared vector names", async () => {
    expect(RUST_PAYLOAD_ERRORS.kinds).toEqual(RING_PAYLOAD_ERROR_KINDS);
    const item = await readItem(erroredItem(RUST_PAYLOAD_ERRORS.foreign_body_and_low_order_key));
    expect(item.payloadErrors).toEqual(RUST_PAYLOAD_ERRORS.foreign_body_and_low_order_key);
  });

  it.each<readonly [string, readonly unknown[]]>([
    [
      "an unknown kind",
      [
        { slotIndex: 2, kind: "decrypt" },
        { slotIndex: 5, kind: "recipientKey" },
      ],
    ],
    [
      "a slot past the published ones",
      [
        { slotIndex: 2, kind: "frame" },
        { slotIndex: 6, kind: "frame" },
      ],
    ],
    [
      "one slot twice",
      [
        { slotIndex: 2, kind: "frame" },
        { slotIndex: 2, kind: "commitment" },
      ],
    ],
  ])("refuses payload errors with %s", async (_name, payloadErrors) => {
    await expect(readItem(erroredItem(payloadErrors))).rejects.toMatchObject({
      code: "RING_RPC",
      details: { path: expect.stringMatching(/^payloadErrors/) },
    });
  });

  it("reads the withdrawal asset of an SPL leg and a SOL leg", async () => {
    const solMint = address("So11111111111111111111111111111111111111112");
    const item = await readItem(
      decryptedItem({
        withdrawals: [
          { recipient: addressOf(31), asset: addressOf(13), amount: 5 },
          { recipient: addressOf(32), asset: solMint, amount: 6 },
        ],
      }),
    );
    expect(item.withdrawals).toEqual([
      { recipient: addressOf(31), asset: addressOf(13), amount: 5n },
      { recipient: addressOf(32), asset: solMint, amount: 6n },
    ]);
  });

  it("sends a passkey assertion under camelCase keys", async () => {
    const bodies: Record<string, unknown>[] = [];
    const fetch = (async (_input: URL | string, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            context: { blockTime: 0, slot: 1 },
            value: { items: [], skipped: [], cursor: null },
          },
        }),
        JSON_HEADERS,
      );
    }) as typeof globalThis.fetch;
    const signer = {
      reader: readerKeyBytes(P256ReaderKey.fromBytes(hex(P256_HEX) as Bytes33)),
      sign: () =>
        Promise.resolve({
          signature: filled(1, 70),
          authenticatorData: filled(2, 37),
          clientDataJSON: filled(3, 80),
        }),
    };
    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).getDecryptedTransactions({
      target: VECTOR_TARGET,
      signer,
    });
    expect(page.cursor).toBeUndefined();
    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(Object.keys(params).sort()).toEqual(["auth", "ringProgramId"]);
    const auth = params["auth"] as Record<string, unknown>;
    expect(Object.keys(auth).sort()).toEqual([
      "nonce",
      "reader",
      "signature",
      "timestamp",
      "webauthn",
    ]);
    expect(auth["webauthn"]).toEqual({
      authenticatorData: Buffer.from(filled(2, 37)).toString("base64"),
      clientDataJson: Buffer.from(filled(3, 80)).toString("base64"),
    });
  });

  const serviceSecret = filled(9, 32);
  const servicePublicKey = getAddressDecoder().decode(ed25519.getPublicKey(serviceSecret));
  const auditor = X25519Keypair.fromBytes(new Uint8Array(32).fill(9)).publicKey();
  const genesisHash = filled(4, 32) as Bytes32;
  const auditorKeyResult = (signature: Uint8Array, service: Address = servicePublicKey) => ({
    ringProgramId: RING,
    auditorPubkey: Buffer.from(auditor.toBytes()).toString("base64"),
    auditorViewTag: getAddressDecoder().decode(auditor.u()),
    servicePubkey: service,
    signature: getBase58Decoder().decode(signature),
  });
  /** A ring rpc whose statement covers the cluster and nonce of each request it answers. */
  const statementFetch = (
    secret: Uint8Array = serviceSecret,
  ): {
    fetch: typeof globalThis.fetch;
    bodies: Record<string, unknown>[];
  } => {
    const bodies: Record<string, unknown>[] = [];
    const fetch = (async (_input: URL | string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      bodies.push(body);
      const auth = (body["params"] as Record<string, Record<string, string>>)["auth"]!;
      const statement = auditorKeyStatement({
        cluster: genesisHash,
        ringProgramId: RING,
        auditorPublicKey: auditor,
        nonce: Uint8Array.from(Buffer.from(auth["nonce"]!, "base64")) as Bytes32,
      });
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: auditorKeyResult(
            ed25519.sign(statement, secret),
            getAddressDecoder().decode(ed25519.getPublicKey(secret)),
          ),
        }),
        JSON_HEADERS,
      );
    }) as typeof globalThis.fetch;
    return { fetch, bodies };
  };

  it("refuses a plain HTTP endpoint unless the caller opts in", () => {
    expect(() => new RingRpc("http://ring.example")).toThrowError(
      expect.objectContaining({ code: "RING_RPC_CONFIG" }),
    );
    expect(() => new RingRpc("https://user:pw@ring.example")).toThrowError(
      expect.objectContaining({ code: "RING_RPC_CONFIG" }),
    );
  });

  it("keeps server error text out of the thrown details", async () => {
    const fetch = (async () =>
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          error: { code: -32000, message: "secret text" },
        }),
        JSON_HEADERS,
      )) as typeof globalThis.fetch;
    const error = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    })
      .ringStatus(addressOf(7))
      .then(
        () => undefined,
        (cause: unknown) => cause,
      );
    expect(error).toMatchObject({ code: "RING_RPC" });
    expect(JSON.stringify(error)).not.toContain("secret");
  });

  it("threads the request context timeout into the transport", async () => {
    const fetch = ((_input: unknown, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new Error("aborted"));
        });
      })) as typeof globalThis.fetch;
    await expect(
      new RingRpc("http://ring.example", {
        fetch,
        allowInsecureHttp: true,
      }).ringStatus(addressOf(7), { timeoutMs: 5 }),
    ).rejects.toMatchObject({ code: "RING_RPC_TRANSPORT" });
  });

  it("verifies the auditor key attestation before trusting the key", async () => {
    const otherRequest = auditorKeyStatement({
      cluster: genesisHash,
      ringProgramId: RING,
      auditorPublicKey: auditor,
      nonce: filled(3, 32) as Bytes32,
    });
    expect(otherRequest.subarray(0, 26)).toEqual(
      new TextEncoder().encode("zolana/ring-auditor-key/v2"),
    );
    expect(otherRequest).toHaveLength(26 + 32 + 32 + 33 + 32);
    const authority = await generateKeyPairSigner();
    const key = await new RingRpc("http://ring.example", {
      fetch: statementFetch().fetch,
      allowInsecureHttp: true,
    }).createAuditorKey({ ringProgramId: RING, genesisHash, authority, servicePublicKey });
    expect(key.auditorPublicKey.equals(auditor)).toBe(true);
    expect(key.auditorViewTag).toEqual(auditor.u());
    expect(key.servicePublicKey).toBe(servicePublicKey);

    await expect(
      new RingRpc("http://ring.example", {
        fetch: capturingFetch(auditorKeyResult(filled(1, 64))).fetch,
        allowInsecureHttp: true,
      }).createAuditorKey({ ringProgramId: RING, genesisHash, authority, servicePublicKey }),
    ).rejects.toMatchObject({ code: "RING_RPC" });
    await expect(
      new RingRpc("http://ring.example", {
        fetch: capturingFetch(auditorKeyResult(ed25519.sign(otherRequest, serviceSecret))).fetch,
        allowInsecureHttp: true,
      }).createAuditorKey({ ringProgramId: RING, genesisHash, authority, servicePublicKey }),
    ).rejects.toMatchObject({ code: "RING_RPC" });
  });

  it("refuses an auditor key attested under a service key the caller did not pin", async () => {
    const authority = await generateKeyPairSigner();
    const answered = new RingRpc("http://ring.example", {
      fetch: statementFetch(filled(8, 32)).fetch,
      allowInsecureHttp: true,
    });

    await expect(
      answered.createAuditorKey({ ringProgramId: RING, genesisHash, authority, servicePublicKey }),
    ).rejects.toMatchObject({ code: "RING_RPC" });
  });

  it("signs the auditor key request with the authority and sends it under camelCase keys", async () => {
    const authority = await generateKeyPairSigner();
    const { fetch, bodies } = statementFetch();
    await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).createAuditorKey({
      ringProgramId: RING,
      genesisHash,
      authority,
      servicePublicKey,
      timestamp: 1_700_000_000n,
    });

    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(Object.keys(params).sort()).toEqual(["auth", "ringProgramId"]);
    expect(params["ringProgramId"]).toBe(RING);
    const auth = params["auth"] as Record<string, unknown>;
    expect(Object.keys(auth).sort()).toEqual([
      "authority",
      "genesisHash",
      "nonce",
      "signature",
      "timestamp",
    ]);
    expect(auth["authority"]).toBe(authority.address);
    expect(auth["genesisHash"]).toBe("GgBaCs3NCBuZN12kCJgAW63ydqohFkHEdfdEXBPzLHq");
    expect(auth["timestamp"]).toBe(1_700_000_000);
    const nonce = Uint8Array.from(Buffer.from(String(auth["nonce"]), "base64"));
    expect(nonce).toHaveLength(32);
    expect(
      ed25519.verify(
        Uint8Array.from(Buffer.from(String(auth["signature"]), "base64")),
        auditorKeyRequestAttestation({
          genesisHash,
          ringProgramId: RING,
          timestamp: 1_700_000_000n,
          nonce: nonce as Bytes32,
        }),
        addressBytes(authority.address),
      ),
    ).toBe(true);
  });
});
