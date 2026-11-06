import { RingListSaltRequest, RingRpc, listSaltAttestation } from "../../../src/rpc/ring-rpc.js";
import {
  RingMergeSettingsRequest,
  encodeSetMergeSettingsRequest,
  mergeSettingsAttestation,
} from "../../../src/ring-advanced.js";
import { encodeGetListSaltRequest } from "../../../src/protocol/ring-rpc/ring-rpc-codec.js";
import { ringRpcRefusalName } from "../../../src/protocol/ring-rpc/ring-rpc-refusal.js";
import type { RelayIntent } from "../../../src/protocol/ring-rpc/ring-rpc-types.js";
import {
  encodeRelayEnrollInputs,
  enrollRequestDigest,
} from "../../../src/protocol/ring-rpc/relay-enroll-inputs.js";
import { readFileSync } from "node:fs";

import {
  createKeyPairSignerFromPrivateKeyBytes,
  getBase58Decoder,
  getBase58Encoder,
} from "@solana/kit";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it, vi } from "vitest";

import { SPL_TOKEN_PROGRAM_ID } from "@heliuslabs/spr/interface";
import type { Address, Bytes32, Bytes33, Signature } from "@heliuslabs/spr/interface";
import { addressBytes, type indexerTypes } from "@heliuslabs/spr/internal";
import { SOL_MINT } from "@heliuslabs/spr/transaction";
import { ShieldedKeypair, SigningKey, ViewingKey } from "@heliuslabs/spr/keypair";
import {
  encodeCreateRecordsRegistryRequest,
  encodeGetPendingListApprovalsRequest,
  encodePrepareAuthorityTransferRequest,
  encodePrepareRelayRequest,
  encodeRefuseListApprovalRequest,
  encodeSetReaderGrantRequest,
} from "../../../src/protocol/ring-rpc/ring-rpc-codec.js";
import {
  depositRequestDigest,
  mergeRequestDigest,
} from "../../../src/protocol/ring-rpc/relay-proof-inputs.js";
import { P256ReaderKey } from "../../../src/operations/management/reader-access.js";
import {
  RingAuthorityTransferRequest,
  RingReaderGrantRequest,
  auditedUtxosAttestation,
  authorityTransferAttestation,
  policyAuthorityAttestation,
  readerGrantAttestation,
  ringReadAttestation,
  signCreateRecordsRegistryRequest,
  signPendingListApprovalsRequest,
  signRefuseListApprovalRequest,
  type PolicyAuthorityAction,
} from "../../../src/rpc/ring-rpc.js";

const base58 = getBase58Decoder();

function filled(byte: number, length: number): string {
  return base58.decode(new Uint8Array(length).fill(byte));
}

describe("prepareRelay", () => {
  it("encodes the request byte for byte as the Rust vector", () => {
    const vector = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/relay_request.json", import.meta.url),
        "utf8",
      ),
    ) as { wire: string };
    const wire = encodePrepareRelayRequest({
      ring: filled(1, 32) as Address,
      quote: { feePayer: filled(2, 32) as Address, validUntilSlot: 4242n },
      intent: {
        operation: "anonymous",
        proofInputs: "AwQF" as indexerTypes.Base64String,
        ownerSignature: filled(7, 64) as Signature,
      },
    });
    expect(JSON.stringify(wire)).toBe(vector.wire);
  });
});

describe("relay_enroll_inputs.json", () => {
  const vector = JSON.parse(
    readFileSync(
      new URL("../../../../../test-vectors/rpc/relay_enroll_inputs.json", import.meta.url),
      "utf8",
    ),
  ) as Readonly<Record<string, string>>;
  const bytes = (name: string) => Uint8Array.from(Buffer.from(vector[name] ?? "", "hex"));
  const hex = (value: Uint8Array) => Buffer.from(value).toString("hex");
  const inputs = {
    ringProgramId: filled(1, 32) as Address,
    owner: filled(2, 32) as Address,
    trackingRegistry: filled(3, 32) as Address,
    instructionData: bytes("instruction_data"),
  };
  const request = (intent: RelayIntent) => ({
    ring: filled(1, 32) as Address,
    quote: { feePayer: filled(2, 32) as Address, validUntilSlot: 4242n },
    intent,
  });
  const proofInputs = "AwQF" as indexerTypes.Base64String;
  const signature = filled(7, 64) as Signature;

  it("encodes the inputs and hashes the digest Rust writes", () => {
    expect(hex(encodeRelayEnrollInputs(inputs))).toBe(vector["encoded"]);
    expect(hex(enrollRequestDigest(inputs))).toBe(vector["request_digest"]);
  });

  it("moves the digest with a changed field", () => {
    expect(
      hex(enrollRequestDigest({ ...inputs, instructionData: Uint8Array.of(6, 7, 9) })),
    ).not.toBe(vector["request_digest"]);
  });

  it("carries each signature byte for byte as Rust", () => {
    expect(
      JSON.stringify(
        encodePrepareRelayRequest(
          request({ operation: "enroll", proofInputs, ownerSignature: signature }),
        ),
      ),
    ).toBe(vector["enroll_wire"]);
    expect(
      JSON.stringify(
        encodePrepareRelayRequest(
          request({ operation: "delegate", proofInputs, delegateSignature: signature }),
        ),
      ),
    ).toBe(vector["delegate_wire"]);
    expect(
      JSON.stringify(
        encodePrepareRelayRequest(
          request({ operation: "deposit", proofInputs, depositorSignature: signature }),
        ),
      ),
    ).toBe(vector["deposit_wire"]);
    expect(
      JSON.stringify(
        encodePrepareRelayRequest(
          request({ operation: "merge", proofInputs, ownerSignature: signature }),
        ),
      ),
    ).toBe(vector["merge_wire"]);
  });

  it("hashes the digests a depositor and an owner sign as Rust", () => {
    const encoded = Uint8Array.of(3, 4, 5);
    expect(hex(depositRequestDigest(encoded))).toBe(vector["deposit_request_digest"]);
    expect(hex(mergeRequestDigest(encoded))).toBe(vector["merge_request_digest"]);
  });

  it("refuses an intent with no signature", () => {
    const missing = undefined as unknown as Signature;
    for (const intent of [
      { operation: "enroll", proofInputs, ownerSignature: missing },
      { operation: "delegate", proofInputs, delegateSignature: missing },
      { operation: "deposit", proofInputs, depositorSignature: missing },
      { operation: "merge", proofInputs, ownerSignature: missing },
    ] as const)
      expect(() => encodePrepareRelayRequest(request(intent))).toThrow();
  });
});

describe("getListSalt", () => {
  const vector = JSON.parse(
    readFileSync(
      new URL("../../../../../test-vectors/rpc/list_salt_request.json", import.meta.url),
      "utf8",
    ),
  ) as { message: string; wire: string };
  const target = {
    cluster: new Uint8Array(32).fill(1) as Bytes32,
    service: filled(2, 32) as Address,
    ringProgramId: filled(7, 32) as Address,
  };
  const owner = filled(3, 32) as Address;
  const signed = async () => {
    const writer = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(8));
    const nonce = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((array) => {
      (array as Uint8Array).fill(4);
      return array;
    });
    const request = await RingListSaltRequest.forOwner(target, owner)
      .at(1_700_000_000n)
      .sign(writer)
      .finally(() => nonce.mockRestore());
    return { writer, request };
  };
  const answering = (body: unknown) =>
    new RingRpc("http://ring.example", {
      allowInsecureHttp: true,
      fetch: (async () =>
        new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, ...(body as object) }), {
          headers: { "content-type": "application/json" },
        })) as typeof globalThis.fetch,
    });

  it("signs the writer's request byte for byte as the Rust vector", async () => {
    const { writer, request } = await signed();
    const message = listSaltAttestation({
      target,
      writer: writer.address,
      owner,
      timestamp: 1_700_000_000n,
      nonce: new Uint8Array(32).fill(4) as Bytes32,
    });
    expect(new TextDecoder().decode(message)).toBe(vector.message);
    expect(JSON.stringify(encodeGetListSaltRequest(request))).toBe(vector.wire);
  });

  it("reads a salt and an owner with no row", async () => {
    const { request } = await signed();
    const salt = new Uint8Array(32).fill(9);
    const text = getBase58Decoder().decode(salt);
    await expect(answering({ result: { listSalt: text } }).getListSalt(request)).resolves.toEqual(
      salt,
    );
    await expect(answering({ result: {} }).getListSalt(request)).resolves.toBeUndefined();
  });

  it("names -32226 as a signer writing no salted list", async () => {
    const { request } = await signed();
    await expect(
      answering({ error: { code: -32226, message: "not a writer" } }).getListSalt(request),
    ).rejects.toMatchObject({
      code: "RING_RPC_REFUSED",
      details: { method: "getListSalt", refusal: "notListWriter" },
    });
  });
});

describe("prepareAuthorityTransfer", () => {
  it("signs the delegate's request byte for byte as the Rust vector", async () => {
    const vector = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/authority_transfer.json", import.meta.url),
        "utf8",
      ),
    ) as { message: string; wire: string };
    const address = (seed: number) =>
      ShieldedKeypair.fromKeypair(
        SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
      ).shieldedAddress();
    const delegate = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(8));
    const target = {
      cluster: new Uint8Array(32).fill(1) as Bytes32,
      service: filled(2, 32) as Address,
      ringProgramId: filled(7, 32) as Address,
    };
    const transfer = {
      sources: [address(5)],
      exits: [{ recipient: address(10), mint: filled(3, 32) as Address, amount: 20n }],
      withdrawals: [
        {
          recipient: filled(11, 32) as Address,
          mint: filled(3, 32) as Address,
          amount: 30n,
          tokenProgram: SPL_TOKEN_PROGRAM_ID,
        },
        { recipient: filled(12, 32) as Address, mint: filled(0, 32) as Address, amount: 40n },
      ],
      payments: [{ recipient: address(9), mint: filled(3, 32) as Address, amount: 250n }],
    };
    const message = authorityTransferAttestation({
      target,
      delegate: delegate.address,
      transfer,
      timestamp: 1_700_000_000n,
      nonce: new Uint8Array(32).fill(4) as Bytes32,
    });
    expect(new TextDecoder().decode(message)).toBe(vector.message);
    const nonce = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((array) => {
      (array as Uint8Array).fill(4);
      return array;
    });
    const signed = await RingAuthorityTransferRequest.forTransfer(target, transfer)
      .at(1_700_000_000n)
      .withTxViewingKey(ViewingKey.fromBytes(new Uint8Array(32).fill(6) as Bytes32).secretBytes())
      .sign(delegate)
      .finally(() => nonce.mockRestore());
    expect(JSON.stringify(encodePrepareAuthorityTransferRequest(signed))).toBe(vector.wire);
  });
});

describe("policy authority requests", () => {
  it("signs the policy authority's list and refusal byte for byte as the Rust vector", async () => {
    type Signed = { message: string; wire: string };
    const vector = JSON.parse(
      readFileSync(
        new URL(
          "../../../../../test-vectors/rpc/policy_authority_attestation.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as {
      list: Signed;
      listAfter: Signed;
      refuse: Signed & { updateId: indexerTypes.Hash };
      createRecords: Signed;
    };
    const authority = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(8));
    const target = {
      cluster: new Uint8Array(32).fill(1) as Bytes32,
      service: filled(2, 32) as Address,
      ringProgramId: filled(7, 32) as Address,
      registry: filled(2, 32) as Address,
    };
    const { updateId } = vector.refuse;
    const message = (action: PolicyAuthorityAction) =>
      new TextDecoder().decode(
        policyAuthorityAttestation({
          target,
          authority: authority.address,
          action,
          timestamp: 1_700_000_000n,
          nonce: new Uint8Array(32).fill(4) as Bytes32,
        }),
      );
    expect(message({ kind: "list", registry: target.registry })).toBe(vector.list.message);
    expect(message({ kind: "list", registry: target.registry, cursor: updateId })).toBe(
      vector.listAfter.message,
    );
    expect(message({ kind: "refuse", registry: target.registry, updateId })).toBe(
      vector.refuse.message,
    );
    expect(message({ kind: "createRecords" })).toBe(vector.createRecords.message);
    const nonce = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((array) => {
      (array as Uint8Array).fill(4);
      return array;
    });
    try {
      const list = await signPendingListApprovalsRequest(
        target,
        authority,
        undefined,
        1_700_000_000n,
      );
      const listAfter = await signPendingListApprovalsRequest(
        target,
        authority,
        updateId,
        1_700_000_000n,
      );
      const refuse = await signRefuseListApprovalRequest(
        target,
        authority,
        updateId,
        1_700_000_000n,
      );
      expect(JSON.stringify(encodeGetPendingListApprovalsRequest(list))).toBe(vector.list.wire);
      expect(JSON.stringify(encodeGetPendingListApprovalsRequest(listAfter))).toBe(
        vector.listAfter.wire,
      );
      expect(JSON.stringify(encodeRefuseListApprovalRequest(refuse))).toBe(vector.refuse.wire);
      const createRecords = await signCreateRecordsRegistryRequest(
        target,
        authority,
        1_700_000_000n,
      );
      expect(JSON.stringify(encodeCreateRecordsRegistryRequest(createRecords))).toBe(
        vector.createRecords.wire,
      );
    } finally {
      nonce.mockRestore();
    }
  });
});

describe("setReaderGrant", () => {
  it("signs ring-wide and wallet grants and wallet reads byte for byte as the Rust vector", async () => {
    type Signed = { message: string; wire: string };
    const vector = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/reader_grant.json", import.meta.url),
        "utf8",
      ),
    ) as { ringWide: Signed; wallet: Signed; walletRead: string; walletUtxos: string };
    const authority = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(8));
    const wallet = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(7));
    const reader = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(9));
    const passkey = P256ReaderKey.fromBytes(
      Uint8Array.from(
        Buffer.from("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "hex"),
      ) as Bytes33,
    );
    const target = {
      cluster: new Uint8Array(32).fill(1) as Bytes32,
      service: filled(2, 32) as Address,
      ringProgramId: filled(7, 32) as Address,
    };
    const timestamp = 1_700_000_000n;
    const nonce = new Uint8Array(32).fill(4) as Bytes32;
    const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
    const grants = [
      {
        signer: authority,
        grant: { reader: reader.address, action: "grant" as const },
        expected: vector.ringWide,
      },
      {
        signer: wallet,
        grant: { wallet: wallet.address, reader: passkey, action: "revoke" as const },
        expected: vector.wallet,
      },
    ];
    const random = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((array) => {
      (array as Uint8Array).fill(4);
      return array;
    });
    try {
      for (const { signer, grant, expected } of grants) {
        expect(text(readerGrantAttestation({ target, ...grant, timestamp, nonce }))).toBe(
          expected.message,
        );
        const signed = await RingReaderGrantRequest.forGrant(target, grant)
          .at(timestamp)
          .sign(signer);
        expect(JSON.stringify(encodeSetReaderGrantRequest(signed))).toBe(expected.wire);
      }
    } finally {
      random.mockRestore();
    }
    // A wallet grant signed by another key never reaches the service.
    await expect(
      RingReaderGrantRequest.forGrant(target, grants[1]!.grant).sign(authority),
    ).rejects.toMatchObject({ code: "RING_RPC" });
    expect(
      text(
        ringReadAttestation({
          method: "getDecryptedTransactions",
          target,
          timestamp,
          nonce,
          wallet: wallet.address,
        }),
      ),
    ).toBe(vector.walletRead);
    expect(
      text(
        auditedUtxosAttestation({
          target,
          timestamp,
          nonce,
          utxoHashes: [new Uint8Array(32).fill(5) as Bytes32],
          wallet: wallet.address,
        }),
      ),
    ).toBe(vector.walletUtxos);
  });
});

describe("setMergeSettings", () => {
  const target = {
    cluster: new Uint8Array(32).fill(1) as Bytes32,
    service: filled(2, 32) as Address,
    ringProgramId: filled(7, 32) as Address,
  };
  const settings = { mint: SOL_MINT, targetNoteCount: 4, minAverageAmount: 9n };
  const timestamp = 1_700_000_000n;
  const nonce = new Uint8Array(32).fill(4) as Bytes32;
  const signed = async () => {
    const owner = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(8));
    const random = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((array) => {
      (array as Uint8Array).fill(4);
      return array;
    });
    const request = await RingMergeSettingsRequest.forSettings(target, settings)
      .at(timestamp)
      .sign(owner)
      .finally(() => random.mockRestore());
    return { owner, request };
  };

  it("signs the owner's settings over the Rust attestation lines", async () => {
    const { owner, request } = await signed();
    // Rust `MergeSettingsAttestation::message`.
    const rust = [
      "zolana/ring-rpc-merge-settings",
      `cluster: ${filled(1, 32)}`,
      `service: ${filled(2, 32)}`,
      `ring: ${filled(7, 32)}`,
      `owner: ${owner.address}`,
      `mint: ${SOL_MINT}`,
      "target notes: 4",
      "minimum average: 9",
      "timestamp: 1700000000",
      `nonce: ${Buffer.from(nonce).toString("base64")}`,
    ].join("\n");
    const message = mergeSettingsAttestation({
      target,
      owner: owner.address,
      settings,
      timestamp,
      nonce,
    });
    expect(new TextDecoder().decode(message)).toBe(rust);
    expect(request).toMatchObject({ ring: target.ringProgramId, owner: owner.address, settings });
    expect(
      ed25519.verify(
        Uint8Array.from(base58Bytes(request.signature)),
        message,
        addressBytes(owner.address),
      ),
    ).toBe(true);
    expect(Object.keys(encodeSetMergeSettingsRequest(request))).toEqual([
      "ring",
      "owner",
      "settings",
      "timestamp",
      "nonce",
      "signature",
    ]);
  });

  it("sends the request and reads the stored settings, a stale write names its refusal", async () => {
    const { request } = await signed();
    const sent: unknown[] = [];
    const answering = (body: unknown) =>
      new RingRpc("http://ring.example", {
        allowInsecureHttp: true,
        fetch: (async (_url: unknown, init?: RequestInit) => {
          sent.push(JSON.parse(String(init?.body)));
          return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, ...(body as object) }), {
            headers: { "content-type": "application/json" },
          });
        }) as typeof globalThis.fetch,
      });
    await expect(
      answering({
        result: { mint: SOL_MINT, targetNoteCount: 4, minAverageAmount: 9 },
      }).setMergeSettings(request),
    ).resolves.toEqual(settings);
    expect(sent[0]).toMatchObject({
      method: "setMergeSettings",
      params: JSON.parse(JSON.stringify(encodeSetMergeSettingsRequest(request))),
    });
    await expect(
      answering({ error: { code: -32171, message: "stale" } }).setMergeSettings(request),
    ).rejects.toMatchObject({
      code: "RING_RPC_REFUSED",
      details: { method: "setMergeSettings", refusal: "staleMergeSettings" },
    });
  });

  it("refuses settings the Rust request cannot carry before any signature", () => {
    expect(() =>
      RingMergeSettingsRequest.forSettings(target, { ...settings, targetNoteCount: 2 ** 32 }),
    ).toThrow();
    expect(() =>
      RingMergeSettingsRequest.forSettings(target, { ...settings, mint: "mint" as Address }),
    ).toThrow();
  });
});

function base58Bytes(text: string): Uint8Array {
  return getBase58Encoder().encode(text) as Uint8Array;
}

describe("ring rpc refusals", () => {
  it("names -32227 and -32228 as delegate notes outside the requested sources", () => {
    expect(ringRpcRefusalName(-32227)).toBe("sourceNote");
    expect(ringRpcRefusalName(-32228)).toBe("unrequestedInput");
  });

  it("names -32165 as a co-signer that approves no demanded class", () => {
    expect(ringRpcRefusalName(-32165)).toBe("notApproved");
  });

  it("names -32216 as a relayed message past one transaction", () => {
    expect(ringRpcRefusalName(-32216)).toBe("oversized");
  });

  it("names -32213 to -32215 as the relayed enrollment refusals", () => {
    expect([-32213, -32214, -32215].map(ringRpcRefusalName)).toEqual([
      "alreadyEnrolled",
      "registerKeyProof",
      "enrollmentRefused",
    ]);
  });
});
