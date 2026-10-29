import { readFileSync } from "node:fs";

import { createKeyPairSignerFromPrivateKeyBytes, getBase58Decoder } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import type { Address, Bytes32, Bytes33, Signature } from "@heliuslabs/zolana/interface";
import type { indexerTypes } from "@heliuslabs/zolana/internal";
import { ShieldedKeypair, SigningKey } from "@heliuslabs/zolana/keypair";
import {
  encodeGetPendingEnrolmentsRequest,
  encodePrepareAuthorityTransferRequest,
  encodePrepareRelayRequest,
  encodeRefuseEnrolmentRequest,
  encodeSetReaderGrantRequest,
} from "../../../src/protocol/ring-rpc/ring-rpc-codec.js";
import { P256ReaderKey } from "../../../src/operations/management/reader-access.js";
import {
  RingAuthorityTransferRequest,
  RingReaderGrantRequest,
  auditedUtxosAttestation,
  authorityTransferAttestation,
  enrolmentAttestation,
  readerGrantAttestation,
  ringReadAttestation,
  signPendingEnrolmentsRequest,
  signRefuseEnrolmentRequest,
  type RingEnrolmentAction,
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
      source: address(5),
      mint: filled(3, 32) as Address,
      payments: [{ recipient: address(9), amount: 250n }],
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
      .sign(delegate)
      .finally(() => nonce.mockRestore());
    expect(JSON.stringify(encodePrepareAuthorityTransferRequest(signed))).toBe(vector.wire);
  });
});

describe("enrolment requests", () => {
  it("signs the config authority's list and refusal byte for byte as the Rust vector", async () => {
    type Signed = { message: string; wire: string };
    const vector = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/enrolment_attestation.json", import.meta.url),
        "utf8",
      ),
    ) as { list: Signed; listAfter: Signed; refuse: Signed & { updateId: indexerTypes.Hash } };
    const authority = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(8));
    const target = {
      cluster: new Uint8Array(32).fill(1) as Bytes32,
      service: filled(2, 32) as Address,
      ringProgramId: filled(7, 32) as Address,
    };
    const { updateId } = vector.refuse;
    const message = (action: RingEnrolmentAction) =>
      new TextDecoder().decode(
        enrolmentAttestation({
          target,
          authority: authority.address,
          action,
          timestamp: 1_700_000_000n,
          nonce: new Uint8Array(32).fill(4) as Bytes32,
        }),
      );
    expect(message({ kind: "list" })).toBe(vector.list.message);
    expect(message({ kind: "list", cursor: updateId })).toBe(vector.listAfter.message);
    expect(message({ kind: "refuse", updateId })).toBe(vector.refuse.message);
    const nonce = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((array) => {
      (array as Uint8Array).fill(4);
      return array;
    });
    try {
      const list = await signPendingEnrolmentsRequest(target, authority, undefined, 1_700_000_000n);
      const listAfter = await signPendingEnrolmentsRequest(
        target,
        authority,
        updateId,
        1_700_000_000n,
      );
      const refuse = await signRefuseEnrolmentRequest(target, authority, updateId, 1_700_000_000n);
      expect(JSON.stringify(encodeGetPendingEnrolmentsRequest(list))).toBe(vector.list.wire);
      expect(JSON.stringify(encodeGetPendingEnrolmentsRequest(listAfter))).toBe(
        vector.listAfter.wire,
      );
      expect(JSON.stringify(encodeRefuseEnrolmentRequest(refuse))).toBe(vector.refuse.wire);
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
