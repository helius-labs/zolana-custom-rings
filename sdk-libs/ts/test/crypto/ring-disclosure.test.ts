import { beforeAll, describe, expect, it } from "vitest";

import stream from "../../../../test-vectors/audit/auditor-stream.json" with { type: "json" };
import { initializePoseidon } from "@heliuslabs/spr";
import type { Bytes32, Bytes33 } from "@heliuslabs/spr/interface";
import { X25519Keypair, X25519PublicKey } from "@heliuslabs/spr/keypair";
import { auditSharedSecret, symmetricAuditApply } from "../../src/crypto/audit/audit.js";

beforeAll(initializePoseidon);

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

describe("auditor-stream.json", () => {
  it.each([...stream.labels, ...stream.records])(
    "$name reads the worked stream at its counter",
    (vector) => {
      const secret = hex(vector.secret) as Bytes32;
      const position = {
        label: new TextEncoder().encode(vector.label),
        counter: vector.counter,
      };
      expect(symmetricAuditApply(secret, position, hex(vector.plaintext))).toEqual(
        hex(vector.ciphertext),
      );
      expect(symmetricAuditApply(secret, position, hex(vector.ciphertext))).toEqual(
        hex(vector.plaintext),
      );
    },
  );

  it("roots the auditor stream in the agreement of both tagged keys", () => {
    const eph = X25519Keypair.fromBytes(hex(stream.eph_sk) as Bytes32);
    expect(eph.publicKey().u()).toEqual(hex(stream.eph_u));
    const auditor = X25519PublicKey.fromBytes(
      Uint8Array.of(4, ...hex(stream.auditor_u)) as Bytes33,
    );
    const secret = auditSharedSecret(eph.ecdh(auditor), eph.publicKey(), auditor);
    const signer = stream.labels.find((vector) => vector.name === "envelope_signer");
    expect(signer === undefined ? "" : hex(signer.secret)).toEqual(secret);
  });
});
