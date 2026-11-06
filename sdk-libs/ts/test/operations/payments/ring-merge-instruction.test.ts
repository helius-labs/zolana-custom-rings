import { address } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import { encodeMergeTransactInstructionData, ZERO_32 } from "@heliuslabs/spr/internal";
import { MergeEncryptionScheme } from "@heliuslabs/spr/interface";
import type { Bytes16, Bytes32, Bytes33, Bytes128 } from "@heliuslabs/spr/interface";
import { ShieldedKeypair } from "@heliuslabs/spr/keypair";
import { Wallet } from "@heliuslabs/spr/transaction";

import {
  buildRingMergeTransaction,
  ringMergeInstruction,
  type RingMergeTransactionParams,
} from "../../../src/operations/payments/merge.js";
import {
  decodeRingMergeRequest,
  MergeRingAuthority,
} from "../../../src/crypto/audit/merge-disclosure.js";
import { OPENING_RECORD_LEN } from "../../../src/protocol/codec/ring-disclosure-layout.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../../../src/protocol/proof/custom-ring-proof.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const TRACKING = address("Stor111111111111111111111111111111111111111");
const PAYER = address("So11111111111111111111111111111111111111112");
const OWNER = address("SysvarC1ock11111111111111111111111111111111");

/** A compressible G2 point, the generator's bytes. */
const G2 = Uint8Array.from(
  Buffer.from(
    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2" +
      "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed" +
      "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b" +
      "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
    "hex",
  ),
) as Bytes128;

const data = () => ({
  expiryUnixTs: 9n,
  proof: { a: ZERO_32, b: G2, c: ZERO_32 },
  outputUtxoHash: new Uint8Array(32).fill(1) as Bytes32,
  outputEncryption: {
    scheme: MergeEncryptionScheme.PoseidonCtrV1,
    salt: new Uint8Array(16) as Bytes16,
    ciphertext: [ZERO_32, ZERO_32, ZERO_32] as const,
  },
  privateTxHash: new Uint8Array(32).fill(2) as Bytes32,
  nullifiers: [new Uint8Array(32).fill(3) as Bytes32, new Uint8Array(32).fill(4) as Bytes32],
  utxoTreeRootIndex: 0,
  nullifierTreeRootIndex: 0,
});

const sealed = {
  proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
  ephemeralPublicKey: new Uint8Array(33) as Bytes33,
  ciphertext: new Uint8Array(OPENING_RECORD_LEN).fill(5),
};

async function instruction(owner?: typeof OWNER) {
  return ringMergeInstruction({
    ringProgramId: RING,
    inputTree: TREE,
    outputTree: TREE,
    payer: PAYER,
    data: data(),
    outputRingDataHash: ZERO_32,
    sealed,
    tracking: TRACKING,
    trackingRevision: owner === undefined ? 7n : 0n,
    ...(owner === undefined ? {} : { owner }),
  });
}

describe("ring merge tag 57", () => {
  beforeAll(initializePoseidon);

  it("a nonzero key names the ring authority and binds the tracking revision", async () => {
    const built = await instruction();
    const bytes = Uint8Array.from(built.data ?? []);
    expect(bytes[0]).toBe(RingInstructionTag.merge);
    const request = decodeRingMergeRequest(bytes.subarray(1));
    expect(request.authority).toBe(MergeRingAuthority.ring);
    expect(request.trackingRevision).toBe(7n);
    expect(built.accounts?.[1]?.address).toBe(TRACKING);
    expect(built.accounts).toHaveLength(8 + 2);
  });

  it("a zero key signs at SPP's owner slot past the ring prefix", async () => {
    const built = await instruction(OWNER);
    const request = decodeRingMergeRequest(Uint8Array.from(built.data ?? []).subarray(1));
    expect(request.authority).toBe(MergeRingAuthority.ownerSigned);
    expect(request.trackingRevision).toBe(0n);
    // `[ring, tracking]` ahead of SPP's list, Rust `RING_MERGE_OWNER_INDEX` 6.
    expect(built.accounts?.[2 + 6]?.address).toBe(OWNER);
    expect(encodeMergeTransactInstructionData(data()).length).toBeGreaterThan(0);
  });

  it("refuses a zero-key signer other than the owner before any read", async () => {
    const owner = ShieldedKeypair.generate();
    const identity = owner.shieldedAddress();
    const params = {
      client: {},
      ringProgramId: RING,
      wallet: new Wallet({ identity }),
      keys: { address: () => identity, viewingPublicKeys: () => [identity.viewingPublicKey] },
      feePayer: PAYER,
      mergeZeroKey: true,
      ownerSigner: OWNER,
    } as unknown as RingMergeTransactionParams;
    await expect(buildRingMergeTransaction(params)).rejects.toMatchObject({
      code: "RING_BUILD_MERGE",
      causeCode: "RING_MERGE_OWNER_MISMATCH",
    });
    owner.destroy();
  });
});
