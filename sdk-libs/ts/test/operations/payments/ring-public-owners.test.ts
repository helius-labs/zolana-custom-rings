import { address, type Address } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import { encodeBase58, ZERO_NULLIFIER_PK } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { ShieldedKeypair } from "@heliuslabs/spr/keypair";
import { AssetRegistry, ProofInputUtxo, SOL_MINT, Utxo } from "@heliuslabs/spr/transaction";
import type { WalletKeys } from "@heliuslabs/spr/client";

import type { AnonymousSpendSigner } from "../../../src/operations/payments/anonymous.js";
import {
  checkZeroKeyInputs,
  ringSpendTransfer,
} from "../../../src/operations/payments/ring-spend.js";
import {
  CustomRingTransfer,
  type PublicOwnerTransferClient,
} from "../../../src/operations/payments/transfer-rails.js";
import { PublicOwnerTransfer } from "../../../src/index.js";
import { RingTransactData } from "../../../src/protocol/transaction/transact.js";
import { ringFrame } from "../../helpers/ring-frame.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const PAYER = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");

function note(owner: ShieldedKeypair, nullifierPublicKey: Bytes32): ProofInputUtxo {
  return new ProofInputUtxo({
    utxo: new Utxo({
      owner: owner.shieldedAddress().signingPublicKey,
      asset: SOL_MINT,
      amount: 10n,
      blinding: new Uint8Array(32).fill(1) as Bytes32,
      ringProgramId: RING,
    }),
    nullifierPublicKey,
    nullifier: new Uint8Array(32).fill(2) as Bytes32,
    treeId: 0,
  });
}

function rail(owner: ShieldedKeypair): CustomRingTransfer {
  const sender = owner.shieldedAddress();
  return CustomRingTransfer.new({
    ringProgramId: RING,
    keys: { address: () => sender } as unknown as WalletKeys,
    transfer: ringSpendTransfer({
      owner: sender,
      inputs: [note(owner, sender.nullifierPublicKey)],
      feePayer: PAYER,
    }),
    assets: new AssetRegistry(),
  });
}

const walletOf = (owner: ShieldedKeypair): Address =>
  encodeBase58(owner.shieldedAddress().signingPublicKey.ed25519());
const noClient = {} as PublicOwnerTransferClient;

describe("public owner rail", () => {
  beforeAll(initializePoseidon);

  it("hands a wallet the rail the package entry exports", () => {
    const owner = ShieldedKeypair.generate();
    expect(rail(owner).spendPublic(walletOf(owner))).toBeInstanceOf(PublicOwnerTransfer);
  });

  it("refuses a named wallet other than the sender", async () => {
    const owner = ShieldedKeypair.generate();
    await expect(rail(owner).spendPublic(PAYER).prove(noClient)).rejects.toMatchObject({
      code: "RING_PUBLIC_SPEND_WALLET_MISMATCH",
    });
  });

  it("refuses an in-proof owner", async () => {
    const owner = ShieldedKeypair.generate();
    const transfer = rail(owner)
      .withInProofOwner({
        publicKey: () => owner.shieldedAddress().signingPublicKey,
        sign: () => Promise.reject(new Error("no signature before the refusal")),
      } satisfies AnonymousSpendSigner)
      .spendPublic(walletOf(owner));
    await expect(transfer.prove(noClient)).rejects.toMatchObject({
      code: "RING_PUBLIC_SPEND_IN_PROOF_OWNER",
    });
  });

  it("refuses an automatic spend of its owner's zero-key note, takes a nonzero one", () => {
    const owner = ShieldedKeypair.generate();
    const signing = owner.shieldedAddress().signingPublicKey;
    expect(() => checkZeroKeyInputs([note(owner, ZERO_NULLIFIER_PK)], signing)).toThrowError(
      expect.objectContaining({ code: "RING_ZERO_KEY_INPUT_UNNAMED" }),
    );
    expect(() =>
      checkZeroKeyInputs([note(owner, owner.shieldedAddress().nullifierPublicKey)], signing),
    ).not.toThrow();
  });

  it("settles a public owner frame on SPP's confidential rail beside its sender bundle", () => {
    const frame = ringFrame({ rail: "anonymous", inputs: 2, outputs: 2, publicOwners: true });
    const parsed = RingTransactData.parse(RingTransactData.encode(frame), "anonymous");
    expect(parsed.publicOwners).toBe(true);
    expect(parsed.sender).toBeDefined();
    expect(parsed.anonymous).toBeUndefined();
    expect(RingTransactData.circuit(parsed).kind).toBe("confidentialRingEddsa");
  });
});
