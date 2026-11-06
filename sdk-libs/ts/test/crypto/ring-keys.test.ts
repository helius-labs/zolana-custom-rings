import { address, getAddressDecoder } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";

import type { Bytes16, Bytes32 } from "@heliuslabs/spr/interface";
import {
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  ed25519DerivationMessage,
  isDerivationInput,
} from "@heliuslabs/spr/keypair";
import { LocalShieldedKeys } from "@heliuslabs/spr/transaction";

import { listSaltOf } from "../../src/crypto/keys/list-salt.js";
import { LocalRingKeys } from "../../src/state/ring-keys.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");

function seed(byte: number): Bytes32 {
  return new Uint8Array(32).fill(byte) as Bytes32;
}

describe("LocalShieldedKeys from a derivation seed", () => {
  it("derives the same keys from a wallet's derivation signature as from the secret", () => {
    const signing = SigningKey.fromEd25519Bytes(seed(7));
    const keypair = ShieldedKeypair.fromKeypair(signing);
    const solanaPublicKey = getAddressDecoder().decode(signing.publicKey().toBytes().subarray(1));
    const local = LocalShieldedKeys.fromKeypair(keypair);
    // The browser wallet output of signMessage(ed25519DerivationMessage(pk)).
    const derived = LocalShieldedKeys.fromDerivationSeed({
      solanaPublicKey,
      derivationSeed: signing.derivationSeed(),
    });
    expect(derived.address().ownerHash()).toEqual(local.address().ownerHash());
    expect(derived.address().viewingPublicKey.toBytes()).toEqual(
      local.address().viewingPublicKey.toBytes(),
    );
    const localViewing = local.viewingPublicKeys()[0]?.toBytes();
    expect(derived.viewingPublicKeys()[0]?.toBytes()).toEqual(localViewing);
    expect(
      isDerivationInput(
        ed25519DerivationMessage(signing.publicKey().toBytes().subarray(1) as Bytes32),
      ),
    ).toBe(true);
    // The hash-free path a page without Poseidon takes.
    expect(ViewingKey.fromDerivationSeed(signing.derivationSeed()).publicKey().toBytes()).toEqual(
      localViewing,
    );
    expect(derived.withNullifierKey((key) => key.publicKey())).toEqual(
      local.withNullifierKey((key) => key.publicKey()),
    );
  });
});

describe("LocalRingKeys.destroy", () => {
  beforeAll(initializePoseidon);

  it("derives the list salt while held and refuses every secret derivation after destroy", async () => {
    const keypair = ShieldedKeypair.generate();
    const keys = LocalRingKeys.fromKeypair(keypair);
    const viewingPublicKey = keypair.shieldedAddress().viewingPublicKey;
    try {
      const salt = await keys.listSalt(RING);
      keys.destroy();
      const destroyed = { code: "KEYPAIR_INVALID_SECRET_KEY", details: { reason: "destroyed" } };
      const delivery = {
        viewingPublicKey,
        txViewingPublicKey: viewingPublicKey,
        salt: new Uint8Array(16) as Bytes16,
        outputIndex: 0,
        firstNullifier: seed(0),
      };
      for (const call of [
        () => keys.listSalt(RING),
        () => keys.mergeSeeds([]),
        () => keys.viewTags([]),
        () => keys.ringDeliverySecrets([]),
        () => keys.ringTagMatches([]),
        () => keys.decrypt([]),
        () => keys.derive([]),
        () => keys.transactionKeys([]),
      ])
        await expect(call()).rejects.toMatchObject(destroyed);
      expect(() => keys.ringDeliverySecret(delivery)).toThrow(expect.objectContaining(destroyed));
      // The caller's keypair keeps its own copy.
      const identity = keypair.viewingKey();
      expect(listSaltOf(identity, RING)).toEqual(salt);
      identity.destroy();
    } finally {
      keypair.destroy();
    }
  });
});
