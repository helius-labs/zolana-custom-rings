import { beforeAll, describe, expect, it } from "vitest";

import { readFileSync } from "node:fs";

import { initializePoseidon } from "@heliuslabs/spr";
import { ZERO_NULLIFIER_PK } from "@heliuslabs/spr/internal";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import { ShieldedAddress, ShieldedKeypair, SigningKey } from "@heliuslabs/spr/keypair";
import { SOL_MINT, Wallet, type WalletUtxo } from "@heliuslabs/spr/transaction";
import { getBase58Decoder, type Address } from "@solana/kit";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";

import { LocalRingKeys } from "../../src/state/ring-keys.js";
import { LIST_SALT_LABEL, listSaltOf, listTagOf } from "../../src/crypto/keys/list-salt.js";
import { RingAddress } from "../../src/crypto/keys/ring-address.js";
import { selectRingInputs } from "../../src/operations/payments/transfer.js";
import { AnonymousWallet } from "../../src/state/anonymous-wallet.js";
import { isZeroKeyNote, mintBalances, noteState } from "../../src/state/exposed-notes.js";
import { ViewingHistory } from "../../src/state/viewing-history.js";
import { ASSETS, RING, ScanIndexer, ScanWallet } from "../helpers/ring-scan.js";

beforeAll(initializePoseidon);

function zeroKeyed(owner: ScanWallet): ShieldedAddress {
  return ShieldedAddress.fromPublicKeys(
    owner.address.signingPublicKey,
    ZERO_NULLIFIER_PK as Bytes32,
    owner.viewingKey,
  );
}

/** A wallet holding a keyed note of `keyed` and a zero-key note of a nonzero `zero`. */
async function holding(keyed: bigint, zero: bigint) {
  const indexer = new ScanIndexer();
  const alice = new ScanWallet(1);
  const bob = new ScanWallet(2);
  const history = ViewingHistory.create(bob.viewingKey, 0n).withRing(RING);
  const wallet = AnonymousWallet.create(
    new Wallet({ identity: bob.address, registry: ASSETS }),
    history,
  );
  await alice.pay(indexer, [{ to: bob.address, amount: keyed }]);
  if (zero > 0n) await alice.pay(indexer, [{ to: zeroKeyed(bob), amount: zero }]);
  await wallet.absorb(await bob.sync(indexer, wallet.history()));
  return { wallet, bob };
}

const select = (wallet: Wallet, amount: bigint) =>
  selectRingInputs({
    wallet,
    ringProgramId: RING,
    asset: SOL_MINT,
    amount,
    inputs: "ring",
    maxInputs: 8,
  });

describe("exposed notes", () => {
  it("reports a zero-key note apart from the spendable balance", async () => {
    const { wallet } = await holding(40n, 25n);
    const [keyed, zero] = wallet.notes();
    if (keyed === undefined || zero === undefined) throw new Error("two notes");
    expect(isZeroKeyNote(keyed)).toBe(false);
    expect(isZeroKeyNote(zero)).toBe(true);
    expect(wallet.noteState(keyed)).toBe("spendable");
    expect(wallet.noteState(zero)).toBe("exposedIfSpent");
    expect(wallet.exposedNotes()).toEqual([zero]);
    expect(wallet.balances().get(SOL_MINT)).toEqual({ spendable: 40n, exposedIfSpent: 25n });
  });

  it("lets spent take precedence, a spent zero-key note leaves the list", async () => {
    const { wallet } = await holding(40n, 25n);
    const [keyed, zero] = wallet.notes();
    if (keyed === undefined || zero === undefined) throw new Error("two notes");
    const spent: WalletUtxo = { ...zero, spent: true };
    expect(noteState(spent)).toBe("spent");
    expect(mintBalances([keyed, spent]).get(SOL_MINT)).toEqual({
      spendable: 40n,
      exposedIfSpent: 0n,
    });
  });

  it("never selects one automatically and names the exposure on a shortfall", async () => {
    const { wallet } = await holding(40n, 25n);
    expect(select(wallet.wallet, 30n).map((note) => note.utxo.amount)).toEqual([40n]);
    expect(() => select(wallet.wallet, 50n)).toThrow(
      expect.objectContaining({
        code: "RING_UNFUNDED_PAST_EXPOSURE",
        details: { asset: SOL_MINT, requested: "50", exposedIfSpent: "25" },
      }),
    );
  });

  it("reports the plain shortfall on a wallet with no exposed funds", async () => {
    const { wallet } = await holding(40n, 0n);
    expect(() => select(wallet.wallet, 500n)).toThrow(
      expect.objectContaining({ code: "RING_INSUFFICIENT_BALANCE" }),
    );
  });
});

describe("list_salt.json", () => {
  const vector = JSON.parse(
    readFileSync(
      new URL("../../../../test-vectors/registry/list_salt.json", import.meta.url),
      "utf8",
    ),
  ) as Record<string, string>;

  it("derives the list salt and tag of the wallet's one secret from the shared vector", async () => {
    const holder = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(hexToBytes(vector["signing_secret"] ?? "") as Bytes32),
    );
    const program = getBase58Decoder().decode(
      hexToBytes(vector["ring_program_id"] ?? ""),
    ) as Address;
    const salt = listSaltOf(holder.viewingKey(), program);
    expect(bytesToHex(salt)).toBe(vector["list_salt"]);
    expect(bytesToHex(listTagOf(salt))).toBe(vector["list_tag"]);
    const addressed = await RingAddress.enrolled(holder, program, salt);
    expect(addressed.recipient.toBytes()).toEqual(holder.shieldedAddress().toBytes());
    expect(addressed.listSalt).toEqual(salt);
    const other = getBase58Decoder().decode(new Uint8Array(32).fill(5)) as Address;
    expect(listSaltOf(holder.viewingKey(), other)).not.toEqual(salt);
    await expect(LocalRingKeys.fromKeypair(holder).listSalt(program)).resolves.toEqual(salt);
    await expect(
      LocalRingKeys.fromKeypair(holder).mergeSeeds([
        {
          viewingPublicKey: holder.viewingPublicKey(),
          ringProgramId: program,
          firstNullifier: LIST_SALT_LABEL,
        },
      ]),
    ).rejects.toMatchObject({ code: "KEYPAIR_INVALID_MERGE_SEED" });
  });
});
