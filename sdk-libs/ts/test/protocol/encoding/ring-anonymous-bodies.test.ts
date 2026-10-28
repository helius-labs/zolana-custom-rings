import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import vectors from "../../../../../test-vectors/wallet/anonymous-bodies.json" with { type: "json" };
import { initializePoseidon } from "@heliuslabs/zolana";
import { encodeBase58 } from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes32, Bytes34 } from "@heliuslabs/zolana/keypair";
import {
  ShieldedAddress,
  ShieldedPublicKey,
  ViewingKey,
  X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import { AssetRegistry, Data } from "@heliuslabs/zolana/transaction";

import {
  DUMMY_RECIPIENT_VIEWING_PK,
  RECIPIENT_BODY_LEN,
  listedRecipients,
  openRecipient,
  rebuilds,
  senderChange,
  type AnonymousOutput,
} from "../../../src/protocol/codec/anonymous-body.js";
import {
  decodeAnonymousRecipient,
  decodeAnonymousSender,
} from "../../../src/protocol/codec/anonymous-plaintext.js";
import { OutputBlindings, ringBlindingSeed } from "../../../src/crypto/derivation/blinding.js";

await initializePoseidon();

type Party = (typeof vectors)["sender"];

function bytes<T extends Uint8Array>(value: string): T {
  return Uint8Array.from(Buffer.from(value, "hex")) as T;
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

const salt = bytes<Bytes16>(vectors.salt);
const firstNullifier = bytes<Bytes32>(vectors.first_nullifier);
const ring = encodeBase58(bytes(vectors.ring_program_id));
const assets = new AssetRegistry(
  vectors.mints.map((mint) => [BigInt(mint.asset_id), encodeBase58(bytes(mint.asset))] as const),
);
const parties = [vectors.sender, ...vectors.recipients].map((party: Party) => ({
  viewing: ViewingKey.fromBytes(bytes<Bytes32>(party.viewing_secret)),
  address: ShieldedAddress.fromPublicKeys(
    ShieldedPublicKey.fromBytes(bytes<Bytes34>(party.owner_pubkey)),
    bytes<Bytes32>(party.nullifier_pubkey),
    X25519PublicKey.fromBytes(bytes(party.viewing_pubkey)),
  ),
}));
const [sender] = parties;
if (sender === undefined) throw new Error("vector without a sender");
const txViewingKey = sender.viewing.transactionViewingKey(firstNullifier);

function outputOf(owner: ShieldedAddress, utxoHash: string): AnonymousOutput {
  return { owner, assets, ring, treeId: vectors.tree_id, utxoHash: bytes<Bytes32>(utxoHash) };
}

function mintOf(asset: string): string {
  return asset === "00".repeat(32) ? encodeBase58(new Uint8Array(32)) : encodeBase58(bytes(asset));
}

describe("anonymous-bodies.json", () => {
  it("derives the transaction key and every blinding from the sender's viewing key", () => {
    for (const party of parties)
      expect(party.viewing.publicKey().equals(party.address.viewingPublicKey)).toBe(true);
    expect(hex(txViewingKey.publicKey().toBytes())).toBe(vectors.tx_viewing_pk);
    const secret = txViewingKey.secretBytes();
    expect(hex(ringBlindingSeed(secret, salt))).toBe(vectors.blinding_seed);
    secret.fill(0);
  });

  it("opens every recipient body its reader reads and rebuilds the published hash", () => {
    for (const output of vectors.outputs) {
      const { opened } = output;
      if (output.ciphertext === null) {
        expect([output.position, opened]).toEqual([0, null]);
        continue;
      }
      const ciphertext = bytes(output.ciphertext);
      if (opened === null) {
        expect([ciphertext.length, output.tag.slice(0, 2)]).toEqual([RECIPIENT_BODY_LEN, "00"]);
        continue;
      }
      const reader = parties.find(
        (party) => hex(party.address.viewingPublicKey.toBytes()) === opened.sealed_to,
      );
      if (reader === undefined) throw new Error("no reader");
      const plaintext = reader.viewing.decryptUtxo(
        ciphertext,
        txViewingKey.publicKey(),
        salt,
        output.position,
      );
      expect(hex(plaintext)).toBe(opened.plaintext);
      // The sender reads its own payment back with the transaction key.
      const sent = txViewingKey.decryptSlotEphemeral(
        reader.address.viewingPublicKey,
        ciphertext,
        salt,
        output.position,
      );
      expect(hex(sent)).toBe(opened.plaintext);
      // The rail seals the same bytes at the same position.
      expect(
        hex(
          txViewingKey.encryptSlot(
            reader.address.viewingPublicKey,
            plaintext,
            salt,
            output.position,
          ),
        ),
      ).toBe(output.ciphertext);
      const note = decodeAnonymousRecipient(plaintext);
      expect(note.unverified.senderPublicKey.equals(sender.address.viewingPublicKey)).toBe(true);
      const utxo = openRecipient(outputOf(reader.address, output.utxo_hash), note);
      expect(utxo?.amount).toBe(BigInt(opened.amount));
      expect(hex(utxo?.blinding ?? new Uint8Array())).toBe(opened.blinding);
      expect(utxo?.asset).toBe(mintOf(opened.mint.asset));
      expect(opened.rebuilt_hash).toBe(output.utxo_hash);
    }
  });

  it("opens the sender bundle after the outputs and rebuilds each change output", () => {
    const bundle = vectors.sender_bundle;
    expect(bundle.slot_index).toBe(vectors.outputs.length);
    expect(bundle.tag).toBe(vectors.outputs[0]?.tag);
    const plaintext = sender.viewing.decryptUtxo(
      bytes(bundle.ciphertext),
      txViewingKey.publicKey(),
      salt,
      bundle.slot_index,
    );
    expect(hex(plaintext)).toBe(bundle.plaintext);
    const opened = decodeAnonymousSender(plaintext);
    const blindings = new OutputBlindings(firstNullifier, bytes<Bytes32>(vectors.blinding_seed));
    expect(hex(opened.unverified.blindingSeed)).toBe(hex(blindings.outputSeed()));
    expect(hex(opened.unverified.blindingSeed)).toBe(bundle.output_seed);
    expect(opened.verified.recipientViewingPublicKeys.map((key) => hex(key.toBytes()))).toEqual(
      bundle.recipient_viewing_pks,
    );
    expect(bundle.recipient_viewing_pks).toEqual([
      ...vectors.recipients.map((party) => party.viewing_pubkey),
      hex(DUMMY_RECIPIENT_VIEWING_PK.toBytes()),
    ]);
    expect(listedRecipients(opened).map((key) => hex(key.toBytes()))).toEqual(
      vectors.recipients.map((party) => party.viewing_pubkey),
    );
    const change = senderChange({ assets, ring }, opened, firstNullifier);
    expect(change).toHaveLength(bundle.change.length);
    change.forEach((utxo, index) => {
      const expected = bundle.change[index];
      const published = vectors.outputs[expected?.position ?? -1];
      if (expected === undefined || published === undefined) throw new Error("no change output");
      expect([utxo.amount, utxo.asset, utxo.ringProgramId]).toEqual([
        BigInt(expected.amount),
        mintOf(expected.mint.asset),
        ring,
      ]);
      expect(hex(utxo.blinding)).toBe(expected.blinding);
      expect(hex(utxo.blinding)).toBe(hex(blindings.at(expected.position)));
      expect(rebuilds(outputOf(sender.address, published.utxo_hash), utxo)).toBe(true);
      expect(expected.rebuilt_hash).toBe(published.utxo_hash);
    });
    blindings.destroy();
  });

  it("opens an SPL-only change as one note at blinding slot 0, like Rust `into_utxos`", () => {
    const opened = decodeAnonymousSender(
      sender.viewing.decryptUtxo(
        bytes(vectors.sender_bundle.ciphertext),
        txViewingKey.publicKey(),
        salt,
        vectors.sender_bundle.slot_index,
      ),
    );
    const spl = vectors.mints.find((mint) => mint.asset !== "00".repeat(32));
    if (spl === undefined) throw new Error("vector without an SPL mint");
    const change = senderChange(
      { assets, ring },
      {
        ...opened,
        verified: {
          ...opened.verified,
          splMint: address(mintOf(spl.asset)),
          splAmount: 6n,
          solAmount: 0n,
        },
      },
      firstNullifier,
    );
    const blindings = new OutputBlindings(firstNullifier, bytes<Bytes32>(vectors.blinding_seed));
    expect(change.map((utxo) => [utxo.asset, utxo.amount, hex(utxo.blinding)])).toEqual([
      [mintOf(spl.asset), 6n, hex(blindings.at(0))],
    ]);
    blindings.destroy();
  });

  it("rebuilds nothing for another reader, another hash or a body that carries ring data", () => {
    const [, bob, carol] = parties;
    const output = vectors.outputs[1];
    if (bob === undefined || carol === undefined || output?.opened == null)
      throw new Error("no payment");
    const note = decodeAnonymousRecipient(bytes(output.opened.plaintext));
    expect(openRecipient(outputOf(carol.address, output.utxo_hash), note)).toBeUndefined();
    expect(openRecipient(outputOf(bob.address, "11".repeat(32)), note)).toBeUndefined();
    const withData = {
      ...note,
      unverified: {
        ...note.unverified,
        data: new Data([{ kind: "ringData", bytes: Uint8Array.of(1) }]),
      },
    };
    expect(() => openRecipient(outputOf(bob.address, output.utxo_hash), withData)).toThrow();
  });
});
