import { address, getAddressEncoder, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";
import {
  ShieldedKeypair,
  ViewingKey,
  type Bytes16,
  type Bytes32,
  type Bytes96,
  Data,
  LocalShieldedKeys,
  SOL_MINT,
  Utxo,
  type ShieldedKeys,
} from "@heliuslabs/zolana";
import { DEFAULT_TREE_ID } from "@heliuslabs/zolana/interface";
import { AssetRegistry, EncryptedScheme } from "@heliuslabs/zolana/transaction";
import { encodeOutputData } from "@heliuslabs/zolana/internal";
import { encodeRingDepositCapsule } from "../../../src/protocol/codec/deposit-capsule.js";
import { encodeRingDepositPlaintext } from "../../../src/protocol/codec/ring-deposit-plaintext.js";
import { openRingNotes } from "../../../src/state/ring-sync.js";

const OWNER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const SIGNATURE = "1".repeat(64) as Signature;

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/** A holder that forwards to `keys`; tests override one method to misbehave. */
function remoteOver(keys: ShieldedKeys): ShieldedKeys {
  return {
    address: () => keys.address(),
    viewingPublicKeys: () => keys.viewingPublicKeys(),
    decrypt: (requests) => keys.decrypt(requests),
    derive: (requests) => keys.derive(requests),
    transactionKeys: (requests) => keys.transactionKeys(requests),
  };
}

function ringDepositBody(
  envelope: ViewingKey,
  salt: Bytes16,
  amount: bigint,
  ciphertext: Uint8Array,
): Uint8Array {
  const amountBytes = new Uint8Array(8);
  new DataView(amountBytes.buffer).setBigUint64(0, amount, true);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, ciphertext.length, true);
  return Uint8Array.from([
    ...bytes(1),
    ...getAddressEncoder().encode(SOL_MINT),
    ...amountBytes,
    0,
    ...getAddressEncoder().encode(OWNER),
    ...new Uint8Array(32),
    ...envelope.publicKey().toBytes(),
    ...salt,
    ...length,
    ...ciphertext,
  ]);
}

describe("audited ring deposit sync", () => {
  it.each([false, true])(
    "opens audited deposits through the ring capsule, malformed %s",
    async (malformed) => {
      const recipient = ShieldedKeypair.generate();
      const envelope = ViewingKey.generate();
      const salt = new Uint8Array(16).fill(6) as Bytes16;
      const blinding = bytes(30);
      const utxo = new Utxo({
        owner: recipient.signingPublicKey(),
        asset: SOL_MINT,
        amount: 2_000_000_000n,
        blinding,
        data: new Data([{ kind: "ringData", bytes: new Uint8Array() }]),
        ringProgramId: OWNER,
      });
      const capsule = encodeRingDepositCapsule({
        slotIndex: 3,
        ephemeralPublicKey: ViewingKey.generate().publicKey().toBytes(),
        ciphertext: new Uint8Array(96).fill(9) as Bytes96,
        recipientCiphertext: envelope.encryptRingDeposit(
          recipient.viewingPublicKey(),
          encodeRingDepositPlaintext({ blinding, ringData: new Uint8Array() }),
          salt,
        ),
      });
      const seen: Parameters<ShieldedKeys["decrypt"]>[0][] = [];
      const local = LocalShieldedKeys.fromKeypair(recipient);
      const holder: ShieldedKeys = {
        ...remoteOver(local),
        decrypt: (requests) => {
          seen.push(requests);
          return local.decrypt(requests);
        },
      };

      const notes = await openRingNotes({
        keys: holder,
        assets: new AssetRegistry(),
        transactions: [
          {
            slot: 3n,
            txSignature: SIGNATURE,
            outputSlots: [
              {
                viewTag: recipient.viewingPublicKey().x(),
                outputContext: {
                  hash: utxo.hash(recipient.nullifierPublicKey(), DEFAULT_TREE_ID),
                  tree: TREE,
                  treeId: DEFAULT_TREE_ID,
                  leafIndex: 9n,
                },
                payload: encodeOutputData(
                  EncryptedScheme.ringDeposit,
                  ringDepositBody(
                    envelope,
                    salt,
                    utxo.amount,
                    malformed ? capsule.slice(0, 12) : capsule,
                  ),
                  "encrypted",
                ),
              },
            ],
            messages: [],
            nullifiers: [],
            proofless: true,
          },
        ],
      });

      if (malformed) {
        expect(notes.utxos).toEqual([]);
        expect(seen).toEqual([]);
        return;
      }
      // The holder never sees the auditor slot, only the recipient ciphertext.
      expect(seen.flat().map((request) => request.ciphertext.length)).toEqual([
        capsule.length - 138,
      ]);
      expect(notes.utxos.map((entry) => entry.utxo)).toEqual([utxo]);
    },
  );
});
