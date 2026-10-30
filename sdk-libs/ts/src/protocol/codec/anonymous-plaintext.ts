/** Scheme 1 recipient and scheme 2 sender bundle plaintexts, the verified fields first, Rust `anonymous_plaintext`. */
import {
  addressBytes,
  decodeData,
  encodeBase58,
  encodeData,
  Reader,
  Writer,
} from "@heliuslabs/zolana/internal";
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";
import {
  ShieldedPublicKey,
  X25519PublicKey,
  type Bytes33,
  type Bytes34,
} from "@heliuslabs/zolana/keypair";
import {
  Data,
  SOL_MINT,
  TransactionError,
  transactOutputBlinding,
  Utxo,
  type AssetRegistry,
} from "@heliuslabs/zolana/transaction";

const OWNER_LEN = 34;
const MINT_LEN = 32;
const AMOUNT_LEN = 8;
const VIEWING_KEY_LEN = 33;
const BLINDING_LEN = 32;

/** A recipient plaintext with empty data, the length of every dummy body. */
export const RECIPIENT_BODY_LEN =
  OWNER_LEN + MINT_LEN + AMOUNT_LEN + VIEWING_KEY_LEN + BLINDING_LEN + 1;

export interface AnonymousRecipientPlaintext {
  readonly verified: VerifiedRecipientPlaintext;
  readonly unverified: UnverifiedRecipientPlaintext;
}

export interface VerifiedRecipientPlaintext {
  readonly ownerPublicKey: ShieldedPublicKey;
  readonly mint: Address;
  readonly amount: bigint;
}

export interface UnverifiedRecipientPlaintext {
  /** Unauthenticated, the recipient pairs with whichever key the sender writes. */
  readonly senderPublicKey: X25519PublicKey;
  readonly blinding: Bytes32;
  readonly data: Data;
}

/** Published as a message, its change outputs carry no ciphertext. */
export interface AnonymousSenderPlaintext {
  readonly verified: VerifiedSenderPlaintext;
  readonly unverified: UnverifiedSenderPlaintext;
}

export interface VerifiedSenderPlaintext {
  readonly ownerPublicKey: ShieldedPublicKey;
  /** The zero address if no SPL change. */
  readonly splMint: Address;
  readonly splAmount: bigint;
  readonly solAmount: bigint;
  /** One per recipient output, in output order. */
  readonly recipientViewingPublicKeys: readonly X25519PublicKey[];
}

export interface UnverifiedSenderPlaintext {
  readonly blindingSeed: Bytes32;
  readonly splData: Data;
  readonly solData: Data;
}

export function encodeAnonymousRecipient(value: AnonymousRecipientPlaintext): Uint8Array {
  const { verified, unverified } = value;
  return new Writer()
    .bytes(verified.ownerPublicKey.toBytes())
    .bytes(addressBytes(verified.mint, "mint"))
    .u64(verified.amount, "amount")
    .bytes(unverified.senderPublicKey.toBytes())
    .bytes(unverified.blinding, BLINDING_LEN, "blinding")
    .bytes(encodeData(unverified.data))
    .finish();
}

export function decodeAnonymousRecipient(bytes: Uint8Array): AnonymousRecipientPlaintext {
  const reader = new Reader(bytes);
  const result: AnonymousRecipientPlaintext = {
    verified: {
      ownerPublicKey: ownerKey(reader),
      mint: encodeBase58(reader.bytes(MINT_LEN, "mint")),
      amount: reader.u64("amount"),
    },
    unverified: {
      senderPublicKey: viewingKey(reader, "senderPublicKey"),
      blinding: reader.bytes(BLINDING_LEN, "blinding") as Bytes32,
      data: readData(reader, "data"),
    },
  };
  reader.done();
  return result;
}

/** A memo is the only record a recipient output carries. */
export function anonymousRecipientUtxo(
  value: AnonymousRecipientPlaintext,
  assets: AssetRegistry,
): Utxo {
  const { verified, unverified } = value;
  if (unverified.data.ringData() !== undefined || unverified.data.utxoData() !== undefined)
    throw new TransactionError("TRANSACTION_OUTPUT_DATA_MISMATCH", { field: "data" });
  return new Utxo({
    owner: verified.ownerPublicKey,
    asset: registeredMint(assets, verified.mint),
    amount: verified.amount,
    blinding: unverified.blinding,
    data: unverified.data,
  });
}

export function encodeAnonymousSender(value: AnonymousSenderPlaintext): Uint8Array {
  const { verified, unverified } = value;
  const writer = new Writer()
    .bytes(verified.ownerPublicKey.toBytes())
    .bytes(addressBytes(verified.splMint, "splMint"))
    .u64(verified.splAmount, "splAmount")
    .u64(verified.solAmount, "solAmount")
    .u8(verified.recipientViewingPublicKeys.length, "recipientViewingPublicKeys");
  for (const key of verified.recipientViewingPublicKeys) writer.bytes(key.toBytes());
  return writer
    .bytes(unverified.blindingSeed, BLINDING_LEN, "blindingSeed")
    .bytes(encodeData(unverified.splData))
    .bytes(encodeData(unverified.solData))
    .finish();
}

export function decodeAnonymousSender(bytes: Uint8Array): AnonymousSenderPlaintext {
  const reader = new Reader(bytes);
  const verified: VerifiedSenderPlaintext = {
    ownerPublicKey: ownerKey(reader),
    splMint: encodeBase58(reader.bytes(MINT_LEN, "splMint")),
    splAmount: reader.u64("splAmount"),
    solAmount: reader.u64("solAmount"),
    recipientViewingPublicKeys: Array.from(
      { length: reader.u8("recipientViewingPublicKeys") },
      () => viewingKey(reader, "recipientViewingPublicKeys"),
    ),
  };
  const result: AnonymousSenderPlaintext = {
    verified,
    unverified: {
      blindingSeed: reader.bytes(BLINDING_LEN, "blindingSeed") as Bytes32,
      splData: readData(reader, "splData"),
      solData: readData(reader, "solData"),
    },
  };
  reader.done();
  return result;
}

/** A zero amount marks a change output absent, the SOL change at slot 1 only after an SPL change. */
export function anonymousSenderUtxos(
  value: AnonymousSenderPlaintext,
  assets: AssetRegistry,
  firstNullifier: Bytes32,
): readonly Utxo[] {
  const { verified, unverified } = value;
  if (
    (verified.splAmount === 0n && !unverified.splData.isEmpty()) ||
    (verified.solAmount === 0n && !unverified.solData.isEmpty())
  )
    throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
  const spl =
    verified.splAmount > 0n
      ? [
          {
            asset: registeredMint(assets, verified.splMint),
            amount: verified.splAmount,
            data: unverified.splData,
          },
        ]
      : [];
  const sol =
    verified.solAmount > 0n
      ? [{ asset: SOL_MINT, amount: verified.solAmount, data: unverified.solData }]
      : [];
  return [...spl, ...sol].map(
    (change, slot) =>
      new Utxo({
        owner: verified.ownerPublicKey,
        asset: change.asset,
        amount: change.amount,
        blinding: transactOutputBlinding(firstNullifier, unverified.blindingSeed, slot),
        data: ringless(change.data),
      }),
  );
}

function ownerKey(reader: Reader): ShieldedPublicKey {
  return ShieldedPublicKey.fromBytes(reader.bytes(OWNER_LEN, "ownerPublicKey") as Bytes34);
}

function viewingKey(reader: Reader, name: string): X25519PublicKey {
  return X25519PublicKey.fromBytes(reader.bytes(VIEWING_KEY_LEN, name) as Bytes33);
}

/** One `Data` field in place, its records checked by `decodeData`. */
function readData(reader: Reader, name: string): Data {
  const count = reader.u8(name);
  const field = new Writer().u8(count, name);
  for (let index = 0; index < count; index += 1) {
    field.u8(reader.u8(name), name);
    const length = reader.u16(name);
    field.u16(length, name).bytes(reader.bytes(length, name));
  }
  return decodeData(field.finish());
}

function ringless(data: Data): Data {
  if (data.ringData() !== undefined)
    throw new TransactionError("TRANSACTION_MISSING_RING_PROGRAM_ID");
  return data;
}

/** A mint the registry does not bind is `TRANSACTION_UNKNOWN_MINT`. */
function registeredMint(assets: AssetRegistry, mint: Address): Address {
  assets.assetId(mint);
  return mint;
}
