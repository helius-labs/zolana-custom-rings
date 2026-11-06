import { getAddressEncoder, type Address } from "@solana/kit";

import { hashBytes, rightAlign, checkedBytes } from "@heliuslabs/spr/internal";
import type { Bytes16, Bytes32 } from "@heliuslabs/spr/keypair";
import type { ViewingKey, X25519PublicKey } from "@heliuslabs/spr/keypair";
import { packBytesBe } from "./hasher.js";

import { u32Field } from "../error.js";
import { RingDomain, domainHash } from "./ring-domain.js";

const addressEncoder = getAddressEncoder();

export type DeliveredSlot = Readonly<{
  /** `X25519(tx_sk, u)`. */
  agreement: Bytes32;
  txViewingKey: X25519PublicKey;
  recipientViewingKey: X25519PublicKey;
  salt: Bytes16;
  outputIndex: number;
  firstNullifier: Bytes32;
}>;

/** `Poseidon(CRDS, pack_be(dh), pack_be(tx_viewing_pk), pack_be(recipient_viewing_pk), salt, i, n0)`, rebuilt by the recipient from `X25519(u_sk, tx_u)`. */
export function deliveredSlotSecret(slot: DeliveredSlot): Bytes32 {
  const keys = [
    ...packBytesBe(slot.txViewingKey.toBytes()),
    ...packBytesBe(slot.recipientViewingKey.toBytes()),
  ];
  const tail = slotTail(slot);
  return domainHash(RingDomain.deliveredSlotSecret, [
    ...packedSecret(slot.agreement, "agreement"),
    ...keys,
    ...tail,
  ]);
}

/** The sealer's and the sent row reader's view of the secret, the agreement wiped once hashed. */
export function txKeySlotSecret(
  input: Readonly<{
    txViewingKey: ViewingKey;
    recipientViewingKey: X25519PublicKey;
    salt: Bytes16;
    outputIndex: number;
    firstNullifier: Bytes32;
  }>,
): Bytes32 {
  const agreement = input.txViewingKey.ecdh(input.recipientViewingKey);
  try {
    return deliveredSlotSecret({
      agreement,
      txViewingKey: input.txViewingKey.publicKey(),
      recipientViewingKey: input.recipientViewingKey,
      salt: input.salt,
      outputIndex: input.outputIndex,
      firstNullifier: input.firstNullifier,
    });
  } finally {
    agreement.fill(0);
  }
}

/** The bytes of a ring slot tag a frame carries, a false match costs one trial open. */
export const SLOT_TAG_LEN = 8;

/** Leading bytes stay zero and off the frame. */
export function slotTag(tag: Bytes32): Bytes32 {
  return unframedSlotTag(framedSlotTag(tag));
}

export function framedSlotTag(tag: Bytes32): Uint8Array {
  return tag.slice(32 - SLOT_TAG_LEN);
}

export function unframedSlotTag(framed: Uint8Array): Bytes32 {
  const tag = new Uint8Array(32);
  tag.set(framed, 32 - SLOT_TAG_LEN);
  return tag as Bytes32;
}

/**
 * A confidential output's tag, stable per recipient key, since the confidential rail hides
 * amounts and leaves the recipient linkable to anyone who holds its address.
 */
export function confidentialSlotTag(viewingU: Bytes32): Bytes32 {
  return slotTag(viewingU);
}

/**
 * An anonymous payment's tag, fresh per transaction and slot, since a tag stable per recipient
 * would link every payment to one recipient in public.
 */
export function anonymousSlotTag(slotSecret: Bytes32): Bytes32 {
  return slotTag(recipientTag(slotSecret));
}

/** `Poseidon(CRRT, slot_secret)`, published for a live recipient and proven against its body's secret. */
export function recipientTag(slotSecret: Bytes32): Bytes32 {
  return domainHash(RingDomain.recipientTagDomain, [
    checkedBytes<Bytes32>(slotSecret, 32, "slot secret"),
  ]);
}

/** `Poseidon(CRST, slot_secret)` at index `m`, the domain keeps it apart from every recipient tag. */
export function bundleTag(slotSecret: Bytes32): Bytes32 {
  return domainHash(RingDomain.senderTagDomain, [
    checkedBytes<Bytes32>(slotSecret, 32, "slot secret"),
  ]);
}

/** Rust `ring_id_field`, `hash_bytes` of the ring program address. */
export function ringIdField(ring: Address): Bytes32 {
  return hashBytes(new Uint8Array(addressEncoder.encode(ring))) as Bytes32;
}

/** Packs a validated copy, the copy wiped once packed. */
export function packedSecret(secret: Bytes32, name: string): Uint8Array[] {
  const copy = checkedBytes<Bytes32>(secret, 32, name);
  try {
    return packBytesBe(copy);
  } finally {
    copy.fill(0);
  }
}

/** `salt, i, n0`, validated before any secret is copied. */
function slotTail(
  slot: Readonly<{ salt: Bytes16; outputIndex: number; firstNullifier: Bytes32 }>,
): Bytes32[] {
  return [
    rightAlign(checkedBytes<Bytes16>(slot.salt, 16, "salt")),
    u32Field(slot.outputIndex, "outputIndex"),
    checkedBytes<Bytes32>(slot.firstNullifier, 32, "first nullifier"),
  ];
}
