import { getAddressEncoder, type Address } from "@solana/kit";

import { hashBytes, rightAlign, checkedBytes } from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes32 } from "@heliuslabs/zolana/keypair";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
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

/** Rust `ring_id_field`, `hash_bytes` of the ring program address. */
export function ringIdField(ring: Address): Bytes32 {
  return hashBytes(new Uint8Array(addressEncoder.encode(ring))) as Bytes32;
}

/** `Poseidon(CRSC, sender_pk_hash, private_tx_blinding)`, binding the audit and policy proofs to one hidden sender. */
export function senderCommitment(
  sender: Readonly<{ senderPkHash: Bytes32; privateTxBlinding: Bytes32 }>,
): Bytes32 {
  return domainHash(RingDomain.senderCommitment, [
    checkedBytes<Bytes32>(sender.senderPkHash, 32, "sender pk hash"),
    checkedBytes<Bytes32>(sender.privateTxBlinding, 32, "private tx blinding"),
  ]);
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
