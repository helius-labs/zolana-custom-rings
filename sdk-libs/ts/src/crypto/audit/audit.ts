import { ctr } from "@noble/ciphers/aes.js";

import { checkedBytes, concatBytes, copyBytes, u32be } from "@heliuslabs/spr/internal";
import type { MessageData } from "@heliuslabs/spr/interface";
import {
  type Bytes16,
  type Bytes32,
  poseidon,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/spr/keypair";
import {
  DISCLOSURE_CHUNK_BYTES,
  ENVELOPE_KEY_LEN,
  STREAM_FIRST_COUNTER,
  TAGGED_KEY_LEN,
  OUTPUT_RECORD_LEN,
  RECIPIENT_KEY_LEN,
  auditorMessageLen,
  envelopeRegion,
  recipientKeysLen,
  type AuditStreamLayout,
} from "../../protocol/codec/ring-disclosure-layout.js";
import { packBytesBe } from "../derivation/hasher.js";

import { RingKeyError } from "../error.js";

/** Schedule labels, one secret under two labels gives two unrelated keys. */
export const AUDIT_ENC_INFO = new TextEncoder().encode("CRING/adt");
export const NF_KEY_ENC_INFO = new TextEncoder().encode("CRING/nfk");
/** One slot's record then its payload, the recipient and the auditor open it under `CRDS_i`. */
export const OUTPUT_RECORD_ENC_INFO = new TextEncoder().encode("CRING/rcp");
export const REPLY_ENC_INFO = new TextEncoder().encode("CRING/rpl");
export const SENDER_BUNDLE_ENC_INFO = new TextEncoder().encode("CRING/snd");
/** The merge envelope to the auditor. */
export const MERGE_RECORD_ENC_INFO = new TextEncoder().encode("CRING/mrg");
/** Rust `MERGE_OUTPUT_LABEL`, the merge record to its owner. */
export const MERGE_OUTPUT_ENC_INFO = new TextEncoder().encode("CRING/mro");

/** `"CR_S"`, Rust `AUDIT_SHARED_SECRET`. */
const DOM_SEP_CR_SHARED = 0x4352_5f53;
const STREAM_LABEL_BYTES = 9;
const U32_MAX = 0xffff_ffff;

export interface StreamPosition {
  readonly label: Uint8Array;
  /** The first block's counter, a counter that serves two plaintexts reveals their XOR. */
  readonly counter: number;
}

export interface AuditorRegion {
  readonly counter: number;
  readonly bytes: Uint8Array;
}

export interface AuditorEnvelope {
  readonly ephemeralSecret: Bytes32;
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly envelope: Uint8Array;
  /** One sealed `V_i` per published slot. */
  readonly recipientKeys: readonly Uint8Array[];
}

/** The one message a ring transfer publishes under the auditor's view tag. */
export interface AuditorMessage {
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly envelope: Uint8Array;
  /** One sealed `V_i` per published slot. */
  readonly recipientKeys: readonly Uint8Array[];
  /** Each exit's record in slot order, an exit's SPP data holds its owner's scheme 3 body. */
  readonly exitRecords: readonly Uint8Array[];
}

/** One label and secret fix one schedule, each region applies it at its own counter. */
export class AuditSchedule {
  readonly #key: Uint8Array;
  readonly #nonce: Uint8Array;

  private constructor(key: Uint8Array, nonce: Uint8Array) {
    this.#key = key;
    this.#nonce = nonce;
  }

  /** Two Poseidon outputs supply 31 key bytes, then one key byte and a 12-byte nonce. */
  static derive(secret: Bytes32, label: Uint8Array): AuditSchedule {
    checkLabel(label);
    const tag = new Uint8Array(STREAM_LABEL_BYTES + 1);
    tag.set(label);
    let head: Uint8Array | undefined;
    let tail: Uint8Array | undefined;
    try {
      head = poseidon([rightAlign(tag), secret]);
      tag[STREAM_LABEL_BYTES] = 1;
      tail = poseidon([rightAlign(tag), secret]);
      const key = new Uint8Array(32);
      key.set(head.subarray(1), 0);
      key[31] = tail[19] ?? 0;
      return new AuditSchedule(key, tail.slice(20));
    } finally {
      tag.fill(0);
      head?.fill(0);
      tail?.fill(0);
    }
  }

  apply(firstCounter: number, data: Uint8Array): Uint8Array {
    checkCounter(firstCounter);
    const counter = new Uint8Array(16);
    try {
      counter.set(this.#nonce, 0);
      counter.set(u32be(firstCounter), 12);
      return ctr(this.#key, counter).encrypt(copyBytes(data));
    } finally {
      counter.fill(0);
    }
  }

  destroy(): void {
    this.#key.fill(0);
    this.#nonce.fill(0);
  }
}

export function symmetricAuditApply(
  secret: Bytes32,
  position: StreamPosition,
  data: Uint8Array,
): Uint8Array {
  checkLabel(position.label);
  checkCounter(position.counter);
  const schedule = AuditSchedule.derive(secret, position.label);
  try {
    return schedule.apply(position.counter, data);
  } finally {
    schedule.destroy();
  }
}

/** Binds the ECDH x-coordinate to both public keys, one shared point serves one key pair. */
export function auditSharedSecret(
  dh: Bytes32,
  ephemeralPublicKey: X25519PublicKey,
  auditorPublicKey: X25519PublicKey,
): Bytes32 {
  const packedDh = packBytesBe(checkedBytes<Bytes32>(dh, 32, "shared secret"));
  try {
    return poseidon([
      rightAlign(u32be(DOM_SEP_CR_SHARED)),
      ...packedDh,
      ...packBytesBe(ephemeralPublicKey.toBytes()),
      ...packBytesBe(auditorPublicKey.toBytes()),
    ]) as Bytes32;
  } finally {
    for (const field of packedDh) field.fill(0);
  }
}

/** A resend repeats the transfer's key, the salt keeps its keystream apart. */
export function sealSaltedAuditorStream(
  input: Readonly<{
    txViewingSecret: Bytes32;
    salt: Bytes16;
    auditorPublicKey: X25519PublicKey;
    envelope: Uint8Array;
    recipientKeys: readonly AuditorRegion[];
  }>,
): AuditorEnvelope {
  const key = X25519Keypair.fromBytes(input.txViewingSecret);
  try {
    return sealRegions(key, input, (shared) => saltedSecret(shared, input.salt));
  } finally {
    key.destroy();
  }
}

function sealRegions(
  key: X25519Keypair,
  input: Readonly<{
    auditorPublicKey: X25519PublicKey;
    envelope: Uint8Array;
    recipientKeys: readonly AuditorRegion[];
  }>,
  keyed: (shared: Bytes32) => Bytes32,
): AuditorEnvelope {
  const { auditorPublicKey } = input;
  const publicKey = key.publicKey();
  const secret = envelopeSecret(key, auditorPublicKey, publicKey, auditorPublicKey);
  let schedule: AuditSchedule | undefined;
  try {
    const stream = (schedule = AuditSchedule.derive(keyed(secret), AUDIT_ENC_INFO));
    const envelope = stream.apply(STREAM_FIRST_COUNTER, input.envelope);
    const recipientKeys = Object.freeze(
      input.recipientKeys.map(({ counter, bytes }) => stream.apply(counter, bytes)),
    );
    return Object.freeze({
      ephemeralSecret: key.secretBytes(),
      ephemeralPublicKey: publicKey,
      envelope,
      recipientKeys,
    });
  } finally {
    secret.fill(0);
    schedule?.destroy();
  }
}

/** Rust `salted`. */
function saltedSecret(secret: Bytes32, salt: Bytes16): Bytes32 {
  const aligned = rightAlign(checkedBytes<Bytes16>(salt, 16, "salt"));
  return poseidon([secret, aligned]) as Bytes32;
}

/** The schedule `sealSaltedAuditorStream` encrypted under, the caller destroys it. */
export function saltedAuditorSchedule(
  auditor: X25519Keypair,
  txViewingPublicKey: X25519PublicKey,
  salt: Bytes16,
): AuditSchedule {
  const shared = envelopeSecret(
    auditor,
    txViewingPublicKey,
    txViewingPublicKey,
    auditor.publicKey(),
  );
  const salted = saltedSecret(shared, salt);
  try {
    return AuditSchedule.derive(salted, AUDIT_ENC_INFO);
  } finally {
    shared.fill(0);
    salted.fill(0);
  }
}

/** The caller destroys the schedule. */
export function sealedAuditorSchedule(
  txViewingSecret: Bytes32,
  auditorPublicKey: X25519PublicKey,
  salt: Bytes16,
): AuditSchedule {
  const key = X25519Keypair.fromBytes(txViewingSecret);
  const shared = envelopeSecret(key, auditorPublicKey, key.publicKey(), auditorPublicKey);
  const salted = saltedSecret(shared, salt);
  try {
    return AuditSchedule.derive(salted, AUDIT_ENC_INFO);
  } finally {
    shared.fill(0);
    salted.fill(0);
    key.destroy();
  }
}

/** The envelope's leading bytes, the evidence behind them opens with the transfer's layout. */
export function openTransactionViewingSecret(
  auditor: X25519Keypair,
  message: Pick<AuditorMessage, "ephemeralPublicKey" | "envelope">,
  salt: Bytes16,
): Bytes32 {
  const bytes = message.envelope.subarray(0, ENVELOPE_KEY_LEN);
  if (bytes.length !== ENVELOPE_KEY_LEN)
    throw new RingKeyError("KEYPAIR_DISCLOSURE_SHAPE", { name: "envelope" });
  const schedule = saltedAuditorSchedule(auditor, message.ephemeralPublicKey, salt);
  try {
    return schedule.apply(STREAM_FIRST_COUNTER, bytes) as Bytes32;
  } finally {
    schedule.destroy();
  }
}

export function auditorViewTag(auditorPublicKey: X25519PublicKey): Bytes32 {
  return auditorPublicKey.u();
}

/** `0x04 ‖ eph_u ‖ envelope_ct ‖ keys_ct ‖ exit record_ct...` under the auditor's view tag. */
export function auditorMessageData(
  message: AuditorMessage,
  auditorPublicKey: X25519PublicKey,
): MessageData {
  return Object.freeze({
    viewTag: auditorViewTag(auditorPublicKey),
    data: concatBytes(
      message.ephemeralPublicKey.toBytes(),
      message.envelope,
      ...message.recipientKeys,
      ...message.exitRecords,
    ),
  });
}

/** The layout and the frame's exit count fix every length, a message of any other length is refused. */
export function parseAuditorMessage(
  data: Uint8Array,
  layout: AuditStreamLayout,
  exits: number,
): AuditorMessage {
  const bytes = checkedBytes(data, auditorMessageLen(layout, exits), "auditor message");
  const keysAt = TAGGED_KEY_LEN + envelopeRegion(layout).length;
  const recordsAt = keysAt + recipientKeysLen(layout);
  const cut = (at: number, length: number, count: number): readonly Uint8Array[] =>
    Object.freeze(
      Array.from({ length: count }, (_, slot) =>
        bytes.subarray(at + slot * length, at + (slot + 1) * length),
      ),
    );
  return Object.freeze({
    ephemeralPublicKey: X25519PublicKey.fromBytes(bytes.subarray(0, TAGGED_KEY_LEN)),
    envelope: bytes.subarray(TAGGED_KEY_LEN, keysAt),
    recipientKeys: cut(keysAt, RECIPIENT_KEY_LEN, layout.outputs),
    exitRecords: cut(recordsAt, OUTPUT_RECORD_LEN, exits),
  });
}

/** Rust `pack_disclosure`, a short last chunk is zero padded at its end. */
export function packDisclosure(plaintext: Uint8Array): readonly Bytes32[] {
  return Array.from(
    { length: Math.ceil(plaintext.length / DISCLOSURE_CHUNK_BYTES) },
    (_, index) => {
      const field = new Uint8Array(32);
      const start = index * DISCLOSURE_CHUNK_BYTES;
      field.set(plaintext.subarray(start, start + DISCLOSURE_CHUNK_BYTES), 1);
      return field as Bytes32;
    },
  );
}

/** Rust `unpack_disclosure`, a field with bytes outside its chunk is refused. */
export function unpackDisclosure(fields: readonly Bytes32[], length: number): Uint8Array {
  if (fields.length !== Math.ceil(length / DISCLOSURE_CHUNK_BYTES))
    throw new RingKeyError("KEYPAIR_DISCLOSURE_SHAPE", { expected: length, actual: fields.length });
  const plaintext = new Uint8Array(length);
  fields.forEach((field, index) => {
    const chunk = Math.min(length - index * DISCLOSURE_CHUNK_BYTES, DISCLOSURE_CHUNK_BYTES);
    if (field[0] !== 0 || field.subarray(1 + chunk).some((byte) => byte !== 0))
      throw new RingKeyError("KEYPAIR_DISCLOSURE_PADDING", { index });
    plaintext.set(field.subarray(1, 1 + chunk), index * DISCLOSURE_CHUNK_BYTES);
  });
  return plaintext;
}

function checkLabel(label: Uint8Array): void {
  if (label.length !== STREAM_LABEL_BYTES)
    throw new RingKeyError("KEYPAIR_DISCLOSURE_SHAPE", { name: "label" });
}

function checkCounter(counter: number): void {
  if (!Number.isInteger(counter) || counter < STREAM_FIRST_COUNTER || counter > U32_MAX)
    throw new RingKeyError("KEYPAIR_DISCLOSURE_SHAPE", { name: "counter" });
}

function envelopeSecret(
  local: X25519Keypair,
  remote: X25519PublicKey,
  ephemeralPublicKey: X25519PublicKey,
  auditorPublicKey: X25519PublicKey,
): Bytes32 {
  const dh = local.ecdh(remote);
  try {
    return auditSharedSecret(dh, ephemeralPublicKey, auditorPublicKey);
  } finally {
    dh.fill(0);
  }
}

function rightAlign(bytes: Uint8Array): Bytes32 {
  const output = new Uint8Array(32);
  output.set(bytes, 32 - bytes.length);
  return output as Bytes32;
}
