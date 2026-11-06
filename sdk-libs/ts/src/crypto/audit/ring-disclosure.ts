/** The auditor stream of a transfer, sealed and opened over its canonical records, Rust `AuditStreamSeal` and `AuditEnvelope`. */
import { clampViewingSecret, concatBytes } from "@heliuslabs/spr/internal";
import {
  ViewingKey,
  type Bytes16,
  type Bytes32,
  type X25519Keypair,
  type X25519PublicKey,
} from "@heliuslabs/spr/keypair";

import { RingError } from "../../protocol/error.js";
import {
  decodeAuditEnvelope,
  decodeAuditRecord,
  decodeCompactAuditRecord,
  decodeDataTail,
  encodeAuditEnvelope,
  envelopeInputMap,
  encodeAuditRecord,
  encodeCompactAuditRecord,
  encodeDataTail,
  type AuditEnvelope,
  type AuditRecord,
  type DataTail,
} from "../../protocol/codec/audit-stream.js";
import {
  ENVELOPE_KEY_LEN,
  DisclosureFormat,
  disclosureFormat,
  checkedStreamLayout,
  envelopeRegion,
  recordRegion,
  STREAM_FIRST_COUNTER,
  tailRegion,
  type AuditStreamLayout,
} from "../../protocol/codec/ring-disclosure-layout.js";
import { RingKeyError } from "../error.js";
import {
  saltedAuditorSchedule,
  sealedAuditorSchedule,
  type AuditSchedule,
  sealSaltedAuditorStream,
  type AuditorEnvelope,
  type AuditorMessage,
} from "./audit.js";

/** One transfer's stream plaintexts, Rust `AuditStreamSeal`. */
export interface RingDisclosure {
  readonly envelope: AuditEnvelope;
  /** One per published slot. */
  readonly records: readonly AuditRecord[];
  /** One per published slot under `has_data`. */
  readonly tails?: readonly DataTail[];
}

/** `layout` is the one the program verified. */
export interface PublishedAudit {
  readonly layout: AuditStreamLayout;
  readonly message: AuditorMessage;
  readonly salt: Bytes16;
}

/** Refuses a disclosure off its layout before sealing. */
export function sealRingDisclosure(
  input: Readonly<{
    layout: AuditStreamLayout;
    auditorPublicKey: X25519PublicKey;
    salt: Bytes16;
    disclosure: RingDisclosure;
  }>,
): AuditorEnvelope {
  const { disclosure, auditorPublicKey } = input;
  const layout = checkedStreamLayout(input.layout);
  const tails = disclosure.tails ?? [];
  if (
    disclosure.records.length !== layout.outputs ||
    tails.length !== (layout.hasData ? layout.outputs : 0) ||
    (disclosure.envelope.evidence.kind === "entry") !== layout.key.entry
  )
    throw shapeError("disclosure");
  const compact = disclosureFormat(layout.key.format) === DisclosureFormat.SingleAssetPayout;
  const evidence = disclosure.envelope.evidence;
  if (
    compact !== (evidence.kind === "singleAssetPayout") ||
    (evidence.kind === "singleAssetPayout" &&
      disclosure.records.some((record) => record.mint !== evidence.mint))
  )
    throw shapeError("mint");
  envelopeInputMap(disclosure.envelope, layout);
  const envelope = encodeAuditEnvelope(disclosure.envelope);
  const recordBytes = disclosure.records.map(
    compact ? encodeCompactAuditRecord : encodeAuditRecord,
  );
  const tailBytes = tails.map(encodeDataTail);
  try {
    if (envelope.length !== envelopeRegion(layout).length) throw shapeError("envelope");
    return sealSaltedAuditorStream({
      txViewingSecret: disclosure.envelope.txViewingSecret,
      salt: input.salt,
      auditorPublicKey,
      envelope,
      records: recordBytes.map((bytes, slot) => ({
        counter: recordRegion(layout, slot).startCounter,
        bytes,
      })),
      ...(layout.hasData
        ? {
            tails: tailBytes.map((bytes, slot) => ({
              counter: tailRegion(layout, slot).startCounter,
              bytes,
            })),
          }
        : {}),
    });
  } finally {
    envelope.fill(0);
    recordBytes.forEach((bytes) => bytes.fill(0));
    tailBytes.forEach((bytes) => bytes.fill(0));
  }
}

/** Every plaintext under the layout the program verified, each read at its own counter. */
export function openRingDisclosure(
  auditor: X25519Keypair,
  published: PublishedAudit,
): RingDisclosure {
  const { message, salt } = published;
  return readDisclosure(
    saltedAuditorSchedule(auditor, message.ephemeralPublicKey, salt),
    published,
  );
}

/** Rust `AuditEnvelope::open_sealed`, the wrong auditor key decrypts noise. */
export function openSealedDisclosure(
  txViewingSecret: Bytes32,
  auditorPublicKey: X25519PublicKey,
  published: PublishedAudit,
): RingDisclosure {
  return readDisclosure(
    sealedAuditorSchedule(txViewingSecret, auditorPublicKey, published.salt),
    published,
  );
}

function readDisclosure(schedule: AuditSchedule, published: PublishedAudit): RingDisclosure {
  const { message } = published;
  const opened: Uint8Array[] = [];
  const plain = (counter: number, bytes: Uint8Array): Uint8Array => {
    const plaintext = schedule.apply(counter, bytes);
    opened.push(plaintext);
    return plaintext;
  };
  try {
    const layout = checkedStreamLayout(published.layout);
    if (
      message.records.length !== layout.outputs ||
      (message.tails?.length ?? 0) !== (layout.hasData ? layout.outputs : 0)
    ) {
      throw shapeError("disclosure");
    }
    const envelope = decodeAuditEnvelope(plain(STREAM_FIRST_COUNTER, message.envelope), layout);
    const records = message.records.map((record, slot) =>
      envelope.evidence.kind === "singleAssetPayout"
        ? decodeCompactAuditRecord(
            plain(recordRegion(layout, slot).startCounter, record),
            envelope.evidence.mint,
          )
        : decodeAuditRecord(plain(recordRegion(layout, slot).startCounter, record)),
    );
    const tails = message.tails?.map((tail, slot) =>
      decodeDataTail(plain(tailRegion(layout, slot).startCounter, tail)),
    );
    return Object.freeze({
      envelope,
      records: Object.freeze(records),
      ...(tails === undefined ? {} : { tails: Object.freeze(tails) }),
    });
  } finally {
    schedule.destroy();
    opened.forEach((bytes) => bytes.fill(0));
  }
}

/** The plaintext concatenation the circuit hashes, `envelope ‖ records ‖ tails` of a sealed stream. */
export function disclosurePlaintext(disclosure: RingDisclosure): Uint8Array {
  return concatBytes(
    encodeAuditEnvelope(disclosure.envelope),
    ...disclosure.records.map(
      disclosure.envelope.evidence.kind === "singleAssetPayout"
        ? encodeCompactAuditRecord
        : encodeAuditRecord,
    ),
    ...(disclosure.tails ?? []).map(encodeDataTail),
  );
}

/** Wipes `recovered`, the circuit seals the clamped encoding and an alias is refused. */
export function canonicalViewingKey(recovered: Bytes32): ViewingKey {
  const canonical = clampViewingSecret(recovered);
  try {
    let difference = 0;
    for (let index = 0; index < ENVELOPE_KEY_LEN; index++)
      difference |= (recovered[index] ?? 0) ^ (canonical[index] ?? 0);
    if (difference !== 0) throw new RingError("RING_AUDIT_NONCANONICAL_KEY");
    return ViewingKey.fromBytes(recovered);
  } finally {
    canonical.fill(0);
    recovered.fill(0);
  }
}

function shapeError(name: string): RingKeyError {
  return new RingKeyError("KEYPAIR_DISCLOSURE_SHAPE", { name });
}
