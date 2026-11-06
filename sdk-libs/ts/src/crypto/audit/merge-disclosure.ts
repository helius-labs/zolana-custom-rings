/** The ring merge's sealed record and statement, Rust `custom_ring_interface::merge`. */
import {
  bytesToBigInt,
  equalBytes,
  hashBytes,
  hashChain,
  Reader,
  rightAlign,
  Writer,
  checkedBytes,
  ZERO_32,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import { pack33 } from "@heliuslabs/spr/interface";
import type { Address, Bytes32, Bytes33, Bytes64, RequestContext } from "@heliuslabs/spr/interface";
import { X25519Keypair, X25519PublicKey } from "@heliuslabs/spr/keypair";
import type { Bytes16, NullifierKey, ViewingKey } from "@heliuslabs/spr/keypair";

import { CUSTOM_RING_PROOF_LENGTH } from "../../protocol/proof/custom-ring-proof.js";
import {
  decodeMergeRecord,
  encodeMergeRecord,
  RecordKind,
  type MergeRecord,
} from "../../protocol/codec/audit-stream.js";
import {
  ENVELOPE_KEY_LEN,
  MERGE_ENVELOPE_LEN,
  MERGE_RECORD_LEN,
  STREAM_FIRST_COUNTER,
} from "../../protocol/codec/ring-disclosure-layout.js";
import { decompressG2 } from "../../protocol/codec/codecs.js";
import { RingError } from "../../protocol/error.js";
import { taggedX25519 } from "../../protocol/transaction/transact.js";
import type { RingProver } from "../../rpc/ports.js";
import type { MergeProofRequest } from "../../rpc/prover/ring.js";
import { x25519FromU } from "../keys/x25519.js";
import { domainField, RingDomain } from "../derivation/ring-domain.js";
import { deliveredSlotSecret } from "../derivation/ring-stream.js";
import { seededMergeOutputBlinding } from "../derivation/merge-seed.js";
import {
  AuditSchedule,
  MERGE_OUTPUT_ENC_INFO,
  MERGE_RECORD_ENC_INFO,
  auditSharedSecret,
} from "./audit.js";

/** Who admits a merge, the wincode tag SPP's `MergeRingIxData` reads. */
export const MergeRingAuthority = Object.freeze({ ring: 0, ownerSigned: 1 } as const);
export type MergeRingAuthority = (typeof MergeRingAuthority)[keyof typeof MergeRingAuthority];

/** The sealed half of tag 57, Rust `SealedMergeRecord`. */
export interface SealedMergeRecord {
  readonly proof: Uint8Array;
  readonly ephemeralPublicKey: Bytes33;
  /** `eph_sk ‖ V` sealed to the auditor, `MERGE_ENVELOPE_LEN` bytes. */
  readonly envelope: Uint8Array;
  /** The merge record sealed to `V`, `MERGE_RECORD_LEN` bytes. */
  readonly record: Uint8Array;
}

/** Tag 57 past its tag, Rust `CustomRingMergeIxData`. */
export interface RingMergeRequest {
  /** Read under the ring authority alone. */
  readonly trackingRevision: bigint;
  readonly outputRingDataHash: Bytes32;
  readonly authority: MergeRingAuthority;
  readonly sealed: SealedMergeRecord;
  /** The SPP merge body with `proof.b` compressed. */
  readonly compactBody: Uint8Array;
}

/** The merge statement, Rust `MergePublicInput`. */
export interface MergePublicInput {
  readonly outputUtxoHash: Bytes32;
  readonly firstNullifier: Bytes32;
  /** `hash_bytes` of the ring program id. */
  readonly ringId: Bytes32;
  /** `0x04 ‖ u`. */
  readonly auditorPubkey: Bytes33;
  readonly ephemeralPublicKey: Bytes33;
  readonly envelope: Uint8Array;
  readonly record: Uint8Array;
  /** The payer's Solana owner identity. */
  readonly payer: Bytes32;
  /** The signing owner's identity under `ownerSigned`, zero under the ring. */
  readonly publishedOwner: Bytes32;
  /** Zero under `ownerSigned`. */
  readonly trackingRoot: Bytes32;
}

/** `expiry_unix_ts u64 ‖ proof.a` ahead of `proof.b`, Rust `MERGE_B_OFFSET`. */
const MERGE_B_OFFSET = 8 + 32;
/** `tracking_revision ‖ output_ring_data_hash ‖ authority ‖ proof ‖ eph_pk ‖ envelope ‖ record`. */
const REQUEST_HEAD_LEN =
  8 + 32 + 1 + CUSTOM_RING_PROOF_LENGTH + 33 + MERGE_ENVELOPE_LEN + MERGE_RECORD_LEN;
/** A merge seals at slot index 0 under a zero salt, its ephemeral is fresh per call. */
const MERGE_SALT = new Uint8Array(16) as Bytes16;
const COMPRESSED_G2_LEN = 64;
const DECOMPRESSED_G2_LEN = 128;
/** `tag ‖ output_ring_data_hash ‖ authority` ahead of the SPP body. */
export const MERGE_RING_DATA_PREFIX_LEN = 1 + 32 + 1;

/** The merge request short of what sealing yields, its seed known to the holder alone. */
export type RingMergeDisclosureRequest = Omit<
  MergeProofRequest,
  "publicInputHash" | "ephSk" | "seed"
> &
  Readonly<{ mint: Address }>;

/** What one merge seals, the record to `V` and `eph_sk ‖ V` to the auditor. */
export interface MergeSeal {
  readonly merge: MergeRecord;
  /** `V`, the merged owner's viewing key. */
  readonly recipient: X25519PublicKey;
  readonly auditorPublicKey: X25519PublicKey;
  readonly firstNullifier: Bytes32;
}

/** The nullifier secret is the seed off the zero key, so its holder seals and proves. */
export interface RingMergeSealer {
  sealRingMerge(
    request: RingMergeDisclosureRequest,
    context?: RequestContext,
  ): Promise<SealedMergeRecord>;
}

/** The caller wipes `request.ephSk`, the seed stays the caller's to wipe. */
export function completeRingMerge(
  input: Readonly<{ request: RingMergeDisclosureRequest; seed: Bytes32 }>,
): Readonly<{ request: MergeProofRequest; sealed: Omit<SealedMergeRecord, "proof"> }> {
  const { request, seed } = input;
  const merge: MergeRecord = {
    record: {
      kind: RecordKind.ring,
      amount: bytesToBigInt(request.amount),
      ownerKey: request.ownerKey,
      mint: request.mint,
      nullifierPk: request.nullifierPk,
      blinding: seededMergeOutputBlinding(seed, request.firstNullifier),
    },
    seed,
  };
  const { sealed, ephemeralSecret } = sealMergeRecord({
    merge,
    recipient: x25519FromU(request.recipientKey),
    auditorPublicKey: x25519FromU(request.auditorPk),
    firstNullifier: request.firstNullifier,
  });
  const { mint: _mint, ...fields } = request;
  return Object.freeze({
    request: Object.freeze({
      ...fields,
      publicInputHash: mergePublicInputHash({
        outputUtxoHash: request.outputUtxoHash,
        firstNullifier: request.firstNullifier,
        ringId: request.ringProgramId,
        auditorPubkey: taggedX25519(request.auditorPk),
        ephemeralPublicKey: sealed.ephemeralPublicKey,
        envelope: sealed.envelope,
        record: sealed.record,
        payer: request.payer,
        publishedOwner: equalBytes(request.nullifierPk, ZERO_NULLIFIER_PK)
          ? request.ownerPkHash
          : ZERO_32,
        trackingRoot: request.trackingRoot,
      }),
      ephSk: ephemeralSecret,
      seed,
    }),
    sealed,
  });
}

/** Seals under the held key and proves, the secret stays in the holder's process. */
export function nullifierKeyMergeSealer(
  input: Readonly<{ nullifierKey: NullifierKey; prover: RingProver }>,
): RingMergeSealer {
  return Object.freeze({
    sealRingMerge: async (request: RingMergeDisclosureRequest, context?: RequestContext) => {
      const secret = input.nullifierKey.secretBytes();
      const seed = rightAlign(secret) as Bytes32;
      secret.fill(0);
      try {
        const complete = completeRingMerge({ request, seed });
        try {
          const proof = await input.prover.proveRing(complete.request, context);
          return Object.freeze({ ...complete.sealed, proof });
        } finally {
          complete.request.ephSk.fill(0);
        }
      } finally {
        seed.fill(0);
      }
    },
  });
}

/** Fresh ephemeral per call, one key and nonce serves one plaintext. */
export function sealMergeRecord(
  input: MergeSeal,
): Readonly<{ sealed: Omit<SealedMergeRecord, "proof">; ephemeralSecret: Bytes32 }> {
  const ephemeral = X25519Keypair.generate();
  try {
    return sealMergeRecordWith({ ...input, ephemeral });
  } finally {
    ephemeral.destroy();
  }
}

/** @internal The vector seals under a chosen ephemeral. */
export function sealMergeRecordWith(
  input: MergeSeal & Readonly<{ ephemeral: X25519Keypair }>,
): Readonly<{ sealed: Omit<SealedMergeRecord, "proof">; ephemeralSecret: Bytes32 }> {
  const { auditorPublicKey, ephemeral, recipient } = input;
  const ephemeralPublicKey = ephemeral.publicKey();
  const ephemeralSecret = ephemeral.secretBytes();
  const envelopePlaintext = new Uint8Array(MERGE_ENVELOPE_LEN);
  envelopePlaintext.set(ephemeralSecret, 0);
  envelopePlaintext.set(recipient.u(), ENVELOPE_KEY_LEN);
  const recordPlaintext = encodeMergeRecord(input.merge);
  const auditorAgreement = ephemeral.ecdh(auditorPublicKey);
  const shared = auditSharedSecret(auditorAgreement, ephemeralPublicKey, auditorPublicKey);
  const recordSecret = mergeRecordSecret({
    agreement: ephemeral.ecdh(recipient),
    ephemeralPublicKey,
    recipient,
    firstNullifier: input.firstNullifier,
  });
  try {
    return Object.freeze({
      sealed: Object.freeze({
        ephemeralPublicKey: ephemeralPublicKey.toBytes(),
        envelope: streamApply(shared, MERGE_RECORD_ENC_INFO, envelopePlaintext),
        record: streamApply(recordSecret, MERGE_OUTPUT_ENC_INFO, recordPlaintext),
      }),
      ephemeralSecret,
    });
  } finally {
    auditorAgreement.fill(0);
    shared.fill(0);
    recordSecret.fill(0);
    envelopePlaintext.fill(0);
    recordPlaintext.fill(0);
  }
}

/** The auditor's side, `eph_sk ‖ V` from the envelope, then the record under the merge's slot secret. */
export function openMergeRecord(
  auditor: X25519Keypair,
  sealed: Pick<SealedMergeRecord, "ephemeralPublicKey" | "envelope" | "record">,
  firstNullifier: Bytes32,
): MergeRecord {
  if (sealed.envelope.length !== MERGE_ENVELOPE_LEN) throw invalid("merge.envelope");
  const ephemeralPublicKey = X25519PublicKey.fromBytes(sealed.ephemeralPublicKey);
  const dh = auditor.ecdh(ephemeralPublicKey);
  const shared = auditSharedSecret(dh, ephemeralPublicKey, auditor.publicKey());
  const envelope = streamApply(shared, MERGE_RECORD_ENC_INFO, sealed.envelope);
  let ephemeral: X25519Keypair | undefined;
  try {
    ephemeral = X25519Keypair.fromBytes(envelope.slice(0, ENVELOPE_KEY_LEN) as Bytes32);
    // An envelope sealing another ephemeral would open a record the statement never bound.
    if (!ephemeral.publicKey().equals(ephemeralPublicKey)) throw invalid("merge.envelope");
    const recipient = x25519FromU(envelope.slice(ENVELOPE_KEY_LEN) as Bytes32);
    return openUnder(sealed.record, {
      agreement: ephemeral.ecdh(recipient),
      ephemeralPublicKey,
      recipient,
      firstNullifier,
    });
  } finally {
    dh.fill(0);
    shared.fill(0);
    envelope.fill(0);
    ephemeral?.destroy();
  }
}

/** The merged owner's side under its viewing key, the record alone, no envelope read. */
export function openOwnMergeRecord(
  viewingKey: ViewingKey,
  sealed: Pick<SealedMergeRecord, "ephemeralPublicKey" | "record">,
  firstNullifier: Bytes32,
): MergeRecord {
  const ephemeralPublicKey = X25519PublicKey.fromBytes(sealed.ephemeralPublicKey);
  return openUnder(sealed.record, {
    agreement: viewingKey.ecdh(ephemeralPublicKey),
    ephemeralPublicKey,
    recipient: viewingKey.publicKey(),
    firstNullifier,
  });
}

/** `DeliveredSlot` at index 0 under a zero salt, `eph_pk` in the transaction key's place. */
function mergeRecordSecret(
  input: Readonly<{
    agreement: Bytes32;
    ephemeralPublicKey: X25519PublicKey;
    recipient: X25519PublicKey;
    firstNullifier: Bytes32;
  }>,
): Bytes32 {
  try {
    return deliveredSlotSecret({
      agreement: input.agreement,
      txViewingKey: input.ephemeralPublicKey,
      recipientViewingKey: input.recipient,
      salt: MERGE_SALT,
      outputIndex: 0,
      firstNullifier: input.firstNullifier,
    });
  } finally {
    input.agreement.fill(0);
  }
}

function openUnder(
  record: Uint8Array,
  secretInput: Parameters<typeof mergeRecordSecret>[0],
): MergeRecord {
  if (record.length !== MERGE_RECORD_LEN) throw invalid("merge.record");
  const secret = mergeRecordSecret(secretInput);
  const plaintext = streamApply(secret, MERGE_OUTPUT_ENC_INFO, record);
  try {
    return decodeMergeRecord(plaintext);
  } finally {
    secret.fill(0);
    plaintext.fill(0);
  }
}

function streamApply(secret: Bytes32, label: Uint8Array, data: Uint8Array): Uint8Array {
  const schedule = AuditSchedule.derive(secret, label);
  try {
    return schedule.apply(STREAM_FIRST_COUNTER, data);
  } finally {
    schedule.destroy();
  }
}

/** `[CRMG, output, n0, ring_id, aud0, aud1, eph0, eph1, hash_bytes(envelope_ct), hash_bytes(record_ct), payer, published_owner, tracking_root]`. */
export function mergePublicInputElements(input: MergePublicInput): readonly Bytes32[] {
  return [
    domainField(RingDomain.mergeStatement),
    checkedBytes<Bytes32>(input.outputUtxoHash, 32, "output utxo hash"),
    checkedBytes<Bytes32>(input.firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(input.ringId, 32, "ring id"),
    ...pack33(checkedBytes<Bytes33>(input.auditorPubkey, 33, "auditor pubkey")),
    ...pack33(checkedBytes<Bytes33>(input.ephemeralPublicKey, 33, "ephemeral pubkey")),
    hashBytes(checkedBytes(input.envelope, MERGE_ENVELOPE_LEN, "envelope")) as Bytes32,
    hashBytes(checkedBytes(input.record, MERGE_RECORD_LEN, "record")) as Bytes32,
    checkedBytes<Bytes32>(input.payer, 32, "payer"),
    checkedBytes<Bytes32>(input.publishedOwner, 32, "published owner"),
    checkedBytes<Bytes32>(input.trackingRoot, 32, "tracking root"),
  ];
}

export function mergePublicInputHash(input: MergePublicInput): Bytes32 {
  return hashChain(mergePublicInputElements(input)) as Bytes32;
}

/** Tag 57 past its tag, the SPP body at its compressed length. */
export function encodeRingMergeRequest(request: RingMergeRequest): Uint8Array {
  const { sealed } = request;
  return new Writer()
    .u64(request.trackingRevision, "merge.trackingRevision")
    .bytes(request.outputRingDataHash, 32, "merge.outputRingDataHash")
    .u8(request.authority, "merge.authority")
    .bytes(sealed.proof, CUSTOM_RING_PROOF_LENGTH, "merge.proof")
    .bytes(sealed.ephemeralPublicKey, 33, "merge.ephemeralPublicKey")
    .bytes(sealed.envelope, MERGE_ENVELOPE_LEN, "merge.envelope")
    .bytes(sealed.record, MERGE_RECORD_LEN, "merge.record")
    .bytes(request.compactBody)
    .finish();
}

/** Refuses an authority byte off the two, Rust `CustomRingMergeIxDataRef::from_bytes`. */
export function decodeRingMergeRequest(data: Uint8Array): RingMergeRequest {
  const reader = new Reader(data);
  const trackingRevision = reader.u64("merge.trackingRevision");
  const outputRingDataHash = reader.bytes(32, "merge.outputRingDataHash") as Bytes32;
  const authority = reader.u8("merge.authority");
  if (authority !== MergeRingAuthority.ring && authority !== MergeRingAuthority.ownerSigned)
    throw invalid("merge.authority");
  const proof = reader.bytes(CUSTOM_RING_PROOF_LENGTH, "merge.proof");
  const ephemeralPublicKey = reader.bytes(33, "merge.ephemeralPublicKey") as Bytes33;
  const envelope = reader.bytes(MERGE_ENVELOPE_LEN, "merge.envelope");
  const record = reader.bytes(MERGE_RECORD_LEN, "merge.record");
  const compactBody = data.subarray(REQUEST_HEAD_LEN);
  return Object.freeze({
    trackingRevision,
    outputRingDataHash,
    authority,
    sealed: Object.freeze({ proof, ephemeralPublicKey, envelope, record }),
    compactBody,
  });
}

/** The SPP body with `proof.b` compressed, the program decompresses it, Rust `SppMergeBody`. */
export function compactMergeBody(body: Uint8Array, compressedB: Bytes64): Uint8Array {
  if (body.length < MERGE_B_OFFSET + DECOMPRESSED_G2_LEN) throw invalid("merge.body");
  const out = new Uint8Array(body.length - DECOMPRESSED_G2_LEN + COMPRESSED_G2_LEN);
  out.set(body.subarray(0, MERGE_B_OFFSET), 0);
  out.set(compressedB, MERGE_B_OFFSET);
  out.set(body.subarray(MERGE_B_OFFSET + DECOMPRESSED_G2_LEN), MERGE_B_OFFSET + COMPRESSED_G2_LEN);
  return out;
}

/** Rust `SppMergeBody::decompressed`, the bytes SPP's `merge_ring` parses past its prefix. */
export function sppMergeBody(compact: Uint8Array): Uint8Array {
  if (compact.length < MERGE_B_OFFSET + COMPRESSED_G2_LEN) throw invalid("merge.body");
  const b = decompressG2(
    compact.slice(MERGE_B_OFFSET, MERGE_B_OFFSET + COMPRESSED_G2_LEN) as Bytes64,
  );
  const body = new Uint8Array(compact.length - COMPRESSED_G2_LEN + DECOMPRESSED_G2_LEN);
  body.set(compact.subarray(0, MERGE_B_OFFSET), 0);
  body.set(b, MERGE_B_OFFSET);
  body.set(
    compact.subarray(MERGE_B_OFFSET + COMPRESSED_G2_LEN),
    MERGE_B_OFFSET + DECOMPRESSED_G2_LEN,
  );
  return body;
}

/** Rust `CustomRingMergeIxDataRef::forwarded`, `[tag, output_ring_data_hash, authority, body]`. */
export function forwardedMergeData(
  request: Pick<RingMergeRequest, "outputRingDataHash" | "authority">,
  sppBody: Uint8Array,
  sppTag: number,
): Uint8Array {
  const out = new Uint8Array(MERGE_RING_DATA_PREFIX_LEN + sppBody.length);
  out[0] = sppTag;
  out.set(request.outputRingDataHash, 1);
  out[33] = request.authority;
  out.set(sppBody, MERGE_RING_DATA_PREFIX_LEN);
  return out;
}

function invalid(path: string): RingError {
  return new RingError("RING_ORIGIN_DECODE", { details: { path } });
}
