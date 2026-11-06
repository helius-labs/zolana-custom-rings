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
import type { NullifierKey } from "@heliuslabs/spr/keypair";

import { CUSTOM_RING_PROOF_LENGTH } from "../../protocol/proof/custom-ring-proof.js";
import {
  decodeOpeningRecord,
  encodeOpeningRecord,
  RecordKind,
  type OpeningRecord,
} from "../../protocol/codec/audit-stream.js";
import {
  OPENING_RECORD_LEN,
  STREAM_FIRST_COUNTER,
} from "../../protocol/codec/ring-disclosure-layout.js";
import { decompressG2 } from "../../protocol/codec/codecs.js";
import { RingError } from "../../protocol/error.js";
import { taggedX25519 } from "../../protocol/transaction/transact.js";
import type { RingProver } from "../../rpc/ports.js";
import type { MergeProofRequest } from "../../rpc/prover/ring.js";
import { x25519FromU } from "../keys/x25519.js";
import { domainField, RingDomain } from "../derivation/ring-domain.js";
import { AuditSchedule, MERGE_RECORD_ENC_INFO, auditSharedSecret } from "./audit.js";

/** Who admits a merge, the wincode tag SPP's `MergeRingIxData` reads. */
export const MergeRingAuthority = Object.freeze({ ring: 0, ownerSigned: 1 } as const);
export type MergeRingAuthority = (typeof MergeRingAuthority)[keyof typeof MergeRingAuthority];

/** The sealed half of tag 57, Rust `SealedMergeRecord`. */
export interface SealedMergeRecord {
  readonly proof: Uint8Array;
  readonly ephemeralPublicKey: Bytes33;
  /** `OPENING_RECORD_LEN` bytes. */
  readonly ciphertext: Uint8Array;
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
  readonly ciphertext: Uint8Array;
  /** The payer's Solana owner identity. */
  readonly payer: Bytes32;
  /** The signing owner's identity under `ownerSigned`, zero under the ring. */
  readonly publishedOwner: Bytes32;
  /** Zero under `ownerSigned`. */
  readonly trackingRoot: Bytes32;
}

/** `expiry_unix_ts u64 ‖ proof.a` ahead of `proof.b`, Rust `MERGE_B_OFFSET`. */
const MERGE_B_OFFSET = 8 + 32;
/** `tracking_revision ‖ output_ring_data_hash ‖ authority ‖ proof ‖ eph_pk ‖ ciphertext`. */
const REQUEST_HEAD_LEN = 8 + 32 + 1 + CUSTOM_RING_PROOF_LENGTH + 33 + OPENING_RECORD_LEN;
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
  const opening: OpeningRecord = {
    record: {
      kind: RecordKind.ring,
      amount: bytesToBigInt(request.amount),
      ownerKey: request.ownerKey,
      mint: request.mint,
      nullifierPk: request.nullifierPk,
    },
    secret: seed,
  };
  const { sealed, ephemeralSecret } = sealMergeRecord({
    opening,
    auditorPublicKey: x25519FromU(request.auditorPk),
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
        ciphertext: sealed.ciphertext,
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
  input: Readonly<{ opening: OpeningRecord; auditorPublicKey: X25519PublicKey }>,
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
  input: Readonly<{
    opening: OpeningRecord;
    auditorPublicKey: X25519PublicKey;
    ephemeral: X25519Keypair;
  }>,
): Readonly<{ sealed: Omit<SealedMergeRecord, "proof">; ephemeralSecret: Bytes32 }> {
  const { auditorPublicKey, ephemeral } = input;
  const ephemeralPublicKey = ephemeral.publicKey();
  const dh = ephemeral.ecdh(auditorPublicKey);
  const shared = auditSharedSecret(dh, ephemeralPublicKey, auditorPublicKey);
  const plaintext = encodeOpeningRecord(input.opening);
  try {
    const schedule = AuditSchedule.derive(shared, MERGE_RECORD_ENC_INFO);
    try {
      return Object.freeze({
        sealed: Object.freeze({
          ephemeralPublicKey: ephemeralPublicKey.toBytes(),
          ciphertext: schedule.apply(STREAM_FIRST_COUNTER, plaintext),
        }),
        ephemeralSecret: ephemeral.secretBytes(),
      });
    } finally {
      schedule.destroy();
    }
  } finally {
    dh.fill(0);
    shared.fill(0);
    plaintext.fill(0);
  }
}

/** The auditor's side, the caller rebuilds the output commitment from the record. */
export function openMergeRecord(
  auditor: X25519Keypair,
  sealed: Pick<SealedMergeRecord, "ephemeralPublicKey" | "ciphertext">,
): OpeningRecord {
  if (sealed.ciphertext.length !== OPENING_RECORD_LEN) throw invalid("merge.ciphertext");
  const ephemeral = X25519PublicKey.fromBytes(sealed.ephemeralPublicKey);
  const dh = auditor.ecdh(ephemeral);
  const shared = auditSharedSecret(dh, ephemeral, auditor.publicKey());
  const schedule = AuditSchedule.derive(shared, MERGE_RECORD_ENC_INFO);
  const plaintext = schedule.apply(STREAM_FIRST_COUNTER, sealed.ciphertext);
  try {
    return decodeOpeningRecord(plaintext);
  } finally {
    dh.fill(0);
    shared.fill(0);
    plaintext.fill(0);
    schedule.destroy();
  }
}

/** `[CRMG, output, n0, ring_id, aud0, aud1, eph0, eph1, hash_bytes(ct), payer, published_owner, tracking_root]`. */
export function mergePublicInputElements(input: MergePublicInput): readonly Bytes32[] {
  return [
    domainField(RingDomain.mergeStatement),
    checkedBytes<Bytes32>(input.outputUtxoHash, 32, "output utxo hash"),
    checkedBytes<Bytes32>(input.firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(input.ringId, 32, "ring id"),
    ...pack33(checkedBytes<Bytes33>(input.auditorPubkey, 33, "auditor pubkey")),
    ...pack33(checkedBytes<Bytes33>(input.ephemeralPublicKey, 33, "ephemeral pubkey")),
    hashBytes(checkedBytes(input.ciphertext, OPENING_RECORD_LEN, "ciphertext")) as Bytes32,
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
    .bytes(sealed.ciphertext, OPENING_RECORD_LEN, "merge.ciphertext")
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
  const ciphertext = reader.bytes(OPENING_RECORD_LEN, "merge.ciphertext");
  const compactBody = data.subarray(REQUEST_HEAD_LEN);
  return Object.freeze({
    trackingRevision,
    outputRingDataHash,
    authority,
    sealed: Object.freeze({ proof, ephemeralPublicKey, ciphertext }),
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
