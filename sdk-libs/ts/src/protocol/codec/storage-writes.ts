import { Reader, Writer, addressBytes, encodeBase58 } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";

import { RingError } from "../error.js";
import {
  MINT_POLICY_LEN,
  mintPolicyFromBytes,
  mintPolicyWrite,
  type MintPolicy,
} from "../membership/mint-policy.js";
import { memberOfIdentity, type Member } from "../membership/policy.js";

/** Rust `write_kind`. */
const RECORD_KIND = 0;
const ESCROW_KIND = 1;
/** Rust `RecordWriteData::SIZE` and `EscrowWriteData::SIZE`. */
const RECORD_LENGTH = 145;
const ESCROW_LENGTH = 128;

/** Rust `StorageWriteData`. */
export type StorageWrite =
  | Readonly<{
      kind: "record";
      member: Member;
      mask: bigint;
      value: bigint;
      /** Absent keeps the record's mint settings. */
      mintPolicy?: MintPolicy;
    }>
  | Readonly<{
      kind: "escrow";
      /** Its owner identity is the leaf member. */
      owner: Address;
      nullifierPk: Bytes32;
      /** The only field the leaf does not bind. */
      ephU: Bytes32;
      ciphertext: Bytes32;
    }>;

/** Mirrors Rust `StorageWriteData::encode_all`. */
export function encodeStorageWrites(writes: readonly StorageWrite[]): Uint8Array {
  const writer = new Writer();
  for (const write of writes) {
    if (write.kind === "record")
      writer
        .u8(RECORD_KIND, "kind")
        .bytes(write.member, 32, "member")
        .u64(write.mask, "mask")
        .u64(write.value, "value")
        .bytes(mintPolicyWrite(write.mintPolicy));
    else
      writer
        .u8(ESCROW_KIND, "kind")
        .bytes(addressBytes(write.owner, "owner"))
        .bytes(write.nullifierPk, 32, "nullifierPk")
        .bytes(write.ephU, 32, "ephU")
        .bytes(write.ciphertext, 32, "ciphertext");
  }
  return writer.finish();
}

/** Mirrors Rust `StorageWriteData::parse_all`, and refuses a mint settings tag past 1 or nonzero settings under tag 0. */
export function decodeStorageWrites(data: Uint8Array): readonly StorageWrite[] {
  const writes: StorageWrite[] = [];
  for (let offset = 0; offset < data.length;) {
    const kind = data[offset];
    const length =
      kind === RECORD_KIND ? RECORD_LENGTH : kind === ESCROW_KIND ? ESCROW_LENGTH : undefined;
    if (length === undefined) throw invalid(offset);
    const body = data.subarray(offset + 1, offset + 1 + length);
    try {
      const reader = new Reader(body);
      writes.push(kind === RECORD_KIND ? recordWrite(reader) : escrowWrite(reader));
      reader.done();
    } catch (cause) {
      throw invalid(offset, cause);
    }
    offset += 1 + length;
  }
  return Object.freeze(writes);
}

function recordWrite(reader: Reader): StorageWrite {
  const member = memberOfIdentity(reader.bytes(32, "member") as Bytes32);
  const mask = reader.u64("mask");
  const value = reader.u64("value");
  const tag = reader.u8("mintPolicy.tag");
  const policy = reader.bytes(MINT_POLICY_LEN, "mintPolicy");
  if (tag === 1) {
    return Object.freeze({
      kind: "record",
      member,
      mask,
      value,
      mintPolicy: mintPolicyFromBytes(policy),
    });
  }
  if (tag !== 0 || !policy.every((byte) => byte === 0))
    throw new RingError("RING_STORAGE_WRITE_INVALID", { details: { field: "mintPolicy" } });
  return Object.freeze({ kind: "record", member, mask, value });
}

function escrowWrite(reader: Reader): StorageWrite {
  const owner = encodeBase58(reader.bytes(32, "owner"));
  const nullifierPk = reader.bytes(32, "nullifierPk") as Bytes32;
  const ephU = reader.bytes(32, "ephU") as Bytes32;
  const ciphertext = reader.bytes(32, "ciphertext") as Bytes32;
  return Object.freeze({ kind: "escrow", owner, nullifierPk, ephU, ciphertext });
}

function invalid(offset: number, cause?: unknown): RingError {
  return new RingError("RING_STORAGE_WRITE_INVALID", {
    details: { offset },
    ...(cause === undefined ? {} : { cause }),
  });
}
