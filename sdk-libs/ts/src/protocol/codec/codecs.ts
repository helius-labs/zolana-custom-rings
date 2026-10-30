/** The SPP wire pieces the ring reads back from its own forwarded data, pinned SPP layout. */
import { bn254 } from "@noble/curves/bn254.js";

import type { Bytes16, Bytes32, Bytes128 } from "@heliuslabs/zolana";
import {
  bigIntToBytes,
  bytesToBigInt,
  checkedBytes,
  fail,
  mergePaddedInputCount,
  Reader,
  unsigned,
  type Writer,
} from "@heliuslabs/zolana/internal";
import {
  CACHE_CAPACITY,
  MergeEncryptionScheme,
  type Bytes64,
  type InterfaceTransfer,
  type MergeOutputEncryption,
  type MergeTransactInstructionData,
  type TreeContext,
} from "@heliuslabs/zolana/interface";

import { ClientError } from "@heliuslabs/zolana/client";

const BN254_BASE_MODULUS = bn254.fields.Fp.ORDER;

export function readInterfaceTransfer(reader: Reader): InterfaceTransfer {
  const kind = reader.u8("interfaceTransfer.kind");
  const amount = reader.u64("interfaceTransfer.amount");
  switch (kind) {
    case 0:
      return Object.freeze({ kind: "solDeposit", amount });
    case 1:
      return Object.freeze({ kind: "solWithdrawal", amount });
    case 2:
    case 3:
      return Object.freeze({
        kind: kind === 2 ? "splDeposit" : "splWithdrawal",
        amount,
        splInterfaceBump: reader.u8("interfaceTransfer.splInterfaceBump"),
      });
    default:
      return fail("INTERFACE_CODEC", { name: "interfaceTransfer.kind", actual: kind });
  }
}

export function writeInterfaceTransfer(writer: Writer, value: InterfaceTransfer): void {
  const tag =
    value.kind === "solDeposit"
      ? 0
      : value.kind === "solWithdrawal"
        ? 1
        : value.kind === "splDeposit"
          ? 2
          : 3;
  writer.u8(tag, "interfaceTransfer.kind").u64(value.amount, "interfaceTransfer.amount");
  if (value.kind === "splDeposit" || value.kind === "splWithdrawal") {
    writer.u8(value.splInterfaceBump, "interfaceTransfer.splInterfaceBump");
  }
}

export function readTreeContext(reader: Reader): TreeContext {
  return Object.freeze({
    utxoTreeRootIndex: reader.u16("treeContext.utxoTreeRootIndex"),
    nullifierTreeRootIndex: reader.u16("treeContext.nullifierTreeRootIndex"),
  });
}

function readMergeOutputEncryption(reader: Reader): MergeOutputEncryption {
  const scheme = reader.u8("outputEncryption.scheme");
  if (scheme !== MergeEncryptionScheme.PoseidonCtrV1) {
    fail("INTERFACE_CODEC", { name: "outputEncryption.scheme", actual: scheme });
  }
  return {
    scheme,
    salt: reader.bytes(16, "outputEncryption.salt") as Bytes16,
    ciphertext: [
      reader.bytes(32, "outputEncryption.ciphertext") as Bytes32,
      reader.bytes(32, "outputEncryption.ciphertext") as Bytes32,
      reader.bytes(32, "outputEncryption.ciphertext") as Bytes32,
    ],
  };
}

/** Reads one `MergeTransactIxData` body, the caller owns the surrounding frame. */
export function readMergeData(reader: Reader): MergeTransactInstructionData {
  const expiryUnixTs = reader.u64("expiryUnixTs");
  const proof = {
    a: reader.bytes(32, "proof.a") as Bytes32,
    b: reader.bytes(128, "proof.b") as Bytes128,
    c: reader.bytes(32, "proof.c") as Bytes32,
  };
  const outputUtxoHash = reader.bytes(32, "outputUtxoHash") as Bytes32;
  const outputEncryption = readMergeOutputEncryption(reader);
  const privateTxHash = reader.bytes(32, "privateTxHash") as Bytes32;
  const count = reader.u8("nullifiers.length");
  if (count === 0 || mergePaddedInputCount(count) === undefined) {
    fail("INTERFACE_CODEC", { name: "nullifiers.length", actual: count });
  }
  const nullifiers = Array.from({ length: count }, () => reader.bytes(32, "nullifier") as Bytes32);
  const utxoTreeRootIndex = reader.u16("utxoTreeRootIndex");
  const nullifierTreeRootIndex = reader.u16("nullifierTreeRootIndex");
  const cacheSlot = reader.option("cacheSlot", (input) =>
    unsigned(input.u8("cacheSlot"), CACHE_CAPACITY - 1, "cacheSlot"),
  );
  return {
    expiryUnixTs,
    proof,
    outputUtxoHash,
    outputEncryption,
    privateTxHash,
    nullifiers,
    utxoTreeRootIndex,
    nullifierTreeRootIndex,
    ...(cacheSlot === undefined ? {} : { cacheSlot }),
  };
}

/** Rust `alt_bn128_g2_decompress_be`, the SPP proof `b` the ring program expands. */
export function decompressG2(compressed: Bytes64): Bytes128 {
  const point = checkedBytes(compressed, 64, "proof.b");
  if (point.every((byte) => byte === 0)) return new Uint8Array(128) as Bytes128;
  const flags = point[0] ?? 0;
  // Bit 6 marks infinity, no proof point takes it.
  if ((flags & 0x40) !== 0) invalidPoint();
  const x1 = bytesToBigInt(point.subarray(0, 32)) & ((1n << 254n) - 1n);
  const x0 = bytesToBigInt(point.subarray(32));
  if (x1 >= BN254_BASE_MODULUS || x0 >= BN254_BASE_MODULUS) invalidPoint();
  const { Fp2 } = bn254.fields;
  const x = Fp2.create({ c0: x0, c1: x1 });
  let y: { c0: bigint; c1: bigint };
  try {
    y = Fp2.sqrt(Fp2.add(Fp2.mul(Fp2.sqr(x), x), bn254.G2.Point.CURVE().b));
  } catch {
    return invalidPoint();
  }
  if (isLargestFp2(y) !== ((flags & 0x80) !== 0)) y = Fp2.neg(y);
  const result = new Uint8Array(128);
  [x1, x0, y.c1, y.c0].forEach((value, index) => {
    result.set(bigIntToBytes(value), index * 32);
  });
  return result as Bytes128;
}

function isLargest(value: bigint): boolean {
  return value > (BN254_BASE_MODULUS - 1n) / 2n;
}

function isLargestFp2(value: Readonly<{ c0: bigint; c1: bigint }>): boolean {
  return isLargest(value.c1) || (value.c1 === 0n && isLargest(value.c0));
}

function invalidPoint(): never {
  throw new ClientError("CLIENT_PROOF_POINT", { details: { field: "proof.b" } });
}
