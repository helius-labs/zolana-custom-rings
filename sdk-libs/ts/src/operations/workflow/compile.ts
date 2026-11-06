import { blockhash, getTransactionSize, isSignerRole } from "@solana/kit";
import {
  InterfaceError,
  TRANSACTION_SIZE_LIMIT,
  type Instruction,
  type Shape,
} from "@heliuslabs/spr/interface";
import {
  compileUnsignedTransaction,
  type TransactionCompilerOptions,
} from "@heliuslabs/spr/internal";

import { RingError } from "../../protocol/error.js";

type LatestBlockhash = TransactionCompilerOptions["lifetime"];

/** Any well-formed blockhash sizes a message the same. */
export const SIZE_PROBE_LIFETIME: LatestBlockhash = Object.freeze({
  blockhash: blockhash("11111111111111111111111111111111"),
  lastValidBlockHeight: 0n,
});

/** The transaction fits version 1, checked before any proof or signature exists. */
export function checkTransactionFits(options: Omit<TransactionCompilerOptions, "lifetime">): void {
  compileUnsignedTransaction({ ...options, lifetime: SIZE_PROBE_LIFETIME });
}

/** Rust `v1::MAX_ADDRESSES`. */
export const MAX_TRANSACTION_ADDRESSES = 64;

/** Rust `v1::MAX_SIGNATURES`. */
export const MAX_TRANSACTION_SIGNATURES = 12;

/** Rust `v1::MAX_INSTRUCTIONS`. */
export const MAX_TRANSACTION_INSTRUCTIONS = 64;

/** Rust `TransactionSize`. */
export interface TransactionSize {
  readonly bytes: number;
  readonly addresses: number;
}

export function fitsOneTransaction(size: TransactionSize): boolean {
  return size.bytes <= TRANSACTION_SIZE_LIMIT && size.addresses <= MAX_TRANSACTION_ADDRESSES;
}

/** Past a limit the count still reads, the kit refuses to compile past the address ceiling. */
export function transactionSize(
  options: Omit<TransactionCompilerOptions, "lifetime">,
): TransactionSize {
  const all = [...(options.setupInstructions ?? []), ...options.instructions];
  const metas = all.flatMap((instruction) => instruction.accounts ?? []);
  const unique = new Set([
    options.feePayer,
    ...all.map((instruction) => instruction.programAddress),
    ...metas.map((account) => account.address),
  ]);
  const excess = unique.size - MAX_TRANSACTION_ADDRESSES;
  const left = new Set<string>();
  if (excess > 0)
    for (const { address, role } of metas)
      if (
        left.size < excess &&
        !isSignerRole(role) &&
        address !== options.feePayer &&
        !all.some((instruction) => instruction.programAddress === address)
      )
        left.add(address);
  // A setup meta can be the one left out, the kit refuses a message past the ceiling either way.
  const kept = (instructions: readonly Instruction[]): readonly Instruction[] =>
    instructions.map((instruction) => ({
      ...instruction,
      accounts: (instruction.accounts ?? []).filter((account) => !left.has(account.address)),
    }));
  // A left out address costs its key and one index per meta.
  const leftOut = 32 * left.size + metas.filter((account) => left.has(account.address)).length;
  return Object.freeze({
    bytes:
      compiledBytes({
        ...options,
        ...(options.setupInstructions === undefined
          ? {}
          : { setupInstructions: kept(options.setupInstructions) }),
        instructions: kept(options.instructions),
      }) + leftOut,
    addresses: unique.size,
  });
}

/** The compiler's header count, a key two roles share or only setup adds signs once. */
export function transactionSignatures(
  options: Pick<
    Omit<TransactionCompilerOptions, "lifetime">,
    "feePayer" | "instructions" | "setupInstructions"
  >,
): number {
  const all = [...(options.setupInstructions ?? []), ...options.instructions];
  return new Set([
    options.feePayer,
    ...all
      .flatMap((instruction) => instruction.accounts ?? [])
      .filter((account) => isSignerRole(account.role))
      .map((account) => account.address),
  ]).size;
}

function compiledBytes(options: Omit<TransactionCompilerOptions, "lifetime">): number {
  try {
    return getTransactionSize(
      compileUnsignedTransaction({ ...options, lifetime: SIZE_PROBE_LIFETIME }),
    );
  } catch (cause) {
    const size = cause instanceof InterfaceError ? cause.details?.["size"] : undefined;
    if (typeof size !== "number") throw cause;
    return size;
  }
}

/** Rust `Unwitnessed::check_size`, checked before approval and any proof. */
export function checkTransferFits(
  shape: Shape,
  options: Omit<TransactionCompilerOptions, "lifetime">,
): void {
  try {
    checkTransactionFits(options);
  } catch (cause) {
    if (!(cause instanceof InterfaceError) || cause.code !== "INTERFACE_TRANSACTION_TOO_LARGE")
      throw cause;
    throw new RingError("RING_TRANSFER_TOO_WIDE", {
      details: {
        inputs: shape.inputs,
        outputs: shape.outputs,
        size: cause.details?.["size"],
        limit: TRANSACTION_SIZE_LIMIT,
      },
      cause,
    });
  }
}
