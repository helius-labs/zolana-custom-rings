import { blockhash } from "@solana/kit";
import { InterfaceError, TRANSACTION_SIZE_LIMIT, type Shape } from "@heliuslabs/zolana/interface";
import {
  compileUnsignedTransaction,
  type TransactionCompilerOptions,
} from "@heliuslabs/zolana/internal";

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
