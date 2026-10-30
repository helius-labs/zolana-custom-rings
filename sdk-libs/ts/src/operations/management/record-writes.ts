import { RingError } from "../../protocol/error.js";
import { LIST_IDS, ListId, listWriter, recordBit } from "../../protocol/membership/policy.js";

/** Rust `ListWrite`, the lists one write sets and clears. */
export interface ListWrite {
  readonly set: readonly ListId[];
  readonly clear: readonly ListId[];
}

/** Rust `ListSet::MEMBER_WRITES`, the escrow list fills only through an escrow write. */
export const MEMBER_WRITABLE_LISTS: readonly ListId[] = Object.freeze(
  LIST_IDS.filter((id) => listWriter(id) === "member" && id !== ListId.escrow),
);
/** Rust `ListSet::AUTHORITY_WRITES`. */
export const AUTHORITY_WRITABLE_LISTS: readonly ListId[] = Object.freeze(
  LIST_IDS.filter((id) => listWriter(id) === "authority"),
);

/** Rust `ListWrite::new`, a write changes at least one list and never sets and clears one. */
export function listWrite(
  input: Readonly<{ set?: readonly ListId[]; clear?: readonly ListId[] }>,
): ListWrite {
  const set = Object.freeze([...new Set(input.set ?? [])]);
  const clear = Object.freeze([...new Set(input.clear ?? [])]);
  if (set.length + clear.length === 0) throw listWriteInvalid("Empty");
  if (set.some((id) => clear.includes(id))) throw listWriteInvalid("SetAndCleared");
  return Object.freeze({ set, clear });
}

export function listMask(write: ListWrite): bigint {
  return listBits([...write.set, ...write.clear]);
}

export function listBits(ids: readonly ListId[]): bigint {
  return ids.reduce((bits, id) => bits | recordBit(id), 0n);
}

/** Rust `check_writer`, every masked list is the writer's. */
export function checkWriter(write: ListWrite, writer: "member" | "authority"): void {
  const writable = writer === "member" ? MEMBER_WRITABLE_LISTS : AUTHORITY_WRITABLE_LISTS;
  const refused = [...write.set, ...write.clear].find((id) => !writable.includes(id));
  if (refused !== undefined)
    throw new RingError("RING_LIST_WRITER_UNAUTHORIZED", { details: { listId: refused, writer } });
}

function listWriteInvalid(reason: "Empty" | "SetAndCleared"): RingError {
  return new RingError("RING_LIST_WRITE_INVALID", { details: { reason } });
}
