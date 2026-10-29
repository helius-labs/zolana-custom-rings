import type { Address, MessagePartialSigner } from "@solana/kit";

import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { addressBytes, copyBytes, indexerScalars } from "@heliuslabs/zolana/internal";

import { RingError } from "../../protocol/error.js";
import { mintPolicyField, type MintPolicy } from "../../protocol/membership/mint-policy.js";
import { checkMember } from "../../protocol/membership/member-opening.js";
import {
  memberOfTag,
  recordBit,
  walletGrantMember,
  type ListId,
  type Member,
} from "../../protocol/membership/policy.js";
import { ENROLMENT_LISTS, signRecordUpdate } from "../../protocol/ring-rpc/record-update.js";
import type {
  ReaderAccess,
  RecordUpdateEntry,
  SubmitRecordUpdateRequest,
} from "../../protocol/ring-rpc/ring-rpc-types.js";
import { checkedReaderKey, readerKeyMember, type ReaderKey } from "./reader-access.js";
import { checkWriter, listBits, listMask, listWrite, type ListWrite } from "./record-writes.js";

/** The writer refuses the update after `validUntilSlot`. */
export interface RecordUpdateTarget {
  /** The cluster the writer serves. */
  readonly genesisHash: Bytes32;
  readonly ringProgramId: Address;
  /** The ring's own `StorageRegistry`. */
  readonly registry: Address;
  readonly validUntilSlot: bigint;
}

export type EscrowEntry = Extract<RecordUpdateEntry, { kind: "escrow" }>;

/** Rust `WalletRecordUpdate`, signed by the wallet, every entry names the wallet. */
export class WalletRecordUpdate {
  readonly #target: RecordUpdateTarget;
  readonly #wallet: Address;
  readonly #member: Member;
  #entries: readonly RecordUpdateEntry[] = Object.freeze([]);
  #awaitedLists = 0n;

  constructor(input: RecordUpdateTarget & Readonly<{ wallet: Address }>) {
    this.#target = input;
    this.#wallet = input.wallet;
    this.#member = memberOfTag(addressBytes(input.wallet, "wallet"));
  }

  withLists(write: ListWrite): WalletRecordUpdate {
    const lists = listWrite(write);
    checkWriter(lists, "member");
    return this.#with({
      kind: "write",
      mintPolicy: null,
      member: indexerScalars.hash(this.#member),
      mask: listMask(lists),
      value: listBits(lists.set),
    });
  }

  /** Sets or clears the `reader` list of the record `walletGrantMember(wallet, readerKeyMember(reader))` keys. */
  withWalletGrant(reader: ReaderKey, access: ReaderAccess): WalletRecordUpdate {
    const member = readerKeyMember(checkedReaderKey(reader));
    walletGrantMember(this.#member, member);
    return this.#with({
      kind: "walletGrant",
      wallet: indexerScalars.hash(this.#member),
      reader: indexerScalars.hash(member),
      access,
    });
  }

  /** `escrow` comes from `KeyRegistration.prove` for this wallet. */
  withEscrow(escrow: EscrowEntry): WalletRecordUpdate {
    if (escrow.member !== indexerScalars.hash(this.#member)) throw invalid("EscrowMember");
    return this.#with(escrow);
  }

  /** Rust `WalletRecordUpdate::awaiting_authority`, held until the config authority sets every list. */
  awaitingAuthority(lists: readonly ListId[]): WalletRecordUpdate {
    if (lists.length === 0 || lists.some((list) => !ENROLMENT_LISTS.includes(list)))
      throw invalid("EnrolmentLists");
    const next = this.#copy(this.#entries);
    next.#awaitedLists = lists.reduce((bits, list) => bits | recordBit(list), 0n);
    return next;
  }

  entries(): readonly RecordUpdateEntry[] {
    return this.#entries;
  }

  async sign(wallet: MessagePartialSigner): Promise<SubmitRecordUpdateRequest> {
    if (wallet.address !== this.#wallet) throw invalid("Signer");
    return signEntries(this.#target, this.#entries, wallet, this.#awaitedLists);
  }

  #with(entry: RecordUpdateEntry): WalletRecordUpdate {
    return this.#copy([...this.#entries, Object.freeze(entry)]);
  }

  #copy(entries: readonly RecordUpdateEntry[]): WalletRecordUpdate {
    const next = new WalletRecordUpdate({ ...this.#target, wallet: this.#wallet });
    next.#entries = Object.freeze(entries);
    next.#awaitedLists = this.#awaitedLists;
    return next;
  }
}

/** Rust `AuthorityRecordUpdate`, signed by the config authority, a write may name any record. */
export class AuthorityRecordUpdate {
  readonly #target: RecordUpdateTarget;
  readonly #authority: Address;
  #entries: readonly RecordUpdateEntry[] = Object.freeze([]);

  constructor(input: RecordUpdateTarget & Readonly<{ authority: Address }>) {
    this.#target = input;
    this.#authority = input.authority;
  }

  /** `member` is any record key, an owner identity or an asset. */
  withWrite(member: Member, write: ListWrite): AuthorityRecordUpdate {
    const lists = listWrite(write);
    checkWriter(lists, "authority");
    return this.#with({
      kind: "write",
      mintPolicy: null,
      member: indexerScalars.hash(checkMember(member)),
      mask: listMask(lists),
      value: listBits(lists.set),
    });
  }

  /** Replaces all mint settings, zero values clear them. */
  withMintPolicy(member: Member, mintPolicy: MintPolicy): AuthorityRecordUpdate {
    mintPolicyField(mintPolicy);
    return this.#with({
      kind: "write",
      mintPolicy: Object.freeze({ ...mintPolicy }),
      member: indexerScalars.hash(checkMember(member)),
      mask: 0n,
      value: 0n,
    });
  }

  entries(): readonly RecordUpdateEntry[] {
    return this.#entries;
  }

  /** The writer refuses a signer other than the config authority. */
  async sign(authority: MessagePartialSigner): Promise<SubmitRecordUpdateRequest> {
    if (authority.address !== this.#authority) throw invalid("Signer");
    return signEntries(this.#target, this.#entries, authority);
  }

  #with(entry: RecordUpdateEntry): AuthorityRecordUpdate {
    const next = new AuthorityRecordUpdate({ ...this.#target, authority: this.#authority });
    next.#entries = Object.freeze([...this.#entries, Object.freeze(entry)]);
    return next;
  }
}

function signEntries(
  target: RecordUpdateTarget,
  entries: readonly RecordUpdateEntry[],
  signer: MessagePartialSigner,
  awaitedLists = 0n,
): Promise<SubmitRecordUpdateRequest> {
  if (entries.length === 0) throw invalid("Empty");
  return signRecordUpdate(
    {
      registry: target.registry,
      update: Object.freeze({
        genesisHash: indexerScalars.hash(
          copyBytes(target.genesisHash, 32, "genesisHash") as Bytes32,
        ),
        ring: target.ringProgramId,
        entries,
        validUntilSlot: target.validUntilSlot,
        ...(awaitedLists === 0n ? {} : { awaitedLists }),
      }),
    },
    signer,
  );
}

function invalid(reason: string): RingError {
  return new RingError("RING_RECORD_UPDATE_INVALID", { details: { reason } });
}
