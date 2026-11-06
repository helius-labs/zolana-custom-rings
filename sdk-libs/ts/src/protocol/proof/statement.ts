import {
  hashBytes,
  hashChain4,
  checkedBytes,
  bigIntBytes,
  bytesKey,
  rightAlign,
} from "@heliuslabs/spr/internal";
import type { Bytes16, Bytes32, Bytes33, Bytes64 } from "@heliuslabs/spr/interface";
import { poseidon } from "@heliuslabs/spr/keypair";
import { packDisclosure } from "../../crypto/audit/audit.js";
import { u32Field } from "../../crypto/error.js";
import { packBytesBe } from "../../crypto/derivation/hasher.js";
import { auditLayoutValue, type AuditLayout } from "../codec/ring-disclosure-layout.js";

import { RingDomain, domainField } from "../../crypto/derivation/ring-domain.js";
import { RingError } from "../error.js";
import {
  ANONYMOUS_PARTIES,
  RingTransactData,
  isAnonymousFrame,
  isDelegateRail,
  taggedX25519,
  type RingOutput,
} from "../transaction/transact.js";
import { N_PUBLIC_SLOTS } from "../transaction/spp.js";
import { TRACKING_CAPACITY } from "../membership/tracking.js";

/** The values every transfer statement opens with, Rust `AuditHead`. */
export interface AuditHead {
  readonly firstNullifier: Bytes32;
  /** `hash_bytes` of the ring program id. */
  readonly ringId: Bytes32;
  readonly txViewingU: Bytes32;
  /** `0x04 ‖ u` as the ring config stores it. */
  readonly auditorPubkey: Bytes33;
  /** `envelope_ct`, the transmitted length is the stream layout's. */
  readonly envelope: Uint8Array;
  readonly salt: Bytes16;
  readonly layout: AuditLayout;
}

/** The rail's own statement values, Rust `TransferFamily`. */
export type TransferFamily =
  /** The signer, in-proof and authority rails. */
  | Readonly<{
      kind: "confidential";
      inProof: boolean;
      delegate: boolean;
      /** The in-proof owner's identity, zero on the signer and authority rails. */
      sender: Bytes32;
    }>
  /** The anonymous frame, the head's layout picks the entry disclosure. */
  | Readonly<{
      kind: "anonymous";
      /** `solana_owner_identity` of the payer, each co-signer and the exit destination, zero when absent. */
      partyIdentities: readonly Bytes32[];
      /** No hidden sender exists, every live owner is a published signer. */
      publicOwners: boolean;
      /** Set only under the authority tag. */
      delegate: boolean;
    }>;

export interface SignerBinding {
  readonly count: number;
  readonly chain: Bytes32;
}

/** Zero where the frame reads none, Rust `TransferRoots`. */
export interface TransferRoots {
  readonly policyHash: Bytes32;
  readonly ownRoot: Bytes32;
  readonly curatorRoot: Bytes32;
  readonly trackingRoot: Bytes32;
}

/** One ring transfer's proof, Rust `TransferStatement`. */
export interface TransferStatement {
  readonly head: AuditHead;
  readonly family: TransferFamily;
  readonly approvalMask: number;
  /** Zero unless the frame discloses totals to a co-signer. */
  readonly approvalTotals: Bytes32;
  /** 5 bits per signer of the run, low bits first, zero past it. */
  readonly signerDataCounts: bigint;
  /** `R` is zero, the frame takes public funds alone. */
  readonly noSpend: boolean;
  /** The `m` published slots. */
  readonly outputs: readonly StatementOutput[];
  /** `N`, every per-slot chain is zero-filled to it. */
  readonly capacity: number;
  /** `n`, the frame's nullifier count. */
  readonly inputCount: number;
  /** The digest of the nullifiers the program forwards to SPP, `inputNullifierChain`. */
  readonly inputNullifierChain: Bytes32;
  readonly privateTxHash: Bytes32;
  /** Default on the in-proof and authority rails and on an empty run. */
  readonly signers: SignerBinding;
  readonly roots: TransferRoots;
  /** SPP's public asset fields, zero past the used slots. */
  readonly publicAssets: readonly Bytes32[];
  /** SPP's signed nets, a withdrawal is `q - |amount|`. */
  readonly publicAmounts: readonly Bytes32[];
  /** Gross withdrawals per slot as right aligned u128. */
  readonly publicGross: readonly Bytes32[];
  readonly withdrawalHash: Bytes32;
}

/** The slot fields the statement chains. */
export type StatementOutput = Pick<RingOutput, "hash" | "record" | "tail">;

/** An application of `count` writes, Rust `ApplyRecordsStatement`. */
export interface ApplyRecordsStatement {
  readonly oldRoot: Bytes32;
  readonly newRoot: Bytes32;
  readonly oldNextIndex: number;
  readonly newNextIndex: number;
  /** `chain_start` of the registry and revision. */
  readonly chainStart: Bytes32;
  /** The chain past the last write. */
  readonly chainEnd: Bytes32;
  readonly count: bigint;
  /** Set exactly when a write tightens a policy field or changes an asset limit. */
  readonly restrictive: boolean;
  /** Absent on a public batch, the public apply key binds no tracking section. */
  readonly private?: PrivateWrites;
}

/** Rust `PrivateWrites`. */
export interface PrivateWrites {
  /** Bit `i` marks write `i` a private owner write whose member's row the circuit opens, never zero. */
  readonly privateWrites: number;
  /** The pinned tracking registry's root at the batch's `tracking_revision`. */
  readonly trackingRoot: Bytes32;
}

/** An application of named enrollments, Rust `ApplyEnrollmentsStatement`. */
export interface ApplyEnrollmentsStatement {
  readonly oldRoot: Bytes32;
  readonly newRoot: Bytes32;
  /** u64, at most `TRACKING_CAPACITY`. */
  readonly oldNextIndex: bigint;
  readonly newNextIndex: bigint;
  /** `chain_start` of the registry and revision. */
  readonly chainStart: Bytes32;
  /** The chain past the last entry. */
  readonly chainEnd: Bytes32;
  readonly count: bigint;
}

/** The auditor envelope of an enrolled nullifier key, Rust `RegisterKeyStatement`. */
export interface RegisterKeyStatement {
  /** The tracking registry's. */
  readonly ringId: Bytes32;
  /** The owner identity of the signing member. */
  readonly member: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly listTag: Bytes32;
  readonly auditorPubkey: Bytes33;
  readonly ephU: Bytes32;
  readonly ciphertext: Bytes64;
}

export function transferStatementElements(statement: TransferStatement): readonly Bytes32[] {
  const { outputs, family, publicAssets, publicAmounts, publicGross, capacity } = statement;
  if (
    publicAssets.length !== N_PUBLIC_SLOTS ||
    publicAmounts.length !== N_PUBLIC_SLOTS ||
    publicGross.length !== N_PUBLIC_SLOTS
  )
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "publicSlots", expected: N_PUBLIC_SLOTS },
    });
  if (outputs.length > capacity)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "outputs", expected: capacity, actual: outputs.length },
    });
  // `in_proof`, `hidden`, `delegate`, a clear set is the signer rail.
  const railBits =
    family.kind === "confidential"
      ? [bit(family.inProof), bit(false), bit(family.delegate)]
      : [bit(false), bit(!family.publicOwners && !family.delegate), bit(family.delegate)];
  const sender =
    family.kind === "confidential"
      ? checkedBytes<Bytes32>(family.sender, 32, "sender")
      : ZERO_FIELD;
  const parties =
    family.kind === "confidential"
      ? Array.from({ length: ANONYMOUS_PARTIES }, () => ZERO_FIELD)
      : checkedParties(family.partyIdentities);
  const elements: Bytes32[] = [
    ...auditHeadElements(statement.head),
    ...railBits,
    rightAlign(Uint8Array.of(statement.approvalMask)),
    statement.approvalTotals,
    bigIntBytes(statement.signerDataCounts) as Bytes32,
    bit(statement.noSpend),
    u32Field(outputs.length, "output count"),
    filledChain(
      outputs.map((output) => output.hash),
      capacity,
    ),
    recordChain(outputs, capacity),
    tailChain(outputs, capacity),
    u32Field(statement.inputCount, "input count"),
    checkedBytes<Bytes32>(statement.inputNullifierChain, 32, "input nullifier chain"),
    checkedBytes<Bytes32>(statement.privateTxHash, 32, "private tx hash"),
    sender,
    ...parties,
    u32Field(statement.signers.count, "signer count"),
    checkedBytes<Bytes32>(statement.signers.chain, 32, "signer chain"),
    checkedBytes<Bytes32>(statement.roots.policyHash, 32, "policy hash"),
    checkedBytes<Bytes32>(statement.roots.ownRoot, 32, "own root"),
    checkedBytes<Bytes32>(statement.roots.curatorRoot, 32, "curator root"),
    checkedBytes<Bytes32>(statement.roots.trackingRoot, 32, "tracking root"),
    ...publicAssets.flatMap((asset, slot) => [
      checkedBytes<Bytes32>(asset, 32, "public asset"),
      checkedBytes<Bytes32>(publicAmounts[slot] as Bytes32, 32, "public amount"),
      checkedBytes<Bytes32>(publicGross[slot] as Bytes32, 32, "public gross"),
    ]),
    checkedBytes<Bytes32>(statement.withdrawalHash, 32, "withdrawal hash"),
  ];
  // The nonzero length counts itself and closes the chain, HashChain4 pads zeros.
  return [...elements, bigIntBytes(BigInt(elements.length + 1)) as Bytes32];
}

export function transferStatementHash(statement: TransferStatement): Bytes32 {
  return chain(transferStatementElements(statement));
}

/** What the program supplies beside the data for the transfer statement, Rust `TransferBinding`. */
export interface TransferBinding {
  /** `hash_bytes` of the ring program id. */
  readonly ringId: Bytes32;
  readonly auditorPubkey: Bytes33;
  /** The in-proof owner's identity, zero otherwise. */
  readonly sender: Bytes32;
  /** Zero off the anonymous frame. */
  readonly partyIdentities: readonly Bytes32[];
  /** Default on the in-proof and authority rails. */
  readonly signers: SignerBinding;
  readonly roots: TransferRoots;
  readonly publicAssets: readonly Bytes32[];
  readonly publicAmounts: readonly Bytes32[];
  readonly publicGross: readonly Bytes32[];
  readonly withdrawalHash: Bytes32;
}

/** The statement the transfer proof is verified against, Rust `ParsedTransact::transfer_statement`. */
export function ringTransferStatement(
  data: RingTransactData,
  binding: TransferBinding,
): TransferStatement {
  const stream = RingTransactData.streamLayout(data);
  const family: TransferFamily = isAnonymousFrame(data.rail)
    ? {
        kind: "anonymous",
        partyIdentities: binding.partyIdentities,
        publicOwners: data.publicOwners,
        delegate: isDelegateRail(data.rail),
      }
    : {
        kind: "confidential",
        inProof: data.inProofOwner !== undefined,
        delegate: data.rail === "delegate",
        sender: data.inProofOwner === undefined ? ZERO_FIELD : binding.sender,
      };
  return Object.freeze({
    head: Object.freeze({
      firstNullifier: RingTransactData.firstNullifier(data),
      ringId: binding.ringId,
      txViewingU: data.txViewingU,
      auditorPubkey: binding.auditorPubkey,
      envelope: data.envelope,
      salt: data.salt,
      layout: RingTransactData.auditLayout(data),
    }),
    family,
    approvalMask: data.approval,
    approvalTotals: data.extensions.approvalTotals ?? ZERO_FIELD,
    signerDataCounts: data.extensions.signerDataCounts ?? 0n,
    noSpend: data.noSpend,
    outputs: data.outputs,
    capacity: stream.capacity,
    inputCount: data.nullifiers.length,
    inputNullifierChain: inputNullifierChain(data.nullifiers, stream.key.class),
    privateTxHash: data.privateTxHash,
    signers: binding.signers,
    roots: binding.roots,
    publicAssets: binding.publicAssets,
    publicAmounts: binding.publicAmounts,
    publicGross: binding.publicGross,
    withdrawalHash: binding.withdrawalHash,
  });
}

/** The `n` published nullifiers zero filled to the key's input class `C`, refused past it. */
export function inputNullifierSlots(
  nullifiers: readonly Bytes32[],
  capacity: number,
): readonly Bytes32[] {
  if (nullifiers.length > capacity)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "inputNullifiers", expected: capacity, actual: nullifiers.length },
    });
  return filled(
    nullifiers.map((nullifier) => checkedBytes<Bytes32>(nullifier, 32, "nullifier")),
    capacity,
  );
}

/** `HashChain4([n, nullifier_0, .., nullifier_(C-1)])`, Rust `ParsedTransact::input_nullifier_chain`. */
export function inputNullifierChain(nullifiers: readonly Bytes32[], capacity: number): Bytes32 {
  return chain([
    u32Field(nullifiers.length, "input count"),
    ...inputNullifierSlots(nullifiers, capacity),
  ]);
}

/** SPP's owner signer run by owner identity deduplicated by first occurrence, wider than `slots` refused, Rust `SignerSet::new`. */
export function signerBinding(identities: readonly Bytes32[], slots: number): SignerBinding {
  const unique = identities.filter(
    (identity, index) =>
      identities.findIndex((seen) => bytesKey(seen) === bytesKey(identity)) === index,
  );
  if (unique.length > slots)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "signers", expected: slots, actual: unique.length },
    });
  // An empty run binds zero on every rail, the program and the circuit agree on it.
  if (unique.length === 0) return Object.freeze({ count: 0, chain: ZERO_FIELD });
  return Object.freeze({ count: unique.length, chain: filledChain(unique, slots) });
}

/**
 * `[CRAP, old_root, new_root, old_next, new_next, chain_start, chain_end, count, restrictive]`,
 * a private batch appends `[private_writes, tracking_root]`.
 */
export function applyRecordsStatementElements(
  statement: ApplyRecordsStatement,
): readonly Bytes32[] {
  const head = {
    ...statement,
    oldNextIndex: BigInt(statement.oldNextIndex),
    newNextIndex: BigInt(statement.newNextIndex),
  };
  return [
    ...applyStatementHead(RingDomain.applyRecords, head, U32_MAX),
    u64Field(statement.restrictive ? 1n : 0n, "restrictive"),
    ...(statement.private === undefined
      ? []
      : [
          u64Field(BigInt(statement.private.privateWrites), "private writes", U16_MAX),
          checkedBytes<Bytes32>(statement.private.trackingRoot, 32, "tracking root"),
        ]),
  ];
}

export function applyRecordsStatementHash(statement: ApplyRecordsStatement): Bytes32 {
  return chain(applyRecordsStatementElements(statement));
}

/** `[CRTA, old_root, new_root, old_next, new_next, chain_start, chain_end, count]`. */
export function applyEnrollmentsStatementElements(
  statement: ApplyEnrollmentsStatement,
): readonly Bytes32[] {
  return applyStatementHead(RingDomain.applyEnrollments, statement, TRACKING_CAPACITY);
}

export function applyEnrollmentsStatementHash(statement: ApplyEnrollmentsStatement): Bytes32 {
  return chain(applyEnrollmentsStatementElements(statement));
}

function applyStatementHead(
  domain: RingDomain,
  statement: ApplyEnrollmentsStatement,
  indexMax: bigint,
): readonly Bytes32[] {
  return [
    domainField(domain),
    checkedBytes<Bytes32>(statement.oldRoot, 32, "old root"),
    checkedBytes<Bytes32>(statement.newRoot, 32, "new root"),
    u64Field(statement.oldNextIndex, "old next index", indexMax),
    u64Field(statement.newNextIndex, "new next index", indexMax),
    checkedBytes<Bytes32>(statement.chainStart, 32, "chain start"),
    checkedBytes<Bytes32>(statement.chainEnd, 32, "chain end"),
    u64Field(statement.count, "count"),
  ];
}

/** `[CRRG, ring_id, member, nullifier_pk, list_tag, aud0, aud1, eph0, eph1, hash_bytes(ciphertext)]`. */
export function registerKeyStatementElements(statement: RegisterKeyStatement): readonly Bytes32[] {
  return [
    domainField(RingDomain.registerKey),
    checkedBytes<Bytes32>(statement.ringId, 32, "ring id"),
    checkedBytes<Bytes32>(statement.member, 32, "member"),
    checkedBytes<Bytes32>(statement.nullifierPk, 32, "nullifier pk"),
    checkedBytes<Bytes32>(statement.listTag, 32, "list tag"),
    ...packedKey(checkedBytes<Bytes33>(statement.auditorPubkey, 33, "auditor pubkey")),
    ...packedKey(taggedX25519(statement.ephU)),
    hashBytes(checkedBytes<Bytes64>(statement.ciphertext, 64, "ciphertext")) as Bytes32,
  ];
}

export function registerKeyStatementHash(statement: RegisterKeyStatement): Bytes32 {
  return chain(registerKeyStatementElements(statement));
}

const ZERO_FIELD = new Uint8Array(32) as Bytes32;
const U16_MAX = 0xffffn;
const U32_MAX = 0xffff_ffffn;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** `[CRTX, n0, ring_id, txpk0, txpk1, aud0, aud1, digest(envelope_ct), salt, layout]`. */
function auditHeadElements(head: AuditHead): readonly Bytes32[] {
  return [
    domainField(RingDomain.transferStatement),
    checkedBytes<Bytes32>(head.firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(head.ringId, 32, "ring id"),
    ...packedKey(taggedX25519(head.txViewingU)),
    ...packedKey(checkedBytes<Bytes33>(head.auditorPubkey, 33, "auditor pubkey")),
    ciphertextDigest(head.envelope),
    rightAlign(checkedBytes<Bytes16>(head.salt, 16, "salt")),
    rightAlign(Uint8Array.of(auditLayoutValue(head.layout))),
  ];
}

/** The length tag closes the trailing zero ambiguity of `HashChain4`. */
export function ciphertextDigest(ciphertext: Uint8Array): Bytes32 {
  return poseidon([
    u32Field(ciphertext.length, "ciphertext length"),
    chain(packDisclosure(ciphertext)),
  ]) as Bytes32;
}

/** `HashChain4(hash_bytes(record_i))`, untagged since every record is one length. */
export function recordChain(
  outputs: readonly Pick<RingOutput, "record">[],
  capacity: number,
): Bytes32 {
  return filledChain(
    outputs.map((output) => hashBytes(output.record) as Bytes32),
    capacity,
  );
}

/** `HashChain4(hash_bytes(tail_i))`, zero while no slot carries a tail. */
export function tailChain(outputs: readonly Pick<RingOutput, "tail">[], capacity: number): Bytes32 {
  const tails = outputs.flatMap((output) => (output.tail === undefined ? [] : [output.tail]));
  if (tails.length === 0) return ZERO_FIELD;
  return filledChain(
    tails.map((tail) => hashBytes(tail) as Bytes32),
    capacity,
  );
}

function checkedParties(parties: readonly Bytes32[]): readonly Bytes32[] {
  if (parties.length !== ANONYMOUS_PARTIES)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "partyIdentities", expected: ANONYMOUS_PARTIES, actual: parties.length },
    });
  return parties.map((party) => checkedBytes<Bytes32>(party, 32, "party"));
}

/** Zero past the published values, `output_count` keeps the length apart. */
function filled(values: readonly Bytes32[], width: number): readonly Bytes32[] {
  return [...values, ...Array.from({ length: width - values.length }, () => ZERO_FIELD)];
}

function filledChain(values: readonly Bytes32[], width: number): Bytes32 {
  return chain(filled(values, width));
}

function packedKey(key: Bytes33): readonly Bytes32[] {
  return packBytesBe(key) as Bytes32[];
}

function chain(values: readonly Bytes32[]): Bytes32 {
  return hashChain4(values) as Bytes32;
}

function bit(value: boolean): Bytes32 {
  return rightAlign(Uint8Array.of(value ? 1 : 0));
}

function u64Field(value: bigint, name: string, maximum = U64_MAX): Bytes32 {
  if (typeof value !== "bigint" || value < 0n || value > maximum)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name, minimum: "0", maximum: maximum.toString() },
    });
  return bigIntBytes(value) as Bytes32;
}
