import { CUSTOM_RING_PROOF_LENGTH } from "../proof/custom-ring-proof.js";
import { Reader, encodeBase58, ZERO_32, equalBytes } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import { RING_RULE_SLOTS, RING_SOURCE_SLOTS } from "../../rpc/prover/types.js";
import { ROOT_HISTORY } from "../membership/member-registry.js";

import { RingError } from "../error.js";

/** Mirrors Rust `RingMode`, set once at creation and never cleared. */
export type RingMode = "confidential" | "confidentialEscrow" | "anonymous";

/** Rust `RingRoles`, nonzero keys pairwise distinct with the delegate. */
export interface RingRoles {
  /** Rotates every role and appoints the delegate. */
  readonly admin: Address;
  /** Signs `UpdatePolicy` and the authority record updates Ring RPC accepts. */
  readonly policy: Address;
  readonly pauser: Address;
  /** Signs `SetCoSigner` and `ClearCoSigner`. */
  readonly cosignAdmin: Address;
}

/** Rust `RingRole`, the role `UpdateAuthority` rotates. */
export type RingAuthorityRole = keyof RingRoles;

/** Rust `RingRole` tags. */
export const RING_ROLE_BYTES: Readonly<Record<RingAuthorityRole, number>> = Object.freeze({
  admin: 0,
  policy: 1,
  pauser: 2,
  cosignAdmin: 3,
});

/** `RingRoles` field order. */
export const RING_ROLES: readonly RingAuthorityRole[] = Object.freeze([
  "admin",
  "policy",
  "pauser",
  "cosignAdmin",
]);

/** Rust `CustomRingCoSigner`, the signer's `CoSigner` record. */
export interface RingCoSigner {
  readonly signer: Address;
  /** `RING_COSIGN_*` bits. */
  readonly scope: number;
}

export const RING_COSIGN_TRANSFERS = 1;
export const RING_COSIGN_DEPOSITS = 2;
export const RING_COSIGN_WITHDRAWALS = 4;
export const RING_COSIGN_SCOPE_MASK = 7;

/** Mirrors Rust `SourceSlot`, slot `i` is empty (`listId === 0`) or serves list `i + 1`. */
export interface RingSourceSlot {
  readonly listId: number;
  /** The curator's member registry account, the zero address for the ring's own. */
  readonly registry: Address;
}

/** Rust `EncodedRuleTable`, counted rows without their zero padding. */
export interface EncodedRuleTable {
  readonly rules: readonly Bytes32[];
}

/** Rust `Root` as a mirror copied it. */
export interface StorageRegistryRoot {
  readonly hash: Bytes32;
  readonly revision: bigint;
  /** Zero on the current root. */
  readonly expiresAt: bigint;
}

/** Rust `RootMirror`, newest first, `undefined` where the registry held no root. */
export interface RootMirror {
  /** Absent before the first `SyncRoots`. */
  readonly registry?: Address;
  readonly roots: readonly (StorageRegistryRoot | undefined)[];
}

/** Rust `RingPolicy`, the ring's one account. */
export interface RingPolicy {
  readonly bump: number;
  readonly mode: RingMode;
  /** `mode === "confidentialEscrow"`, every output nullifier key is escrowed in the registry. */
  readonly keyEscrow: boolean;
  /** `RING_COSIGN_*` bits some `CoSigner` record covers, absent without a record. */
  readonly coSignerClasses?: number;
  readonly roles: RingRoles;
  readonly delegate?: Address;
  readonly auditorPublicKey: X25519PublicKey;
  /** The slot `Initialize` ran in. */
  readonly createdSlot: bigint;
  /** The ring's own `StorageRegistry`, the zero address on an audit-only ring bound to none. */
  readonly records: Address;
  /** Zero on an audit-only ring. */
  readonly policyHash: Bytes32;
  /** Rust `RingPolicy::has_policy`, a written `policyHash`. */
  readonly hasPolicy: boolean;
  readonly sources: readonly RingSourceSlot[];
  readonly rules: EncodedRuleTable;
  readonly generation: number;
  readonly generationSlot: bigint;
  readonly ownRoots: RootMirror;
  readonly curatorRoots: RootMirror;
}

export type RootMirrorKind = "own" | "curator";

/** Rust `GRACE_SLOTS`, the grace a new storage registry gives an outgoing root. */
export const GRACE_SLOTS = 750n;

const RING_MODES: readonly RingMode[] = ["confidential", "confidentialEscrow", "anonymous"];
export const RING_CO_SIGNER_DISCRIMINATOR = 14;
export const RING_CO_SIGNER_SIZE = 35;
const RING_COSIGN_CLASSES = [RING_COSIGN_TRANSFERS, RING_COSIGN_DEPOSITS, RING_COSIGN_WITHDRAWALS];
export const RING_POLICY_DISCRIMINATOR = 15;
export const RING_POLICY_SIZE = 4196;

/** Mirrors Rust `CoSigner::valid`, a nonzero signer under a valid scope. */
export function decodeRingCoSigner(data: Uint8Array): RingCoSigner & Readonly<{ bump: number }> {
  const reader = accountReader(data, {
    discriminator: RING_CO_SIGNER_DISCRIMINATOR,
    size: RING_CO_SIGNER_SIZE,
    code: "RING_CO_SIGNER_INVALID",
  });
  const signer = reader.bytes(32, "signer");
  const scope = reader.u8("scope");
  const bump = reader.u8("bump");
  reader.done();
  if (equalBytes(signer, ZERO_32) || !validScope(scope))
    throw new RingError("RING_CO_SIGNER_INVALID", { details: { scope } });
  return Object.freeze({ signer: encodeBase58(signer), scope, bump });
}

/** Mirrors Rust `RingPolicy::from_data`, a known mode and every rule row past its count zero. */
export function decodeRingPolicy(data: Uint8Array): RingPolicy {
  const reader = accountReader(data, {
    discriminator: RING_POLICY_DISCRIMINATOR,
    size: RING_POLICY_SIZE,
    code: "RING_POLICY_INVALID",
  });
  const bump = reader.u8("bump");
  const modeByte = reader.u8("mode");
  const mode = RING_MODES[modeByte];
  if (mode === undefined)
    throw new RingError("RING_POLICY_INVALID", { details: { mode: modeByte } });
  const counts = reader.bytes(RING_COSIGN_CLASSES.length, "coSigners");
  const roles = Object.fromEntries(
    RING_ROLES.map((role) => [role, encodeBase58(reader.bytes(32, role))]),
  ) as Record<RingAuthorityRole, Address>;
  const delegate = reader.bytes(32, "delegate");
  const auditorPublicKey = auditorKey(reader.bytes(33, "auditorPubkey") as Bytes33);
  const createdSlot = reader.u64("createdSlot");
  const records = encodeBase58(reader.bytes(32, "records"));
  const policy = readPolicyFields(reader, "RING_POLICY_INVALID");
  const ownRoots = readRootMirror(reader);
  const curatorRoots = readRootMirror(reader);
  reader.done();
  const classes = RING_COSIGN_CLASSES.reduce(
    (covered, bit, index) => (counts[index] === 0 ? covered : covered | bit),
    0,
  );
  return Object.freeze({
    bump,
    mode,
    keyEscrow: mode === "confidentialEscrow",
    ...(classes === 0 ? {} : { coSignerClasses: classes }),
    roles: Object.freeze(roles),
    ...(equalBytes(delegate, ZERO_32) ? {} : { delegate: encodeBase58(delegate) }),
    auditorPublicKey,
    createdSlot,
    records,
    ...policy,
    hasPolicy: !equalBytes(policy.policyHash, ZERO_32),
    ownRoots,
    curatorRoots,
  });
}

/** Rust `RingPolicy::curator`, the one curator registry the sources name. */
export function registryCurator(registry: Pick<RingPolicy, "sources">): Address | undefined {
  return registry.sources.find((source) => !isZeroAddress(source.registry))?.registry;
}

export function rootMirror(policy: RingPolicy, kind: RootMirrorKind): RootMirror {
  return kind === "own" ? policy.ownRoots : policy.curatorRoots;
}

/** Rust `RootMirror::root`, the current root or a retired one before its expiry. */
export function mirrorRoot(mirror: RootMirror, revision: bigint, slot: bigint): Bytes32 {
  const current = mirror.roots[0]?.revision;
  const root = mirror.roots.find(
    (entry) =>
      entry !== undefined &&
      entry.revision === revision &&
      (revision === current || slot < entry.expiresAt),
  );
  if (root === undefined)
    throw new RingError("RING_ROOT_NOT_MIRRORED", {
      details: { registry: mirror.registry, revision: revision.toString() },
    });
  return root.hash;
}

/** The newest root `SyncRoots` copied from `registry`, refused when the mirror holds another registry. */
export function mirrorCurrentRoot(mirror: RootMirror, registry: Address): StorageRegistryRoot {
  const current = mirror.roots[0];
  if (mirror.registry !== registry || current === undefined)
    throw new RingError("RING_ROOT_NOT_MIRRORED", {
      details: { registry, mirrored: mirror.registry },
    });
  return current;
}

export { CUSTOM_RING_PROOF_LENGTH };

export function checkedCustomRingProof(proof: Uint8Array): Uint8Array {
  if (proof.length !== CUSTOM_RING_PROOF_LENGTH) {
    throw new RingError("RING_PROOF_LENGTH", {
      details: { expected: CUSTOM_RING_PROOF_LENGTH, actual: proof.length },
    });
  }
  return new Uint8Array(proof);
}

function accountReader(
  data: Uint8Array,
  account: Readonly<{
    discriminator: number;
    size: number;
    code: AccountInvalidCode;
  }>,
): Reader {
  if (data.length !== account.size || data[0] !== account.discriminator)
    throw new RingError(account.code, {
      details: { length: data.length, discriminator: data[0] },
    });
  const reader = new Reader(data);
  reader.u8("discriminator");
  return reader;
}

/** A key the program would refuse to encrypt to reads as an invalid ring account. */
function auditorKey(bytes: Bytes33): X25519PublicKey {
  try {
    return X25519PublicKey.fromBytes(bytes);
  } catch (cause) {
    throw new RingError("RING_POLICY_INVALID", {
      details: { field: "auditorPubkey" },
      cause,
    });
  }
}

function validScope(scope: number): boolean {
  return scope !== 0 && (scope & ~RING_COSIGN_SCOPE_MASK) === 0;
}

type AccountInvalidCode = "RING_CO_SIGNER_INVALID" | "RING_POLICY_INVALID";

function readPolicyFields(reader: Reader, code: AccountInvalidCode) {
  const policyHash = reader.bytes(32, "policyHash") as Bytes32;
  const sources = Array.from({ length: RING_SOURCE_SLOTS }, () =>
    Object.freeze({
      listId: reader.u8("source.listId"),
      registry: encodeBase58(reader.bytes(32, "source.registry")),
    }),
  );
  const rules = readEncodedRuleTable(reader, code);
  const generation = reader.u32("generation");
  const generationSlot = reader.u64("generationSlot");
  return { policyHash, sources: Object.freeze(sources), rules, generation, generationSlot };
}

function readRootMirror(reader: Reader): RootMirror {
  const registry = reader.bytes(32, "mirror.registry");
  const roots = Array.from({ length: ROOT_HISTORY }, () => {
    const hash = reader.bytes(32, "mirror.root") as Bytes32;
    const revision = reader.u64("mirror.revision");
    const expiresAt = reader.u64("mirror.expiresAt");
    return equalBytes(hash, ZERO_32) ? undefined : Object.freeze({ hash, revision, expiresAt });
  });
  return Object.freeze({
    ...(equalBytes(registry, ZERO_32) ? {} : { registry: encodeBase58(registry) }),
    roots: Object.freeze(roots),
  });
}

/** Mirrors Rust `EncodedRuleTable::decode`, every slot past a count zero. */
function readEncodedRuleTable(reader: Reader, code: AccountInvalidCode): EncodedRuleTable {
  const rules = countedRows(reader, RING_RULE_SLOTS, "rules", code);
  return Object.freeze({ rules });
}

function countedRows(
  reader: Reader,
  slots: number,
  field: string,
  code: AccountInvalidCode,
): readonly Bytes32[] {
  const count = reader.u8(`${field}.count`);
  if (count > slots) throw new RingError(code, { details: { field, count } });
  const rows = Array.from({ length: slots }, () => reader.bytes(32, field) as Bytes32);
  if (rows.slice(count).some((row) => !equalBytes(row, ZERO_32)))
    throw new RingError(code, { details: { field, padding: true } });
  return Object.freeze(rows.slice(0, count));
}

function isZeroAddress(address: Address): boolean {
  return address === ZERO_ADDRESS;
}

const ZERO_ADDRESS = encodeBase58(ZERO_32);
