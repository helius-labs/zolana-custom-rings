import type { AccountMeta, Address, Instruction } from "@solana/kit";

import {
  SYSTEM_PROGRAM,
  meta,
  signerAddress,
  type SignerAccount,
  Writer,
  addressBytes,
  protocolConfigAddress,
  ZERO_32,
  equalBytes,
} from "@heliuslabs/zolana/internal";
import { SHIELDED_POOL_PROGRAM_ID } from "@heliuslabs/zolana/interface";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  ringAuthAddress,
  ringCoSignerAddress,
  ringPolicyAddress,
} from "../../protocol/pda/index.js";
import { isSmallOrder } from "../../crypto/keys/x25519.js";

import {
  RING_COSIGN_SCOPE_MASK,
  RING_ROLE_BYTES,
  RING_ROLES,
  type RingAuthorityRole,
  type RingRoles,
} from "../../protocol/codec/ring-codecs.js";
import { ringProgramDataAddress } from "../../protocol/membership/config.js";
import { RingInstructionTag } from "../../protocol/transaction/instruction-tag.js";
import { RingError } from "../../protocol/error.js";
import {
  buildRuleTable,
  checkedListId,
  encodeRule,
  policySourceLists,
  type ListId,
  type RuleTable,
} from "../../protocol/membership/policy.js";
import { checkTransactionFits } from "../workflow/compile.js";

export { RingInstructionTag } from "../../protocol/transaction/instruction-tag.js";

const ACCOUNT_UNITS = 50_000;
/** One policy hash plus a curator registry load. */
const POLICY_UNITS = 150_000;
/** A ring proof, most also CPI into SPP and its own proof. */
const PROOF_UNITS = 1_400_000;

/** Rust `compute_unit_limit`, the budget one instruction of `tag` declares. */
export function ringComputeUnitLimit(tag: RingInstructionTag): number {
  switch (tag) {
    case RingInstructionTag.initialize:
      return 2 * ACCOUNT_UNITS + POLICY_UNITS;
    case RingInstructionTag.updatePolicy:
      return POLICY_UNITS;
    case RingInstructionTag.legacyTransact:
    case RingInstructionTag.legacyDelegateTransact:
    case RingInstructionTag.transfer:
    case RingInstructionTag.merge:
    case RingInstructionTag.authorityTransfer:
    case RingInstructionTag.deposit:
      return PROOF_UNITS;
    default:
      return ACCOUNT_UNITS;
  }
}

/** Rust `RingKind`, fixed for the ring's life. */
export type RingKind = "auditOnly" | "policy" | "anonymous" | "anonymousPolicy";

const RING_KIND_BYTES: Readonly<Record<RingKind, number>> = Object.freeze({
  auditOnly: 0,
  policy: 1,
  anonymous: 2,
  anonymousPolicy: 3,
});

function ringKindByte(kind: RingKind): number {
  if (!Object.hasOwn(RING_KIND_BYTES, kind))
    throw new RingError("RING_CONFIG_INVALID", { details: { reason: "kind", kind } });
  return RING_KIND_BYTES[kind];
}

/** Rust `Initialize`, the upgrade authority signs and names the four roles, the pool registers the ring in the same instruction. */
export async function initializeRingInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    auditorPublicKey: X25519PublicKey;
    kind: RingKind;
    roles: RingRoles;
    /** Required on a policy ring, an audit-only ring takes it for its withdrawal exemptions. */
    policy?: RingInitialPolicy;
  }>,
): Promise<Instruction> {
  if (isSmallOrder(input.auditorPublicKey))
    throw new RingError("RING_CONFIG_INVALID", { details: { reason: "InvalidAuditorPubkey" } });
  checkRoles(input.roles);
  const [ring, programData, protocolConfig, ringAuth] = await Promise.all([
    ringPolicyAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
    protocolConfigAddress(),
    ringAuthAddress(input.ringProgramId),
  ]);
  const writer = new Writer()
    .u8(RingInstructionTag.initialize, "tag")
    .bytes(input.auditorPublicKey.toBytes(), 33, "auditorPubkey")
    .u8(ringKindByte(input.kind), "kind");
  for (const role of RING_ROLES) writer.bytes(addressBytes(input.roles[role], role), 32, role);
  const accounts: AccountMeta[] = [
    meta(input.payer, true, true),
    meta(input.authority, true, false),
    meta(ring, false, true),
    meta(SYSTEM_PROGRAM, false, false),
    meta(input.ringProgramId, false, false),
    meta(programData, false, false),
    meta(protocolConfig, false, false),
    meta(ringAuth, false, true),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
  ];
  const { policy } = input;
  writer.bool(policy !== undefined, "policy");
  if (policy !== undefined) {
    const curators = writePolicyTable(writer, policy);
    accounts.push(
      meta(policy.records, false, false),
      ...curators.map((registry) => meta(registry, false, false)),
    );
  }
  const instruction = ringInstruction(input.ringProgramId, writer.finish(), accounts);
  checkFits(input.payer, instruction, ringComputeUnitLimit(RingInstructionTag.initialize));
  return instruction;
}

/** Rust `SyncRoots`, permissionless, `registry` is the ring's records or its curator. */
export async function syncRootsInstruction(
  input: Readonly<{ ringProgramId: Address; registry: Address }>,
): Promise<Instruction> {
  const policy = await ringPolicyAddress(input.ringProgramId);
  return ringInstruction(input.ringProgramId, Uint8Array.of(RingInstructionTag.syncRoots), [
    meta(policy, false, true),
    meta(input.registry, false, false),
  ]);
}

/** Rust `UpdateAuthority`, the admin and the new key sign so a mistyped address cannot strand the role. */
export async function updateRingAuthorityInstruction(
  input: Readonly<{
    ringProgramId: Address;
    /** The admin. */
    authority: SignerAccount;
    role: RingAuthorityRole;
    newAuthority: SignerAccount;
  }>,
): Promise<Instruction> {
  if (!Object.hasOwn(RING_ROLE_BYTES, input.role))
    throw new RingError("RING_CONFIG_INVALID", { details: { reason: "role", role: input.role } });
  const ring = await ringPolicyAddress(input.ringProgramId);
  const data = Uint8Array.of(RingInstructionTag.updateAuthority, RING_ROLE_BYTES[input.role]);
  return ringInstruction(input.ringProgramId, data, [
    meta(input.authority, true, false),
    meta(input.newAuthority, true, false),
    meta(ring, false, true),
  ]);
}

/** Rust `CustomRing::set_paused`, the pauser signs. */
export async function setRingPausedInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    paused: boolean;
  }>,
): Promise<Instruction> {
  const [ring, ringAuth] = await Promise.all([
    ringPolicyAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
  ]);
  const data = new Writer()
    .u8(RingInstructionTag.setPaused, "tag")
    .bool(input.paused, "paused")
    .finish();
  return ringInstruction(input.ringProgramId, data, [
    meta(input.authority, true, false),
    meta(ring, false, false),
    meta(ringAuth, false, true),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
  ]);
}

/** Rust `SetCoSigner`, the co-signer admin creates the signer's record or rescopes it. */
export async function setRingCoSignerInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    signer: Address;
    /** A nonzero subset of the `RING_COSIGN_*` bits. */
    scope: number;
  }>,
): Promise<Instruction> {
  checkCoSigner(input.signer, input.scope);
  const [ring, record] = await Promise.all([
    ringPolicyAddress(input.ringProgramId),
    ringCoSignerAddress(input.ringProgramId, input.signer),
  ]);
  const data = new Writer()
    .u8(RingInstructionTag.setCoSigner, "tag")
    .bytes(addressBytes(input.signer, "signer"), 32, "signer")
    .u8(input.scope, "scope")
    .finish();
  return ringInstruction(input.ringProgramId, data, [
    meta(input.payer, true, true),
    meta(input.authority, true, false),
    meta(ring, false, true),
    meta(record, false, true),
    meta(SYSTEM_PROGRAM, false, false),
  ]);
}

/** Rust `ClearCoSigner`, the co-signer admin signs and the record's rent goes to `rentRecipient`. */
export async function clearRingCoSignerInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    signer: Address;
    rentRecipient: Address;
  }>,
): Promise<Instruction> {
  const [ring, record] = await Promise.all([
    ringPolicyAddress(input.ringProgramId),
    ringCoSignerAddress(input.ringProgramId, input.signer),
  ]);
  return ringInstruction(input.ringProgramId, Uint8Array.of(RingInstructionTag.clearCoSigner), [
    meta(input.authority, true, false),
    meta(ring, false, true),
    meta(record, false, true),
    meta(input.rentRecipient, false, true),
  ]);
}

/** Rust `CustomRing::set_delegate`, the admin and the delegate sign, permanent and it turns key escrow on. */
export async function setRingDelegateInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    delegate: SignerAccount;
  }>,
): Promise<Instruction> {
  const ring = await ringPolicyAddress(input.ringProgramId);
  return ringInstruction(input.ringProgramId, Uint8Array.of(RingInstructionTag.setDelegate), [
    meta(input.authority, true, false),
    meta(ring, false, true),
    meta(input.delegate, true, false),
  ]);
}

/** Where a policy list is read, the ring's own records or a curator `StorageRegistry`. */
export type RingPolicySourceOwner =
  | Readonly<{ kind: "own" }>
  | Readonly<{ kind: "curator"; registry: Address }>;

/** A referenced list read from a curator `StorageRegistry`. */
export interface RingSharedSource {
  readonly listId: ListId;
  readonly curatorRegistry: Address;
}

/** A table and the lists it reads from curators, every other referenced list reads the ring's own. */
export interface RingPolicyTableInput {
  readonly table: RuleTable;
  readonly sharedSources?: readonly RingSharedSource[];
}

export interface RingInitialPolicy extends RingPolicyTableInput {
  readonly records: Address;
}

export type RingPolicyUpdate =
  | (Readonly<{ kind: "rules" }> & RingPolicyTableInput)
  | Readonly<{ kind: "source"; listId: ListId; source: RingPolicySourceOwner }>
  | Readonly<{ kind: "records"; records: Address }>;

const POLICY_UPDATE_VARIANT = Object.freeze({ rules: 0, source: 1, records: 2 } as const);

/** Rust `UpdatePolicy`, the policy role signs and own lists read rebound records once `syncRootsInstruction` mirrors them. */
export async function updateRingPolicyInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    update: RingPolicyUpdate;
  }>,
): Promise<Instruction> {
  const { update } = input;
  const writer = new Writer()
    .u8(RingInstructionTag.updatePolicy, "tag")
    .u8(POLICY_UPDATE_VARIANT[update.kind], "variant");
  const trailing = policyUpdateBody(writer, update);
  const accounts = await policyWriteMetas(input.ringProgramId, input.authority);
  const instruction = ringInstruction(input.ringProgramId, writer.finish(), [
    ...accounts,
    ...trailing.map((account) => meta(account, false, false)),
  ]);
  checkFits(input.authority, instruction, ringComputeUnitLimit(RingInstructionTag.updatePolicy));
  return instruction;
}

/** Writes the variant body and returns the trailing accounts it names. */
function policyUpdateBody(writer: Writer, update: RingPolicyUpdate): readonly Address[] {
  switch (update.kind) {
    case "rules":
      return writePolicyTable(writer, update);
    case "source": {
      writer.u8(checkedListId(update.listId), "listId");
      if (update.source.kind === "own") {
        writer.u8(0, "source");
        return [];
      }
      writer.u8(1, "source");
      return [update.source.registry];
    }
    case "records":
      return [update.records];
  }
}

async function policyWriteMetas(
  ringProgramId: Address,
  authority: SignerAccount,
): Promise<readonly AccountMeta[]> {
  const ring = await ringPolicyAddress(ringProgramId);
  return [meta(authority, true, false), meta(ring, false, true)];
}

/** Rust `PolicyTable::payload`, returns the curator registries in first-use order. */
function writePolicyTable(writer: Writer, input: RingPolicyTableInput): readonly Address[] {
  const table = buildRuleTable(input.table);
  const referenced = policySourceLists(table.rules);
  const shared = input.sharedSources ?? [];
  const seen = new Set<ListId>();
  for (const source of shared) {
    if (!referenced.includes(source.listId)) throw sourceInvalid("UnreferencedList", source.listId);
    if (seen.has(source.listId)) throw sourceInvalid("DuplicateList", source.listId);
    seen.add(source.listId);
  }
  const curators: Address[] = [];
  writer.u8(referenced.length, "sources.length");
  for (const listId of referenced) {
    const curator = shared.find((source) => source.listId === listId)?.curatorRegistry;
    if (curator !== undefined && !curators.includes(curator)) curators.push(curator);
    writer
      .u8(listId, "listId")
      .u8(curator === undefined ? 0 : 1 + curators.indexOf(curator), "source");
  }
  if (curators.length > 1) throw sourceInvalid("MultipleCurators");
  const { rules } = table;
  writer.u8(rules.length, "rules.length");
  for (const rule of rules) writer.bytes(encodeRule(rule), 32, "rule");
  return curators;
}

/** Rust `fit`, the signed transaction must fit v1 before the authority signs it. */
function checkFits(payer: SignerAccount, instruction: Instruction, computeUnitLimit: number): void {
  checkTransactionFits({
    feePayer: signerAddress(payer),
    instructions: [instruction],
    computeUnitLimit,
  });
}

/** Mirrors Rust `RingRoles::check`, every key nonzero and distinct. */
function checkRoles(roles: RingRoles): void {
  const keys = RING_ROLES.map((role) => roles[role]);
  const reason = keys.some((key) => equalBytes(addressBytes(key, "role"), ZERO_32))
    ? "ZeroRoleKey"
    : new Set(keys).size !== keys.length
      ? "DuplicateRoleKey"
      : undefined;
  if (reason !== undefined) throw new RingError("RING_CONFIG_INVALID", { details: { reason } });
}

/** Mirrors the program's `SetCoSigner` refusals before the authority signs. */
function checkCoSigner(signer: Address, scope: number): void {
  const reason =
    !Number.isInteger(scope) || scope === 0 || (scope & ~RING_COSIGN_SCOPE_MASK) !== 0
      ? "InvalidCoSignerScope"
      : equalBytes(addressBytes(signer, "signer"), ZERO_32)
        ? "InvalidCoSigner"
        : undefined;
  if (reason !== undefined) throw new RingError("RING_CO_SIGNER_INVALID", { details: { reason } });
}

function ringInstruction(
  ringProgramId: Address,
  data: Uint8Array,
  accounts: readonly AccountMeta[],
): Instruction {
  return { programAddress: ringProgramId, accounts, data };
}

function sourceInvalid(reason: string, listId?: ListId): RingError {
  return new RingError("RING_POLICY_SOURCE_INVALID", {
    details: listId === undefined ? { reason } : { reason, listId },
  });
}
