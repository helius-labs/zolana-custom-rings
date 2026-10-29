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
  ringConfigAddress,
  ringPolicyAddress,
} from "../../protocol/pda/index.js";
import { isSmallOrder } from "../../crypto/keys/x25519.js";

import {
  RING_COSIGN_SCOPE_MASK,
  type RingProgramConfig,
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
    case RingInstructionTag.createPolicy:
    case RingInstructionTag.setPolicySource:
    case RingInstructionTag.setPolicyRules:
      return POLICY_UNITS;
    case RingInstructionTag.legacyTransact:
    case RingInstructionTag.legacyDelegateTransact:
    case RingInstructionTag.transact:
    case RingInstructionTag.merge:
    case RingInstructionTag.delegateTransact:
    case RingInstructionTag.auditedDeposit:
      return PROOF_UNITS;
    case RingInstructionTag.deposit:
      return 200_000;
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

/** Rust `CustomRing::create_config`, the upgrade authority signs and becomes the ring authority. */
export async function createRingConfigInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    auditorPublicKey: X25519PublicKey;
    kind: RingKind;
  }>,
): Promise<Instruction> {
  if (isSmallOrder(input.auditorPublicKey))
    throw new RingError("RING_CONFIG_INVALID", { details: { reason: "InvalidAuditorPubkey" } });
  const [config, programData] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
  ]);
  const data = new Writer()
    .u8(RingInstructionTag.createConfig, "tag")
    .bytes(input.auditorPublicKey.toBytes(), 33, "auditorPubkey")
    .u8(ringKindByte(input.kind), "kind")
    .finish();
  return ringInstruction(input.ringProgramId, data, [
    meta(input.payer, true, true),
    meta(input.authority, true, false),
    meta(config, false, true),
    meta(SYSTEM_PROGRAM, false, false),
    meta(input.ringProgramId, false, false),
    meta(programData, false, false),
  ]);
}

/** Rust `CustomRing::init_spp_ring_config`, a policy ring registers after its policy is set. */
export async function initSppRingConfigInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    config: RingProgramConfig;
  }>,
): Promise<Instruction> {
  const [config, protocolConfig, ringAuth, policy] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    protocolConfigAddress(),
    ringAuthAddress(input.ringProgramId),
    ringPolicyAddress(input.ringProgramId),
  ]);
  return ringInstruction(input.ringProgramId, Uint8Array.of(RingInstructionTag.initSppRingConfig), [
    meta(input.payer, true, true),
    meta(input.authority, true, false),
    meta(config, false, false),
    meta(protocolConfig, false, false),
    meta(ringAuth, false, true),
    meta(SYSTEM_PROGRAM, false, false),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    ...(input.config.hasPolicy ? [meta(policy, false, false)] : []),
  ]);
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

/** Rust `CustomRing::set_authority`, both keys sign so a mistyped address cannot strand the config. */
export async function setRingAuthorityInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    newAuthority: SignerAccount;
  }>,
): Promise<Instruction> {
  const config = await ringConfigAddress(input.ringProgramId);
  return ringInstruction(input.ringProgramId, Uint8Array.of(RingInstructionTag.setAuthority), [
    meta(input.authority, true, false),
    meta(input.newAuthority, true, false),
    meta(config, false, true),
  ]);
}

/** Rust `CustomRing::set_paused`. */
export async function setRingPausedInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    paused: boolean;
  }>,
): Promise<Instruction> {
  const [config, ringAuth] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
  ]);
  const data = new Writer()
    .u8(RingInstructionTag.setPaused, "tag")
    .bool(input.paused, "paused")
    .finish();
  return ringInstruction(input.ringProgramId, data, [
    meta(input.authority, true, false),
    meta(config, false, false),
    meta(ringAuth, false, true),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
  ]);
}

/** Rust `SetCoSigner`, creates the signer's record or rescopes it. */
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
  const [config, record] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
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
    meta(config, false, true),
    meta(record, false, true),
    meta(SYSTEM_PROGRAM, false, false),
  ]);
}

/** Rust `ClearCoSigner`, the record's rent goes to `rentRecipient`. */
export async function clearRingCoSignerInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    signer: Address;
    rentRecipient: Address;
  }>,
): Promise<Instruction> {
  const [config, record] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringCoSignerAddress(input.ringProgramId, input.signer),
  ]);
  return ringInstruction(input.ringProgramId, Uint8Array.of(RingInstructionTag.clearCoSigner), [
    meta(input.authority, true, false),
    meta(config, false, true),
    meta(record, false, true),
    meta(input.rentRecipient, false, true),
  ]);
}

/** Rust `CustomRing::set_delegate`, the config authority and the delegate sign, permanent and it turns key escrow on. */
export async function setRingDelegateInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    delegate: SignerAccount;
  }>,
): Promise<Instruction> {
  const [config, policy] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringPolicyAddress(input.ringProgramId),
  ]);
  return ringInstruction(input.ringProgramId, Uint8Array.of(RingInstructionTag.setDelegate), [
    meta(input.authority, true, false),
    meta(config, false, true),
    meta(input.delegate, true, false),
    meta(policy, false, false),
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

/** Rust `CustomRing::set_source_owner`, re-points one referenced list, the rows stay. */
export async function setRingPolicySourceInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    listId: ListId;
    source: RingPolicySourceOwner;
  }>,
): Promise<Instruction> {
  const curatorAccount = input.source.kind === "curator" ? input.source.registry : undefined;
  const accounts = await policyWriteMetas(input.ringProgramId, input.authority);
  return ringInstruction(
    input.ringProgramId,
    Uint8Array.of(
      RingInstructionTag.setPolicySource,
      checkedListId(input.listId),
      curatorAccount === undefined ? 0 : 1,
    ),
    curatorAccount === undefined ? accounts : [...accounts, meta(curatorAccount, false, false)],
  );
}

/** Rust `CustomRing::create_policy`, pins the table and its source map. */
export function createRingPolicyInstruction(
  input: RingPolicyTableInput & Readonly<{ ringProgramId: Address; authority: SignerAccount }>,
): Promise<Instruction> {
  return policyTableInstruction(RingInstructionTag.createPolicy, input);
}

/** Rust `CustomRing::set_policy_rules`, replaces the pinned table and the complete source map. */
export function setRingPolicyRulesInstruction(
  input: RingPolicyTableInput & Readonly<{ ringProgramId: Address; authority: SignerAccount }>,
): Promise<Instruction> {
  return policyTableInstruction(RingInstructionTag.setPolicyRules, input);
}

/** `CreatePolicy`, `SetPolicyRules` and `SetPolicySource` write the ring policy. */
async function policyWriteMetas(
  ringProgramId: Address,
  authority: SignerAccount,
): Promise<readonly AccountMeta[]> {
  const [config, policy] = await Promise.all([
    ringConfigAddress(ringProgramId),
    ringPolicyAddress(ringProgramId),
  ]);
  return [meta(authority, true, false), meta(config, false, false), meta(policy, false, true)];
}

/** Rust `CustomRing::policy_table`, curator registries follow in first-use order and the transaction fits v1. */
async function policyTableInstruction(
  tag: typeof RingInstructionTag.createPolicy | typeof RingInstructionTag.setPolicyRules,
  input: RingPolicyTableInput & Readonly<{ ringProgramId: Address; authority: SignerAccount }>,
): Promise<Instruction> {
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
  const writer = new Writer().u8(tag, "tag").u8(referenced.length, "sources.length");
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
  const accounts = await policyWriteMetas(input.ringProgramId, input.authority);
  const instruction = ringInstruction(input.ringProgramId, writer.finish(), [
    ...accounts,
    ...curators.map((registry) => meta(registry, false, false)),
  ]);
  checkFits(input.authority, instruction, ringComputeUnitLimit(tag));
  return instruction;
}

/** Rust `fit`, the signed transaction must fit v1 before the authority signs it. */
function checkFits(payer: SignerAccount, instruction: Instruction, computeUnitLimit: number): void {
  checkTransactionFits({
    feePayer: signerAddress(payer),
    instructions: [instruction],
    computeUnitLimit,
  });
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
