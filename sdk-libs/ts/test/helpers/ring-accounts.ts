import { getAddressDecoder, type Address } from "@solana/kit";

import type { RpcAccount } from "@heliuslabs/zolana/client";
import { Writer, addressBytes } from "@heliuslabs/zolana/internal";
import { SHIELDED_POOL_PROGRAM_ID, StateDiscriminator } from "@heliuslabs/zolana/interface";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { ringAuthAddress, ringCoSignerPda } from "../../src/protocol/pda/index.js";
import { ROOT_HISTORY } from "../../src/protocol/membership/member-registry.js";
import type {
  RingCoSigner,
  RingMode,
  RingRoles,
  RingSourceSlot,
  StorageRegistryRoot,
} from "../../src/protocol/codec/ring-codecs.js";
import { RING_POLICY_DISCRIMINATOR, RING_ROLES } from "../../src/protocol/codec/ring-codecs.js";
import { X25519Keypair } from "@heliuslabs/zolana/keypair";
import {
  LIST_IDS,
  encodeRule,
  referencedLists,
  type RuleTable,
} from "../../src/protocol/membership/policy.js";

export const ZERO_ADDRESS = getAddressDecoder().decode(new Uint8Array(32));

const MODES: readonly RingMode[] = ["confidential", "confidentialEscrow", "anonymous"];

export function ownedAccount(owner: Address, data: Uint8Array): RpcAccount {
  return { owner, lamports: 1n, data };
}

/** Every referenced list read from the ring's own registry, the other slots empty. */
export function ownSources(table: RuleTable): readonly RingSourceSlot[] {
  const referenced = referencedLists(table.rules);
  return LIST_IDS.map((listId) =>
    referenced.includes(listId)
      ? { listId, registry: ZERO_ADDRESS }
      : { listId: 0, registry: ZERO_ADDRESS },
  );
}

/** SPP's `RingConfig` registration of `ringProgramId`, active unless told otherwise. */
export async function sppRingRegistration(
  input: Readonly<{
    authority: Address;
    ringProgramId: Address;
    activated?: boolean;
    paused?: boolean;
  }>,
): Promise<readonly [Address, RpcAccount]> {
  const data = new Uint8Array(69);
  data[0] = StateDiscriminator.ringConfig;
  data.set(addressBytes(input.authority), 1);
  data.set(addressBytes(input.ringProgramId), 33);
  data[66] = input.paused === true ? 1 : 0;
  data[67] = input.activated === false ? 0 : 1;
  return [await ringAuthAddress(input.ringProgramId), ownedAccount(SHIELDED_POOL_PROGRAM_ID, data)];
}

/** Rust `CoSigner` at its canonical PDA. */
export async function ringCoSignerAccount(
  ringProgramId: Address,
  coSigner: RingCoSigner,
): Promise<readonly [Address, RpcAccount]> {
  const [address, bump] = await ringCoSignerPda(ringProgramId, coSigner.signer);
  const data = new Writer()
    .u8(14, "discriminator")
    .bytes(addressBytes(coSigner.signer))
    .u8(coSigner.scope, "scope")
    .u8(bump, "bump")
    .finish();
  return [address, ownedAccount(ringProgramId, data)];
}

/** A mirror copied from `registry`, newest root first. */
export interface FixtureMirror {
  readonly registry: Address;
  readonly roots: readonly StorageRegistryRoot[];
}

/** Distinct role keys a fixture fills where a test names none. */
export const FIXTURE_ROLES: RingRoles = Object.freeze({
  admin: getAddressDecoder().decode(new Uint8Array(32).fill(0xa1)),
  policy: getAddressDecoder().decode(new Uint8Array(32).fill(0xa2)),
  pauser: getAddressDecoder().decode(new Uint8Array(32).fill(0xa3)),
  cosignAdmin: getAddressDecoder().decode(new Uint8Array(32).fill(0xa4)),
});

const FIXTURE_AUDITOR = X25519Keypair.fromBytes(new Uint8Array(32).fill(9)).publicKey().toBytes();

/** Rust `RingPolicy` bytes, a policy ring once `policyHash` is set. */
export function ringPolicyData(
  input: Readonly<{
    bump: number;
    records?: Address;
    roles?: Partial<RingRoles>;
    auditorPublicKey?: Uint8Array;
    mode?: RingMode;
    coSigner?: RingCoSigner;
    delegate?: Address;
    createdSlot?: bigint;
    policyHash?: Bytes32;
    sources?: readonly RingSourceSlot[];
    table?: RuleTable;
    generation?: number;
    ownRoots?: FixtureMirror;
    curatorRoots?: FixtureMirror;
  }>,
): Uint8Array {
  const roles = { ...FIXTURE_ROLES, ...input.roles };
  const writer = new Writer()
    .u8(RING_POLICY_DISCRIMINATOR, "discriminator")
    .u8(input.bump, "bump")
    .u8(MODES.indexOf(input.mode ?? "confidential"), "mode")
    .bytes(
      Uint8Array.from([1, 2, 4], (bit) => (((input.coSigner?.scope ?? 0) & bit) === 0 ? 0 : 1)),
      3,
      "coSigners",
    );
  for (const role of RING_ROLES) writer.bytes(addressBytes(roles[role]));
  writer
    .bytes(addressBytes(input.delegate ?? ZERO_ADDRESS))
    .bytes(input.auditorPublicKey ?? FIXTURE_AUDITOR, 33, "auditorPublicKey")
    .u64(input.createdSlot ?? 0n, "createdSlot")
    .bytes(addressBytes(input.records ?? ZERO_ADDRESS));
  writePolicyFields(writer, input);
  for (const mirror of [input.ownRoots, input.curatorRoots]) {
    writer.bytes(addressBytes(mirror?.registry ?? ZERO_ADDRESS));
    for (let slot = 0; slot < ROOT_HISTORY; slot += 1) {
      const root = mirror?.roots[slot];
      writer
        .bytes(root?.hash ?? new Uint8Array(32))
        .u64(root?.revision ?? 0n, "revision")
        .u64(root?.expiresAt ?? 0n, "expiresAt");
    }
  }
  return writer.finish();
}

function writePolicyFields(
  writer: Writer,
  input: Readonly<{
    policyHash?: Bytes32;
    sources?: readonly RingSourceSlot[];
    table?: RuleTable;
    generation?: number;
  }>,
): Writer {
  writer.bytes(input.policyHash ?? new Uint8Array(32));
  const sources = input.sources ?? LIST_IDS.map(() => ({ listId: 0, registry: ZERO_ADDRESS }));
  for (const source of sources)
    writer.u8(source.listId, "listId").bytes(addressBytes(source.registry));
  counted(writer, (input.table ?? { rules: [] }).rules.map(encodeRule), 16);
  return writer.u32(input.generation ?? 0, "generation").u64(0n, "generationSlot");
}

function counted(writer: Writer, rows: readonly Uint8Array[], slots: number): void {
  writer.u8(rows.length, "count");
  padded(writer, rows, slots, 32);
}

function padded(writer: Writer, rows: readonly Uint8Array[], slots: number, width: number): void {
  for (const row of rows) writer.bytes(row, width);
  writer.bytes(new Uint8Array(width * (slots - rows.length)));
}
