import { getAddressDecoder, type Address } from "@solana/kit";

import type { RpcAccount } from "@heliuslabs/spr/client";
import { Writer, addressBytes } from "@heliuslabs/spr/internal";
import { SHIELDED_POOL_PROGRAM_ID, StateDiscriminator } from "@heliuslabs/spr/interface";
import type { Bytes32 } from "@heliuslabs/spr/interface";
import {
  ringAuthAddress,
  ringCoSignerPda,
  STORAGE_PROGRAM_ID,
  trackingAuthorizationPda,
} from "../../src/protocol/pda/index.js";
import { ROOT_HISTORY } from "../../src/protocol/membership/member-registry.js";
import type {
  RingCoSigner,
  RingMode,
  RingRoles,
  RingSourceSlot,
  StorageRegistryRoot,
} from "../../src/protocol/codec/ring-codecs.js";
import {
  RING_POLICY_DISCRIMINATOR,
  RING_ROLES,
  STORAGE_REGISTRY_DISCRIMINATOR,
} from "../../src/protocol/codec/ring-codecs.js";
import { X25519Keypair, type ShieldedAddress } from "@heliuslabs/spr/keypair";
import {
  LIST_IDS,
  encodeRule,
  referencedLists,
  type RuleTable,
} from "../../src/protocol/membership/policy.js";

export const ZERO_ADDRESS = getAddressDecoder().decode(new Uint8Array(32));

const MODE_BYTES: Readonly<Record<RingMode, number>> = { confidential: 0, anonymous: 2 };

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

/** Rust `TrackingRegistry`, the newest root in slot 0. */
export function trackingRegistryAccount(
  input: Readonly<{
    root: Bytes32;
    revision: bigint;
    nextIndex: number;
    auditorPubkey: Uint8Array;
  }>,
): RpcAccount {
  const writer = new Writer()
    .u8(3, "discriminator")
    .bytes(new Uint8Array(32), 32, "ringId")
    .bytes(input.auditorPubkey, 33, "auditorPubkey")
    .u64(BigInt(input.nextIndex), "nextIndex");
  for (let slot = 0; slot < ROOT_HISTORY; slot += 1)
    writer
      .bytes(slot === 0 ? input.root : new Uint8Array(32), 32, "hash")
      .u64(slot === 0 ? input.revision : 0n, "revision")
      .u64(0n, "expiresAt");
  return ownedAccount(STORAGE_PROGRAM_ID, writer.finish());
}

/** Rust `TrackingAuthorization` of an applied enrollment at its PDA, the seal fields filled. */
export async function trackingAuthorizationAccount(
  input: Readonly<{
    registry: Address;
    owner: Address;
    nullifierPk: Uint8Array;
    listTag: Uint8Array;
    viewingU: Uint8Array;
  }>,
): Promise<readonly [Address, RpcAccount]> {
  const data = new Writer()
    .u8(4, "discriminator")
    .bytes(addressBytes(input.registry))
    .bytes(addressBytes(input.owner))
    .bytes(input.nullifierPk, 32, "nullifierPk")
    .bytes(input.listTag, 32, "listTag")
    .bytes(input.viewingU, 32, "viewingU")
    .bytes(new Uint8Array(32).fill(0x22), 32, "ephU")
    .bytes(new Uint8Array(64).fill(0x33), 64, "ciphertext")
    .u8(1, "applied")
    .finish();
  const [address] = await trackingAuthorizationPda(input.registry, input.owner);
  return [address, ownedAccount(STORAGE_PROGRAM_ID, data)];
}

/** Each enrolled owner's authorization at its PDA, keyed by address, the zero list tag. */
export async function trackingAuthorizations(
  registry: Address,
  owners: readonly ShieldedAddress[],
): Promise<ReadonlyMap<Address, RpcAccount>> {
  return new Map(
    await Promise.all(
      owners.map((owner) =>
        trackingAuthorizationAccount({
          registry,
          owner: owner.solanaAddress(),
          nullifierPk: owner.nullifierPublicKey,
          listTag: new Uint8Array(32),
          viewingU: owner.viewingPublicKey.u(),
        }),
      ),
    ),
  );
}

/** Rust `StorageRegistry` owned by the storage program, `roots` newest first. */
export function storageRegistryAccount(
  roots: readonly StorageRegistryRoot[],
  authority: Address = ZERO_ADDRESS,
  source: Readonly<{
    trackingRegistry?: Address;
    trackingFloor?: bigint;
  }> = {},
): RpcAccount {
  const writer = new Writer()
    .u8(STORAGE_REGISTRY_DISCRIMINATOR, "discriminator")
    .bytes(addressBytes(authority))
    .u64(0n, "graceSlots")
    .u32(1, "nextIndex")
    .bytes(new Uint8Array(32), 32, "ringId")
    .bytes(addressBytes(source.trackingRegistry ?? ZERO_ADDRESS))
    .u64(source.trackingFloor ?? 0n, "trackingFloor");
  for (let slot = 0; slot < ROOT_HISTORY; slot += 1) {
    const root = roots[slot];
    writer
      .bytes(root?.hash ?? new Uint8Array(32))
      .u64(root?.revision ?? 0n, "revision")
      .u64(root?.expiresAt ?? 0n, "expiresAt");
  }
  return ownedAccount(STORAGE_PROGRAM_ID, writer.finish());
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
    tracking?: Address;
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
  }>,
): Uint8Array {
  const roles = { ...FIXTURE_ROLES, ...input.roles };
  const writer = new Writer()
    .u8(RING_POLICY_DISCRIMINATOR, "discriminator")
    .u8(input.bump, "bump")
    .u8(MODE_BYTES[input.mode ?? "confidential"], "mode")
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
    .bytes(addressBytes(input.records ?? ZERO_ADDRESS))
    .bytes(addressBytes(input.tracking ?? ZERO_ADDRESS));
  writePolicyFields(writer, input);
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
