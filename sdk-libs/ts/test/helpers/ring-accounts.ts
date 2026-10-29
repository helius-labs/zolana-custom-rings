import { getAddressDecoder, type Address } from "@solana/kit";

import type { RpcAccount } from "@heliuslabs/zolana/client";
import { Writer, addressBytes } from "@heliuslabs/zolana/internal";
import { SHIELDED_POOL_PROGRAM_ID, StateDiscriminator } from "@heliuslabs/zolana/interface";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { ringAuthAddress } from "../../src/protocol/pda/index.js";
import {
  APPLY_BATCH,
  MEMBER_REGISTRY_ROOT_HISTORY,
} from "../../src/protocol/membership/member-registry.js";
import type {
  RingCoSigner,
  RingMode,
  RingSourceSlot,
  RingRootEntry,
  StorageRegistryRoot,
} from "../../src/protocol/codec/ring-codecs.js";
import { RING_POLICY_DISCRIMINATOR } from "../../src/protocol/codec/ring-codecs.js";
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

/** Rust `RingProgramConfig` bytes. */
export function ringProgramConfigData(
  input: Readonly<{
    authority: Address;
    auditorPublicKey: Uint8Array;
    bump: number;
    hasPolicy: boolean;
    mode?: RingMode;
    insertFee?: bigint;
    coSigner?: RingCoSigner;
    delegate?: Address;
    createdSlot?: bigint;
  }>,
): Uint8Array {
  const writer = new Writer()
    .u8(10, "discriminator")
    .bytes(addressBytes(input.authority))
    .bytes(input.auditorPublicKey, 33, "auditorPublicKey")
    .u8(input.bump, "bump")
    .u8(input.hasPolicy ? 1 : 0, "hasPolicy")
    .u8(MODES.indexOf(input.mode ?? "confidential"), "mode")
    .u64(input.insertFee ?? 0n, "insertFee")
    .bytes(addressBytes(input.coSigner?.signer ?? ZERO_ADDRESS))
    .u8(input.coSigner?.scope ?? 0, "coSignScope");
  return writer
    .bytes(addressBytes(input.delegate ?? ZERO_ADDRESS))
    .u64(input.createdSlot ?? 0n, "createdSlot")
    .finish();
}

/** Rust `MemberRegistry` bytes, the newest root at `historyCursor`. */
export function memberRegistryData(
  input: Readonly<{
    bump: number;
    history: readonly (RingRootEntry | undefined)[];
    historyCursor?: number;
    nextIndex: number;
    floor?: bigint;
    priorFloor?: bigint;
    floorSlot?: bigint;
    policyHash?: Bytes32;
    sources?: readonly RingSourceSlot[];
    table?: RuleTable;
    generation?: number;
  }>,
): Uint8Array {
  const writer = new Writer()
    .u8(11, "discriminator")
    .u8(input.bump, "bump")
    .u8(input.historyCursor ?? 0, "historyCursor")
    .u32(input.nextIndex, "nextIndex")
    .u64(input.floor ?? 0n, "floor")
    .u64(input.priorFloor ?? 0n, "priorFloor")
    .u64(input.floorSlot ?? 0n, "floorSlot");
  for (let slot = 0; slot < MEMBER_REGISTRY_ROOT_HISTORY; slot += 1) {
    const entry = input.history[slot];
    writer
      .bytes(entry?.root ?? new Uint8Array(32))
      .u64(entry?.applied ?? 0n, "applied")
      .u64(entry?.slot ?? 0n, "slot");
  }
  return writePolicyFields(writer, input).finish();
}

/** A mirror copied from `registry`, newest root first. */
export interface FixtureMirror {
  readonly registry: Address;
  readonly roots: readonly StorageRegistryRoot[];
}

/** Rust `RingPolicy` bytes. */
export function ringPolicyData(
  input: Readonly<{
    bump: number;
    records: Address;
    policyHash?: Bytes32;
    sources?: readonly RingSourceSlot[];
    table?: RuleTable;
    generation?: number;
    ownRoots?: FixtureMirror;
    curatorRoots?: FixtureMirror;
  }>,
): Uint8Array {
  const writer = new Writer()
    .u8(RING_POLICY_DISCRIMINATOR, "discriminator")
    .u8(input.bump, "bump")
    .bytes(addressBytes(input.records));
  writePolicyFields(writer, input);
  for (const mirror of [input.ownRoots, input.curatorRoots]) {
    writer.bytes(addressBytes(mirror?.registry ?? ZERO_ADDRESS));
    for (let slot = 0; slot < MEMBER_REGISTRY_ROOT_HISTORY; slot += 1) {
      const root = mirror?.roots[slot];
      writer
        .bytes(root?.hash ?? new Uint8Array(32))
        .u64(root?.revision ?? 0n, "revision")
        .u64(root?.expiresAt ?? 0n, "expiresAt");
    }
  }
  return writer.finish();
}

/** Rust `RecordQueue` bytes, every queued position's checkpoint at `position mod APPLY_BATCH`. */
export function recordQueueData(
  input: Readonly<{
    bump: number;
    head: bigint;
    tail: bigint;
    chainHead: Bytes32;
    checkpoints?: readonly Readonly<{ position: bigint; chain: Bytes32; slot: bigint }>[];
    nextApplySlot?: bigint;
  }>,
): Uint8Array {
  const writer = new Writer()
    .u8(12, "discriminator")
    .u8(input.bump, "bump")
    .u64(input.head, "head")
    .u64(input.tail, "tail")
    .bytes(input.chainHead, 32, "chainHead");
  for (let slot = 0; slot < APPLY_BATCH; slot += 1) {
    const checkpoint = input.checkpoints?.find(
      (entry) => entry.position % BigInt(APPLY_BATCH) === BigInt(slot),
    );
    writer.bytes(checkpoint?.chain ?? new Uint8Array(32)).u64(checkpoint?.slot ?? 0n, "slot");
  }
  return writer.u64(input.nextApplySlot ?? 0n, "nextApplySlot").finish();
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
