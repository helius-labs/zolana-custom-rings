import { hashBytes, writeTreeContext, Reader, Writer } from "@heliuslabs/zolana/internal";
import {
  encodeRingTransactInstructionData,
  type RingCircuitId,
  type RingTransactInstructionData,
} from "../proof/circuit.js";
import {
  InterfaceError,
  externalDataHash,
  type SettlementAccounts,
  InstructionTag,
  SPP_SUPPORTED_SHAPES,
} from "@heliuslabs/zolana/interface";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes64,
  Bytes128,
  InterfaceTransfer,
  TransactInstructionData,
  TransactOutput,
  TreeContext,
} from "@heliuslabs/zolana/interface";
import { packBytesBe } from "../../crypto/derivation/hasher.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../proof/custom-ring-proof.js";
import {
  DELIVERED_AUDIT_CAPACITIES,
  anonymousAuditKey,
  disclosureFieldCount,
  type AuditLayout,
  type DisclosureLayout,
} from "../codec/ring-disclosure-layout.js";

import { RingInstructionTag } from "../../operations/management/admin.js";
import type { RingMode } from "../codec/ring-codecs.js";
import { RingError } from "../error.js";
import { N_PUBLIC_SLOTS, RING_AUTHORITY_SHAPES } from "./spp.js";
import {
  decompressG2,
  readInterfaceTransfer,
  readTreeContext,
  writeInterfaceTransfer,
} from "../codec/codecs.js";
import {
  CONFIDENTIAL_DATA_FREE_BODY_LEN,
  RING_DELIVERED_BODY_LEN,
  encodeRingOutput,
  RingScheme,
} from "./output.js";

/** The program rail the data serves, fixed by the instruction and the ring mode. */
export type RingRail = "confidential" | "anonymous" | "delegate";

/** The policy proof and the roots it binds. */
export interface PolicyProof {
  readonly splWithdrawalOwners: readonly Bytes32[];
  readonly proof: Uint8Array;
  readonly ownRevision: bigint;
  /** Set exactly when a source names the curator registry. */
  readonly curatorRevision?: bigint;
  /** Set exactly on the anonymous rail. */
  readonly senderCommitment?: Bytes32;
}

/** The anonymous SPP rail's BSB22 commitment and its hidden owner's default-ring key. */
export interface AnonymousProofData {
  readonly commitment: Bytes32;
  readonly commitmentPok: Bytes32;
  readonly defaultOwnerTag?: Bytes32;
}

export type InputTrees =
  | Readonly<{ kind: "one"; context: TreeContext }>
  | Readonly<{
      kind: "two";
      first: TreeContext;
      second: TreeContext;
      /** Bit `i` spends input `i` from `second`. */
      secondInputs: bigint;
    }>;

/** One published output slot without its SPP framing, Rust `RingOutput`. */
export type RingOutput =
  | Readonly<{ kind: "delivered"; hash: Bytes32; u: Bytes32; body: Uint8Array }>
  /** Under a view tag, its scheme 1 body unproven and absent on a change output. */
  | Readonly<{ kind: "anonymous"; hash: Bytes32; tag: Bytes32; body?: Uint8Array }>
  | Readonly<{ kind: "exit"; hash: Bytes32; ownerTag: Bytes32; payload: Uint8Array }>;

/** Scheme 2, forwarded under its tag as the first SPP message, Rust `SenderBundle`. */
export interface SenderBundle {
  readonly tag: Bytes32;
  readonly body: Uint8Array;
}

/** The data of `Transact` and `DelegateTransact`, Rust `RingTransactData`. */
export interface RingTransactData {
  readonly rail: RingRail;
  /** SPP shape inputs. */
  readonly nIn: number;
  /** SPP shape outputs. */
  readonly nOut: number;
  readonly auditProof: Uint8Array;
  /** Present exactly on a policy ring. */
  readonly policy?: PolicyProof;
  readonly withdrawalExemption?: Readonly<{ proof: Uint8Array; revision: bigint }>;
  readonly approvalRequired: boolean;
  readonly expiryUnixTs: number;
  readonly txViewingU: Bytes32;
  /** Random per attempt, a resend under the same first nullifier reuses no pad or keystream. */
  readonly salt: Bytes16;
  readonly interfaceTransfers: readonly InterfaceTransfer[];
  /** The policy proof escrows every output nullifier key, the ring mode's. */
  readonly keyEscrow: boolean;
  /** The anonymous entry key, every spent UTXO opens in full. */
  readonly fullOpenings: boolean;
  /** Published order. */
  readonly outputs: readonly RingOutput[];
  /** Present exactly on the anonymous rail. */
  readonly sender?: SenderBundle;
  readonly ephU: Bytes32;
  readonly sealed: Bytes32;
  /** Exactly the fields the disclosure layout publishes. */
  readonly disclosure: readonly Bytes32[];
  readonly privateTxHash: Bytes32;
  /** Present exactly on the anonymous rail. */
  readonly anonymous?: AnonymousProofData;
  /** `a ‖ b ‖ c` with `b` compressed. */
  readonly sppProof: Uint8Array;
  /** One per spent input slot SPP publishes. */
  readonly nullifiers: readonly Bytes32[];
  readonly inputTrees: InputTrees;
}

/** The ring config values the program expands the data with. */
export interface RingTransactConfig {
  /** `0x04 ‖ u`. */
  readonly auditorPubkey: Bytes33;
}

/** The rail of the ring instruction `tag` under `mode`, Rust `RingRail::of`. */
export function ringRailOf(tag: number, mode: RingMode): RingRail {
  if (tag === RingInstructionTag.transact || tag === RingInstructionTag.legacyTransact)
    return mode === "anonymous" ? "anonymous" : "confidential";
  if (
    tag !== RingInstructionTag.delegateTransact &&
    tag !== RingInstructionTag.legacyDelegateTransact
  )
    throw invalid("InvalidInstructionData");
  if (mode === "anonymous") throw invalid("AnonymousRingRefused");
  return "delegate";
}

/** Rust `RingRail::new`, the delegate rail needs the delegate only `SetDelegate` writes. */
export function ringRail(
  tag: number,
  config: Readonly<{ mode: RingMode; delegate?: Address }>,
): RingRail {
  const rail = ringRailOf(tag, config.mode);
  if (rail === "delegate" && config.delegate === undefined) throw invalid("DelegateDisabled");
  return rail;
}

export function railSppTag(rail: RingRail): number {
  return rail === "delegate" ? InstructionTag.ringAuthorityTransact : InstructionTag.ringTransact;
}

/** `hash_bytes(body)` of a delivered slot, zero for any other. */
export function outputBodyHash(output: RingOutput): Bytes32 {
  return output.kind === "delivered" ? (hashBytes(checkedBody(output.body)) as Bytes32) : ZERO;
}

/** `pack_be(u)` of a delivered slot, zeros for any other. */
export function outputRecipientKeyFields(output: RingOutput): readonly Bytes32[] {
  return output.kind === "delivered"
    ? (packBytesBe(checkedField(output.u, "u")) as Bytes32[])
    : [ZERO, ZERO];
}

/** SPP's input slots and tree contexts, the nullifier accounts the instruction names follow them. */
export function ringSppInputs(
  data: Pick<RingTransactData, "nullifiers" | "inputTrees">,
): Pick<TransactInstructionData, "inputs" | "treeContexts"> {
  return Object.freeze({
    inputs: data.nullifiers.map((nullifierHash, input) =>
      Object.freeze({ nullifierHash, treeIndex: treeIndex(data.inputTrees, input) }),
    ),
    treeContexts:
      data.inputTrees.kind === "one"
        ? [data.inputTrees.context]
        : [data.inputTrees.first, data.inputTrees.second],
  });
}

/** The layout the audit key of a shape publishes, `inputs` and `outputs` the published counts. */
export function ringDisclosureLayout(
  shape: Readonly<{
    rail: RingRail;
    nIn: number;
    nOut: number;
    inputs: number;
    outputs: number;
    layout: AuditLayout;
  }>,
): DisclosureLayout {
  const { keyEscrow, fullOpenings } = shape.layout;
  const flags: FrameFlags = { defaultOwnerTag: false, keyEscrow, fullOpenings };
  checkFrameFlags(flags, shape.rail);
  return auditShape(shape.rail, {
    nIn: shape.nIn,
    nOut: shape.nOut,
    inputCount: shape.inputs,
    flags,
  }).layout(shape.outputs, shape.layout);
}

/** `0x04 ‖ u`, the tagged key the statements pack and SPP carries. */
export function taggedX25519(u: Bytes32): Bytes33 {
  const key = new Uint8Array(33);
  key[0] = VIEWING_PUBKEY_TAG;
  key.set(checkedField(u, "u"), 1);
  return key as Bytes33;
}

export const RingTransactData = Object.freeze({
  /** Every length fixed by the flags, the shape and the counts, trailing bytes refused. */
  parse(data: Uint8Array, rail: RingRail): RingTransactData {
    const bytes = new TransactReader(data);
    try {
      return readCompact(bytes, rail);
    } catch (error) {
      throw shortRead(error, "RingTransactLength");
    }
  },

  /** Historical decoding only; the upgraded program rejects legacy tags. */
  parseLegacy(data: Uint8Array, rail: RingRail): RingTransactData {
    try {
      return readCompact(new TransactReader(data), rail, true);
    } catch (error) {
      throw shortRead(error, "RingTransactLength");
    }
  },

  /** The bytes `parse` reads back, refusing what it refuses. */
  encode(data: RingTransactData): Uint8Array {
    try {
      return writeCompact(data);
    } catch (error) {
      throw shortRead(error, "InvalidInstructionData");
    }
  },

  /** The statement's layout element, the exits flag read from the outputs. */
  auditLayout(data: RingTransactData): AuditLayout {
    return Object.freeze({
      exits: data.outputs.some((output) => output.kind === "exit"),
      keyEscrow: data.keyEscrow,
      fullOpenings: data.fullOpenings,
    });
  },

  disclosureLayout(data: RingTransactData): DisclosureLayout {
    return ringDisclosureLayout({
      rail: data.rail,
      nIn: data.nIn,
      nOut: data.nOut,
      inputs: data.nullifiers.length,
      outputs: data.outputs.length,
      layout: RingTransactData.auditLayout(data),
    });
  },

  /** The SPP selector of the data's shape and rail. */
  circuit(data: RingTransactData): RingCircuitId {
    return circuitId(data.rail, data.nIn, data.nOut, data.anonymous);
  },

  firstNullifier(data: RingTransactData): Bytes32 {
    const first = data.nullifiers[0];
    if (first === undefined) throw invalid("RingTransactLength");
    return first;
  },

  /** The SPP data the program forwards, `b` decompressed for SPP's verifier. */
  expand(data: RingTransactData, config: RingTransactConfig): RingTransactInstructionData {
    let b: Bytes128;
    try {
      b = decompressG2(data.sppProof.slice(32, 96) as Bytes64);
    } catch (cause) {
      throw new RingError("RING_TRANSACT_DATA_INVALID", {
        details: { reason: "InvalidSppProofPoint" },
        cause,
      });
    }
    return transactIxData(data, config, {
      a: data.sppProof.slice(0, 32) as Bytes32,
      b,
      c: data.sppProof.slice(96, 128) as Bytes32,
    });
  },

  sppInstructionData(data: RingTransactData, config: RingTransactConfig): Uint8Array {
    const expanded = encodeRingTransactInstructionData(RingTransactData.expand(data, config));
    const out = new Uint8Array(1 + expanded.length);
    out[0] = railSppTag(data.rail);
    out.set(expanded, 1);
    return out;
  },

  /** The external data hash the SPP proof binds, computable before either proof exists. */
  externalDataHash(
    data: RingTransactData,
    config: RingTransactConfig,
    settlements: readonly SettlementAccounts[],
  ): Bytes32 {
    const expanded = transactIxData(data, config, ZERO_PROOF);
    return externalDataHash({
      ...expanded,
      instructionDiscriminator: railSppTag(data.rail),
      settlementAccounts: settlements,
      resolvedOwnerTags: expanded.outputs.map((output) =>
        output.ownerTag.kind === "inline" ? output.ownerTag.value : ZERO,
      ),
    });
  },
});

/** Byte 0 of the compact data. */
const Flag = Object.freeze({
  policy: 1 << 0,
  curator: 1 << 1,
  approvalRequired: 1 << 2,
  secondTree: 1 << 5,
});
/** Bits 3, 4, 6 and 7 are refused. */
const KNOWN_FLAGS = Flag.policy | Flag.curator | Flag.approvalRequired | Flag.secondTree;

/** Bytes 1 and 2 of the compact data, the SPP shape's index and the input count below their flags. */
const FrameByte = Object.freeze({
  low: 0b0011_1111,
  bit6: 1 << 6,
  bit7: 1 << 7,
});

/** The flags of frame bytes 1 and 2, Rust `FrameFlags`. */
interface FrameFlags {
  /** Shape byte bit 6, the anonymous rail's default owner tag follows the commitment pok. */
  readonly defaultOwnerTag: boolean;
  /** Input byte bit 6. */
  readonly keyEscrow: boolean;
  /** Input byte bit 7, the anonymous entry key. */
  readonly fullOpenings: boolean;
}

interface FrameHeader {
  readonly nIn: number;
  readonly nOut: number;
  readonly inputCount: number;
  readonly flags: FrameFlags;
}

/** A storage revision, little endian u64. */
export const REVISION_LENGTH = 8;
/** `a ‖ b ‖ c` with `b` compressed, Rust `PlainGroth16Proof::SIZE`. */
export const PLAIN_GROTH16_PROOF_LENGTH = 128;
const VIEWING_PUBKEY_TAG = 4;
const ZERO = new Uint8Array(32) as Bytes32;
const ZERO_PROOF = Object.freeze({
  a: new Uint8Array(32) as Bytes32,
  b: new Uint8Array(128) as Bytes128,
  c: new Uint8Array(32) as Bytes32,
});

type AuditShape = Readonly<{
  /** Every slot of the shape is published. */
  outputs: number;
  layout(published: number, flags: AuditLayout): DisclosureLayout;
}>;

/** The audit key the header names, before the outputs are read, Rust `RingRail::audit_shape`. */
function auditShape(rail: RingRail, header: FrameHeader): AuditShape {
  const { nIn, nOut, inputCount: inputs } = header;
  const keyed = rail === "delegate" ? RING_AUTHORITY_SHAPES : SPP_SUPPORTED_SHAPES;
  const supported = keyed.some((shape) => shape.inputs === nIn && shape.outputs === nOut);
  let shape: AuditShape | undefined;
  if (rail !== "anonymous" && DELIVERED_AUDIT_CAPACITIES.includes(nOut)) {
    shape = {
      outputs: nOut,
      layout: (published, flags) =>
        exactly(published, nOut, {
          kind: "delivered",
          outputs: nOut,
          exits: flags.exits,
          keyEscrow: flags.keyEscrow,
        }),
    };
  } else if (rail === "anonymous") {
    const key = anonymousAuditKey({
      inputs,
      outputs: nOut,
      spendsDefaultRing: header.flags.fullOpenings,
    });
    if (key !== undefined)
      shape = {
        outputs: nOut,
        layout: (published, flags) =>
          exactly(published, nOut, {
            kind: "anonymous",
            key,
            inputs,
            outputs: nOut,
            exits: flags.exits,
          }),
      };
  }
  if (shape === undefined || !supported) throw invalid("RingShapeUnkeyed");
  if (inputs === 0 || inputs > nIn) throw invalid("RingTransactLength");
  return shape;
}

function exactly(published: number, outputs: number, layout: DisclosureLayout): DisclosureLayout {
  if (published !== outputs) throw invalid("RingTransactLength");
  return Object.freeze(layout);
}

function readCompact(bytes: TransactReader, rail: RingRail, legacy = false): RingTransactData {
  const flags = bytes.u8("flags");
  checkFlags(flags);
  const header = readHeader(bytes, rail);
  const { nIn, nOut, inputCount } = header;
  const shape = auditShape(rail, header);
  const auditProof = bytes.bytes(CUSTOM_RING_PROOF_LENGTH, "auditProof");
  let policy = has(flags, Flag.policy)
    ? readPolicy(bytes, {
        curator: has(flags, Flag.curator),
        anonymous: rail === "anonymous",
        legacy,
      })
    : undefined;
  const expiryUnixTs = bytes.u32("expiryUnixTs");
  const txViewingU = field32(bytes, "txViewingU");
  const salt = bytes.bytes(16, "salt") as Bytes16;
  const interfaceTransfers = within("InvalidInstructionData", () =>
    Array.from({ length: bytes.u8("interfaceTransfers.length") }, () =>
      readInterfaceTransfer(bytes),
    ),
  );
  if (policy !== undefined && !legacy)
    policy = Object.freeze({
      ...policy,
      splWithdrawalOwners: Object.freeze(
        interfaceTransfers
          .filter((t) => t.kind === "splWithdrawal")
          .map(() => field32(bytes, "splWithdrawalOwner")),
      ),
    });
  const outputCount = shape.outputs;
  const exits = readBitmap(bytes, outputCount);
  if (rail === "delegate" && exits !== 0n) throw invalid("FlagNotAllowed");
  const layout = shape.layout(outputCount, auditLayoutOf(header.flags, exits !== 0n));
  const outputs = Array.from({ length: outputCount }, (_, slot) =>
    readOutput(bytes, layout, ((exits >> BigInt(slot)) & 1n) === 1n),
  );
  const sender = rail === "anonymous" ? readSender(bytes) : undefined;
  const ephU = field32(bytes, "ephU");
  const sealed = field32(bytes, "sealed");
  const disclosure = Array.from({ length: disclosureFieldCount(layout) }, () =>
    field32(bytes, "disclosure"),
  );
  const privateTxHash = field32(bytes, "privateTxHash");
  const anonymous =
    rail === "anonymous" ? readAnonymous(bytes, header.flags.defaultOwnerTag) : undefined;
  const sppProof = bytes.bytes(PLAIN_GROTH16_PROOF_LENGTH, "sppProof");
  const nullifiers = Array.from({ length: inputCount }, () => field32(bytes, "nullifier"));
  const inputTrees: InputTrees = has(flags, Flag.secondTree)
    ? (() => {
        const secondInputs = readBitmap(bytes, inputCount);
        return Object.freeze({
          kind: "two" as const,
          first: readTreeContext(bytes),
          second: readTreeContext(bytes),
          secondInputs,
        });
      })()
    : Object.freeze({ kind: "one" as const, context: readTreeContext(bytes) });
  const withdrawalExemption =
    !legacy && bytes.remaining === CUSTOM_RING_PROOF_LENGTH + REVISION_LENGTH
      ? Object.freeze({
          proof: bytes.bytes(CUSTOM_RING_PROOF_LENGTH, "withdrawalExemption.proof"),
          revision: bytes.u64("withdrawalExemption.revision"),
        })
      : undefined;
  bytes.done();
  return Object.freeze({
    ...(withdrawalExemption === undefined ? {} : { withdrawalExemption }),
    rail,
    nIn,
    nOut,
    auditProof,
    ...(policy === undefined ? {} : { policy }),
    approvalRequired: has(flags, Flag.approvalRequired),
    expiryUnixTs,
    txViewingU,
    salt,
    interfaceTransfers: Object.freeze(interfaceTransfers),
    keyEscrow: header.flags.keyEscrow,
    fullOpenings: header.flags.fullOpenings,
    outputs: Object.freeze(outputs),
    ...(sender === undefined ? {} : { sender }),
    ephU,
    sealed,
    disclosure: Object.freeze(disclosure),
    privateTxHash,
    ...(anonymous === undefined ? {} : { anonymous }),
    sppProof,
    nullifiers: Object.freeze(nullifiers),
    inputTrees,
  });
}

/** A legacy frame names each root by a one byte history slot, read into its revision field. */
function readPolicy(
  bytes: Reader,
  frame: Readonly<{ curator: boolean; anonymous: boolean; legacy: boolean }>,
): PolicyProof {
  const proof = bytes.bytes(CUSTOM_RING_PROOF_LENGTH, "policy.proof");
  const revision = (field: string): bigint =>
    frame.legacy ? BigInt(bytes.u8(field)) : bytes.u64(field);
  const ownRevision = revision("policy.ownRevision");
  const curatorRevision = frame.curator ? revision("policy.curatorRevision") : undefined;
  const senderCommitment = frame.anonymous ? field32(bytes, "policy.senderCommitment") : undefined;
  return Object.freeze({
    proof,
    ownRevision,
    splWithdrawalOwners: Object.freeze([]),
    ...(curatorRevision === undefined ? {} : { curatorRevision }),
    ...(senderCommitment === undefined ? {} : { senderCommitment }),
  });
}

function readSender(bytes: Reader): SenderBundle {
  const tag = field32(bytes, "sender.tag");
  const body = readAnonymousBody(bytes, "sender");
  if (body.length === 0) throw invalid("AnonymousBodyLength");
  return Object.freeze({ tag, body });
}

function readAnonymous(bytes: Reader, tagged: boolean): AnonymousProofData {
  const commitment = field32(bytes, "anonymous.commitment");
  const commitmentPok = field32(bytes, "anonymous.commitmentPok");
  const defaultOwnerTag = tagged ? field32(bytes, "anonymous.defaultOwnerTag") : undefined;
  return Object.freeze({
    commitment,
    commitmentPok,
    ...(defaultOwnerTag === undefined ? {} : { defaultOwnerTag }),
  });
}

/** No output carries data, every exit payload is a data-free scheme 3 body. */
function readOutput(bytes: Reader, layout: DisclosureLayout, exit: boolean): RingOutput {
  const hash = field32(bytes, "output.hash");
  if (exit) {
    const ownerTag = field32(bytes, "output.ownerTag");
    return Object.freeze({
      kind: "exit",
      hash,
      ownerTag,
      payload: bytes.bytes(CONFIDENTIAL_DATA_FREE_BODY_LEN, "output.payload"),
    });
  }
  switch (layout.kind) {
    case "delivered": {
      const u = field32(bytes, "output.u");
      return Object.freeze({
        kind: "delivered",
        hash,
        u,
        body: bytes.bytes(RING_DELIVERED_BODY_LEN, "output.body"),
      });
    }
    case "anonymous": {
      const tag = field32(bytes, "output.tag");
      const body = readAnonymousBody(bytes, "output");
      return Object.freeze({
        kind: "anonymous",
        hash,
        tag,
        ...(body.length === 0 ? {} : { body }),
      });
    }
  }
}

function readAnonymousBody(bytes: Reader, name: string): Uint8Array {
  return bytes.bytes(bytes.u16(`${name}.length`), `${name}.body`);
}

/** `ceil(len / 8)` bytes, bit `i` at byte `i / 8` bit `i % 8`, no bit set past `len`. */
function readBitmap(bytes: Reader, length: number): bigint {
  const raw = bytes.bytes(Math.ceil(length / 8), "bitmap");
  const bits = raw.reduce((value, byte, index) => value | (BigInt(byte) << BigInt(8 * index)), 0n);
  if (bits >> BigInt(length) !== 0n) throw invalid("InvalidInstructionData");
  return bits;
}

function writeCompact(data: RingTransactData): Uint8Array {
  const flags = compactFlags(data);
  checkFlags(flags);
  if ([data.keyEscrow, data.fullOpenings].some((flag) => typeof flag !== "boolean"))
    throw invalid("InvalidInstructionData");
  const header = headerOf(data);
  const shape = auditShape(data.rail, header);
  const layout = shape.layout(data.outputs.length, RingTransactData.auditLayout(data));
  const anonymousRail = data.rail === "anonymous";
  const commitmentFits =
    data.policy === undefined || (data.policy.senderCommitment !== undefined) === anonymousRail;
  if (
    !commitmentFits ||
    (data.anonymous !== undefined) !== anonymousRail ||
    (data.sender !== undefined) !== anonymousRail ||
    data.disclosure.length !== disclosureFieldCount(layout) ||
    !data.outputs.every((output) => fits(output, layout))
  )
    throw invalid("RingTransactLength");
  if (data.rail === "delegate" && data.outputs.some((output) => output.kind === "exit"))
    throw invalid("FlagNotAllowed");
  const [shapeByte, inputByte] = headerBytes(header);
  const out = new Writer()
    .u8(flags, "flags")
    .u8(shapeByte, "shapeByte")
    .u8(inputByte, "inputByte")
    .bytes(data.auditProof, CUSTOM_RING_PROOF_LENGTH, "auditProof");
  if (data.policy !== undefined) {
    out.bytes(data.policy.proof, CUSTOM_RING_PROOF_LENGTH, "policy.proof");
    out.u64(data.policy.ownRevision, "policy.ownRevision");
    if (data.policy.curatorRevision !== undefined)
      out.u64(data.policy.curatorRevision, "policy.curatorRevision");
    if (data.policy.senderCommitment !== undefined)
      out.bytes(data.policy.senderCommitment, 32, "policy.senderCommitment");
  }
  out
    .u32(data.expiryUnixTs, "expiryUnixTs")
    .bytes(data.txViewingU, 32, "txViewingU")
    .bytes(data.salt, 16, "salt")
    .u8(data.interfaceTransfers.length, "interfaceTransfers.length");
  for (const transfer of data.interfaceTransfers) writeInterfaceTransfer(out, transfer);
  if (data.policy !== undefined) {
    if (
      data.policy.splWithdrawalOwners.length !==
      data.interfaceTransfers.filter((t) => t.kind === "splWithdrawal").length
    )
      throw invalid("RingTransactLength");
    for (const owner of data.policy.splWithdrawalOwners) out.bytes(owner, 32, "splWithdrawalOwner");
  }
  writeBitmap(
    out,
    data.outputs.map((output) => output.kind === "exit"),
  );
  for (const output of data.outputs) writeOutput(out, output);
  if (data.sender !== undefined) {
    out.bytes(data.sender.tag, 32, "sender.tag");
    writeAnonymousBody(out, data.sender.body, "sender");
  }
  out.bytes(data.ephU, 32, "ephU").bytes(data.sealed, 32, "sealed");
  for (const field of data.disclosure) out.bytes(field, 32, "disclosure");
  out.bytes(data.privateTxHash, 32, "privateTxHash");
  if (data.anonymous !== undefined) {
    out
      .bytes(data.anonymous.commitment, 32, "anonymous.commitment")
      .bytes(data.anonymous.commitmentPok, 32, "anonymous.commitmentPok");
    if (data.anonymous.defaultOwnerTag !== undefined)
      out.bytes(data.anonymous.defaultOwnerTag, 32, "anonymous.defaultOwnerTag");
  }
  out.bytes(data.sppProof, PLAIN_GROTH16_PROOF_LENGTH, "sppProof");
  for (const nullifier of data.nullifiers) out.bytes(nullifier, 32, "nullifier");
  if (data.inputTrees.kind === "one") {
    writeTreeContext(out, data.inputTrees.context);
  } else {
    const { secondInputs } = data.inputTrees;
    if (
      typeof secondInputs !== "bigint" ||
      secondInputs < 0n ||
      secondInputs >> BigInt(header.inputCount) !== 0n
    )
      throw invalid("InvalidInstructionData");
    writeBitmap(
      out,
      data.nullifiers.map((_, input) => ((secondInputs >> BigInt(input)) & 1n) === 1n),
    );
    writeTreeContext(out, data.inputTrees.first);
    writeTreeContext(out, data.inputTrees.second);
  }
  if (data.withdrawalExemption !== undefined)
    out
      .bytes(data.withdrawalExemption.proof, CUSTOM_RING_PROOF_LENGTH, "withdrawalExemption.proof")
      .u64(data.withdrawalExemption.revision, "withdrawalExemption.revision");
  return out.finish();
}

function writeOutput(out: Writer, output: RingOutput): void {
  out.bytes(output.hash, 32, "output.hash");
  switch (output.kind) {
    case "delivered":
      out
        .bytes(output.u, 32, "output.u")
        .bytes(output.body, RING_DELIVERED_BODY_LEN, "output.body");
      return;
    case "anonymous":
      out.bytes(output.tag, 32, "output.tag");
      if (output.body === undefined) out.u16(0, "output.length");
      else writeAnonymousBody(out, output.body, "output");
      return;
    case "exit":
      if (output.payload.length !== CONFIDENTIAL_DATA_FREE_BODY_LEN)
        throw invalid("DataFreeBodyLength");
      out.bytes(output.ownerTag, 32, "output.ownerTag").bytes(output.payload);
      return;
  }
}

function writeAnonymousBody(out: Writer, body: Uint8Array, name: string): void {
  out.u16(checkedAnonymousBody(body).length, `${name}.length`).bytes(body);
}

function writeBitmap(out: Writer, bits: readonly boolean[]): void {
  const bytes = new Uint8Array(Math.ceil(bits.length / 8));
  bits.forEach((set, index) => {
    if (set) bytes[index >> 3] = (bytes[index >> 3] ?? 0) | (1 << (index & 7));
  });
  out.bytes(bytes);
}

/** Whether the slot uses the output encoding `layout` gives ring outputs. */
function fits(output: RingOutput, layout: DisclosureLayout): boolean {
  return output.kind === "exit" || output.kind === layout.kind;
}

function compactFlags(data: RingTransactData): number {
  const bits: readonly (readonly [boolean, number])[] = [
    [data.policy !== undefined, Flag.policy],
    [data.policy?.curatorRevision !== undefined, Flag.curator],
    [data.approvalRequired, Flag.approvalRequired],
    [data.inputTrees.kind === "two", Flag.secondTree],
  ];
  return bits.reduce((flags, [set, bit]) => (set ? flags | bit : flags), 0);
}

/** The curator and approval flags need a policy. */
function checkFlags(flags: number): void {
  if ((flags & ~KNOWN_FLAGS) !== 0) throw invalid("FlagNotAllowed");
  const needsPolicy = has(flags, Flag.curator) || has(flags, Flag.approvalRequired);
  if (needsPolicy && !has(flags, Flag.policy)) throw invalid("FlagNotAllowed");
}

function has(flags: number, bit: number): boolean {
  return (flags & bit) !== 0;
}

function readHeader(bytes: Reader, rail: RingRail): FrameHeader {
  const shapeByte = bytes.u8("shapeByte");
  const inputByte = bytes.u8("inputByte");
  if (has(shapeByte, FrameByte.bit7)) throw invalid("FlagNotAllowed");
  const shape = SPP_SUPPORTED_SHAPES[shapeByte & FrameByte.low];
  if (shape === undefined) throw invalid("RingShapeUnkeyed");
  const flags: FrameFlags = {
    defaultOwnerTag: has(shapeByte, FrameByte.bit6),
    keyEscrow: has(inputByte, FrameByte.bit6),
    fullOpenings: has(inputByte, FrameByte.bit7),
  };
  checkFrameFlags(flags, rail);
  return { nIn: shape.inputs, nOut: shape.outputs, inputCount: inputByte & FrameByte.low, flags };
}

function headerOf(data: RingTransactData): FrameHeader {
  const flags: FrameFlags = {
    defaultOwnerTag: data.anonymous?.defaultOwnerTag !== undefined,
    keyEscrow: data.keyEscrow,
    fullOpenings: data.fullOpenings,
  };
  checkFrameFlags(flags, data.rail);
  return { nIn: data.nIn, nOut: data.nOut, inputCount: data.nullifiers.length, flags };
}

function headerBytes(header: FrameHeader): readonly [number, number] {
  const index = SPP_SUPPORTED_SHAPES.findIndex(
    (shape) => shape.inputs === header.nIn && shape.outputs === header.nOut,
  );
  if (index < 0) throw invalid("RingShapeUnkeyed");
  if (header.inputCount > FrameByte.low) throw invalid("RingTransactLength");
  const { flags } = header;
  const bit = (set: boolean, value: number) => (set ? value : 0);
  return [
    index | bit(flags.defaultOwnerTag, FrameByte.bit6),
    header.inputCount |
      bit(flags.keyEscrow, FrameByte.bit6) |
      bit(flags.fullOpenings, FrameByte.bit7),
  ];
}

/** The anonymous rail alone takes a default owner tag and the entry key and never escrows, the delegate rail always escrows. */
function checkFrameFlags(flags: FrameFlags, rail: RingRail): void {
  const anonymousOnly = flags.defaultOwnerTag || flags.fullOpenings;
  const refused =
    rail === "anonymous"
      ? flags.keyEscrow
      : rail === "confidential"
        ? anonymousOnly
        : anonymousOnly || !flags.keyEscrow;
  if (refused) throw invalid("FlagNotAllowed");
}

/** The audit statement's layout element, Rust `FrameFlags::audit_layout`. */
function auditLayoutOf(flags: FrameFlags, exits: boolean): AuditLayout {
  return Object.freeze({
    exits,
    keyEscrow: flags.keyEscrow,
    fullOpenings: flags.fullOpenings,
  });
}

function circuitId(
  rail: RingRail,
  inputs: number,
  outputs: number,
  anonymous: AnonymousProofData | undefined,
): RingCircuitId {
  const shape = { inputs, outputs, publicAssetSlots: N_PUBLIC_SLOTS };
  switch (rail) {
    case "confidential":
      return Object.freeze({ kind: "confidentialRingEddsa", ...shape });
    case "delegate":
      return Object.freeze({ kind: "ringAuthority", ...shape });
    case "anonymous":
      if (anonymous === undefined) throw invalid("RingTransactLength");
      return Object.freeze({
        kind: "anonymousRingEddsa",
        ...shape,
        proofData: Object.freeze({
          bsb22Commitment: Object.freeze({
            commitment: anonymous.commitment,
            commitmentPok: anonymous.commitmentPok,
          }),
          ...(anonymous.defaultOwnerTag === undefined
            ? {}
            : { defaultOwnerTag: anonymous.defaultOwnerTag }),
        }),
      });
  }
}

function transactIxData(
  data: RingTransactData,
  config: RingTransactConfig,
  proof: TransactInstructionData["proof"],
): RingTransactInstructionData {
  const auditor = config.auditorPubkey;
  if (!(auditor instanceof Uint8Array) || auditor.length !== 33)
    throw invalid("InvalidAuditorPubkey");
  return Object.freeze({
    expiryUnixTs: BigInt(data.expiryUnixTs),
    txViewingPk: taggedX25519(data.txViewingU),
    salt: data.salt,
    interfaceTransfers: data.interfaceTransfers,
    outputs: data.outputs.map(ringTransactOutput),
    // The auditor message stays last.
    messages: [
      ...(data.sender === undefined
        ? []
        : [
            Object.freeze({
              viewTag: checkedField(data.sender.tag, "sender.tag"),
              data: encodeRingOutput(
                RingScheme.anonymousSender,
                checkedAnonymousBody(data.sender.body),
              ),
            }),
          ]),
      Object.freeze({
        viewTag: auditor.slice(1) as Bytes32,
        data: concat([
          taggedX25519(data.ephU),
          checkedField(data.sealed, "sealed"),
          ...data.disclosure,
        ]),
      }),
    ],
    privateTxHash: data.privateTxHash,
    circuit: RingTransactData.circuit(data),
    proof,
    ...ringSppInputs(data),
  });
}

/** The SPP output, the owner tag and the scheme framing rebuilt from the slot, Rust `RingOutput::transact_output`. */
export function ringTransactOutput(output: RingOutput): TransactOutput {
  const [ownerTag, data] = ((): readonly [Bytes32, Uint8Array | undefined] => {
    switch (output.kind) {
      case "delivered":
        return [
          output.u,
          encodeRingOutput(RingScheme.ringConfidentialDelivered, checkedBody(output.body)),
        ];
      case "anonymous":
        return [
          output.tag,
          output.body === undefined
            ? undefined
            : encodeRingOutput(RingScheme.anonymousRecipient, checkedAnonymousBody(output.body)),
        ];
      case "exit":
        return [output.ownerTag, encodeRingOutput(RingScheme.confidential, output.payload)];
    }
  })();
  return Object.freeze({
    utxoHash: output.hash,
    ownerTag: Object.freeze({ kind: "inline", value: checkedField(ownerTag, "ownerTag") }),
    ...(data === undefined ? {} : { data }),
  });
}

function treeIndex(trees: InputTrees, input: number): number {
  return trees.kind === "one" ? 0 : Number((trees.secondInputs >> BigInt(input)) & 1n);
}

function field32(bytes: Reader, name: string): Bytes32 {
  return bytes.bytes(32, name) as Bytes32;
}

function checkedField(value: Uint8Array, name: string): Bytes32 {
  if (!(value instanceof Uint8Array) || value.length !== 32)
    throw new RingError("RING_TRANSACT_DATA_INVALID", {
      details: { reason: "InvalidInstructionData", name },
    });
  return value as Bytes32;
}

function checkedAnonymousBody(body: Uint8Array): Uint8Array {
  if (!(body instanceof Uint8Array) || body.length === 0 || body.length > 0xffff)
    throw invalid("AnonymousBodyLength");
  return body;
}

function checkedBody(body: Uint8Array): Uint8Array {
  if (!(body instanceof Uint8Array) || body.length !== RING_DELIVERED_BODY_LEN)
    throw invalid("RingTransactLength");
  return body;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** An interface codec failure inside `run` reads as `reason`. */
function within<T>(reason: string, run: () => T): T {
  try {
    return run();
  } catch (error) {
    throw shortRead(error, reason);
  }
}

/** A short read or a codec refusal is the program's `reason`, a ring refusal passes through. */
function shortRead(error: unknown, reason: string): unknown {
  return error instanceof InterfaceError
    ? new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason }, cause: error })
    : error;
}

/** `reason` names the `CustomRingError` the program raises. */
function invalid(reason: string): RingError {
  return new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason } });
}

/** Tracks the optional suffix without changing the core codec. */
class TransactReader extends Reader {
  remaining: number;
  constructor(data: Uint8Array) {
    super(data);
    this.remaining = data.length;
  }
  override bytes(length: number, name: string): Uint8Array {
    const result = super.bytes(length, name);
    this.remaining -= length;
    return result;
  }
}
