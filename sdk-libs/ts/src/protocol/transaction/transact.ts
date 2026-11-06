import {
  writeTreeContext,
  Reader,
  Writer,
  concatBytes,
  equalBytes,
  solanaOwnerIdentity,
} from "@heliuslabs/spr/internal";
import {
  encodeRingTransactInstructionData,
  type RingCircuitId,
  type RingTransactInstructionData,
} from "../proof/circuit.js";
import {
  InterfaceError,
  externalDataHash,
  InstructionTag,
  MAX_CACHE_WRITES,
  SPP_SUPPORTED_SHAPES,
  type SettlementAccounts,
} from "@heliuslabs/spr/interface";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes64,
  Bytes128,
  CacheAccess,
  InterfaceTransfer,
  MessageData,
  TransactInstructionData,
  TransactOutput,
  TreeContext,
  Shape,
} from "@heliuslabs/spr/interface";
import { CUSTOM_RING_PROOF_LENGTH } from "../proof/custom-ring-proof.js";
import {
  auditRecordLength,
  DisclosureFormat,
  SINGLE_ASSET_PAYOUT_INPUTS,
  SINGLE_ASSET_PAYOUT_OUTPUTS,
  disclosureFormat,
  DATA_TAIL_LEN,
  checkedStreamLayout,
  envelopeRegion,
  type AuditLayout,
  type AuditStreamLayout,
} from "../codec/ring-disclosure-layout.js";
import {
  type BundleLayout,
  MIN_REPLY_LEN,
  RECIPIENT_BODY_LEN,
  COMPACT_RECIPIENT_BODY_LEN,
  senderBundleLen,
} from "../codec/anonymous-delivery.js";
import {
  SLOT_TAG_LEN,
  framedSlotTag,
  slotTag,
  unframedSlotTag,
} from "../../crypto/derivation/ring-stream.js";
import { fittedSpend, frameKeyShape } from "../proof/transfer-shapes.js";
import { validSignerDataCounts } from "../membership/signer-data-counts.js";

import { RingInstructionTag } from "./instruction-tag.js";
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
  encodeRingBodyOutput,
  encodeRingOutput,
  RingScheme,
} from "./output.js";

/** The program rail the data serves, fixed by the instruction and the ring mode, Rust `RingRail`. */
export type RingRail = "confidential" | "anonymous" | "delegate" | "anonymousDelegate";

/** The policy section of the frame, Rust `PolicyProof`. */
export interface PolicyProof {
  /** Set exactly when a source names the curator registry. */
  readonly curatorRevision?: bigint;
}

/** One application message, forwarded ahead of the auditor's, Rust `AppMessage`. */
export interface AppMessage {
  readonly viewTag: Bytes32;
  readonly data: Uint8Array;
}

/** SPP's optional fields a frame carries through, each absent by default, Rust `FrameExtensions`. */
export interface FrameExtensions {
  readonly format?: DisclosureFormat;
  /** The transaction's application digest, distinct from a note's `data_hash`. */
  readonly dataHash?: Bytes32;
  /** The transaction's ring digest, distinct from a note's `ring_data_hash`. */
  readonly ringDataHash?: Bytes32;
  readonly messages?: readonly AppMessage[];
  /** The cached selector, refused on the authority rails. */
  readonly cache?: CacheAccess;
  /** Present only for a co-signer that reads exact totals, the opening stays off chain. */
  readonly approvalTotals?: Bytes32;
  /** Present exactly while a count is nonzero, an absent one reads zero in the statement. */
  readonly signerDataCounts?: bigint;
}

/** Rust `ApprovalMask`. */
export const ApprovalMask = Object.freeze({ outflow: 1, withdrawal: 2 } as const);
/** Each record covers a new class. */
export const MAX_CO_SIGNERS = 5;
/** Rust `ANONYMOUS_PARTIES`. */
export const ANONYMOUS_PARTIES = 2 + MAX_CO_SIGNERS;

/** The owner SPP's anonymous rail verifies and hides, the transfer statement publishes it. */
export interface InProofOwner {
  readonly owner: Bytes32;
  readonly commitment: Bytes32;
  readonly commitmentPok: Bytes32;
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

/** The bytes a slot hands SPP outside the proof, the external data hash binds them, Rust `SlotBody`. */
export type SlotBody =
  /** A slot another message covers, such as change the sender bundle holds. */
  | Readonly<{ kind: "none" }>
  /** Ring body under the slot's view tag or recipient key. */
  | Readonly<{ kind: "recipient"; body: Uint8Array }>
  /** Scheme 3 under its own owner tag, a default-ring wallet reads it. */
  | Readonly<{ kind: "exit"; payload: Uint8Array }>;

/** A published output slot without its SPP framing, its record in the auditor message, Rust `RingOutput`. */
export interface RingOutput {
  readonly hash: Bytes32;
  readonly ownerTag: Bytes32;
  readonly body: SlotBody;
  /** `AUDIT_RECORD_LEN` sealed bytes. */
  readonly record: Uint8Array;
  /** `DATA_TAIL_LEN` sealed bytes, present exactly under `hasData`. */
  readonly tail?: Uint8Array;
}

/** Sender bundle, forwarded under its tag as the first SPP message, its length fixed by `m`. */
export interface PublishedSenderBundle {
  readonly tag: Bytes32;
  readonly body: Uint8Array;
}

/** Every reply of a frame, one length, a hidden dummy matches a recipient, Rust `Replies`. */
export interface Replies {
  /** `reply_len`, at least `MIN_REPLY_LEN`. */
  readonly length: number;
  /** `length` bytes per body-bearing slot, in slot order. */
  readonly region: Uint8Array;
}

/** The data of `Transfer` and `AuthorityTransfer`, every count ahead of the sections it sizes, Rust `RingTransactData`. */
export interface RingTransactData {
  readonly rail: RingRail;
  /** SPP shape inputs. */
  readonly nIn: number;
  /** SPP shape outputs, the key's `N`. */
  readonly nOut: number;
  readonly proof: Uint8Array;
  /** Every rail reads it, the output predicate needs a served root. */
  readonly trackingRevision: bigint;
  /** Present exactly on a ring with own records, off the delegate rails. */
  readonly ownRevision?: bigint;
  /** Present exactly on a policy ring, off the delegate rails. */
  readonly policy?: PolicyProof;
  /** Token owners checked on chain in SPL withdrawal order, present with `ownRevision`. */
  readonly splWithdrawalOwners: readonly Bytes32[];
  /** `ApprovalMask` bits the statement proves. */
  readonly approval: number;
  /** The sealed `R` is zero. */
  readonly noSpend: boolean;
  /** The anonymous rail with every live owner a published signer, SPP's confidential rail settles it. */
  readonly publicOwners: boolean;
  readonly expiryUnixTs: number;
  readonly txViewingU: Bytes32;
  /** Random per attempt, a resend under the same first nullifier reuses no keystream. */
  readonly salt: Bytes16;
  readonly extensions: FrameExtensions;
  readonly interfaceTransfers: readonly InterfaceTransfer[];
  /** One tail per published slot, every data hash is zero while clear. */
  readonly hasData: boolean;
  /** The key with entry capacity. */
  readonly entry: boolean;
  /** The key with its full owner rows, a hidden owner count needs the frame to name the key. */
  readonly wideOwners: boolean;
  /** The `m` published slots, slot `i` keeps its index in every derivation. */
  readonly outputs: readonly RingOutput[];
  /** Set exactly under the reply flag. */
  readonly replies?: Replies;
  /** Present exactly on the anonymous frame. */
  readonly sender?: PublishedSenderBundle;
  /** `envelope_ct`, the transmitted length is the stream layout's. */
  readonly envelope: Uint8Array;
  readonly privateTxHash: Bytes32;
  /** Present exactly on the anonymous rail with a hidden sender. */
  readonly anonymous?: AnonymousProofData;
  /** Set exactly on the in-proof owner rail. */
  readonly inProofOwner?: InProofOwner;
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
  if (tag === RingInstructionTag.transfer)
    return mode === "anonymous" ? "anonymous" : "confidential";
  if (tag === RingInstructionTag.authorityTransfer)
    return mode === "anonymous" ? "anonymousDelegate" : "delegate";
  throw invalid("InvalidInstructionData");
}

/** The rail of a landed ring instruction, read from its own bytes and SPP's rail. */
export function landedRingRail(instruction: Uint8Array, sppAnonymous: boolean): RingRail {
  const tag = instruction[0];
  if (tag === undefined) throw invalid("InvalidInstructionData");
  if (tag === RingInstructionTag.authorityTransfer) return authorityRail(instruction);
  const ownerInProof = has(instruction[1] ?? 0, Flag.ownerInProof);
  const publicOwners = has(instruction[2] ?? 0, ShapeFlag.publicOwners);
  return ringRailOf(
    tag,
    (sppAnonymous && !ownerInProof) || publicOwners ? "anonymous" : "confidential",
  );
}

/** SPP's authority rail names neither ring mode, the frame parses under one, the sender bundle moves every length. */
function authorityRail(instruction: Uint8Array): RingRail {
  for (const rail of ["delegate", "anonymousDelegate"] as const) {
    try {
      RingTransactData.parse(instruction.subarray(1), rail);
      return rail;
    } catch (error) {
      if (!(error instanceof RingError)) throw error;
    }
  }
  throw invalid("InvalidInstructionData");
}

/** Rust `RingRail::new`, the delegate rails need the delegate only `SetDelegate` writes. */
export function ringRail(
  tag: number,
  config: Readonly<{ mode: RingMode; delegate?: Address }>,
): RingRail {
  const rail = ringRailOf(tag, config.mode);
  if (isDelegateRail(rail) && config.delegate === undefined) throw invalid("DelegateDisabled");
  return rail;
}

export function isDelegateRail(rail: RingRail): boolean {
  return rail === "delegate" || rail === "anonymousDelegate";
}

export function isAnonymousFrame(rail: RingRail): boolean {
  return rail === "anonymous" || rail === "anonymousDelegate";
}

/** Rust `MAX_SPP_MESSAGES`, SPP's `messages` vector has a `u8` length. */
export const MAX_SPP_MESSAGES = 0xff;

/** Rust `MAX_CPI_DATA_LEN`, the runtime's ceiling on the SPP data a transfer forwards. */
export const MAX_CPI_DATA_LEN = 10 * 1024;

/** Rust `max_application_messages`, SPP also receives the auditor message and an anonymous frame's sender bundle. */
export function maxApplicationMessages(rail: RingRail): number {
  return MAX_SPP_MESSAGES - 1 - (isAnonymousFrame(rail) ? 1 : 0);
}

/** Runs ahead of the message list's allocation, as Rust `check_message_count`. */
function checkMessageCount(count: number, rail: RingRail): void {
  if (count > maxApplicationMessages(rail)) throw invalid("TooManyApplicationMessages");
}

export function railSppTag(rail: RingRail): number {
  return isDelegateRail(rail) ? InstructionTag.ringAuthorityTransact : InstructionTag.ringTransact;
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

/** The stream layout the audit key of a shape fixes, `inputs` the published count. */
export function ringStreamLayout(
  shape: Readonly<{
    rail: RingRail;
    format?: DisclosureFormat;
    nIn: number;
    nOut: number;
    inputs: number;
    /** `m`. */
    outputs: number;
    entry: boolean;
    hasData: boolean;
    publicOwners?: boolean;
    /** The selected key's flag, unset fits the published counts alone. */
    wideOwners?: boolean;
  }>,
): AuditStreamLayout {
  const fitted = fittedSpend({
    rail: shape.rail,
    format: disclosureFormat(shape.format),
    inputs: shape.inputs,
    outputs: shape.nOut,
    spendsDefaultRing: shape.entry,
    legs: 0,
    owners: 0,
    pools: { own: 0, curator: 0, tracking: 0 },
    wide: false,
  });
  const spend = { ...fitted, wide: shape.wideOwners ?? fitted.wide };
  const flags: FrameFlags = {
    defaultOwnerTag: false,
    publicOwners: shape.publicOwners ?? false,
    hasData: shape.hasData,
    entry: shape.entry,
    wideOwners: spend.wide,
  };
  if (frameKeyShape(spend) === undefined)
    throw new RingError("RING_CATALOG_KEY_MISSING", {
      details: { rail: shape.rail, inputs: shape.inputs, outputs: shape.nOut },
    });
  checkFrameFlags(flags, shape.rail);
  return streamOf(
    shape.rail,
    {
      nIn: shape.nIn,
      nOut: shape.nOut,
      inputCount: shape.inputs,
      outputCount: shape.outputs,
      flags,
    },
    disclosureFormat(shape.format),
  );
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
    try {
      return readCompact(new Reader(data), rail);
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

  auditLayout(data: Pick<RingTransactData, "hasData" | "entry" | "extensions">): AuditLayout {
    return Object.freeze({
      hasData: data.hasData,
      entry: data.entry,
      format: disclosureFormat(data.extensions.format),
    });
  },

  streamLayout(data: RingTransactData): AuditStreamLayout {
    return streamOf(data.rail, headerOf(data), disclosureFormat(data.extensions.format));
  },

  /** The SPP selector of the data's shape and rail. */
  circuit(data: RingTransactData): RingCircuitId {
    return circuitId(data);
  },

  firstNullifier(data: Pick<RingTransactData, "nullifiers">): Bytes32 {
    const first = data.nullifiers[0];
    if (first === undefined) throw invalid("RingTransactLength");
    return first;
  },

  /** The reply of each slot in order, empty off a recipient body. */
  slotReplies(data: Pick<RingTransactData, "outputs" | "replies">): readonly Uint8Array[] {
    const { replies } = data;
    let next = 0;
    return data.outputs.map((output) => {
      if (replies === undefined || output.body.kind !== "recipient") return EMPTY;
      const start = next * replies.length;
      next += 1;
      return replies.region.subarray(start, start + replies.length);
    });
  },

  /** `0x04 ‖ tx_viewing_u ‖ envelope_ct ‖ record_ct... ‖ tail_ct...`. */
  auditorMessage(data: Pick<RingTransactData, "txViewingU" | "envelope" | "outputs">): Uint8Array {
    return concatBytes(
      taggedX25519(data.txViewingU),
      data.envelope,
      ...data.outputs.map((output) => output.record),
      ...data.outputs.flatMap((output) => (output.tail === undefined ? [] : [output.tail])),
    );
  },

  /** The in-proof owner's identity, `undefined` off that rail. */
  inProofSender(data: Pick<RingTransactData, "inProofOwner">): Bytes32 | undefined {
    return data.inProofOwner === undefined
      ? undefined
      : (solanaOwnerIdentity(data.inProofOwner.owner) as Bytes32);
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

  /** The tag and expansion's length, Rust `spp_instruction_data_under`, every proof field is fixed width. */
  sppDataLength(data: RingTransactData, config: RingTransactConfig): number {
    return 1 + encodeRingTransactInstructionData(transactIxData(data, config, ZERO_PROOF)).length;
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

/** Byte 0 of the compact data, one bit per optional section, Rust `transact_flag`. */
const Flag = Object.freeze({
  policy: 1 << 0,
  curator: 1 << 1,
  noSpend: 1 << 2,
  /** The confidential rail's owner signs inside SPP's anonymous rail proof. */
  ownerInProof: 1 << 3,
  /** The own revision and the SPL withdrawal owners follow. */
  ownRoot: 1 << 4,
  secondTree: 1 << 5,
  /** Anonymous frame only, one reply per body-bearing slot. */
  replyMetadata: 1 << 6,
  /** SPP's optional fields follow the salt. */
  extensions: 1 << 7,
});

/** Byte 1, the index into `SPP_SUPPORTED_SHAPES` below these flags, Rust `shape_flag`. */
const ShapeFlag = Object.freeze({ defaultOwnerTag: 1 << 6, publicOwners: 1 << 7 });
/** Byte 2, the published input count below these flags, Rust `input_flag`. */
const InputFlag = Object.freeze({ hasData: 1 << 6, entry: 1 << 7 });
/** Byte 3 past `m`, Rust `output_flag::WIDE_OWNERS`, the proof's key opens its full owner rows. */
const WIDE_OWNERS = 1 << 7;
/** The shape index or the input count, bits 6 and 7 carry the flags. */
const HEADER_LOW = 0b0011_1111;

/** The extension section's first byte, Rust `extension_flag`. */
const ExtensionFlag = Object.freeze({
  dataHash: 1 << 0,
  ringDataHash: 1 << 1,
  messages: 1 << 2,
  cache: 1 << 3,
  approvalTotals: 1 << 4,
  signerDataCounts: 1 << 5,
  singleAssetPayout: 1 << 6,
});
const KNOWN_EXTENSIONS = 0b111_1111;

/** The flags of the frame header, Rust `FrameFlags`. */
interface FrameFlags {
  /** Shape byte bit 6, the anonymous rail's default owner tag follows the commitment pok. */
  readonly defaultOwnerTag: boolean;
  /** Shape byte bit 7, the anonymous rail settling on SPP's confidential rail. */
  readonly publicOwners: boolean;
  /** Input byte bit 6. */
  readonly hasData: boolean;
  /** Input byte bit 7. */
  readonly entry: boolean;
  /** Output count byte bit 7. */
  readonly wideOwners: boolean;
}

interface FrameHeader {
  readonly nIn: number;
  readonly nOut: number;
  readonly inputCount: number;
  /** `m`. */
  readonly outputCount: number;
  readonly flags: FrameFlags;
}

/** A storage revision, little endian u64. */
export const REVISION_LENGTH = 8;
/** `a ‖ b ‖ c` with `b` compressed, Rust `PlainGroth16Proof::SIZE`. */
export const PLAIN_GROTH16_PROOF_LENGTH = 128;
const VIEWING_PUBKEY_TAG = 4;
const ZERO = new Uint8Array(32) as Bytes32;
const EMPTY = new Uint8Array();
const ZERO_PROOF = Object.freeze({
  a: new Uint8Array(32) as Bytes32,
  b: new Uint8Array(128) as Bytes128,
  c: new Uint8Array(32) as Bytes32,
});

/** Rust `RingRail::supports`, the authority rail admits SPP's ring-authority widths alone. */
export function railShapes(rail: RingRail): readonly Shape[] {
  return isDelegateRail(rail) ? RING_AUTHORITY_SHAPES : SPP_SUPPORTED_SHAPES;
}

/** Public owners settle on SPP's confidential rail, no hidden sender proves its signature. */
function sppRail(rail: RingRail, publicOwners: boolean): RingRail {
  return rail === "anonymous" && publicOwners ? "confidential" : rail;
}

/** The stream layout of the key the header names, before the outputs are read, Rust `RingRail::key_shape`. */
function streamOf(
  rail: RingRail,
  header: FrameHeader,
  format: DisclosureFormat = DisclosureFormat.Standard,
): AuditStreamLayout {
  const { nIn, nOut, inputCount: inputs, outputCount: outputs, flags } = header;
  const supported = railShapes(sppRail(rail, flags.publicOwners)).some(
    (shape) => shape.inputs === nIn && shape.outputs === nOut,
  );
  const shape = frameKeyShape({
    rail,
    format,
    inputs,
    outputs: nOut,
    spendsDefaultRing: flags.entry,
    wide: flags.wideOwners,
  });
  if (shape === undefined || !supported) throw invalid("RingShapeUnkeyed");
  if (inputs === 0 || inputs > nIn) throw invalid("RingTransactLength");
  if (outputs < 1 || outputs > nOut) throw invalid("OutputCountOutOfRange");
  return Object.freeze(
    checkedStreamLayout({
      key: Object.freeze({ class: shape.inputs, entry: flags.entry, format }),
      inputs,
      outputs,
      capacity: shape.outputs,
      hasData: flags.hasData,
    }),
  );
}

function readCompact(bytes: Reader, rail: RingRail): RingTransactData {
  const flags = bytes.u8("flags");
  checkFlags(flags, rail);
  const header = readHeader(bytes, rail);
  const { nIn, nOut, inputCount, outputCount } = header;
  const approval = checkedApproval(bytes.u8("approval"));
  const proof = bytes.bytes(CUSTOM_RING_PROOF_LENGTH, "proof");
  const trackingRevision = bytes.u64("trackingRevision");
  const ownRevision = has(flags, Flag.ownRoot) ? bytes.u64("ownRevision") : undefined;
  const policy: PolicyProof | undefined = has(flags, Flag.policy)
    ? Object.freeze(
        has(flags, Flag.curator) ? { curatorRevision: bytes.u64("curatorRevision") } : {},
      )
    : undefined;
  const expiryUnixTs = bytes.u32("expiryUnixTs");
  const txViewingU = field32(bytes, "txViewingU");
  const salt = bytes.bytes(16, "salt") as Bytes16;
  const extensions = has(flags, Flag.extensions) ? readExtensions(bytes, rail) : NO_EXTENSIONS;
  checkExtensions(extensions, rail);
  const stream = streamOf(rail, header, disclosureFormat(extensions.format));
  const interfaceTransfers = within("InvalidInstructionData", () =>
    Array.from({ length: bytes.u8("interfaceTransfers.length") }, () =>
      readInterfaceTransfer(bytes),
    ),
  );
  const splWithdrawalOwners = has(flags, Flag.ownRoot)
    ? interfaceTransfers
        .filter((transfer) => transfer.kind === "splWithdrawal")
        .map(() => field32(bytes, "splWithdrawalOwner"))
    : [];
  const exits = readBitmap(bytes, outputCount);
  const bodiless = readBitmap(bytes, outputCount);
  if ((exits & bodiless) !== 0n) throw invalid("BodilessExit");
  const slots = Array.from({ length: outputCount }, (_, slot) =>
    readSlot(
      bytes,
      stream.hasData,
      bitAt(exits, slot),
      bitAt(bodiless, slot),
      disclosureFormat(stream.key.format),
    ),
  );
  const replies = has(flags, Flag.replyMetadata) ? readReplies(bytes, slots) : undefined;
  const sender: PublishedSenderBundle | undefined = isAnonymousFrame(rail)
    ? Object.freeze({
        tag: field32(bytes, "sender.tag"),
        body: bytes.bytes(senderBundleLen(bundleLayout(slots)), "sender.body"),
      })
    : undefined;
  const envelope = bytes.bytes(envelopeRegion(stream).length, "envelope");
  const records = slots.map(() => bytes.bytes(auditRecordLength(stream.key), "record"));
  const tails = stream.hasData ? slots.map(() => bytes.bytes(DATA_TAIL_LEN, "tail")) : undefined;
  const outputs: readonly RingOutput[] = slots.map((slot, index) =>
    Object.freeze({
      ...slot,
      record: records[index] as Uint8Array,
      ...(tails === undefined ? {} : { tail: tails[index] as Uint8Array }),
    }),
  );
  const privateTxHash = field32(bytes, "privateTxHash");
  const anonymous =
    rail === "anonymous" && !header.flags.publicOwners
      ? readAnonymous(bytes, header.flags.defaultOwnerTag)
      : undefined;
  const inProofOwner: InProofOwner | undefined = has(flags, Flag.ownerInProof)
    ? Object.freeze({
        owner: field32(bytes, "inProofOwner.owner"),
        commitment: field32(bytes, "inProofOwner.commitment"),
        commitmentPok: field32(bytes, "inProofOwner.commitmentPok"),
      })
    : undefined;
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
  bytes.done();
  const data: RingTransactData = Object.freeze({
    rail,
    nIn,
    nOut,
    proof,
    trackingRevision,
    ...(ownRevision === undefined ? {} : { ownRevision }),
    ...(policy === undefined ? {} : { policy }),
    splWithdrawalOwners: Object.freeze(splWithdrawalOwners),
    approval,
    noSpend: has(flags, Flag.noSpend),
    publicOwners: header.flags.publicOwners,
    expiryUnixTs,
    txViewingU,
    salt,
    extensions,
    interfaceTransfers: Object.freeze(interfaceTransfers),
    hasData: header.flags.hasData,
    entry: header.flags.entry,
    wideOwners: header.flags.wideOwners,
    outputs: Object.freeze(outputs),
    ...(replies === undefined ? {} : { replies }),
    ...(sender === undefined ? {} : { sender }),
    envelope,
    privateTxHash,
    ...(anonymous === undefined ? {} : { anonymous }),
    ...(inProofOwner === undefined ? {} : { inProofOwner }),
    sppProof,
    nullifiers: Object.freeze(nullifiers),
    inputTrees,
  });
  checkFormat(data);
  return data;
}

type FramedSlot = Omit<RingOutput, "record" | "tail">;

/** Rust `RingTransactData::bundle_layout`, one change cell per bodiless slot. */
export function bundleLayout(slots: readonly { readonly body: SlotBody }[]): BundleLayout {
  return Object.freeze({
    outputs: slots.length,
    change: slots.filter((slot) => slot.body.kind === "none").length,
  });
}

/** A plain frame fixes each body's length, a data frame prefixes it. */
function readSlot(
  bytes: Reader,
  hasData: boolean,
  exit: boolean,
  bodiless: boolean,
  format: DisclosureFormat,
): FramedSlot {
  const length = bodiless
    ? 0
    : hasData
      ? bytes.u16("output.bodyLen")
      : exit
        ? CONFIDENTIAL_DATA_FREE_BODY_LEN
        : format === DisclosureFormat.SingleAssetPayout
          ? COMPACT_RECIPIENT_BODY_LEN
          : RECIPIENT_BODY_LEN;
  const hash = field32(bytes, "output.hash");
  // SPP binds an exit's tag to its owner, any other is a slot tag.
  const ownerTag = exit
    ? field32(bytes, "output.ownerTag")
    : unframedSlotTag(bytes.bytes(SLOT_TAG_LEN, "output.ownerTag"));
  const raw = bytes.bytes(length, "output.body");
  const body: SlotBody = bodiless
    ? Object.freeze({ kind: "none" })
    : exit
      ? Object.freeze({ kind: "exit", payload: raw })
      : Object.freeze({ kind: "recipient", body: raw });
  return { hash, ownerTag, body };
}

/** `reply_len`, then one reply per body-bearing slot. */
function readReplies(bytes: Reader, slots: readonly FramedSlot[]): Replies {
  const length = bytes.u16("replyLen");
  if (length < MIN_REPLY_LEN) throw invalid("ReplyLength");
  const bodies = slots.filter((slot) => slot.body.kind === "recipient").length;
  return Object.freeze({ length, region: bytes.bytes(length * bodies, "replies") });
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

function checkedApproval(approval: number): number {
  if (
    !Number.isInteger(approval) ||
    approval < 0 ||
    approval > (ApprovalMask.outflow | ApprovalMask.withdrawal)
  )
    throw invalid("FlagNotAllowed");
  return approval;
}

const NO_EXTENSIONS: FrameExtensions = Object.freeze({});

/** The cached selector's reads then its write slots, little endian. */
const CACHE_ACCESS_WRITES = MAX_CACHE_WRITES;

function readExtensions(bytes: Reader, rail: RingRail): FrameExtensions {
  const flags = bytes.u8("extensions");
  if ((flags & ~KNOWN_EXTENSIONS) !== 0) throw invalid("FlagNotAllowed");
  const dataHash = has(flags, ExtensionFlag.dataHash) ? field32(bytes, "dataHash") : undefined;
  const ringDataHash = has(flags, ExtensionFlag.ringDataHash)
    ? field32(bytes, "ringDataHash")
    : undefined;
  const count = has(flags, ExtensionFlag.messages) ? bytes.u8("messages.length") : 0;
  if (has(flags, ExtensionFlag.messages)) checkMessageCount(count, rail);
  const messages = has(flags, ExtensionFlag.messages)
    ? Array.from({ length: count }, (): AppMessage => {
        const viewTag = field32(bytes, "message.viewTag");
        const data = bytes.bytes(bytes.u16("message.length"), "message.data");
        return Object.freeze({ viewTag, data });
      })
    : undefined;
  const cache = has(flags, ExtensionFlag.cache) ? readCacheAccess(bytes) : undefined;
  const approvalTotals = has(flags, ExtensionFlag.approvalTotals)
    ? field32(bytes, "approvalTotals")
    : undefined;
  const signerDataCounts = has(flags, ExtensionFlag.signerDataCounts)
    ? bytes.u64("signerDataCounts")
    : undefined;
  // Zero travels as the clear bit, one encoding per statement value.
  if (signerDataCounts !== undefined && !validSignerDataCounts(signerDataCounts))
    throw invalid("InvalidSignerDataCounts");
  return Object.freeze({
    ...(has(flags, ExtensionFlag.singleAssetPayout)
      ? { format: DisclosureFormat.SingleAssetPayout }
      : {}),
    ...(dataHash === undefined ? {} : { dataHash }),
    ...(ringDataHash === undefined ? {} : { ringDataHash }),
    ...(messages === undefined ? {} : { messages: Object.freeze(messages) }),
    ...(cache === undefined ? {} : { cache }),
    ...(approvalTotals === undefined ? {} : { approvalTotals }),
    ...(signerDataCounts === undefined ? {} : { signerDataCounts }),
  });
}

function readCacheAccess(bytes: Reader): CacheAccess {
  const readBitmap = bytes.u64("cache.readBitmap");
  const writeSlots = Array.from({ length: CACHE_ACCESS_WRITES }, () => {
    const output = bytes.u8("cache.output");
    const slot = bytes.u8("cache.slot");
    return Object.freeze({ output, slot });
  });
  return Object.freeze({ readBitmap, writeSlots: Object.freeze(writeSlots) });
}

function extensionsEmpty(extensions: FrameExtensions): boolean {
  return (
    extensions.dataHash === undefined &&
    extensions.ringDataHash === undefined &&
    (extensions.messages === undefined || extensions.messages.length === 0) &&
    extensions.cache === undefined &&
    extensions.approvalTotals === undefined &&
    extensions.signerDataCounts === undefined &&
    disclosureFormat(extensions.format) === DisclosureFormat.Standard
  );
}

function writeExtensions(out: Writer, extensions: FrameExtensions, rail: RingRail): void {
  const messages = extensions.messages ?? [];
  checkMessageCount(messages.length, rail);
  const bits: readonly (readonly [boolean, number])[] = [
    [
      disclosureFormat(extensions.format) === DisclosureFormat.SingleAssetPayout,
      ExtensionFlag.singleAssetPayout,
    ],
    [extensions.dataHash !== undefined, ExtensionFlag.dataHash],
    [extensions.ringDataHash !== undefined, ExtensionFlag.ringDataHash],
    [messages.length > 0, ExtensionFlag.messages],
    [extensions.cache !== undefined, ExtensionFlag.cache],
    [extensions.approvalTotals !== undefined, ExtensionFlag.approvalTotals],
    [extensions.signerDataCounts !== undefined, ExtensionFlag.signerDataCounts],
  ];
  out.u8(
    bits.reduce((flags, [set, bit]) => (set ? flags | bit : flags), 0),
    "extensions",
  );
  if (extensions.dataHash !== undefined) out.bytes(extensions.dataHash, 32, "dataHash");
  if (extensions.ringDataHash !== undefined) out.bytes(extensions.ringDataHash, 32, "ringDataHash");
  if (messages.length > 0) {
    out.u8(messages.length, "messages.length");
    for (const message of messages) {
      if (message.data.length > 0xffff) throw invalid("OutputBodyLength");
      out
        .bytes(message.viewTag, 32, "message.viewTag")
        .u16(message.data.length, "message.length")
        .bytes(message.data);
    }
  }
  if (extensions.cache !== undefined) writeCacheAccess(out, extensions.cache);
  if (extensions.approvalTotals !== undefined)
    out.bytes(extensions.approvalTotals, 32, "approvalTotals");
  if (extensions.signerDataCounts !== undefined) {
    if (!validSignerDataCounts(extensions.signerDataCounts))
      throw invalid("InvalidSignerDataCounts");
    out.u64(extensions.signerDataCounts, "signerDataCounts");
  }
}

function writeCacheAccess(out: Writer, cache: CacheAccess): void {
  if (cache.writeSlots.length !== CACHE_ACCESS_WRITES) throw invalid("InvalidInstructionData");
  out.u64(cache.readBitmap, "cache.readBitmap");
  for (const write of cache.writeSlots)
    out.u8(write.output, "cache.output").u8(write.slot, "cache.slot");
}

/** The delegate's cached selector has no SPP rail. */
function checkExtensions(extensions: FrameExtensions, rail: RingRail): void {
  if (isDelegateRail(rail) && extensions.cache !== undefined) throw invalid("FlagNotAllowed");
}

/** `ceil(len / 8)` bytes, bit `i` at byte `i / 8` bit `i % 8`, no bit set past `len`. */
function readBitmap(bytes: Reader, length: number): bigint {
  const raw = bytes.bytes(Math.ceil(length / 8), "bitmap");
  const bits = raw.reduce((value, byte, index) => value | (BigInt(byte) << BigInt(8 * index)), 0n);
  if (bits >> BigInt(length) !== 0n) throw invalid("InvalidInstructionData");
  return bits;
}

function bitAt(bits: bigint, index: number): boolean {
  return ((bits >> BigInt(index)) & 1n) === 1n;
}

function writeCompact(data: RingTransactData): Uint8Array {
  const flags = compactFlags(data);
  checkFlags(flags, data.rail);
  const header = headerOf(data);
  checkExtensions(data.extensions, data.rail);
  const stream = streamOf(data.rail, header, disclosureFormat(data.extensions.format));
  checkFormat(data);
  const anonymousFrame = isAnonymousFrame(data.rail);
  const hiddenOwnerProof = data.rail === "anonymous" && !data.publicOwners;
  const ownersExpected = has(flags, Flag.ownRoot)
    ? data.interfaceTransfers.filter((transfer) => transfer.kind === "splWithdrawal").length
    : 0;
  if (
    data.splWithdrawalOwners.length !== ownersExpected ||
    (data.anonymous !== undefined) !== hiddenOwnerProof ||
    (data.sender !== undefined) !== anonymousFrame ||
    (data.sender !== undefined &&
      data.sender.body.length !== senderBundleLen(bundleLayout(data.outputs))) ||
    data.envelope.length !== envelopeRegion(stream).length ||
    !data.outputs.every((output) => slotFits(output, data.hasData, stream.key))
  )
    throw invalid("RingTransactLength");
  checkReplies(data);
  const [shapeByte, inputByte, outputByte] = headerBytes(header);
  const out = new Writer()
    .u8(flags, "flags")
    .u8(shapeByte, "shapeByte")
    .u8(inputByte, "inputByte")
    .u8(outputByte, "outputByte")
    .u8(checkedApproval(data.approval), "approval")
    .bytes(data.proof, CUSTOM_RING_PROOF_LENGTH, "proof")
    .u64(data.trackingRevision, "trackingRevision");
  if (data.ownRevision !== undefined) out.u64(data.ownRevision, "ownRevision");
  if (data.policy?.curatorRevision !== undefined)
    out.u64(data.policy.curatorRevision, "curatorRevision");
  out
    .u32(data.expiryUnixTs, "expiryUnixTs")
    .bytes(data.txViewingU, 32, "txViewingU")
    .bytes(data.salt, 16, "salt");
  if (has(flags, Flag.extensions)) writeExtensions(out, data.extensions, data.rail);
  out.u8(data.interfaceTransfers.length, "interfaceTransfers.length");
  for (const transfer of data.interfaceTransfers) writeInterfaceTransfer(out, transfer);
  for (const owner of data.splWithdrawalOwners) out.bytes(owner, 32, "splWithdrawalOwner");
  writeBitmap(
    out,
    data.outputs.map((output) => output.body.kind === "exit"),
  );
  writeBitmap(
    out,
    data.outputs.map((output) => output.body.kind === "none"),
  );
  for (const output of data.outputs) writeSlot(out, output, data.hasData);
  if (data.replies !== undefined)
    out.u16(data.replies.length, "replyLen").bytes(data.replies.region);
  if (data.sender !== undefined)
    out.bytes(data.sender.tag, 32, "sender.tag").bytes(data.sender.body);
  out.bytes(data.envelope);
  for (const output of data.outputs)
    out.bytes(output.record, auditRecordLength(stream.key), "record");
  for (const output of data.outputs)
    if (output.tail !== undefined) out.bytes(output.tail, DATA_TAIL_LEN, "tail");
  out.bytes(data.privateTxHash, 32, "privateTxHash");
  if (data.anonymous !== undefined) {
    out
      .bytes(data.anonymous.commitment, 32, "anonymous.commitment")
      .bytes(data.anonymous.commitmentPok, 32, "anonymous.commitmentPok");
    if (data.anonymous.defaultOwnerTag !== undefined)
      out.bytes(data.anonymous.defaultOwnerTag, 32, "anonymous.defaultOwnerTag");
  }
  if (data.inProofOwner !== undefined)
    out
      .bytes(data.inProofOwner.owner, 32, "inProofOwner.owner")
      .bytes(data.inProofOwner.commitment, 32, "inProofOwner.commitment")
      .bytes(data.inProofOwner.commitmentPok, 32, "inProofOwner.commitmentPok");
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
      data.nullifiers.map((_, input) => bitAt(secondInputs, input)),
    );
    writeTreeContext(out, data.inputTrees.first);
    writeTreeContext(out, data.inputTrees.second);
  }
  return out.finish();
}

function slotBytes(body: SlotBody): Uint8Array {
  switch (body.kind) {
    case "none":
      return EMPTY;
    case "recipient":
      return body.body;
    case "exit":
      return body.payload;
  }
}

function writeSlot(out: Writer, output: RingOutput, hasData: boolean): void {
  const raw = slotBytes(output.body);
  if (hasData && output.body.kind !== "none") {
    if (raw.length > 0xffff) throw invalid("OutputBodyLength");
    out.u16(raw.length, "output.bodyLen");
  }
  out.bytes(output.hash, 32, "output.hash");
  if (output.body.kind === "exit") out.bytes(output.ownerTag, 32, "output.ownerTag");
  else out.bytes(framedSlotTag(output.ownerTag), SLOT_TAG_LEN, "output.ownerTag");
  out.bytes(raw);
}

/** A frame with no data carries each body at its plain length. */
function slotFits(output: RingOutput, hasData: boolean, key: AuditStreamLayout["key"]): boolean {
  if (output.record.length !== auditRecordLength(key)) return false;
  if ((output.tail !== undefined) !== hasData) return false;
  if (output.body.kind !== "exit" && !equalBytes(slotTag(output.ownerTag), output.ownerTag))
    return false;
  if (hasData) return true;
  switch (output.body.kind) {
    case "none":
      return true;
    case "recipient":
      return (
        output.body.body.length ===
        (disclosureFormat(key.format) === DisclosureFormat.SingleAssetPayout
          ? COMPACT_RECIPIENT_BODY_LEN
          : RECIPIENT_BODY_LEN)
      );
    case "exit":
      return output.body.payload.length === CONFIDENTIAL_DATA_FREE_BODY_LEN;
  }
}

function checkFormat(data: RingTransactData): void {
  const format = disclosureFormat(data.extensions.format);
  if (
    format === DisclosureFormat.SingleAssetPayout &&
    (data.rail !== "confidential" ||
      data.nIn !== SINGLE_ASSET_PAYOUT_INPUTS ||
      data.nOut !== SINGLE_ASSET_PAYOUT_OUTPUTS ||
      data.outputs.length !== SINGLE_ASSET_PAYOUT_OUTPUTS ||
      data.nullifiers.length !== SINGLE_ASSET_PAYOUT_INPUTS ||
      data.hasData ||
      data.entry ||
      data.wideOwners ||
      data.inProofOwner !== undefined ||
      data.replies !== undefined ||
      data.interfaceTransfers.length !== 0 ||
      data.noSpend ||
      data.extensions.dataHash !== undefined ||
      data.extensions.ringDataHash !== undefined ||
      (data.extensions.messages?.length ?? 0) !== 0 ||
      data.extensions.signerDataCounts !== undefined ||
      data.outputs.some(
        (output) =>
          output.body.kind !== "recipient" ||
          output.body.body.length !== COMPACT_RECIPIENT_BODY_LEN,
      ))
  )
    throw invalid("FlagNotAllowed");
  if (data.hasData) {
    const lengths = data.outputs.flatMap((output) =>
      output.body.kind === "recipient" ? [output.body.body.length] : [],
    );
    if (lengths.some((length) => length < RECIPIENT_BODY_LEN + 2 || length !== lengths[0]))
      throw invalid("OutputBodyLength");
  }
}

function writeBitmap(out: Writer, bits: readonly boolean[]): void {
  const bytes = new Uint8Array(Math.ceil(bits.length / 8));
  bits.forEach((set, index) => {
    if (set) bytes[index >> 3] = (bytes[index >> 3] ?? 0) | (1 << (index & 7));
  });
  out.bytes(bytes);
}

/** Rust `Replies::checked`, `length` bytes per body-bearing slot. */
function checkReplies(data: RingTransactData): void {
  const { replies } = data;
  if (replies === undefined) return;
  const bodies = data.outputs.filter((output) => output.body.kind === "recipient").length;
  if (
    !isAnonymousFrame(data.rail) ||
    replies.length < MIN_REPLY_LEN ||
    replies.length > 0xffff ||
    replies.region.length !== replies.length * bodies
  )
    throw invalid("ReplyLength");
}

function compactFlags(data: RingTransactData): number {
  const bits: readonly (readonly [boolean, number])[] = [
    [data.policy !== undefined, Flag.policy],
    [data.policy?.curatorRevision !== undefined, Flag.curator],
    [data.noSpend, Flag.noSpend],
    [data.inProofOwner !== undefined, Flag.ownerInProof],
    [data.ownRevision !== undefined, Flag.ownRoot],
    [data.inputTrees.kind === "two", Flag.secondTree],
    [data.replies !== undefined, Flag.replyMetadata],
    [!extensionsEmpty(data.extensions), Flag.extensions],
  ];
  return bits.reduce((flags, [set, bit]) => (set ? flags | bit : flags), 0);
}

/** A delegate frame carries no policy section, and a policy section sits on the own root. */
function checkFlags(flags: number, rail: RingRail): void {
  const foreignOwner = has(flags, Flag.ownerInProof) && rail !== "confidential";
  const foreignReply = has(flags, Flag.replyMetadata) && !isAnonymousFrame(rail);
  const delegatePolicy =
    isDelegateRail(rail) && (has(flags, Flag.policy) || has(flags, Flag.ownRoot));
  if (foreignOwner || foreignReply || delegatePolicy) throw invalid("FlagNotAllowed");
  if (
    (has(flags, Flag.curator) && !has(flags, Flag.policy)) ||
    (has(flags, Flag.policy) && !has(flags, Flag.ownRoot))
  )
    throw invalid("FlagNotAllowed");
}

function has(flags: number, bit: number): boolean {
  return (flags & bit) !== 0;
}

function readHeader(bytes: Reader, rail: RingRail): FrameHeader {
  const shapeByte = bytes.u8("shapeByte");
  const inputByte = bytes.u8("inputByte");
  const outputByte = bytes.u8("outputByte");
  const shape = SPP_SUPPORTED_SHAPES[shapeByte & HEADER_LOW];
  if (shape === undefined) throw invalid("RingShapeUnkeyed");
  const flags: FrameFlags = {
    defaultOwnerTag: has(shapeByte, ShapeFlag.defaultOwnerTag),
    publicOwners: has(shapeByte, ShapeFlag.publicOwners),
    hasData: has(inputByte, InputFlag.hasData),
    entry: has(inputByte, InputFlag.entry),
    wideOwners: has(outputByte, WIDE_OWNERS),
  };
  checkFrameFlags(flags, rail);
  const outputCount = outputByte & ~WIDE_OWNERS;
  if (outputCount < 1 || outputCount > shape.outputs) throw invalid("OutputCountOutOfRange");
  return {
    nIn: shape.inputs,
    nOut: shape.outputs,
    inputCount: inputByte & HEADER_LOW,
    outputCount,
    flags,
  };
}

function headerOf(data: RingTransactData): FrameHeader {
  const flags: FrameFlags = {
    defaultOwnerTag: data.anonymous?.defaultOwnerTag !== undefined,
    publicOwners: data.publicOwners,
    hasData: data.hasData,
    entry: data.entry,
    wideOwners: data.wideOwners,
  };
  checkFrameFlags(flags, data.rail);
  if (data.outputs.length < 1 || data.outputs.length > data.nOut)
    throw invalid("OutputCountOutOfRange");
  return {
    nIn: data.nIn,
    nOut: data.nOut,
    inputCount: data.nullifiers.length,
    outputCount: data.outputs.length,
    flags,
  };
}

function headerBytes(header: FrameHeader): readonly [number, number, number] {
  const index = SPP_SUPPORTED_SHAPES.findIndex(
    (shape) => shape.inputs === header.nIn && shape.outputs === header.nOut,
  );
  if (index < 0) throw invalid("RingShapeUnkeyed");
  if (header.inputCount > HEADER_LOW) throw invalid("RingTransactLength");
  const { flags } = header;
  const bit = (set: boolean, value: number) => (set ? value : 0);
  return [
    index |
      bit(flags.defaultOwnerTag, ShapeFlag.defaultOwnerTag) |
      bit(flags.publicOwners, ShapeFlag.publicOwners),
    header.inputCount | bit(flags.hasData, InputFlag.hasData) | bit(flags.entry, InputFlag.entry),
    header.outputCount | bit(flags.wideOwners, WIDE_OWNERS),
  ];
}

/** The anonymous rail alone takes public owners and a default owner tag, a hidden owner alone the tag, and the delegate spends no default-ring note. */
function checkFrameFlags(flags: FrameFlags, rail: RingRail): void {
  const offAnonymous = rail !== "anonymous" && (flags.defaultOwnerTag || flags.publicOwners);
  if (
    offAnonymous ||
    (flags.publicOwners && flags.defaultOwnerTag) ||
    (flags.entry && isDelegateRail(rail))
  )
    throw invalid("FlagNotAllowed");
}

function circuitId(data: RingTransactData): RingCircuitId {
  const { anonymous, inProofOwner, extensions } = data;
  const shape = { inputs: data.nIn, outputs: data.nOut, publicAssetSlots: N_PUBLIC_SLOTS };
  const cache = extensions.cache;
  const proofData = (commitment: Bytes32, commitmentPok: Bytes32, defaultOwnerTag?: Bytes32) =>
    Object.freeze({
      bsb22Commitment: Object.freeze({ commitment, commitmentPok }),
      ...(defaultOwnerTag === undefined ? {} : { defaultOwnerTag }),
    });
  const anonymousCircuit = (data_: ReturnType<typeof proofData>): RingCircuitId =>
    Object.freeze(
      cache === undefined
        ? { kind: "anonymousRingEddsa" as const, ...shape, proofData: data_ }
        : {
            kind: "anonymousRingEddsaCached" as const,
            ...shape,
            proofData: data_,
            cacheAccess: cache,
          },
    );
  // Ring notes only, a default owner tag would publish the owner SPP hides.
  if (inProofOwner !== undefined)
    return anonymousCircuit(proofData(inProofOwner.commitment, inProofOwner.commitmentPok));
  switch (sppRail(data.rail, data.publicOwners)) {
    case "confidential":
      return Object.freeze(
        cache === undefined
          ? { kind: "confidentialRingEddsa" as const, ...shape }
          : { kind: "confidentialRingEddsaCached" as const, ...shape, cacheAccess: cache },
      );
    case "anonymous":
      if (anonymous === undefined) throw invalid("RingTransactLength");
      return anonymousCircuit(
        proofData(anonymous.commitment, anonymous.commitmentPok, anonymous.defaultOwnerTag),
      );
    case "delegate":
    case "anonymousDelegate":
      return Object.freeze({
        kind: data.outputs.some((output) => output.body.kind === "exit")
          ? ("ringAuthorityExit" as const)
          : ("ringAuthority" as const),
        ...shape,
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
  const replies = RingTransactData.slotReplies(data);
  const messages: MessageData[] = [
    ...(data.sender === undefined
      ? []
      : [
          Object.freeze({
            viewTag: checkedField(data.sender.tag, "sender.tag"),
            data: encodeRingOutput(RingScheme.ringSenderBundle, data.sender.body),
          }),
        ]),
    ...(data.extensions.messages ?? []),
    // The auditor message stays last.
    Object.freeze({
      viewTag: auditor.slice(1) as Bytes32,
      data: RingTransactData.auditorMessage(data),
    }),
  ];
  return Object.freeze({
    expiryUnixTs: BigInt(data.expiryUnixTs),
    txViewingPk: taggedX25519(data.txViewingU),
    salt: data.salt,
    interfaceTransfers: data.interfaceTransfers,
    ...(data.extensions.dataHash === undefined ? {} : { dataHash: data.extensions.dataHash }),
    ...(data.extensions.ringDataHash === undefined
      ? {}
      : { ringDataHash: data.extensions.ringDataHash }),
    outputs: data.outputs.map((output, slot) => ringTransactOutput(output, replies[slot])),
    messages,
    privateTxHash: data.privateTxHash,
    circuit: RingTransactData.circuit(data),
    proof,
    ...ringSppInputs(data),
  });
}

/** The SPP output, the scheme framing rebuilt from the slot, Rust `RingOutput::transact_output`. */
export function ringTransactOutput(
  output: Pick<RingOutput, "hash" | "ownerTag" | "body">,
  reply: Uint8Array = EMPTY,
): TransactOutput {
  const { body } = output;
  const data =
    body.kind === "none"
      ? undefined
      : body.kind === "recipient"
        ? encodeRingBodyOutput(body.body, reply)
        : encodeRingOutput(RingScheme.confidential, body.payload);
  return Object.freeze({
    utxoHash: output.hash,
    ownerTag: Object.freeze({ kind: "inline", value: checkedField(output.ownerTag, "ownerTag") }),
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
