/** The ring output rails, mirrors Rust `zolana-ring-transaction` over the ring program's expansion. */
import {
  concatBytes,
  encryptConfidential,
  equalBytes,
  isZero,
  ZERO_32,
} from "@heliuslabs/spr/internal";
import type { Address } from "@heliuslabs/spr/interface";
import type { Bytes16, Bytes32, MessageData, TransactOutput } from "@heliuslabs/spr/interface";
import { randomSalt, ViewingKey } from "@heliuslabs/spr/keypair";
import type { ShieldedAddress, X25519PublicKey } from "@heliuslabs/spr/keypair";
import {
  createExternalData,
  createProofOutput,
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  TransactionError,
  type AssetRegistry,
  type PreparedTransfer,
  type ProofOutputUtxo,
} from "@heliuslabs/spr/transaction";
import { SPP_SUPPORTED_SHAPES } from "@heliuslabs/spr/interface";

import {
  encodeRingOutput,
  readRingOutput,
  ringBodyOutput,
  RingScheme,
  senderBundleOutputBody,
} from "../../protocol/transaction/output.js";
import { OUTPUT_RECORD_LEN } from "../../protocol/codec/ring-disclosure-layout.js";
import {
  replyLength,
  sealReply,
  sealSenderBundle,
  type ReplyMetadata,
} from "../../protocol/codec/anonymous-delivery.js";
import {
  DUMMY_RECORD,
  EMPTY_PAYLOAD,
  RecordKind,
  encodeRecipientPayload,
  type OutputRecord,
  type RecipientPayload,
} from "../../protocol/codec/audit-stream.js";
import { sealOutputSlot } from "../../crypto/audit/ring-disclosure.js";
import {
  anonymousSlotTag,
  bundleTag,
  confidentialSlotTag,
  txKeySlotSecret,
} from "../../crypto/derivation/ring-stream.js";
import { randomTagPreimage } from "../../crypto/derivation/dummy-tag.js";
import { dummyRecipientKey } from "../../crypto/derivation/dummy-key.js";
import { withOutputFields } from "../../protocol/proof/proof-output.js";
import type { NoteData } from "./anonymous.js";
import {
  OutputBlindings,
  ringBlindedOutputs,
  ringBlindingSeed,
} from "../../crypto/derivation/blinding.js";
import { RingError } from "../../protocol/error.js";
import {
  ringTransactOutput,
  type PublishedSenderBundle,
  type RingOutput,
} from "../../protocol/transaction/transact.js";

/** The dummy preimages a plan draws ahead. */
const MAX_OUTPUTS = Math.max(...SPP_SUPPORTED_SHAPES.map((shape) => shape.outputs));

/** How the ring outputs of one transfer reach their recipients, Rust `RingDelivery`. */
export type RingDelivery =
  /** Each record under the owner's confidential tag. */
  | Readonly<{ kind: "delivered" }>
  /** Each record under a view tag derived from its slot secret, sender bundle in a message. */
  | Readonly<{ kind: "anonymous"; plan: AnonymousPlan }>;

/** One recipient record, its tag derived from the slot secret. */
export interface PlannedPayment {
  /** The viewing key the record seals to. */
  readonly recipient: X25519PublicKey;
  /** `null` sends no reply, the caller always names the choice. */
  readonly reply: ReplyMetadata | null;
}

/** One slot of an anonymous transfer, Rust `AnonymousSlot`. */
export type AnonymousSlot =
  /** At most two lead, the tag zero. */
  | Readonly<{ kind: "change" }>
  | Readonly<{ kind: "payment"; payment: PlannedPayment }>
  | Readonly<{ kind: "exit" }>
  | Readonly<{ kind: "dummy"; preimage: Bytes32 }>;

/** Payments in declared order. */
export class AnonymousPlan {
  readonly payments: readonly PlannedPayment[];
  /** Drawn ahead, every encoding of one dummy slot publishes one tag. */
  readonly #dummyPreimages: readonly Bytes32[];

  private constructor(payments: readonly PlannedPayment[], dummyPreimages: readonly Bytes32[]) {
    this.payments = Object.freeze([...payments]);
    this.#dummyPreimages = dummyPreimages;
    Object.freeze(this);
  }

  static create(): AnonymousPlan {
    return new AnonymousPlan(
      [],
      Object.freeze(Array.from({ length: MAX_OUTPUTS }, () => randomTagPreimage())),
    );
  }

  /** `dummyPreimages` exactly as a sealed plan drew them. */
  static fromDummyPreimages(
    payments: readonly PlannedPayment[],
    dummyPreimages: readonly Bytes32[],
  ): AnonymousPlan {
    if (dummyPreimages.length !== MAX_OUTPUTS)
      throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
    return new AnonymousPlan(payments, Object.freeze([...dummyPreimages]));
  }

  /** One per output slot. */
  dummyPreimages(): readonly Bytes32[] {
    return this.#dummyPreimages;
  }

  withPayment(payment: PlannedPayment): AnonymousPlan {
    return new AnonymousPlan(
      [...this.payments, Object.freeze({ ...payment })],
      this.#dummyPreimages,
    );
  }

  /** Change leads, every other ring output takes the next payment in declared order. */
  slots(outputs: readonly ProofOutputUtxo[], sender: ShieldedAddress): readonly AnonymousSlot[] {
    const change = leadingChange(outputs, sender);
    const payments = this.payments[Symbol.iterator]();
    const slots = outputs.map((output, slotIndex): AnonymousSlot => {
      const owner = output.ownerAddress;
      const preimage = this.#dummyPreimages[slotIndex];
      if (preimage === undefined) throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
      if (slotIndex < change) return Object.freeze({ kind: "change" });
      if (owner === undefined) return Object.freeze({ kind: "dummy", preimage });
      if (isChange(output, sender))
        throw new RingError("RING_ANONYMOUS_CHANGE", { details: { slotIndex } });
      if (output.ringProgramId === undefined) {
        if (owner.signingPublicKey.equals(sender.signingPublicKey))
          throw new RingError("RING_SENDER_EXIT", { details: { slotIndex } });
        return Object.freeze({ kind: "exit" });
      }
      const payment = payments.next();
      if (payment.done === true)
        throw new RingError("RING_UNPLANNED_OUTPUT", { details: { slotIndex } });
      if (!payment.value.recipient.equals(owner.viewingPublicKey))
        throw new RingError("RING_PAYMENT_SLOT", { details: { slotIndex } });
      return Object.freeze({ kind: "payment", payment: payment.value });
    });
    if (payments.next().done !== true)
      throw new RingError("RING_PAYMENT_SLOT", { details: { slotIndex: outputs.length } });
    return Object.freeze(slots);
  }
}

/** Zero on change, `undefined` on an exit whose scheme 3 owner tag stays on the frame, Rust `RingOutputRail::anonymous_tag`. */
export function anonymousTag(
  slot: AnonymousSlot,
  slotSecret: (recipient: X25519PublicKey) => Bytes32,
): Bytes32 | undefined {
  switch (slot.kind) {
    case "exit":
      return undefined;
    case "change":
      return ZERO_32;
    case "dummy":
      return anonymousSlotTag(slot.preimage);
    case "payment": {
      const secret = slotSecret(slot.payment.recipient);
      try {
        return anonymousSlotTag(secret);
      } finally {
        secret.fill(0);
      }
    }
  }
}

/** Moves the sender's change to the front, Rust `lead_change` before its reblinding. */
export function leadChange(
  outputs: readonly ProofOutputUtxo[],
  sender: ShieldedAddress,
): readonly ProofOutputUtxo[] {
  const rank = (output: ProofOutputUtxo): number => (isChange(output, sender) ? 0 : 1);
  return Object.freeze(
    outputs
      .map((output, index) => ({ output, index }))
      .sort((left, right) => rank(left.output) - rank(right.output) || left.index - right.index)
      .map(({ output }) => output),
  );
}

/** The first padding slot becomes a zero SOL change, a frame with no padding carries none. */
export function withSenderChange(
  outputs: readonly ProofOutputUtxo[],
  sender: ShieldedAddress,
): readonly ProofOutputUtxo[] {
  if (outputs.some((output) => isChange(output, sender))) return outputs;
  const slot = outputs.findIndex(
    (output) => output.isDummy() && !output.isCompact() && output.ringProgramId !== undefined,
  );
  const padding = outputs[slot];
  if (padding?.ringProgramId === undefined) return outputs;
  const change = createProofOutput({
    ownerAddress: sender,
    asset: SOL_MINT,
    amount: 0n,
    ringProgramId: padding.ringProgramId,
  });
  return Object.freeze(outputs.map((output, index) => (index === slot ? change : output)));
}

/** Ring change owned by the sender and carrying no data, it leads the anonymous frame. */
export function isChange(output: ProofOutputUtxo, sender: ShieldedAddress): boolean {
  return (
    output.ringProgramId !== undefined &&
    output.ownerAddress !== undefined &&
    !carriesData(output) &&
    equalBytes(output.ownerAddress.toBytes(), sender.toBytes())
  );
}

/** A nonzero data hash or ring data hash, the commitment covers both. */
export function carriesData(output: ProofOutputUtxo): boolean {
  return (
    (output.dataHash !== undefined && !isZero(output.dataHash)) ||
    (output.ringDataHash !== undefined && !isZero(output.ringDataHash))
  );
}

/** The bytes past `output`'s record, `data` leads with the hash the commitment reads, Rust `recipient_payload`. */
export function recipientPayload(output: ProofOutputUtxo): RecipientPayload {
  const { dataHash, ringDataHash } = output;
  return Object.freeze({
    ...(ringDataHash === undefined || isZero(ringDataHash) ? {} : { ringDataHash }),
    data:
      dataHash === undefined || isZero(dataHash)
        ? new Uint8Array()
        : concatBytes(dataHash, output.data.utxoData() ?? new Uint8Array()),
  });
}

/** The circuit derives the kind from the slot's domain and ring id, a dummy's plaintext is zero, Rust `OutputRecord::of`. */
export function outputRecord(output: ProofOutputUtxo): OutputRecord {
  const owner = output.ownerAddress;
  if (owner === undefined || output.isDummy()) return DUMMY_RECORD;
  return Object.freeze({
    kind: output.ringProgramId === undefined ? RecordKind.exit : RecordKind.ring,
    amount: output.amount,
    ownerKey: owner.signingPublicKey.confidentialViewTag() as Bytes32,
    mint: output.asset as Address,
    nullifierPk: owner.nullifierPublicKey,
    blinding: output.blinding,
  });
}

function withPaymentData(
  outputs: readonly ProofOutputUtxo[],
  senderOutputCount: number,
  paymentData: readonly (NoteData | undefined)[],
): readonly ProofOutputUtxo[] {
  const payments = paymentData[Symbol.iterator]();
  return outputs.map((output, slot) => {
    // An exit past the sender's outputs takes no payment.
    if (slot < senderOutputCount || output.isDummy() || output.ringProgramId === undefined)
      return output;
    const { value: data } = payments.next();
    if (data === undefined) return output;
    const { ringDataHash, application } = data;
    if (application !== undefined && isZero(application.hash))
      throw new RingError("RING_NOTE_DATA_UNBOUND", { details: { slotIndex: slot } });
    const hashed = ringDataHash === undefined ? output : withOutputFields(output, { ringDataHash });
    return application === undefined
      ? hashed
      : hashed.withUtxoData(application.bytes, application.hash);
  });
}

/** The frame's `HAS_DATA`, every non-exit slot then carries a payload of one length, Rust `payload_width`. */
export function framesData(outputs: readonly ProofOutputUtxo[]): boolean {
  return outputs.some(
    (output) => !output.isDummy() && (output.data.utxoData() !== undefined || carriesData(output)),
  );
}

export type SlotWire = RingOutput;

/** One published slot, its compact wire form and the key its record seals to, Rust `PublishedSlot`. */
export interface PublishedSlot {
  readonly output: ProofOutputUtxo;
  /** The final slot index of `output`. */
  readonly slotIndex: number;
  readonly wire: SlotWire;
  /** `V_i`, sealed to the auditor beside the envelope. */
  readonly recipientKey: X25519PublicKey;
  /** The slot's reply ciphertext when the frame carries replies. */
  readonly reply?: Uint8Array;
  /** Set on the anonymous rail. */
  readonly anonymous?: AnonymousSlot;
}

/** The frame-wide lengths every slot of one transfer shares. */
type FrameLengths = Readonly<{
  /** `undefined` off a data frame. */
  payloadLength: number | undefined;
  /** `undefined` when no payment names a reply. */
  replyLength: number | undefined;
}>;

/** One slot before framing, its key and tag fixed by the delivery and the slot index alone. */
type PlannedSlot = Readonly<{
  output: ProofOutputUtxo;
  recipientKey: X25519PublicKey;
  /** `undefined` on an exit, whose tag is its owner's. */
  tag: Bytes32 | undefined;
  anonymous?: AnonymousSlot;
}>;

/**
 * Rust `RingOutputRail`, keyed by a transaction viewing key the caller destroys, a rebuild draws a
 * new salt so a slot secret never repeats.
 * Every slot seals its record to `V_i` under `CRDS_i`, the auditor reads `V_i` from its stream and
 * derives the same secret from `tx_viewing_sk`. An exit's record travels in the auditor message.
 */
export class RingOutputRail {
  readonly #paymentData: readonly (NoteData | undefined)[];
  readonly txViewingKey: ViewingKey;
  readonly salt: Bytes16;
  readonly delivery: RingDelivery;
  readonly #firstNullifier: Bytes32;

  /** `firstNullifier` is the transfer's input slot 0, padding never moves it. */
  constructor(
    txViewingKey: ViewingKey,
    firstNullifier: Bytes32,
    delivery: RingDelivery,
    paymentData: readonly (NoteData | undefined)[] = [],
  ) {
    this.#paymentData = paymentData;
    this.txViewingKey = txViewingKey;
    this.salt = randomSalt();
    this.delivery = delivery;
    this.#firstNullifier = firstNullifier;
    Object.freeze(this);
  }

  /** The CRDS slot secret of the slot at `slotIndex` sealed to `recipient`. */
  slotSecret(recipient: X25519PublicKey, slotIndex: number): Bytes32 {
    return txKeySlotSecret({
      txViewingKey: this.txViewingKey,
      recipientViewingKey: recipient,
      salt: this.salt,
      outputIndex: slotIndex,
      firstNullifier: this.#firstNullifier,
    });
  }

  /** SPP's `blinding_seed`, rebuilt by any holder of the transaction key. */
  blindingSeed(): Bytes32 {
    const txViewingSecret = this.txViewingKey.secretBytes();
    try {
      return ringBlindingSeed(txViewingSecret, this.salt);
    } finally {
      txViewingSecret.fill(0);
    }
  }

  /** Seals every slot of `prepared` under its own inline tag, Rust `RingOutputRail::encrypt`. */
  encrypt(
    input: Readonly<{
      prepared: PreparedTransfer;
      sender: ShieldedAddress;
      assets: AssetRegistry;
      /** An exit's record seals to the auditor's key. */
      auditor: X25519PublicKey;
      instructionDiscriminator: number;
    }>,
  ): SppProofInputs {
    const { prepared, sender, auditor } = input;
    if (!equalBytes(prepared.firstNullifier, this.#firstNullifier)) throw framingError(0);
    const anonymous = this.delivery.kind === "anonymous";
    const proofOutputs = withPaymentData(
      prepared.proofOutputs(),
      prepared.senderOutputCount,
      this.#paymentData,
    );
    checkCompactSuffix(proofOutputs);
    const planned = anonymous
      ? leadChange(withSenderChange(proofOutputs, sender), sender).map((output) =>
          // The anonymous circuit folds the zero tag into every padding owner.
          output.isDummy()
            ? withOutputFields(output, { ownerTag: new Uint8Array(32) as Bytes32 })
            : output,
        )
      : proofOutputs;
    const outputs = ringBlindedOutputs({
      outputs: planned,
      firstNullifier: this.#firstNullifier,
      blindingSeed: this.blindingSeed(),
    });
    const live = publishedOutputs(outputs);
    const slots = this.#plannedSlots(live, sender, auditor);
    const lengths = frameLengths(this.delivery, live);
    const messages: MessageData[] =
      this.delivery.kind === "anonymous"
        ? [
            {
              viewTag: this.#bundleTag(sender.viewingPublicKey, live.length),
              data: encodeRingOutput(
                RingScheme.ringSenderBundle,
                this.#senderBundle(slots, sender.viewingPublicKey),
              ),
            },
          ]
        : [];
    const published: TransactOutput[] = slots.map((slot, slotIndex) => {
      const wire = this.#wire(slot, slotIndex, prepared.outputTreeId, input.assets, lengths);
      return ringTransactOutput(wire, this.#reply(slot, slotIndex, lengths));
    });
    return new SppProofInputs({
      payer: prepared.payer,
      inputUtxos: paddedInputs(prepared),
      outputs,
      externalData: createExternalData({
        instructionDiscriminator: input.instructionDiscriminator,
        interfaceTransfers: prepared.interfaceTransfers,
        txViewingPublicKey: this.txViewingKey.publicKey(),
        salt: this.salt,
        outputs: published,
        resolvedOwnerTags: published.map(({ ownerTag }) =>
          ownerTag.kind === "inline" ? ownerTag.value : ZERO_32,
        ),
        messages,
      }),
      blindingSeed: this.blindingSeed(),
      outputTreeId: prepared.outputTreeId,
    });
  }

  /**
   * Every published slot in order, each expanding to exactly the output the SPP proof binds, Rust
   * `RingOutputRail::published_slots`.
   */
  publishedSlots(
    proofInputs: SppProofInputs,
    sender: ShieldedAddress,
    auditor: X25519PublicKey,
  ): readonly PublishedSlot[] {
    const outputs = publishedOutputs(proofInputs.outputs);
    const published = proofInputs.externalData.outputs;
    if (published.length !== outputs.length)
      throw framingError(Math.min(outputs.length, published.length));
    const slots = this.#plannedSlots(outputs, sender, auditor);
    const lengths = framedLengths(published, slots);
    return Object.freeze(
      slots.map((slot, slotIndex) => {
        const expected = published[slotIndex];
        if (expected === undefined) throw framingError(slotIndex);
        // The exit body is scheme 3 under a random ephemeral, the published bytes are the wire's.
        const wire =
          slot.tag === undefined
            ? this.#exitWire(slot, slotIndex, expected)
            : this.#wire(slot, slotIndex, proofInputs.outputTreeId, undefined, lengths);
        const reply = replyOf(slot, expected, slotIndex);
        if (!sameOutput(ringTransactOutput(wire, reply), expected)) throw framingError(slotIndex);
        return Object.freeze({
          output: slot.output,
          slotIndex,
          wire: Object.freeze(wire),
          recipientKey: slot.recipientKey,
          ...(reply === undefined ? {} : { reply }),
          ...(slot.anonymous === undefined ? {} : { anonymous: slot.anonymous }),
        });
      }),
    );
  }

  /** The first message, its tag derived for index `m`. */
  publishedSender(
    proofInputs: SppProofInputs,
    senderViewingPublicKey: X25519PublicKey,
  ): PublishedSenderBundle | undefined {
    if (this.delivery.kind !== "anonymous") return undefined;
    const message = proofInputs.externalData.messages[0];
    const body = message === undefined ? undefined : senderBundleOutputBody(message.data);
    if (
      message === undefined ||
      body === undefined ||
      !equalBytes(
        message.viewTag,
        this.#bundleTag(senderViewingPublicKey, publishedOutputs(proofInputs.outputs).length),
      )
    )
      throw new RingError("RING_SENDER_BUNDLE_FRAMING");
    return Object.freeze({ tag: message.viewTag, body });
  }

  /** `V_i` and the tag of each slot, Rust `RingOutputRail::slot_keys`. */
  #plannedSlots(
    outputs: readonly ProofOutputUtxo[],
    sender: ShieldedAddress,
    auditor: X25519PublicKey,
  ): readonly PlannedSlot[] {
    // Every encoding of one dummy slot seals to one key, a relay holding the transaction key
    // rederives it.
    const dummyKey = (slotIndex: number): X25519PublicKey => {
      const txViewingSecret = this.txViewingKey.secretBytes();
      try {
        return dummyRecipientKey(txViewingSecret, slotIndex);
      } finally {
        txViewingSecret.fill(0);
      }
    };
    if (this.delivery.kind === "anonymous") {
      const anonymousSlots = this.delivery.plan.slots(outputs, sender);
      return anonymousSlots.map((slot, slotIndex) => {
        const output = outputs[slotIndex];
        if (output === undefined) throw framingError(slotIndex);
        const recipientKey =
          slot.kind === "payment"
            ? slot.payment.recipient
            : slot.kind === "change"
              ? sender.viewingPublicKey
              : slot.kind === "exit"
                ? auditor
                : dummyKey(slotIndex);
        const tag = anonymousTag(slot, (recipient) => this.slotSecret(recipient, slotIndex));
        return Object.freeze({ output, recipientKey, tag, anonymous: slot });
      });
    }
    return outputs.map((output, slotIndex) => {
      const owner = output.ownerAddress;
      if (owner === undefined || output.isDummy()) {
        const recipientKey = dummyKey(slotIndex);
        // The derived key publishes its confidential tag as a real recipient's would.
        return Object.freeze({
          output,
          recipientKey,
          tag: confidentialSlotTag(recipientKey.u()),
        });
      }
      if (output.ringProgramId === undefined)
        return Object.freeze({ output, recipientKey: auditor, tag: undefined });
      return Object.freeze({
        output,
        recipientKey: owner.viewingPublicKey,
        tag: confidentialSlotTag(owner.viewingPublicKey.u()),
      });
    });
  }

  /** `record_ct` under the slot secret, then the payload or the exit's scheme 3 body. */
  #wire(
    slot: PlannedSlot,
    slotIndex: number,
    treeId: PreparedTransfer["outputTreeId"],
    assets: AssetRegistry | undefined,
    lengths: FrameLengths,
  ): SlotWire {
    const { output } = slot;
    const hash = output.hash(treeId);
    const secret = this.slotSecret(slot.recipientKey, slotIndex);
    try {
      const record = outputRecord(output);
      if (slot.tag === undefined) {
        if (assets === undefined) throw framingError(slotIndex);
        return {
          hash,
          ownerTag: exitTag(output, slotIndex),
          record: sealOutputSlot(secret, { record }),
          body: { kind: "exit", payload: this.#exitBody(output, slotIndex, assets) },
        };
      }
      const sealed = sealOutputSlot(secret, {
        record,
        ...(lengths.payloadLength === undefined
          ? {}
          : {
              payload: record.kind === RecordKind.ring ? recipientPayload(output) : EMPTY_PAYLOAD,
              payloadLength: lengths.payloadLength,
            }),
      });
      return {
        hash,
        ownerTag: slot.tag,
        record: sealed.slice(0, OUTPUT_RECORD_LEN),
        body: { kind: "recipient", payload: sealed.slice(OUTPUT_RECORD_LEN) },
      };
    } finally {
      secret.fill(0);
    }
  }

  /** The exit's scheme 3 body as published, its record resealed to check the frame. */
  #exitWire(slot: PlannedSlot, slotIndex: number, published: TransactOutput): SlotWire {
    const { hash, ownerTag } = inline(published, slotIndex);
    if (!equalBytes(ownerTag, exitTag(slot.output, slotIndex))) throw framingError(slotIndex);
    const secret = this.slotSecret(slot.recipientKey, slotIndex);
    try {
      return {
        hash,
        ownerTag,
        record: sealOutputSlot(secret, { record: outputRecord(slot.output) }),
        body: {
          kind: "exit",
          payload: schemeBody(
            published.data ?? new Uint8Array(),
            RingScheme.confidential,
            slotIndex,
          ),
        },
      };
    } finally {
      secret.fill(0);
    }
  }

  /** Scheme 3 to the exit's owner at its slot, under the rail's salt. */
  #exitBody(output: ProofOutputUtxo, slotIndex: number, assets: AssetRegistry): Uint8Array {
    const owner = output.ownerAddress;
    if (owner === undefined) throw framingError(slotIndex);
    return encryptConfidential(
      this.txViewingKey,
      owner.viewingPublicKey,
      {
        assetId: assets.assetId(output.asset),
        amount: output.amount,
        blinding: output.blinding,
        data: output.data,
      },
      this.salt,
      slotIndex,
    );
  }

  /** Random bytes on a non-exit slot that names none, every reply shares one length. */
  #reply(slot: PlannedSlot, slotIndex: number, lengths: FrameLengths): Uint8Array | undefined {
    const { replyLength: length } = lengths;
    if (length === undefined || slot.tag === undefined) return undefined;
    const reply = slot.anonymous?.kind === "payment" ? slot.anonymous.payment.reply : null;
    if (reply === null) return randomBytes(length);
    const secret = this.slotSecret(slot.recipientKey, slotIndex);
    try {
      return sealReply(secret, reply, length);
    } finally {
      secret.fill(0);
    }
  }

  #bundleTag(senderViewingPublicKey: X25519PublicKey, outputCount: number): Bytes32 {
    const secret = this.slotSecret(senderViewingPublicKey, outputCount);
    try {
      return bundleTag(secret);
    } finally {
      secret.fill(0);
    }
  }

  /** Sealed to the sender at index `m`, key `k` names slot `k`'s `V_k`, zero on an exit or a dummy. */
  #senderBundle(slots: readonly PlannedSlot[], senderKey: X25519PublicKey): Uint8Array {
    const blindings = new OutputBlindings(this.#firstNullifier, this.blindingSeed());
    const outputSeed = blindings.outputSeed();
    blindings.destroy();
    const secret = this.slotSecret(senderKey, slots.length);
    try {
      return sealSenderBundle(secret, {
        outputSeed,
        recipientKeys: slots.map((slot) =>
          slot.anonymous?.kind === "payment" || slot.anonymous?.kind === "change"
            ? slot.recipientKey.u()
            : ZERO_32,
        ),
      });
    } finally {
      outputSeed.fill(0);
      secret.fill(0);
    }
  }
}
/** The reply bytes past a non-exit record, `undefined` on an exit or a frame without replies. */
function replyOf(
  slot: PlannedSlot,
  published: TransactOutput,
  slotIndex: number,
): Uint8Array | undefined {
  if (slot.tag === undefined) return undefined;
  const framedBody = ringBodyOutput(published.data ?? new Uint8Array());
  if (framedBody === undefined) throw framingError(slotIndex);
  return framedBody.reply.length === 0 ? undefined : framedBody.reply;
}

function schemeBody(data: Uint8Array, scheme: RingScheme, slotIndex: number): Uint8Array {
  const frame = readRingOutput(data);
  if (frame.encoding !== "encrypted" || frame.scheme !== scheme) throw framingError(slotIndex);
  return frame.body;
}

/** Omission removes a suffix, no index moves and every published slot keeps its blinding. */
function checkCompactSuffix(outputs: readonly ProofOutputUtxo[]): void {
  const first = outputs.findIndex((output) => output.isCompact());
  if (first >= 0 && outputs.slice(first).some((output) => !output.isCompact()))
    throw new RingError("RING_COMPACT_NOT_SUFFIX", { details: { slotIndex: first } });
}

/** `m` slots, a compact suffix leaves the frame. */
export function publishedOutputs(outputs: readonly ProofOutputUtxo[]): readonly ProofOutputUtxo[] {
  return outputs.filter((output) => !output.isCompact());
}

function leadingChange(outputs: readonly ProofOutputUtxo[], sender: ShieldedAddress): number {
  const first = outputs.findIndex((output) => !isChange(output, sender));
  return first < 0 ? outputs.length : first;
}

function inline(
  published: TransactOutput,
  slotIndex: number,
): Readonly<{ hash: Bytes32; ownerTag: Bytes32 }> {
  if (published.ownerTag.kind !== "inline") throw framingError(slotIndex);
  return { hash: published.utxoHash, ownerTag: published.ownerTag.value };
}

function sameOutput(expanded: TransactOutput, published: TransactOutput): boolean {
  return (
    equalBytes(expanded.utxoHash, published.utxoHash) &&
    expanded.ownerTag.kind === "inline" &&
    published.ownerTag.kind === "inline" &&
    equalBytes(expanded.ownerTag.value, published.ownerTag.value) &&
    equalBytes(expanded.data ?? new Uint8Array(), published.data ?? new Uint8Array())
  );
}

/** Random dummies join the last input tree and compact padding the first, as SPP reads them. */
function paddedInputs(prepared: PreparedTransfer): readonly ProofInputUtxo[] {
  const treeId = prepared.compactPadding ? prepared.inputTreeIds[0] : prepared.inputTreeIds.at(-1);
  if (treeId === undefined) throw new TransactionError("TRANSACTION_NO_INPUTS");
  const inputs = [...prepared.inputs];
  while (inputs.length < prepared.shape.inputs)
    inputs.push(
      prepared.compactPadding
        ? ProofInputUtxo.compact(treeId)
        : ProofInputUtxo.dummy(undefined, treeId),
    );
  return inputs;
}

/** The payload and reply lengths a sealer fixes, one per frame. */
function frameLengths(delivery: RingDelivery, outputs: readonly ProofOutputUtxo[]): FrameLengths {
  const replies =
    delivery.kind === "anonymous"
      ? delivery.plan.payments.flatMap((payment) => (payment.reply === null ? [] : [payment.reply]))
      : [];
  return Object.freeze({
    payloadLength: framesData(outputs)
      ? outputs.reduce(
          (width, output) =>
            output.ringProgramId === undefined || output.isDummy()
              ? width
              : Math.max(width, encodeRecipientPayload(recipientPayload(output)).length),
          encodeRecipientPayload(EMPTY_PAYLOAD).length,
        )
      : undefined,
    replyLength: replies.length === 0 ? undefined : replyLength(replies),
  });
}

/** The payload length the published frame carries, read back from its first non-exit body. */
function framedLengths(
  published: readonly TransactOutput[],
  slots: readonly PlannedSlot[],
): FrameLengths {
  const index = slots.findIndex((slot) => slot.tag !== undefined);
  const framedBody =
    index < 0 ? undefined : ringBodyOutput(published[index]?.data ?? new Uint8Array());
  if (index >= 0 && framedBody === undefined) throw framingError(index);
  const payload = (framedBody?.body.length ?? OUTPUT_RECORD_LEN) - OUTPUT_RECORD_LEN;
  return Object.freeze({
    payloadLength: payload === 0 ? undefined : payload,
    replyLength: undefined,
  });
}

/** SPP binds an exit's tag to its owner. */
function exitTag(output: ProofOutputUtxo, slotIndex: number): Bytes32 {
  const owner = output.ownerAddress;
  if (owner === undefined) throw framingError(slotIndex);
  return owner.signingPublicKey.confidentialViewTag() as Bytes32;
}

function framingError(slotIndex: number): RingError {
  return new RingError("RING_OUTPUT_FRAMING", { details: { slotIndex } });
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}
