/** The ring output rails, mirrors Rust `zolana-ring-transaction` over the ring program's expansion. */
import {
  concatBytes,
  encryptConfidential,
  equalBytes,
  isZero,
  ZERO_32,
} from "@heliuslabs/spr/internal";
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
import {
  RECIPIENT_BODY_LEN,
  encodeRecipientBody,
  sealCompactRecipientBody,
  type RecipientBody,
  replyLength,
  sealRecipientBody,
  sealReply,
  sealSenderBundle,
  type ReplyMetadata,
} from "../../protocol/codec/anonymous-delivery.js";
import {
  anonymousSlotTag,
  bundleTag,
  confidentialSlotTag,
  txKeySlotSecret,
} from "../../crypto/derivation/ring-stream.js";
import { randomTagPreimage } from "../../crypto/derivation/dummy-tag.js";
import { withOutputFields } from "../../protocol/proof/proof-output.js";
import {
  DisclosureFormat,
  SINGLE_ASSET_PAYOUT_INPUTS,
  SINGLE_ASSET_PAYOUT_OUTPUTS,
} from "../../protocol/codec/ring-disclosure-layout.js";
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
  type SlotBody,
} from "../../protocol/transaction/transact.js";

/** The dummy preimages a plan draws ahead. */
const MAX_OUTPUTS = Math.max(...SPP_SUPPORTED_SHAPES.map((shape) => shape.outputs));

/** How the ring outputs of one transfer reach their recipients, Rust `RingDelivery`. */
export type RingDelivery =
  /** Ring body under the owner's viewing key. */
  | Readonly<{ kind: "delivered" }>
  /** Ring body under view tags at each recipient output, sender bundle in a message. */
  | Readonly<{ kind: "anonymous"; plan: AnonymousPlan }>;

/** One recipient body, its tag derived from the slot secret. */
export interface PlannedPayment {
  /** The record-bound viewing key the body is sealed to. */
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

/** Ring change owned by the sender, a bundle cell holds no data, a data note travels in its own body. */
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

/** The sender's body for `output`, `data` leads with the hash the commitment reads, Rust `recipient_body`. */
export function recipientBody(output: ProofOutputUtxo): RecipientBody {
  const { dataHash, ringDataHash } = output;
  return Object.freeze({
    blinding: output.blinding,
    amount: output.amount,
    mint: output.asset,
    ...(ringDataHash === undefined || isZero(ringDataHash) ? {} : { ringDataHash }),
    ...(dataHash === undefined || isZero(dataHash)
      ? {}
      : { data: concatBytes(dataHash, output.data.utxoData() ?? new Uint8Array()) }),
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

/** The statement's `has_data`, one tail per published slot. */
export function framesData(outputs: readonly ProofOutputUtxo[]): boolean {
  return outputs.some(carriesData);
}

export type SlotWire = Pick<RingOutput, "hash" | "ownerTag" | "body">;

/** One published slot, its compact wire form and what its audit proof opens, Rust `PublishedSlot`. */
export interface PublishedSlot {
  readonly output: ProofOutputUtxo;
  /** The final slot index of `output`. */
  readonly slotIndex: number;
  /** The frame's slot before its record and tail seal. */
  readonly wire: SlotWire;
  /** The slot's reply ciphertext when the frame carries replies. */
  readonly reply?: Uint8Array;
  /** Set on the anonymous rail. */
  readonly anonymous?: AnonymousSlot;
}

type AnonymousSeal = Readonly<{
  slots: readonly AnonymousSlot[];
  outputs: readonly ProofOutputUtxo[];
  sender: ShieldedAddress;
  /** One length for every body of the frame, `undefined` when no payment names a reply. */
  replyLength: number | undefined;
  bodyLength: number | undefined;
}>;

/** How a delivered slot publishes. */
type Slot =
  | Readonly<{ kind: "ring"; owner: ShieldedAddress }>
  | Readonly<{ kind: "exit" }>
  | Readonly<{ kind: "dummy" }>;

/** The payload SPP binds for one final slot, as the program expands the slot's compact wire. */
type FramedSlot = Readonly<{ viewTag: Bytes32; data?: Uint8Array }>;

/** Rust `RingOutputRail`, keyed by a transaction viewing key the caller destroys, a rebuild draws a new salt so a slot secret never repeats. */
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

  /** The CRDS slot secret of the delivered ring output at `slotIndex`, the key of its body. */
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
      instructionDiscriminator: number;
    }>,
  ): SppProofInputs {
    const { prepared, sender } = input;
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
    let frames: readonly FramedSlot[];
    let messages: MessageData[] = [];
    if (this.delivery.kind === "anonymous") {
      const { plan } = this.delivery;
      const replies = plan.payments.flatMap((payment) =>
        payment.reply === null ? [] : [payment.reply],
      );
      const seal: AnonymousSeal = {
        slots: plan.slots(live, sender),
        outputs: live,
        sender,
        replyLength: replies.length === 0 ? undefined : replyLength(replies),
        bodyLength: paddedBodyLength(live),
      };
      messages = [
        {
          viewTag: this.#bundleTag(sender.viewingPublicKey, live.length),
          data: encodeRingOutput(RingScheme.ringSenderBundle, this.#senderBundle(seal)),
        },
      ];
      frames = this.#anonymousFrames(seal, input.assets);
    } else {
      const compact = isSingleAssetPayout(prepared, live);
      const bodyLength = paddedBodyLength(live);
      frames = live.map((output, slotIndex) =>
        this.#deliveredFrame(output, slotIndex, input.assets, compact, bodyLength),
      );
    }
    const published: TransactOutput[] = live.map((output, slotIndex) => {
      const frame = frames[slotIndex];
      if (frame === undefined) throw framingError(slotIndex);
      return {
        utxoHash: output.hash(prepared.outputTreeId),
        ownerTag: { kind: "inline", value: frame.viewTag },
        ...(frame.data === undefined ? {} : { data: frame.data }),
      };
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
  publishedSlots(proofInputs: SppProofInputs, sender: ShieldedAddress): readonly PublishedSlot[] {
    const outputs = publishedOutputs(proofInputs.outputs);
    const published = proofInputs.externalData.outputs;
    if (published.length !== outputs.length)
      throw framingError(Math.min(outputs.length, published.length));
    const anonymous =
      this.delivery.kind === "anonymous" ? this.delivery.plan.slots(outputs, sender) : undefined;
    return Object.freeze(
      outputs.map((output, slotIndex) => {
        const expected = published[slotIndex];
        if (expected === undefined) throw framingError(slotIndex);
        const slot = anonymous?.[slotIndex];
        const wire =
          slot === undefined
            ? this.#deliveredWire(output, expected, slotIndex)
            : anonymousWire(slot, this.#slotTag(slot, slotIndex), expected, slotIndex);
        const reply = slot === undefined ? undefined : replyOf(wire, expected, slotIndex);
        if (!sameOutput(ringTransactOutput(wire, reply), expected)) throw framingError(slotIndex);
        return Object.freeze({
          output,
          slotIndex,
          wire: Object.freeze(wire),
          ...(reply === undefined ? {} : { reply }),
          ...(slot === undefined ? {} : { anonymous: slot }),
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

  #slotTag(slot: AnonymousSlot, slotIndex: number): Bytes32 | undefined {
    return anonymousTag(slot, (recipient) => this.slotSecret(recipient, slotIndex));
  }

  #bundleTag(senderViewingPublicKey: X25519PublicKey, outputCount: number): Bytes32 {
    const secret = this.slotSecret(senderViewingPublicKey, outputCount);
    try {
      return bundleTag(secret);
    } finally {
      secret.fill(0);
    }
  }

  /** Every tagged body sealed at its output position, an exit framed as scheme 3. */
  #anonymousFrames(seal: AnonymousSeal, assets: AssetRegistry): readonly FramedSlot[] {
    return seal.slots.map((slot, slotIndex) => {
      const output = seal.outputs[slotIndex];
      if (output === undefined) throw framingError(slotIndex);
      const tag = this.#slotTag(slot, slotIndex);
      if (tag === undefined) return this.#exitFrame(output, slotIndex, assets);
      if (slot.kind === "change") return Object.freeze({ viewTag: tag });
      const { data } = ringTransactOutput(
        {
          hash: ZERO_32,
          ownerTag: tag,
          body: { kind: "recipient", body: this.#anonymousBody(seal, slotIndex) },
        },
        this.#reply(seal, slotIndex),
      );
      return Object.freeze({ viewTag: tag, ...(data === undefined ? {} : { data }) });
    });
  }

  /** A hidden dummy's random bytes match a live body's length. */
  #anonymousBody(seal: AnonymousSeal, slotIndex: number): Uint8Array {
    const slot = seal.slots[slotIndex];
    const output = seal.outputs[slotIndex];
    if (slot === undefined || output === undefined) throw framingError(slotIndex);
    switch (slot.kind) {
      case "dummy":
        return randomBytes(seal.bodyLength ?? RECIPIENT_BODY_LEN);
      case "change":
      case "exit":
        throw framingError(slotIndex);
      case "payment": {
        const secret = this.slotSecret(slot.payment.recipient, slotIndex);
        try {
          return sealRecipientBody(secret, recipientBody(output), seal.bodyLength);
        } finally {
          secret.fill(0);
        }
      }
    }
  }

  /** Random bytes on a slot that names none, every body shares one length. */
  #reply(seal: AnonymousSeal, slotIndex: number): Uint8Array | undefined {
    const { replyLength: length } = seal;
    if (length === undefined) return undefined;
    const slot = seal.slots[slotIndex];
    const reply = slot?.kind === "payment" ? slot.payment.reply : null;
    if (slot?.kind !== "payment" || reply === null) return randomBytes(length);
    const secret = this.slotSecret(slot.payment.recipient, slotIndex);
    try {
      return sealReply(secret, reply, length);
    } finally {
      secret.fill(0);
    }
  }

  /** Sealed to the sender at index `m`, opens under a retained or reproducible viewing key and published values alone. */
  #senderBundle(seal: AnonymousSeal): Uint8Array {
    const { outputs, sender } = seal;
    // A change slot publishes no body, so the frame's bodiless count is the bundle's cell count.
    const change = seal.slots.flatMap((slot, slotIndex) => {
      const output = outputs[slotIndex];
      return slot.kind === "change" && output !== undefined
        ? [Object.freeze({ mint: output.asset, amount: output.amount })]
        : [];
    });
    const blindings = new OutputBlindings(this.#firstNullifier, this.blindingSeed());
    const outputSeed = blindings.outputSeed();
    blindings.destroy();
    const secret = this.slotSecret(sender.viewingPublicKey, outputs.length);
    try {
      return sealSenderBundle(secret, {
        outputSeed,
        change,
        recipientKeys: seal.slots.flatMap((slot) =>
          slot.kind === "change"
            ? []
            : [slot.kind === "payment" ? slot.payment.recipient.u() : ZERO_32],
        ),
      });
    } finally {
      outputSeed.fill(0);
      secret.fill(0);
    }
  }

  /** Rust `RingOutputRail::encode_delivered` under the owner tag `owner_tags` resolves. */
  #deliveredFrame(
    output: ProofOutputUtxo,
    slotIndex: number,
    assets: AssetRegistry,
    compact: boolean,
    bodyLength: number | undefined,
  ): FramedSlot {
    const slot = deliveredSlot(output);
    switch (slot.kind) {
      case "exit":
        return this.#exitFrame(output, slotIndex, assets);
      case "ring": {
        const secret = this.slotSecret(slot.owner.viewingPublicKey, slotIndex);
        try {
          const body = compact
            ? sealCompactRecipientBody(secret, {
                blinding: output.blinding,
                amount: output.amount,
                assetId: assets.assetId(output.asset),
              })
            : sealRecipientBody(secret, recipientBody(output), bodyLength);
          return framed(confidentialSlotTag(slot.owner.viewingPublicKey.u()), {
            kind: "recipient",
            body,
          });
        } finally {
          secret.fill(0);
        }
      }
      case "dummy": {
        // A random key publishes as a real recipient's would.
        const key = ViewingKey.generate();
        try {
          return framed(confidentialSlotTag(key.publicKey().u()), {
            kind: "recipient",
            body: randomBytes(bodyLength ?? RECIPIENT_BODY_LEN),
          });
        } finally {
          key.destroy();
        }
      }
    }
  }

  /** Scheme 3 to the exit's owner at its slot, under the rail's salt. */
  #exitFrame(output: ProofOutputUtxo, slotIndex: number, assets: AssetRegistry): FramedSlot {
    const owner = output.ownerAddress;
    if (owner === undefined) throw framingError(slotIndex);
    const viewTag = owner.signingPublicKey.confidentialViewTag();
    const payload = encryptConfidential(
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
    return framed(viewTag, { kind: "exit", payload });
  }

  /** The round trip through the program's expansion refuses any other framing. */
  #deliveredWire(output: ProofOutputUtxo, published: TransactOutput, slotIndex: number): SlotWire {
    const { hash, ownerTag } = inline(published, slotIndex);
    const data = published.data ?? new Uint8Array();
    if (deliveredSlot(output).kind === "exit")
      return {
        hash,
        ownerTag,
        body: { kind: "exit", payload: schemeBody(data, RingScheme.confidential, slotIndex) },
      };
    const framedBody = ringBodyOutput(data);
    if (framedBody === undefined) throw framingError(slotIndex);
    return { hash, ownerTag, body: { kind: "recipient", body: framedBody.body } };
  }
}

/** The body kind and tag each anonymous slot publishes, any other is refused. */
function anonymousWire(
  slot: AnonymousSlot,
  tag: Bytes32 | undefined,
  published: TransactOutput,
  slotIndex: number,
): SlotWire {
  const { hash, ownerTag } = inline(published, slotIndex);
  const data = published.data;
  if (tag === undefined) {
    if (data === undefined) throw framingError(slotIndex);
    return {
      hash,
      ownerTag,
      body: { kind: "exit", payload: schemeBody(data, RingScheme.confidential, slotIndex) },
    };
  }
  if (!equalBytes(tag, ownerTag)) throw framingError(slotIndex);
  if (slot.kind === "change") {
    if (data !== undefined) throw framingError(slotIndex);
    return { hash, ownerTag, body: { kind: "none" } };
  }
  const framedBody = data === undefined ? undefined : ringBodyOutput(data);
  if (framedBody === undefined) throw framingError(slotIndex);
  return { hash, ownerTag, body: { kind: "recipient", body: framedBody.body } };
}

/** The bytes past a ring body, `undefined` on any other slot. */
function replyOf(
  wire: SlotWire,
  published: TransactOutput,
  slotIndex: number,
): Uint8Array | undefined {
  if (wire.body.kind !== "recipient") return undefined;
  const framedBody = ringBodyOutput(published.data ?? new Uint8Array());
  if (framedBody === undefined) throw framingError(slotIndex);
  return framedBody.reply.length === 0 ? undefined : framedBody.reply;
}

function schemeBody(data: Uint8Array, scheme: RingScheme, slotIndex: number): Uint8Array {
  const frame = readRingOutput(data);
  if (frame.encoding !== "encrypted" || frame.scheme !== scheme) throw framingError(slotIndex);
  return frame.body;
}

function deliveredSlot(output: ProofOutputUtxo): Slot {
  const owner = output.ownerAddress;
  if (owner === undefined) return Object.freeze({ kind: "dummy" });
  if (output.ringProgramId === undefined) return Object.freeze({ kind: "exit" });
  return Object.freeze({ kind: "ring", owner });
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

function framed(viewTag: Bytes32, body: SlotBody): FramedSlot {
  const { data } = ringTransactOutput({ hash: ZERO_32, ownerTag: viewTag, body });
  if (data === undefined) throw new RingError("RING_OUTPUT_FRAMING");
  return Object.freeze({ viewTag, data });
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

export function outputDisclosureFormat(inputs: SppProofInputs): DisclosureFormat {
  const formats = inputs.externalData.outputs.flatMap((output) => {
    const body = output.data === undefined ? undefined : ringBodyOutput(output.data);
    return body === undefined ? [] : [body.format];
  });
  if (!formats.includes(DisclosureFormat.SingleAssetPayout)) return DisclosureFormat.Standard;
  if (
    formats.length !== SINGLE_ASSET_PAYOUT_OUTPUTS ||
    formats.some((format) => format !== DisclosureFormat.SingleAssetPayout)
  )
    throw framingError(0);
  return DisclosureFormat.SingleAssetPayout;
}

function paddedBodyLength(outputs: readonly ProofOutputUtxo[]): number | undefined {
  if (!framesData(outputs)) return undefined;
  return outputs.reduce(
    (width, output) =>
      output.ringProgramId === undefined || output.isDummy()
        ? width
        : Math.max(width, encodeRecipientBody(recipientBody(output)).length),
    RECIPIENT_BODY_LEN + 2,
  );
}

function isSingleAssetPayout(
  prepared: PreparedTransfer,
  outputs: readonly ProofOutputUtxo[],
): boolean {
  const first = prepared.inputs[0];
  return (
    prepared.shape.inputs === SINGLE_ASSET_PAYOUT_INPUTS &&
    prepared.inputs.length === SINGLE_ASSET_PAYOUT_INPUTS &&
    first !== undefined &&
    !first.isDummy() &&
    !first.isAddress() &&
    prepared.ownerMode === "signed" &&
    first.utxo.ringProgramId !== undefined &&
    prepared.interfaceTransfers.length === 0 &&
    outputs.length === SINGLE_ASSET_PAYOUT_OUTPUTS &&
    outputs.every(
      (output) =>
        !output.isDummy() &&
        !output.isCompact() &&
        output.ringProgramId === first.utxo.ringProgramId &&
        output.asset === first.utxo.asset &&
        !carriesData(output),
    )
  );
}

function framingError(slotIndex: number): RingError {
  return new RingError("RING_OUTPUT_FRAMING", { details: { slotIndex } });
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}
