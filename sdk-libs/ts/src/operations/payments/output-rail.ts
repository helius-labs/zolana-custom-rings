/** The ring output rails, mirrors Rust `zolana-ring-transaction` over the ring program's expansion. */
import { encryptConfidential, equalBytes, ZERO_32 } from "@heliuslabs/zolana/internal";
import type {
  Address,
  Bytes16,
  Bytes32,
  MessageData,
  TransactOutput,
} from "@heliuslabs/zolana/interface";
import { randomSalt, ViewingKey } from "@heliuslabs/zolana/keypair";
import type { ShieldedAddress, ViewTag, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  createExternalData,
  createProofOutput,
  Data,
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  TransactionError,
  type AssetRegistry,
  type PreparedTransfer,
  type ProofOutputUtxo,
} from "@heliuslabs/zolana/transaction";
import { SPP_SUPPORTED_SHAPES } from "@heliuslabs/zolana/interface";

import {
  anonymousRecipientOutputBody,
  anonymousSenderOutputBody,
  encodeRingOutput,
  readRingOutput,
  RING_DELIVERED_BODY_LEN,
  RingScheme,
  sealDeliveredBody,
} from "../../protocol/transaction/output.js";
import {
  DUMMY_RECIPIENT_VIEWING_PK,
  RECIPIENT_BODY_LEN,
} from "../../protocol/codec/anonymous-body.js";
import {
  encodeAnonymousRecipient,
  encodeAnonymousSender,
} from "../../protocol/codec/anonymous-plaintext.js";
import { deliveredSlotSecret } from "../../crypto/derivation/ring-stream.js";
import { withOutputFields } from "../../protocol/proof/proof-output.js";
import {
  OutputBlindings,
  ringBlindedOutputs,
  ringBlindingSeed,
} from "../../crypto/derivation/blinding.js";
import { RingError } from "../../protocol/error.js";
import {
  ringTransactOutput,
  type RingOutput,
  type SenderBundle,
} from "../../protocol/transaction/transact.js";

/** The widest SPP shape's outputs, the dummy tags a plan draws ahead. */
const MAX_OUTPUTS = Math.max(...SPP_SUPPORTED_SHAPES.map((shape) => shape.outputs));

/** How the ring outputs of one transfer reach their recipients, Rust `RingDelivery`. */
export type RingDelivery =
  /** Scheme 10 delivered to the owner's viewing key, at `DELIVERED_AUDIT_CAPACITIES`. */
  | Readonly<{ kind: "delivered" }>
  /** Scheme 1 under view tags at each recipient output, scheme 2 in a message. */
  | Readonly<{ kind: "anonymous"; plan: AnonymousPlan }>;

/** One recipient body, its tag picked by the spec view tag selection, Rust `TaggedPayment`. */
export interface TaggedPayment {
  /** The recipient's viewing key the body is sealed to. */
  readonly recipient: X25519PublicKey;
  readonly tag: ViewTag;
}

/** One slot of an anonymous transfer, Rust `AnonymousSlot`. */
export type AnonymousSlot =
  /** A sender change output, output 0 always one. */
  | Readonly<{ kind: "change"; tag: ViewTag }>
  | Readonly<{ kind: "payment"; payment: TaggedPayment }>
  | Readonly<{ kind: "exit" }>
  | Readonly<{ kind: "dummy"; tag: ViewTag }>;

/** The tags of one anonymous transfer, its payments in declared order, Rust `AnonymousPlan`. */
export class AnonymousPlan {
  readonly senderTag: ViewTag;
  readonly payments: readonly TaggedPayment[];
  /** Drawn ahead, every encoding of a dummy slot publishes one tag. */
  readonly #dummyTags: readonly ViewTag[];

  private constructor(
    senderTag: ViewTag,
    payments: readonly TaggedPayment[],
    dummyTags: readonly ViewTag[],
  ) {
    this.senderTag = senderTag;
    this.payments = Object.freeze([...payments]);
    this.#dummyTags = dummyTags;
    Object.freeze(this);
  }

  static create(senderTag: ViewTag): AnonymousPlan {
    return new AnonymousPlan(
      senderTag,
      [],
      Object.freeze(Array.from({ length: MAX_OUTPUTS }, dummyTag)),
    );
  }

  withPayment(payment: TaggedPayment): AnonymousPlan {
    return new AnonymousPlan(
      this.senderTag,
      [...this.payments, Object.freeze({ ...payment })],
      this.#dummyTags,
    );
  }

  /** Change leads, every other ring output takes the next payment in declared order. */
  slots(outputs: readonly ProofOutputUtxo[], sender: ShieldedAddress): readonly AnonymousSlot[] {
    const change = leadingChange(outputs, sender);
    if (change === 0) throw new RingError("RING_MISSING_SENDER_CHANGE");
    const payments = this.payments[Symbol.iterator]();
    const slots = outputs.map((output, slotIndex): AnonymousSlot => {
      const owner = output.ownerAddress;
      const dummy = this.#dummyTags[slotIndex];
      if (dummy === undefined) throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
      // Later change opens from the sender bundle, only output 0 takes the sender tag.
      if (slotIndex < change)
        return Object.freeze({ kind: "change", tag: slotIndex === 0 ? this.senderTag : dummy });
      if (owner === undefined) return Object.freeze({ kind: "dummy", tag: dummy });
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

export function anonymousSlotTag(slot: AnonymousSlot): ViewTag | undefined {
  switch (slot.kind) {
    case "change":
    case "dummy":
      return slot.tag;
    case "payment":
      return slot.payment.tag;
    case "exit":
      return undefined;
  }
}

/** Moves the sender's change to the front, SPL before SOL, Rust `lead_change` before its reblinding. */
export function leadChange(
  outputs: readonly ProofOutputUtxo[],
  sender: ShieldedAddress,
): readonly ProofOutputUtxo[] {
  const rank = (output: ProofOutputUtxo): number =>
    !isChange(output, sender) ? 2 : output.asset === SOL_MINT ? 1 : 0;
  return Object.freeze(
    outputs
      .map((output, index) => ({ output, index }))
      .sort((left, right) => rank(left.output) - rank(right.output) || left.index - right.index)
      .map(({ output }) => output),
  );
}

/** A transfer returning nothing takes its first padding slot as a zero SOL change, Rust `SenderChange::ensure`. */
export function withSenderChange(
  outputs: readonly ProofOutputUtxo[],
  sender: ShieldedAddress,
): readonly ProofOutputUtxo[] {
  if (outputs.some((output) => isChange(output, sender))) return outputs;
  const slot = outputs.findIndex(
    (output) => output.isDummy() && output.ringProgramId !== undefined,
  );
  const padding = outputs[slot];
  if (padding?.ringProgramId === undefined) throw new RingError("RING_MISSING_SENDER_CHANGE");
  const change = createProofOutput({
    ownerAddress: sender,
    asset: SOL_MINT,
    amount: 0n,
    ringProgramId: padding.ringProgramId,
  });
  return Object.freeze(outputs.map((output, index) => (index === slot ? change : output)));
}

/** Ring change owned by the sender, every anonymous transfer leads with one. */
export function isChange(output: ProofOutputUtxo, sender: ShieldedAddress): boolean {
  return (
    output.ringProgramId !== undefined &&
    output.ownerAddress !== undefined &&
    equalBytes(output.ownerAddress.toBytes(), sender.toBytes())
  );
}

/** One published slot, its compact wire form and what its audit proof opens, Rust `PublishedSlot`. */
export interface PublishedSlot {
  readonly output: ProofOutputUtxo;
  /** The final slot index of `output`. */
  readonly slotIndex: number;
  readonly wire: RingOutput;
  /** Set on the anonymous rail. */
  readonly anonymous?: AnonymousSlot;
}

type AnonymousSeal = Readonly<{
  slots: readonly AnonymousSlot[];
  outputs: readonly ProofOutputUtxo[];
  sender: ShieldedAddress;
}>;

/** How a delivered slot publishes. */
type Slot =
  | Readonly<{ kind: "ring"; recipient: X25519PublicKey }>
  | Readonly<{ kind: "exit" }>
  | Readonly<{ kind: "dummy" }>;

/** The payload SPP binds for one final slot, as the program expands the slot's compact wire. */
type FramedSlot = Readonly<{ viewTag: Bytes32; data?: Uint8Array }>;

/** Rust `RingOutputRail`, keyed by a transaction viewing key the caller destroys and a salt drawn per rail. */
export class RingOutputRail {
  readonly txViewingKey: ViewingKey;
  readonly salt: Bytes16;
  readonly delivery: RingDelivery;
  readonly #firstNullifier: Bytes32;

  /** `firstNullifier` is the transfer's input slot 0, padding never moves it. */
  constructor(txViewingKey: ViewingKey, firstNullifier: Bytes32, delivery: RingDelivery) {
    this.txViewingKey = txViewingKey;
    this.salt = randomSalt();
    this.delivery = delivery;
    this.#firstNullifier = firstNullifier;
    Object.freeze(this);
  }

  /** The CRDS slot secret of the delivered ring output at `slotIndex`, the key of its body. */
  slotSecret(recipient: X25519PublicKey, slotIndex: number): Bytes32 {
    const agreement = this.txViewingKey.ecdh(recipient);
    try {
      return deliveredSlotSecret({
        agreement,
        txViewingKey: this.txViewingKey.publicKey(),
        recipientViewingKey: recipient,
        salt: this.salt,
        outputIndex: slotIndex,
        firstNullifier: this.#firstNullifier,
      });
    } finally {
      agreement.fill(0);
    }
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
    const proofOutputs = prepared.proofOutputs();
    proofOutputs.forEach(checkPlain);
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
    let frames: readonly FramedSlot[];
    let messages: MessageData[] = [];
    if (this.delivery.kind === "anonymous") {
      const { plan } = this.delivery;
      const seal: AnonymousSeal = { slots: plan.slots(outputs, sender), outputs, sender };
      messages = [
        {
          viewTag: plan.senderTag,
          data: encodeRingOutput(RingScheme.anonymousSender, this.#senderBundle(seal)),
        },
      ];
      frames = this.#anonymousFrames(seal, input.assets);
    } else
      frames = outputs.map((output, slotIndex) =>
        this.#deliveredFrame(output, slotIndex, input.assets),
      );
    const published: TransactOutput[] = outputs.map((output, slotIndex) => {
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
    const { outputs } = proofInputs;
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
            : anonymousWire(slot, expected, slotIndex);
        if (!sameOutput(ringTransactOutput(wire), expected)) throw framingError(slotIndex);
        return Object.freeze({
          output,
          slotIndex,
          wire: Object.freeze(wire),
          ...(slot === undefined ? {} : { anonymous: slot }),
        });
      }),
    );
  }

  /** The anonymous rail's sender bundle, the first message, Rust `RingOutputRail::published_sender`. */
  publishedSender(proofInputs: SppProofInputs): SenderBundle | undefined {
    if (this.delivery.kind !== "anonymous") return undefined;
    const message = proofInputs.externalData.messages[0];
    const body = message === undefined ? undefined : anonymousSenderOutputBody(message.data);
    if (
      message === undefined ||
      body === undefined ||
      !equalBytes(message.viewTag, this.delivery.plan.senderTag)
    )
      throw new RingError("RING_SENDER_BUNDLE_FRAMING");
    return Object.freeze({ tag: message.viewTag, body });
  }

  /** Every tagged body sealed at its output position, an exit framed as scheme 3. */
  #anonymousFrames(seal: AnonymousSeal, assets: AssetRegistry): readonly FramedSlot[] {
    return seal.slots.map((slot, slotIndex) => {
      const output = seal.outputs[slotIndex];
      if (output === undefined) throw framingError(slotIndex);
      const tag = anonymousSlotTag(slot);
      if (tag === undefined) return this.#exitFrame(output, slotIndex, assets);
      const body = this.#anonymousBody(seal, slotIndex);
      const { data } = ringTransactOutput({
        kind: "anonymous",
        hash: ZERO_32,
        tag,
        ...(body === undefined ? {} : { body }),
      });
      return Object.freeze({ viewTag: tag, ...(data === undefined ? {} : { data }) });
    });
  }

  /** The body of a tagged slot sealed at its output position, `undefined` on a change output, Rust `AnonymousSeal::body`. */
  #anonymousBody(seal: AnonymousSeal, slotIndex: number): Uint8Array | undefined {
    const slot = seal.slots[slotIndex];
    const output = seal.outputs[slotIndex];
    if (slot === undefined || output === undefined) throw framingError(slotIndex);
    switch (slot.kind) {
      case "change":
        return undefined;
      case "dummy":
        return randomBytes(RECIPIENT_BODY_LEN);
      case "exit":
        throw framingError(slotIndex);
      case "payment": {
        const owner = output.ownerAddress;
        if (owner === undefined) throw framingError(slotIndex);
        const plaintext = encodeAnonymousRecipient({
          verified: {
            ownerPublicKey: owner.signingPublicKey,
            mint: output.asset,
            amount: output.amount,
          },
          unverified: {
            senderPublicKey: seal.sender.viewingPublicKey,
            blinding: output.blinding,
            data: new Data(),
          },
        });
        return this.#seal(slot.payment.recipient, plaintext, slotIndex);
      }
    }
  }

  /** The change and the recipient list, sealed to the sender after every output, Rust `AnonymousSeal::sender_bundle`. */
  #senderBundle(seal: AnonymousSeal): Uint8Array {
    const change = seal.outputs.slice(0, leadingChange(seal.outputs, seal.sender));
    // A zero amount reads back as absent and would shift the later change's position.
    if (change.length > 1 && change.some((output) => output.amount === 0n))
      throw new RingError("RING_ANONYMOUS_CHANGE_COUNT");
    let splMint: Address = SOL_MINT;
    let splAmount = 0n;
    let solAmount = 0n;
    for (const output of change.filter((held) => held.amount !== 0n)) {
      const sol = output.asset === SOL_MINT;
      if ((sol ? solAmount : splAmount) !== 0n) throw new RingError("RING_ANONYMOUS_CHANGE_COUNT");
      if (sol) solAmount = output.amount;
      else {
        splMint = output.asset;
        splAmount = output.amount;
      }
    }
    const blindings = new OutputBlindings(this.#firstNullifier, this.blindingSeed());
    const blindingSeed = blindings.outputSeed();
    blindings.destroy();
    try {
      const plaintext = encodeAnonymousSender({
        verified: {
          ownerPublicKey: seal.sender.signingPublicKey,
          splMint,
          splAmount,
          solAmount,
          recipientViewingPublicKeys: seal.slots.flatMap(listedRecipient),
        },
        unverified: { blindingSeed, splData: new Data(), solData: new Data() },
      });
      return this.#seal(seal.sender.viewingPublicKey, plaintext, seal.outputs.length);
    } finally {
      blindingSeed.fill(0);
    }
  }

  #seal(recipient: X25519PublicKey, plaintext: Uint8Array, slotIndex: number): Uint8Array {
    try {
      return this.txViewingKey.encryptSlot(recipient, plaintext, this.salt, slotIndex);
    } finally {
      plaintext.fill(0);
    }
  }

  /** Rust `RingOutputRail::encode_delivered` under the owner tag `owner_tags` resolves. */
  #deliveredFrame(output: ProofOutputUtxo, slotIndex: number, assets: AssetRegistry): FramedSlot {
    const slot = deliveredSlot(output);
    switch (slot.kind) {
      case "exit":
        return this.#exitFrame(output, slotIndex, assets);
      case "ring": {
        const secret = this.slotSecret(slot.recipient, slotIndex);
        let body: Uint8Array;
        try {
          body = sealDeliveredBody(secret, { blinding: output.blinding, amount: output.amount });
        } finally {
          secret.fill(0);
        }
        const u = slot.recipient.u();
        return framed(u, { kind: "delivered", hash: ZERO_32, u, body });
      }
      case "dummy": {
        const body = randomBytes(RING_DELIVERED_BODY_LEN);
        // A random key publishes as a real recipient's would.
        const key = ViewingKey.generate();
        try {
          const u = key.publicKey().u();
          return framed(u, { kind: "delivered", hash: ZERO_32, u, body });
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
    return framed(viewTag, { kind: "exit", hash: ZERO_32, ownerTag: viewTag, payload });
  }

  /** The round trip through the program's expansion refuses any other framing. */
  #deliveredWire(
    output: ProofOutputUtxo,
    published: TransactOutput,
    slotIndex: number,
  ): RingOutput {
    const { hash, ownerTag } = inline(published, slotIndex);
    const body = (scheme: RingScheme): Uint8Array =>
      schemeBody(published.data ?? new Uint8Array(), scheme, slotIndex);
    return deliveredSlot(output).kind === "exit"
      ? { kind: "exit", hash, ownerTag, payload: body(RingScheme.confidential) }
      : { kind: "delivered", hash, u: ownerTag, body: body(RingScheme.ringConfidentialDelivered) };
  }
}

/** The body kind and tag each anonymous slot publishes, any other is refused. */
function anonymousWire(
  slot: AnonymousSlot,
  published: TransactOutput,
  slotIndex: number,
): RingOutput {
  const { hash, ownerTag } = inline(published, slotIndex);
  const data = published.data;
  const tag = anonymousSlotTag(slot);
  if (tag === undefined) {
    if (data === undefined) throw framingError(slotIndex);
    return {
      kind: "exit",
      hash,
      ownerTag,
      payload: schemeBody(data, RingScheme.confidential, slotIndex),
    };
  }
  if (!equalBytes(tag, ownerTag)) throw framingError(slotIndex);
  if (slot.kind === "change") {
    if (data !== undefined) throw framingError(slotIndex);
    return { kind: "anonymous", hash, tag: ownerTag };
  }
  const body = data === undefined ? undefined : anonymousRecipientOutputBody(data);
  if (body === undefined) throw framingError(slotIndex);
  return { kind: "anonymous", hash, tag: ownerTag, body };
}

function schemeBody(data: Uint8Array, scheme: RingScheme, slotIndex: number): Uint8Array {
  const frame = readRingOutput(data);
  if (frame.encoding !== "encrypted" || frame.scheme !== scheme) throw framingError(slotIndex);
  return frame.body;
}

/** The sender bundle's entry, a dummy key where no anonymous recipient reads the output. */
function listedRecipient(slot: AnonymousSlot): readonly X25519PublicKey[] {
  switch (slot.kind) {
    case "change":
      return [];
    case "payment":
      return [slot.payment.recipient];
    // An exit's owner reads no shared tag, listing it would mispair the next payment.
    case "exit":
    case "dummy":
      return [DUMMY_RECIPIENT_VIEWING_PK];
  }
}

function deliveredSlot(output: ProofOutputUtxo): Slot {
  const owner = output.ownerAddress;
  if (owner === undefined) return Object.freeze({ kind: "dummy" });
  if (output.ringProgramId === undefined) return Object.freeze({ kind: "exit" });
  return Object.freeze({ kind: "ring", recipient: owner.viewingPublicKey });
}

/** A ring rail slot carries no data and is never compact padding, Rust `check_plain`. */
function checkPlain(output: ProofOutputUtxo, slotIndex: number): void {
  if (output.isCompact())
    throw new RingError("RING_DELIVERED_COMPACT_PADDING", { details: { slotIndex } });
  const carriesData =
    !output.data.isEmpty() || output.dataHash !== undefined || output.ringDataHash !== undefined;
  if (!output.isDummy() && carriesData)
    throw new RingError("RING_DELIVERED_OUTPUT_DATA", { details: { slotIndex } });
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

/** `0x00 ‖ 31 random bytes`, distributed as every derived view tag. */
function dummyTag(): ViewTag {
  const tag = randomBytes(32);
  tag[0] = 0;
  return tag as ViewTag;
}

function framed(viewTag: Bytes32, wire: RingOutput): FramedSlot {
  const { data } = ringTransactOutput(wire);
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

function framingError(slotIndex: number): RingError {
  return new RingError("RING_OUTPUT_FRAMING", { details: { slotIndex } });
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}
