import { openingTotals } from "../../../src/protocol/membership/approval-totals.js";
import {
  authorizeHiddenOwner,
  bytesToBigInt,
  encodeBase58,
  prepareTransfer,
} from "@heliuslabs/spr/internal";
import type { NoteData } from "../../../src/operations/payments/anonymous.js";
import { EMPTY_MINT_POLICY } from "../../../src/protocol/membership/mint-policy.js";
import { policyWithdrawalHash } from "../../../src/proof/withdrawals.js";
import { AccountState, getTokenEncoder } from "@solana-program/token";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  AccountRole,
  address,
  generateKeyPairSigner,
  getBase58Encoder,
  getBase64Encoder,
  none,
  signTransactionWithSigners,
  some,
  type Address,
} from "@solana/kit";
import { describe, expect, it } from "vitest";
import { ringIntentMismatch } from "../../../src/operations/workflow/selection.js";

import type { WalletKeys, RpcAccount } from "@heliuslabs/spr/client";
import {
  SYSTEM_PROGRAM,
  addressBytes,
  associatedTokenAddress,
  splInterfaceWithBump,
} from "@heliuslabs/spr/internal";
import { initializePoseidon } from "@heliuslabs/spr";
import {
  SOL_INTERFACE,
  SPL_TOKEN_2022_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  TransactWithdrawal,
  type Bytes32,
} from "@heliuslabs/spr/interface";
import {
  randomBlinding,
  ShieldedAddress,
  ShieldedKeypair,
  SigningKey,
  solanaOwnerIdentity,
  X25519PublicKey,
} from "@heliuslabs/spr/keypair";
import {
  AssetRegistry,
  SOL_MINT,
  ConfidentialTransfer,
  WithdrawalTarget,
  type SettlementTransfer,
  decodeConfidential,
  ProofInputUtxo,
  Utxo,
  Wallet,
  SppProofInputs,
  Data,
  type PreparedTransfer,
  type ProofOutputUtxo,
} from "@heliuslabs/spr/transaction";
import {
  checkRingPreparedTransfer,
  approveRingUnattended,
  type RingApprovalRequest,
} from "../../../src/protocol/transaction/intent.js";
import { ringProofCircuit } from "../../../src/rpc/prover/ring.js";
import { ringCoSignerAddress, ringPolicyAddress } from "../../../src/protocol/pda/index.js";
import { ringCircuitType } from "../../../src/protocol/proof/proving-keys.js";
import { RingAddress, RingPaymentRequest } from "../../../src/crypto/keys/ring-address.js";
import {
  anonymousExitTokenOwner,
  signingKeySpendSigner,
  type AnonymousSpendSigner,
} from "../../../src/operations/payments/anonymous.js";
import {
  RING_COSIGN_APPROVE_OUTFLOW,
  RING_COSIGN_TRANSFERS,
  decodeRingPolicy,
} from "../../../src/protocol/codec/ring-codecs.js";
import {
  ListId,
  buildRuleTable,
  memberOfAsset,
  memberOfIdentity,
} from "../../../src/protocol/membership/policy.js";
import type { ProvenRingTransfer } from "../../../src/operations/workflow/pipeline.js";
import {
  CustomRingTransfer,
  type AnonymousTransfer,
} from "../../../src/operations/payments/transfer-rails.js";
import {
  buildRingEntryTransaction,
  buildRingExitTransaction,
  buildRingTransferTransaction,
  buildRingWithdrawalTransaction,
  createRingEntrySubmission,
  prepareRingEntryRelay,
  prepareRingTransferRelay,
  prepareRingWithdrawalRelay,
} from "../../../src/operations/payments/transfer.js";
import { createRingTransferSubmission } from "../../../src/index.js";
import type { PreparedRingRelay } from "../../../src/operations/payments/transfer-rails.js";
import { decodeRelayProofInputs } from "../../../src/protocol/ring-rpc/relay-proof-inputs.js";
import type { PrepareRelayRequest } from "../../../src/protocol/ring-rpc/ring-rpc-types.js";
import { relayId, submittedRelay, type RingRelayClient } from "../../../src/rpc/relay.js";
import {
  ANONYMOUS_PARTIES,
  ApprovalMask,
  bundleLayout,
  RingTransactData,
} from "../../../src/protocol/transaction/transact.js";
import {
  bundleTag,
  deliveredSlotSecret,
  recipientTag,
  slotTag,
} from "../../../src/crypto/derivation/ring-stream.js";

import { BLOCKHASH } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";

import {
  TREE,
  TREE_ID,
  bindingSigners,
  screenedMembers,
  checkAccounts,
  checkTransferProof,
  checkDisclosure,
  checkFrameCounted,
  checkRingBlindings,
  expanded,
  itemAt,
  noteInput,
  randomAddress,
  ringError,
  ringFixture,
  small,
  walletKeys,
  type Fixture,
  type RingFixtureOptions,
} from "../../helpers/ring-pipeline.js";
import { type RingKeys } from "../../../src/state/ring-keys.js";
import {
  MIN_REPLY_LEN,
  RECIPIENT_BODY_LEN,
  openRecipientBody,
  openReply,
  openSenderBundle,
  senderBundleLen,
  type ReplyMetadata,
} from "../../../src/protocol/codec/anonymous-delivery.js";

await initializePoseidon();

const assets = new AssetRegistry();

interface Sender {
  readonly signing: SigningKey;
  readonly keypair: ShieldedKeypair;
}

function anonymousSender(): Sender {
  const signing = SigningKey.generate();
  return { signing, keypair: ShieldedKeypair.fromKeypair(signing) };
}

function anonymousRing(options: RingFixtureOptions = {}): Promise<Fixture> {
  return ringFixture({ mode: "anonymous", ...options });
}

/** One note of the sender, of the ring unless `ring` is `"default"`. */
function spend(
  fixture: Fixture,
  sender: Sender,
  options: Readonly<{
    ring?: Address | "default";
    payer?: Address;
    asset?: Address;
  }> = {},
): ConfidentialTransfer {
  const ring = options.ring === "default" ? undefined : (options.ring ?? fixture.ringProgramId);
  return new ConfidentialTransfer(
    sender.keypair.shieldedAddress(),
    [noteInput(sender.keypair, 10_000n, ring, options.asset)],
    options.payer ?? fixture.authority,
  );
}

/** The hidden owner's rail over `transfer`. */
function rail(
  input: Readonly<{
    fixture: Fixture;
    sender: Sender;
    transfer: ConfidentialTransfer;
    keys?: WalletKeys;
    signer?: AnonymousSpendSigner;
    withdrawal?: TransactWithdrawal;
    /** False leaves the sender without a record address. */
    enrolled?: boolean;
  }>,
): AnonymousTransfer {
  const { fixture, sender } = input;
  if (input.enrolled !== false) fixture.enroll(sender.keypair.shieldedAddress());
  const owner = CustomRingTransfer.new({
    ringProgramId: fixture.ringProgramId,
    keys: input.keys ?? walletKeys(sender.keypair),
    transfer: input.transfer,
    assets,
    ...(fixture.coSigner === undefined ? {} : { coSigners: [fixture.coSigner] }),
  });
  return (
    input.withdrawal === undefined ? owner : owner.withWithdrawalAccounts(input.withdrawal)
  ).withAnonymousSigner(input.signer ?? signingKeySpendSigner(sender.signing));
}

async function addressOf(fixture: Fixture, owner: ShieldedKeypair): Promise<RingAddress> {
  fixture.enroll(owner.shieldedAddress());
  return new RingAddress({
    recipient: owner.shieldedAddress(),
    ringProgramId: fixture.ringProgramId,
    listSalt: new Uint8Array(32).fill(1) as Bytes32,
  });
}

/** The anonymous transfer request, its circuit the key the program verifies under. */
function anonymousTransfer(fixture: Fixture) {
  const request = fixture.ringRequests.find((request) => request.kind === "transfer");
  if (request?.kind !== "transfer" || !request.hidden)
    throw new Error("no anonymous transfer request");
  return { request, circuit: ringCircuitType(ringProofCircuit(request)) };
}

async function anonymousCoreInputs(fixture: Fixture) {
  const call = itemAt(fixture.sppCalls, 0);
  if (call.owner === undefined) throw new Error("missing owner authorization");
  const prepared = prepareTransfer(call.proofInputs, {
    kind: "anonymousRingEddsa",
    ring: fixture.ringProgramId,
    authorization: await authorizeHiddenOwner(call.proofInputs, call.owner),
  });
  if (prepared.inputs.circuit !== "transferAnonymousRingEddsa")
    throw new Error("unexpected anonymous circuit");
  return prepared.inputs.payload;
}

function noProofs(fixture: Fixture): void {
  expect(fixture.ringRequests).toHaveLength(0);
  expect(fixture.sppCalls).toHaveLength(0);
}

/** The CRDS slot secret `reader` rebuilds with its own key and the frame's transaction key. */
function slotSecretOf(
  reader: ShieldedKeypair,
  data: RingTransactData,
  call: Fixture["sppCalls"][number],
  slotIndex: number,
): Bytes32 {
  const viewing = reader.viewingKey();
  const txViewingKey = X25519PublicKey.fromBytes(call.data.txViewingPk);
  const agreement = viewing.ecdh(txViewingKey);
  try {
    return deliveredSlotSecret({
      agreement,
      txViewingKey,
      recipientViewingKey: reader.viewingPublicKey(),
      salt: data.salt,
      outputIndex: slotIndex,
      firstNullifier: RingTransactData.firstNullifier(data),
    });
  } finally {
    agreement.fill(0);
    viewing.destroy();
  }
}

function openedBody(
  reader: ShieldedKeypair,
  data: RingTransactData,
  call: Fixture["sppCalls"][number],
  slotIndex: number,
) {
  const output = data.outputs[slotIndex];
  if (output?.body.kind !== "recipient") throw new Error("no recipient body");
  return openRecipientBody(slotSecretOf(reader, data, call, slotIndex), output.body.body);
}

function openedBundle(
  sender: ShieldedKeypair,
  data: RingTransactData,
  call: Fixture["sppCalls"][number],
) {
  if (data.sender === undefined) throw new Error("no sender bundle");
  return openSenderBundle(
    slotSecretOf(sender, data, call, data.outputs.length),
    data.sender.body,
    bundleLayout(data.outputs),
  );
}

const ZERO_KEY = new Uint8Array(32) as Bytes32;

function claim(who: ShieldedKeypair): ReplyMetadata {
  const address = who.shieldedAddress();
  return {
    viewingKey: address.viewingPublicKey,
    ownerKey: address.signingPublicKey.ed25519(),
    nullifierPk: address.nullifierPublicKey,
    data: new Data(),
  };
}

function tagOf(output: RingTransactData["outputs"][number] | undefined): Bytes32 {
  if (output === undefined || output.body.kind === "exit") throw new Error("no tagged slot");
  return output.ownerTag;
}

function bodyKinds(data: RingTransactData): readonly string[] {
  return data.outputs.map((output) => output.body.kind);
}

/** One reply per body-bearing slot, in slot order. */
function replySlots(data: RingTransactData): readonly Uint8Array[] {
  const { replies } = data;
  if (replies === undefined) return [];
  return Array.from({ length: replies.region.length / replies.length }, (_, slot) =>
    replies.region.subarray(slot * replies.length, (slot + 1) * replies.length),
  );
}

import { ringSpendTransfer } from "../../../src/operations/payments/ring-spend.js";

describe("anonymous ring payment", () => {
  it("carries a fresh digest its opening rebuilds in the frame and the request", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const prove = () =>
      rail({ fixture, sender, transfer: spend(fixture, sender) })
        .withExactApproval()
        .withPayment({ to, asset: SOL_MINT, amount: 400n, reply: null })
        .prove(fixture.client);
    const proven = await prove();
    const { approvalOpening: opening } = proven;
    if (opening === undefined) throw new Error("no opening");
    const totals = openingTotals(opening);
    if (totals === undefined) throw new Error("no totals");
    const digest = totals.commitment(opening.blinder);
    expect(proven.data.extensions.approvalTotals).toEqual(digest);
    const request = checkTransferProof(fixture, proven.data);
    expect(request.approvalTotals).toEqual(digest);
    expect(request.approvalBlinder).toEqual(opening.blinder);
    expect((await prove()).approvalOpening?.blinder).not.toEqual(opening.blinder);
  });

  it("names a read cache and its selector, refuses a note it does not spend", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const anonymous = rail({ fixture, sender, transfer: spend(fixture, sender) }).withPayment({
      to,
      asset: SOL_MINT,
      amount: 400n,
      reply: null,
    });
    const cache = randomAddress();
    await expect(
      anonymous
        .withReadCache({ cache, notes: [{ nullifier: new Uint8Array(32) as Bytes32, slot: 3 }] })
        .prove(fixture.client),
    ).rejects.toMatchObject({ details: { reason: "CachedInputUnknown" } });
  });

  it("carries no digest and no opening unless asked", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender) })
      .withPayment({ to, asset: SOL_MINT, amount: 400n, reply: null })
      .prove(fixture.client);
    expect(proven.approvalOpening).toBeUndefined();
    expect(proven.data.extensions.approvalTotals).toBeUndefined();
  });

  it("publishes a zero tag on change, the slot secret tags on the payment and the bundle, the recipient opens its body and the auditor every hash", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const proven = await rail({
      fixture,
      sender,
      transfer: spend(fixture, sender),
    })
      .withPayment({
        to,
        asset: SOL_MINT,
        amount: 400n,
        reply: null,
      })
      .prove(fixture.client);
    const { instruction, data, call } = await expanded(fixture, proven, "anonymous");

    expect(call.circuit.kind).toBe("ringAnonymous");
    expect(bodyKinds(data)).toEqual(["none", "recipient"]);
    expect(data.entry).toBe(false);
    const [change, payment] = data.outputs;
    if (change === undefined || payment?.body.kind !== "recipient")
      throw new Error("no anonymous slots");
    expect(change.ownerTag).toEqual(ZERO_KEY);
    expect(payment.ownerTag).toEqual(slotTag(recipientTag(slotSecretOf(bob, data, call, 1))));
    expect(data.sender?.tag).toEqual(
      bundleTag(slotSecretOf(sender.keypair, data, call, data.outputs.length)),
    );
    expect(payment.body.body).toHaveLength(RECIPIENT_BODY_LEN);
    await checkAccounts(instruction, {
      fixture,
      data,
      registries: [fixture.ownRegistry],
      prefix: [],
      payer: fixture.authority,
    });
    checkTransferProof(fixture, data);
    checkDisclosure(fixture, call, data);
    checkRingBlindings(call, data);
    const { request, circuit } = anonymousTransfer(fixture);
    expect(circuit).toBe("custom-ring-transfer-2-in24-w4-s4");
    expect([request.inputCount, request.inputs.length]).toEqual([1, 24]);
    expect(request.outputs.map((slot) => slot.ownerKey)).toEqual([
      sender.keypair.shieldedAddress().signingPublicKey.confidentialViewTag(),
      bob.shieldedAddress().signingPublicKey.confidentialViewTag(),
    ]);
    const body = openedBody(bob, data, call, 1);
    expect(body.mint).toBe(SOL_MINT);
    expect(body.amount).toBe(400n);
    const note = new Utxo({
      owner: bob.signingPublicKey(),
      asset: body.mint,
      amount: body.amount,
      blinding: body.blinding,
      ringProgramId: fixture.ringProgramId,
    });
    expect(note.hash(bob.nullifierPublicKey(), TREE_ID)).toEqual(payment.hash);
    const bundle = openedBundle(sender.keypair, data, call);
    expect(bundle.change).toEqual([{ mint: SOL_MINT, amount: 9_600n }]);
    expect(bundle.recipientKeys).toEqual([bob.shieldedAddress().viewingPublicKey.u()]);
    expect(proven).not.toHaveProperty("viewingHistory");
  });

  it("derives one tag per transfer key and never repeats it for a repeated recipient", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const frame = async () => {
      const proven = await rail({ fixture, sender, transfer: spend(fixture, sender) })
        .withPayment({ to, asset: SOL_MINT, amount: 400n, reply: null })
        .withPayment({ to, asset: SOL_MINT, amount: 300n, reply: null })
        .prove(fixture.client);
      return (await expanded(fixture, proven, "anonymous")).data.outputs.slice(1, 3).map(tagOf);
    };
    const [first, second] = await frame();
    if (first === undefined || second === undefined) throw new Error("no slots");
    expect(hex(first)).not.toBe(hex(second));
    expect((await frame()).map(hex)).not.toContain(hex(first));
  });

  it("leads with a zero SOL change when nothing returns to the sender", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const proven = await rail({
      fixture,
      sender,
      transfer: spend(fixture, sender),
    })
      .withPayment({
        to,
        asset: SOL_MINT,
        amount: 10_000n,
        reply: null,
      })
      .prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");
    expect(data.outputs[0]?.body).toEqual({ kind: "none" });
    const zero = itemAt(call.proofInputs.outputs, 0);
    expect([
      zero.amount,
      zero.asset,
      hex(zero.ownerAddress?.toBytes() ?? new Uint8Array()),
    ]).toEqual([0n, SOL_MINT, hex(sender.keypair.shieldedAddress().toBytes())]);
    const bundle = openedBundle(sender.keypair, data, call);
    expect(bundle.change).toEqual([{ mint: SOL_MINT, amount: 0n }]);
    checkDisclosure(fixture, call, data);
  });

  it("lists every body-bearing slot in the sender bundle, an exit and a dummy under the zero key", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const outside = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const transfer = spend(fixture, sender);
    const paying = rail({ fixture, sender, transfer }).withPayment({
      to,
      asset: SOL_MINT,
      amount: 400n,
      reply: null,
    });
    transfer.sendDefaultRing(outside.shieldedAddress(), SOL_MINT, 300n);
    const { data, call } = await expanded(fixture, await paying.prove(fixture.client), "anonymous");

    expect(bodyKinds(data)).toEqual(["none", "recipient", "exit", "recipient"]);
    expect(openedBundle(sender.keypair, data, call).recipientKeys).toEqual([
      bob.shieldedAddress().viewingPublicKey.u(),
      ZERO_KEY,
      ZERO_KEY,
    ]);
    const dummy = data.outputs[3];
    if (dummy?.body.kind !== "recipient") throw new Error("no dummy slot");
    expect(dummy.body.body).toHaveLength(RECIPIENT_BODY_LEN);
    expect(hex(dummy.ownerTag)).not.toBe(hex(ZERO_KEY));
    expect(dummy.ownerTag).toEqual(slotTag(dummy.ownerTag));
    checkDisclosure(fixture, call, data);
  });

  it("refuses a recipient key no agreement accepts before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate().shieldedAddress();
    const lowOrder = new RingAddress({
      recipient: ShieldedAddress.fromPublicKeys(
        bob.signingPublicKey,
        bob.nullifierPublicKey,
        X25519PublicKey.fromBytes(Uint8Array.of(4, ...new Uint8Array(32))),
      ),
      ringProgramId: fixture.ringProgramId,
      listSalt: new Uint8Array(32).fill(1) as Bytes32,
    });
    await expect(
      rail({ fixture, sender, transfer: spend(fixture, sender) })
        .withPayment({
          to: lowOrder,
          asset: SOL_MINT,
          amount: 400n,
          reply: null,
        })
        .prove(fixture.client),
    ).rejects.toThrow(ringError("RING_RECIPIENT_KEY_NOT_CONTRIBUTORY"));
    noProofs(fixture);
  });

  it("completes through a remote holder that forwards only port methods", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const local = walletKeys(sender.keypair);
    const called = new Set<string>();
    const track = <T>(name: string, value: T): T => {
      called.add(name);
      return value;
    };
    const remote: WalletKeys & RingKeys = {
      address: () => track("address", local.address()),
      viewingPublicKeys: () => track("viewingPublicKeys", local.viewingPublicKeys()),
      decrypt: (requests) => track("decrypt", local.decrypt(requests)),
      derive: (requests) => track("derive", local.derive(requests)),
      transactionKeys: (requests) => track("transactionKeys", local.transactionKeys(requests)),
      ringDeliverySecrets: (requests) =>
        track("ringDeliverySecrets", local.ringDeliverySecrets(requests)),
      mergeSeeds: (requests) => track("mergeSeeds", local.mergeSeeds(requests)),
      listSalt: (ring) => track("listSalt", local.listSalt(ring)),
      ringTagMatches: (frames) => track("ringTagMatches", local.ringTagMatches(frames)),
      viewTags: (requests) => track("viewTags", local.viewTags(requests)),
      prove: (inputs, context) => track("prove", local.prove(inputs, context)),
      proveMerge: (inputs, context) => track("proveMerge", local.proveMerge(inputs, context)),
    };
    const proven = await rail({
      fixture,
      sender,
      transfer: spend(fixture, sender),
      keys: remote,
    })
      .withPayment({
        to,
        asset: SOL_MINT,
        amount: 400n,
        reply: null,
      })
      .prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    checkDisclosure(fixture, call, data);
    expect(call.authority).toBe(remote);
    expect([...called].sort()).toEqual(["address", "transactionKeys"]);
  });
});

describe("anonymous delivery slots", () => {
  async function paying(
    amounts: readonly bigint[],
    options: Readonly<{
      compact?: boolean;
      replies?: readonly (ReplyMetadata | null)[];
    }> = {},
  ) {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const note = [noteInput(sender.keypair, 10_000n, fixture.ringProgramId)];
    const address = sender.keypair.shieldedAddress();
    const transfer =
      options.compact === true
        ? ConfidentialTransfer.compact(address, note, fixture.authority)
        : new ConfidentialTransfer(address, note, fixture.authority);
    const recipients = amounts.map(() => ShieldedKeypair.generate());
    let anonymous = rail({ fixture, sender, transfer });
    for (const [index, amount] of amounts.entries())
      anonymous = anonymous.withPayment({
        to: await addressOf(fixture, itemAt(recipients, index)),
        asset: SOL_MINT,
        amount,
        reply: options.replies?.[index] ?? null,
      });
    return { fixture, sender, recipients, anonymous };
  }

  it("omits a compact suffix on the anonymous rail and keeps every published slot's blinding", async () => {
    const { fixture, recipients, anonymous } = await paying([400n, 300n], {
      compact: true,
    });
    const { data, call } = await expanded(
      fixture,
      await anonymous.prove(fixture.client),
      "anonymous",
    );

    expect([data.nOut, data.outputs.length]).toEqual([4, 3]);
    expect(data.sender?.body).toHaveLength(senderBundleLen({ outputs: 3, change: 1 }));
    checkRingBlindings(call, data);
    const request = checkTransferProof(fixture, data);
    expect([request.outputCount, request.outputs.length]).toEqual([3, 4]);
    expect(openedBody(itemAt(recipients, 1), data, call, 2).blinding).toEqual(
      call.proofInputs.outputs[2]?.blinding,
    );
    checkDisclosure(fixture, call, data);
  });

  it("leads with the change at the sender's exact address, ahead of every payment", async () => {
    const { fixture, sender, anonymous } = await paying([400n]);
    const { data, call } = await expanded(
      fixture,
      await anonymous.prove(fixture.client),
      "anonymous",
    );
    expect(bodyKinds(data)).toEqual(["none", "recipient"]);
    expect(itemAt(call.proofInputs.outputs, 0).ownerAddress?.toBytes()).toEqual(
      sender.keypair.shieldedAddress().toBytes(),
    );
    expect(itemAt(call.proofInputs.outputs, 0).amount).toBe(9_600n);
    const request = checkTransferProof(fixture, data);
    const owner = sender.keypair.shieldedAddress().signingPublicKey;
    expect(request.outputs[0]?.ownerKey).toEqual(owner.confidentialViewTag());
    // The proof holds the change key to the sender's tracking row.
    expect(itemAt(request.trackingPool.subjects, request.outputEntries[0] ?? -1).member).toEqual(
      owner.ownerProofInputHash(),
    );
  });

  it("builds a frame with no change output when no padding slot is left", async () => {
    const { fixture, sender, anonymous } = await paying([5_000n, 3_000n, 1_000n, 1_000n]);
    const { data, call } = await expanded(
      fixture,
      await anonymous.prove(fixture.client),
      "anonymous",
    );
    expect(bodyKinds(data)).toEqual(Array(4).fill("recipient"));
    const bundle = openedBundle(sender.keypair, data, call);
    expect(bundle.change).toEqual([]);
    checkTransferProof(fixture, data);
  });

  it("writes no reply bytes on a frame whose payments all name no reply", async () => {
    const { fixture, anonymous } = await paying([400n]);
    const { data, instruction } = await expanded(
      fixture,
      await anonymous.prove(fixture.client),
      "anonymous",
    );
    expect(data.replies).toBeUndefined();
    // Flags bit 6 is `REPLY_METADATA`.
    expect((instruction.data?.[1] ?? 0) & 0x40).toBe(0);
    checkTransferProof(fixture, data);
  });

  it("gives every body one reply length on any named reply, a dummy's bytes random", async () => {
    const sayer = ShieldedKeypair.generate();
    const build = async () => {
      const { fixture, recipients, anonymous } = await paying([400n, 300n], {
        replies: [claim(sayer), null],
      });
      anonymous.withShape({ inputs: 1, outputs: 4 });
      const expand = await expanded(fixture, await anonymous.prove(fixture.client), "anonymous");
      return { ...expand, recipients };
    };
    const { data, call, recipients } = await build();
    expect(bodyKinds(data)).toEqual(["none", "recipient", "recipient", "recipient"]);
    const replies = replySlots(data);
    expect(data.replies?.length).toBeGreaterThanOrEqual(MIN_REPLY_LEN);
    expect(replies).toHaveLength(3);
    const secret = (reader: ShieldedKeypair, slot: number) =>
      slotSecretOf(reader, data, call, slot);
    const opened = openReply(secret(itemAt(recipients, 0), 1), itemAt(replies, 0));
    expect(opened?.claimed.ownerKey).toEqual(sayer.shieldedAddress().signingPublicKey.ed25519());
    expect(opened?.claimed.viewingKey.u()).toEqual(sayer.shieldedAddress().viewingPublicKey.u());
    // The slot that names none and the dummy hold random bytes, no reply opens from them.
    expect(openReply(secret(itemAt(recipients, 1), 2), itemAt(replies, 1))).toBeUndefined();
    expect(itemAt(replies, 2).some((byte) => byte !== 0)).toBe(true);
    const again = await build();
    expect(replySlots(again.data)[2]).not.toEqual(replies[2]);
  });

  it("carries no reply on a change slot", async () => {
    const { fixture, anonymous } = await paying([400n], {
      replies: [claim(ShieldedKeypair.generate())],
    });
    const { data, call } = await expanded(
      fixture,
      await anonymous.prove(fixture.client),
      "anonymous",
    );
    expect(bodyKinds(data)).toEqual(["none", "recipient"]);
    expect(replySlots(data)).toHaveLength(1);
    expect(call.proofInputs.externalData.outputs[0]?.data).toBeUndefined();
  });

  it("refuses every send of a payment that names no reply", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    fixture.enroll(sender.keypair.shieldedAddress());
    const wallet = new Wallet({ identity: sender.keypair.shieldedAddress() });
    const utxo = new Utxo({
      owner: sender.keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 100n,
      blinding: randomBlinding(),
      ringProgramId: fixture.ringProgramId,
    });
    const hash = utxo.proofInput(sender.keypair.nullifierPublicKey(), TREE_ID).hash();
    wallet._replace({
      utxos: [
        {
          utxo,
          outputContext: { hash, tree: TREE, leafIndex: 0n },
          nullifier: utxo.nullifier(hash, sender.keypair.nullifierKey()),
          spent: false,
        },
      ],
      transactions: [],
      nullifiers: new Set(),
    });
    const owner = {
      signer: signingKeySpendSigner(sender.signing),
    };
    const params = {
      client: { ...fixture.client, getLatestBlockhash: async () => BLOCKHASH },
      ringProgramId: fixture.ringProgramId,
      wallet,
      keys: walletKeys(sender.keypair),
      amount: 10n,
      approve: async (request: RingApprovalRequest) => approveRingUnattended(request),
      recipient: await addressOf(fixture, ShieldedKeypair.generate()),
    };
    const refused = {
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_REPLY_INVALID",
      cause: { details: { reason: "unnamed" } },
    };
    await expect(
      prepareRingTransferRelay({
        ...params,
        anonymous: {
          ...owner,
          quote: { feePayer: fixture.authority, validUntilSlot: 100n },
          nullifierKey: sender.keypair.nullifierKey(),
        },
      }),
    ).rejects.toMatchObject(refused);
    await expect(
      createRingTransferSubmission({
        ...params,
        feePayer: fixture.authority,
        anonymous: owner,
      }),
    ).rejects.toMatchObject(refused);
    noProofs(fixture);
  });
});

describe("anonymous ring exits and entries", () => {
  it("exits a note to the default ring under scheme 3 with its record in the auditor message", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const outside = ShieldedKeypair.generate();
    const transfer = spend(fixture, sender);
    transfer.sendDefaultRing(outside.shieldedAddress(), SOL_MINT, 300n);
    const proven = await rail({ fixture, sender, transfer }).prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    expect(bodyKinds(data)).toEqual(["none", "exit"]);
    checkTransferProof(fixture, data);
    checkDisclosure(fixture, call, data);
    const exit = data.outputs[1];
    if (exit?.body.kind !== "exit") throw new Error("no exit slot");
    const viewing = outside.viewingKey();
    const opened = decodeConfidential(
      viewing.decryptUtxo(
        exit.body.payload.subarray(33),
        X25519PublicKey.fromBytes(call.data.txViewingPk),
        data.salt,
        1,
      ),
    );
    viewing.destroy();
    expect(opened.amount).toBe(300n);
  });

  it("spends a default-ring note under the entry key, every input opened in full", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const proven = await rail({
      fixture,
      sender,
      transfer: spend(fixture, sender, { ring: "default" }),
    })
      .withPayment({
        to,
        asset: SOL_MINT,
        amount: 400n,
        reply: null,
      })
      .prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    expect(data.entry).toBe(true);
    // Input byte bit 7 names the entry key.
    expect((RingTransactData.encode(data)[2] ?? 0) & 0x80).toBe(0x80);
    checkTransferProof(fixture, data);
    const disclosure = checkDisclosure(fixture, call, data);
    expect(disclosure.envelope.evidence.kind).toBe("entry");
    const { request, circuit } = anonymousTransfer(fixture);
    expect(circuit).toBe("custom-ring-transfer-entry-4-in8-w4-s8");
    expect([request.layout.entry, request.inputs.length]).toEqual([true, 8]);
  });

  it("counts an entry's default owner tag, its setup instructions and fee before approval and any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    await checkFrameCounted(fixture, {
      payer: fixture.authority,
      prove: (approval) =>
        rail({
          fixture,
          sender,
          transfer: spend(fixture, sender, { ring: "default" }),
        })
          .withPayment({
            to,
            asset: SOL_MINT,
            amount: 400n,
            reply: null,
          })
          .proveApproved(fixture.client, approval),
    });
  });

  it("binds an entry input data hash in both proof requests", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const input = ProofInputUtxo.fromKeypair(
      new Utxo({
        owner: sender.keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 10_000n,
        blinding: randomBlinding(),
      }),
      sender.keypair,
      { dataHash: small(0x55) },
      TREE_ID,
    );
    const transfer = new ConfidentialTransfer(
      sender.keypair.shieldedAddress(),
      [input],
      fixture.authority,
    );
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const proven = await rail({ fixture, sender, transfer })
      .withPayment({ to, asset: SOL_MINT, amount: 400n, reply: null })
      .prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");
    expect(data.entry).toBe(true);
    expect(itemAt(checkTransferProof(fixture, data).inputs, 0).dataHash).toEqual(small(0x55));
    const core = await anonymousCoreInputs(fixture);
    expect(itemAt(core.inputs, 0).circuit.dataHash).toBe(0x55n);
    expect(core.defaultOwnerPublicKeyHash).toBe(
      bytesToBigInt(sender.keypair.signingPublicKey().ownerProofInputHash()),
    );
    checkDisclosure(fixture, call, data);
  });

  it("refuses ring notes beside a default-ring note before the entry width and any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const transfer = new ConfidentialTransfer(
      sender.keypair.shieldedAddress(),
      [
        noteInput(sender.keypair, 10_000n),
        ...Array.from({ length: 8 }, () =>
          noteInput(sender.keypair, 1_000n, fixture.ringProgramId),
        ),
      ],
      fixture.authority,
    );
    await expect(rail({ fixture, sender, transfer }).prove(fixture.client)).rejects.toThrow(
      ringError("RING_ENTRY_RING_INPUT", { index: 1 }),
    );
    noProofs(fixture);
  });

  it("refuses a frame of public owners alone and a hidden owner's note past a co-owner's", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const other = ShieldedKeypair.generate();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const refused = async (notes: readonly ProofInputUtxo[], index: number) => {
      const transfer = ringSpendTransfer({
        owner: sender.keypair.shieldedAddress(),
        inputs: notes,
        feePayer: fixture.authority,
      });
      transfer.withShape({ inputs: notes.length === 1 ? 2 : 4, outputs: 2 });
      await expect(
        rail({ fixture, sender, transfer })
          .withPayment({
            to,
            asset: SOL_MINT,
            amount: 100n,
            reply: null,
          })
          .prove(fixture.client),
      ).rejects.toThrow(ringError("RING_NO_HIDDEN_OWNER", { index }));
    };
    await refused([noteInput(other, 10_000n, fixture.ringProgramId)], 0);
    await refused(
      [
        noteInput(sender.keypair, 5_000n, fixture.ringProgramId),
        noteInput(other, 5_000n, fixture.ringProgramId),
        noteInput(sender.keypair, 5_000n, fixture.ringProgramId),
      ],
      1,
    );
    noProofs(fixture);
  });

  it("runs a public co-owner in the account run beside the hidden owner", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const coOwner = ShieldedKeypair.generate();
    const transfer = ringSpendTransfer({
      owner: sender.keypair.shieldedAddress(),
      inputs: [
        noteInput(sender.keypair, 5_000n, fixture.ringProgramId),
        noteInput(coOwner, 5_000n, fixture.ringProgramId),
      ],
      feePayer: fixture.authority,
    });
    transfer.withShape({ inputs: 2, outputs: 2 });
    fixture.enroll(coOwner.shieldedAddress());
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const proven = await rail({ fixture, sender, transfer })
      .withCoOwner({
        owner: coOwner.shieldedAddress().solanaAddress(),
        nullifierKey: coOwner.nullifierKey(),
      })
      .withPayment({
        to,
        asset: SOL_MINT,
        amount: 400n,
        reply: null,
      })
      .prove(fixture.client);
    const { instruction, data, call } = await expanded(fixture, proven, "anonymous");
    const coOwnerAddress = coOwner.shieldedAddress().solanaAddress();

    expect(proven.accounts.ownerSigners).toEqual([coOwnerAddress]);
    await checkAccounts(instruction, {
      fixture,
      data,
      registries: [fixture.ownRegistry],
      prefix: [],
      payer: fixture.authority,
      ownerSigners: [coOwnerAddress],
    });
    const request = checkTransferProof(fixture, data);
    const identity = coOwner.shieldedAddress().signingPublicKey.ownerProofInputHash();
    expect(bindingSigners(request)).toEqual([identity]);
    // The rows ascend as field integers.
    expect(request.rows.slice(0, 2).map(hex)).toEqual(
      [sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash(), identity]
        .map(hex)
        .sort(),
    );
    checkDisclosure(fixture, call, data);
  });

  it.each([
    ["default", "default"],
    ["default", "ring"],
    ["ring", "default"],
  ] as const)(
    "binds a %s hidden input and a %s public input on the entry key",
    async (hiddenRing, publicRing) => {
      const fixture = await anonymousRing();
      const sender = anonymousSender();
      const coOwner = ShieldedKeypair.generate();
      fixture.enroll(coOwner.shieldedAddress());
      const transfer = ringSpendTransfer({
        owner: sender.keypair.shieldedAddress(),
        inputs: [
          { owner: sender.keypair, ring: hiddenRing },
          { owner: coOwner, ring: publicRing },
        ].map(({ owner, ring }) =>
          ProofInputUtxo.fromKeypair(
            new Utxo({
              owner: owner.signingPublicKey(),
              asset: SOL_MINT,
              amount: 5_000n,
              blinding: randomBlinding(),
              ...(ring === "ring" ? { ringProgramId: fixture.ringProgramId } : {}),
            }),
            owner,
            ring === "ring" ? { ringDataHash: small(0x66) } : {},
            TREE_ID,
          ),
        ),
        feePayer: fixture.authority,
      });
      transfer.withShape({ inputs: 2, outputs: 2 });
      const to = await addressOf(fixture, ShieldedKeypair.generate());
      const proven = await rail({ fixture, sender, transfer })
        .withCoOwner({
          owner: coOwner.shieldedAddress().solanaAddress(),
          nullifierKey: coOwner.nullifierKey(),
        })
        .withPayment({ to, asset: SOL_MINT, amount: 400n, reply: null })
        .prove(fixture.client);
      const { data, call } = await expanded(fixture, proven, "anonymous");
      expect(data.entry).toBe(true);
      const request = checkTransferProof(fixture, data);
      const identity = coOwner.signingPublicKey().ownerProofInputHash();
      expect(bindingSigners(request)).toEqual([identity]);
      expect(proven.accounts.ownerSigners).toEqual([coOwner.shieldedAddress().solanaAddress()]);
      const core = await anonymousCoreInputs(fixture);
      for (const [index, ring] of [hiddenRing, publicRing].entries()) {
        expect(itemAt(request.inputs, index).ringDataHash).toEqual(
          small(ring === "ring" ? 0x66 : 0),
        );
        expect(itemAt(core.inputs, index).circuit.ringDataHash).toBe(ring === "ring" ? 0x66n : 0n);
      }
      expect(core.signerPublicKeyHashes.filter((value) => value !== 0n)).toEqual([
        bytesToBigInt(identity),
      ]);
      expect(core.defaultOwnerPublicKeyHash).toBe(
        hiddenRing === "default"
          ? bytesToBigInt(sender.keypair.signingPublicKey().ownerProofInputHash())
          : 0n,
      );
      expect(itemAt(request.entries, 0).ownerKey).toEqual(
        hiddenRing === "default"
          ? sender.keypair.signingPublicKey().confidentialViewTag()
          : small(0),
      );
      expect(itemAt(request.entries, 1).ownerKey).toEqual(
        publicRing === "default" ? coOwner.signingPublicKey().confidentialViewTag() : small(0),
      );
      checkDisclosure(fixture, call, data);
    },
  );

  it("refuses an entry without its public co-owner key before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const transfer = ringSpendTransfer({
      owner: sender.keypair.shieldedAddress(),
      inputs: [noteInput(sender.keypair, 5_000n), noteInput(ShieldedKeypair.generate(), 5_000n)],
      feePayer: fixture.authority,
    });
    transfer.withShape({ inputs: 2, outputs: 2 });
    await expect(rail({ fixture, sender, transfer }).prove(fixture.client)).rejects.toThrow(
      ringError("RING_MISSING_CO_OWNER_KEY", { index: 1 }),
    );
    noProofs(fixture);
  });

  it("refuses an unkeyed sixteen output frame before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const payments = await Promise.all(
      Array.from({ length: 15 }, () => addressOf(fixture, ShieldedKeypair.generate())),
    );
    const paying = payments.reduce(
      (transfer, to) => transfer.withPayment({ to, asset: SOL_MINT, amount: 1n, reply: null }),
      rail({ fixture, sender, transfer: spend(fixture, sender) }),
    );
    await expect(paying.prove(fixture.client)).rejects.toThrow(
      ringError("RING_CATALOG_KEY_MISSING"),
    );
    noProofs(fixture);
  });

  describe("a payment carrying data", () => {
    const pay = async (data: NoteData) => {
      const fixture = await anonymousRing();
      const sender = anonymousSender();
      const bob = ShieldedKeypair.generate();
      const to = await addressOf(fixture, bob);
      const proven = await rail({ fixture, sender, transfer: spend(fixture, sender) })
        .withPayment({ to, asset: SOL_MINT, amount: 400n, reply: null, data })
        .prove(fixture.client);
      const { data: frame, call } = await expanded(fixture, proven, "anonymous");
      const slot = call.proofInputs.outputs.findIndex((output) =>
        output.ownerAddress?.signingPublicKey.equals(bob.signingPublicKey()),
      );
      return { proven, frame, call, bob, slot, output: itemAt(call.proofInputs.outputs, slot) };
    };

    it("commits a ring data hash with no owner signature", async () => {
      const ringDataHash = small(0x33);
      const { proven, output } = await pay({ ringDataHash });
      expect(output.ringDataHash).toEqual(ringDataHash);
      expect(proven.accounts.ownerSigners).toEqual([]);
    });

    it("holds application data to a signing owner and carries it in the body", async () => {
      const hash = small(0x44);
      const bytes = new TextEncoder().encode("app");
      const { proven, output, frame, bob, slot, call } = await pay({
        application: { hash, bytes },
      });
      expect(output.dataHash).toEqual(hash);
      expect(frame.hasData).toBe(true);
      expect(proven.accounts.ownerSigners).toEqual([
        encodeBase58(bob.signingPublicKey().ed25519()),
      ]);
      const body = frame.outputs[slot]?.body;
      if (body?.kind !== "recipient") throw new Error("no body");
      const opened = openRecipientBody(slotSecretOf(bob, frame, call, slot), body.body);
      expect(opened.data).toEqual(Uint8Array.of(...hash, ...bytes));
    });

    it("keeps a payment's data on its slot past an exit", async () => {
      const fixture = await anonymousRing();
      const sender = anonymousSender();
      const bob = ShieldedKeypair.generate();
      const to = await addressOf(fixture, bob);
      const transfer = spend(fixture, sender);
      const leaving = ShieldedKeypair.generate();
      fixture.enroll(leaving.shieldedAddress());
      transfer.sendDefaultRing(leaving.shieldedAddress(), SOL_MINT, 100n);
      const ringDataHash = small(0x33);
      const proven = await rail({ fixture, sender, transfer })
        .withPayment({ to, asset: SOL_MINT, amount: 400n, reply: null, data: { ringDataHash } })
        .prove(fixture.client);
      const { call } = await expanded(fixture, proven, "anonymous");
      const owned = (owner: ShieldedKeypair) =>
        call.proofInputs.outputs.find((output) =>
          output.ownerAddress?.signingPublicKey.equals(owner.signingPublicKey()),
        );
      expect(owned(bob)?.ringDataHash).toEqual(ringDataHash);
      expect(owned(leaving)?.ringDataHash).toBeUndefined();
    });

    it("refuses application bytes under a zero hash before any proof", async () => {
      const fixture = await anonymousRing();
      const sender = anonymousSender();
      const to = await addressOf(fixture, ShieldedKeypair.generate());
      await expect(
        rail({ fixture, sender, transfer: spend(fixture, sender) })
          .withPayment({
            to,
            asset: SOL_MINT,
            amount: 400n,
            reply: null,
            data: {
              application: {
                hash: new Uint8Array(32) as Bytes32,
                bytes: new TextEncoder().encode("app"),
              },
            },
          })
          .prove(fixture.client),
      ).rejects.toThrow(ringError("RING_NOTE_DATA_UNBOUND"));
      noProofs(fixture);
    });
  });

  it("refuses a recipient viewing key off its record", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const enrolledElsewhere = bob.shieldedAddress();
    fixture.enroll(
      ShieldedAddress.fromPublicKeys(
        enrolledElsewhere.signingPublicKey,
        enrolledElsewhere.nullifierPublicKey,
        ShieldedKeypair.generate().viewingPublicKey(),
      ),
    );
    await expect(
      rail({ fixture, sender, transfer: spend(fixture, sender) })
        .withPayment({
          to,
          asset: SOL_MINT,
          amount: 400n,
          reply: null,
        })
        .prove(fixture.client),
    ).rejects.toThrow(ringError("RING_RECIPIENT_VIEWING_KEY_STALE"));
    noProofs(fixture);
  });

  it("refuses a sender and a recipient without an enrolled address", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const unenrolled = new RingAddress({
      recipient: bob.shieldedAddress(),
      ringProgramId: fixture.ringProgramId,
      listSalt: new Uint8Array(32).fill(1) as Bytes32,
    });
    const pay = (enrolled: boolean, to: RingAddress) =>
      rail({ fixture, sender, transfer: spend(fixture, sender), enrolled })
        .withPayment({
          to,
          asset: SOL_MINT,
          amount: 400n,
          reply: null,
        })
        .prove(fixture.client);
    const enrolledRecipient = await addressOf(fixture, ShieldedKeypair.generate());
    const senderMember = Buffer.from(
      sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash(),
    ).toString("hex");
    await expect(pay(false, enrolledRecipient)).rejects.toThrow(
      ringError("RING_ADDRESS_NOT_ENROLLED", { member: senderMember }),
    );
    await expect(pay(true, unenrolled)).rejects.toThrow(ringError("RING_RECIPIENT_NOT_ENROLLED"));
    noProofs(fixture);
  });

  it("refuses an exit to the hidden sender, its owner tag would publish the sender", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const toOwn = spend(fixture, sender);
    toOwn.sendDefaultRing(sender.keypair.shieldedAddress(), SOL_MINT, 100n);
    await expect(rail({ fixture, sender, transfer: toOwn }).prove(fixture.client)).rejects.toThrow(
      ringError("RING_SENDER_EXIT", { slotIndex: 1 }),
    );
    noProofs(fixture);
  });

  it("carries one bundle cell per change output, each bodiless", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const transfer = spend(fixture, sender);
    transfer.send(sender.keypair.shieldedAddress(), SOL_MINT, 100n);
    transfer.send(sender.keypair.shieldedAddress(), SOL_MINT, 200n);
    const proven = await rail({ fixture, sender, transfer }).prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");
    expect(bodyKinds(data).slice(0, 3)).toEqual(["none", "none", "none"]);
    const bundle = openedBundle(sender.keypair, data, call);
    expect(bundle.change.map((cell) => cell.amount).toSorted()).toEqual([100n, 200n, 9_700n]);
    expect(bundle.recipientKeys.every((key) => key.every((byte) => byte === 0))).toBe(true);
  });

  it("refuses change outputs past the transaction's output count before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const transfer = spend(fixture, sender);
    transfer.withShape({ inputs: 1, outputs: 2 });
    transfer.send(sender.keypair.shieldedAddress(), SOL_MINT, 100n);
    transfer.send(sender.keypair.shieldedAddress(), SOL_MINT, 200n);
    await expect(rail({ fixture, sender, transfer }).prove(fixture.client)).rejects.toThrow(
      "TRANSACTION_TOO_MANY_OUTPUTS_FOR_SHAPE",
    );
    noProofs(fixture);
  });

  it("refuses a ring output no payment planned", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const transfer = spend(fixture, sender);
    transfer.send(ShieldedKeypair.generate().shieldedAddress(), SOL_MINT, 100n);
    await expect(rail({ fixture, sender, transfer }).prove(fixture.client)).rejects.toThrow(
      ringError("RING_UNPLANNED_OUTPUT", { slotIndex: 1 }),
    );
    noProofs(fixture);
  });
});

describe("anonymous ring signer", () => {
  it("refuses another signer, a hidden owner that signs in public and another ring", async () => {
    const sender = anonymousSender();
    const hidden = sender.keypair.shieldedAddress().solanaAddress();
    const refused = async (
      fixture: Fixture,
      transfer: Promise<ProvenRingTransfer>,
      code: string,
    ): Promise<void> => {
      await expect(transfer).rejects.toThrow(ringError(code));
      noProofs(fixture);
    };
    const ring = await anonymousRing();
    await refused(
      ring,
      rail({
        fixture: ring,
        sender,
        transfer: spend(ring, sender),
        signer: signingKeySpendSigner(SigningKey.generate()),
      }).prove(ring.client),
      "RING_ANONYMOUS_SIGNER_MISMATCH",
    );
    await refused(
      ring,
      rail({
        fixture: ring,
        sender,
        transfer: spend(ring, sender, { payer: hidden }),
      }).prove(ring.client),
      "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
    );
    const coSigned = await anonymousRing({
      coSigner: { signer: hidden, scope: RING_COSIGN_TRANSFERS },
    });
    await refused(
      coSigned,
      rail({
        fixture: coSigned,
        sender,
        transfer: spend(coSigned, sender),
      }).prove(coSigned.client),
      "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
    );
    const confidential = await ringFixture();
    await refused(
      confidential,
      rail({
        fixture: confidential,
        sender,
        transfer: spend(confidential, sender),
      }).prove(confidential.client),
      "RING_NOT_ANONYMOUS",
    );
    const other = await anonymousRing();
    const foreign = await addressOf(other, ShieldedKeypair.generate());
    expect(() =>
      rail({
        fixture: ring,
        sender,
        transfer: spend(ring, sender),
      }).withPayment({
        to: foreign,
        asset: SOL_MINT,
        amount: 1n,
        reply: null,
      }),
    ).toThrow(ringError("RING_FOREIGN_RING", { address: other.ringProgramId }));
  });
});

describe("anonymous ring relay", () => {
  /** A relay of `notes` notes of 10, of the ring or the default ring, on a ring a co-signer guards when `policy`. */
  async function anonymousSpend(
    input: Readonly<{
      notes: number;
      amount: bigint;
      ring?: "default";
      /** Default-ring notes beside the ring notes, a transfer may spend them. */
      defaultNotes?: readonly bigint[];
      /** Default-ring notes carrying a data hash. */
      dataNotes?: readonly Readonly<{ amount: bigint; dataHash: Bytes32 }>[];
      policy?: boolean;
      withdraw?: boolean;
      entry?: boolean;
    }>,
  ) {
    const sender = anonymousSender();
    const coSigner = randomAddress();
    const fixture = await anonymousRing(
      input.policy === true
        ? {
            table: buildRuleTable({
              rules: [
                {
                  subject: "sender",
                  source: {
                    kind: "lists",
                    present: [ListId.allow],
                    absent: [],
                  },
                  guard: { kind: "always" },
                },
              ],
            }),
            records: [
              {
                member: memberOfAsset(SOL_MINT),
                lists: 0n,
                mintPolicy: { ...EMPTY_MINT_POLICY, cosignAbove: 1n },
              },
              {
                member: memberOfIdentity(
                  sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash(),
                ),
                lists: 1n,
              },
            ],
            coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS },
          }
        : {},
    );
    fixture.enroll(sender.keypair.shieldedAddress());
    const notes: readonly Readonly<{
      amount: bigint;
      ring?: Address;
      dataHash?: Bytes32;
    }>[] = [
      ...Array.from({ length: input.notes }, () =>
        input.ring === "default" ? { amount: 10n } : { amount: 10n, ring: fixture.ringProgramId },
      ),
      ...(input.defaultNotes ?? []).map((amount) => ({ amount })),
      ...(input.dataNotes ?? []),
    ];
    const wallet = new Wallet({ identity: sender.keypair.shieldedAddress() });
    wallet._replace({
      utxos: notes.map((note, index) => {
        const utxo = new Utxo({
          owner: sender.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: note.amount,
          blinding: randomBlinding(),
          ...(note.ring === undefined ? {} : { ringProgramId: note.ring }),
        });
        const nullifierPublicKey = sender.keypair.nullifierPublicKey();
        const hash = utxo.proofInput(nullifierPublicKey, TREE_ID, note.dataHash).hash();
        return {
          utxo,
          outputContext: { hash, tree: TREE, leafIndex: BigInt(index) },
          nullifier: utxo.nullifier(hash, sender.keypair.nullifierKey()),
          ...(note.dataHash === undefined ? {} : { dataHash: note.dataHash }),
          spent: false,
        };
      }),
      transactions: [],
      nullifiers: new Set(),
    });
    const requests: RingApprovalRequest[] = [];
    const params = {
      client: recordReads(fixture),
      ringProgramId: fixture.ringProgramId,
      wallet,
      keys: walletKeys(sender.keypair),
      amount: input.amount,
      approve: async (request: RingApprovalRequest) => {
        requests.push(request);
        return approveRingUnattended(request);
      },
      anonymous: {
        quote: { feePayer: fixture.authority, validUntilSlot: 100n },
        nullifierKey: sender.keypair.nullifierKey(),
        signer: signingKeySpendSigner(sender.signing),
        reply: null,
      },
    };
    const relay =
      input.entry === true
        ? prepareRingEntryRelay(params)
        : input.withdraw === true
          ? prepareRingWithdrawalRelay({ ...params, recipient: randomAddress() })
          : prepareRingTransferRelay({
              ...params,
              recipient: await addressOf(fixture, ShieldedKeypair.generate()),
              ...(input.ring === "default"
                ? { inputs: "default" as const }
                : input.defaultNotes === undefined
                  ? {}
                  : { inputs: "ring-or-default" as const }),
            });
    return { fixture, requests, relay, params, sender };
  }

  /** The client the relay stages with, every record read counted. */
  function recordReads(fixture: Fixture) {
    const reads = { count: 0 };
    const client = {
      ...fixture.client,
      getLatestBlockhash: async () => BLOCKHASH,
      getStorageMemberOpenings: (
        ...args: Parameters<Fixture["client"]["getStorageMemberOpenings"]>
      ) => {
        reads.count += 1;
        return fixture.client.getStorageMemberOpenings(...args);
      },
      getStorageRecordPool: (...args: Parameters<Fixture["client"]["getStorageRecordPool"]>) => {
        reads.count += 1;
        return fixture.client.getStorageRecordPool(...args);
      },
    };
    return Object.assign(client, { reads });
  }

  /** Ring RPC answering every relay as submitted, each request kept. */
  function stubRelay() {
    const prepared: PrepareRelayRequest[] = [];
    const unexpected = () =>
      Promise.reject(new Error("the anonymous rail calls prepareRelay only"));
    const relay: RingRelayClient = {
      getRelayQuote: unexpected,
      submitRelay: unexpected,
      getRelayStatus: unexpected,
      prepareRelay: async (request) => {
        prepared.push(request);
        return { step: "submitted", relayId: relayId(request) };
      },
    };
    return { relay, prepared };
  }

  async function payload(relay: PreparedRingRelay) {
    const { intent } = (await relay.relay.sign()).request;
    if (intent.operation !== "anonymous") throw new Error("no anonymous intent");
    return decodeRelayProofInputs(
      new Uint8Array(getBase64Encoder().encode(intent.proofInputs)),
      assets,
    );
  }

  /** The inline owner tag of every output the payload publishes. */
  async function publishedTags(relay: PreparedRingRelay): Promise<readonly string[]> {
    return (await payload(relay)).externalData.outputs.map((output) =>
      output.ownerTag.kind === "inline" ? hex(output.ownerTag.value) : "",
    );
  }

  it("sends no Merkle path or record request and signs the payload's message hash", async () => {
    const { fixture, relay, params, sender } = await anonymousSpend({
      notes: 2,
      amount: 5n,
      policy: true,
    });
    const prepared = await relay;
    const stub = stubRelay();
    const relayIdSent = submittedRelay(await (await prepared.relay.sign()).send(stub.relay));

    expect(params.client.reads.count).toBe(0);
    noProofs(fixture);
    const [request] = stub.prepared;
    if (request?.intent.operation !== "anonymous") throw new Error("no anonymous relay");
    expect(relayIdSent).toBe(relayId(request));
    const sent = await payload(prepared);
    const messageHash = new SppProofInputs({
      payer: fixture.authority,
      inputUtxos: sent.inputs,
      outputs: sent.outputs,
      externalData: sent.externalData,
      blindingSeed: sent.blindingSeed,
      outputTreeId: sent.outputTreeId,
    }).messageHash();
    expect(
      ed25519.verify(
        new Uint8Array(getBase58Encoder().encode(request.intent.ownerSignature)),
        messageHash,
        sender.keypair.signingPublicKey().ed25519(),
      ),
    ).toBe(true);
  });

  describe("an entry of 25 out of a default note of 40", () => {
    const entered = (
      outputs: readonly ProofOutputUtxo[],
      sender: Sender,
    ): readonly (readonly [bigint, boolean, Address | undefined])[] =>
      outputs
        .filter((output) => !output.isDummy())
        .map((output) => [
          output.amount,
          output.ownerAddress?.signingPublicKey.equals(sender.keypair.signingPublicKey()) === true,
          output.ringProgramId,
        ]);
    const moved = (ring: Address) => [
      [25n, true, ring],
      [15n, true, ring],
    ];

    it("relays the 15 change in the ring, owned by the sender", async () => {
      const { fixture, requests, relay, sender } = await anonymousSpend({
        notes: 0,
        amount: 25n,
        defaultNotes: [40n],
        entry: true,
      });
      const sent = await payload(await relay);
      expect(sent.inputs.map((input) => input.utxo.amount)).toEqual([40n]);
      expect(entered(sent.outputs, sender)).toEqual(
        expect.arrayContaining(moved(fixture.ringProgramId)),
      );
      expect(entered(sent.outputs, sender)).toHaveLength(2);
      expect(requests[0]?.intent).toMatchObject({ kind: "ringEntry", amount: 40n });
      noProofs(fixture);
    });

    it("proves the 15 change in the ring, owned by the sender, from another payer", async () => {
      const { fixture, params, relay, sender } = await anonymousSpend({
        notes: 0,
        amount: 25n,
        defaultNotes: [40n, 40n],
        entry: true,
      });
      await relay;
      const payer = await generateKeyPairSigner();
      const { anonymous, ...plain } = params;
      await createRingEntrySubmission({
        ...plain,
        feePayer: payer.address,
        anonymous: { signer: anonymous.signer, reply: anonymous.reply },
      });
      const outputs = fixture.sppCalls.at(-1)?.proofInputs.outputs ?? [];
      expect(entered(outputs, sender)).toEqual(
        expect.arrayContaining(moved(fixture.ringProgramId)),
      );
      expect(entered(outputs, sender)).toHaveLength(2);
    });

    it("refuses an approval short of the change and change of another owner, another ring or the default ring", () => {
      const owner = ShieldedKeypair.generate().shieldedAddress();
      const ring = randomAddress();
      const output = (slot: Readonly<Record<string, unknown>>) =>
        ({
          isDummy: () => false,
          ownerAddress: owner,
          asset: SOL_MINT,
          amount: 25n,
          ringProgramId: ring,
          ...slot,
        }) as unknown as ProofOutputUtxo;
      const check = (change: Readonly<Record<string, unknown>>, amount = 40n) =>
        checkRingPreparedTransfer(
          {
            owner,
            inputs: [],
            interfaceTransfers: [],
            senderOutputCount: 1,
            outputs: [output({ amount: 15n, ...change }), output({})],
          } as unknown as PreparedTransfer,
          { kind: "ringEntry", ringProgramId: ring, asset: SOL_MINT, amount },
          ringIntentMismatch,
        );
      expect(() => check({})).not.toThrow();
      expect(() => check({}, 25n)).toThrow(
        expect.objectContaining({ code: "RING_INTENT_MISMATCH", details: { field: "amount" } }),
      );
      for (const wrong of [
        { ownerAddress: ShieldedKeypair.generate().shieldedAddress() },
        { ownerAddress: undefined },
        { ringProgramId: randomAddress() },
        { ringProgramId: undefined },
        { asset: randomAddress() },
      ])
        expect(() => check(wrong)).toThrow(
          expect.objectContaining({
            code: "RING_INTENT_MISMATCH",
            details: { field: "outputs" },
          }),
        );
    });
  });

  it("refuses a plain build on an anonymous ring and sends the hidden owner's submission from another payer", async () => {
    const { fixture, requests, params, relay, sender } = await anonymousSpend({
      notes: 2,
      amount: 5n,
      defaultNotes: [10n],
    });
    await relay;
    const approvals = requests.length;
    const { anonymous, ...plain } = params;
    const payer = await generateKeyPairSigner();
    const built = { ...plain, feePayer: payer.address };
    const recipient = await addressOf(fixture, ShieldedKeypair.generate());
    const refusals = [
      [
        () =>
          buildRingTransferTransaction({
            ...built,
            recipient: ShieldedKeypair.generate().shieldedAddress(),
          }),
        "RING_BUILD_TRANSFER",
      ],
      [
        () =>
          buildRingExitTransaction({
            ...built,
            recipient: ShieldedKeypair.generate().shieldedAddress(),
          }),
        "RING_BUILD_TRANSFER",
      ],
      [() => buildRingEntryTransaction(built), "RING_BUILD_ENTRY"],
      [
        () =>
          buildRingWithdrawalTransaction({
            ...built,
            recipient: randomAddress(),
          }),
        "RING_BUILD_WITHDRAWAL",
      ],
    ] as const;
    for (const [build, code] of refusals)
      await expect(build()).rejects.toMatchObject({
        code,
        causeCode: "RING_ANONYMOUS_SIGNER_REQUIRED",
        cause: { details: { ringProgramId: fixture.ringProgramId } },
      });
    const owner = {
      signer: anonymous.signer,
      reply: anonymous.reply,
    };
    await expect(
      createRingTransferSubmission({
        ...built,
        feePayer: sender.keypair.shieldedAddress().solanaAddress(),
        recipient,
        anonymous: owner,
      }),
    ).rejects.toMatchObject({ causeCode: "RING_ANONYMOUS_SIGNER_LINKS_OWNER" });
    expect(requests).toHaveLength(approvals);
    noProofs(fixture);

    const submission = await createRingTransferSubmission({
      ...built,
      recipient,
      anonymous: owner,
    });
    submission.prove();
    const result = await submission.send({
      sign: (transaction) => signTransactionWithSigners([payer], transaction),
      send: async () => undefined,
      status: async () => ({ kind: "confirmed", slot: 3n }),
    });
    expect(result).toMatchObject({ kind: "confirmed", attempts: 1 });
    expect(fixture.sppCalls.map((call) => call.circuit.kind)).toEqual(["ringAnonymous"]);
  });

  it("takes fresh tags on a second relay, a reply teaches no state", async () => {
    const { fixture, params, sender, relay } = await anonymousSpend({
      notes: 3,
      amount: 5n,
    });
    await relay;
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const first = await prepareRingTransferRelay({
      ...params,
      recipient: to,
      anonymous: { ...params.anonymous, reply: claim(sender.keypair) },
    });
    const second = await prepareRingTransferRelay({ ...params, recipient: to });
    expect((await publishedTags(first))[0]).toBe(hex(ZERO_KEY));
    expect((await publishedTags(second))[0]).toBe(hex(ZERO_KEY));
    expect((await publishedTags(first))[1]).not.toBe((await publishedTags(second))[1]);
  });

  it("pays a request and refuses one the payment contradicts before approval", async () => {
    const { fixture, params, requests, relay } = await anonymousSpend({
      notes: 4,
      amount: 5n,
    });
    await relay;
    const bob = ShieldedKeypair.generate();
    const request = new RingPaymentRequest({
      address: await addressOf(fixture, bob),
      amount: 5n,
      mint: SOL_MINT,
    });
    await prepareRingTransferRelay({ ...params, recipient: request });
    const approvals = requests.length;
    const contradicted = [
      [{ amount: 4n }, "amount"],
      [{ asset: randomAddress() }, "asset"],
    ] as const;
    for (const [change, field] of contradicted)
      await expect(
        prepareRingTransferRelay({ ...params, recipient: request, ...change }),
      ).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_INTENT_MISMATCH",
        cause: { details: { field } },
      });
    expect(requests).toHaveLength(approvals);
  });

  it("spends the widest commitment class and refuses a payment past it before approval", async () => {
    const widest = await anonymousSpend({ notes: 40, amount: 395n });
    expect((await payload(await widest.relay)).inputs).toHaveLength(40);
    expect(widest.requests).toHaveLength(1);
    const wider = await anonymousSpend({ notes: 41, amount: 405n });
    await expect(wider.relay).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { maximum: 40 } },
    });
    expect(wider.requests).toEqual([]);
    noProofs(wider.fixture);
  });

  it("relays a policy withdrawal of the widest class", async () => {
    const wide = await anonymousSpend({
      notes: 24,
      amount: 235n,
      policy: true,
      withdraw: true,
    });
    const sent = await payload(await wide.relay);
    expect([sent.inputs.length, sent.interfaceTransferAccounts.length]).toEqual([24, 1]);
    expect(wide.requests).toHaveLength(1);
  });

  it("spends the entry key's input class of default-ring notes and refuses one more", async () => {
    const entry = await anonymousSpend({
      notes: 8,
      amount: 75n,
      ring: "default",
      policy: true,
    });
    expect((await payload(await entry.relay)).inputs).toHaveLength(8);
    expect(entry.requests).toHaveLength(1);
    const wider = await anonymousSpend({
      notes: 9,
      amount: 85n,
      ring: "default",
    });
    await expect(wider.relay).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { maximum: 8 } },
    });
    expect(wider.requests).toEqual([]);
    noProofs(wider.fixture);
  });

  it("funds an entry from default-ring notes without data", async () => {
    const entry = await anonymousSpend({
      notes: 2,
      amount: 15n,
      ring: "default",
      dataNotes: [{ amount: 100n, dataHash: small(0x55) }],
    });
    await entry.relay;
    expect(entry.requests[0]?.intent).toMatchObject({ defaultFunding: 20n });
  });

  it("funds an entry from a default-ring note whose data hash is zero, like Rust `carries_no_data`", async () => {
    const entry = await anonymousSpend({
      notes: 0,
      amount: 15n,
      ring: "default",
      dataNotes: [{ amount: 20n, dataHash: small(0) }],
    });
    await entry.relay;
    expect(entry.requests[0]?.intent).toMatchObject({ defaultFunding: 20n });
  });

  it("funds a ring-or-default payment from ring notes alone, else default-ring notes alone, never both", async () => {
    const ringAlone = await anonymousSpend({
      notes: 3,
      amount: 25n,
      defaultNotes: [100n],
    });
    await ringAlone.relay;
    expect(ringAlone.requests[0]?.intent).toMatchObject({ defaultFunding: 0n });
    const defaultAlone = await anonymousSpend({
      notes: 3,
      amount: 40n,
      defaultNotes: [100n],
    });
    await defaultAlone.relay;
    expect(defaultAlone.requests[0]?.intent).toMatchObject({
      defaultFunding: 100n,
    });
    const both = await anonymousSpend({
      notes: 3,
      amount: 50n,
      defaultNotes: [25n],
    });
    await expect(both.relay).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_INSUFFICIENT_BALANCE",
    });
    expect(both.requests).toEqual([]);
    noProofs(both.fixture);
  });
});

const MINT = address("So11111111111111111111111111111111111111112");
const STRANGER = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
/** A keypair address, on the ed25519 curve. */
const DESTINATION = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
const TOKEN_ACCOUNT = await associatedTokenAddress(STRANGER, MINT, SPL_TOKEN_PROGRAM_ID);

function tokenAccount(
  owner: Address,
  others: Readonly<{
    mint?: Address;
    delegate?: Address;
    closeAuthority?: Address;
  }> = {},
): RpcAccount {
  const key = (value: Address | undefined) => (value === undefined ? none<Address>() : some(value));
  return {
    owner: SPL_TOKEN_PROGRAM_ID,
    lamports: 1n,
    data: new Uint8Array(
      getTokenEncoder().encode({
        mint: others.mint ?? MINT,
        owner,
        amount: 0n,
        delegate: key(others.delegate),
        state: AccountState.Initialized,
        isNative: none(),
        delegatedAmount: 0n,
        closeAuthority: key(others.closeAuthority),
      }),
    ),
  };
}

/** An SPL or SOL withdrawal of 4 out of a ring note, the destination's account as the chain holds it. */
async function anonymousWithdrawal(
  input: Readonly<{
    sender: Sender;
    destination: Address;
    spl: boolean;
    accounts?: ReadonlyMap<Address, RpcAccount>;
    exitTokenOwner?: Address;
  }>,
): Promise<Readonly<{ fixture: Fixture; proven: Promise<ProvenRingTransfer> }>> {
  const fixture = await anonymousRing();
  for (const [key, account] of input.accounts ?? []) fixture.accounts.set(key, account);
  const { sender, destination } = input;
  const transfer = spend(fixture, sender, input.spl ? { asset: MINT } : {});
  let withdrawal: TransactWithdrawal;
  if (input.spl) {
    const [splTokenInterface, splInterfaceBump] = await splInterfaceWithBump(MINT);
    transfer.withdraw(
      MINT,
      4n,
      WithdrawalTarget.spl({
        recipientTokenAccount: destination,
        splTokenInterface,
        splInterfaceBump,
      }),
    );
    withdrawal = TransactWithdrawal.spl({
      mint: MINT,
      splTokenInterface,
      recipientTokenAccount: destination,
      tokenProgram: SPL_TOKEN_PROGRAM_ID,
    });
  } else {
    transfer.withdraw(SOL_MINT, 4n, WithdrawalTarget.sol({ recipient: destination }));
    withdrawal = TransactWithdrawal.sol({ recipient: destination });
  }
  const anonymous = rail({ fixture, sender, transfer, withdrawal });
  return {
    fixture,
    proven: (input.exitTokenOwner === undefined
      ? anonymous
      : anonymous.withExitTokenOwner(input.exitTokenOwner)
    ).prove(fixture.client),
  };
}

/** The withdrawal destination the anonymous audit binds, the SPL token account's owner or the SOL recipient. */
function exitPartyOf(fixture: Fixture): Bytes32 {
  return itemAt(anonymousTransfer(fixture).request.partyIdentities, ANONYMOUS_PARTIES - 1);
}

function partyIdentity(party: Address): Bytes32 {
  return solanaOwnerIdentity(addressBytes(party)) as Bytes32;
}

describe("anonymous ring withdrawal destination", () => {
  const sender = anonymousSender();
  const hidden = sender.keypair.shieldedAddress().solanaAddress();

  it("refuses an SPL destination naming the hidden owner or a second key before proving", async () => {
    const associated = await associatedTokenAddress(hidden, MINT, SPL_TOKEN_PROGRAM_ID);
    const refusals: readonly (readonly [Address, RpcAccount | undefined, string])[] = [
      [TOKEN_ACCOUNT, tokenAccount(hidden), "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [hidden, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [associated, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [DESTINATION, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_ON_CURVE"],
      [
        TOKEN_ACCOUNT,
        tokenAccount(STRANGER, { delegate: STRANGER }),
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_SHARED",
      ],
      [
        TOKEN_ACCOUNT,
        tokenAccount(STRANGER, { closeAuthority: STRANGER }),
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_SHARED",
      ],
      [TOKEN_ACCOUNT, undefined, "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID"],
      [
        TOKEN_ACCOUNT,
        tokenAccount(STRANGER, { mint: STRANGER }),
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
    ];
    for (const [destination, account, code] of refusals) {
      const { fixture, proven } = await anonymousWithdrawal({
        sender,
        destination,
        spl: true,
        accounts: new Map(account === undefined ? [] : [[destination, account] as const]),
      });
      await expect(proven).rejects.toThrow(ringError(code, { destination }));
      noProofs(fixture);
    }
  });

  it("refuses a SOL recipient that is the hidden owner or holds data before proving", async () => {
    for (const [recipient, account, code] of [
      [hidden, undefined, "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [DESTINATION, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_ACCOUNT_HAS_DATA"],
      [
        DESTINATION,
        { owner: SYSTEM_PROGRAM, lamports: 1n, data: new Uint8Array(80) },
        "RING_ANONYMOUS_EXIT_ACCOUNT_HAS_DATA",
      ],
    ] as const) {
      const { fixture, proven } = await anonymousWithdrawal({
        sender,
        destination: recipient,
        spl: false,
        accounts: new Map(account === undefined ? [] : [[recipient, account] as const]),
      });
      await expect(proven).rejects.toThrow(ringError(code, { destination: recipient }));
      noProofs(fixture);
    }
  });

  it("binds the SPL token account owner or no owner for a SOL recipient", async () => {
    const spl = await anonymousWithdrawal({
      sender,
      destination: TOKEN_ACCOUNT,
      spl: true,
      accounts: new Map([[TOKEN_ACCOUNT, tokenAccount(STRANGER)]]),
    });
    await expanded(spl.fixture, await spl.proven, "anonymous");
    expect(exitPartyOf(spl.fixture)).toEqual(partyIdentity(STRANGER));
    const sol = await anonymousWithdrawal({
      sender,
      destination: DESTINATION,
      spl: false,
    });
    const { instruction, data } = await expanded(sol.fixture, await sol.proven, "anonymous");
    expect(exitPartyOf(sol.fixture)).toEqual(partyIdentity(DESTINATION));
    await checkAccounts(instruction, {
      fixture: sol.fixture,
      data,
      registries: [sol.fixture.ownRegistry],
      prefix: [],
      payer: sol.fixture.authority,
      settlement: [
        { address: SOL_INTERFACE, role: AccountRole.WRITABLE },
        { address: DESTINATION, role: AccountRole.WRITABLE },
      ],
    });
  });

  const minted = new Map([
    [MINT, { owner: SPL_TOKEN_PROGRAM_ID, lamports: 1n, data: new Uint8Array(82) }],
  ]);

  it("takes a destination the transaction creates as the named owner's associated token account", async () => {
    const { fixture, proven } = await anonymousWithdrawal({
      sender,
      destination: TOKEN_ACCOUNT,
      spl: true,
      accounts: minted,
      exitTokenOwner: STRANGER,
    });
    await expanded(fixture, await proven, "anonymous");
    expect(exitPartyOf(fixture)).toEqual(partyIdentity(STRANGER));
  });

  const splLeg = (destination: Address): SettlementTransfer => ({
    kind: "spl",
    mint: MINT,
    isDeposit: false,
    amount: 4n,
    tokenAccount: destination,
    splInterfaceBump: 255,
  });

  const exitOwner = (
    input: Readonly<{
      transfers: readonly SettlementTransfer[];
      accounts: ReadonlyMap<Address, RpcAccount>;
      tokenOwner?: Address;
    }>,
  ) =>
    anonymousExitTokenOwner({
      client: { getAccount: async (key) => input.accounts.get(key) },
      transfers: input.transfers,
      hiddenOwner: addressBytes(hidden) as Bytes32,
      ...(input.tokenOwner === undefined ? {} : { tokenOwner: input.tokenOwner }),
    });

  const tokenOwnerOf = (account: RpcAccount) =>
    exitOwner({
      transfers: [splLeg(TOKEN_ACCOUNT)],
      accounts: new Map([[TOKEN_ACCOUNT, account]]),
    });

  it("refuses a named owner the destination or the withdrawals contradict", async () => {
    const associated = await associatedTokenAddress(hidden, MINT, SPL_TOKEN_PROGRAM_ID);
    const refusals: readonly (readonly [Parameters<typeof exitOwner>[0], string])[] = [
      [
        { transfers: [splLeg(TOKEN_ACCOUNT)], accounts: minted },
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
      [
        {
          transfers: [splLeg(TOKEN_ACCOUNT)],
          accounts: minted,
          tokenOwner: DESTINATION,
        },
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
      [
        {
          transfers: [splLeg(TOKEN_ACCOUNT)],
          accounts: new Map(),
          tokenOwner: STRANGER,
        },
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
      [
        {
          transfers: [splLeg(associated)],
          accounts: minted,
          tokenOwner: hidden,
        },
        "RING_ANONYMOUS_EXIT_LINKS_OWNER",
      ],
      [
        {
          transfers: [splLeg(TOKEN_ACCOUNT)],
          accounts: new Map([[TOKEN_ACCOUNT, tokenAccount(STRANGER)]]),
          tokenOwner: DESTINATION,
        },
        "RING_ANONYMOUS_EXIT_NAMED_OWNER_MISMATCH",
      ],
      [
        {
          transfers: [
            {
              kind: "sol",
              isDeposit: false,
              amount: 4n,
              userSolAccount: DESTINATION,
            },
          ],
          accounts: new Map(),
          tokenOwner: STRANGER,
        },
        "RING_ANONYMOUS_EXIT_TOKEN_OWNER_MISMATCH",
      ],
    ];
    for (const [input, code] of refusals)
      await expect(exitOwner(input)).rejects.toMatchObject({ code });
  });

  it("names the destination, the named owner and the token owner of a mismatch", async () => {
    await expect(
      exitOwner({
        transfers: [splLeg(TOKEN_ACCOUNT)],
        accounts: new Map([[TOKEN_ACCOUNT, tokenAccount(STRANGER)]]),
        tokenOwner: DESTINATION,
      }),
    ).rejects.toThrow(
      ringError("RING_ANONYMOUS_EXIT_NAMED_OWNER_MISMATCH", {
        destination: TOKEN_ACCOUNT,
        named: DESTINATION,
        owner: STRANGER,
      }),
    );
  });

  it("refuses two SPL exits to different owners", async () => {
    const other = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
    const second = await associatedTokenAddress(other, MINT, SPL_TOKEN_PROGRAM_ID);
    await expect(
      exitOwner({
        transfers: [splLeg(TOKEN_ACCOUNT), splLeg(second)],
        accounts: new Map([
          [TOKEN_ACCOUNT, tokenAccount(STRANGER)],
          [second, tokenAccount(other)],
        ]),
      }),
    ).rejects.toMatchObject({
      code: "RING_ANONYMOUS_EXIT_DESTINATIONS_DIFFER",
    });
  });

  const token2022 = (
    tail: readonly number[],
    edit: (data: Uint8Array) => void = () => undefined,
  ): RpcAccount => {
    const base = tokenAccount(STRANGER);
    const data = Uint8Array.from([...base.data, ...tail]);
    edit(data);
    return { ...base, owner: SPL_TOKEN_2022_PROGRAM_ID, data };
  };

  it("reads a Token-2022 account with extensions as SPP unpacks it", async () => {
    // Account type `Account`, then an ImmutableOwner entry of type 7 and length 0.
    await expect(tokenOwnerOf(token2022([2, 7, 0, 0, 0]))).resolves.toBe(STRANGER);
  });

  it.each<readonly [string, RpcAccount, string]>([
    [
      "an extension tail that is not an account",
      token2022([1, 7, 0, 0, 0]),
      "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
    ],
    [
      "the multisig length",
      token2022([2, ...new Uint8Array(189)]),
      "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
    ],
    [
      "a frozen state",
      token2022([], (data) => (data[108] = AccountState.Frozen)),
      "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
    ],
    [
      "a delegate tag above one",
      token2022([], (data) => (data[72] = 2)),
      "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_SHARED",
    ],
  ])("refuses a token account with %s", async (_, account, code) => {
    await expect(tokenOwnerOf(account)).rejects.toThrow(
      ringError(code, { destination: TOKEN_ACCOUNT }),
    );
  });

  it("refuses a destination of another program than the token programs", async () => {
    await expect(
      tokenOwnerOf({ ...tokenAccount(STRANGER), owner: randomAddress() }),
    ).rejects.toThrow(
      ringError("RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID", {
        destination: TOKEN_ACCOUNT,
      }),
    );
  });
});

describe("anonymous rail on a policy ring", () => {
  const ZERO = new Uint8Array(32) as Bytes32;

  /** One rule over the sender's allow list and one SOL limit, the sender's record on the list. */
  function policyRing(
    sender: Sender,
    limit: Readonly<{ cap: bigint; cosignAbove: bigint }>,
    coSigner?: Address,
    coOwners: readonly ShieldedKeypair[] = [],
  ): Promise<Fixture> {
    return anonymousRing({
      table: buildRuleTable({
        rules: [
          {
            subject: "sender",
            source: { kind: "lists", present: [ListId.allow], absent: [] },
            guard: { kind: "always" },
          },
        ],
      }),
      records: [
        {
          member: memberOfAsset(SOL_MINT),
          lists: 0n,
          mintPolicy: { ...EMPTY_MINT_POLICY, ...limit },
        },
        {
          member: memberOfIdentity(
            sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash(),
          ),
          lists: 1n,
        },
        ...coOwners.map((coOwner) => ({
          member: memberOfIdentity(coOwner.signingPublicKey().ownerProofInputHash()),
          lists: 1n,
        })),
      ],
      ...(coSigner === undefined
        ? {}
        : {
            coSigner: {
              signer: coSigner,
              scope: RING_COSIGN_TRANSFERS | RING_COSIGN_APPROVE_OUTFLOW,
            },
          }),
    });
  }

  async function pay(fixture: Fixture, sender: Sender): Promise<ProvenRingTransfer> {
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    return rail({ fixture, sender, transfer: spend(fixture, sender) })
      .withPayment({
        to,
        asset: SOL_MINT,
        amount: 400n,
        reply: null,
      })
      .prove(fixture.client);
  }

  it("proves the policy over the hidden sender the frame and the statement bind", async () => {
    const sender = anonymousSender();
    const fixture = await policyRing(sender, { cap: 1_000n, cosignAbove: 0n });
    const proven = await pay(fixture, sender);
    const { instruction, data } = await expanded(fixture, proven, "anonymous");

    const senderPkHash = sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash();
    expect(data.approval).toBe(0);
    const policyAccount = fixture.accounts.get(await ringPolicyAddress(fixture.ringProgramId));
    if (policyAccount === undefined) throw new Error("no ring policy");
    const request = checkTransferProof(fixture, data);
    expect(request).toMatchObject({
      approvalMask: 0,
      hidden: true,
      policyHash: decodeRingPolicy(policyAccount.data).policyHash,
      ownRoot: fixture.ownTree.root,
      curatorRoot: ZERO,
      withdrawalHash: policyWithdrawalHash([]),
    });
    // The hidden sender is screened as the pool's first subject, never published.
    expect(screenedMembers(request, 1)).toEqual([senderPkHash]);
    await checkAccounts(instruction, {
      fixture,
      data,
      registries: [fixture.ownRegistry],
      prefix: [],
      payer: fixture.authority,
    });
  });

  it("refuses a hidden sender off the required list before any proof", async () => {
    const fixture = await policyRing(anonymousSender(), {
      cap: 1_000n,
      cosignAbove: 0n,
    });
    await expect(pay(fixture, anonymousSender())).rejects.toThrow(
      ringError("RING_POLICY_RULE_UNSATISFIED", {
        reason: "lists",
        ruleIndex: 0,
        subject: "sender",
      }),
    );
    noProofs(fixture);
  });

  it("takes the wide key for public owners past the narrow rows beside the hidden sender", async () => {
    const sender = anonymousSender();
    const coOwners = Array.from({ length: 4 }, () => ShieldedKeypair.generate());
    const fixture = await policyRing(sender, { cap: 0n, cosignAbove: 0n }, undefined, coOwners);
    const transfer = ringSpendTransfer({
      owner: sender.keypair.shieldedAddress(),
      inputs: [
        noteInput(sender.keypair, 5_000n, fixture.ringProgramId),
        ...coOwners.map((coOwner) => noteInput(coOwner, 5_000n, fixture.ringProgramId)),
      ],
      feePayer: fixture.authority,
    });
    transfer.withShape({ inputs: 8, outputs: 2 });
    for (const coOwner of coOwners) fixture.enroll(coOwner.shieldedAddress());
    const proven = await coOwners
      .reduce(
        (built, coOwner) =>
          built.withCoOwner({
            owner: coOwner.shieldedAddress().solanaAddress(),
            nullifierKey: coOwner.nullifierKey(),
          }),
        rail({ fixture, sender, transfer }),
      )
      .withPayment({
        to: await addressOf(fixture, ShieldedKeypair.generate()),
        asset: SOL_MINT,
        amount: 400n,
        reply: null,
      })
      .prove(fixture.client);
    const { data } = await expanded(fixture, proven, "anonymous");
    expect(data.wideOwners).toBe(true);
    const { request, circuit } = anonymousTransfer(fixture);
    expect(circuit).toBe("custom-ring-transfer-wide-8-in24-w32-s13");
    expect(request.rows.filter((row) => row.some((byte) => byte !== 0))).toHaveLength(5);
  });

  it("refuses an outflow past the cap before any proof", async () => {
    const sender = anonymousSender();
    const fixture = await policyRing(sender, { cap: 399n, cosignAbove: 0n });
    await expect(pay(fixture, sender)).rejects.toThrow(
      ringError("RING_OUTFLOW_CAP_EXCEEDED", { cap: "399", chargedOutflow: "400" }),
    );
    noProofs(fixture);
  });

  it("names and signs with the co-signer when the outflow passes the co-sign bound", async () => {
    const sender = anonymousSender();
    const coSigner = randomAddress();
    const fixture = await policyRing(sender, { cap: 0n, cosignAbove: 100n }, coSigner);
    const proven = await pay(fixture, sender);
    const { instruction, data } = await expanded(fixture, proven, "anonymous");

    expect(proven.coSigners).toEqual([coSigner]);
    expect(data.approval).toBe(ApprovalMask.outflow);
    expect(anonymousTransfer(fixture).request.approvalMask).toBe(ApprovalMask.outflow);
    await checkAccounts(instruction, {
      fixture,
      data,
      registries: [fixture.ownRegistry],
      prefix: [
        {
          address: await ringCoSignerAddress(fixture.ringProgramId, coSigner),
          role: AccountRole.READONLY,
        },
        { address: coSigner, role: AccountRole.READONLY_SIGNER },
      ],
      payer: fixture.authority,
    });
  });

  it("refuses an outflow past the co-sign bound on a ring without a co-signer", async () => {
    const sender = anonymousSender();
    const fixture = await policyRing(sender, { cap: 0n, cosignAbove: 100n });
    await expect(pay(fixture, sender)).rejects.toThrow(ringError("RING_COSIGNER_REQUIRED"));
    noProofs(fixture);
  });
});

describe("anonymous entry key bound", () => {
  /** A payment out of `count` default-ring notes of the sender. */
  async function entry(
    fixture: Fixture,
    sender: Sender,
    count: number,
  ): Promise<ProvenRingTransfer> {
    const transfer = new ConfidentialTransfer(
      sender.keypair.shieldedAddress(),
      Array.from({ length: count }, () => noteInput(sender.keypair, 1_000n)),
      fixture.authority,
    );
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    return rail({ fixture, sender, transfer })
      .withPayment({
        to,
        asset: SOL_MINT,
        amount: 400n,
        reply: null,
      })
      .prove(fixture.client);
  }

  it("spends eight default-ring notes under the entry key", async () => {
    const fixture = await anonymousRing();
    const proven = await entry(fixture, anonymousSender(), 8);
    const { data } = await expanded(fixture, proven, "anonymous");
    expect(data.entry).toBe(true);
    expect(data.nullifiers).toHaveLength(8);
    expect(anonymousTransfer(fixture).circuit).toBe("custom-ring-transfer-entry-4-in8-w4-s8");
  });

  it("refuses a default-ring note past the widest entry key before any proof", async () => {
    const fixture = await anonymousRing();
    await expect(entry(fixture, anonymousSender(), 25)).rejects.toThrow(
      ringError("RING_CATALOG_KEY_MISSING"),
    );
    noProofs(fixture);
  });
});

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
