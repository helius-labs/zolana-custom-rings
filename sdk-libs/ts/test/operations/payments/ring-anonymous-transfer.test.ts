import { EMPTY_MINT_POLICY } from "../../../src/protocol/membership/mint-policy.js";
import { policyWithdrawalHash } from "../../../src/proof/withdrawals.js";
import { AccountState, getTokenEncoder } from "@solana-program/token";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  AccountRole,
  address,
  getBase58Encoder,
  getBase64Encoder,
  none,
  some,
  type Address,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { WalletKeys, RpcAccount } from "@heliuslabs/zolana/client";
import {
  SYSTEM_PROGRAM,
  addressBytes,
  associatedTokenAddress,
  splInterfaceWithBump,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import {
  SOL_INTERFACE,
  SPL_TOKEN_2022_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  TransactWithdrawal,
  type Bytes32,
} from "@heliuslabs/zolana/interface";
import {
  randomBlinding,
  ShieldedAddress,
  ShieldedKeypair,
  SigningKey,
  X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
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
} from "@heliuslabs/zolana/transaction";
import {
  approveRingUnattended,
  type RingApprovalRequest,
} from "../../../src/protocol/transaction/intent.js";
import { ringProofCircuit } from "../../../src/rpc/prover/ring.js";
import { ringCoSignerAddress, ringPolicyAddress } from "../../../src/protocol/pda/index.js";
import { ringCircuitType } from "../../../src/protocol/proof/proving-keys.js";
import { RingAddress, RingPaymentRequest } from "../../../src/crypto/keys/ring-address.js";
import { ringIdField, senderCommitment } from "../../../src/crypto/derivation/ring-stream.js";
import {
  anonymousExitTokenOwner,
  checkAnonymousSlots,
  signingKeySpendSigner,
  type AnonymousSpendSigner,
} from "../../../src/operations/payments/anonymous.js";
import {
  RING_COSIGN_TRANSFERS,
  decodeRingPolicy,
} from "../../../src/protocol/codec/ring-codecs.js";
import {
  ListId,
  buildRuleTable,
  memberOfAsset,
  memberOfIdentity,
} from "../../../src/protocol/membership/policy.js";
import { policyStatementHash } from "../../../src/protocol/proof/statement.js";
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
  prepareRingTransferRelay,
  prepareRingWithdrawalRelay,
} from "../../../src/operations/payments/transfer.js";
import type { PreparedRingRelay } from "../../../src/operations/payments/transfer-rails.js";
import { decodeRelayProofInputs } from "../../../src/protocol/ring-rpc/relay-proof-inputs.js";
import type { PrepareRelayRequest } from "../../../src/protocol/ring-rpc/ring-rpc-types.js";
import { relayId, submittedRelay, type RingRelayClient } from "../../../src/rpc/relay.js";
import { RingTransactData } from "../../../src/protocol/transaction/transact.js";

import { BLOCKHASH } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";

import {
  TREE,
  TREE_ID,
  checkAccounts,
  checkAudit,
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
import { publicAmountFields, publicSlots } from "../../../src/protocol/transaction/spp.js";
import { type RingKeys } from "../../../src/state/ring-keys.js";
import {
  TransferTagging,
  ViewingHistory,
  type FirstContact,
} from "../../../src/state/viewing-history.js";
import {
  DUMMY_RECIPIENT_VIEWING_PK,
  RECIPIENT_BODY_LEN,
  openRecipient,
} from "../../../src/protocol/codec/anonymous-body.js";
import {
  decodeAnonymousRecipient,
  decodeAnonymousSender,
} from "../../../src/protocol/codec/anonymous-plaintext.js";

await initializePoseidon();

const assets = new AssetRegistry();
const BOOTSTRAP: FirstContact = { kind: "bootstrap" };

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
  options: Readonly<{ ring?: Address | "default"; payer?: Address; asset?: Address }> = {},
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
    history?: ViewingHistory;
    keys?: WalletKeys;
    signer?: AnonymousSpendSigner;
    withdrawal?: TransactWithdrawal;
  }>,
): AnonymousTransfer {
  const { fixture, sender } = input;
  const owner = CustomRingTransfer.new({
    ringProgramId: fixture.ringProgramId,
    keys: input.keys ?? walletKeys(sender.keypair),
    transfer: input.transfer,
    assets,
    ...(fixture.coSigner === undefined ? {} : { coSigner: fixture.coSigner }),
  });
  return (
    input.withdrawal === undefined ? owner : owner.withWithdrawalAccounts(input.withdrawal)
  ).withAnonymousSigner(
    input.signer ?? signingKeySpendSigner(sender.signing),
    input.history ?? historyOf(sender.keypair),
  );
}

/** A wallet whose one viewing key never paid or was paid. */
function historyOf(keypair: ShieldedKeypair): ViewingHistory {
  return ViewingHistory.create(keypair.shieldedAddress().viewingPublicKey, 0n);
}

async function addressOf(fixture: Fixture, owner: ShieldedKeypair): Promise<RingAddress> {
  return new RingAddress({
    recipient: owner.shieldedAddress(),
    ringProgramId: fixture.ringProgramId,
  });
}

/** The anonymous audit request, its circuit the key the program verifies under. */
function anonymousAudit(fixture: Fixture) {
  const audit = fixture.ringRequests.find((request) => request.kind === "anonymousAudit");
  if (audit?.kind !== "anonymousAudit") throw new Error("no anonymous audit request");
  return { audit, circuit: ringCircuitType(ringProofCircuit(audit)) };
}

function noProofs(fixture: Fixture): void {
  expect(fixture.ringRequests).toHaveLength(0);
  expect(fixture.sppCalls).toHaveLength(0);
}

/** `ciphertext` opened by `reader` under `slotIndex` with the transaction key the frame publishes. */
function opened(
  reader: ShieldedKeypair,
  data: RingTransactData,
  call: Fixture["sppCalls"][number],
  ciphertext: Uint8Array,
  slotIndex: number,
): Uint8Array {
  const viewing = reader.viewingKey();
  try {
    return viewing.decryptUtxo(
      ciphertext,
      X25519PublicKey.fromBytes(call.data.txViewingPk),
      data.salt,
      slotIndex,
    );
  } finally {
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
  if (output?.kind !== "anonymous" || output.body === undefined)
    throw new Error("no recipient body");
  return decodeAnonymousRecipient(opened(reader, data, call, output.body, slotIndex));
}

/** The sender bundle, sealed to the sender after every output. */
function openedBundle(
  sender: ShieldedKeypair,
  data: RingTransactData,
  call: Fixture["sppCalls"][number],
) {
  if (data.sender === undefined) throw new Error("no sender bundle");
  return decodeAnonymousSender(opened(sender, data, call, data.sender.body, data.outputs.length));
}

describe("anonymous ring payment", () => {
  it("tags the change under the sender tag and a first payment under the bootstrap tag, the recipient opens its body and the auditor every hash", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender) })
      .withPayment({ to, firstContact: BOOTSTRAP, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { instruction, data, call } = await expanded(fixture, proven, "anonymous");

    expect(call.circuit.kind).toBe("ringAnonymous");
    expect(data.outputs.map((output) => output.kind)).toEqual(["anonymous", "anonymous"]);
    expect([data.fullOpenings, data.keyEscrow]).toEqual([false, false]);
    const [change, payment] = data.outputs;
    if (change?.kind !== "anonymous" || payment?.kind !== "anonymous")
      throw new Error("no anonymous slots");
    const viewing = sender.keypair.viewingKey();
    expect(change.tag).toEqual(viewing.senderViewTag(0n));
    viewing.destroy();
    expect(change.body).toBeUndefined();
    expect(data.sender?.tag).toEqual(change.tag);
    expect(payment.tag).toEqual(bob.shieldedAddress().viewingPublicKey.u());
    expect(payment.body).toBeDefined();
    await checkAccounts(instruction, { fixture, data, prefix: [], payer: fixture.authority });
    checkAudit(fixture, data, { kind: "anonymousAudit" });
    checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    checkRingBlindings(call, data);
    const { audit, circuit } = anonymousAudit(fixture);
    expect(circuit).toBe("custom-ring-audit-anonymous-v2-4-2");
    expect([audit.inputCount, audit.inputs.length]).toEqual([1, 4]);
    expect(audit.outputs.map((slot) => slot.ownerKey)).toEqual([
      sender.keypair.shieldedAddress().signingPublicKey.confidentialViewTag(),
      bob.shieldedAddress().signingPublicKey.confidentialViewTag(),
    ]);
    const body = openedBody(bob, data, call, 1);
    expect(
      body.unverified.senderPublicKey.equals(sender.keypair.shieldedAddress().viewingPublicKey),
    ).toBe(true);
    expect(body.verified.mint).toBe(SOL_MINT);
    const note = openRecipient(
      {
        owner: bob.shieldedAddress(),
        assets,
        ring: fixture.ringProgramId,
        treeId: TREE_ID,
        utxoHash: payment.hash,
      },
      body,
    );
    expect(note?.amount).toBe(400n);
    const bundle = openedBundle(sender.keypair, data, call);
    expect([bundle.verified.splAmount, bundle.verified.solAmount]).toEqual([0n, 9_600n]);
    expect(bundle.verified.recipientViewingPublicKeys).toEqual([
      bob.shieldedAddress().viewingPublicKey,
    ]);
    const history = proven.viewingHistory?.current();
    expect(history?.txCount).toBe(1n);
    expect(
      history?.counter({
        kind: "toRecipient",
        counterparty: bob.shieldedAddress().viewingPublicKey,
      })?.next,
    ).toBe(0n);
  });

  it("takes a request tag on a first payment and a shared tag once the pair is known", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const request = bob.viewingKey().recipientRequestViewTag(3n);
    const first = await rail({ fixture, sender, transfer: spend(fixture, sender) })
      .withPayment({
        to,
        firstContact: { kind: "request", tag: request },
        asset: SOL_MINT,
        amount: 400n,
      })
      .prove(fixture.client);
    const firstData = (await expanded(fixture, first, "anonymous")).data;
    expect(firstData.outputs[1]?.kind === "anonymous" && firstData.outputs[1].tag).toEqual(request);
    const paired = first.viewingHistory;
    if (paired === undefined) throw new Error("no viewing history");
    const second = await rail({
      fixture,
      sender,
      transfer: spend(fixture, sender),
      history: paired,
    })
      .withPayment({
        to,
        firstContact: { kind: "request", tag: request },
        asset: SOL_MINT,
        amount: 400n,
      })
      .prove(fixture.client);
    const { data } = await expanded(fixture, second, "anonymous");
    const viewing = sender.keypair.viewingKey();
    const bobKey = bob.shieldedAddress().viewingPublicKey;
    expect(data.outputs[0]?.kind === "anonymous" && data.outputs[0].tag).toEqual(
      viewing.senderViewTag(1n),
    );
    expect(data.outputs[1]?.kind === "anonymous" && data.outputs[1].tag).toEqual(
      viewing.sendSharedViewTags(bobKey).tag(0n),
    );
    viewing.destroy();
    expect(
      second.viewingHistory?.current().counter({ kind: "toRecipient", counterparty: bobKey })?.next,
    ).toBe(1n);
  });

  it("takes the same tags on every attempt from the stored history", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const transfer = rail({ fixture, sender, transfer: spend(fixture, sender) }).withPayment({
      to,
      firstContact: BOOTSTRAP,
      asset: SOL_MINT,
      amount: 400n,
    });
    const tags = async () => {
      const { data } = await expanded(fixture, await transfer.prove(fixture.client), "anonymous");
      return data.outputs.map((output) => (output.kind === "anonymous" ? hex(output.tag) : ""));
    };
    expect(await tags()).toEqual(await tags());
    expect((await transfer.viewingHistory()).toJson()).toBe(
      (
        await new TransferTagging({
          keys: walletKeys(sender.keypair),
          history: historyOf(sender.keypair),
          recipients: [
            { viewingPublicKey: to.recipient.viewingPublicKey, firstContact: BOOTSTRAP },
          ],
        }).plan()
      ).history.toJson(),
    );
  });

  it("leads with a zero SOL change when nothing returns to the sender", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender) })
      .withPayment({ to, firstContact: BOOTSTRAP, asset: SOL_MINT, amount: 10_000n })
      .prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");
    expect(data.outputs[0]).toMatchObject({ kind: "anonymous" });
    expect(data.outputs[0]).not.toHaveProperty("body");
    const zero = itemAt(call.proofInputs.outputs, 0);
    expect([
      zero.amount,
      zero.asset,
      hex(zero.ownerAddress?.toBytes() ?? new Uint8Array()),
    ]).toEqual([0n, SOL_MINT, hex(sender.keypair.shieldedAddress().toBytes())]);
    const bundle = openedBundle(sender.keypair, data, call);
    expect([bundle.verified.splAmount, bundle.verified.solAmount]).toEqual([0n, 0n]);
    checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
  });

  it("lists every output after the change in the sender bundle, an exit and a dummy under the zero key", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const outside = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const transfer = spend(fixture, sender);
    const paying = rail({ fixture, sender, transfer }).withPayment({
      to,
      firstContact: BOOTSTRAP,
      asset: SOL_MINT,
      amount: 400n,
    });
    transfer.sendDefaultRing(outside.shieldedAddress(), SOL_MINT, 300n);
    const { data, call } = await expanded(fixture, await paying.prove(fixture.client), "anonymous");

    expect(data.outputs.map((output) => output.kind)).toEqual([
      "anonymous",
      "anonymous",
      "exit",
      "anonymous",
    ]);
    expect(openedBundle(sender.keypair, data, call).verified.recipientViewingPublicKeys).toEqual([
      bob.shieldedAddress().viewingPublicKey,
      DUMMY_RECIPIENT_VIEWING_PK,
      DUMMY_RECIPIENT_VIEWING_PK,
    ]);
    const dummy = data.outputs[3];
    if (dummy?.kind !== "anonymous") throw new Error("no dummy slot");
    expect([dummy.tag[0], dummy.body?.length]).toEqual([0, RECIPIENT_BODY_LEN]);
    checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
  });

  it("refuses a recipient key no agreement accepts and a history of another key before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate().shieldedAddress();
    const lowOrder = new RingAddress({
      recipient: ShieldedAddress.fromPublicKeys(
        bob.signingPublicKey,
        bob.nullifierPublicKey,
        DUMMY_RECIPIENT_VIEWING_PK,
      ),
      ringProgramId: fixture.ringProgramId,
    });
    await expect(
      rail({ fixture, sender, transfer: spend(fixture, sender) })
        .withPayment({ to: lowOrder, firstContact: BOOTSTRAP, asset: SOL_MINT, amount: 400n })
        .prove(fixture.client),
    ).rejects.toThrow(ringError("RING_RECIPIENT_KEY_NOT_CONTRIBUTORY"));
    await expect(
      rail({
        fixture,
        sender,
        transfer: spend(fixture, sender),
        history: historyOf(ShieldedKeypair.generate()),
      }).prove(fixture.client),
    ).rejects.toThrow(ringError("RING_VIEWING_KEY_NOT_CURRENT"));
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
      viewTags: (requests) => track("viewTags", local.viewTags(requests)),
      sharedViewTags: (requests) => track("sharedViewTags", local.sharedViewTags(requests)),
      prove: (inputs, context) => track("prove", local.prove(inputs, context)),
      proveMerge: (inputs, context) => track("proveMerge", local.proveMerge(inputs, context)),
    };
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender), keys: remote })
      .withPayment({ to, firstContact: BOOTSTRAP, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    expect(call.authority).toBe(remote);
    expect([...called].sort()).toEqual(["address", "transactionKeys", "viewTags"]);
  });
});

describe("anonymous ring exits and entries", () => {
  it("exits a note to the default ring under scheme 3 with SeedOut in the disclosure", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const outside = ShieldedKeypair.generate();
    const transfer = spend(fixture, sender);
    transfer.sendDefaultRing(outside.shieldedAddress(), SOL_MINT, 300n);
    const proven = await rail({ fixture, sender, transfer }).prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    expect(data.outputs.map((output) => output.kind)).toEqual(["anonymous", "exit"]);
    checkAudit(fixture, data, { kind: "anonymousAudit" });
    const disclosure = checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    expect(disclosure.seedOut).toEqual(call.proofInputs.outputBlindingSeed());
    const exit = data.outputs[1];
    if (exit?.kind !== "exit") throw new Error("no exit slot");
    const viewing = outside.viewingKey();
    const opened = decodeConfidential(
      viewing.decryptUtxo(
        exit.payload.subarray(33),
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
      .withPayment({ to, firstContact: BOOTSTRAP, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    expect(data.fullOpenings).toBe(true);
    // Input byte bit 7 names the entry key.
    expect((RingTransactData.encode(data)[2] ?? 0) & 0x80).toBe(0x80);
    checkAudit(fixture, data, { kind: "anonymousAudit" });
    const disclosure = checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    expect(disclosure.kind === "anonymous" && disclosure.inputs.kind).toBe("openings");
    const { audit, circuit } = anonymousAudit(fixture);
    expect(circuit).toBe("custom-ring-audit-anonymous-entry-v2-8-2");
    expect([audit.layout.fullOpenings, audit.inputs.length]).toEqual([true, 8]);
  });

  it("counts an entry's default owner tag, its setup instructions and fee before approval and any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    await checkFrameCounted(fixture, {
      payer: fixture.authority,
      prove: (approval) =>
        rail({ fixture, sender, transfer: spend(fixture, sender, { ring: "default" }) })
          .withPayment({ to, firstContact: BOOTSTRAP, asset: SOL_MINT, amount: 400n })
          .proveApproved(fixture.client, approval),
    });
  });

  it("refuses an entry input that carries data before any proof", async () => {
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
    await expect(rail({ fixture, sender, transfer }).prove(fixture.client)).rejects.toThrow(
      ringError("RING_ENTRY_INPUT_DATA", { index: 0 }),
    );
    noProofs(fixture);
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

  it("refuses a note of another owner than the sender before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const other = ShieldedKeypair.generate();
    const transfer = new ConfidentialTransfer(
      other.shieldedAddress(),
      [noteInput(other, 10_000n, fixture.ringProgramId)],
      fixture.authority,
    );
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    await expect(
      rail({ fixture, sender, transfer })
        .withPayment({ to, firstContact: BOOTSTRAP, asset: SOL_MINT, amount: 10_000n })
        .prove(fixture.client),
    ).rejects.toThrow(ringError("RING_MIXED_OWNERS", { index: 0 }));
    noProofs(fixture);
  });

  it("refuses an address slot among anonymous inputs like Rust `check_anonymous_slots`", () => {
    const owner = ShieldedKeypair.generate();
    const reserved = ProofInputUtxo.address(owner.signingPublicKey(), small(7));
    const proofInputs = { inputUtxos: [reserved], outputs: [] } as unknown as SppProofInputs;
    expect(() => checkAnonymousSlots(proofInputs)).toThrow(
      ringError("RING_ANONYMOUS_SLOT_INVALID"),
    );
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

  it("refuses a second SOL change, the sender bundle carries one per asset kind", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const transfer = spend(fixture, sender);
    transfer.send(sender.keypair.shieldedAddress(), SOL_MINT, 100n);
    await expect(rail({ fixture, sender, transfer }).prove(fixture.client)).rejects.toThrow(
      ringError("RING_ANONYMOUS_CHANGE_COUNT"),
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
  it("refuses another signer, a hidden owner that signs in public, a partial key holder and another ring", async () => {
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
      rail({ fixture: ring, sender, transfer: spend(ring, sender, { payer: hidden }) }).prove(
        ring.client,
      ),
      "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
    );
    const coSigned = await anonymousRing({
      coSigner: { signer: hidden, scope: RING_COSIGN_TRANSFERS },
    });
    await refused(
      coSigned,
      rail({ fixture: coSigned, sender, transfer: spend(coSigned, sender) }).prove(coSigned.client),
      "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
    );
    const local = walletKeys(sender.keypair);
    const partial: WalletKeys = {
      address: () => local.address(),
      viewingPublicKeys: () => local.viewingPublicKeys(),
      decrypt: (requests) => local.decrypt(requests),
      derive: (requests) => local.derive(requests),
      transactionKeys: (requests) => local.transactionKeys(requests),
      prove: (inputs, context) => local.prove(inputs, context),
      proveMerge: (inputs, context) => local.proveMerge(inputs, context),
    };
    await refused(
      ring,
      rail({ fixture: ring, sender, transfer: spend(ring, sender), keys: partial }).prove(
        ring.client,
      ),
      "RING_KEYS_REQUIRED",
    );
    const confidential = await ringFixture();
    await refused(
      confidential,
      rail({ fixture: confidential, sender, transfer: spend(confidential, sender) }).prove(
        confidential.client,
      ),
      "RING_NOT_ANONYMOUS",
    );
    const other = await anonymousRing();
    const foreign = await addressOf(other, ShieldedKeypair.generate());
    expect(() =>
      rail({ fixture: ring, sender, transfer: spend(ring, sender) }).withPayment({
        to: foreign,
        firstContact: BOOTSTRAP,
        asset: SOL_MINT,
        amount: 1n,
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
                  source: { kind: "lists", present: [ListId.allow], absent: [] },
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
    const notes: readonly Readonly<{ amount: bigint; ring?: Address; dataHash?: Bytes32 }>[] = [
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
        history: historyOf(sender.keypair),
        firstContact: BOOTSTRAP,
      },
    };
    const relay =
      input.withdraw === true
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
    if (relay.relay.request.intent.operation !== "anonymous")
      throw new Error("no anonymous intent");
    return decodeRelayProofInputs(
      new Uint8Array(getBase64Encoder().encode(relay.relay.request.intent.proofInputs)),
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
    const relayIdSent = submittedRelay(await prepared.relay.send(stub.relay));

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

  it("refuses every plain build on an anonymous ring before approval and names its relay", async () => {
    const { fixture, requests, params, relay } = await anonymousSpend({
      notes: 1,
      amount: 5n,
      defaultNotes: [10n],
    });
    await relay;
    const approvals = requests.length;
    const { anonymous: _, ...plain } = params;
    const built = { ...plain, feePayer: fixture.authority };
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const refusals = [
      [
        () => buildRingTransferTransaction({ ...built, recipient }),
        "RING_BUILD_TRANSFER",
        "prepareRingTransferRelay",
      ],
      [
        () =>
          buildRingExitTransaction({
            ...built,
            recipient: ShieldedKeypair.generate().shieldedAddress(),
          }),
        "RING_BUILD_TRANSFER",
        "prepareRingExitRelay",
      ],
      [() => buildRingEntryTransaction(built), "RING_BUILD_ENTRY", "prepareRingEntryRelay"],
      [
        () => buildRingWithdrawalTransaction({ ...built, recipient: randomAddress() }),
        "RING_BUILD_WITHDRAWAL",
        "prepareRingWithdrawalRelay",
      ],
    ] as const;
    for (const [build, code, use] of refusals)
      await expect(build()).rejects.toMatchObject({
        code,
        causeCode: "RING_ANONYMOUS_RELAY_REQUIRED",
        cause: { details: { ringProgramId: fixture.ringProgramId, use } },
      });
    expect(requests).toHaveLength(approvals);
    noProofs(fixture);
  });

  it("takes the next tags on a second relay prepared from the stored history", async () => {
    const { fixture, params, sender, relay } = await anonymousSpend({ notes: 3, amount: 5n });
    await relay;
    const bob = ShieldedKeypair.generate();
    const bobKey = bob.shieldedAddress().viewingPublicKey;
    const to = await addressOf(fixture, bob);
    const first = await prepareRingTransferRelay({ ...params, recipient: to });
    const second = await prepareRingTransferRelay({
      ...params,
      recipient: to,
      anonymous: { ...params.anonymous, history: first.viewingHistory },
    });
    const viewing = sender.keypair.viewingKey();
    expect((await publishedTags(first)).slice(0, 2)).toEqual([
      hex(viewing.senderViewTag(0n)),
      hex(bobKey.u()),
    ]);
    expect((await publishedTags(second)).slice(0, 2)).toEqual([
      hex(viewing.senderViewTag(1n)),
      hex(viewing.sendSharedViewTags(bobKey).tag(0n)),
    ]);
    viewing.destroy();
    expect(second.viewingHistory.current().txCount).toBe(2n);
  });

  it("pays a request under its tag and refuses one the payment contradicts before approval", async () => {
    const { fixture, params, requests, relay } = await anonymousSpend({ notes: 4, amount: 5n });
    await relay;
    const bob = ShieldedKeypair.generate();
    const bobViewing = bob.viewingKey();
    const requestViewTag = bobViewing.recipientRequestViewTag(0n);
    bobViewing.destroy();
    const request = new RingPaymentRequest({
      address: await addressOf(fixture, bob),
      requestViewTag,
      amount: 5n,
      mint: SOL_MINT,
    });
    const { firstContact: _, ...anonymous } = params.anonymous;
    const paid = await prepareRingTransferRelay({ ...params, anonymous, recipient: request });
    expect((await publishedTags(paid))[1]).toBe(hex(requestViewTag));
    const approvals = requests.length;
    const contradicted = [
      [{ amount: 4n }, "amount"],
      [{ asset: randomAddress() }, "asset"],
      [{ anonymous: params.anonymous }, "firstContact"],
    ] as const;
    for (const [change, field] of contradicted)
      await expect(
        prepareRingTransferRelay({ ...params, anonymous, recipient: request, ...change }),
      ).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_INTENT_MISMATCH",
        cause: { details: { field } },
      });
    expect(requests).toHaveLength(approvals);
  });

  it("spends the widest commitment class and refuses a payment past it before approval", async () => {
    const widest = await anonymousSpend({ notes: 16, amount: 155n });
    expect((await payload(await widest.relay)).inputs).toHaveLength(16);
    expect(widest.requests).toHaveLength(1);
    const wider = await anonymousSpend({ notes: 17, amount: 165n });
    await expect(wider.relay).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { maximum: 16 } },
    });
    expect(wider.requests).toEqual([]);
    noProofs(wider.fixture);
  });

  it("relays a policy withdrawal of the widest class", async () => {
    const wide = await anonymousSpend({ notes: 16, amount: 155n, policy: true, withdraw: true });
    const sent = await payload(await wide.relay);
    expect([sent.inputs.length, sent.withdrawals.length]).toEqual([16, 1]);
    expect(wide.requests).toHaveLength(1);
  });

  it("spends the entry key's input class of default-ring notes and refuses one more", async () => {
    const entry = await anonymousSpend({ notes: 8, amount: 75n, ring: "default", policy: true });
    expect((await payload(await entry.relay)).inputs).toHaveLength(8);
    expect(entry.requests).toHaveLength(1);
    const wider = await anonymousSpend({ notes: 9, amount: 85n, ring: "default" });
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
    const ringAlone = await anonymousSpend({ notes: 3, amount: 25n, defaultNotes: [100n] });
    await ringAlone.relay;
    expect(ringAlone.requests[0]?.intent).toMatchObject({ defaultFunding: 0n });
    const defaultAlone = await anonymousSpend({ notes: 3, amount: 40n, defaultNotes: [100n] });
    await defaultAlone.relay;
    expect(defaultAlone.requests[0]?.intent).toMatchObject({ defaultFunding: 100n });
    const both = await anonymousSpend({ notes: 3, amount: 50n, defaultNotes: [25n] });
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
  others: Readonly<{ mint?: Address; delegate?: Address; closeAuthority?: Address }> = {},
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

function exitTokenOwnerOf(fixture: Fixture): Address | undefined {
  const call = itemAt(fixture.sppCalls, 0);
  return call.exitTokenOwner;
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
    expect(exitTokenOwnerOf(spl.fixture)).toBe(STRANGER);
    const sol = await anonymousWithdrawal({ sender, destination: DESTINATION, spl: false });
    const { instruction, data } = await expanded(sol.fixture, await sol.proven, "anonymous");
    expect(exitTokenOwnerOf(sol.fixture)).toBeUndefined();
    await checkAccounts(instruction, {
      fixture: sol.fixture,
      data,
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
    expect(exitTokenOwnerOf(fixture)).toBe(STRANGER);
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
        { transfers: [splLeg(TOKEN_ACCOUNT)], accounts: minted, tokenOwner: DESTINATION },
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
      [
        { transfers: [splLeg(TOKEN_ACCOUNT)], accounts: new Map(), tokenOwner: STRANGER },
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
      [
        { transfers: [splLeg(associated)], accounts: minted, tokenOwner: hidden },
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
          transfers: [{ kind: "sol", isDeposit: false, amount: 4n, userSolAccount: DESTINATION }],
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
    ).rejects.toMatchObject({ code: "RING_ANONYMOUS_EXIT_DESTINATIONS_DIFFER" });
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
      ringError("RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID", { destination: TOKEN_ACCOUNT }),
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
      ],
      ...(coSigner === undefined
        ? {}
        : { coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS } }),
    });
  }

  async function pay(fixture: Fixture, sender: Sender): Promise<ProvenRingTransfer> {
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    return rail({ fixture, sender, transfer: spend(fixture, sender) })
      .withPayment({ to, firstContact: BOOTSTRAP, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
  }

  function memberPolicy(fixture: Fixture) {
    const policy = fixture.ringRequests.find((request) => request.kind === "memberPolicy");
    if (policy?.kind !== "memberPolicy") throw new Error("no member policy request");
    return policy;
  }

  it("proves the policy over the hidden sender's commitment the frame and both statements bind", async () => {
    const sender = anonymousSender();
    const fixture = await policyRing(sender, { cap: 1_000n, cosignAbove: 0n });
    const proven = await pay(fixture, sender);
    const { instruction, data, call } = await expanded(fixture, proven, "anonymous");

    const senderPkHash = sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash();
    const commitment = senderCommitment({
      senderPkHash,
      privateTxBlinding: call.proofInputs.privateTxBlinding(),
    });
    expect(data.policy?.senderCommitment).toEqual(commitment);
    expect(data.approvalRequired).toBe(false);
    const policy = memberPolicy(fixture);
    expect(policy).toMatchObject({ anonymous: true, sender: commitment, senderPkHash });
    const senderRecord = policy.ownPool.subjects[policy.senderEntry.own]?.recordIndex;
    expect(policy.ownPool.records[senderRecord ?? -1]?.member).toEqual(senderPkHash);
    const policyAccount = fixture.accounts.get(await ringPolicyAddress(fixture.ringProgramId));
    if (policyAccount === undefined) throw new Error("no ring policy");
    const slots = publicSlots(call.proofInputs.externalData.interfaceTransfers);
    expect(policy.publicInputHash).toEqual(
      policyStatementHash({
        withdrawalHash: policyWithdrawalHash([]),
        key: { kind: "member", anonymous: true },
        privateTxHash: data.privateTxHash,
        policyHash: decodeRingPolicy(policyAccount.data).policyHash,
        ringId: ringIdField(fixture.ringProgramId),
        approvalRequired: false,
        keyEscrow: false,
        ownRoot: fixture.ownTree.root,
        curatorRoot: ZERO,
        sender: commitment,
        recipients: data.outputs.map(() => new Uint8Array(32) as Bytes32),
        publicAssets: slots.assets,
        publicAmounts: publicAmountFields(slots),
      }),
    );
    checkAudit(fixture, data, { kind: "anonymousAudit" });
    expect(anonymousAudit(fixture).audit.senderCommitment).toEqual(commitment);
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [],
      payer: fixture.authority,
    });
  });

  it("refuses a hidden sender off the required list before any proof", async () => {
    const fixture = await policyRing(anonymousSender(), { cap: 1_000n, cosignAbove: 0n });
    await expect(pay(fixture, anonymousSender())).rejects.toThrow(
      ringError("RING_POLICY_RULE_UNSATISFIED", {
        reason: "lists",
        ruleIndex: 0,
        subject: "sender",
      }),
    );
    noProofs(fixture);
  });

  it("refuses an outflow past the cap before any proof", async () => {
    const sender = anonymousSender();
    const fixture = await policyRing(sender, { cap: 399n, cosignAbove: 0n });
    await expect(pay(fixture, sender)).rejects.toThrow(
      ringError("RING_OUTFLOW_CAP_EXCEEDED", { cap: "399", outflow: "400" }),
    );
    noProofs(fixture);
  });

  it("names and signs with the co-signer when the outflow passes the co-sign bound", async () => {
    const sender = anonymousSender();
    const coSigner = randomAddress();
    const fixture = await policyRing(sender, { cap: 0n, cosignAbove: 100n }, coSigner);
    const proven = await pay(fixture, sender);
    const { instruction, data } = await expanded(fixture, proven, "anonymous");

    expect(proven.approvalRequired).toBe(true);
    expect(proven.coSigner).toBe(coSigner);
    expect(data.approvalRequired).toBe(true);
    expect(memberPolicy(fixture).approvalRequired).toBe(true);
    await checkAccounts(instruction, {
      fixture,
      data,
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
      .withPayment({ to, firstContact: BOOTSTRAP, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
  }

  it("spends eight default-ring notes under the entry key", async () => {
    const fixture = await anonymousRing();
    const proven = await entry(fixture, anonymousSender(), 8);
    const { data } = await expanded(fixture, proven, "anonymous");
    expect(data.fullOpenings).toBe(true);
    expect(data.nullifiers).toHaveLength(8);
    expect(anonymousAudit(fixture).circuit).toBe("custom-ring-audit-anonymous-entry-v2-8-2");
  });

  it("refuses a ninth default-ring note before any proof", async () => {
    const fixture = await anonymousRing();
    await expect(entry(fixture, anonymousSender(), 9)).rejects.toThrow(
      ringError("RING_TRANSACT_DATA_INVALID", { reason: "RingShapeUnkeyed" }),
    );
    noProofs(fixture);
  });
});

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
