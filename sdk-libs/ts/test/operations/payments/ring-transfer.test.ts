import { withConfirmedReads } from "../../helpers/clients.js";
import { EMPTY_MINT_POLICY } from "../../../src/protocol/membership/mint-policy.js";
import { publicListKey } from "../../../src/protocol/membership/private-list.js";
import { policyWithdrawalHash } from "../../../src/proof/withdrawals.js";
import {
  AccountRole,
  generateKeyPairSigner,
  signTransactionWithSigners,
  type Address,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import {
  SOL_INTERFACE,
  TransactWithdrawal,
  type Bytes32,
  TRANSACTION_SIZE_LIMIT,
  transactionSize,
} from "@heliuslabs/spr/interface";
import {
  randomBlinding,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/spr/keypair";
import {
  AssetRegistry,
  SOL_MINT,
  ConfidentialTransfer,
  WithdrawalTarget,
  assetField,
  createProofOutput,
  decodeConfidential,
  Utxo,
  Wallet,
  type PreparedTransfer,
  type SppProofInputs,
} from "@heliuslabs/spr/transaction";
import {
  approveRingUnattended,
  type RingApprovalRequest,
} from "../../../src/protocol/transaction/intent.js";
import { ringCoSignerAddress, ringPolicyAddress } from "../../../src/protocol/pda/index.js";
import {
  RING_COSIGN_APPROVE_OUTFLOW,
  RING_COSIGN_APPROVE_WITHDRAWAL,
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_TRANSFERS,
  decodeRingPolicy,
} from "../../../src/protocol/codec/ring-codecs.js";
import { readMemberRecords } from "../../../src/rpc/registered-record.js";
import { sealAudit } from "../../../src/proof/audit-proof.js";
import { transferOutflows } from "../../../src/proof/policy-proof.js";
import { ApprovalMask, ringStreamLayout } from "../../../src/protocol/transaction/transact.js";
import type { ProvenRingTransfer } from "../../../src/operations/workflow/pipeline.js";
import {
  ListId,
  buildRuleTable,
  memberOfAsset,
  memberOfIdentity,
  publicMember,
  recordBit,
  type RuleTable,
} from "../../../src/protocol/membership/policy.js";
import { buildRingDelegateTransferTransaction } from "../../../src/operations/management/delegate.js";
import { buildRingTransferTransaction } from "../../../src/operations/payments/transfer.js";
import { RingProgramError, createRingTransferSubmission } from "../../../src/index.js";
import { signingKeySpendSigner } from "../../../src/operations/payments/anonymous.js";
import { RingOutputRail } from "../../../src/operations/payments/output-rail.js";
import {
  CustomRingTransfer,
  DelegateTransfer,
} from "../../../src/operations/payments/transfer-rails.js";

import { BLOCKHASH, kitReads } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";

import type { FixtureRecord } from "../../helpers/member-registry.js";
import {
  bindingSigners,
  screenedMembers,
  checkAccounts,
  checkTransferProof,
  checkDisclosure,
  checkFrameCounted,
  checkRingBlindings,
  expanded,
  filled,
  itemAt,
  noteInput,
  openDelivered,
  randomAddress,
  ringError,
  ringFixture,
  small,
  walletKeys,
  CURATOR_REVISION,
  OWN_REVISION,
  TRACKING_REVISION,
  hex,
  type Fixture,
  type RingFixtureOptions,
} from "../../helpers/ring-pipeline.js";

import {
  RING_AUTHORITY_MAX_INPUTS,
  RING_AUTHORITY_SHAPES,
} from "../../../src/protocol/transaction/spp.js";

const assets = new AssetRegistry();
const EMPTY_TABLE: RuleTable = buildRuleTable({ rules: [] });

function transferTo(
  fixture: Fixture,
  sender: ShieldedKeypair,
  recipients: readonly ShieldedKeypair[],
  options: Readonly<{ amount?: bigint; each?: bigint; compact?: boolean }> = {},
): ConfidentialTransfer {
  fixture.enroll(sender.shieldedAddress());
  for (const recipient of recipients) fixture.enroll(recipient.shieldedAddress());
  const inputs = [noteInput(sender, options.amount ?? 10_000n, fixture.ringProgramId)];
  const transfer =
    options.compact === true
      ? ConfidentialTransfer.compact(sender.shieldedAddress(), inputs, fixture.authority)
      : new ConfidentialTransfer(sender.shieldedAddress(), inputs, fixture.authority);
  for (const recipient of recipients)
    transfer.send(recipient.shieldedAddress(), SOL_MINT, options.each ?? 400n);
  return transfer;
}

async function prove(
  fixture: Fixture,
  sender: ShieldedKeypair,
  transfer: ConfidentialTransfer,
  withdrawal?: TransactWithdrawal,
  coOwners: readonly ShieldedKeypair[] = [],
): Promise<ProvenRingTransfer> {
  const rail = coOwners.reduce(
    (built, coOwner) =>
      built.withCoOwner({
        owner: coOwner.shieldedAddress().solanaAddress(),
        nullifierKey: coOwner.nullifierKey(),
      }),
    CustomRingTransfer.new({
      ringProgramId: fixture.ringProgramId,
      keys: walletKeys(sender),
      transfer,
      assets,
      ...(fixture.coSigner === undefined ? {} : { coSigners: [fixture.coSigner] }),
    }),
  );
  for (const coOwner of coOwners) fixture.enroll(coOwner.shieldedAddress());
  return (withdrawal === undefined ? rail : rail.withWithdrawalAccounts(withdrawal)).prove(
    fixture.client,
  );
}

/** An empty record for each owner. */
function escrowed(owners: readonly ShieldedKeypair[]): FixtureRecord[] {
  return owners.map((owner) => ({
    member: publicMember(
      memberOfIdentity(owner.shieldedAddress().signingPublicKey.ownerProofInputHash()),
    ),
    lists: 0n,
  }));
}

async function policyOf(fixture: Fixture) {
  const address = await ringPolicyAddress(fixture.ringProgramId);
  const account = fixture.accounts.get(address);
  if (account === undefined) throw new Error("no ring policy");
  return { address, ...decodeRingPolicy(account.data) };
}

function readonly(address: Address) {
  return { address, role: AccountRole.READONLY };
}

function signer(address: Address) {
  return { address, role: AccountRole.READONLY_SIGNER };
}

import { ringSpendTransfer } from "../../../src/operations/payments/ring-spend.js";
import { ringProofInput } from "../../../src/operations/workflow/selection.js";
import { ZERO_NULLIFIER_PK } from "@heliuslabs/spr/internal";
import type { WalletUtxo } from "@heliuslabs/spr/transaction";

const ownNullifier = (): Bytes32 => new Uint8Array(32).fill(0x12) as Bytes32;

describe("confidential rail", () => {
  it("refuses sixteen recipients before any proof, no general key reaches sixteen outputs", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const recipients = Array.from({ length: 16 }, () => ShieldedKeypair.generate());
    await expect(
      prove(
        fixture,
        sender,
        transferTo(fixture, sender, recipients, { amount: 6_400n, each: 400n }),
      ),
    ).rejects.toThrow(ringError("RING_CATALOG_KEY_MISSING"));
    expect(fixture.ringRequests).toHaveLength(0);
  });

  it("delivers two outputs as proven bodies each owner opens to the committed note", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const proven = await prove(fixture, sender, transferTo(fixture, sender, [recipient]));
    const { instruction, data, call } = await expanded(fixture, proven, "confidential");

    expect([data.nIn, data.nOut]).toEqual([1, 2]);
    expect(data.outputs.map((output) => output.body.kind)).toEqual(["recipient", "recipient"]);
    expect(data.policy).toBeUndefined();
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [],
      payer: fixture.authority,
      ownerSigners: [sender.shieldedAddress().solanaAddress()],
    });
    expect(fixture.ringRequests).toHaveLength(1);
    checkTransferProof(fixture, data);
    checkDisclosure(fixture, call, data);
    checkRingBlindings(call, data);
    const open = (owner: ShieldedKeypair, slotIndex: number) =>
      openDelivered({
        fixture,
        keys: walletKeys(owner),
        recipient: owner.viewingPublicKey(),
        call,
        data,
        slotIndex,
      });
    const opened = await open(recipient, 1);
    expect(opened?.utxo.amount).toBe(400n);
    expect(opened?.utxo.blinding).toEqual(call.proofInputs.outputs[1]?.blinding);
    expect((await open(sender, 0))?.utxo.amount).toBe(9_600n);
  });

  it("delivers eight outputs as proven bodies the recipient opens to the committed note", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const recipients = Array.from({ length: 7 }, () => ShieldedKeypair.generate());
    const proven = await prove(fixture, sender, transferTo(fixture, sender, recipients));
    const { data, call } = await expanded(fixture, proven, "confidential");

    expect(data.nOut).toBe(8);
    expect(data.outputs.every((output) => output.body.kind === "recipient")).toBe(true);
    checkTransferProof(fixture, data);
    checkDisclosure(fixture, call, data);
    checkRingBlindings(call, data);
    const open = (recipient: ShieldedKeypair) =>
      openDelivered({
        fixture,
        keys: walletKeys(recipient),
        recipient: recipient.viewingPublicKey(),
        call,
        data,
        slotIndex: 3,
      });
    const note = await open(itemAt(recipients, 2));
    expect(note?.utxo.amount).toBe(400n);
    expect(note?.utxoHash).toEqual(data.outputs[3]?.hash);
    expect(await open(itemAt(recipients, 3))).toBeUndefined();
  });

  it("frames a default-ring recipient as a scheme 3 exit and settles a public withdrawal", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const outside = ShieldedKeypair.generate();
    const transfer = transferTo(fixture, sender, []);
    transfer.sendDefaultRing(outside.shieldedAddress(), SOL_MINT, 300n);
    const recipient = randomAddress();
    transfer.withdraw(SOL_MINT, 200n, WithdrawalTarget.sol({ recipient }));
    const proven = await prove(fixture, sender, transfer, TransactWithdrawal.sol({ recipient }));
    const { instruction, data, call } = await expanded(fixture, proven, "confidential");

    expect(data.outputs.map((output) => output.body.kind)).toEqual(["recipient", "exit"]);
    expect(data.interfaceTransfers).toHaveLength(1);
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [],
      payer: fixture.authority,
      ownerSigners: [sender.shieldedAddress().solanaAddress()],
      settlement: [
        { address: SOL_INTERFACE, role: AccountRole.WRITABLE },
        { address: recipient, role: AccountRole.WRITABLE },
      ],
    });
    checkDisclosure(fixture, call, data);
    checkRingBlindings(call, data);
    const exit = data.outputs[1]?.body;
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
    expect(opened.ringProgramId).toBeUndefined();
  });

  it("refuses withdrawal accounts that name another recipient or a withdrawal the transfer lacks", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const transfer = transferTo(fixture, sender, []);
    transfer.withdraw(SOL_MINT, 200n, WithdrawalTarget.sol({ recipient: randomAddress() }));
    await expect(
      prove(fixture, sender, transfer, TransactWithdrawal.sol({ recipient: randomAddress() })),
    ).rejects.toThrow(ringError("RING_SETTLEMENT_ACCOUNTS_INVALID"));
    await expect(
      prove(
        fixture,
        sender,
        transferTo(fixture, sender, []),
        TransactWithdrawal.sol({ recipient: randomAddress() }),
      ),
    ).rejects.toThrow(ringError("RING_SETTLEMENT_ACCOUNTS_INVALID"));
    expect(fixture.ringRequests).toHaveLength(0);
  });

  it("refuses an owner as the co-signer its scope or a withdrawal past its threshold demands", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const owner = sender.shieldedAddress().solanaAddress();
    const isOwner = ringError("RING_COSIGNER_REQUIRED", {
      reason: "coSignerIsOwner",
      signer: owner,
    });
    const scoped = async (signer: Address) => {
      const fixture = await ringFixture({
        coSigner: { signer, scope: RING_COSIGN_TRANSFERS },
      });
      return {
        fixture,
        proven: prove(fixture, sender, transferTo(fixture, sender, [recipient])),
      };
    };
    const other = randomAddress();
    expect((await (await scoped(other)).proven).coSigners).toEqual([other]);
    const refused = await scoped(owner);
    await expect(refused.proven).rejects.toThrow(isOwner);
    expect(refused.fixture.ringRequests).toHaveLength(0);
    expect(refused.fixture.sppCalls).toHaveLength(0);

    const fixture = await ringFixture({
      coSigner: {
        signer: owner,
        scope: RING_COSIGN_APPROVE_WITHDRAWAL,
      },
      records: [
        {
          member: memberOfAsset(SOL_MINT),
          lists: 0n,
          mintPolicy: { ...EMPTY_MINT_POLICY, withdrawalThreshold: 200n },
        },
      ],
    });
    const withdraw = (amount: bigint) => {
      const transfer = transferTo(fixture, sender, []);
      const target = randomAddress();
      transfer.withdraw(SOL_MINT, amount, WithdrawalTarget.sol({ recipient: target }));
      return prove(fixture, sender, transfer, TransactWithdrawal.sol({ recipient: target }));
    };
    const exempt = await withdraw(200n);
    expect(exempt.coSigners).toEqual([]);
    const { data } = await expanded(fixture, exempt, "confidential");
    expect(data.approval & ApprovalMask.withdrawal).toBe(0);
    expect(data.ownRevision).toBeDefined();
    checkTransferProof(fixture, data);
    await expect(withdraw(201n)).rejects.toThrow(isOwner);
    expect(fixture.sppCalls).toHaveLength(1);
  });

  it("counts the setup instructions and the priority fee before approval and any proof", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    await checkFrameCounted(fixture, {
      payer: fixture.authority,
      prove: (approval) =>
        CustomRingTransfer.new({
          ringProgramId: fixture.ringProgramId,
          keys: walletKeys(sender),
          transfer: transferTo(fixture, sender, [recipient]),
          assets,
        }).proveApproved(fixture.client, approval),
    });
  });

  it("omits a compact output suffix and keeps every published slot's blinding", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const recipients = [ShieldedKeypair.generate(), ShieldedKeypair.generate()];
    const proven = await prove(
      fixture,
      sender,
      transferTo(fixture, sender, recipients, { compact: true }),
    );
    const { data, call } = await expanded(fixture, proven, "confidential");

    expect([data.nOut, data.outputs.length]).toEqual([4, 3]);
    expect(call.proofInputs.outputs.map((output) => output.isCompact())).toEqual([
      false,
      false,
      false,
      true,
    ]);
    checkRingBlindings(call, data);
    const request = checkTransferProof(fixture, data);
    expect([request.outputCount, request.outputs.length]).toEqual([3, 4]);
    checkDisclosure(fixture, call, data);
  });

  it("refuses a compact hole, omission removes a suffix alone", () => {
    const sender = ShieldedKeypair.generate();
    const ring = randomAddress();
    const live = () =>
      createProofOutput({
        ownerAddress: sender.shieldedAddress(),
        asset: SOL_MINT,
        amount: 1n,
        ringProgramId: ring,
      });
    const hole = createProofOutput({
      asset: SOL_MINT,
      amount: 0n,
      compact: true,
    });
    const firstNullifier = small(9);
    const txViewingKey = ViewingKey.generate();
    try {
      const rail = new RingOutputRail(txViewingKey, firstNullifier, { kind: "delivered" });
      expect(() =>
        rail.encrypt({
          prepared: {
            firstNullifier,
            proofOutputs: () => [live(), hole, live()],
          } as unknown as PreparedTransfer,
          sender: sender.shieldedAddress(),
          assets,
          auditor: X25519Keypair.generate().publicKey(),
          instructionDiscriminator: 0,
        }),
      ).toThrow(ringError("RING_COMPACT_NOT_SUFFIX", { slotIndex: 1 }));
    } finally {
      txViewingKey.destroy();
    }
  });

  it("refuses an anonymous ring, a paused ring and a ring SPP never activated", async () => {
    const sender = ShieldedKeypair.generate();
    for (const [options, code] of [
      [{ mode: "anonymous" }, "RING_ANONYMOUS_SIGNER_REQUIRED"],
      [{ registration: { activated: true, paused: true } }, "RING_PAUSED"],
      [{ registration: { activated: false, paused: false } }, "RING_NOT_ACTIVATED"],
    ] as const) {
      const fixture = await ringFixture(options);
      await expect(prove(fixture, sender, transferTo(fixture, sender, []))).rejects.toThrow(
        ringError(code),
      );
      expect(fixture.ringRequests).toHaveLength(0);
      expect(fixture.sppCalls).toHaveLength(0);
    }
  });
});

describe("policy ring", () => {
  const allowOwners = (): RuleTable =>
    buildRuleTable({
      rules: [
        {
          subject: "outputOwner",
          source: { kind: "lists", present: [ListId.allow], absent: [] },
          guard: { kind: "always" },
        },
      ],
    });

  async function curatedRing(
    owners: readonly ShieldedKeypair[],
    options: Readonly<{
      coSigner?: Readonly<{ signer: Address; scope: number }>;
      cap?: bigint;
    }> = {},
  ) {
    return ringFixture({
      table: allowOwners(),
      records: [
        {
          member: memberOfAsset(SOL_MINT),
          lists: 0n,
          mintPolicy: {
            ...EMPTY_MINT_POLICY,
            cap: options.cap ?? 0n,
            cosignAbove: 100n,
          },
        },
      ],
      curator: {
        lists: [ListId.allow],
        records: owners.map((owner) => ({
          member: publicMember(
            memberOfIdentity(owner.shieldedAddress().signingPublicKey.ownerProofInputHash()),
          ),
          lists: 1n,
        })),
      },
      ...(options.coSigner === undefined ? {} : { coSigner: { ...options.coSigner } }),
    });
  }

  it("reads the curator's list, sets the approval bit past the co-sign bound and demands the co-signer", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const coSigner = randomAddress();
    const fixture = await curatedRing([sender, recipient], {
      coSigner: { signer: coSigner, scope: RING_COSIGN_APPROVE_OUTFLOW },
    });
    const proven = await prove(fixture, sender, transferTo(fixture, sender, [recipient]));
    const { instruction, data, call } = await expanded(fixture, proven, "confidential");

    expect(proven.coSigners).toEqual([coSigner]);
    expect(proven.chargedOutflows).toMatchObject([
      {
        owner: sender.shieldedAddress().signingPublicKey.ownerProofInputHash(),
        chargedOutflow: 400n,
      },
    ]);
    expect(data.approval).toBe(ApprovalMask.outflow);
    expect(data.ownRevision).toBe(OWN_REVISION);
    expect(data.policy?.curatorRevision).toBe(CURATOR_REVISION);
    expect(data.trackingRevision).toBe(TRACKING_REVISION);
    const ringPolicy = await policyOf(fixture);
    expect(proven.policy).toEqual({
      ringProgramId: fixture.ringProgramId,
      policyHash: ringPolicy.policyHash,
    });
    if (fixture.curatorRegistry === undefined || fixture.curatorTree === undefined)
      throw new Error("no curator");
    await checkAccounts(instruction, {
      fixture,
      data,
      registries: [fixture.ownRegistry, fixture.curatorRegistry],
      prefix: [
        readonly(await ringCoSignerAddress(fixture.ringProgramId, coSigner)),
        signer(coSigner),
      ],
      payer: fixture.authority,
      ownerSigners: [sender.shieldedAddress().solanaAddress()],
    });
    const request = checkTransferProof(fixture, data);
    expect(request).toMatchObject({
      inProof: false,
      hidden: false,
      delegate: false,
      approvalMask: ApprovalMask.outflow,
      policyHash: ringPolicy.policyHash,
      ownRoot: fixture.ownTree.root,
      curatorRoot: fixture.curatorTree.root,
      sender: new Uint8Array(32) as Bytes32,
      withdrawalHash: policyWithdrawalHash([]),
    });
    checkDisclosure(fixture, call, data);
    checkRingBlindings(call, data);
  });

  it("refuses an opening under a root the live registry does not hold before any proof", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const fixture = await curatedRing([sender, recipient]);
    const served = (revision: bigint): Fixture["client"] => ({
      ...fixture.client,
      getStorageRecordPool: async (request) => {
        const pool = await fixture.client.getStorageRecordPool(request);
        return request.registry === fixture.curatorRegistry
          ? { ...pool, root: { ...pool.root, revision } }
          : pool;
      },
    });
    const transfer = transferTo(fixture, sender, [recipient]);
    const rail = (client: Fixture["client"]) =>
      CustomRingTransfer.new({
        ringProgramId: fixture.ringProgramId,
        keys: walletKeys(sender),
        transfer,
        assets,
      }).prove(client);

    // The indexer serves a curator revision the registry account does not hold yet.
    await expect(rail(served(CURATOR_REVISION + 1n))).rejects.toThrow(
      ringError("RING_ROOT_NOT_SERVED", {
        reason: "pool",
        registry: fixture.curatorRegistry,
      }),
    );
    expect(fixture.ringRequests).toHaveLength(0);
    expect(fixture.sppCalls).toHaveLength(0);
  });

  it("refuses an output owner off the required list before any proof, naming the rule and its slot", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const fixture = await curatedRing([sender]);
    await expect(
      prove(fixture, sender, transferTo(fixture, sender, [recipient], { each: 100n })),
    ).rejects.toThrow(
      ringError("RING_POLICY_RULE_UNSATISFIED", {
        reason: "lists",
        ruleIndex: 0,
        subject: "owner",
        slotIndex: 1,
      }),
    );
    expect(fixture.ringRequests).toHaveLength(0);
    expect(fixture.sppCalls).toHaveLength(0);
  });

  it("refuses an outflow past the co-sign bound on a ring without a co-signer", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const fixture = await curatedRing([sender, recipient]);
    await expect(prove(fixture, sender, transferTo(fixture, sender, [recipient]))).rejects.toThrow(
      ringError("RING_COSIGNER_REQUIRED", {
        ringProgramId: fixture.ringProgramId,
        reason: "missing",
      }),
    );
    expect(fixture.ringRequests).toHaveLength(0);
  });

  it("refuses the owner as the co-signer an approval demands, and proves inside the bound without it", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const owner = sender.shieldedAddress().solanaAddress();
    const fixture = await curatedRing([sender, recipient], {
      coSigner: { signer: owner, scope: RING_COSIGN_APPROVE_OUTFLOW },
    });
    await expect(prove(fixture, sender, transferTo(fixture, sender, [recipient]))).rejects.toThrow(
      ringError("RING_COSIGNER_REQUIRED", {
        reason: "coSignerIsOwner",
        signer: owner,
      }),
    );
    expect(fixture.ringRequests).toHaveLength(0);
    expect(fixture.sppCalls).toHaveLength(0);
    const proven = await prove(
      fixture,
      sender,
      transferTo(fixture, sender, [recipient], { each: 100n }),
    );
    expect([proven.data.approval, proven.coSigners]).toEqual([0, []]);
  });

  it("refuses an outflow past the cap before any proof", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const fixture = await curatedRing([sender, recipient], { cap: 399n });
    await expect(prove(fixture, sender, transferTo(fixture, sender, [recipient]))).rejects.toThrow(
      ringError("RING_OUTFLOW_CAP_EXCEEDED", { cap: "399", chargedOutflow: "400" }),
    );
    expect(fixture.ringRequests).toHaveLength(0);
    expect(fixture.sppCalls).toHaveLength(0);
  });

  it("keeps the approval bit clear inside the bound and names no co-signer outside its scope", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const fixture = await curatedRing([sender, recipient], {
      coSigner: { signer: randomAddress(), scope: RING_COSIGN_DEPOSITS },
    });
    const proven = await prove(
      fixture,
      sender,
      transferTo(fixture, sender, [recipient], { each: 100n }),
    );
    expect(proven.coSigners).toEqual([]);
    const { data } = await expanded(fixture, proven, "confidential");
    expect(data.approval).toBe(0);
  });

  it("names the configured co-signer of transfers inside the bound", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const coSigner = randomAddress();
    const fixture = await curatedRing([sender, recipient], {
      coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS },
    });
    const proven = await prove(
      fixture,
      sender,
      transferTo(fixture, sender, [recipient], { each: 100n }),
    );
    expect(proven.data.approval).toBe(0);
    expect(proven.coSigners).toEqual([coSigner]);
    await expanded(fixture, proven, "confidential");
  });

  const unreachableProver = (): never => {
    throw new Error("proved past the size check");
  };

  it("refuses an unkeyed in-proof owner shape on a co-signed policy ring before any proof", async () => {
    for (const [inputs, outputs] of [[5, 16]] as const) {
      const signing = SigningKey.generate();
      const sender = ShieldedKeypair.fromKeypair(signing);
      const paid = Array.from({ length: outputs - 1 }, () => ShieldedKeypair.generate());
      const fixture = await ringFixture({
        mode: "confidential",
        table: EMPTY_TABLE,
        records: escrowed([sender, ...paid]),
        coSigner: { signer: randomAddress(), scope: RING_COSIGN_TRANSFERS },
      });
      for (const owner of [sender, ...paid]) fixture.enroll(owner.shieldedAddress());
      const transfer = new ConfidentialTransfer(
        sender.shieldedAddress(),
        Array.from({ length: inputs }, () => noteInput(sender, 100n, fixture.ringProgramId)),
        fixture.authority,
      );
      for (const recipient of paid) transfer.send(recipient.shieldedAddress(), SOL_MINT, 1n);
      await expect(
        CustomRingTransfer.new({
          ringProgramId: fixture.ringProgramId,
          keys: walletKeys(sender),
          transfer,
          assets,
          ...(fixture.coSigner === undefined ? {} : { coSigners: [fixture.coSigner] }),
        })
          .withInProofOwner(signingKeySpendSigner(signing))
          .prove({
            ...fixture.client,
            proveAnonymousRingTransact: unreachableProver,
          }),
      ).rejects.toThrow(ringError("RING_CATALOG_KEY_MISSING"));
      expect(fixture.ringRequests).toHaveLength(0);
      expect(fixture.sppCalls).toHaveLength(0);
    }
  });

  it("proves an in-proof owner on SPP's anonymous rail and publishes the sender in the delivered audit", async () => {
    const signing = SigningKey.generate();
    const sender = ShieldedKeypair.fromKeypair(signing);
    const recipient = ShieldedKeypair.generate();
    const fixture = await ringFixture({ table: EMPTY_TABLE });
    const proven = await CustomRingTransfer.new({
      ringProgramId: fixture.ringProgramId,
      keys: walletKeys(sender),
      transfer: transferTo(fixture, sender, [recipient]),
      assets,
    })
      .withInProofOwner(signingKeySpendSigner(signing))
      .prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "confidential");

    expect(call.circuit.kind).toBe("ringAnonymous");
    expect(call.owner?.ownerPublicKey).toEqual(sender.shieldedAddress().signingPublicKey.ed25519());
    expect(data.outputs.map((output) => output.body.kind)).toEqual(["recipient", "recipient"]);
    expect(call.data.circuit).toMatchObject({
      kind: "anonymousRingEddsa",
      inputs: 1,
      outputs: 2,
    });
    expect(call.data.circuit.kind === "anonymousRingEddsa" && call.data.circuit.proofData).toEqual({
      bsb22Commitment: {
        commitment: filled(0x51),
        commitmentPok: filled(0x52),
      },
    });
    expect(proven.accounts.ownerSigners).toEqual([]);
    const request = checkTransferProof(fixture, data);
    const identity = sender.shieldedAddress().signingPublicKey.ownerProofInputHash();
    expect([request.inProof, request.delegate]).toEqual([true, false]);
    expect(request.sender).toEqual(identity);
    expect(request.privateTxHash).toEqual(data.privateTxHash);
    expect(request.inputs).toHaveLength(24);
  });

  it("refuses a default-ring input on the in-proof owner rail before any proof", async () => {
    const signing = SigningKey.generate();
    const sender = ShieldedKeypair.fromKeypair(signing);
    const fixture = await ringFixture();
    const transfer = new ConfidentialTransfer(
      sender.shieldedAddress(),
      [noteInput(sender, 100n, fixture.ringProgramId), noteInput(sender, 50n)],
      fixture.authority,
    );
    transfer.send(ShieldedKeypair.generate().shieldedAddress(), SOL_MINT, 30n);
    await expect(
      CustomRingTransfer.new({
        ringProgramId: fixture.ringProgramId,
        keys: walletKeys(sender),
        transfer,
        assets,
      })
        .withInProofOwner(signingKeySpendSigner(signing))
        .prove(fixture.client),
    ).rejects.toThrow(ringError("RING_IN_PROOF_DEFAULT_RING_INPUT", { index: 1 }));
    expect(fixture.ringRequests).toHaveLength(0);
    expect(fixture.sppCalls).toHaveLength(0);
  });

  it("binds the tracking root on every ring and pays an output owner with no row", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const fixture = await ringFixture({ table: EMPTY_TABLE });
    const proven = await prove(fixture, sender, transferTo(fixture, sender, [recipient]));
    const { data } = await expanded(fixture, proven, "confidential");
    expect(checkTransferProof(fixture, data).trackingRoot).toEqual(fixture.trackingTree.root);
    expect(data.policy?.curatorRevision).toBeUndefined();

    const unregistered = await ringFixture({ table: EMPTY_TABLE });
    unregistered.enroll(sender.shieldedAddress());
    const transfer = new ConfidentialTransfer(
      sender.shieldedAddress(),
      [noteInput(sender, 10_000n, unregistered.ringProgramId)],
      unregistered.authority,
    );
    transfer.send(recipient.shieldedAddress(), SOL_MINT, 400n);
    // Any nonzero key pays its owner, only a matching registration spends the note.
    await prove(unregistered, sender, transfer);
    expect(unregistered.ringRequests).toHaveLength(1);
  });
});

describe("signer set and owner debits", () => {
  const identity = (owner: ShieldedKeypair): Bytes32 =>
    owner.shieldedAddress().signingPublicKey.ownerProofInputHash();
  const ZERO = new Uint8Array(32) as Bytes32;

  function mixedTransfer(
    fixture: Fixture,
    owners: readonly ShieldedKeypair[],
    each: bigint,
  ): ConfidentialTransfer {
    const first = itemAt(owners, 0);
    for (const owner of owners) fixture.enroll(owner.shieldedAddress());
    return ringSpendTransfer({
      owner: first.shieldedAddress(),
      inputs: owners.map((owner) => noteInput(owner, each, fixture.ringProgramId)),
      feePayer: fixture.authority,
    });
  }

  it("spends mixed owners over a policy within Q, each one signing and screened", async () => {
    const owners = [ShieldedKeypair.generate(), ShieldedKeypair.generate()];
    const fixture = await ringFixture({ table: EMPTY_TABLE, records: [] });
    const transfer = mixedTransfer(fixture, owners, 500n);
    transfer.withShape({ inputs: 2, outputs: 2 });
    const proven = await prove(fixture, itemAt(owners, 0), transfer, undefined, owners.slice(1));
    const { instruction, data, call } = await expanded(fixture, proven, "confidential");

    const addresses = owners.map((owner) => owner.shieldedAddress().solanaAddress());
    await checkAccounts(instruction, {
      fixture,
      data,
      registries: [fixture.ownRegistry],
      prefix: [],
      payer: fixture.authority,
      ownerSigners: addresses,
    });
    const request = checkTransferProof(fixture, data);
    const identities = owners.map(identity);
    expect(bindingSigners(request)).toEqual(identities);
    expect(new Set(screenedMembers(request, 2).map(hex))).toEqual(
      new Set(identities.map(publicListKey).map(hex)),
    );
    expect(request).toMatchObject({ sender: ZERO });
    checkDisclosure(fixture, call, data);
  });

  it("takes the wide key past the narrow key's owner rows", async () => {
    const owners = Array.from({ length: 5 }, () => ShieldedKeypair.generate());
    const fixture = await ringFixture({ table: EMPTY_TABLE, records: [] });
    const transfer = mixedTransfer(fixture, owners, 100n);
    transfer.withShape({ inputs: 8, outputs: 2 });
    const proven = await prove(fixture, itemAt(owners, 0), transfer, undefined, owners.slice(1));
    expect(proven.data.wideOwners).toBe(true);
  });

  const cappedRing = (cap: bigint) =>
    ringFixture({
      table: EMPTY_TABLE,
      records: [
        {
          member: memberOfAsset(SOL_MINT),
          lists: 0n,
          mintPolicy: { ...EMPTY_MINT_POLICY, cap },
        },
      ],
    });

  it("refuses the wallet's own zero key note on the rail before any proof", async () => {
    const sender = ShieldedKeypair.generate();
    const address = sender.shieldedAddress();
    const fixture = await ringFixture({ table: EMPTY_TABLE, records: [] });
    const client = fixture.client;
    const wallet = (key: Bytes32, amount: bigint, nullifier: Bytes32): WalletUtxo => {
      const utxo = new Utxo({
        owner: sender.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: randomBlinding(),
        ringProgramId: fixture.ringProgramId,
      });
      return {
        utxo,
        outputContext: {
          hash: utxo.proofInput(key, client.treeId).hash(),
          tree: client.tree,
          leafIndex: 0n,
        },
        nullifier,
        spent: false,
      } as WalletUtxo;
    };
    const zeroNullifier = new Uint8Array(32).fill(0x11) as Bytes32;
    const inputs = [
      ringProofInput(wallet(address.nullifierPublicKey, 500n, ownNullifier()), address, client),
      ringProofInput(wallet(ZERO_NULLIFIER_PK, 300n, zeroNullifier), address, client),
    ];
    fixture.enroll(address);
    const transfer = ringSpendTransfer({
      owner: address,
      inputs,
      feePayer: fixture.authority,
    }).withOutputTreeId(client.treeId);
    transfer.withShape({ inputs: 2, outputs: 2 });
    await expect(prove(fixture, sender, transfer)).rejects.toThrow(
      ringError("RING_ZERO_KEY_INPUT_UNNAMED", { index: 1 }),
    );
    expect(fixture.ringRequests).toHaveLength(0);
  });

  it("debits each owner apart, a credit to one never covers another", async () => {
    const payer = ShieldedKeypair.generate();
    const funded = ShieldedKeypair.generate();
    const transfer = async (cap: bigint) => {
      const fixture = await cappedRing(cap);
      const spent = mixedTransfer(fixture, [payer, funded], 500n);
      spent.withShape({ inputs: 2, outputs: 2 });
      // Nothing leaves the ring, the first owner still debits its whole note.
      spent.send(funded.shieldedAddress(), SOL_MINT, 1_000n);
      return prove(fixture, payer, spent, undefined, [funded]);
    };
    await expect(transfer(499n)).rejects.toThrow(
      ringError("RING_OUTFLOW_CAP_EXCEEDED", { cap: "499", chargedOutflow: "500" }),
    );
    await expect(transfer(500n)).resolves.toBeDefined();
  });

  it("clamps a single owner's debit to zero when a deposit funds what returns", () => {
    const owner = ShieldedKeypair.generate();
    const ring = randomAddress();
    const asset = assetField(SOL_MINT);
    const proofInputs = {
      inputUtxos: [noteInput(owner, 100n, ring)],
      outputs: [
        createProofOutput({
          ownerAddress: owner.shieldedAddress(),
          asset: SOL_MINT,
          amount: 120n,
          ringProgramId: ring,
        }),
        createProofOutput({
          ownerAddress: ShieldedKeypair.generate().shieldedAddress(),
          asset: SOL_MINT,
          amount: 30n,
          ringProgramId: ring,
        }),
      ],
    } as unknown as SppProofInputs;
    expect(
      transferOutflows({
        rows: [identity(owner)],
        proofInputs,
        publicSlots: {
          assets: [asset, ZERO, ZERO],
          nets: [50n, 0n, 0n],
          gross: [0n, 0n, 0n],
        },
        policyOf: () => ({ ...EMPTY_MINT_POLICY, cap: 1n, cosignAbove: 1n }),
      }),
    ).toEqual({ chargedOutflows: [], approvalMask: 0 });
  });
});

describe("delegate rail", () => {
  async function delegateRing(owners: readonly ShieldedKeypair[]) {
    const delegate = randomAddress();
    const fixture = await ringFixture({
      mode: "confidential",
      table: EMPTY_TABLE,
      delegate,
      records: escrowed(owners),
    });
    for (const owner of owners) fixture.enroll(owner.shieldedAddress());
    return { fixture, delegate };
  }

  function move(
    input: Readonly<{
      fixture: Fixture;
      delegate: Address;
      source: ShieldedKeypair;
      recipients: readonly ShieldedKeypair[];
      spender?: ShieldedKeypair;
    }>,
  ): DelegateTransfer {
    const { fixture, source } = input;
    return DelegateTransfer.new({
      ringProgramId: fixture.ringProgramId,
      delegate: input.delegate,
      payer: fixture.authority,
      source: source.shieldedAddress(),
      sourceProofs: walletKeys(source),
      inputs: [noteInput(input.spender ?? source, 10_000n, fixture.ringProgramId)],
      outputs: input.recipients.map((recipient) => ({
        recipient: recipient.shieldedAddress(),
        asset: SOL_MINT,
        amount: 100n,
      })),
      assets,
    });
  }

  it("moves a member's notes on the authority rail with the delegate signing", async () => {
    const source = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const { fixture, delegate } = await delegateRing([source, recipient]);
    const proven = await move({
      fixture,
      delegate,
      source,
      recipients: [recipient],
    }).prove(fixture.client);
    const { instruction, data, call } = await expanded(fixture, proven, "delegate");

    expect(call.circuit.kind).toBe("ringAuthority");
    expect(data.outputs.every((output) => output.body.kind === "recipient")).toBe(true);
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [signer(delegate)],
      payer: fixture.authority,
    });
    const zero = new Uint8Array(32) as Bytes32;
    const request = checkTransferProof(fixture, data);
    expect(request).toMatchObject({
      inProof: false,
      delegate: true,
      approvalMask: 0,
      sender: zero,
      withdrawalHash: policyWithdrawalHash([]),
    });
    expect([request.policyHash, request.ownRoot, request.curatorRoot].map(hex)).toEqual(
      [zero, zero, zero].map(hex),
    );
    expect(request.rows[0]).toEqual(
      source.shieldedAddress().signingPublicKey.ownerProofInputHash(),
    );
    checkDisclosure(fixture, call, data);
    checkRingBlindings(call, data);
    const opened = await openDelivered({
      fixture,
      keys: walletKeys(recipient),
      recipient: recipient.viewingPublicKey(),
      call,
      data,
      slotIndex: 1,
    });
    expect(opened?.utxo.amount).toBe(100n);
  });

  it("withdraws a member's note publicly on the authority rail", async () => {
    const source = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const { fixture, delegate } = await delegateRing([source, recipient]);
    const destination = randomAddress();
    const proven = await DelegateTransfer.new({
      ringProgramId: fixture.ringProgramId,
      delegate,
      payer: fixture.authority,
      source: source.shieldedAddress(),
      sourceProofs: walletKeys(source),
      inputs: [noteInput(source, 10_000n, fixture.ringProgramId)],
      outputs: [{ recipient: recipient.shieldedAddress(), asset: SOL_MINT, amount: 100n }],
      withdrawal: {
        asset: SOL_MINT,
        amount: 200n,
        target: WithdrawalTarget.sol({ recipient: destination }),
        accounts: TransactWithdrawal.sol({ recipient: destination }),
      },
      assets,
    }).prove(fixture.client);
    const { instruction, data, call } = await expanded(fixture, proven, "delegate");

    expect(call.data.circuit.kind).toBe("ringAuthority");
    expect(data.interfaceTransfers).toEqual([{ kind: "solWithdrawal", amount: 200n }]);
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [signer(delegate)],
      payer: fixture.authority,
      settlement: [
        { address: SOL_INTERFACE, role: AccountRole.WRITABLE },
        { address: destination, role: AccountRole.WRITABLE },
      ],
    });
  });

  it("refuses a delegate exit before any read until the exit keys are pinned", async () => {
    const source = ShieldedKeypair.generate();
    const outside = ShieldedKeypair.generate();
    const { fixture, delegate } = await delegateRing([source]);
    const reads = fixture.client.getAccount;
    const getAccount = vi.fn(reads);
    await expect(
      DelegateTransfer.new({
        ringProgramId: fixture.ringProgramId,
        delegate,
        payer: fixture.authority,
        source: source.shieldedAddress(),
        sourceProofs: walletKeys(source),
        inputs: [noteInput(source, 10_000n, fixture.ringProgramId)],
        outputs: [
          { recipient: outside.shieldedAddress(), asset: SOL_MINT, amount: 100n, exit: true },
        ],
        assets,
      }).prove({ ...fixture.client, getAccount }),
    ).rejects.toMatchObject({ code: "RING_EXIT_PROOF_UNAVAILABLE" });
    expect(getAccount).not.toHaveBeenCalled();
    expect(fixture.sppCalls).toHaveLength(0);
  });

  it("takes the narrowest pinned authority shape holding a move and refuses a wider one", async () => {
    const source = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const { fixture, delegate } = await delegateRing([source, recipient]);
    for (const [recipients, shape] of [
      [1, RING_AUTHORITY_SHAPES[0]],
      [3, RING_AUTHORITY_SHAPES[1]],
    ] as const) {
      const proven = await move({
        fixture,
        delegate,
        source,
        recipients: Array.from({ length: recipients }, () => recipient),
      }).prove(fixture.client);
      const { data } = await expanded(fixture, proven, "delegate");
      expect([data.nIn, data.nOut]).toEqual([shape?.inputs, shape?.outputs]);
    }
    const wide = move({
      fixture,
      delegate,
      source,
      recipients: Array(4).fill(recipient),
    });
    await expect(wide.prove(fixture.client)).rejects.toThrow(
      expect.objectContaining({ code: "TRANSACTION_UNSUPPORTED_SHAPE" }),
    );
  });

  it("counts the setup instructions and the priority fee before approval and any proof", async () => {
    const source = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const { fixture, delegate } = await delegateRing([source, recipient]);
    await checkFrameCounted(fixture, {
      payer: fixture.authority,
      prove: (approval) =>
        move({
          fixture,
          delegate,
          source,
          recipients: [recipient],
        }).proveApproved(fixture.client, approval),
    });
  });

  it("refuses another delegate, a ring without one and another member's notes", async () => {
    const source = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const { fixture, delegate } = await delegateRing([source, recipient]);
    const refused = async (
      input: Parameters<typeof move>[0],
      details: Readonly<Record<string, unknown>>,
      code = "RING_DELEGATE_INVALID",
    ) => {
      await expect(move(input).prove(input.fixture.client)).rejects.toThrow(
        ringError(code, details),
      );
      expect(input.fixture.ringRequests).toHaveLength(0);
    };
    await refused(
      { fixture, delegate: randomAddress(), source, recipients: [recipient] },
      { reason: "unauthorized" },
    );
    await refused(
      {
        fixture: await ringFixture({
          mode: "confidential",
          table: EMPTY_TABLE,
        }),
        delegate,
        source,
        recipients: [recipient],
      },
      { reason: "missing" },
    );
    await refused(
      {
        fixture,
        delegate,
        source,
        recipients: [recipient],
        spender: recipient,
      },
      { reason: "mixedOwners" },
    );
  });
});

describe("member records", () => {
  const identity = (keys: ShieldedKeypair): Bytes32 =>
    keys.shieldedAddress().signingPublicKey.ownerProofInputHash();

  it("reads records in member order with their lists like Rust `MemberRecords::read`", async () => {
    const registered = ShieldedKeypair.generate();
    const stranger = ShieldedKeypair.generate();
    const [record] = escrowed([registered]);
    if (record === undefined) throw new Error("no record");
    const fixture = await ringFixture({
      mode: "confidential",
      table: EMPTY_TABLE,
      records: [{ ...record, lists: recordBit(ListId.allow) }],
    });
    const [absent, present] = await readMemberRecords({
      client: fixture.client,
      ringProgramId: fixture.ringProgramId,
      members: [identity(stranger), identity(registered)].map((owner) =>
        publicMember(memberOfIdentity(owner)),
      ),
    });
    expect(absent?.record()).toBeUndefined();
    expect(absent?.listed(ListId.allow)).toBe(false);
    expect(present?.listed(ListId.allow)).toBe(true);
    expect(present?.listed(ListId.block)).toBe(false);
  });
});

describe("delegate move builder", () => {
  /** A move paying `amounts` out of `notes` source notes of 100, the delegate paying on one tree. */
  async function delegateMove(
    input: Readonly<{
      amounts: readonly bigint[];
      notes?: number;
    }>,
  ) {
    const source = ShieldedKeypair.generate();
    const recipients = input.amounts.map(() => ShieldedKeypair.generate());
    const delegate = randomAddress();
    const fixture = await ringFixture({
      mode: "confidential",
      table: EMPTY_TABLE,
      delegate,
      records: escrowed([source, ...recipients]),
    });
    for (const owner of [source, ...recipients]) fixture.enroll(owner.shieldedAddress());
    const wallet = new Wallet({ identity: source.shieldedAddress() });
    wallet._replace({
      utxos: Array.from({ length: input.notes ?? 40 }, (_, index) => ({
        utxo: new Utxo({
          owner: source.signingPublicKey(),
          asset: SOL_MINT,
          amount: 100n,
          blinding: randomBlinding(),
          ringProgramId: fixture.ringProgramId,
        }),
        outputContext: {
          hash: small(index + 1),
          tree: fixture.client.tree,
          leafIndex: BigInt(index),
        },
        nullifier: small(index + 100),
        spent: false,
      })),
      transactions: [],
      nullifiers: new Set(),
    });
    const requests: RingApprovalRequest[] = [];
    const ring = await ringPolicyAddress(fixture.ringProgramId);
    const reads = { ring: 0, openings: 0, proofsAtApproval: [] as number[] };
    const build = buildRingDelegateTransferTransaction({
      client: withConfirmedReads({
        ...fixture.client,
        getAccount: async (address) => {
          if (address === ring) reads.ring += 1;
          return fixture.client.getAccount(address);
        },
        getTrackingRecordPool: async (request) => {
          reads.openings += 1;
          return fixture.client.getTrackingRecordPool(request);
        },
        getLatestBlockhash: async () => BLOCKHASH,
        ...kitReads({
          solanaRpc: { getProgramAccounts: () => ({ send: async () => [] }) },
        }),
      }),
      ringProgramId: fixture.ringProgramId,
      wallet,
      source: walletKeys(source),
      approve: async (request) => {
        requests.push(request);
        reads.proofsAtApproval.push(fixture.ringRequests.length + fixture.sppCalls.length);
        return approveRingUnattended(request);
      },
      delegate,
      feePayer: delegate,
      outputs: input.amounts.map((amount, index) => ({
        recipient: itemAt(recipients, index).shieldedAddress(),
        asset: SOL_MINT,
        amount,
      })),
    });
    return { fixture, requests, reads, build };
  }

  it("reads the ring and seals the move once, approving between its size check and its proofs", async () => {
    const { fixture, reads, build } = await delegateMove({
      amounts: [400n],
      notes: 4,
    });
    await build;
    expect(reads).toEqual({ ring: 1, openings: 1, proofsAtApproval: [0] });
    expect(fixture.sppCalls).toHaveLength(1);
  });

  it("bounds a move's notes by the widest authority shape holding its payments and change", async () => {
    const one = await delegateMove({ amounts: [301n], notes: 30 });
    await one.build;
    expect(one.fixture.sppCalls.at(-1)?.proofInputs.checkShape()).toEqual({
      inputs: 4,
      outputs: 4,
    });
    const two = await delegateMove({ amounts: [150n, 150n], notes: 30 });
    await two.build;
    expect(two.fixture.sppCalls.at(-1)?.proofInputs.checkShape()).toEqual({
      inputs: 4,
      outputs: 4,
    });
    const wide = await delegateMove({ amounts: [401n], notes: 30 });
    await expect(wide.build).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { maximum: RING_AUTHORITY_MAX_INPUTS } },
    });
    expect(wide.requests).toEqual([]);
  });

  it("lands a move of the widest authority shape in one transaction", async () => {
    const { fixture, requests, build } = await delegateMove({
      amounts: [400n],
    });
    const transaction = await build;
    expect(requests).toHaveLength(1);
    expect(transactionSize(transaction)).toBeLessThanOrEqual(TRANSACTION_SIZE_LIMIT);
    expect(fixture.sppCalls.at(-1)?.proofInputs.checkShape()).toEqual({
      inputs: 4,
      outputs: 4,
    });
  });
});

describe("ring transfer builder", () => {
  /** A payment of `amount` out of `notes` ring notes of 100, the owner paying the fee. */
  async function ringTransfer(
    input: Readonly<{
      amount: bigint;
      notes: number;
      ring?: RingFixtureOptions;
      cosigner?: Address;
    }>,
  ) {
    const owner = ShieldedKeypair.generate();
    const fixture = await ringFixture(input.ring);
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    fixture.enroll(owner.shieldedAddress());
    fixture.enroll(recipient);
    const wallet = new Wallet({ identity: owner.shieldedAddress() });
    wallet._replace({
      utxos: Array.from({ length: input.notes }, (_, index) => ({
        utxo: new Utxo({
          owner: owner.signingPublicKey(),
          asset: SOL_MINT,
          amount: 100n,
          blinding: randomBlinding(),
          ringProgramId: fixture.ringProgramId,
        }),
        outputContext: {
          hash: small(index + 1),
          tree: fixture.client.tree,
          leafIndex: BigInt(index),
        },
        nullifier: small(index + 100),
        spent: false,
      })),
      transactions: [],
      nullifiers: new Set(),
    });
    const requests: RingApprovalRequest[] = [];
    const build = buildRingTransferTransaction({
      client: { ...fixture.client, getLatestBlockhash: async () => BLOCKHASH },
      ringProgramId: fixture.ringProgramId,
      wallet,
      keys: walletKeys(owner),
      feePayer: owner.shieldedAddress().solanaAddress(),
      approve: async (request) => {
        requests.push(request);
        return approveRingUnattended(request);
      },
      recipient,
      amount: input.amount,
      ...(input.cosigner === undefined ? {} : { cosigners: [input.cosigner] }),
    });
    return { fixture, requests, build };
  }

  it("refuses a payment past the widest confidential key before approval and any proof", async () => {
    const wide = await ringTransfer({ amount: 4_950n, notes: 50 });
    await expect(wide.build).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_TOO_MANY_INPUTS",
    });
    expect(wide.requests).toEqual([]);
    expect(wide.fixture.ringRequests).toHaveLength(0);
    expect(wide.fixture.sppCalls).toHaveLength(0);
    const widest = await ringTransfer({ amount: 2_350n, notes: 24 });
    expect(transactionSize(await widest.build)).toBeLessThanOrEqual(TRANSACTION_SIZE_LIMIT);
    expect(widest.requests).toHaveLength(1);
  });

  it("refuses a missing or another co-signer before approval and any proof", async () => {
    const coSigner = randomAddress();
    const ring = {
      coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS },
    };
    for (const [cosigner, reason] of [
      [undefined, "missing"],
      [randomAddress(), "noRecord"],
    ] as const) {
      const refused = await ringTransfer({
        amount: 300n,
        notes: 4,
        ring,
        ...(cosigner === undefined ? {} : { cosigner }),
      });
      await expect(refused.build).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_COSIGNER_REQUIRED",
        cause: { details: { reason } },
      });
      expect(refused.requests).toEqual([]);
      expect(refused.fixture.ringRequests).toHaveLength(0);
      expect(refused.fixture.sppCalls).toHaveLength(0);
    }
    const signed = await ringTransfer({
      amount: 300n,
      notes: 4,
      ring,
      cosigner: coSigner,
    });
    await signed.build;
    expect(signed.requests).toHaveLength(1);
  });
});

describe("direct confidential spend", () => {
  it("sends on the in-proof rail from the wallet's own payer and proves again after a stale root", async () => {
    const signing = SigningKey.generate();
    const sender = ShieldedKeypair.fromKeypair(signing);
    const fixture = await ringFixture({ table: EMPTY_TABLE });
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    fixture.enroll(sender.shieldedAddress());
    fixture.enroll(recipient);
    const payer = await generateKeyPairSigner();
    const wallet = new Wallet({ identity: sender.shieldedAddress() });
    wallet._replace({
      utxos: [
        {
          utxo: new Utxo({
            owner: sender.signingPublicKey(),
            asset: SOL_MINT,
            amount: 100n,
            blinding: randomBlinding(),
            ringProgramId: fixture.ringProgramId,
          }),
          outputContext: {
            hash: small(1),
            tree: fixture.client.tree,
            leafIndex: 0n,
          },
          nullifier: small(100),
          spent: false,
        },
      ],
      transactions: [],
      nullifiers: new Set(),
    });
    const submission = await createRingTransferSubmission({
      client: { ...fixture.client, getLatestBlockhash: async () => BLOCKHASH },
      ringProgramId: fixture.ringProgramId,
      wallet,
      keys: walletKeys(sender),
      feePayer: payer.address,
      inProofOwner: signingKeySpendSigner(signing),
      recipient,
      amount: 30n,
    });
    submission.prove();
    let polled = 0;
    const result = await submission.send({
      sign: (transaction) => signTransactionWithSigners([payer], transaction),
      send: async () => undefined,
      status: async () =>
        ++polled === 1
          ? {
              kind: "failed",
              instructionIndex: 0,
              customCode: RingProgramError.rootNotServed,
            }
          : { kind: "confirmed", slot: 9n },
    });

    expect(result).toMatchObject({ kind: "confirmed", attempts: 2 });
    expect(fixture.sppCalls.map((call) => call.circuit.kind)).toEqual([
      "ringAnonymous",
      "ringAnonymous",
    ]);
  });
});

describe("audit seal", () => {
  const layout = ringStreamLayout({
    rail: "confidential",
    nIn: 1,
    nOut: 2,
    inputs: 1,
    outputs: 2,
    entry: false,
    publicOwners: false,
  });
  const signed = (sender: ShieldedKeypair) =>
    new ConfidentialTransfer(
      sender.shieldedAddress(),
      [noteInput(sender, 10n)],
      randomAddress(),
    ).sign(sender, new AssetRegistry());

  it("makes no ephemeral key for a disclosure it refuses", () => {
    const sender = ShieldedKeypair.generate();
    const proofInputs = signed(sender);
    const txViewingKey = ViewingKey.generate();
    const auditor = X25519Keypair.generate();
    const generate = vi.spyOn(X25519Keypair, "generate");
    try {
      expect(() =>
        sealAudit({
          rail: new RingOutputRail(txViewingKey, proofInputs.firstNullifier(), {
            kind: "delivered",
          }),
          layout,
          published: [],
          inputs: proofInputs.inputUtxos,
          auditor: auditor.publicKey(),
        }),
      ).toThrow(expect.objectContaining({ code: "KEYPAIR_DISCLOSURE_SHAPE" }));
      expect(generate).not.toHaveBeenCalled();
    } finally {
      generate.mockRestore();
      auditor.destroy();
    }
  });

  it("draws a new salt and a new keystream for every build of one transfer", () => {
    const sender = ShieldedKeypair.generate();
    const proofInputs = signed(sender);
    const txViewingKey = ViewingKey.generate();
    const auditor = X25519Keypair.generate();
    const build = () => {
      const rail = new RingOutputRail(txViewingKey, proofInputs.firstNullifier(), {
        kind: "delivered",
      });
      return {
        salt: rail.salt,
        sealed: sealAudit({
          rail,
          layout,
          published: proofInputs.outputs.map((output, slotIndex) => ({
            output,
            slotIndex,
            wire: {
              hash: new Uint8Array(32) as Bytes32,
              ownerTag: new Uint8Array(32) as Bytes32,
              record: new Uint8Array(137),
              body: { kind: "recipient" as const, payload: new Uint8Array() },
            },
            recipientKey: auditor.publicKey(),
          })),
          inputs: proofInputs.inputUtxos,
          auditor: auditor.publicKey(),
        }),
      };
    };
    const first = build();
    const second = build();
    try {
      expect(first.salt).not.toEqual(second.salt);
      // One plaintext under one key and two salts, a repeated salt would repeat these bytes.
      expect(first.sealed.envelope).not.toEqual(second.sealed.envelope);
    } finally {
      first.sealed.ephemeralSecret.fill(0);
      second.sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });
});
