import {
  decompileTransactionMessage,
  getBase58Decoder,
  getCompiledTransactionMessageDecoder,
  signature,
} from "@solana/kit";
import { initializePoseidon, SHIELDED_POOL_PROGRAM_ID } from "@heliuslabs/spr";
import { StateDiscriminator } from "@heliuslabs/spr/interface";
import type { Address, Bytes32, Instruction } from "@heliuslabs/spr/interface";
import {
  addressBytes,
  compileUnsignedTransaction,
  encodeBase58,
  indexerScalars,
  treeAddress,
} from "@heliuslabs/spr/internal";
import { randomBlinding, ShieldedKeypair, ViewingKey } from "@heliuslabs/spr/keypair";
import {
  AssetRegistry,
  Data,
  SOL_MINT,
  ProofInputUtxo,
  Utxo,
  type WalletUtxo,
} from "@heliuslabs/spr/transaction";
import { beforeAll, describe, expect, it } from "vitest";

import { withConfirmedReads } from "../../helpers/clients.js";
import { openSealedDisclosure } from "../../../src/crypto/audit/ring-disclosure.js";
import { x25519FromU } from "../../../src/crypto/keys/x25519.js";
import { RecordKind } from "../../../src/protocol/codec/audit-stream.js";
import { ringComputeUnitLimit } from "../../../src/operations/management/admin.js";
import { buildRingDelegateRecoveredTransaction } from "../../../src/operations/management/delegate.js";
import { DelegateTransfer } from "../../../src/operations/payments/transfer-rails.js";
import { ringProofInput } from "../../../src/operations/workflow/selection.js";
import { SIZE_PROBE_LIFETIME } from "../../../src/operations/workflow/compile.js";
import { buildRuleTable } from "../../../src/protocol/membership/policy.js";
import type { RingMode } from "../../../src/protocol/codec/ring-codecs.js";
import type { PrepareAuthorityTransferRequest } from "../../../src/protocol/ring-rpc/ring-rpc-types.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import {
  ringRailOf,
  RingTransactData,
  type RingRail,
} from "../../../src/protocol/transaction/transact.js";
import {
  AllowedNullifiers,
  checkRelayMessage,
  expectedDelegate,
} from "../../../src/rpc/relay-message.js";
import { BLOCKHASH, kitReads } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import {
  noteInput,
  PROOF_SERVICE,
  randomAddress,
  ringFixture,
  small,
  walletKeys,
  type Fixture,
} from "../../helpers/ring-pipeline.js";

const assets = new AssetRegistry();
const TX_VIEWING_KEY = (() => {
  const key = new Uint8Array(32).fill(6);
  key[0] = 0;
  key[31] = 0x46;
  return key as Bytes32;
})();

const USDC = address32(0x31);
const EURC = address32(0x32);
const SPL_MINTS = [
  { mint: USDC, assetId: 2n },
  { mint: EURC, assetId: 3n },
];

function address32(byte: number): Address {
  return encodeBase58(new Uint8Array(32).fill(byte)) as Address;
}

function registryAccount(mint: Address, assetId: bigint): string {
  const data = new Uint8Array(48);
  data[0] = StateDiscriminator.splAssetRegistry;
  data.set(addressBytes(mint), 8);
  new DataView(data.buffer).setBigUint64(40, assetId, true);
  return Buffer.from(data).toString("base64");
}

async function moveRing(mode: RingMode, owners: readonly ShieldedKeypair[]) {
  const delegate = randomAddress();
  const fixture = await ringFixture({ mode, table: buildRuleTable({ rules: [] }), delegate });
  for (const owner of owners) fixture.enroll(owner.shieldedAddress());
  return { fixture, delegate };
}

/** Change returns to the owner of the last note spent. */
function movingFrom(
  fixture: Fixture,
  delegate: string,
  sources: readonly ShieldedKeypair[],
  payee: ShieldedKeypair,
  amount: bigint,
): Readonly<{ transfer: DelegateTransfer; notes: readonly ProofInputUtxo[] }> {
  const notes = sources.map((source) => noteInput(source, 10n, fixture.ringProgramId));
  const change = sources.at(-1);
  if (change === undefined) throw new Error("a source");
  const transfer = sources
    .filter((source) => source !== change)
    .reduce(
      (built, source) =>
        built.withCoSource({
          owner: source.shieldedAddress().solanaAddress(),
          nullifierKey: source.nullifierKey(),
        }),
      DelegateTransfer.new({
        ringProgramId: fixture.ringProgramId,
        delegate: delegate as never,
        payer: fixture.authority,
        source: change.shieldedAddress(),
        sourceProofs: walletKeys(change),
        inputs: notes,
        outputs: [{ recipient: payee.shieldedAddress(), asset: SOL_MINT, amount }],
        assets,
      }).withTxViewingKey(TX_VIEWING_KEY),
    );
  return { transfer, notes };
}

function allowedOf(
  sources: readonly Readonly<{ owner: ShieldedKeypair; notes: readonly ProofInputUtxo[] }>[],
): AllowedNullifiers {
  return sources.reduce(
    (allowed, { owner, notes }) =>
      allowed.admit(
        { address: owner.shieldedAddress(), nullifierKey: owner.nullifierKey() },
        notes,
      ),
    new AllowedNullifiers(),
  );
}

function messageOf(fixture: Fixture, instruction: Instruction): Uint8Array {
  const { messageBytes } = compileUnsignedTransaction({
    feePayer: fixture.authority,
    lifetime: SIZE_PROBE_LIFETIME,
    instructions: [instruction],
    computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.authorityTransfer),
  });
  return new Uint8Array(messageBytes);
}

const requestOf = (
  fixture: Fixture,
  delegate: Address,
  sources: readonly ShieldedKeypair[],
  payments: readonly Readonly<{ recipient: ShieldedKeypair; mint: Address; amount: bigint }>[],
): PrepareAuthorityTransferRequest => ({
  ring: fixture.ringProgramId,
  delegate,
  transfer: {
    exits: [],
    withdrawals: [],
    sources: sources.map((source) => source.shieldedAddress()),
    payments: payments.map((payment) => ({
      ...payment,
      recipient: payment.recipient.shieldedAddress(),
    })),
  },
  txViewingKey: TX_VIEWING_KEY,
  timestamp: 0n,
  nonce: indexerScalars.base64String(new Uint8Array(32)),
  signature: signature(getBase58Decoder().decode(new Uint8Array(64))),
});

const requestFor = (
  fixture: Fixture,
  delegate: Address,
  sources: readonly ShieldedKeypair[],
  payee: ShieldedKeypair,
  amount: bigint,
) => requestOf(fixture, delegate, sources, [{ recipient: payee, mint: SOL_MINT, amount }]);

function liveRecords(fixture: Fixture, instruction: Instruction, rail: RingRail) {
  const frame = RingTransactData.parse(Uint8Array.from(instruction.data ?? []).subarray(1), rail);
  const { records } = openSealedDisclosure(TX_VIEWING_KEY, fixture.auditor.publicKey(), {
    layout: RingTransactData.streamLayout(frame),
    salt: frame.salt,
    message: {
      ephemeralPublicKey: x25519FromU(frame.txViewingU),
      envelope: frame.envelope,
      records: frame.outputs.map((output) => output.record),
    },
  });
  return records.filter((record) => record.kind !== RecordKind.dummy);
}

describe("delegate sources", () => {
  beforeAll(async () => {
    await initializePoseidon();
  });

  describe.each(["confidential", "anonymous"] as const)("on the %s rail", (mode) => {
    it.each([
      ["its own", 1, 4n],
      ["one member's", 1, 4n],
      ["several members'", 2, 15n],
    ])("moves %s notes and the frame opens to the auditor", async (_name, count, amount) => {
      const sources = Array.from({ length: count }, () => ShieldedKeypair.generate());
      const payee = ShieldedKeypair.generate();
      const { fixture, delegate } = await moveRing(mode, [...sources, payee]);
      const { transfer, notes } = movingFrom(fixture, delegate, sources, payee, amount);
      const instruction = await (await transfer.prove(fixture.client)).instruction();

      const expected = await expectedDelegate({
        request: requestFor(fixture, delegate, sources, payee, amount),
        quote: { feePayer: fixture.authority, validUntilSlot: 100n },
        config: { mode, auditorPublicKey: fixture.auditor.publicKey() },
        allowed: allowedOf(sources.map((owner, at) => ({ owner, notes: notes.slice(at, at + 1) }))),
      });
      const message = messageOf(fixture, instruction);
      expect(checkRelayMessage(expected, message, delegate as never).signer).toBe(delegate);

      const live = liveRecords(
        fixture,
        instruction,
        ringRailOf(RingInstructionTag.authorityTransfer, mode),
      );
      expect(live.reduce((total, record) => total + record.amount, 0n)).toBe(
        BigInt(sources.length) * 10n,
      );
      const keys = [...sources, payee].map((owner) =>
        Array.from(owner.shieldedAddress().signingPublicKey.confidentialViewTag()).join(),
      );
      for (const record of live) expect(keys).toContain(Array.from(record.ownerKey).join());
    });

    it("refuses another member's note and its change the request does not name", async () => {
      const [member, other, payee] = [
        ShieldedKeypair.generate(),
        ShieldedKeypair.generate(),
        ShieldedKeypair.generate(),
      ];
      const { fixture, delegate } = await moveRing(mode, [member, other, payee]);
      const { transfer, notes } = movingFrom(fixture, delegate, [member, other], payee, 15n);
      const instruction = await (await transfer.prove(fixture.client)).instruction();
      const expected = await expectedDelegate({
        request: requestFor(fixture, delegate, [member], payee, 15n),
        quote: { feePayer: fixture.authority, validUntilSlot: 100n },
        config: { mode, auditorPublicKey: fixture.auditor.publicKey() },
        allowed: allowedOf([{ owner: member, notes: notes.slice(0, 1) }]),
      });
      expect(() =>
        checkRelayMessage(expected, messageOf(fixture, instruction), delegate as never),
      ).toThrow(expect.objectContaining({ details: { mismatch: "SpendsUnrequestedNote" } }));
    });

    it("refuses a victim's note under exactly the requested payment and change", async () => {
      const [member, victim, payee] = [
        ShieldedKeypair.generate(),
        ShieldedKeypair.generate(),
        ShieldedKeypair.generate(),
      ];
      const { fixture, delegate } = await moveRing(mode, [member, victim, payee]);
      const owned = noteInput(member, 10n, fixture.ringProgramId);
      const stolen = noteInput(victim, 10n, fixture.ringProgramId);
      // The change returns to the requested source as its own output.
      const transfer = DelegateTransfer.new({
        ringProgramId: fixture.ringProgramId,
        delegate: delegate as never,
        payer: fixture.authority,
        source: member.shieldedAddress(),
        sourceProofs: walletKeys(member),
        inputs: [stolen],
        outputs: [{ recipient: payee.shieldedAddress(), asset: SOL_MINT, amount: 4n }],
        assets,
      })
        .withCoSource({
          owner: victim.shieldedAddress().solanaAddress(),
          nullifierKey: victim.nullifierKey(),
        })
        .withTxViewingKey(TX_VIEWING_KEY);
      const message = messageOf(
        fixture,
        await (await transfer.prove(fixture.client)).instruction(),
      );
      const asked = {
        request: requestFor(fixture, delegate, [member], payee, 4n),
        quote: { feePayer: fixture.authority, validUntilSlot: 100n },
        config: { mode, auditorPublicKey: fixture.auditor.publicKey() },
      };

      const unchecked = {
        checkSources: () => undefined,
        spendsOnly: () => true,
      } as unknown as AllowedNullifiers;
      const outputsOnly = await expectedDelegate({ ...asked, allowed: unchecked });
      expect(checkRelayMessage(outputsOnly, message, delegate as never).signer).toBe(delegate);
      await expect(
        expectedDelegate({ ...asked, allowed: allowedOf([{ owner: victim, notes: [stolen] }]) }),
      ).rejects.toMatchObject({ details: { reason: "sources" } });
      const expected = await expectedDelegate({
        ...asked,
        allowed: allowedOf([{ owner: member, notes: [owned] }]),
      });
      expect(() => checkRelayMessage(expected, message, delegate as never)).toThrow(
        expect.objectContaining({ details: { mismatch: "SpendsUnrequestedNote" } }),
      );
    });
  });

  describe("recovered move", () => {
    const noteOf = (
      fixture: Fixture,
      owner: ShieldedKeypair,
      leaf: number,
      asset: Address = SOL_MINT,
      amount = 10n,
    ): WalletUtxo => {
      const input = noteInput(owner, amount, fixture.ringProgramId, asset);
      return {
        utxo: input.utxo,
        outputContext: {
          hash: small(leaf + 1),
          tree: fixture.client.tree,
          leafIndex: BigInt(leaf),
        },
        nullifier: input.nullifier(),
        spent: false,
      };
    };
    const clientOf = (fixture: Fixture) =>
      withConfirmedReads({
        ...fixture.client,
        proofService: PROOF_SERVICE,
        getLatestBlockhash: async () => BLOCKHASH,
        ...kitReads({
          solanaRpc: {
            getProgramAccounts: () => ({
              send: async () =>
                SPL_MINTS.map(({ mint, assetId }) => ({
                  account: {
                    owner: SHIELDED_POOL_PROGRAM_ID,
                    data: [registryAccount(mint, assetId), "base64"],
                  },
                })),
            }),
          },
        }),
      });
    const sourceOf = (
      fixture: Fixture,
      owner: ShieldedKeypair,
      leaf: number,
      assets: readonly Address[] = [SOL_MINT],
    ) => ({
      address: owner.shieldedAddress(),
      nullifierKey: owner.nullifierKey(),
      notes: assets.map((asset, at) => noteOf(fixture, owner, leaf + at, asset)),
    });

    const on = (note: WalletUtxo, tree: Address): WalletUtxo => ({
      ...note,
      outputContext: { ...note.outputContext, tree },
    });
    const withSecondTree = async (fixture: Fixture) => {
      const second = treeAddress(fixture.client.treeId + 1);
      const first = await fixture.client.getAccount(fixture.client.tree);
      if (first === undefined) throw new Error("the client's tree is published");
      const data = first.data.slice();
      new DataView(data.buffer).setUint16(2, fixture.client.treeId + 1, true);
      const client = clientOf(fixture);
      return {
        second,
        client: withConfirmedReads({
          ...client,
          getAccount: async (address: Address) =>
            address === second ? { ...first, data } : client.getAccount(address),
        }),
      };
    };

    it("funds every mint of a move across at most two trees", async () => {
      const [member, payee] = [ShieldedKeypair.generate(), ShieldedKeypair.generate()];
      const { fixture, delegate } = await moveRing("confidential", [member, payee]);
      const { second, client } = await withSecondTree(fixture);
      const move = (notes: readonly WalletUtxo[]) =>
        buildRingDelegateRecoveredTransaction({
          client,
          ringProgramId: fixture.ringProgramId,
          delegate: delegate as never,
          feePayer: fixture.authority,
          outputs: [
            { recipient: payee.shieldedAddress(), asset: SOL_MINT, amount: 5n },
            { recipient: payee.shieldedAddress(), asset: USDC, amount: 5n },
          ],
          sources: [
            { address: member.shieldedAddress(), nullifierKey: member.nullifierKey(), notes },
          ],
          txViewingKey: TX_VIEWING_KEY,
        });
      await move([
        on(noteOf(fixture, member, 1), second),
        on(noteOf(fixture, member, 2, USDC), second),
      ]);
      const spent = fixture.sppCalls
        .at(-1)
        ?.proofInputs.inputUtxos.filter((input) => !input.isDummy());
      expect(spent?.map((input) => input.treeId)).toEqual([
        fixture.client.treeId + 1,
        fixture.client.treeId + 1,
      ]);
      await move([noteOf(fixture, member, 0), on(noteOf(fixture, member, 1, USDC), second)]);
      const split = fixture.sppCalls.at(-1)?.proofInputs;
      expect(
        split?.inputUtxos.filter((input) => !input.isDummy()).map((input) => input.treeId),
      ).toEqual([fixture.client.treeId, fixture.client.treeId + 1]);
      expect(split?.inputTreeIds()).toEqual([fixture.client.treeId, fixture.client.treeId + 1]);
    });

    it("moves a note carrying ring data, application data and a memo", async () => {
      const [member, payee] = [ShieldedKeypair.generate(), ShieldedKeypair.generate()];
      const { fixture, delegate } = await moveRing("confidential", [member, payee]);
      const input = ProofInputUtxo.fromKeypair(
        new Utxo({
          owner: member.signingPublicKey(),
          asset: SOL_MINT,
          amount: 10n,
          blinding: randomBlinding(),
          ringProgramId: fixture.ringProgramId,
          data: new Data([
            { kind: "ringData", bytes: Uint8Array.of(1) },
            { kind: "utxoData", bytes: Uint8Array.of(2) },
            { kind: "memo", bytes: Uint8Array.of(3) },
          ]),
        }),
        member,
        {},
        fixture.client.treeId,
      );
      const note: WalletUtxo = {
        utxo: input.utxo,
        outputContext: { hash: small(1), tree: fixture.client.tree, leafIndex: 0n },
        nullifier: input.nullifier(),
        spent: false,
      };
      await buildRingDelegateRecoveredTransaction({
        client: clientOf(fixture),
        ringProgramId: fixture.ringProgramId,
        delegate: delegate as never,
        feePayer: fixture.authority,
        outputs: [{ recipient: payee.shieldedAddress(), asset: SOL_MINT, amount: 4n }],
        sources: [
          { address: member.shieldedAddress(), nullifierKey: member.nullifierKey(), notes: [note] },
        ],
        txViewingKey: TX_VIEWING_KEY,
      });
      const spent = fixture.sppCalls
        .at(-1)
        ?.proofInputs.inputUtxos.filter((input) => !input.isDummy());
      expect(spent?.map((input) => input.utxo.data.memo())).toEqual([Uint8Array.of(3)]);
    });

    it("pays the change to the owner of the smallest note across tree runs", async () => {
      const [member, other, payee] = [
        ShieldedKeypair.generate(),
        ShieldedKeypair.generate(),
        ShieldedKeypair.generate(),
      ];
      const { fixture, delegate } = await moveRing("confidential", [member, other, payee]);
      const { second, client } = await withSecondTree(fixture);
      await buildRingDelegateRecoveredTransaction({
        client,
        ringProgramId: fixture.ringProgramId,
        delegate: delegate as never,
        feePayer: fixture.authority,
        outputs: [{ recipient: payee.shieldedAddress(), asset: SOL_MINT, amount: 200n }],
        sources: [
          {
            address: member.shieldedAddress(),
            nullifierKey: member.nullifierKey(),
            notes: [
              noteOf(fixture, member, 0, SOL_MINT, 100n),
              noteOf(fixture, member, 1, SOL_MINT, 50n),
            ],
          },
          {
            address: other.shieldedAddress(),
            nullifierKey: other.nullifierKey(),
            notes: [on(noteOf(fixture, other, 2, SOL_MINT, 80n), second)],
          },
        ],
        txViewingKey: TX_VIEWING_KEY,
      });
      const change = fixture.sppCalls
        .at(-1)
        ?.proofInputs.outputs.find((output) => output.amount === 30n);
      expect(
        change?.ownerAddress?.signingPublicKey.equals(member.shieldedAddress().signingPublicKey),
      ).toBe(true);
    });

    it("spends several owners' notes and pays the change to the last note's owner", async () => {
      const [member, other, payee] = [
        ShieldedKeypair.generate(),
        ShieldedKeypair.generate(),
        ShieldedKeypair.generate(),
      ];
      const { fixture, delegate } = await moveRing("confidential", [member, other, payee]);
      await buildRingDelegateRecoveredTransaction({
        client: clientOf(fixture),
        ringProgramId: fixture.ringProgramId,
        delegate: delegate as never,
        feePayer: fixture.authority,
        outputs: [{ recipient: payee.shieldedAddress(), asset: SOL_MINT, amount: 15n }],
        sources: [sourceOf(fixture, member, 0), sourceOf(fixture, other, 1)],
        txViewingKey: TX_VIEWING_KEY,
      });
      const proofInputs = fixture.sppCalls.at(-1)?.proofInputs;
      expect(proofInputs?.externalData.txViewingPublicKey.u()).toEqual(
        ViewingKey.fromBytes(TX_VIEWING_KEY.slice() as Bytes32)
          .publicKey()
          .u(),
      );
      const spent = proofInputs?.inputUtxos.filter((input) => !input.isDummy()) ?? [];
      expect(spent).toHaveLength(2);
      const change = proofInputs?.outputs.find((output) => output.amount === 5n);
      expect(change?.ownerAddress?.signingPublicKey.equals(spent.at(-1)?.utxo.owner as never)).toBe(
        true,
      );
    });

    it.each(["confidential", "anonymous"] as const)(
      "returns each mint's change to its owner on the %s rail",
      async (mode) => {
        const [member, other, payee] = [
          ShieldedKeypair.generate(),
          ShieldedKeypair.generate(),
          ShieldedKeypair.generate(),
        ];
        const { fixture, delegate } = await moveRing(mode, [member, other, payee]);
        const [memberSource, otherSource] = [
          sourceOf(fixture, member, 0),
          sourceOf(fixture, other, 1, [USDC]),
        ];
        const { messageBytes } = await buildRingDelegateRecoveredTransaction({
          client: clientOf(fixture),
          ringProgramId: fixture.ringProgramId,
          delegate: delegate as never,
          feePayer: fixture.authority,
          outputs: [
            { recipient: payee.shieldedAddress(), asset: SOL_MINT, amount: 4n },
            { recipient: payee.shieldedAddress(), asset: USDC, amount: 3n },
          ],
          sources: [memberSource, otherSource],
          txViewingKey: TX_VIEWING_KEY,
        });
        const message = new Uint8Array(messageBytes);
        const recovered = [
          { owner: member, source: memberSource },
          { owner: other, source: otherSource },
        ].map(({ owner, source }) => ({
          owner,
          notes: source.notes.map((note) =>
            ringProofInput(note, owner.shieldedAddress(), fixture.client),
          ),
        }));
        const expected = await expectedDelegate({
          request: requestOf(
            fixture,
            delegate,
            [member, other],
            [
              { recipient: payee, mint: SOL_MINT, amount: 4n },
              { recipient: payee, mint: USDC, amount: 3n },
            ],
          ),
          quote: { feePayer: fixture.authority, validUntilSlot: 100n },
          config: { mode, auditorPublicKey: fixture.auditor.publicKey() },
          allowed: allowedOf(recovered),
        });
        expect(checkRelayMessage(expected, message, delegate as never).signer).toBe(delegate);

        const [instruction] = decompileTransactionMessage(
          getCompiledTransactionMessageDecoder().decode(message) as Parameters<
            typeof decompileTransactionMessage
          >[0] & { version: 1 },
        ).instructions;
        const key = (owner: ShieldedKeypair) =>
          Array.from(owner.shieldedAddress().signingPublicKey.confidentialViewTag()).join();
        const moved = liveRecords(
          fixture,
          instruction as Instruction,
          ringRailOf(RingInstructionTag.authorityTransfer, mode),
        ).map((record) => [Array.from(record.ownerKey).join(), record.mint, record.amount]);
        expect(moved).toHaveLength(4);
        expect(moved).toEqual(
          expect.arrayContaining([
            [key(payee), SOL_MINT, 4n],
            [key(payee), USDC, 3n],
            [key(member), SOL_MINT, 6n],
            [key(other), USDC, 7n],
          ]),
        );
      },
    );

    it("returns one owner's change on two SPL mints on both rails", async () => {
      const [member, payee] = [ShieldedKeypair.generate(), ShieldedKeypair.generate()];
      const build = async (mode: RingMode) => {
        const { fixture, delegate } = await moveRing(mode, [member, payee]);
        return buildRingDelegateRecoveredTransaction({
          client: clientOf(fixture),
          ringProgramId: fixture.ringProgramId,
          delegate: delegate as never,
          feePayer: fixture.authority,
          outputs: [
            { recipient: payee.shieldedAddress(), asset: USDC, amount: 3n },
            { recipient: payee.shieldedAddress(), asset: EURC, amount: 3n },
          ],
          sources: [sourceOf(fixture, member, 0, [USDC, EURC])],
          txViewingKey: TX_VIEWING_KEY,
        });
      };
      await expect(build("confidential")).resolves.toBeDefined();
      await expect(build("anonymous")).resolves.toBeDefined();
    });

    it("refuses a source named twice and no source", async () => {
      const [member, payee] = [ShieldedKeypair.generate(), ShieldedKeypair.generate()];
      const { fixture, delegate } = await moveRing("confidential", [member, payee]);
      const build = (sources: readonly ReturnType<typeof sourceOf>[]) =>
        buildRingDelegateRecoveredTransaction({
          client: clientOf(fixture),
          ringProgramId: fixture.ringProgramId,
          delegate: delegate as never,
          feePayer: fixture.authority,
          outputs: [{ recipient: payee.shieldedAddress(), asset: SOL_MINT, amount: 4n }],
          sources,
        });
      await expect(
        build([sourceOf(fixture, member, 0), sourceOf(fixture, member, 1)]),
      ).rejects.toMatchObject({
        code: "RING_DELEGATE_INVALID",
        details: { reason: "repeatedSource" },
      });
      await expect(
        build([{ ...sourceOf(fixture, member, 0), nullifierKey: payee.nullifierKey() }]),
      ).rejects.toMatchObject({ code: "RING_NULLIFIER_KEY_MISMATCH" });
      await expect(build([])).rejects.toMatchObject({
        code: "RING_DELEGATE_INVALID",
        details: { reason: "inputs" },
      });
    });
  });

  it("refuses a note of an owner the move does not name", async () => {
    const [member, other, payee] = [
      ShieldedKeypair.generate(),
      ShieldedKeypair.generate(),
      ShieldedKeypair.generate(),
    ];
    const { fixture, delegate } = await moveRing("confidential", [member, other, payee]);
    const transfer = DelegateTransfer.new({
      ringProgramId: fixture.ringProgramId,
      delegate: delegate as never,
      payer: fixture.authority,
      source: other.shieldedAddress(),
      sourceProofs: walletKeys(other),
      inputs: [
        noteInput(member, 10n, fixture.ringProgramId),
        noteInput(other, 10n, fixture.ringProgramId),
      ],
      outputs: [{ recipient: payee.shieldedAddress(), asset: SOL_MINT, amount: 15n }],
      assets,
    });
    await expect(transfer.prove(fixture.client)).rejects.toMatchObject({
      code: "RING_DELEGATE_INVALID",
      details: { reason: "mixedOwners" },
    });
  });

  it("admits no opening that fails to rebuild its nullifier under the source's key", () => {
    const [member, victim] = [ShieldedKeypair.generate(), ShieldedKeypair.generate()];
    const stolen = noteInput(victim, 10n);
    const relabeled = new ProofInputUtxo({
      utxo: new Utxo({
        owner: member.signingPublicKey(),
        asset: stolen.utxo.asset,
        amount: stolen.utxo.amount,
        blinding: stolen.utxo.blinding,
      }),
      nullifierPublicKey: member.shieldedAddress().nullifierPublicKey,
      nullifier: stolen.nullifier(),
      treeId: stolen.treeId,
    });
    const source = { address: member.shieldedAddress(), nullifierKey: member.nullifierKey() };
    expect(() => new AllowedNullifiers().admit(source, [noteInput(member, 5n), relabeled])).toThrow(
      expect.objectContaining({ details: { reason: "unboundOpening", index: 1 } }),
    );
    expect(() => new AllowedNullifiers().admit(source, [stolen])).toThrow(
      expect.objectContaining({ details: { reason: "foreignNote", index: 0 } }),
    );
  });
});
