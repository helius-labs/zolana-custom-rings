import { X25519Keypair, ShieldedAddress } from "@heliuslabs/zolana/keypair";
import { SOL_MINT } from "@heliuslabs/zolana/transaction";
import { SPL_TOKEN_2022_PROGRAM_ID } from "@heliuslabs/zolana/interface";
import {
  ZERO_NULLIFIER_PK,
  addressBytes,
  withdrawalSetupInstructions,
} from "@heliuslabs/zolana/internal";
import {
  generateKeyPairSigner,
  getCompiledTransactionMessageDecoder,
  decompileTransactionMessage,
} from "@solana/kit";
import { describe, expect, it } from "vitest";
import {
  AuthorityListWrite,
  NullifierKeyEscrow,
  RegisterKey,
  RingInstructionTag,
  fetchRingMemberRegistry,
  fetchRingSealedKey,
  openRingSealedKey,
  recoverRingMemberNotes,
  createRingDelegateRecoveredSubmission,
  setRingCoSignerInstruction,
  setRingDelegateInstruction,
  fetchRingProgramConfig,
  clearRingCoSignerInstruction,
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  ringComputeUnitLimit,
  createKitRingSubmissionTransport,
  createRingTransferSubmission,
  createRingMergeSubmission,
  createRingWithdrawalSubmission,
  createRingDelegateSubmission,
  buildRingTransferTransaction,
  buildRingDelegateTransferTransaction,
  buildRingDepositTransaction,
} from "../../src/ring/index.js";
import {
  EMPTY_MINT_POLICY,
  ListId,
  buildRuleTable,
  memberOfAsset,
  memberOfTag,
} from "../../src/ring/advanced.js";
import { liveHarness, signSendAndConfirm } from "./live-helpers.js";
import {
  airdrop,
  applyQueuedWrites,
  createRing,
  enrolInAllow,
  freshActor,
  indexedKeys,
  sendInstruction,
  sync,
  writeList,
  settle,
  settleWithTransport,
} from "./ring-live-helpers.js";

describe.each(["client", "prover"] as const)("controls %s", (proofDataSource) => {
  it("escrows keys, enforces policy and recovers notes", async () => {
    const harness = await liveHarness(proofDataSource);
    if (!["127.0.0.1", "localhost", "[::1]"].includes(new URL(harness.rpcUrl).hostname))
      throw new Error("controls fixture runs on a local validator only");
    const { client } = harness;
    await airdrop(client, harness.testAuthority.address);
    const authority = (await freshActor(client)).signer;
    const delegate = (await freshActor(client)).signer;
    const cosigner = (await freshActor(client)).signer;
    const program = await generateKeyPairSigner();
    const ringProgramId = program.address;
    const auditor = X25519Keypair.generate();
    try {
      for (let i = 0; i < 6; i++) await airdrop(client, authority.address);
      await airdrop(client, delegate.address);
      await createRing(client, {
        program,
        authority,
        auditor: auditor.publicKey(),
        kind: "policy",
        table: buildRuleTable({
          rules: [
            {
              subject: "outputOwner",
              source: { kind: "lists", present: [ListId.allow], absent: [] },
              guard: { kind: "always" },
            },
            {
              subject: "sender",
              source: { kind: "lists", present: [], absent: [ListId.frozen] },
              guard: { kind: "always" },
            },
            {
              subject: "outputOwner",
              source: { kind: "lists", present: [], absent: [ListId.block] },
              guard: { kind: "always" },
            },
          ],
        }),
        authorityTransact: true,
      });
      await sendInstruction(
        client,
        await setRingDelegateInstruction({ ringProgramId, authority, delegate }),
        [authority, delegate],
      );
      expect((await fetchRingProgramConfig(client, ringProgramId)).keyEscrow).toBe(true);
      await sendInstruction(
        client,
        await setRingCoSignerInstruction({
          ringProgramId,
          authority,
          signer: cosigner.address,
          scope: RING_COSIGN_WITHDRAWALS,
        }),
        authority,
      );
      const mintSettings = await new AuthorityListWrite({
        ringProgramId,
        authority: authority.address,
      })
        .withMintPolicy(memberOfAsset(SOL_MINT), {
          ...EMPTY_MINT_POLICY,
          cap: 500_000_000n,
          cosignAbove: 300_000_000n,
          withdrawalThreshold: 100_000_000n,
        })
        .withMintPolicy(memberOfAsset(harness.mint), {
          ...EMPTY_MINT_POLICY,
          cap: 300n,
          cosignAbove: 90n,
        })
        .withMintPolicy(memberOfAsset(harness.token2022Mint), {
          ...EMPTY_MINT_POLICY,
          cap: 500n,
          cosignAbove: 190n,
        })
        .prove(client);
      await sendInstruction(
        client,
        mintSettings.instruction,
        authority,
        ringComputeUnitLimit(RingInstructionTag.authorityWriteRecords),
      );
      const sender = await freshActor(client),
        recipient = await freshActor(client),
        unregistered = await freshActor(client);
      await airdrop(client, sender.signer.address);
      await airdrop(client, recipient.signer.address);
      await enrolInAllow(client, ringProgramId, authority, [sender, recipient, unregistered]);
      const listed = await fetchRingMemberRegistry(client, ringProgramId);
      // The sentinel, three mint settings and three listed members occupy leaves.
      expect(listed.nextIndex).toBe(7);
      // Key escrow is on, every note owner registers before receiving.
      for (const member of [sender, recipient]) {
        const nullifierKey = member.keypair.nullifierKey();
        const escrow = new NullifierKeyEscrow(nullifierKey, client);
        try {
          const registration = await new RegisterKey({
            ringProgramId,
            member: member.keypair.shieldedAddress(),
            payer: member.signer,
            authority: escrow,
          }).prove(client);
          await sendInstruction(
            client,
            registration.instruction,
            member.signer,
            ringComputeUnitLimit(RingInstructionTag.registerKey),
          );
        } finally {
          escrow.destroy();
          nullifierKey.destroy();
        }
      }
      // The escrow writes queue, an application lands them in the records.
      await applyQueuedWrites(client, ringProgramId, authority);
      // Registering keys updates existing list records without allocating new leaves.
      expect((await fetchRingMemberRegistry(client, ringProgramId)).nextIndex).toBe(
        listed.nextIndex,
      );
      const registered = recipient.keypair.shieldedAddress();
      const zeroKey = ShieldedAddress.fromPublicKeys(
        registered.signingPublicKey,
        ZERO_NULLIFIER_PK,
        registered.viewingPublicKey,
      );
      for (const refused of [unregistered.keypair.shieldedAddress(), zeroKey]) {
        await expect(
          indexedKeys(() =>
            buildRingDepositTransaction({
              client,
              ringProgramId,
              feePayer: sender.signer.address,
              recipient: { kind: "confidential", address: refused },
              amount: 1n,
            }),
          ),
        ).rejects.toMatchObject({
          code: "RING_BUILD_DEPOSIT",
          causeCode: "RING_UNREGISTERED_OUTPUT_KEY",
        });
      }
      for (const amount of [900_000_000n, 1_100_000_000n]) {
        await signSendAndConfirm(
          client,
          await buildRingDepositTransaction({
            client,
            ringProgramId,
            feePayer: sender.signer.address,
            recipient: { kind: "confidential", address: sender.keypair.shieldedAddress() },
            amount,
          }),
          [sender.signer],
        );
      }
      for (const [asset, splTokenAccount, splTokenProgram] of [
        [harness.mint, harness.testTokenAccount, undefined],
        [harness.token2022Mint, harness.testToken2022Account, SPL_TOKEN_2022_PROGRAM_ID],
      ] as const) {
        await signSendAndConfirm(
          client,
          await buildRingDepositTransaction({
            client,
            ringProgramId,
            feePayer: harness.testAuthority.address,
            recipient: { kind: "confidential", address: sender.keypair.shieldedAddress() },
            asset,
            amount: 1000n,
            splTokenAccount,
            ...(splTokenProgram === undefined ? {} : { splTokenProgram }),
          }),
          [harness.testAuthority],
        );
      }
      await sync(client, sender);
      const depositKey = sender.keypair.nullifierKey();
      try {
        const recoveredDeposits = await recoverRingMemberNotes({
          client,
          ringProgramId,
          auditor,
          source: sender.keypair.shieldedAddress(),
          nullifierKey: depositKey,
          assets: sender.wallet.registry,
        });
        expect(recoveredDeposits.unopened).toEqual([]);
        expect(recoveredDeposits.unsupportedDeposits).toEqual([]);
        const deposits = sender.wallet
          .utxos()
          .filter((note) => !note.spent && note.utxo.ringProgramId === ringProgramId);
        expect(recoveredDeposits.notes.map((note) => note.outputContext.hash)).toEqual(
          expect.arrayContaining(deposits.map((note) => note.outputContext.hash)),
        );
        expect(recoveredDeposits.notes).toHaveLength(4);
        for (const [asset, amount] of [
          [SOL_MINT, 2_000_000_000n],
          [harness.mint, 1000n],
          [harness.token2022Mint, 1000n],
        ] as const) {
          expect(
            deposits.filter((note) => note.utxo.asset === asset).map((note) => note.utxo.amount),
          ).toEqual(
            expect.arrayContaining(asset === SOL_MINT ? [900_000_000n, 1_100_000_000n] : [amount]),
          );
          expect(
            recoveredDeposits.notes
              .filter((note) => note.utxo.asset === asset)
              .map((note) => note.utxo.amount),
          ).toEqual(
            expect.arrayContaining(asset === SOL_MINT ? [900_000_000n, 1_100_000_000n] : [amount]),
          );
        }
      } finally {
        depositKey.destroy();
      }
      // A key escrow ring merges only once the ring merge proof lands.
      await expect(
        createRingMergeSubmission({
          client,
          ringProgramId,
          wallet: sender.wallet,
          keys: sender.keys,
          feePayer: sender.signer.address,
        }),
      ).rejects.toMatchObject({
        code: "RING_BUILD_MERGE",
        causeCode: "RING_ESCROW_MERGE_UNVERIFIED",
      });
      await sync(client, sender);
      expect(
        sender.wallet
          .utxos()
          .filter(
            (note) =>
              !note.spent &&
              note.utxo.ringProgramId === ringProgramId &&
              note.utxo.asset === SOL_MINT,
          )
          .map((note) => note.utxo.amount)
          .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0)),
      ).toEqual([900_000_000n, 1_100_000_000n]);
      const transfer = {
        client,
        ringProgramId,
        wallet: sender.wallet,
        keys: sender.keys,
        feePayer: sender.signer.address,
        recipient: recipient.keypair.shieldedAddress(),
        amount: 350_000_000n,
      };
      await expect(
        indexedKeys(() =>
          buildRingTransferTransaction({
            ...transfer,
            recipient: unregistered.keypair.shieldedAddress(),
            amount: 1n,
          }),
        ),
      ).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_UNREGISTERED_OUTPUT_KEY",
      });
      await settle(
        await indexedKeys(() => createRingTransferSubmission({ ...transfer, amount: 50_000_000n })),
        client,
        [sender.signer],
      );
      await sync(client, sender);
      await expect(indexedKeys(() => buildRingTransferTransaction(transfer))).rejects.toMatchObject(
        {
          code: "RING_BUILD_TRANSFER",
          causeCode: "RING_COSIGNER_REQUIRED",
        },
      );
      await settle(
        await indexedKeys(() => createRingTransferSubmission({ ...transfer, cosigner })),
        client,
        [sender.signer, cosigner],
      );
      await sync(client, sender);
      await settle(
        await indexedKeys(() =>
          createRingWithdrawalSubmission({
            client,
            ringProgramId,
            wallet: sender.wallet,
            keys: sender.keys,
            feePayer: sender.signer.address,
            recipient: sender.signer.address,
            amount: 100_000_000n,
            cosigner,
          }),
        ),
        client,
        [sender.signer],
      );
      await sync(client, sender);
      // A single transfer above the SOL cap is refused before any proof.
      await expect(
        indexedKeys(() =>
          buildRingTransferTransaction({
            ...transfer,
            amount: 600_000_000n,
            cosigner,
          }),
        ),
      ).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_OUTFLOW_CAP_EXCEEDED",
      });
      for (const [asset, amount, rejected] of [
        [harness.mint, 100n, 301n],
        [harness.token2022Mint, 200n, 501n],
      ] as const) {
        await settle(
          await indexedKeys(() =>
            createRingTransferSubmission({
              ...transfer,
              asset,
              amount,
              cosigner,
            }),
          ),
          client,
          [sender.signer, cosigner],
        );
        await sync(client, sender);
        await expect(
          indexedKeys(() =>
            buildRingTransferTransaction({
              ...transfer,
              asset,
              amount: rejected,
              cosigner,
            }),
          ),
        ).rejects.toMatchObject({
          code: "RING_BUILD_TRANSFER",
          causeCode: "RING_OUTFLOW_CAP_EXCEEDED",
        });
      }
      await sendInstruction(
        client,
        await setRingCoSignerInstruction({
          ringProgramId,
          authority,
          signer: cosigner.address,
          scope: RING_COSIGN_TRANSFERS,
        }),
        authority,
      );
      // Delegation is exempt from the limits, the move passes the SOL cap.
      const move = {
        client,
        ringProgramId,
        wallet: sender.wallet,
        source: sender.keys,
        delegate,
        feePayer: delegate.address,
        outputs: [
          {
            recipient: recipient.keypair.shieldedAddress(),
            asset: SOL_MINT,
            amount: 700_000_000n,
          },
        ],
      };
      await expect(
        indexedKeys(() => buildRingDelegateTransferTransaction(move)),
      ).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_COSIGNER_REQUIRED",
      });
      await settle(
        await indexedKeys(() => createRingDelegateSubmission({ ...move, cosigner })),
        client,
        [delegate, cosigner],
      );
      await sync(client, sender);
      const twoAssetMove = await indexedKeys(() =>
        createRingDelegateSubmission({
          ...move,
          cosigner,
          outputs: [
            { recipient: recipient.keypair.shieldedAddress(), asset: harness.mint, amount: 900n },
            {
              recipient: recipient.keypair.shieldedAddress(),
              asset: harness.token2022Mint,
              amount: 600n,
            },
          ],
        }),
      );
      const moveTransport = createKitRingSubmissionTransport(client, [delegate, cosigner]);
      await settleWithTransport(twoAssetMove, {
        ...moveTransport,
        sign: async (transaction, context) => {
          const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
          if (compiled.version !== 1) throw new Error("expected V1");
          const instruction = decompileTransactionMessage(compiled, {
            lastValidBlockHeight: 1n,
          }).instructions.find((instruction) => instruction.programAddress === ringProgramId);
          expect(instruction?.data?.[0]).toBe(RingInstructionTag.delegateTransact);
          return moveTransport.sign(transaction, context);
        },
      });
      await sync(client, sender);
      await sync(client, recipient);
      for (const [asset, sourceAmount, recipientAmount] of [
        [SOL_MINT, 800_000_000n, 1_100_000_000n],
        [harness.mint, 0n, 1000n],
        [harness.token2022Mint, 200n, 800n],
      ] as const) {
        expect(
          sender.wallet
            .ringBalances()
            .find((ring) => ring.ringProgramId === ringProgramId)
            ?.assets.find((balance) => balance.mint === asset)?.amount ?? 0n,
        ).toBe(sourceAmount);
        expect(
          recipient.wallet
            .ringBalances()
            .find((ring) => ring.ringProgramId === ringProgramId)
            ?.assets.find((balance) => balance.mint === asset)?.amount,
        ).toBe(recipientAmount);
      }
      const sealed = await indexedKeys(() =>
        fetchRingSealedKey({
          client,
          ringProgramId,
          member: memberOfTag(sender.keypair.shieldedAddress().confidentialViewTag()),
        }),
      );
      const recoveredKey = openRingSealedKey(sealed, auditor);
      try {
        expect(recoveredKey.publicKey()).toEqual(sender.keypair.nullifierPublicKey());
        const recovered = await recoverRingMemberNotes({
          client,
          ringProgramId,
          auditor,
          source: sender.keypair.shieldedAddress(),
          nullifierKey: recoveredKey,
          assets: sender.wallet.registry,
        });
        expect(recovered.unopened).toEqual([]);
        expect(recovered.unsupportedDeposits).toEqual([]);
        const heldSol = recovered.notes
          .filter((note) => note.utxo.asset === SOL_MINT)
          .reduce((total, note) => total + note.utxo.amount, 0n);
        expect(heldSol).toBe(800_000_000n);
        await settle(
          await indexedKeys(() =>
            createRingDelegateRecoveredSubmission({
              client,
              ringProgramId,
              source: sender.keypair.shieldedAddress(),
              nullifierKey: recoveredKey,
              notes: recovered.notes,
              delegate,
              cosigner,
              feePayer: delegate.address,
              outputs: [
                {
                  recipient: recipient.keypair.shieldedAddress(),
                  asset: SOL_MINT,
                  amount: 100_000_000n,
                },
              ],
            }),
          ),
          client,
          [delegate, cosigner],
        );
      } finally {
        recoveredKey.destroy();
      }
      await sync(client, sender);
      await sync(client, recipient);
      expect(
        sender.wallet
          .ringBalances()
          .find((ring) => ring.ringProgramId === ringProgramId)
          ?.assets.find((balance) => balance.mint === SOL_MINT)?.amount,
      ).toBe(700_000_000n);
      expect(
        recipient.wallet
          .ringBalances()
          .find((ring) => ring.ringProgramId === ringProgramId)
          ?.assets.find((balance) => balance.mint === SOL_MINT)?.amount,
      ).toBe(1_200_000_000n);
      await writeList(client, ringProgramId, authority, {
        listId: ListId.allow,
        tag: addressBytes(authority.address),
        state: "active",
      });
      // Policy proves the token account's current owner; create the destination first.
      for (const instruction of await withdrawalSetupInstructions({
        payer: authority.address,
        recipient: authority.address,
        asset: harness.token2022Mint,
        splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
      })) {
        await sendInstruction(client, instruction, authority);
      }
      await settle(
        await indexedKeys(() =>
          createRingWithdrawalSubmission({
            client,
            ringProgramId,
            wallet: sender.wallet,
            keys: sender.keys,
            feePayer: authority.address,
            recipient: authority.address,
            asset: harness.token2022Mint,
            splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
            amount: 200n,
            cosigner,
          }),
        ),
        client,
        [sender.signer, authority, cosigner],
      );
      await sync(client, sender);
      expect(
        sender.wallet
          .ringBalances()
          .find((ring) => ring.ringProgramId === ringProgramId)
          ?.assets.find((balance) => balance.mint === harness.token2022Mint)?.amount ?? 0n,
      ).toBe(0n);
      await writeList(client, ringProgramId, authority, {
        listId: ListId.block,
        tag: recipient.keypair.shieldedAddress().confidentialViewTag(),
        state: "active",
      });
      await expect(
        indexedKeys(() =>
          buildRingDelegateTransferTransaction({
            ...move,
            cosigner,
            outputs: [{ ...move.outputs[0]!, amount: 1n }],
          }),
        ),
      ).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_POLICY_RULE_UNSATISFIED",
      });
      await sendInstruction(
        client,
        await clearRingCoSignerInstruction({ ringProgramId, authority }),
        authority,
      );
      expect((await fetchRingProgramConfig(client, ringProgramId)).coSigner).toBeUndefined();
    } finally {
      auditor.destroy();
    }
  }, 1_800_000);
});
