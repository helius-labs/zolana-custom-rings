import type { AccountMeta, Instruction } from "@solana/kit";

import { CUSTOM_RING_PROOF_LENGTH } from "../proof/custom-ring-proof.js";
import {
  encodeRingDepositInstructionData,
  depositAccounts,
  depositAssetIndex,
  depositLayout,
  instruction,
  meta,
  tagged,
  type SignerAccount,
  Writer,
  fail,
} from "@heliuslabs/zolana/internal";
import { InstructionTag } from "@heliuslabs/zolana/interface";
import type { Address, RingAssetDeposit } from "@heliuslabs/zolana/interface";
import {
  ringAuthAddress,
  ringCoSignerMetas,
  ringConfigAddress,
  ringPolicyAddress,
} from "../pda/index.js";
import { REVISION_LENGTH } from "./transact.js";

import {
  AUDITED_RING_DEPOSIT_TAG,
  RING_DEPOSIT_AUDIT_SLOTS,
  readRingDepositCapsule,
} from "../codec/deposit-capsule.js";

/** The SPP ring deposit the ring program forwards unchanged, Rust `RingDeposit`. */
export interface RingDepositSpp {
  /** `RING_DEPOSIT ‖ RingDepositIxData`, the bytes the deposit proof binds. */
  readonly data: Uint8Array;
  readonly accounts: readonly AccountMeta[];
}

/** `AUDITED_DEPOSIT ‖ proof ‖ own_revision ‖ curator_revision` ahead of the forwarded SPP deposit. */
export const AUDITED_DEPOSIT_PREFIX_LENGTH = 1 + CUSTOM_RING_PROOF_LENGTH + 2 * REVISION_LENGTH;

/** The accounts `[config, policy?, co_signer?]` ahead of SPP's deposit list. */
export async function ringDepositInstruction(
  input: Readonly<{
    ringProgramId: Address;
    tree: Address;
    depositor: SignerAccount;
    deposits: readonly RingAssetDeposit[];
    proof: Uint8Array;
    /** Escrow or policy rings only, the policy account then follows the config. */
    ownRevision?: bigint;
    /** Rings with a curator source only. */
    curatorRevision?: bigint;
    /** The supplied co-signer when a record covers deposits. */
    cosigner?: SignerAccount;
  }>,
): Promise<Instruction> {
  const [spp, config, policy, cosigner] = await Promise.all([
    ringDepositSpp(input),
    ringConfigAddress(input.ringProgramId),
    input.ownRevision === undefined ? undefined : ringPolicyAddress(input.ringProgramId),
    input.cosigner === undefined ? [] : ringCoSignerMetas(input.ringProgramId, input.cosigner),
  ]);
  const prefix = new Writer()
    .bytes(input.proof, CUSTOM_RING_PROOF_LENGTH, "deposit proof")
    .u64(input.ownRevision ?? 0n, "ownRevision")
    .u64(input.curatorRevision ?? 0n, "curatorRevision")
    .finish();
  return instruction(
    tagged(AUDITED_RING_DEPOSIT_TAG, new Uint8Array([...prefix, ...spp.data])),
    [
      meta(config, false, false),
      ...(policy === undefined ? [] : [meta(policy, false, false)]),
      ...cosigner,
      ...spp.accounts,
    ],
    input.ringProgramId,
  );
}

/** One capsule per output at its own slot, all under one ephemeral key, as the program reads them. */
export async function ringDepositSpp(
  input: Readonly<{
    ringProgramId: Address;
    tree: Address;
    depositor: SignerAccount;
    deposits: readonly RingAssetDeposit[];
  }>,
): Promise<RingDepositSpp> {
  if (input.deposits.length > RING_DEPOSIT_AUDIT_SLOTS)
    fail("INTERFACE_CODEC", { field: "deposit count" });
  let ephemeralKey: Uint8Array | undefined;
  for (const [index, deposit] of input.deposits.entries()) {
    const capsule = readRingDepositCapsule(deposit.encrypted.ciphertext);
    if (
      capsule === undefined ||
      capsule.slotIndex !== index ||
      (ephemeralKey !== undefined &&
        !ephemeralKey.every((byte, offset) => capsule.ephemeralPublicKey[offset] === byte))
    )
      fail("INTERFACE_CODEC", { field: "deposit capsule" });
    ephemeralKey = capsule.ephemeralPublicKey;
  }
  const layout = depositLayout(input.deposits);
  const { accounts, splInterfaceBumps } = await depositAccounts(
    input.tree,
    input.depositor,
    layout,
    await ringAuthAddress(input.ringProgramId),
  );
  const data = tagged(
    InstructionTag.ringDeposit,
    encodeRingDepositInstructionData({
      assets: [
        ...(layout.hasSol ? ([{ kind: "sol" }] as const) : []),
        ...splInterfaceBumps.map((splInterfaceBump) => ({
          kind: "spl" as const,
          splInterfaceBump,
        })),
      ],
      deposits: input.deposits.map((deposit) => ({
        assetIndex: depositAssetIndex(layout, deposit),
        viewTag: deposit.viewTag,
        ownerUtxoHash: deposit.ownerUtxoHash,
        amount: deposit.amount,
        ringDataHash: deposit.ringDataHash,
        encrypted: deposit.encrypted,
      })),
    }),
  );
  return Object.freeze({ data, accounts: Object.freeze(accounts) });
}
